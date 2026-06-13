/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.analyzer.ipc;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.*;

/**
 * Recovers the IPC commands a module ACTUALLY invokes on a connected service, grounded entirely in
 * real ARM64 bytes (the "import"/client usage side). Pipeline (proven on sdk + stripped ns/ncm):
 * <ol>
 *   <li>service-name string -&gt; referencing connector function -&gt; the proxy vtable it installs
 *       inline ({@code adrp/add <rodata>; str|stp <reg>,[obj,#0]}).</li>
 *   <li>decode each root vtable slot's command id (the stub passes it as {@code mov w2..w7,#cmdid}
 *       to the generic CMIF dispatch, which writes it as the SFCI MethodId).</li>
 *   <li>walk UP the call graph to consumer functions; in each, TYPE every virtual-call's object via
 *       stack-slot provenance so commands resolve against the CORRECT vtable:
 *       <ul>
 *         <li>object = return of an accessor in this connector's subtree -&gt; ROOT proxy vtable;</li>
 *         <li>object = out-param of a prior resolved {@code Open*} call -&gt; that out-interface's own
 *             vtable (the {@code Open*} stub's first {@code bl} is the out-object constructor, which
 *             installs the sub-interface vtable the same {@code str|stp ...,[obj,#0]} way); recursive;</li>
 *         <li>object with unrecognised provenance -&gt; UNVERIFIED (never assumed root).</li>
 *       </ul></li>
 * </ol>
 * Output groups proven commands as root commands + sub-interface commands keyed by the root command
 * that opens the sub-interface (e.g. fsp-srv cmd 400 OpenDeviceOperator -&gt; IDeviceOperator cmds).
 */
public class ServiceUsageTracer
{
    /**
     * Full byte-level proof for one invoked command:
     * <ul>
     *   <li>{@code vtOffset} -- the proxy vtable slot it is dispatched through;</li>
     *   <li>{@code stub} -- the dispatch stub that slot points to;</li>
     *   <li>{@code decodeSite} -- the EXACT instruction ({@code mov w2,#cmdId}) that materialises the
     *       command id, i.e. the source line where the id is proven;</li>
     *   <li>{@code callSites} -- every {@code blr} in the module that actually invokes this command.</li>
     * </ul>
     */
    public static class CommandProof
    {
        public final long command;
        public final long vtOffset;
        public final long stub;
        public final long decodeSite;
        public final String decodeInstruction;       // the exact instruction text, e.g. "mov w4,#0x23"
        public final TreeSet<Long> callSites = new TreeSet<>();

        CommandProof(long command, long vtOffset, long stub, long decodeSite, String decodeInstruction)
        {
            this.command = command; this.vtOffset = vtOffset; this.stub = stub;
            this.decodeSite = decodeSite; this.decodeInstruction = decodeInstruction;
        }
    }

    /** Decoded vtable slot: command id + where/how it is proven (stub, the mov address + its text). */
    private static class Slot
    {
        final long cmd; final long stub; final long decodeSite; final String decodeText;
        Slot(long cmd, long stub, long decodeSite, String decodeText)
        {
            this.cmd = cmd; this.stub = stub; this.decodeSite = decodeSite; this.decodeText = decodeText;
        }
    }

    /** Result of decoding a stub: command id, the decode-site address, and the instruction text there. */
    private static class Decoded
    {
        final long cmd; final long site; final String text;
        Decoded(long cmd, long site, String text) { this.cmd = cmd; this.site = site; this.text = text; }
    }

    /** Proven command usage for one connected service, each command carrying its full proof. */
    public static class ServiceUsage
    {
        public final String serviceName;
        public final long rootVtable;
        /** root-interface command id -&gt; proof. */
        public final TreeMap<Long, CommandProof> rootCommands = new TreeMap<>();
        /** producing root command id -&gt; (sub-interface command id -&gt; proof). */
        public final TreeMap<Long, TreeMap<Long, CommandProof>> subCommandsByOpenCommand = new TreeMap<>();
        public int unverified;
        public int unresolved;

        ServiceUsage(String serviceName, long rootVtable) { this.serviceName = serviceName; this.rootVtable = rootVtable; }

        public boolean isEmpty() { return rootCommands.isEmpty() && subCommandsByOpenCommand.isEmpty(); }
    }

    private final ghidra.program.model.listing.Program program;
    private final Listing listing;
    private final Memory memory;
    private final FunctionManager fnMgr;
    private final ReferenceManager refMgr;

    private long rootVtable;
    private String rootInterfaceName;                          // the service's root interface (DB), for Open* out-interface lookup
    private long rootGlobal;                                   // BSS global caching the proxy (0 = none)
    private Set<Long> accessorEntries = new HashSet<>();
    // RTTI-resolved vtables. Fallback for SDK 22+ lazy-singleton/template proxies whose install the
    // structural scans can't reach -- used for both the root proxy and Open*-returned sub-interfaces.
    private Map<Long, String> rttiVtableToInterface = Collections.emptyMap();   // vtable addr -> iface fullname
    private Map<String, List<Long>> rttiProxyVtables = Collections.emptyMap();  // iface SIMPLE name -> vtable addrs
    private final Map<Long, Map<Long, Slot>> offToCmdCache = new HashMap<>();   // vtableAddr -> off->slot
    private final Map<String, Long> subVtCache = new HashMap<>();               // "Vhex:off" -> sub vtable (0 = none)
    private final Map<Long, Integer> vtableValidationCache = new HashMap<>();   // addr -> #slots that decode

    public ServiceUsageTracer(ghidra.program.model.listing.Program program)
    {
        this.program = program;
        this.listing = program.getListing();
        this.memory = program.getMemory();
        this.fnMgr = program.getFunctionManager();
        this.refMgr = program.getReferenceManager();
    }

    /** The RTTI vtable->interface-fullname map (incl. client/proxy vtables). Builds both the reverse
     *  lookup (for an Open*'s out-interface) and the SIMPLE-name index (interface -> proxy vtables). */
    public void setRttiVtables(Map<Long, String> vtableToInterface)
    {
        this.rttiVtableToInterface = vtableToInterface != null ? vtableToInterface : Collections.emptyMap();
        Map<String, List<Long>> index = new HashMap<>();
        for (Map.Entry<Long, String> e : this.rttiVtableToInterface.entrySet())
            index.computeIfAbsent(simpleName(e.getValue()), k -> new ArrayList<>()).add(e.getKey());
        this.rttiProxyVtables = index;
    }

    /** The RTTI proxy vtable for the sub-interface an Open* command returns: the command's DB out-
     *  interface (e.g. IFileSystemProxy cmd 400 -> IDeviceOperator) resolved to its RTTI proxy vtable.
     *  Picks the candidate that decodes the most command stubs (the proxy vtable, not the typeinfo one). */
    private long subVtableViaRtti(long vtableUsed, long off)
    {
        String iface = rttiVtableToInterface.get(vtableUsed);
        if (iface == null && vtableUsed == rootVtable)
            iface = rootInterfaceName;                          // structural root vtable: name it from the service
        Slot slot = offToCmd(vtableUsed).get(off);
        if (iface == null || slot == null)
            return 0;
        String outIface = IPCDatabase.getInstance().getOutInterface(iface, slot.cmd);
        List<Long> vts = outIface != null ? rttiProxyVtables.get(simpleName(outIface)) : null;
        long best = 0; int bestCount = -1;
        if (vts != null)
            for (long c : vts)
            {
                int cnt = vtableDecodeCount(c);
                if (cnt > bestCount) { bestCount = cnt; best = c; }
            }
        return bestCount >= 1 ? best : 0;
    }

    /** Trace one service. Returns null if the service string isn't referenced or no proxy vtable found. */
    public ServiceUsage trace(String serviceName)
    {
        for (Function connector : connectorsFor(serviceName))
        {
            Set<Function> consumers = findConsumers(connector);   // also sets rootGlobal + accessorEntries

            // 1) Structural: the proxy vtable the connector demonstrably installs (works for the common
            //    inline/accessor patterns, e.g. fsp-srv).
            Address vt = extractInstalledVtable(connector);
            if (vt != null)
            {
                ServiceUsage u = decode(serviceName, vt.getOffset(), consumers);
                if (!u.isEmpty())
                    return u;
            }

            // 2) RTTI fallback: SDK 22+ lazy-singleton/template proxies (prepo/applet/ngct/...) build the
            //    proxy through a stored factory the structural scan can't reach -- the scan only finds the
            //    shared session-manager base. Use the service's root interface -> its RTTI-resolved client
            //    proxy vtable instead. The proxy still PROVES itself: consumers load it from the BSS global
            //    ("groot") and their vcalls decode against this vtable.
            // An interface can have several RTTI vtables (its own interface/typeinfo vtable AND the
            // actual CMIF client-proxy vtable). They decode different command counts -- the proxy vtable
            // carries the real command stubs -- so try all and keep the one that resolves the MOST.
            ServiceUsage best = null;
            for (long pvt : rttiProxyVtablesForService(serviceName))
            {
                ServiceUsage u = decode(serviceName, pvt, consumers);
                if (!u.isEmpty() && (best == null || u.rootCommands.size() > best.rootCommands.size()))
                    best = u;
            }
            if (best != null)
                return best;
        }
        return null;
    }

    /** Consumers of a service's proxy: callers of the connector + (lazy-singleton) referencers of the BSS
     *  global it caches the proxy in. Also sets {@code rootGlobal} and {@code accessorEntries}. */
    private Set<Function> findConsumers(Function connector)
    {
        rootGlobal = findProxyGlobal(connector);
        Set<Function> consumers = new LinkedHashSet<>(callersUpTo(connector, 4));
        consumers.add(connector);                          // the connector itself may invoke commands
        if (rootGlobal != 0)
            for (Reference r : refMgr.getReferencesTo(addr(rootGlobal)))
            {
                Function cf = fnMgr.getFunctionContaining(r.getFromAddress());
                if (cf != null) consumers.add(cf);
            }

        accessorEntries = new HashSet<>();
        accessorEntries.add(connector.getEntryPoint().getOffset());
        for (Function c : consumers)
            accessorEntries.add(c.getEntryPoint().getOffset());
        return consumers;
    }

    /** Decode all consumer vcalls against a given root proxy vtable. */
    private ServiceUsage decode(String serviceName, long vtable, Set<Function> consumers)
    {
        rootVtable = vtable;
        // The service's root interface, so an Open* on the (possibly non-RTTI-named, structural) root
        // vtable can still resolve its out-interface from the database.
        rootInterfaceName = IPCDatabase.getInstance().getServiceInterface(serviceName, Collections.emptySet());
        offToCmdCache.clear();
        subVtCache.clear();
        ServiceUsage usage = new ServiceUsage(serviceName, rootVtable);
        for (Function f : consumers)
            analyzeConsumer(f, usage);
        return usage;
    }

    /** The RTTI-resolved client-proxy vtable(s) for a service's root interface (matched by simple name). */
    private List<Long> rttiProxyVtablesForService(String serviceName)
    {
        if (rttiProxyVtables.isEmpty())
            return Collections.emptyList();
        String iface = IPCDatabase.getInstance().getServiceInterface(serviceName, Collections.emptySet());
        if (iface == null)
            return Collections.emptyList();
        List<Long> vts = rttiProxyVtables.get(simpleName(iface));
        return vts != null ? vts : Collections.emptyList();
    }

    private static String simpleName(String n)
    {
        int i = n.lastIndexOf("::");
        return i >= 0 ? n.substring(i + 2) : n;
    }

    // ---- per-consumer object type-flow ----
    private void analyzeConsumer(Function f, ServiceUsage usage)
    {
        long spDelta = 0;
        Map<String, Object[]> regKind = new HashMap<>();   // reg -> {"vtable",obj}|{"method",obj,off}
        Map<String, String> regTag = new HashMap<>();      // reg -> addr:N | load:N | ret:@e|name | vt:@addr|openCmd | groot
        Map<Long, String> slotProv = new HashMap<>();      // slot -> writer tag
        Map<String, Long> regGlobal = new HashMap<>();     // reg -> global address it holds (adrp/add)

        Instruction insn = firstInstruction(f);
        int n = 0;
        while (insn != null && n++ < 6000 && f.getBody().contains(insn.getAddress()))
        {
            String mn = insn.getMnemonicString().toLowerCase();
            if (mn.equals("ldur")) mn = "ldr"; else if (mn.equals("stur")) mn = "str";
            String d0 = reg(insn, 0);

            if (mn.equals("add") && "x29".equals(d0) && "x31".equals(reg(insn, 1)))
            {
                Long im = imm(insn, 2); if (im != null) spDelta = im;
            }

            // Track global addresses (adrp/add) so a load from the proxy's BSS global types as ROOT.
            if (mn.equals("adrp"))
            {
                Long im = imm(insn, 1);
                if (d0 != null) { if (im != null) regGlobal.put(d0, im); else regGlobal.remove(d0); regKind.put(d0, null); regTag.remove(d0); }
                insn = insn.getNext();
                continue;
            }
            if (mn.equals("add") && d0 != null && reg(insn, 1) != null && regGlobal.containsKey(reg(insn, 1))
                && !"x31".equals(reg(insn, 1)) && !"x29".equals(reg(insn, 1)))
            {
                Long im = imm(insn, 2);
                if (im != null) regGlobal.put(d0, regGlobal.get(reg(insn, 1)) + im); else regGlobal.remove(d0);
                regKind.put(d0, null); regTag.remove(d0);
                insn = insn.getNext();
                continue;
            }

            if (mn.equals("blr"))
            {
                Object[] k = regKind.get(reg(insn, 0));
                if (k != null && "method".equals(k[0]))
                {
                    String objReg = (String) k[1];
                    long off = (Long) k[2];
                    String writer = rawWriter(objReg, regTag, slotProv);
                    long objVt = objVtable(writer);            // 0 = unverified

                    if (!isControl(off))
                    {
                        if (objVt == 0)
                        {
                            usage.unverified++;
                        }
                        else
                        {
                            Slot slot = offToCmd(objVt).get(off);
                            if (slot == null)
                            {
                                usage.unresolved++;
                            }
                            else
                            {
                                long callSite = insn.getAddress().getOffset();
                                TreeMap<Long, CommandProof> target = (objVt == rootVtable)
                                    ? usage.rootCommands
                                    : usage.subCommandsByOpenCommand
                                        .computeIfAbsent(openCommandOf(writer), key -> new TreeMap<>());
                                target.computeIfAbsent(slot.cmd,
                                        c -> new CommandProof(slot.cmd, off, slot.stub, slot.decodeSite, slot.decodeText))
                                    .callSites.add(callSite);
                            }
                        }
                    }

                    // If this call returns an interface (Open*), type its out-param object.
                    if (objVt != 0)
                    {
                        long subVt = subVtableFor(objVt, off);
                        if (subVt != 0)
                        {
                            Long outSlot = findOutParamSlot(regTag, slotProv);
                            if (outSlot != null)
                            {
                                Slot openSlot = offToCmd(objVt).get(off);
                                slotProv.put(outSlot, "vt:@" + Long.toHexString(subVt) + "|" + (openSlot != null ? openSlot.cmd : -1));
                            }
                        }
                    }
                }
                clearCallerSaved(regKind, regTag, regGlobal);
            }
            else if (mn.equals("bl"))
            {
                String ret = retTag(insn);
                String sret = regTag.get("x8");
                if (sret != null && sret.startsWith("addr:"))
                    slotProv.put(Long.parseLong(sret.substring(5)), ret);
                clearCallerSaved(regKind, regTag, regGlobal);
                regTag.put("x0", ret);
            }
            else if (mn.equals("ldr") && d0 != null)
            {
                long[] mem = memBaseOff(insn);
                regGlobal.remove(d0);
                if (mem != null && regGlobal.containsKey("x" + mem[0]))
                {
                    // Loading the cached proxy pointer out of a global: d0 is the object (ROOT iff it
                    // is the service's proxy global), NOT a vtable.
                    long g = regGlobal.get("x" + mem[0]) + mem[1];
                    regKind.put(d0, null);
                    if (rootGlobal != 0 && g == rootGlobal) regTag.put(d0, "groot"); else regTag.remove(d0);
                }
                else if (mem != null)
                {
                    String base = "x" + mem[0]; long off = mem[1];
                    Object[] bk = regKind.get(base);
                    if (off == 0) regKind.put(d0, new Object[] { "vtable", base });
                    else if (bk != null && "vtable".equals(bk[0])) regKind.put(d0, new Object[] { "method", bk[1], off });
                    else regKind.put(d0, null);
                    if (mem[0] == 31 || mem[0] == 29) regTag.put(d0, "load:" + ((mem[0] == 29) ? off + spDelta : off));
                    else regTag.remove(d0);
                }
                else { regKind.put(d0, null); regTag.remove(d0); }
            }
            else if ((mn.equals("add") || mn.equals("sub")) && d0 != null
                     && ("x31".equals(reg(insn, 1)) || "x29".equals(reg(insn, 1))))
            {
                Long im = imm(insn, 2);
                if (im != null)
                {
                    long base = "x29".equals(reg(insn, 1)) ? spDelta : 0;
                    regTag.put(d0, "addr:" + (mn.equals("sub") ? base - im : base + im));
                }
                regKind.put(d0, null); regGlobal.remove(d0);
            }
            else if (mn.equals("mov") && d0 != null && !"x29".equals(d0)
                     && ("x31".equals(reg(insn, 1)) || "x29".equals(reg(insn, 1))))
            {
                // `mov xN, sp` / `mov xN, x29` == address of a frame slot (add xN, base, #0).
                regTag.put(d0, "addr:" + ("x29".equals(reg(insn, 1)) ? spDelta : 0));
                regKind.put(d0, null); regGlobal.remove(d0);
            }
            else if (mn.equals("mov") && d0 != null && reg(insn, 1) != null)
            {
                // Register copy (e.g. `mov x19, x0` saving an accessor return into a callee-saved reg):
                // propagate the object's provenance, vtable-chain state, and global tag from src to dst.
                String src = reg(insn, 1);
                if (regTag.containsKey(src)) regTag.put(d0, regTag.get(src)); else regTag.remove(d0);
                if (regKind.containsKey(src)) regKind.put(d0, regKind.get(src)); else regKind.put(d0, null);
                if (regGlobal.containsKey(src)) regGlobal.put(d0, regGlobal.get(src)); else regGlobal.remove(d0);
            }
            else if (mn.equals("str") && d0 != null)
            {
                long[] mem = memBaseOff(insn);
                if (mem != null && (mem[0] == 31 || mem[0] == 29))
                {
                    long slot = (mem[0] == 29) ? mem[1] + spDelta : mem[1];
                    String vt = regTag.get(d0);
                    if (vt != null) slotProv.put(slot, vt);
                }
            }
            else if (d0 != null && !readsOperand0(mn)) { regKind.put(d0, null); regTag.remove(d0); regGlobal.remove(d0); }

            insn = insn.getNext();
        }
    }

    /**
     * True if the instruction READS operand 0 rather than writing it (compares, tests, conditional
     * branches on a register, stores). Such instructions must not clear the tracked state of that
     * register -- e.g. a {@code cbz xObj} null-check must not wipe xObj's proxy type.
     */
    private boolean readsOperand0(String mn)
    {
        switch (mn)
        {
            case "cbz": case "cbnz": case "tbz": case "tbnz":
            case "cmp": case "cmn": case "tst": case "ccmp": case "ccmn":
            case "str": case "stp": case "strb": case "strh": case "stur": case "sturb": case "sturh":
                return true;
            default:
                return false;
        }
    }

    private boolean isControl(long off) { return off == 0 || off == 0x8 || off == 0x10 || off == 0x18; }

    /** The tag that TYPED the object: resolve one level of stack-slot indirection. */
    private String rawWriter(String objReg, Map<String, String> regTag, Map<Long, String> slotProv)
    {
        String t = regTag.get(objReg);
        if (t == null) return null;
        if (t.startsWith("load:")) return slotProv.get(Long.parseLong(t.substring(5)));
        return t;
    }

    /** Object's vtable from its writer tag: vt:@addr -> addr; ret:@e -> rootVtable iff e is an accessor. 0 = unknown. */
    private long objVtable(String writer)
    {
        if (writer == null) return 0;
        if (writer.equals("groot")) return rootVtable;   // proxy loaded from the service's BSS global
        if (writer.startsWith("vt:@"))
        {
            String hex = writer.substring(4);
            int bar = hex.indexOf('|');
            if (bar >= 0) hex = hex.substring(0, bar);
            try { return Long.parseLong(hex, 16); } catch (Exception e) { return 0; }
        }
        if (writer.startsWith("ret:@"))
        {
            int bar = writer.indexOf('|');
            String hex = writer.substring(5, bar < 0 ? writer.length() : bar);
            try { if (accessorEntries.contains(Long.parseLong(hex, 16))) return rootVtable; } catch (Exception e) { /* fall */ }
        }
        return 0;
    }

    /** For a SUB object, the root command id that opened its interface (carried in the vt:@..|openCmd tag). */
    private long openCommandOf(String writer)
    {
        if (writer != null && writer.startsWith("vt:@"))
        {
            int bar = writer.indexOf('|');
            if (bar >= 0) { try { return Long.parseLong(writer.substring(bar + 1)); } catch (Exception e) { /* fall */ } }
        }
        return -1;
    }

    private String retTag(Instruction insn)
    {
        String hex = "0";
        if (insn.getFlows().length > 0)
            hex = Long.toHexString(insn.getFlows()[0].getOffset());
        return "ret:@" + hex;
    }

    /** Out-interface param of an Open*: arg reg x1..x7 tagged addr:S; double-indirect holder -> inner slot. */
    private Long findOutParamSlot(Map<String, String> regTag, Map<Long, String> slotProv)
    {
        for (int i = 1; i <= 7; i++)
        {
            String t = regTag.get("x" + i);
            if (t == null || !t.startsWith("addr:")) continue;
            long s = Long.parseLong(t.substring(5));
            String inner = slotProv.get(s);
            if (inner != null && inner.startsWith("addr:")) return Long.parseLong(inner.substring(5));
            return s;
        }
        return null;
    }

    private void clearCallerSaved(Map<String, Object[]> regKind, Map<String, String> regTag,
                                  Map<String, Long> regGlobal)
    {
        for (int i = 0; i <= 18; i++) { regKind.put("x" + i, null); regTag.remove("x" + i); regGlobal.remove("x" + i); }
    }

    // ---- sub-interface vtable resolution ----
    private long subVtableFor(long vtableUsed, long off)
    {
        String key = Long.toHexString(vtableUsed) + ":" + off;
        Long cached = subVtCache.get(key);
        if (cached != null) return cached;
        long structural = 0;
        try
        {
            Address stub = addr(memory.getLong(addr(vtableUsed + off)));
            if (memory.getBlock(stub) != null)
            {
                Address subVt = extractSubVtable(stub);
                if (subVt != null) structural = subVt.getOffset();
            }
        }
        catch (Exception e) { /* leave 0 */ }

        // Trust the structural result ONLY when it landed on a real RTTI-named interface vtable. In SDK
        // 22+ the lazy/template install makes the scan land on an unnamed base/session vtable instead --
        // non-zero but wrong -- which would mask the correct sub-interface; for those, resolve the Open*'s
        // out-interface from the database and use its RTTI proxy vtable.
        long sub;
        if (structural != 0 && vtableDecodeCount(structural) >= 1)
            sub = structural;                                  // landed on a real command vtable -> trust it
        else
        {
            long rtti = subVtableViaRtti(vtableUsed, off);
            sub = rtti != 0 ? rtti : structural;
        }

        subVtCache.put(key, sub);
        return sub;
    }

    private Address extractSubVtable(Address stubEntry)
    {
        Address a = stubEntry;
        for (int i = 0; i < 80 && a != null; i++)
        {
            Instruction insn = at(a);
            if (insn == null) break;
            String mn = insn.getMnemonicString().toLowerCase();
            if (mn.equals("bl") && insn.getFlows().length > 0)
            {
                Address vt = vtableInstalledAtOffsetZero(insn.getFlows()[0]);
                if (vt != null) return vt;
            }
            if (mn.equals("ret")) break;
            a = nextAddr(insn);
        }
        return null;
    }

    private Address vtableInstalledAtOffsetZero(Address entry)
    {
        Map<String, Long> rc = new HashMap<>();
        Address a = entry;
        for (int i = 0; i < 1500 && a != null; i++)
        {
            Instruction insn = at(a);
            if (insn == null) break;
            String mn = insn.getMnemonicString().toLowerCase();
            String d0 = op(insn, 0);
            if (mn.equals("adrp")) { Long im = imm(insn, 1); if (d0 != null && im != null) rc.put(d0, im); }
            else if (mn.equals("add"))
            {
                String s = op(insn, 1); Long im = imm(insn, 2);
                if (d0 != null && s != null && im != null && rc.containsKey(s)) rc.put(d0, rc.get(s) + im);
                else if (d0 != null) rc.remove(d0);
            }
            else if (mn.equals("str") || mn.equals("stur") || mn.equals("stp"))
            {
                String v = op(insn, 0);
                long[] mem = memBaseOff(insn);
                if (mem != null && mem[1] == 0 && v != null && rc.containsKey(v))
                {
                    Address cand = addr(rc.get(v));
                    if (memory.getBlock(cand) != null) return cand;
                }
            }
            else if (d0 != null) rc.remove(d0);
            if (mn.equals("ret")) break;
            a = nextAddr(insn);
        }
        return null;
    }

    private Address nextAddr(Instruction insn)
    {
        Address ft = insn.getFallThrough();
        if (ft != null) return ft;
        if (insn.getMnemonicString().equalsIgnoreCase("b") && insn.getFlows().length == 1) return insn.getFlows()[0];
        return null;
    }

    // ---- vtable decode (cached) ----
    private Map<Long, Slot> offToCmd(long vtable)
    {
        Map<Long, Slot> cached = offToCmdCache.get(vtable);
        if (cached != null) return cached;
        Map<Long, Slot> m = new TreeMap<>();
        for (int i = 4; i < 256; i++)
        {
            long off = (long) i * 8; long val;
            try { val = memory.getLong(addr(vtable + off)); } catch (Exception e) { break; }
            Address stub = addr(val);
            if (memory.getBlock(stub) == null) continue;
            Decoded decoded = decodeCmd(stub);
            if (decoded != null) m.put(off, new Slot(decoded.cmd, val, decoded.site, decoded.text));
        }
        offToCmdCache.put(vtable, m);
        return m;
    }

    /** Decode a stub to {commandId, decode-site address, decode-site instruction text}. */
    private Decoded decodeCmd(Address start)
    {
        for (int hop = 0; hop < 2 && start != null; hop++)
        {
            Address a = start; Address tail = null;
            Long lastImm = null; long lastImmAddr = 0; String lastImmText = null; int lastIdx = -100;
            // SDK 22.x abstracted per-command stubs into 3-instruction thunks
            // (`add x0,#8; mov w<reg>,#cmdId; b <sharedDispatcher>`) where the cmd-id
            // register varies and can be w1 (older stubs always used w2..w7, with w1 a
            // normal arg). Track w1 separately and only fall back to it when no w2..w7
            // immediate was seen, so older stubs do not regress.
            Long lastImm1 = null; long lastImm1Addr = 0; String lastImm1Text = null; int lastIdx1 = -100;
            for (int i = 0; i < 36 && a != null; i++)
            {
                Instruction insn = at(a);
                if (insn == null) break;
                String mn = insn.getMnemonicString().toLowerCase();
                if (mn.equals("mov") || mn.equals("movz"))
                {
                    String dr = op(insn, 0);
                    boolean is27 = dr != null && dr.matches("[wx][2-7]");
                    boolean is1  = dr != null && dr.matches("[wx]1");
                    if (is27 || is1)
                    {
                        String src = op(insn, 1);
                        // command id 0 is emitted as `mov w2, wzr` (zero register), not an immediate.
                        Long im = ("wzr".equals(src) || "xzr".equals(src)) ? Long.valueOf(0) : imm(insn, 1);
                        if (im != null && im >= 0 && im <= 0xFFFF)
                        {
                            if (is27)
                            {
                                lastImm = im; lastImmAddr = insn.getAddress().getOffset();
                                lastImmText = instructionText(insn); lastIdx = i;
                            }
                            else
                            {
                                lastImm1 = im; lastImm1Addr = insn.getAddress().getOffset();
                                lastImm1Text = instructionText(insn); lastIdx1 = i;
                            }
                        }
                    }
                }
                if (mn.equals("bl") || mn.equals("b") || mn.equals("blr") || mn.equals("br"))
                {
                    if (lastImm != null && i - lastIdx <= 8) return new Decoded(lastImm, lastImmAddr, lastImmText);
                    if (lastImm1 != null && i - lastIdx1 <= 8) return new Decoded(lastImm1, lastImm1Addr, lastImm1Text);
                    if (mn.equals("b") && insn.getFlows().length > 0) { tail = insn.getFlows()[0]; break; }
                }
                if (mn.equals("ret")) break;
                a = insn.getFallThrough();
            }
            start = tail;
        }
        return null;
    }

    /** Mnemonic + operands, e.g. "mov w4,#0x23" or "mov w2,wzr". */
    private String instructionText(Instruction insn)
    {
        StringBuilder sb = new StringBuilder(insn.getMnemonicString());
        for (int i = 0; i < insn.getNumOperands(); i++)
            sb.append(i == 0 ? " " : ",").append(insn.getDefaultOperandRepresentation(i));
        return sb.toString();
    }

    // ---- graph + vtable-install helpers ----
    private Set<Function> connectorsFor(String svc)
    {
        Set<Function> out = new LinkedHashSet<>();
        for (Data d : listing.getDefinedData(true))
        {
            if (d == null || !(d.getValue() instanceof String) || !svc.equals(d.getValue())) continue;
            for (Reference r : refMgr.getReferencesTo(d.getAddress()))
            {
                Function f = fnMgr.getFunctionContaining(r.getFromAddress());
                if (f != null) out.add(f);
            }
        }
        return out;
    }

    private Set<Function> callersUpTo(Function start, int depth)
    {
        Set<Function> seen = new LinkedHashSet<>();
        Set<Function> frontier = new LinkedHashSet<>();
        frontier.add(start);
        for (int d = 0; d < depth; d++)
        {
            Set<Function> next = new LinkedHashSet<>();
            for (Function f : frontier)
                for (Reference r : refMgr.getReferencesTo(f.getEntryPoint()))
                {
                    Function caller = fnMgr.getFunctionContaining(r.getFromAddress());
                    if (caller != null && seen.add(caller)) next.add(caller);
                }
            frontier = next;
            if (frontier.isEmpty()) break;
        }
        return seen;
    }

    /**
     * Recover the proxy vtable a connector installs. Handles three patterns: the inline install
     * ({@code adrp/add <vtable>; str <reg>,[obj,#0]}) and the lazy-singleton accessor where the vtable
     * is loaded from the GOT ({@code adrp/ldr}) and installed inside a factory callee. BFS the connector
     * and its callees, track adrp/add (addresses) and adrp/ldr (GOT-loaded pointers), and pick the
     * candidate that VALIDATES as a CMIF client vtable (its slots decode as command stubs), preferring
     * the one stored at object offset 0. Validation is what filters out non-vtable data the heuristic
     * would otherwise grab.
     */
    private Address extractInstalledVtable(Function connector)
    {
        long bestStrZero = -1; int bestStrZeroCount = -1;   // validated vtable installed at [obj,#0]
        long bestLoaded  = -1; int bestLoadedCount  = -1;   // validated vtable loaded from the GOT

        for (Function f : calleeClosure(connector, 3))
        {
            Map<String, Long> rc = new HashMap<>();
            int n = 0;
            for (Instruction insn = firstInstruction(f);
                 insn != null && n++ < 4000 && f.getBody().contains(insn.getAddress());
                 insn = insn.getNext())
            {
                String mn = insn.getMnemonicString().toLowerCase();
                String d0 = op(insn, 0);
                if (mn.equals("adrp")) { Long im = imm(insn, 1); if (d0 != null && im != null) rc.put(d0, im); }
                else if (mn.equals("add"))
                {
                    String s = op(insn, 1); Long im = imm(insn, 2);
                    if (d0 != null && s != null && im != null && rc.containsKey(s)) rc.put(d0, rc.get(s) + im);
                    else if (d0 != null) rc.remove(d0);
                }
                else if (mn.equals("ldr"))
                {
                    long[] mem = memBaseOff(insn);
                    if (d0 != null && mem != null && rc.containsKey("x" + mem[0]))
                    {
                        try
                        {
                            long v = memory.getLong(addr(rc.get("x" + mem[0]) + mem[1]));   // GOT slot value
                            rc.put(d0, v);
                            int c = vtableDecodeCount(v);
                            if (c > bestLoadedCount) { bestLoadedCount = c; bestLoaded = v; }
                        }
                        catch (Exception e) { rc.remove(d0); }
                    }
                    else if (d0 != null) rc.remove(d0);
                }
                else if (mn.equals("str") || mn.equals("stp"))
                {
                    String v = op(insn, 0); long[] mem = memBaseOff(insn);
                    if (mem != null && mem[1] == 0 && v != null && rc.containsKey(v))
                    {
                        int c = vtableDecodeCount(rc.get(v));
                        if (c > bestStrZeroCount) { bestStrZeroCount = c; bestStrZero = rc.get(v); }
                    }
                }
                else if (d0 != null) rc.remove(d0);
            }
        }

        // Prefer the inline str-at-[obj,#0] install (stronger positional evidence) over GOT-loaded.
        // Count >= 1 is enough: in SDK 22+ Nintendo LTO-strips unused proxy stubs, leaving fewer than
        // 4 decodable slots for services with few actively-invoked commands. The adrp/add/str pattern
        // in a service-connector callee closure is already specific enough that any decodable stub at
        // slot 4+ is sufficient evidence this is a CMIF proxy vtable, not a coincidental data store.
        if (bestStrZeroCount >= 1) return addr(bestStrZero);
        if (bestLoadedCount >= 1) return addr(bestLoaded);
        return null;
    }

    /** The connector plus its transitive callees up to {@code depth} (capped), for vtable scanning. */
    private Set<Function> calleeClosure(Function start, int depth)
    {
        Set<Function> seen = new LinkedHashSet<>();
        Set<Function> frontier = new LinkedHashSet<>();
        seen.add(start); frontier.add(start);
        for (int d = 0; d < depth && seen.size() < 120; d++)
        {
            Set<Function> next = new LinkedHashSet<>();
            for (Function f : frontier)
                for (Instruction insn = firstInstruction(f);
                     insn != null && f.getBody().contains(insn.getAddress());
                     insn = insn.getNext())
                    if (insn.getMnemonicString().equalsIgnoreCase("bl") && insn.getFlows().length > 0)
                    {
                        Function c = fnMgr.getFunctionContaining(insn.getFlows()[0]);
                        if (c != null && seen.add(c)) next.add(c);
                    }
            frontier = next;
            if (frontier.isEmpty()) break;
        }
        return seen;
    }

    /**
     * The BSS global a lazy-singleton connector caches its proxy in: scan the connector for a global
     * address (adrp/add) whose loaded value (`ldr obj,[global]`) flows into a virtual call
     * (`ldr vt,[obj]; ldr m,[vt,#off]; blr m`). Returns that global, or 0 (accessor pattern instead).
     */
    private long findProxyGlobal(Function f)
    {
        Map<String, Long> gaddr = new HashMap<>();   // reg -> computed global address (adrp/add)
        Map<String, Long> taint = new HashMap<>();   // reg -> the global it derives from (obj/vt/method chain)
        int n = 0;
        for (Instruction insn = firstInstruction(f); insn != null && n++ < 4000 && f.getBody().contains(insn.getAddress()); insn = insn.getNext())
        {
            String mn = insn.getMnemonicString().toLowerCase();
            if (mn.equals("ldur")) mn = "ldr";
            String d0 = reg(insn, 0);
            if (mn.equals("adrp")) { Long im = imm(insn, 1); if (d0 != null && im != null) { gaddr.put(d0, im); taint.remove(d0); } }
            else if (mn.equals("add"))
            {
                String s = reg(insn, 1); Long im = imm(insn, 2);
                if (d0 != null && s != null && im != null && gaddr.containsKey(s)) { gaddr.put(d0, gaddr.get(s) + im); taint.remove(d0); }
                else if (d0 != null) { gaddr.remove(d0); taint.remove(d0); }
            }
            else if (mn.equals("ldr"))
            {
                long[] mem = memBaseOff(insn);
                if (d0 != null && mem != null)
                {
                    String base = "x" + mem[0]; long off = mem[1];
                    gaddr.remove(d0);
                    if (gaddr.containsKey(base)) taint.put(d0, gaddr.get(base) + off);   // obj = [global]
                    else if (taint.containsKey(base)) taint.put(d0, taint.get(base));     // vt=[obj] / m=[vt] -> propagate
                    else taint.remove(d0);
                }
                else if (d0 != null) { gaddr.remove(d0); taint.remove(d0); }
            }
            else if (mn.equals("blr"))
            {
                String m = reg(insn, 0);
                if (m != null && taint.containsKey(m)) return taint.get(m);
                for (int i = 0; i <= 18; i++) { taint.remove("x" + i); gaddr.remove("x" + i); }
            }
            else if (mn.equals("bl")) { for (int i = 0; i <= 18; i++) { taint.remove("x" + i); gaddr.remove("x" + i); } }
            else if (d0 != null && !readsOperand0(mn)) { gaddr.remove(d0); taint.remove(d0); }
        }
        return 0;
    }

    /** Number of slots (skipping the 4 control slots) of a candidate vtable that decode as command stubs. */
    private int vtableDecodeCount(long vtableAddr)
    {
        Integer cached = vtableValidationCache.get(vtableAddr);
        if (cached != null) return cached;

        int count = 0;
        if (memory.getBlock(addr(vtableAddr)) != null)
        {
            for (int i = 4; i < 48; i++)
            {
                long val;
                try { val = memory.getLong(addr(vtableAddr + (long) i * 8)); } catch (Exception e) { break; }
                Address stub = addr(val);
                if (memory.getBlock(stub) == null) continue;
                if (decodeCmd(stub) != null) count++;
            }
        }
        vtableValidationCache.put(vtableAddr, count);
        return count;
    }

    // ---- low-level ----
    private Address addr(long off) { return program.getAddressFactory().getDefaultAddressSpace().getAddress(off); }

    private Instruction firstInstruction(Function f)
    {
        return listing.getInstructions(f.getBody(), true).hasNext()
            ? listing.getInstructions(f.getBody(), true).next() : null;
    }

    /**
     * Strictly READ-ONLY instruction lookup. This tracer runs inside the program DB during analysis;
     * it must never mutate the program. In particular it must NOT disassemble -- vtable slots read out
     * of range point into data, and disassembling those would corrupt the program (and break later
     * pointer markup with "Conflicting instruction exists"). Already-analysed stubs are real code, so
     * returning null for anything not already an instruction is both safe and sufficient.
     */
    private Instruction at(Address a)
    {
        return listing.getInstructionAt(a);
    }

    private String reg(Instruction insn, int i)
    {
        String s = op(insn, i);
        if (s != null && s.matches("[xw]\\d+")) return "x" + s.substring(1);
        if ("sp".equals(s) || "wsp".equals(s)) return "x31";
        return null;
    }

    private String op(Instruction insn, int i)
    {
        String s = insn.getDefaultOperandRepresentation(i);
        return s == null ? null : s.trim().toLowerCase();
    }

    private Long imm(Instruction insn, int i) { return parseImm(op(insn, i)); }

    private Long parseImm(String s)
    {
        if (s == null) return null;
        s = s.replace("#", "").trim();
        long sign = 1;
        if (s.startsWith("-")) { sign = -1; s = s.substring(1); } else if (s.startsWith("+")) s = s.substring(1);
        try { return sign * (s.startsWith("0x") ? Long.parseLong(s.substring(2), 16) : Long.parseLong(s)); }
        catch (Exception e) { return null; }
    }

    private long[] memBaseOff(Instruction insn)
    {
        for (int i = 0; i < insn.getNumOperands(); i++)
        {
            String o = insn.getDefaultOperandRepresentation(i);
            if (o == null || o.indexOf('[') < 0) continue;
            o = o.toLowerCase().replace("[", "").replace("]", "").replace("!", "").trim();
            String[] p = o.split(",");
            String base = p[0].trim();
            long baseId;
            if (base.matches("[xw]\\d+")) baseId = Long.parseLong(base.substring(1));
            else if (base.equals("sp") || base.equals("wsp")) baseId = 31;
            else return null;
            long off = 0;
            if (p.length > 1) { Long v = parseImm(p[1]); if (v == null) return null; off = v; }
            return new long[] { baseId, off };
        }
        return null;
    }
}
