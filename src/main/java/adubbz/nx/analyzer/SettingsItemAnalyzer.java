package adubbz.nx.analyzer;

import adubbz.nx.loader.SwitchLoader;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Marks nn::settings::fwdbg item lookups (GetSettingsItemValue, GetSettingsItemValueSize, ...).
 *
 * For every known settings name (e.g. "ns.application") present in the program, each xref to the
 * name string is visited and the key string loaded beside it (e.g. "qualification_rule") is
 * resolved. The xref address then gets an Analysis bookmark (category = name, comment = key),
 * a label ns.application["qualification_rule"] and an EOL comment ns.application [ "qualification_rule" ].
 */
public class SettingsItemAnalyzer extends AbstractAnalyzer
{
    public static final String[] SETTINGS_NAMES = {
        "account", "account.daemon", "am.debug", "am.display", "am.gpu", "am.pfcfg", "apm", "audio",
        "bcat", "bgtc", "btp", "bluetooth_config", "bluetooth_debug", "boot", "bpc", "bsp0", "btm",
        "btm.recovery", "btp_config", "capsrv", "cec", "contents_delivery", "creport", "cs", "dauth",
        "devmenu", "eclct", "erpt", "eth", "err", "es", "eupld", "fatal", "friends", "gpu_core_dump",
        "hdcp", "hid", "hid_debug", "htc", "htcnet", "mnpp", "ndim", "ndrm.low", "netdiag", "idle",
        "jit_debug", "lbl", "ldn", "lm", "migration", "mii", "nd", "news", "nfc", "nfp", "ngc.t",
        "nifm", "nim.install", "nim.vphym", "nim.pfcfg", "notification.presenter", "npns",
        "ns.applet", "ns.application", "ns.autoboot", "ns.factoryreset", "ns.gamecard",
        "ns.notification", "ns.promotion", "ns.pseudodeviceid", "ns.rights", "ns.sdcard", "ns.vphym",
        "ns.vulnerability", "ns.systemupdate", "ns.ticket", "nsd", "ntc", "nv", "nvservices", "olsc",
        "omm", "pcie", "pcm", "pctl", "pdm", "platformconfig", "prepo", "productinfo", "psm",
        "push_notification", "ro", "settings_debug", "ssl.test", "sio_hoag", "snap_shot_dump",
        "sprofile", "systemconfig", "systeminitializer", "systempowerstate", "systemreport",
        "systemsleep", "systemstartup", "systemupdate", "target_manager", "tc", "tcap",
        "tc.low-temperature-burn", "time", "ts", "usb", "vi", "vulnerability", "wlan_debug",
        "wlan_config",
    };

    /* How far to look around the name xref for the key load; stops early at calls/branches. */
    private static final int WINDOW = 12;
    private static final int MAX_STR = 128;
    /* fwdbg keys are lower snake_case; filters stray strings ("1", language codes like "es-419"). */
    private static final Pattern KEY_RE = Pattern.compile("[a-z][a-z0-9_.]{2,}");

    public SettingsItemAnalyzer()
    {
        super("(Switch) Settings Item Analyzer", "Bookmarks and labels nn::settings::fwdbg name/key lookups.", AnalyzerType.INSTRUCTION_ANALYZER);

        this.setPriority(AnalysisPriority.LOW_PRIORITY);
        this.setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean getDefaultEnablement(Program program)
    {
        return true;
    }

    @Override
    public boolean canAnalyze(Program program)
    {
        return program.getExecutableFormat().equals(SwitchLoader.SWITCH_NAME);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException
    {
        Result result = markSettingsItems(program, set, Arrays.asList(SETTINGS_NAMES), monitor);
        if (result.marked > 0)
            Msg.info(this, String.format("Marked %d settings item lookups (%d names) in %s, %d unresolved",
                result.marked, result.keys.size(), program.getName(),
                result.unresolved.values().stream().mapToInt(List::size).sum()));
        return true;
    }

    public static final class Result
    {
        public int found;
        public int marked;
        /* name -> key -> number of marked call sites */
        public final Map<String, Map<String, Integer>> keys = new TreeMap<>();
        /* name -> xrefs whose key could not be resolved (usually a non-settings use of the word) */
        public final Map<String, List<Address>> unresolved = new TreeMap<>();
    }

    private record Candidate(String key, int dist, boolean regMatch) {}

    /**
     * Marks every settings lookup whose name xref lies in {@code restrictTo} (null = whole program).
     * Safe to re-run: bookmarks are replaced, labels and comments are not duplicated.
     */
    public static Result markSettingsItems(Program program, AddressSetView restrictTo, Collection<String> names,
        TaskMonitor monitor) throws CancelledException
    {
        return new Marker(program, names).run(restrictTo, monitor);
    }

    private static final class Marker
    {
        private final Program program;
        private final Listing listing;
        private final Memory memory;
        private final Set<String> names;

        Marker(Program program, Collection<String> names)
        {
            this.program = program;
            this.listing = program.getListing();
            this.memory = program.getMemory();
            this.names = new LinkedHashSet<>(names);
        }

        Result run(AddressSetView restrictTo, TaskMonitor monitor) throws CancelledException
        {
            Result result = new Result();
            Map<String, List<Address>> found = this.findNameStrings(monitor);
            result.found = found.size();

            for (Map.Entry<String, List<Address>> e : found.entrySet())
            {
                String name = e.getKey();
                for (Address str : e.getValue())
                {
                    for (Reference r : program.getReferenceManager().getReferencesTo(str))
                    {
                        monitor.checkCancelled();
                        Address from = r.getFromAddress();
                        /* ldrb etc. reading the string's bytes is not a lookup argument. */
                        if (r.getReferenceType().isRead() || (restrictTo != null && !restrictTo.contains(from)))
                            continue;

                        String key = this.resolveKey(from, name, str);
                        if (key == null)
                        {
                            result.unresolved.computeIfAbsent(name, k -> new ArrayList<>()).add(from);
                            continue;
                        }

                        this.mark(from, name, key);
                        result.keys.computeIfAbsent(name, k -> new TreeMap<>()).merge(key, 1, Integer::sum);
                        result.marked++;
                    }
                }
            }
            return result;
        }

        /* Locate every NUL-terminated occurrence of each settings name in initialized, non-code memory. */
        private Map<String, List<Address>> findNameStrings(TaskMonitor monitor) throws CancelledException
        {
            Set<Integer> lengths = new TreeSet<>();
            for (String n : names)
                lengths.add(n.length());

            Map<String, List<Address>> out = new TreeMap<>();
            for (MemoryBlock b : memory.getBlocks())
            {
                monitor.checkCancelled();
                if (!b.isInitialized() || b.isExecute() || b.getSize() > Integer.MAX_VALUE)
                    continue;

                byte[] buf = new byte[(int) b.getSize()];
                try
                {
                    b.getBytes(b.getStart(), buf);
                }
                catch (MemoryAccessException e)
                {
                    continue;
                }

                for (int i = 0; i < buf.length; i++)
                {
                    if (buf[i] != 0)
                        continue;

                    for (int len : lengths)
                    {
                        int s = i - len;
                        if (s < 0)
                            break;

                        String cand = new String(buf, s, len, StandardCharsets.ISO_8859_1);
                        if (!names.contains(cand))
                            continue;

                        Address a = b.getStart().add(s);
                        /* Accept tail-merged strings only if something actually points at them. */
                        if (s == 0 || buf[s - 1] == 0 || program.getReferenceManager().getReferenceCountTo(a) > 0)
                            out.computeIfAbsent(cand, k -> new ArrayList<>()).add(a);
                    }
                }
            }
            return out;
        }

        private String resolveKey(Address from, String name, Address nameAddr)
        {
            Instruction insn = listing.getInstructionAt(from);
            if (insn == null)
                return this.resolveKeyFromData(from, name, nameAddr);

            /* { name, key } pair built on the stack: stp xN,xM,[sp,...] carries both refs. */
            String same = this.stringLoadedBy(insn, name, nameAddr);
            if (same != null)
                return same;

            /* fwdbg APIs take (..., name, key): key is loaded into the register right after name's. */
            int nameReg = regIndex(insn.getRegister(0));
            Candidate best = null;
            for (int dir : new int[] { 1, -1 })
            {
                Instruction cur = insn;
                for (int d = 1; d <= WINDOW; d++)
                {
                    cur = dir > 0 ? cur.getNext() : cur.getPrevious();
                    if (cur == null || isBarrier(cur, dir))
                        break;

                    String key = this.stringLoadedBy(cur, name, nameAddr);
                    if (key == null)
                        continue;

                    boolean regMatch = nameReg >= 0 && regIndex(cur.getRegister(0)) == nameReg + 1;
                    Candidate c = new Candidate(key, dir > 0 ? d : d + WINDOW, regMatch);
                    if (best == null || (c.regMatch && !best.regMatch)
                        || (c.regMatch == best.regMatch && c.dist < best.dist))
                        best = c;
                }
            }
            return best == null ? null : best.key;
        }

        /* Pointer tables of { name, key } (or { key, name }) pairs. */
        private String resolveKeyFromData(Address from, String name, Address nameAddr)
        {
            Data d = listing.getDataContaining(from);
            if (d == null || !d.isPointer())
                return null;

            for (long off : new long[] { 8, -8 })
            {
                try
                {
                    Address p = from.getNewAddress(memory.getLong(from.add(off)));
                    String s = this.readKey(p, name, nameAddr);
                    if (s != null)
                        return s;
                }
                catch (MemoryAccessException | AddressOutOfBoundsException e)
                {
                    // not a pointer
                }
            }
            return null;
        }

        private static boolean isBarrier(Instruction insn, int dir)
        {
            FlowType ft = insn.getFlowType();
            /* Walking forward the call itself ends the window; walking backward any earlier branch does. */
            return ft.isCall() || ft.isTerminal() || (ft.isJump() && ft.isUnConditional())
                || (dir < 0 && ft.isJump());
        }

        private String stringLoadedBy(Instruction insn, String name, Address nameAddr)
        {
            if ("adrp".equals(insn.getMnemonicString()))
                return null;

            for (Reference r : insn.getReferencesFrom())
            {
                String s = this.readKey(r.getToAddress(), name, nameAddr);
                if (s != null)
                    return s;
            }
            return null;
        }

        private String readKey(Address a, String name, Address nameAddr)
        {
            if (a == null || !a.isMemoryAddress())
                return null;

            /* Pointers into the name string itself (e.g. "account" + 1 -> "ccount"). */
            if (a.getAddressSpace().equals(nameAddr.getAddressSpace())
                && a.getOffset() >= nameAddr.getOffset() && a.getOffset() <= nameAddr.getOffset() + name.length())
                return null;

            MemoryBlock b = memory.getBlock(a);
            if (b == null || !b.isInitialized() || b.isExecute())
                return null;

            StringBuilder sb = new StringBuilder();
            try
            {
                for (int i = 0; i < MAX_STR; i++)
                {
                    byte c = memory.getByte(a.add(i));
                    if (c == 0)
                        break;
                    sb.append((char) (c & 0xff));
                }
            }
            catch (MemoryAccessException | AddressOutOfBoundsException e)
            {
                return null;
            }

            String s = sb.toString();
            if (s.length() >= MAX_STR || !KEY_RE.matcher(s).matches() || s.equals(name) || names.contains(s))
                return null;
            return s;
        }

        private static int regIndex(Register r)
        {
            if (r == null)
                return -1;

            String n = r.getName().toLowerCase();
            if (n.length() < 2 || (n.charAt(0) != 'x' && n.charAt(0) != 'w'))
                return -1;

            try
            {
                return Integer.parseInt(n.substring(1));
            }
            catch (NumberFormatException e)
            {
                return -1;
            }
        }

        private void mark(Address at, String name, String key)
        {
            program.getBookmarkManager().setBookmark(at, BookmarkType.ANALYSIS, name, key);

            String label = name + "[\"" + key + "\"]";
            boolean have = false;
            for (Symbol s : program.getSymbolTable().getSymbols(at))
            {
                if (s.getName().equals(label))
                {
                    have = true;
                    break;
                }
            }

            if (!have)
            {
                try
                {
                    program.getSymbolTable().createLabel(at, label, SourceType.ANALYSIS);
                }
                catch (Exception e)
                {
                    Msg.warn(SettingsItemAnalyzer.class, "Failed to label " + at + " as " + label + ": " + e.getMessage());
                }
            }

            String cmt = name + " [ \"" + key + "\" ]";
            CodeUnit cu = listing.getCodeUnitAt(at);
            if (cu != null)
            {
                String old = cu.getComment(CommentType.EOL);
                if (old == null)
                    cu.setComment(CommentType.EOL, cmt);
                else if (!old.contains(cmt))
                    cu.setComment(CommentType.EOL, old + "\n" + cmt);
            }
        }
    }
}
