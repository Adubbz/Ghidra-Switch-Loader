// Import an Atmosphère creport crash report (.log, "Atmosphère Crash Report (v1.x)") as bookmarks.
// Maps runtime addresses to the loaded program via: ghidra = imageBase + (addr - module start),
// where the module is one entry of the report's "Module Info" list (picked in a dialog).
//@category Switch

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

public class ImportCrashReport extends GhidraScript {

    /* creport reports raw runtime addresses and module starts; the NSO header is not mapped, so 0. */
    private static final long HEADER_ADJUST = 0;
    private static final boolean SCAN_STACK_DUMP = true;
    private static final boolean SCAN_STACK_DUMP_ALL_THREADS = false;
    private static final boolean ALL_THREADS = true;

    private static final String TYPE = "Info";
    private static final String CAT_IPC = "Crash/IPC";
    private static final String CAT_EXC = "Crash/Exception";

    private static final String[] HIPC_TYPES = {
        "Invalid", "LegacyRequest", "Close", "LegacyControl", "Request", "Control", "RequestWithContext", "ControlWithContext"
    };
    /* CMIF control commands are interface-independent. */
    private static final String[] CMIF_CONTROL = {
        "ConvertCurrentObjectToDomain", "CopyFromCurrentDomain", "CloneCurrentObject", "QueryPointerBufferSize", "CloneCurrentObjectEx"
    };

    private static final Pattern RE_RESULT = Pattern.compile("^Result:\\s+(0x[0-9A-Fa-f]+)\\s+\\((\\d+-\\d+)\\)");
    private static final Pattern RE_PROC = Pattern.compile("^Process Name:\\s+(.*)$");
    private static final Pattern RE_PID = Pattern.compile("^Program ID:\\s+([0-9A-Fa-f]+)");
    private static final Pattern RE_TYPE = Pattern.compile("^Type:\\s+(.*)$");
    private static final Pattern RE_ADDR = Pattern.compile("^(Address|Fault Address|Break Address):\\s+([0-9A-Fa-f]{8,16})\\b");
    private static final Pattern RE_MODHDR = Pattern.compile("^Module\\s+(\\d+):");
    private static final Pattern RE_RANGE = Pattern.compile("^Address:\\s+([0-9A-Fa-f]{8,16})-([0-9A-Fa-f]{8,16})");
    private static final Pattern RE_NAME = Pattern.compile("^Name:\\s+(.*)$");
    private static final Pattern RE_ID = Pattern.compile("^Module Id:\\s+([0-9A-Fa-f]+)");
    private static final Pattern RE_TID = Pattern.compile("^Thread ID:\\s+([0-9A-Fa-f]+)");
    private static final Pattern RE_TNAME = Pattern.compile("^Thread Name:\\s+(.*)$");
    private static final Pattern RE_REG = Pattern.compile("^([A-Za-z]+(?:\\[\\d+\\])?):\\s+([0-9A-Fa-f]{8,16})\\b");
    private static final Pattern RE_RA = Pattern.compile("^ReturnAddress\\[(\\d+)\\]:\\s+([0-9A-Fa-f]{8,16})\\b");
    private static final Pattern RE_ROW = Pattern.compile("^([0-9A-Fa-f]{8,16})((?:\\s+[0-9A-Fa-f]{2}){16})\\s*$");

    private enum Top { NONE, PROC, EXC, CRASHED, DYING, MODS, THREADS }
    private enum Sub { NONE, REGS, TRACE, STACK, TLS }

    private static class Mod {
        int index;
        long start, end;
        String name = "?", id = "";
    }

    private static class Ent {
        final String name;
        final long v;
        Ent(String name, long v) { this.name = name; this.v = v; }
    }

    private static class Thr {
        final String label;
        long id = -1;
        String name = "";
        final List<Ent> regs = new ArrayList<>();
        final List<Ent> trace = new ArrayList<>();
        final ByteArrayOutputStream stack = new ByteArrayOutputStream();
        long stackBase = -1;
        final ByteArrayOutputStream tls = new ByteArrayOutputStream();
        Thr(String label) { this.label = label; }
    }

    private Sub sub = Sub.NONE;
    private Address imageBase;
    private long imageSize, modStart, modEnd;

    @Override
    protected void run() throws Exception {
        File f = askFile("Atmosphere crash report", "Import");
        List<String> lines = Files.readAllLines(f.toPath());
        if (!lines.isEmpty() && lines.get(0).contains("Fatal Report")) {
            printerr("This is a fatal report; use ImportFatalReport");
            return;
        }

        String result = "", proc = "", pid = "", excType = "";
        StringBuilder excNotes = new StringBuilder();
        List<Ent> exc = new ArrayList<>();
        List<Mod> mods = new ArrayList<>();
        List<Thr> threads = new ArrayList<>();
        Top top = Top.NONE;
        Thr cur = null;
        Mod curMod = null;

        for (String raw : lines) {
            String t = raw.trim();
            if (t.isEmpty()) continue;
            Matcher m;

            if (!Character.isWhitespace(raw.charAt(0))) {
                if (t.startsWith("Process Info")) top = Top.PROC;
                else if (t.startsWith("Exception Info")) top = Top.EXC;
                else if (t.startsWith("Crashed Thread Info")) {
                    top = Top.CRASHED;
                    cur = new Thr("Crashed");
                    threads.add(cur);
                    sub = Sub.NONE;
                } else if (t.startsWith("Dying Message Info")) top = Top.DYING;
                else if (t.startsWith("Module Info")) top = Top.MODS;
                else if (t.startsWith("Thread Report")) { top = Top.THREADS; cur = null; }
                else if ((m = RE_RESULT.matcher(t)).find()) result = m.group(1) + " (" + m.group(2) + ")";
                continue;
            }

            switch (top) {
            case PROC:
                if ((m = RE_PROC.matcher(t)).find()) proc = m.group(1).trim();
                else if ((m = RE_PID.matcher(t)).find()) pid = m.group(1);
                break;
            case EXC:
                if ((m = RE_TYPE.matcher(t)).find()) excType = m.group(1).trim();
                else if ((m = RE_ADDR.matcher(t)).find()) exc.add(new Ent(m.group(1), Long.parseUnsignedLong(m.group(2), 16)));
                else excNotes.append(t).append("; ");
                break;
            case MODS:
                if ((m = RE_MODHDR.matcher(t)).find()) {
                    curMod = new Mod();
                    curMod.index = Integer.parseInt(m.group(1));
                    mods.add(curMod);
                } else if (curMod != null) {
                    if ((m = RE_RANGE.matcher(t)).find()) {
                        curMod.start = Long.parseUnsignedLong(m.group(1), 16);
                        curMod.end = Long.parseUnsignedLong(m.group(2), 16);
                    } else if ((m = RE_NAME.matcher(t)).find()) curMod.name = m.group(1).trim();
                    else if ((m = RE_ID.matcher(t)).find()) curMod.id = m.group(1);
                }
                break;
            case CRASHED:
            case THREADS:
                if (t.startsWith("Threads[")) {
                    cur = new Thr(t.substring(0, t.indexOf(']') + 1));
                    threads.add(cur);
                    sub = Sub.NONE;
                } else if (cur != null) {
                    threadLine(cur, t);
                }
                break;
            default:
                break;
            }
        }

        if (mods.isEmpty()) {
            printerr("No 'Module Info' entries in report");
            return;
        }

        // Module -> program mapping.
        List<String> choices = new ArrayList<>();
        String def = null;
        for (Mod md : mods) {
            String c = String.format("%02d %s (0x%x-0x%x)", md.index, md.name, md.start, md.end);
            choices.add(c);
            if (def == null && md.name.equalsIgnoreCase(currentProgram.getName())) def = c;
        }
        if (def == null) def = choices.get(0);
        String pick = askChoice("Module", "Which module is this program?", choices, def);
        Mod mod = mods.get(choices.indexOf(pick));
        modStart = mod.start;
        modEnd = mod.end;
        imageBase = currentProgram.getImageBase();
        imageSize = currentProgram.getMemory().getMaxAddress().getOffset() - imageBase.getOffset() + 1;

        println(String.format("Crash: %s pid=%s result=%s", proc, pid, result));
        println(String.format("  exception: %s %s", excType, excNotes));
        println(String.format("  module %02d %s id=%s start=0x%x imageBase=%s", mod.index, mod.name, mod.id, modStart, imageBase));

        // Exception addresses.
        for (Ent e : exc) {
            Address a = map(e.v, false);
            if (a == null) continue;
            String txt = String.format("%s %s=0x%x", excType, e.name, e.v);
            if (e.name.equals("Address")) txt += " | " + result + " " + proc + (excNotes.length() > 0 ? " | " + excNotes : "");
            bookmark(a, CAT_EXC, txt);
        }

        // Threads.
        long crashedId = (!threads.isEmpty() && threads.get(0).label.equals("Crashed")) ? threads.get(0).id : -1;
        Thr crashedThr = null;
        Address pcAddr = null;
        int regs = 0, trace = 0, stack = 0, callOk = 0, callUnknown = 0, skipped = 0;

        for (Thr th : threads) {
            boolean crashed = th.label.equals("Crashed");
            if (crashed) crashedThr = th;
            else if (!ALL_THREADS || (crashedId != -1 && th.id == crashedId)) continue;

            String cat = "Crash/" + th.label;
            String tn = th.name.isEmpty() ? "" : " '" + th.name + "'";

            for (Ent r : th.regs) {
                Address a = map(r.v, false);
                if (a == null) { skipped++; continue; }
                String c = r.name + "=0x" + Long.toHexString(r.v) + tn;
                if (crashed && r.name.equalsIgnoreCase("PC")) {
                    pcAddr = a;
                    c += " | " + result + " " + proc;
                }
                bookmark(a, cat + "/Register", c);
                regs++;
            }
            int idx = 0;
            for (Ent r : th.trace) {
                Address a = map(r.v, true);
                if (a == null) { skipped++; idx++; continue; }
                bookmark(a, cat + "/StackTrace", "ra[" + r.name + "]=0x" + Long.toHexString(r.v) + tn + " (call site: -4)");
                trace++;
                idx++;
                Instruction i = currentProgram.getListing().getInstructionAt(a.subtract(4));
                if (i != null && i.getFlowType().isCall()) callOk++; else callUnknown++;
            }
            if (SCAN_STACK_DUMP && (crashed || SCAN_STACK_DUMP_ALL_THREADS) && th.stackBase >= 0) {
                byte[] d = th.stack.toByteArray();
                for (int o = 0; o + 8 <= d.length; o += 8) {
                    if (((th.stackBase + o) & 7) != 0) continue;
                    long v = u64(d, o);
                    if ((v & 3) != 0) continue;
                    Address a = map(v, true);
                    if (a == null) continue;
                    bookmark(a, cat + "/StackDump", String.format("stack+0x%x = 0x%x", o, v));
                    stack++;
                }
            }
        }

        if (crashedThr != null && crashedThr.tls.size() >= 8) decodeIpc(crashedThr.tls.toByteArray(), pcAddr);

        println(String.format("Bookmarks: regs=%d trace=%d stackdump=%d skipped(out of module)=%d", regs, trace, stack, skipped));
        println(String.format("Trace sanity: %d/%d preceded by a call instruction (rest: not disassembled, wrong module or wrong offset)",
                callOk, callOk + callUnknown));
    }

    private void threadLine(Thr th, String t) {
        Matcher m;
        if (t.startsWith("Registers:")) { sub = Sub.REGS; return; }
        if (t.startsWith("Stack Trace:")) { sub = Sub.TRACE; return; }
        if (t.startsWith("Stack Dump:")) { sub = Sub.STACK; return; }
        if (t.startsWith("TLS Address:") || t.startsWith("TLS Dump:")) { sub = Sub.TLS; return; }
        if ((m = RE_TID.matcher(t)).find()) { th.id = Long.parseUnsignedLong(m.group(1), 16); sub = Sub.NONE; return; }
        if ((m = RE_TNAME.matcher(t)).find()) { th.name = m.group(1).trim(); sub = Sub.NONE; return; }

        switch (sub) {
        case REGS:
            if ((m = RE_REG.matcher(t)).find()) th.regs.add(new Ent(m.group(1), Long.parseUnsignedLong(m.group(2), 16)));
            break;
        case TRACE:
            if ((m = RE_RA.matcher(t)).find()) {
                long v = Long.parseUnsignedLong(m.group(2), 16);
                if (v != 0) th.trace.add(new Ent(m.group(1), v));
            }
            break;
        case STACK:
            if ((m = RE_ROW.matcher(t)).matches()) {
                if (th.stackBase < 0) th.stackBase = Long.parseUnsignedLong(m.group(1), 16);
                for (String b : m.group(2).trim().split("\\s+")) th.stack.write(Integer.parseInt(b, 16));
            }
            break;
        case TLS:
            if ((m = RE_ROW.matcher(t)).matches()) {
                for (String b : m.group(2).trim().split("\\s+")) th.tls.write(Integer.parseInt(b, 16));
            }
            break;
        default:
            break;
        }
    }

    private static int u32(byte[] t, int o) {
        return (t[o] & 0xff) | ((t[o + 1] & 0xff) << 8) | ((t[o + 2] & 0xff) << 16) | ((t[o + 3] & 0xff) << 24);
    }

    private static long u64(byte[] t, int o) {
        return (u32(t, o) & 0xffffffffL) | ((long) u32(t, o + 4) << 32);
    }

    /** "SFCI"/"SFCO" at o, else null. */
    private static String magic(byte[] t, int o) {
        if (o < 0 || o + 16 > t.length) return null;
        if (t[o] != 'S' || t[o + 1] != 'F' || t[o + 2] != 'C') return null;
        return t[o + 3] == 'I' ? "SFCI" : t[o + 3] == 'O' ? "SFCO" : null;
    }

    private static String result(int r) {
        return String.format("0x%X (2%03d-%04d)", r, r & 0x1ff, (r >>> 9) & 0x1fff);
    }

    /** Decodes the HIPC/CMIF message left in the crashed thread's TLS IPC buffer (first 0x100 bytes). */
    private void decodeIpc(byte[] t, Address pc) {
        if (t.length < 8) return;
        int w0 = u32(t, 0), w1 = u32(t, 4);
        int type = w0 & 0xffff;
        int nx = (w0 >>> 16) & 0xf, na = (w0 >>> 20) & 0xf, nb = (w0 >>> 24) & 0xf, nw = (w0 >>> 28) & 0xf;
        int rawWords = w1 & 0x3ff, recvMode = (w1 >>> 10) & 0xf;
        boolean special = (w1 >>> 31) != 0;
        String tname = type < HIPC_TYPES.length ? HIPC_TYPES[type] : "Unknown";
        boolean ctrl = type == 3 || type == 5 || type == 7;

        StringBuilder hdr = new StringBuilder();
        int p = 8;
        if (special && p + 4 <= t.length) {
            int s = u32(t, p);
            p += 4;
            int nc = (s >>> 1) & 0xf, nm = (s >>> 5) & 0xf;
            if ((s & 1) != 0 && p + 8 <= t.length) {
                hdr.append(String.format(" pid=0x%x", u64(t, p)));
                p += 8;
            }
            hdr.append(" copy=[");
            for (int i = 0; i < nc && p + 4 <= t.length; i++, p += 4) hdr.append(i > 0 ? "," : "").append(String.format("0x%x", u32(t, p)));
            hdr.append("] move=[");
            for (int i = 0; i < nm && p + 4 <= t.length; i++, p += 4) hdr.append(i > 0 ? "," : "").append(String.format("0x%x", u32(t, p)));
            hdr.append("]");
        }
        StringBuilder bufs = new StringBuilder();
        for (int i = 0; i < nx && p + 8 <= t.length; i++, p += 8) {
            int d0 = u32(t, p), d1 = u32(t, p + 4);
            long addr = (d1 & 0xffffffffL) | ((long) ((d0 >>> 12) & 0xf) << 32) | ((long) ((d0 >>> 6) & 0x7) << 36);
            bufs.append(String.format("  X[%d]: addr=0x%x%s size=0x%x counter=%d\n", i, addr, ghidraOf(addr), d0 >>> 16,
                    (d0 & 0x3f) | (((d0 >>> 9) & 0x7) << 6)));
        }
        String[] bn = {"A", "B", "W"};
        int[] bc = {na, nb, nw};
        for (int k = 0; k < 3; k++) {
            for (int i = 0; i < bc[k] && p + 12 <= t.length; i++, p += 12) {
                int d2 = u32(t, p + 8);
                long size = (u32(t, p) & 0xffffffffL) | ((long) ((d2 >>> 24) & 0xf) << 32);
                long addr = (u32(t, p + 4) & 0xffffffffL) | ((long) ((d2 >>> 28) & 0xf) << 32) | ((long) ((d2 >>> 2) & 0x7) << 36);
                bufs.append(String.format("  %s[%d]: addr=0x%x%s size=0x%x mode=%d\n", bn[k], i, addr, ghidraOf(addr), size, d2 & 3));
            }
        }
        int raw = (p + 15) & ~15;

        println(String.format("IPC TLS+0x0: type=%s(%d) X=%d A=%d B=%d W=%d recv_mode=%d raw=0x%x words @+0x%x%s",
                tname, type, nx, na, nb, nw, recvMode, rawWords, raw, hdr));
        if (bufs.length() > 0) println(bufs.toString().stripTrailing());

        int m = -1;
        boolean domain = false;
        if (magic(t, raw) != null) m = raw;
        else if (magic(t, raw + 0x10) != null) { m = raw + 0x10; domain = true; }

        String summary = tname + "(" + type + ")";
        if (m < 0) {
            println(String.format("  no SFCI/SFCO at raw+0 or raw+0x10 (+0x%x): not a CMIF message, or stale/empty TLS", raw));
        } else {
            if (domain) {
                int dt = t[raw] & 0xff;
                println(String.format("  domain header: type=%d(%s) num_objects=%d data_size=0x%x object_id=0x%x",
                        dt, dt == 1 ? "SendMessage" : dt == 2 ? "Close" : "?", t[raw + 1] & 0xff,
                        (t[raw + 2] & 0xff) | ((t[raw + 3] & 0xff) << 8), u32(t, raw + 4)));
            }
            summary += " " + describe(t, m, ctrl);
        }

        StringBuilder more = new StringBuilder();
        for (int o = 0; o + 16 <= t.length; o += 4) {
            if (o == m || magic(t, o) == null) continue;
            String d = describe(t, o, false);
            println(String.format("  secondary @TLS+0x%x: %s (stale message or second buffer)", o, d));
            more.append(String.format(" | +0x%x %s", o, d));
        }

        if (pc != null) bookmark(pc, CAT_IPC, "IPC " + summary + more);
    }

    /** " (ghidra 0x...)" if addr lies in the mapped module, else "". */
    private String ghidraOf(long addr) {
        Address a = map(addr, false);
        return a == null ? "" : " (ghidra " + a + ")";
    }

    private String describe(byte[] t, int o, boolean ctrl) {
        String mg = magic(t, o);
        int ver = u32(t, o + 4), v = u32(t, o + 8), tok = u32(t, o + 12);
        String d;
        if (mg.equals("SFCI")) {
            d = "SFCI cmd=" + v;
            if (ctrl && v >= 0 && v < CMIF_CONTROL.length) d += "(" + CMIF_CONTROL[v] + ")";
        } else {
            d = "SFCO result=" + result(v);
        }
        return String.format("%s ver=%d token=0x%x @TLS+0x%x", d, ver, tok, o);
    }

    /** runtime address -> program address, or null if outside the selected module (or not code when requireExec). */
    private Address map(long v, boolean requireExec) {
        if (Long.compareUnsigned(v, modStart) < 0 || Long.compareUnsigned(v, modEnd) >= 0) return null;
        long rel = v - modStart;
        if (Long.compareUnsigned(rel, imageSize) >= 0) return null;
        try {
            Address a = imageBase.add(rel + HEADER_ADJUST);
            MemoryBlock b = currentProgram.getMemory().getBlock(a);
            if (b == null || (requireExec && !b.isExecute())) return null;
            return a;
        } catch (Exception e) {
            return null;
        }
    }

    private void bookmark(Address a, String cat, String text) {
        currentProgram.getBookmarkManager().setBookmark(a, TYPE, cat, text);
    }
}
