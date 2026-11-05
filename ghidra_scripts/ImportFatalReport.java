// Import an Atmosphère fatal report (.log, "Atmosphère Fatal Report (v1.x)") as bookmarks.
// Maps runtime addresses to the loaded program via: ghidra = imageBase + (addr - "Start Address").
//@category Switch

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

public class ImportFatalReport extends GhidraScript {

    /* fatal writes raw runtime addresses; the NSO header is not mapped, so 0 (see notes). */
    private static final long HEADER_ADJUST = 0;
    private static final boolean SCAN_STACK_DUMP = true;

    private static final String TYPE = "Info";
    private static final String CAT_REG = "Fatal/Register";
    private static final String CAT_TRACE = "Fatal/StackTrace";
    private static final String CAT_STACK = "Fatal/StackDump";
    private static final String CAT_IPC = "Fatal/IPC";

    private static final String[] HIPC_TYPES = {
        "Invalid", "LegacyRequest", "Close", "LegacyControl", "Request", "Control", "RequestWithContext", "ControlWithContext"
    };
    /* CMIF control commands are interface-independent. */
    private static final String[] CMIF_CONTROL = {
        "ConvertCurrentObjectToDomain", "CopyFromCurrentDomain", "CloneCurrentObject", "QueryPointerBufferSize", "CloneCurrentObjectEx"
    };

    private static final Pattern RE_RESULT = Pattern.compile("^Result:\\s+(0x[0-9A-Fa-f]+)\\s+\\((\\d+-\\d+)\\)");
    private static final Pattern RE_PROC = Pattern.compile("^Process Name:\\s+(\\S+)");
    private static final Pattern RE_START = Pattern.compile("^Start Address:\\s+([0-9A-Fa-f]+)");
    private static final Pattern RE_REG = Pattern.compile("^\\s+(\\w+):\\s+([0-9A-Fa-f]{8,16})\\s*$");
    private static final Pattern RE_RA = Pattern.compile("^\\s+ReturnAddress\\[(\\d+)\\]:\\s+([0-9A-Fa-f]+)\\s*$");
    private static final Pattern RE_ROW = Pattern.compile("^\\s+([0-9A-Fa-f]{12})((?:\\s+[0-9A-Fa-f]{2}){16})\\s*$");

    private enum Sec { NONE, REGS, TRACE, STACK, TLS }

    private Address imageBase;
    private long imageSize;

    @Override
    protected void run() throws Exception {
        File f = askFile("Atmosphere fatal report", "Import");
        List<String> lines = Files.readAllLines(f.toPath());

        imageBase = currentProgram.getImageBase();
        imageSize = currentProgram.getMemory().getMaxAddress().getOffset() - imageBase.getOffset() + 1;

        String result = "", proc = "";
        long start = -1;
        boolean haveStart = false;
        Sec sec = Sec.NONE;

        // Pass 1: header + start address (Start Address follows the registers).
        for (String l : lines) {
            Matcher m;
            if ((m = RE_RESULT.matcher(l)).find()) result = m.group(1) + " (" + m.group(2) + ")";
            else if ((m = RE_PROC.matcher(l)).find()) proc = m.group(1);
            else if ((m = RE_START.matcher(l)).find()) { start = Long.parseUnsignedLong(m.group(1), 16); haveStart = true; }
        }
        if (!haveStart) {
            printerr("No 'Start Address' in report");
            return;
        }
        println(String.format("Report start=0x%x imageBase=%s size=0x%x", start, imageBase, imageSize));

        int regs = 0, trace = 0, stack = 0, callOk = 0, callUnknown = 0, skipped = 0;
        long stackBase = -1;
        ByteArrayOutputStream stackBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream tlsBytes = new ByteArrayOutputStream();
        Address pcAddr = null;

        // Pass 2: sections.
        for (String l : lines) {
            if (l.startsWith("General Purpose Registers")) { sec = Sec.REGS; continue; }
            if (l.startsWith("Start Address")) { sec = Sec.NONE; continue; }
            if (l.startsWith("Stack Trace")) { sec = Sec.TRACE; continue; }
            if (l.startsWith("Stack Dump")) { sec = Sec.STACK; continue; }
            if (l.startsWith("TLS Address")) { sec = Sec.TLS; continue; }

            Matcher m;
            switch (sec) {
            case REGS:
                if ((m = RE_REG.matcher(l)).matches()) {
                    String name = m.group(1);
                    long v = Long.parseUnsignedLong(m.group(2), 16);
                    Address a = map(v, start, false);
                    if (a == null) { skipped++; break; }
                    String c = name + "=0x" + Long.toHexString(v);
                    if (name.equalsIgnoreCase("PC") && !result.isEmpty()) c += " | fatal " + result + (proc.isEmpty() ? "" : " " + proc);
                    bookmark(a, CAT_REG, c);
                    if (name.equalsIgnoreCase("PC")) pcAddr = a;
                    regs++;
                }
                break;
            case TRACE:
                if ((m = RE_RA.matcher(l)).matches()) {
                    long v = Long.parseUnsignedLong(m.group(2), 16);
                    if (v == 0) break;
                    Address a = map(v, start, true);
                    if (a == null) { skipped++; break; }
                    bookmark(a, CAT_TRACE, "ra[" + m.group(1) + "]=0x" + Long.toHexString(v) + " (call site: -4)");
                    trace++;
                    Instruction i = currentProgram.getListing().getInstructionAt(a.subtract(4));
                    if (i != null && i.getFlowType().isCall()) callOk++; else callUnknown++;
                }
                break;
            case STACK:
                if (SCAN_STACK_DUMP && (m = RE_ROW.matcher(l)).matches()) {
                    long addr = Long.parseUnsignedLong(m.group(1), 16);
                    if (stackBase < 0) stackBase = addr;
                    for (String b : m.group(2).trim().split("\\s+")) stackBytes.write(Integer.parseInt(b, 16));
                }
                break;
            case TLS:
                if ((m = RE_ROW.matcher(l)).matches()) {
                    for (String b : m.group(2).trim().split("\\s+")) tlsBytes.write(Integer.parseInt(b, 16));
                }
                break;
            default:
                break;
            }
        }

        if (SCAN_STACK_DUMP && stackBase >= 0) {
            byte[] d = stackBytes.toByteArray();
            for (int o = 0; o + 8 <= d.length; o += 8) {
                if (((stackBase + o) & 7) != 0) continue;
                long v = 0;
                for (int k = 7; k >= 0; k--) v = (v << 8) | (d[o + k] & 0xff);
                if ((v & 3) != 0) continue;
                Address a = map(v, start, true);
                if (a == null) continue;
                bookmark(a, CAT_STACK, String.format("stack+0x%x = 0x%x", o, v));
                stack++;
            }
        }

        if (tlsBytes.size() > 0) decodeIpc(tlsBytes.toByteArray(), pcAddr);

        println(String.format("Bookmarks: regs=%d trace=%d stackdump=%d skipped(out of image)=%d", regs, trace, stack, skipped));
        println(String.format("Trace sanity: %d/%d preceded by a call instruction (rest: not disassembled or wrong offset)",
                callOk, callOk + callUnknown));
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

    /** Decodes the HIPC/CMIF message left in the thread's TLS IPC buffer (first 0x100 bytes). */
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
        p += nx * 8 + (na + nb + nw) * 12;
        int raw = (p + 15) & ~15;

        println(String.format("IPC TLS+0x0: type=%s(%d) X=%d A=%d B=%d W=%d recv_mode=%d raw=0x%x words @+0x%x%s",
                tname, type, nx, na, nb, nw, recvMode, rawWords, raw, hdr));

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

    /** runtime address -> program address, or null if outside the image (or not code when requireExec). */
    private Address map(long v, long start, boolean requireExec) {
        long rel = v - start;
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
