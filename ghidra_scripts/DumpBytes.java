// Diagnostic: dump a memory region as both raw qwords and as resolved pointers
// (with any symbol at the target). Useful for reading CMIF s_Table / command-meta
// tables (cmd-id arrays interleaved/parallel with handler pointers).
// @category Nintendo Switch
//
// Usage: -postScript DumpBytes.java 0x710036E840:0xC0

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

public class DumpBytes extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) { println("Usage: DumpBytes <addr[:len]> ..."); return; }
        println("==== " + currentProgram.getName() + " : bytes ====");
        for (String a : args) {
            String[] parts = a.split(":");
            long base = Long.parseLong(parts[0].replace("0x", ""), 16);
            long len = parts.length > 1
                ? Long.parseLong(parts[1].replace("0x", ""), 16) : 0x80;
            Address addr = toAddr(base);
            println("---- " + addr + " (len 0x" + Long.toHexString(len) + ") ----");
            for (long off = 0; off + 8 <= len; off += 8) {
                Address at = addr.add(off);
                long q;
                try { q = currentProgram.getMemory().getLong(at); }
                catch (Exception e) { println("  +0x" + Long.toHexString(off) + "  <unreadable>"); continue; }
                StringBuilder sb = new StringBuilder();
                sb.append("  ").append(at).append("  +0x").append(String.format("%-3x", off));
                sb.append("  0x").append(String.format("%016x", q));
                // low 32 bits as a decimal (cmd-id candidate)
                long lo = q & 0xFFFFFFFFL;
                if (lo < 0x100000L) sb.append("  u32lo=").append(lo);
                // pointer interpretation
                Address ptr = toAddr(q);
                MemoryBlock blk = (q != 0) ? currentProgram.getMemory().getBlock(ptr) : null;
                if (blk != null) {
                    sb.append("  -> ").append(ptr).append("[").append(blk.getName()).append("]");
                    Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(ptr);
                    if (s != null) sb.append("(").append(s.getName(true)).append(")");
                }
                println(sb.toString());
            }
        }
    }
}
