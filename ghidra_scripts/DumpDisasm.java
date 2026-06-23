// Diagnostic: disassemble N instructions starting at each given address, showing
// immediates and resolved call/data references.
// @category Nintendo Switch
//
// Usage: -postScript DumpDisasm.java 0x71000c3460:40 0x71000c34e4:40

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class DumpDisasm extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) { println("Usage: DumpDisasm <addr[:count]> ..."); return; }
        println("==== " + currentProgram.getName() + " : disasm ====");
        for (String a : args) {
            String[] parts = a.split(":");
            long base = Long.parseLong(parts[0].replace("0x", ""), 16);
            int count = parts.length > 1 ? Integer.parseInt(parts[1]) : 40;
            Address addr = toAddr(base);
            println("---- " + addr + " ----");
            for (int i = 0; i < count && addr != null; i++) {
                Instruction insn = getInstructionAt(addr);
                if (insn == null) {
                    disassemble(addr);
                    insn = getInstructionAt(addr);
                }
                if (insn == null) { println("  " + addr + "  <no instruction>"); break; }
                StringBuilder sb = new StringBuilder("  ").append(addr).append("  ").append(insn);
                for (Reference r : insn.getReferencesFrom()) {
                    Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(r.getToAddress());
                    sb.append("  ; ").append(r.getReferenceType()).append("->").append(r.getToAddress());
                    if (s != null) sb.append("(").append(s.getName(true)).append(")");
                }
                println(sb.toString());
                if ("ret".equals(insn.getMnemonicString())) { println("  (ret)"); break; }
                addr = insn.getFallThrough();
                if (addr == null) addr = insn.getAddress().add(insn.getLength());
            }
        }
    }
}
