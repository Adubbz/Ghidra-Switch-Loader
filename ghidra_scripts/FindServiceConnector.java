// Diagnostic: for a given sm service-name string, find the connector function(s) that reference it
// and disassemble each, so the proxy-vtable install pattern can be inspected.
// @category Nintendo Switch
//
// Usage: -postScript FindServiceConnector.java prepo:u

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class FindServiceConnector extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) { println("Usage: FindServiceConnector <service>"); return; }
        String svc = args[0];
        println("==== " + currentProgram.getName() + " : connectors for '" + svc + "' ====");
        int strHits = 0, connHits = 0;
        for (Data d : currentProgram.getListing().getDefinedData(true)) {
            if (d == null || !(d.getValue() instanceof String) || !svc.equals(d.getValue())) continue;
            strHits++;
            println("string @ " + d.getAddress());
            for (Reference r : currentProgram.getReferenceManager().getReferencesTo(d.getAddress())) {
                Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                if (f == null) { println("  ref from " + r.getFromAddress() + " (no function)"); continue; }
                connHits++;
                println("  connector " + f.getName() + " @ " + f.getEntryPoint() + "  (ref from " + r.getFromAddress() + ")");
                int n = 0;
                for (Instruction insn = getInstructionAt(f.getEntryPoint());
                     insn != null && n++ < 90 && f.getBody().contains(insn.getAddress());
                     insn = insn.getNext()) {
                    StringBuilder sb = new StringBuilder("      ").append(insn.getAddress()).append("  ").append(insn);
                    for (Reference rr : insn.getReferencesFrom()) {
                        Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(rr.getToAddress());
                        sb.append("  ; ->").append(rr.getToAddress());
                        if (s != null) sb.append("(").append(s.getName(true)).append(")");
                    }
                    println(sb.toString());
                    if ("ret".equals(insn.getMnemonicString())) break;
                }
            }
        }
        println("==== string hits: " + strHits + ", connector refs: " + connHits + " ====");
    }
}
