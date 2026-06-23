// Diagnostic: list all references (code + data) to a given address, with the containing
// function and instruction. Used to find whether a 22.x client command vtable is
// materialized (adrp;add) by a factory function we can link to a parent command.
//
// Usage: -postScript DumpRefsTo.java 0x7100b5cba8

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class DumpRefsTo extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) { println("Usage: DumpRefsTo <addr> [addr...]"); return; }
        for (String arg : args) {
            Address a = toAddr(Long.decode(arg));
            println("==== refs to " + a + " ====");
            int n = 0;
            for (Reference r : currentProgram.getReferenceManager().getReferencesTo(a)) {
                Address from = r.getFromAddress();
                Function f = currentProgram.getFunctionManager().getFunctionContaining(from);
                Instruction insn = getInstructionAt(from);
                println("  from " + from
                        + "  type=" + r.getReferenceType()
                        + (f != null ? "  in " + f.getName() + "@" + f.getEntryPoint() : "  (no func)")
                        + (insn != null ? "  : " + insn : "  : (data)"));
                n++;
            }
            println("  (" + n + " refs)");
        }
    }
}
