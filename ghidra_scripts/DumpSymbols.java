// Diagnostic: list symbols whose name contains any of the given substrings.
// Useful to confirm the IPC analyzer applied interface/command labels in the listing.
// @category Nintendo Switch
//
// Usage: -postScript DumpSymbols.java IAsyncValue IVulnerabilityManager

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class DumpSymbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) { println("Usage: DumpSymbols <substr> ..."); return; }
        println("==== " + currentProgram.getName() + " : symbols matching " + java.util.Arrays.toString(args) + " ====");
        int count = 0;
        SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
        for (Symbol s : it) {
            String name = s.getName(true);
            for (String needle : args) {
                if (name.contains(needle)) {
                    println(String.format("  %s @ 0x%X", name, s.getAddress().getOffset()));
                    count++;
                    break;
                }
            }
        }
        println("==== " + count + " matching symbols ====");
    }
}
