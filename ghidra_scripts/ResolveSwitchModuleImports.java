// Link this module's imports to its sibling ExeFS modules (main, subsdkN, sdk) in the
// same project folder, searched in rtld load order. Runs the same logic as the
// "(Switch) Module Import Resolver" analyzer; use it on programs that were analyzed
// before the analyzer existed, or to retry after importing more sibling modules.
// @category Nintendo Switch
//
// Usage (GUI): open a module, run the script.
// Usage (headless): -postScript ResolveSwitchModuleImports.java [order] [-v]
//   order  comma-separated sibling file names in search order
//          (default: main,subsdk0,...,subsdk9,sdk)
//   -v     list every resolved import per library

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import adubbz.nx.analyzer.ModuleImportResolverAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

public class ResolveSwitchModuleImports extends GhidraScript {
    @Override
    public void run() throws Exception {
        String order = ModuleImportResolverAnalyzer.DEFAULT_SEARCH_ORDER;
        boolean verbose = false;
        for (String arg : getScriptArgs()) {
            if (arg.equals("-v")) verbose = true;
            else order = arg;
        }

        List<String> lines = new ArrayList<>();
        ModuleImportResolverAnalyzer.Result result = ModuleImportResolverAnalyzer.resolve(
            currentProgram, ModuleImportResolverAnalyzer.parseSearchOrder(order), monitor, lines::add);
        lines.forEach(this::println);

        println(String.format("==== %s: %d imports resolved, %d left in %s, per module %s ====",
            currentProgram.getName(), result.resolved(), result.unresolved(), Library.UNKNOWN,
            result.resolvedPerModule()));

        if (!verbose) return;
        // Group external functions by library, including ones in nested namespaces
        // (ExternalManager.getExternalLocations(lib) only returns direct children).
        Map<Library, List<String>> byLib = new LinkedHashMap<>();
        var extManager = currentProgram.getExternalManager();
        for (Library lib : extManager.getLibraries()) byLib.put(lib, new ArrayList<>());
        for (Symbol s : currentProgram.getSymbolTable().getExternalSymbols()) {
            if (s.getSymbolType() != SymbolType.FUNCTION) continue;
            Namespace ns = s.getParentNamespace();
            while (ns != null && !(ns instanceof Library)) ns = ns.getParentNamespace();
            if (ns instanceof Library lib && byLib.containsKey(lib)) byLib.get(lib).add(s.getName(true));
        }
        for (Map.Entry<Library, List<String>> e : byLib.entrySet()) {
            Library lib = e.getKey();
            if (Library.UNKNOWN.equals(lib.getName()) && e.getValue().isEmpty()) continue;
            println(String.format("  [%s] ordinal %d -> %s, %d imports", lib.getName(),
                extManager.getLibraryOrdinal(lib.getName()), lib.getAssociatedProgramPath(), e.getValue().size()));
            e.getValue().forEach(n -> println("      " + n));
        }
    }
}
