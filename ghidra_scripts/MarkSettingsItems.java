// Re-run the (Switch) Settings Item Analyzer on an already analyzed program and print what it found.
// Marks each nn::settings::fwdbg lookup with a bookmark (category = name, comment = key), a label
// ns.application["qualification_rule"] and an EOL comment ns.application [ "qualification_rule" ].
//
// Usage: -postScript MarkSettingsItems.java [name ...]   (no args = every known settings name)
//@category Switch

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import adubbz.nx.analyzer.SettingsItemAnalyzer;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class MarkSettingsItems extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        List<String> names = Arrays.asList(args.length > 0 ? args : SettingsItemAnalyzer.SETTINGS_NAMES);

        SettingsItemAnalyzer.Result r = SettingsItemAnalyzer.markSettingsItems(currentProgram, null, names, monitor);

        println("==== " + currentProgram.getName() + " : " + r.found + " of " + names.size()
                + " settings names present ====");
        for (Map.Entry<String, List<Address>> e : r.unresolved.entrySet()) {
            for (Address a : e.getValue()) println("  [" + e.getKey() + "] " + a + " : key not resolved");
        }
        for (Map.Entry<String, Map<String, Integer>> e : r.keys.entrySet()) {
            println(e.getKey() + " (" + e.getValue().size() + " keys)");
            for (Map.Entry<String, Integer> k : e.getValue().entrySet()) {
                println("    " + k.getKey() + (k.getValue() > 1 ? "  x" + k.getValue() : ""));
            }
        }
        int unresolved = r.unresolved.values().stream().mapToInt(List::size).sum();
        println("==== marked " + r.marked + " xrefs, " + unresolved + " unresolved ====");
    }
}
