// Exports Ghidra-Switch-Loader IPC metadata JSON after headless analysis.
// Run as -postScript so analysis (including the IPC analyzer) has already completed.
// @category Nintendo Switch

import java.io.File;
import java.io.FileWriter;
import java.lang.reflect.Method;
import java.util.List;

import adubbz.nx.analyzer.IPCAnalyzer;
import adubbz.nx.common.ElfCompatibilityProvider;

import com.google.common.collect.HashBiMap;
import com.google.common.collect.Multimap;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.util.task.TaskMonitor;

public class EnableSwitchIpcJsonExport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 || args[0].isBlank()) {
            printerr("Usage: EnableSwitchIpcJsonExport.java <json_output_dir>");
            return;
        }

        File outputDir = new File(args[0]);
        if (!outputDir.exists() && !outputDir.mkdirs()) {
            printerr("Failed to create JSON output directory: " + outputDir.getAbsolutePath());
            return;
        }

        String programName = currentProgram.getName();
        File outputFile = new File(outputDir, programName + ".json");

        // Check this is actually a Switch binary before doing any work
        if (!currentProgram.getExecutableFormat().equals(adubbz.nx.loader.SwitchLoader.SWITCH_NAME)) {
            printerr("Not a Nintendo Switch binary, skipping IPC export: " + programName);
            return;
        }

        println("Running IPC analysis and exporting to: " + outputFile.getAbsolutePath());

        // Instantiate the analyzer and run it directly with export options set via reflection
        IPCAnalyzer analyzer = new IPCAnalyzer();

        // Use reflection to set the private export fields before calling added()
        java.lang.reflect.Field exportJsonField = IPCAnalyzer.class.getDeclaredField("exportIpcJson");
        exportJsonField.setAccessible(true);
        exportJsonField.set(analyzer, true);

        java.lang.reflect.Field exportPathField = IPCAnalyzer.class.getDeclaredField("exportIpcJsonPath");
        exportPathField.setAccessible(true);
        exportPathField.set(analyzer, outputFile.getAbsolutePath());

        // Run the analyzer
        MessageLog log = new MessageLog();
        boolean result = analyzer.added(
            currentProgram,
            currentProgram.getMemory().getLoadedAndInitializedAddressSet(),
            monitor,
            log
        );

        if (!result) {
            printerr("IPC analyzer returned false for: " + programName);
            printerr("Log: " + log.toString());
            return;
        }

        if (outputFile.exists()) {
            println("IPC JSON exported successfully: " + outputFile.getAbsolutePath());
        } else {
            printerr("IPC analyzer ran but no JSON file was produced at: " + outputFile.getAbsolutePath());
        }
    }
}