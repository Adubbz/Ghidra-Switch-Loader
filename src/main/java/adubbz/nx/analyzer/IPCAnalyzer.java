/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.analyzer;

import adubbz.nx.analyzer.ipc.IPCEmulator;
import adubbz.nx.analyzer.ipc.IPCTrace;
import adubbz.nx.analyzer.ipc.IPCDatabase;
import adubbz.nx.analyzer.ipc.IPCHashDatabase;
import adubbz.nx.analyzer.ipc.IPCServiceDatabase;
import adubbz.nx.analyzer.ipc.ServiceUsageTracer;
import adubbz.nx.common.ElfCompatibilityProvider;
import adubbz.nx.common.NXRelocation;
import adubbz.nx.loader.SwitchLoader;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Multimap;
import generic.stl.Pair;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.compress.utils.Lists;
import com.google.common.collect.HashBiMap;
import com.google.common.collect.Sets;

import java.io.IOException;
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static adubbz.nx.common.ElfCompatibilityProvider.R_FAKE_RELR;

public class IPCAnalyzer extends AbstractAnalyzer 
{
    private static final Pattern AARCH64_MEMORY_BASE_PATTERN = Pattern.compile("\\[\\s*([xw]\\d+|sp)\\b", Pattern.CASE_INSENSITIVE);
    private static final String OPTION_EXPORT_IPC_JSON = "Export IPC metadata JSON";
    private static final String OPTION_EXPORT_IPC_JSON_PATH = "IPC metadata JSON export path";
    private static final String FSSRV_INTERFACE_PREFIX = "nn::fssrv::sf::";
    private static final int SDK_LARGE_POINTER_REGION_EXTRA_SLOTS = 0x20;
    private static final int CLIENT_IMPORT_EMU_STUB_LIMIT = 4096;

    private boolean exportIpcJson = false;
    private String exportIpcJsonPath = "";

    public IPCAnalyzer() 
    {
        super("(Switch) IPC Analyzer", "Locates and labels IPC vtables, s_Tables and implementation functions.", AnalyzerType.INSTRUCTION_ANALYZER);
    
        this.setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean getDefaultEnablement(Program program) 
    {
        return false;
    }

    @Override
    public boolean canAnalyze(Program program) 
    {
        return program.getExecutableFormat().equals(SwitchLoader.SWITCH_NAME);
    }

    @Override
    public void registerOptions(Options options, Program program) 
    {
        options.registerOption(OPTION_EXPORT_IPC_JSON, false, null,
            "Export recovered IPC metadata to a JSON file after analysis.");
        options.registerOption(OPTION_EXPORT_IPC_JSON_PATH, "", null,
            "Path for exported IPC metadata JSON. If empty, exports beside the program executable.");
    }

    @Override
    public void optionsChanged(Options options, Program program)
    {
        this.exportIpcJson = options.getBoolean(OPTION_EXPORT_IPC_JSON, false);
        this.exportIpcJsonPath = options.getString(OPTION_EXPORT_IPC_JSON_PATH, "");
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
    {
        Memory memory = program.getMemory();
        MemoryBlock text = memory.getBlock(".text");
        MemoryBlock data = memory.getBlock(".data");
        ElfCompatibilityProvider elfCompatProvider = new ElfCompatibilityProvider(program, false);
        
        Msg.info(this, String.format("Beginning IPC analysis for %s...", program.getName()));
        
        if (text == null || data == null)
            return true;

        // .rodata may be split into .rodata, .rodata.1, .rodata.2 etc.
        // Just check that at least one rodata block exists.
        boolean hasRodata = false;
        for (MemoryBlock block : memory.getBlocks())
        {
            if (block.getName().startsWith(".rodata"))
            {
                hasRodata = true;
                break;
            }
        }

        if (!hasRodata)
            return true;

        try
        {
            List<Address> vtAddrs = this.locateIpcVtables(program, elfCompatProvider);
            // FIX 3: build rttiNames before createVTableEntries and pass it in
            Map<Address, String> rttiNames = this.buildRttiNameMap(program, elfCompatProvider);
            Set<Address> allVtAddrs = new LinkedHashSet<>(vtAddrs);
            allVtAddrs.addAll(rttiNames.keySet());
            vtAddrs = new ArrayList<>(allVtAddrs);
            List<IPCVTableEntry> vtEntries = this.createVTableEntries(program, elfCompatProvider, vtAddrs, rttiNames);
            HashBiMap<Address, Address> sTableProcessFuncMap = this.locateSTables(program, elfCompatProvider);
            Multimap<Address, IPCTrace> processFuncTraces = this.emulateProcessFunctions(program, monitor, sTableProcessFuncMap.values());
            this.logIpcTraceHashes(processFuncTraces);
            HashBiMap<Address, IPCVTableEntry> procFuncVtMap = this.matchVtables(vtEntries, sTableProcessFuncMap.values(), processFuncTraces);
            Set<String> localInterfaceNames = this.collectLocalInterfaceNames(vtEntries);

            // Interface identity comes from trace hashes. Command-id sets are version-sensitive
            // hints only, so they must not rename dispatchers or synthesize interface identity.
            for (int i = 0; i < vtEntries.size(); i++)
            {
                IPCVTableEntry entry = vtEntries.get(i);

                Address procFuncAddr = procFuncVtMap.inverse().get(entry);
                if (procFuncAddr == null || !processFuncTraces.containsKey(procFuncAddr))
                    continue;

                IPCHashDatabase.HashMatch hashMatch = this.findUniqueHashInterfaceMatch(procFuncAddr,
                    processFuncTraces.get(procFuncAddr), localInterfaceNames);

                if (hashMatch == null)
                    continue;

                String fullName = hashMatch.getUniqueInterface() + "::vtable";
                String shortName = shortenIpcSymbol(fullName);
                Msg.info(this, String.format("%s-matched server/export dispatcher: %s -> %s (%s)",
                    hashMatch.formatSource(), entry.abvName, shortName, hashMatch.hash));

                IPCVTableEntry newEntry = new IPCVTableEntry(fullName, shortName, entry.addr, entry.ipcFuncs,
                    entry.hasRealVtable);
                vtEntries.set(i, newEntry);
                procFuncVtMap.forcePut(procFuncAddr, newEntry);
            }

            for (Address procFuncAddr : sTableProcessFuncMap.values())
            {
                if (procFuncVtMap.containsKey(procFuncAddr))
                    continue;

                if (!processFuncTraces.containsKey(procFuncAddr))
                    continue;

                IPCHashDatabase.HashMatch hashMatch = this.findUniqueHashInterfaceMatch(procFuncAddr,
                    processFuncTraces.get(procFuncAddr), localInterfaceNames);

                if (hashMatch == null)
                    continue;

                String fullName = hashMatch.getUniqueInterface() + "::vtable";
                String shortName = shortenIpcSymbol(fullName);
                Address sTableAddr = sTableProcessFuncMap.inverse().get(procFuncAddr);
                Msg.info(this, String.format(
                    "%s-matched s_Table server/export proc_func 0x%X (s_Table %s) -> %s (%s)",
                    hashMatch.formatSource(),
                    procFuncAddr.getOffset(),
                    sTableAddr != null ? String.format("0x%X", sTableAddr.getOffset()) : "unknown",
                    hashMatch.getUniqueInterface(), hashMatch.hash));

                IPCVTableEntry newEntry = new IPCVTableEntry(fullName, shortName,
                    sTableAddr != null ? sTableAddr : procFuncAddr, new ArrayList<>(), false);
                vtEntries.add(newEntry);
                procFuncVtMap.forcePut(procFuncAddr, newEntry);
            }

            // Keep remaining unmatched process functions for markup/export, but do not
            // infer an interface name without a unique hash.
            for (Address procFuncAddr : sTableProcessFuncMap.values())
            {
                if (procFuncVtMap.containsKey(procFuncAddr))
                    continue;

                if (!processFuncTraces.containsKey(procFuncAddr))
                    continue;

                Set<Long> emulatedCmds = processFuncTraces.get(procFuncAddr).stream()
                    .filter(t -> t.vtOffset != -1 && t.hasDescription())
                    .map(t -> t.cmdId)
                    .collect(Collectors.toCollection(LinkedHashSet::new));

                if (emulatedCmds.isEmpty()) continue;

                Address sTableAddr = sTableProcessFuncMap.inverse().get(procFuncAddr);
                String fullName = String.format("SRV_%X::vtable",
                    sTableAddr != null ? sTableAddr.getOffset() : procFuncAddr.getOffset());
                String shortName = fullName;

                Msg.info(this, String.format(
                    "Keeping unverified server/export proc_func 0x%X (s_Table %s) as %s: no unique hash match (cmds %s)",
                    procFuncAddr.getOffset(),
                    sTableAddr != null ? String.format("0x%X", sTableAddr.getOffset()) : "unknown",
                    shortName, formatCommandIds(emulatedCmds)));

                IPCVTableEntry newEntry = new IPCVTableEntry(fullName, shortName,
                    sTableAddr != null ? sTableAddr : procFuncAddr, new ArrayList<>(), false);
                vtEntries.add(newEntry);
                procFuncVtMap.forcePut(procFuncAddr, newEntry);
            }

            Map<Address, SyntheticCommandFunctionTable> syntheticCommandTables =
                this.findSyntheticCommandFunctionTables(program, processFuncTraces, procFuncVtMap,
                    vtEntries, sTableProcessFuncMap);

            this.markupIpc(program, monitor, vtEntries, sTableProcessFuncMap, processFuncTraces,
                procFuncVtMap, syntheticCommandTables);
            List<IPCInterfaceVTableGroup> interfaceVtableGroups = this.markupInterfaceVtableGroups(program, rttiNames);
            List<String> connectedServices = this.recoverConnectedServices(program);

            // Client-side service usage: traced once, used for BOTH the in-program markup and the JSON.
            Map<String, ServiceUsageTracer.ServiceUsage> invokedCommands = connectedServices != null
                ? this.recoverInvokedCommands(program, connectedServices, rttiNames)
                : Collections.emptyMap();
            this.markupInvokedCommands(program, invokedCommands);

            this.exportIpcJson(program, vtEntries, processFuncTraces, procFuncVtMap,
                interfaceVtableGroups, syntheticCommandTables, connectedServices, sTableProcessFuncMap,
                invokedCommands);
        }
        catch (Exception e)
        {
            Msg.error(this, "Failed to analyze binary IPC.", e);
            return false;
        }
        
        return true;
    }
    
    private List<Address> locateIpcVtables(Program program, ElfCompatibilityProvider elfProvider) throws MemoryAccessException, AddressOutOfBoundsException, IOException
    {
        List<Address> out = Lists.newArrayList();
        Address baseAddr = program.getImageBase();
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        Memory mem = program.getMemory();
        SymbolTable symbolTable = program.getSymbolTable();
        
        Map<String, Address> knownVTabAddrs = new HashMap<>();
        Map<Address, Address> gotDataSyms = this.getGotDataSyms(program, elfProvider);
        
        if (gotDataSyms.isEmpty())
        {
            Msg.warn(this, "Failed to locate vtables - No got data symbols found!");
            return out;
        }
        
        Msg.info(this, "Locating IPC vtables...");
        
        // NOTE: We can't get the .<bla> block and check if it contains an address, as there may be multiple
        // blocks with the same name, which Ghidra doesn't account for.
        
        // Locate some initial vtables based on RTTI
        for (Address vtAddr : gotDataSyms.values()) 
        {
            MemoryBlock vtBlock = mem.getBlock(vtAddr);
            
            // vtables are only found in the data block
            if (!this.isRttiDataBlock(program, vtBlock))
                continue;
            
            try
            {
                Address rttiAddr = aSpace.getAddress(mem.getLong(vtAddr.add(8)));
                MemoryBlock rttiBlock = mem.getBlock(rttiAddr);
                
                // RTTI is only found in the data block
                if (!this.isRttiDataBlock(program, rttiBlock))
                    continue;

                Address thisAddr = aSpace.getAddress(mem.getLong(rttiAddr.add(0x8)));
                MemoryBlock thisBlock = mem.getBlock(thisAddr);

                // FIX 2: use startsWith(".rodata") instead of equals(".rodata") to handle
                // split rodata sections (.rodata.1, .rodata.2, etc.)
                if (thisBlock == null || !thisBlock.getName().startsWith(".rodata"))
                    continue;

                String symbol = elfProvider.getReader().readAsciiString(thisAddr.getOffset());

                if (symbol.isEmpty() || symbol.length() > 512)
                    continue;

                if (symbol.contains("UnmanagedServiceObject") || symbol.equals("N2nn2sf4cmif6server23CmifServerDomainManager6DomainE"))
                {
                    knownVTabAddrs.put(symbol, vtAddr);
                }
            }
            catch (MemoryAccessException e) // Skip entries with out of bounds offsets
            {
                continue;
            }
        }
        
        if (knownVTabAddrs.isEmpty())
        {
            if (this.isSdkLikeLayout(program))
            {
                Msg.info(this, "Legacy server/export vtable locator found no anchors in SDK-like layout; continuing with RTTI client/import scan.");
            }
            else
            {
                Msg.warn(this, "Failed to locate vtables - No known addresses found!");
            }
            return out;
        }
            
        // All IServiceObjects share a common non-overridable virtual function at vt + 0x20
        // and thus that value can be used to distinguish a virtual table vs a non-virtual table.
        // Here we locate the address of that function.
        long knownAddress = 0;

        for (Address addr : knownVTabAddrs.values())
        {
            long curKnownAddr = mem.getLong(addr.add(0x20));

            // Handle the case where the GOT entry points to the RTTI slot rather than
            // offset-to-top, making the vtable base appear 8 bytes early
            if (knownAddress == 0)
            {
                knownAddress = curKnownAddr;
            }
            else if (knownAddress != curKnownAddr)
            {
                // Try +0x28 in case this entry is shifted by 8
                long shifted = mem.getLong(addr.add(0x28));
                if (shifted == knownAddress)
                {
                    // This entry's GOT ptr is 8 bytes early — replace it in the map
                    // We'll handle the shift in the second loop
                }
                else
                    return out;
            }
        }
        
        Msg.info(this, String.format("Known service address: 0x%x", knownAddress));
        
        // Use the known function to find all IPC vtables
        for (Address vtAddr : gotDataSyms.values()) 
        {
            MemoryBlock vtBlock = mem.getBlock(vtAddr);
            
            try
            {
                if (this.isRttiDataBlock(program, vtBlock))
                {
                    long at20 = 0, at28 = 0;
                    try { at20 = mem.getLong(vtAddr.add(0x20)); } catch (MemoryAccessException e2) {}
                    try { at28 = mem.getLong(vtAddr.add(0x28)); } catch (MemoryAccessException e2) {}
                    
                    if (at20 == knownAddress || at28 == knownAddress)
                    {
                        Msg.info(this, String.format(
                            "Candidate vtAddr=0x%X: at+0x20=0x%X, at+0x28=0x%X, knownAddress=0x%X, match=%s",
                            vtAddr.getOffset(), at20, at28, knownAddress,
                            at20 == knownAddress ? "+0x20" : "+0x28"));
                    }
                    
                    if (at20 == knownAddress)
                    {
                        out.add(vtAddr);
                    }
                    else if (at28 == knownAddress)
                    {
                        out.add(vtAddr.add(0x8));
                    }
                }
            }
            catch (Exception e)
            {
                continue;
            }
        }
        
        return out;
    }
    
    protected List<IPCVTableEntry> createVTableEntries(Program program, ElfCompatibilityProvider elfProvider, List<Address> vtAddrs, Map<Address, String> rttiNames) throws MemoryAccessException, AddressOutOfBoundsException, IOException
    {
        List<IPCVTableEntry> out = Lists.newArrayList();
        Memory mem = program.getMemory();
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();

        // Build GOT value set once for the whole method; getGotDataSyms() caches the map
        // but containsValue is O(n) — pre-index into a HashSet for O(1) slot boundary checks.
        Map<Address, Address> gotDataSyms = this.getGotDataSyms(program, elfProvider);
        Set<Address> gotValueAddrs = new HashSet<>(gotDataSyms.values());

        for (Address vtAddr : vtAddrs)
        {
            long vtOff = vtAddr.getOffset();
            long rttiBase = mem.getLong(vtAddr.add(0x8));
            String name = String.format("SRV_%X::vtable", vtOff);
            
            if (rttiBase != 0)
            {
                Address rttiBaseAddr = aSpace.getAddress(rttiBase);
                MemoryBlock rttiBaseBlock = mem.getBlock(rttiBaseAddr);
                
                if (rttiBaseBlock == null)
                {
                    Msg.debug(this, String.format("VT 0x%X: rttiBaseBlock is null for addr 0x%X", vtOff, rttiBase));
                }
                else if (!this.isRttiDataBlock(program, rttiBaseBlock))
                {
                    Msg.debug(this, String.format("VT 0x%X: rttiBaseBlock name is '%s' (not .data) for addr 0x%X", vtOff, rttiBaseBlock.getName(), rttiBase));
                }
                else
                {
                    Address thisAddr = aSpace.getAddress(mem.getLong(rttiBaseAddr.add(0x8)));
                    MemoryBlock thisBlock = mem.getBlock(thisAddr);
                    
                    if (thisBlock == null)
                    {
                        Msg.debug(this, String.format("VT 0x%X: thisBlock is null for addr 0x%X", vtOff, thisAddr.getOffset()));
                    }
                    // FIX 1: was "thisBlock != null && thisBlock.getName().startsWith(".rodata")"
                    // which is inverted — it logged "not .rodata" when rodata WAS found, and fell
                    // through to the bare else (symbol read) only when rodata was NOT found.
                    // Correct logic: skip with a debug message when the block does NOT start with
                    // ".rodata"; read the symbol when it DOES start with ".rodata".
                    else if (!thisBlock.getName().startsWith(".rodata"))
                    {
                        Msg.debug(this, String.format("VT 0x%X: thisBlock name is '%s' (not .rodata) for addr 0x%X", vtOff, thisBlock.getName(), thisAddr.getOffset()));
                    }
                    else
                    {
                        // thisBlock starts with ".rodata" — safe to read the symbol
                        String symbol = elfProvider.getReader().readAsciiString(thisAddr.getOffset());
                        Msg.debug(this, String.format("VT 0x%X: found symbol '%s'", vtOff, symbol));
                        
                        if (!symbol.isEmpty() && symbol.length() <= 512)
                        {
                        if (!symbol.startsWith("_Z"))
                            symbol = "_ZTV" + symbol;
                            
                        name = demangleIpcSymbol(symbol);
                        if (name.equals(symbol) || name.startsWith("_ZTV"))
                            name = parseMangledVtableName(symbol);
                    }
                }
            }
            }
            else
            {
                Msg.debug(this, String.format("VT 0x%X: rttiBase is 0 (no RTTI)", vtOff));
            }

            // Prefer the pre-built RTTI association when the inline name is
            // generic. SDK client/proxy vtables often demangle to a template
            // base object even though the nearby interface RTTI identifies the
            // concrete nn::fssrv::sf interface.
            if (rttiNames != null && rttiNames.containsKey(vtAddr)
                && this.shouldPreferAssociatedRttiName(program, name, rttiNames.get(vtAddr)))
            {
                String rttiResolved = rttiNames.get(vtAddr);
                String preferredName = this.formatAssociatedRttiName(program, name, rttiResolved);
                Msg.info(this, String.format("VT 0x%X: using associated RTTI name -> '%s' (was '%s')",
                    vtOff, preferredName, name));
                name = preferredName;
            }
            
            // gotDataSyms is cached in getGotDataSyms(); use the value-set built before the loop
            // for O(1) slot boundary checks instead of O(n) containsValue per iteration.
            List<Address> implAddrs = new ArrayList<>();
            long funcVtOff = 0x30;
            long funcOff;
            
            // Find all ipc impl functions in the vtable
            while ((funcOff = mem.getLong(vtAddr.add(funcVtOff))) != 0)
            {
                Address funcAddr = aSpace.getAddress(funcOff);
                MemoryBlock funcAddrBlock = mem.getBlock(funcAddr);
                
                if (this.isExecutableCodeBlock(program, funcAddrBlock))
                {
                    implAddrs.add(funcAddr);
                    funcVtOff += 0x8;
                }
                else
                {
                    Msg.debug(this, String.format("VT 0x%X: function at offset 0x%X (0x%X) is not in .text (block: %s)", 
                        vtOff, funcVtOff, funcOff, funcAddrBlock != null ? funcAddrBlock.getName() : "null"));
                    break;
                }
            
                if (gotValueAddrs.contains(vtAddr.add(funcVtOff)))
                {
                    break;
                }
            }
            
            // Debug: log when no functions found
            if (implAddrs.isEmpty())
            {
                long firstOffset = mem.getLong(vtAddr.add(0x30));
                Msg.debug(this, String.format("VT 0x%X: No .text functions found in vtable (first offset at 0x30: 0x%X)", vtOff, firstOffset));
            }
            
            Set<Address> uniqueAddrs = new HashSet<>(implAddrs);
            
            // There must be either 1 unique function without repeats, or more than one unique function with repeats allowed
            if (uniqueAddrs.size() <= 1 && implAddrs.size() != 1)
            {
                String message = String.format(
                    "Insufficient unique addresses for vtable at 0x%X (found %d functions, %d unique)",
                    vtAddr.getOffset(), implAddrs.size(), uniqueAddrs.size());
                boolean sdkRepeatedThunkVtable = this.isSdkLikeLayout(program)
                    && uniqueAddrs.size() == 1 && implAddrs.size() > 1;

                if (sdkRepeatedThunkVtable
                    || (implAddrs.isEmpty() && rttiNames != null && rttiNames.containsKey(vtAddr)))
                {
                    Msg.debug(this, message);
                }
                else
                {
                    Msg.warn(this, message);

                    for (Address addr : uniqueAddrs)
                    {
                        Msg.info(this, String.format("    Found: 0x%X", addr.getOffset()));
                    }
                }
                
                implAddrs.clear();
            }
            
            // Some IPC symbols are very long and Ghidra crops them off far too early by default.
            // Let's shorten these.
            String shortName = shortenIpcSymbol(name);
            
            var entry = new IPCVTableEntry(name, shortName, vtAddr, implAddrs);
            Msg.info(this, String.format("VTable Entry: %s @ 0x%X", entry.abvName, entry.addr.getOffset()));
            out.add(entry);
        }
        
        return out;
    }
    
    protected HashBiMap<Address, Address> locateSTables(Program program, ElfCompatibilityProvider elfProvider) throws MemoryAccessException {
        HashBiMap<Address, Address> out = HashBiMap.create();
        List<Pair<Long, Long>> candidates = new ArrayList<>();
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        Address baseAddr = program.getImageBase();
        Memory mem = program.getMemory();

        for (NXRelocation reloc : elfProvider.getRelocations())
        {
            if (reloc.addend > 0) {
                candidates.add(new Pair<>(baseAddr.getOffset() + reloc.addend, baseAddr.getOffset() + reloc.offset));
            }
            else if (reloc.r_type == R_FAKE_RELR) {
                reloc.addend = mem.getLong(baseAddr.add(reloc.offset)) - baseAddr.getOffset();
                if (reloc.addend > 0)
                    candidates.add(new Pair<>(baseAddr.getOffset() + reloc.addend, baseAddr.getOffset() + reloc.offset));
            }
        }

        Msg.info(this, String.format("locateSTables: built %d relocation candidates", candidates.size()));

        candidates.sort(Comparator.comparing(a -> a.first));

        long movMask  = 0x5288CAL;
        long movkMask = 0x72A928L;

        MemoryBlock text = mem.getBlock(".text");
        int sfciMatchCount = 0;
        int sTableFoundCount = 0;

        try
        {
            for (long off = text.getStart().getOffset(); off < text.getEnd().getOffset() - 0x4; off += 0x4)
            {
                long val1 = (elfProvider.getReader().readUnsignedInt(off) & 0xFFFFFF00L) >> 8;
                long val2 = (elfProvider.getReader().readUnsignedInt(off + 0x4) & 0xFFFFFF00L) >> 8;

                if (val1 == movMask && val2 == movkMask)
                {
                    sfciMatchCount++;
                    long processFuncOffset = 0;
                    long sTableOffset = 0;

                    for (Pair<Long, Long> candidate : candidates)
                    {
                        if (candidate.first > off)
                            break;

                        processFuncOffset = candidate.first;
                        sTableOffset = candidate.second;
                    }

                    if (processFuncOffset == 0) {
                        Msg.warn(this, String.format("  SFCI at 0x%X: no candidate found before this offset", off));
                        continue;
                    }

                    long pRetOff;
                    boolean foundRet = false;
                    for (pRetOff = processFuncOffset; pRetOff < text.getEnd().getOffset(); pRetOff += 0x4)
                    {
                        long rval = elfProvider.getReader().readUnsignedInt(pRetOff);
                        if (rval == 0xD65F03C0L)
                        {
                            foundRet = true;
                            break;
                        }
                    }

                    if (foundRet && pRetOff > off)
                    {
                        Address stAddr = aSpace.getAddress(sTableOffset);
                        Address pFuncAddr = aSpace.getAddress(processFuncOffset);
                        out.put(stAddr, pFuncAddr);
                        sTableFoundCount++;
                        Msg.info(this, String.format("  s_Table 0x%X -> process_func 0x%X (SFCI at 0x%X)",
                            sTableOffset, processFuncOffset, off));
                    }
                    else
                    {
                        Msg.warn(this, String.format("  SFCI at 0x%X: RET not found after process_func 0x%X (ret scan ended at 0x%X)",
                            off, processFuncOffset, pRetOff));
                    }
                }
            }
        }
        catch (IOException e)
        {
            Msg.error(this, "Failed to locate s_Tables", e);
        }

        Msg.info(this, String.format("locateSTables: found %d SFCI patterns, %d s_Tables", sfciMatchCount, sTableFoundCount));

        // If nothing found, the SDK may use a different dispatch pattern.
        // Try the 6.x+ "SFCO" reply magic as a secondary signal, or log that
        // the binary may use a newer dispatch mechanism.
        if (out.isEmpty()) {
            Msg.warn(this, "locateSTables: no s_Tables found via SFCI scan. " +
                "The binary may use a newer SDK dispatch mechanism (post-6.x tipc/cmif split). " +
                "Consider checking for SFCO (0x4F434653) or direct vtable dispatch.");
        }

        return out;
    }
        
    protected Multimap<Address, IPCTrace> emulateProcessFunctions(Program program, TaskMonitor monitor, Set<Address> procFuncAddrs)
    {
        Multimap<Address, IPCTrace> out = HashMultimap.create();
        IPCEmulator ipcEmu = new IPCEmulator(program);
        Set<Integer> cmdsToTry = Sets.newHashSet();
        
        // Bruteforce 0-1000
        //for (int i = 0; i <= 1000; i++)
            //cmdsToTry.add(i);
        
        // The rest we add ourselves. From SwIPC. Duplicates are avoided by using a set
        int[] presets = new int[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 4201, 106, 107, 108, 4205, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 20501, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 2413, 8216, 150, 151, 2201, 2202, 2203, 2204, 2205, 2207, 10400, 2209, 8219, 8220, 8221, 30900, 30901, 30902, 8223, 90300, 190, 8224, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 220, 20701, 222, 223, 230, 231, 250, 251, 252, 2301, 2302, 255, 256, 10500, 261, 2312, 280, 290, 291, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 2101, 20800, 20801, 322, 323, 2102, 8250, 350, 2400, 2401, 2402, 2403, 2404, 2405, 10600, 10601, 2411, 2412, 2450, 2414, 8253, 10610, 2451, 2421, 2422, 2424, 8255, 2431, 8254, 2433, 2434, 406, 8257, 400, 401, 402, 403, 404, 405, 10300, 407, 408, 409, 410, 411, 2460, 20900, 8252, 412, 2501, 10700, 10701, 10702, 8200, 1106, 1107, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511, 512, 513, 520, 521, 90200, 8201, 90201, 540, 30810, 542, 543, 544, 545, 546, 30811, 30812, 8202, 8203, 8291, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 614, 8295, 620, 8204, 8296, 630, 105, 640, 4203, 8225, 2050, 109, 30830, 2052, 8256, 700, 701, 702, 703, 704, 705, 706, 707, 708, 709, 8207, 20600, 8208, 49900, 751, 11000, 127, 8209, 800, 801, 802, 803, 804, 805, 806, 821, 822, 823, 824, 8211, 850, 851, 852, 7000, 2055, 900, 901, 902, 903, 904, 905, 906, 907, 908, 909, 3000, 3001, 3002, 160, 8012, 8217, 8013, 320, 997, 998, 999, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1020, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1061, 1062, 1063, 21000, 1100, 1101, 1102, 2053, 5202, 5203, 8218, 3200, 3201, 3202, 3203, 3204, 3205, 3206, 3207, 3208, 3209, 3210, 3211, 3214, 3215, 3216, 3217, 40100, 40101, 541, 1200, 1201, 1202, 1203, 1204, 1205, 1206, 1207, 1208, 8292, 547, 20500, 8293, 2054, 2601, 8294, 40200, 40201, 1300, 1301, 1302, 1303, 1304, 8227, 20700, 221, 8228, 8297, 8229, 4206, 1400, 1401, 1402, 1403, 1404, 1405, 1406, 1411, 1421, 1422, 1423, 1424, 30100, 30101, 30102, 1431, 1432, 30110, 30120, 30121, 1451, 1452, 1453, 1454, 1455, 1456, 1457, 1458, 1471, 1472, 1473, 1474, 1500, 1501, 1502, 1503, 1504, 1505, 2300, 30200, 30201, 30202, 30203, 30204, 30205, 30210, 30211, 30212, 30213, 30214, 30215, 30216, 30217, 260, 1600, 1601, 1602, 1603, 60001, 60002, 30300, 2051, 20100, 20101, 20102, 20103, 20104, 20110, 1700, 1701, 1702, 1703, 8222, 30400, 30401, 30402, 631, 20200, 20201, 1800, 1801, 1802, 1803, 2008, 10011, 30500, 7992, 7993, 7994, 7995, 7996, 7997, 7998, 7999, 8000, 8001, 8002, 8011, 20300, 20301, 8021, 1900, 1901, 1902, 6000, 6001, 6002, 10100, 10101, 10102, 10110, 30820, 321, 1941, 1951, 1952, 1953, 8100, 20400, 20401, 8210, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 10200, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 10211, 2020, 2021, 30700, 2030, 2031, 8251, 90100, 90101, 90102 };
        
        for (int preset : presets)
            cmdsToTry.add(preset);

        // Newer SDK dispatchers use a few command-id ranges not covered by the
        // historical preset list above. Keep these as candidates only; the emulator
        // still has to prove the command exists by executing the process function.
        int[] additionalCandidates = new int[] {
            142, 143, 144, 147, 148,
            152, 153, 154, 155, 156, 157, 158, 159,
            161, 162, 163, 164, 165, 166, 167, 168, 169,
            170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
            180, 181, 182, 191,
            219, 224, 225, 226,
            253, 271,
            292, 293,
            330, 340, 341, 342, 351, 352, 353, 360, 370,
            413, 414, 415, 416, 417, 418, 419,
            420, 421, 422, 423, 424, 425, 426, 427, 428, 429,
            430, 431, 450, 460,
            509, 514, 515, 516, 517, 518, 519,
            615, 616, 617, 618, 632,
            650, 651, 660,
            710, 720, 810, 820,
            910, 911, 912, 913, 914, 915, 916, 917, 918, 919,
            920, 921, 922, 923, 924, 925, 926, 927, 928, 929,
            930, 931, 933, 934, 935, 936,
            1014, 1015, 1016, 1017, 1018, 1019,
            1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030,
            1050,
            1110, 1111, 1112, 1113, 1114,
            1120, 1121, 1122, 1123, 1124,
            1308, 1309, 1310, 1311, 1312, 1313, 1314,
            1506, 1508, 1509, 1510, 1511, 1512,
            1604, 1605, 1606,
            1704, 1705, 1706,
            1903,
            2018, 2019,
            2022, 2023, 2024, 2025, 2026, 2027, 2028, 2029,
            2032, 2033, 2034, 2035, 2036, 2037, 2038, 2039,
            2040, 2041, 2042, 2043, 2044, 2045, 2046, 2047, 2048, 2049,
            2060, 2070,
            2100,
            2150, 2151, 2152, 2153, 2154, 2155, 2156,
            2160, 2161,
            2170, 2171,
            2180, 2181, 2182, 2183,
            2190, 2199, 2200, 2250,
            2350, 2351, 2352, 2353, 2354, 2355, 2356, 2357, 2358, 2359,
            2360, 2361, 2362, 2363, 2364, 2365, 2366, 2367, 2368, 2369,
            2500, 2502,
            2510, 2511, 2513, 2514, 2515, 2516, 2517, 2518, 2519,
            2520, 2521, 2522, 2523, 2524, 2525,
            2800,
            3003, 3004, 3005, 3006, 3007, 3008, 3009,
            3010, 3011, 3012, 3013, 3014, 3015,
            3050,
            3100, 3101, 3102, 3104, 3105, 3150,
            4000, 4004,
            4006, 4007, 4008, 4009,
            4010, 4011, 4012, 4013, 4015, 4017, 4019,
            4020, 4021, 4022, 4023, 4024, 4025, 4026, 4027, 4028, 4029,
            4030, 4031, 4032, 4033, 4034, 4035, 4037, 4038, 4039,
            4040, 4041, 4042, 4043, 4044, 4045, 4046, 4049,
            4050, 4051, 4052, 4053, 4054, 4055, 4056, 4057, 4058, 4059,
            4060, 4061, 4062, 4063, 4064, 4065, 4066, 4067, 4068, 4069,
            4070, 4071, 4072, 4073, 4074, 4075, 4076, 4077, 4078, 4079,
            4080, 4081, 4083, 4084, 4085, 4086, 4087, 4088, 4089,
            4090, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4099,
            5000, 5001,
            7988, 7989, 7991,
            8003, 8004,
            9010, 9013, 9014, 9015, 9016, 9018, 9019, 9022, 9025, 9026,
            9999, 10000
        };

        for (int candidate : additionalCandidates)
            cmdsToTry.add(candidate);

        addDatabaseCommandIds(cmdsToTry);

        // AUGMENT: statically harvest the real command-ids out of each dispatcher's own
        // switch/binary-search in the binary, and add any not already covered. This makes
        // discovery independent of the preset list AND the database: a genuinely new command
        // (one swipc/our DB never recorded) that the dispatcher actually routes will now be
        // tried and, if the emulator confirms it, surfaced as NOT_IN_DATABASE. Over-harvesting
        // is harmless (the emulator rejects ids the dispatcher does not implement). Note this
        // only recovers ids compared as literals (binary-search leaves like Capture's 0xc350=
        // 50000); index-transform dispatchers (e.g. ror-by-4 -> 16/32/64) hide the literal id,
        // but those tend to be low/dense ids the presets already cover and the emulator proves.
        int beforeHarvest = cmdsToTry.size();
        for (Address procFuncAddr : procFuncAddrs)
            harvestDispatcherCommandIds(program, procFuncAddr, cmdsToTry);
        Msg.info(this, String.format(
            "Harvested %d new static dispatcher command ids (cmdsToTry now %d)",
            cmdsToTry.size() - beforeHarvest, cmdsToTry.size()));

        Multimap<Address, IPCTrace> map = HashMultimap.create();
        
        List<Integer> sortedCmdsToTry = new ArrayList<>(cmdsToTry);
        Collections.sort(sortedCmdsToTry);

        int maxProgress = procFuncAddrs.size() * sortedCmdsToTry.size();
        int progress = 0;
        
        monitor.setMessage("Emulating IPC process functions...");
        monitor.initialize(maxProgress);
        
        for (Address procFuncAddr : procFuncAddrs)
        {
            int candidateAttempt = 0;
            int firstSuccessAttempt = -1;
            int lastSuccessAttempt = -1;
            int firstSuccessCmd = -1;
            int lastSuccessCmd = -1;
            int successCount = 0;
            int consecutiveTimeouts = 0;
            long totalCoreInstructions = 0;
            int maxCoreInstructions = 0;
            long totalCompleteInstructions = 0;
            int maxCompleteInstructions = 0;
            long totalValidationAttempts = 0;
            int maxValidationAttempts = 0;
            long timeoutUninitializedLocalReads = 0;

            for (int i = 0; i < sortedCmdsToTry.size(); i++)
            {
                int cmd = sortedCmdsToTry.get(i);
                candidateAttempt++;
                IPCTrace trace = ipcEmu.emulateCommand(procFuncAddr, cmd);

                boolean validTrace = trace != null && trace.hasDescription() && trace.vtOffset != -1;
                if (validTrace)
                {
                    map.put(procFuncAddr, trace);

                    successCount++;
                    consecutiveTimeouts = 0;

                    if (firstSuccessAttempt == -1)
                    {
                        firstSuccessAttempt = candidateAttempt;
                        firstSuccessCmd = cmd;
                    }

                    lastSuccessAttempt = candidateAttempt;
                    lastSuccessCmd = cmd;

                    int coreInstructions = trace.coreTraceInstructionCount >= 0
                        ? trace.coreTraceInstructionCount
                        : trace.instructionsExecuted;
                    int completeInstructions = trace.completeTraceInstructionCount >= 0
                        ? trace.completeTraceInstructionCount
                        : trace.instructionsExecuted;

                    totalCoreInstructions += coreInstructions;
                    maxCoreInstructions = Math.max(maxCoreInstructions, coreInstructions);
                    totalCompleteInstructions += completeInstructions;
                    maxCompleteInstructions = Math.max(maxCompleteInstructions, completeInstructions);
                    totalValidationAttempts += trace.validationAttempts;
                    maxValidationAttempts = Math.max(maxValidationAttempts, trace.validationAttempts);
                }
                else if (trace != null && trace.timedOut)
                {
                    consecutiveTimeouts++;
                    timeoutUninitializedLocalReads += trace.uninitializedLocalReads;
                    // The old "stop after 3 consecutive timeouts before any valid command" early-out was
                    // REMOVED: it silently dropped real s_Table dispatchers whose first command-id is high
                    // (IHidSystemServer@31, ISystemServer@101, IIrSensorServer@302, IServiceGetterInterface
                    // @7988, ISessionObject@999, ...). Emulating the non-existent low ids wanders/times out
                    // and tripped the 3-timeout bail before the real commands were ever reached, so the whole
                    // interface vanished (not even SRV_). Every proc_func here is a confirmed s_Table
                    // dispatcher, so all candidate ids are now tried; commands at arbitrary ids are recovered.
                }
                else
                {
                    consecutiveTimeouts = 0;
                }
            
                progress++;
                monitor.setProgress(progress);
            }

            if (successCount > 0)
            {
                Msg.info(this, String.format(
                    "IPC emu proc_func 0x%X: %d successful commands; first success candidate %d/%d cmd %d; last success candidate %d/%d cmd %d; validation attempts avg/max %d/%d; core instructions avg/max %d/%d; complete instructions avg/max %d/%d",
                    procFuncAddr.getOffset(),
                    successCount,
                    firstSuccessAttempt, sortedCmdsToTry.size(), firstSuccessCmd,
                    lastSuccessAttempt, sortedCmdsToTry.size(), lastSuccessCmd,
                    totalValidationAttempts / successCount, maxValidationAttempts,
                    totalCoreInstructions / successCount, maxCoreInstructions,
                    totalCompleteInstructions / successCount, maxCompleteInstructions));
            }
        }
        
        // Recreate the map as we can't sort the original
        for (Address procFuncAddr : map.keySet())
        {
            List<IPCTrace> traces = Lists.newArrayList(map.get(procFuncAddr).iterator());
            
            traces.sort(Comparator.comparingLong(a -> a.cmdId));
            
            for (IPCTrace trace : traces)
            {
                out.put(procFuncAddr, trace);
            }
        }
        
        return out;
    }

    private static void addDatabaseCommandIds(Set<Integer> cmdsToTry)
    {
        int before = cmdsToTry.size();

        for (Map<String, String> ifaceCmds : IPCDatabase.getInstance().getAllInterfaces().values())
        {
            for (String cmdId : ifaceCmds.keySet())
            {
                try
                {
                    cmdsToTry.add(Integer.parseInt(cmdId));
                }
                catch (NumberFormatException e)
                {
                    Msg.warn(IPCAnalyzer.class, String.format("Skipping non-integer IPC database command id '%s'", cmdId));
                }
            }
        }

        Msg.info(IPCAnalyzer.class, String.format("Added %d IPC database command ids to emulator candidates", cmdsToTry.size() - before));
    }

    // Largest plausible command id. Real ids top out around 90300; anything larger is an
    // address, a magic (e.g. SFCI 0x49434653), or an unrelated constant -- not a command id.
    private static final long MAX_PLAUSIBLE_COMMAND_ID = 0x100000L;
    // Upper bound for treating a "cmp #N; b.hi default" guard as a jump-table range [0..N].
    private static final int MAX_JUMP_TABLE_RANGE = 0x80;

    /**
     * Statically recover the command ids a CMIF dispatcher routes, by reading the comparison
     * constants out of its switch / binary-search. Scans the process function and the inner
     * dispatch function it directly calls (the SFCI-validating outer typically tail/bl-calls a
     * pure switch). Handlers are reached only via indirect (blr) vtable calls, so they are not
     * scanned and do not pollute the result.
     */
    private void harvestDispatcherCommandIds(Program program, Address procFuncAddr, Set<Integer> out)
    {
        try
        {
            FunctionManager fm = program.getFunctionManager();
            Function f0 = fm.getFunctionContaining(procFuncAddr);
            if (f0 == null)
                return;

            Set<Long> scanned = new HashSet<>();
            Set<Address> innerTargets = new HashSet<>();
            Set<Integer> local = new HashSet<>();

            // 1) the outer/process function itself (covers inline switches + the SFCI-extract path)
            scanFunctionForCommandIds(program, f0, local, innerTargets);
            scanned.add(f0.getEntryPoint().getOffset());

            // 2) the inner dispatcher(s) it directly calls (depth 1; do not follow case branches)
            for (Address target : innerTargets)
            {
                Function inner = fm.getFunctionContaining(target);
                if (inner == null)
                    continue;
                if (!scanned.add(inner.getEntryPoint().getOffset()))
                    continue;
                scanFunctionForCommandIds(program, inner, local, null);
            }

            out.addAll(local);

            // surface the high/sparse ids (the ones the preset list is least likely to cover,
            // and where genuinely-new commands hide) so a run can be eyeballed for new discoveries
            List<Integer> high = new ArrayList<>();
            for (int id : local)
                if (id >= 1000)
                    high.add(id);
            if (!high.isEmpty())
            {
                Collections.sort(high);
                Msg.info(this, String.format("harvest 0x%X: %d ids (high>=1000: %s)",
                    procFuncAddr.getOffset(), local.size(), high));
            }
        }
        catch (Exception e)
        {
            // best-effort augmentation; never let it break the analysis run
            Msg.warn(this, String.format("harvestDispatcherCommandIds failed at 0x%X: %s",
                procFuncAddr.getOffset(), e.getMessage()));
        }
    }

    /**
     * Collect command-id comparison constants from one function. Handles:
     *   - cmp Wn,#imm                        (ids <= 4095, direct immediate)
     *   - mov Wt,#lo [; movk Wt,#hi,LSL#16]; cmp Wn,Wt   (larger ids, e.g. 0xc350 = 50000)
     *   - cmp Wn,#N ; b.hi/b.cc/b.ls default (jump-table guard) -> the dense range [0..N]
     * If collectCalls is non-null, direct bl targets are recorded there (the inner dispatcher).
     */
    private void scanFunctionForCommandIds(Program program, Function func, Set<Integer> out, Set<Address> collectCalls)
    {
        Listing listing = program.getListing();
        List<Instruction> insns = new ArrayList<>();
        for (Instruction in : listing.getInstructions(func.getBody(), true))
            insns.add(in);

        for (int i = 0; i < insns.size(); i++)
        {
            Instruction insn = insns.get(i);
            String mn = insn.getMnemonicString();

            if (collectCalls != null && insn.getFlowType() != null && insn.getFlowType().isCall())
            {
                for (Address flow : insn.getFlows())
                    collectCalls.add(flow);
                continue;
            }

            if (!mn.equals("cmp") && !mn.equals("subs"))
                continue;
            if (insn.getNumOperands() < 2)
                continue;

            // the immediate may be a direct scalar, or supplied via a preceding mov/movk register
            Long id = null;
            Scalar sc = insn.getScalar(insn.getNumOperands() - 1);
            if (sc != null)
            {
                id = sc.getUnsignedValue();
            }
            else
            {
                Register cmpReg = insn.getRegister(insn.getNumOperands() - 1);
                if (cmpReg != null)
                    id = reconstructImmediate(insns, i, cmpReg);
            }
            if (id == null)
                continue;

            addCommandId(out, id);

            // a small "cmp #N" guarding an unsigned branch is a jump table over the dense range [0..N]
            if (id <= MAX_JUMP_TABLE_RANGE && i + 1 < insns.size())
            {
                String next = insns.get(i + 1).getMnemonicString();
                if (next.equals("b.hi") || next.equals("b.cs") || next.equals("b.cc")
                    || next.equals("b.lo") || next.equals("b.ls"))
                {
                    for (long r = 0; r <= id; r++)
                        addCommandId(out, r);
                }
            }
        }
    }

    /** Rebuild an immediate placed into {@code reg} by a preceding {@code mov}(+{@code movk}). */
    private Long reconstructImmediate(List<Instruction> insns, int cmpIdx, Register reg)
    {
        Long lo = null, hi = null;
        for (int j = cmpIdx - 1; j >= 0 && j >= cmpIdx - 4; j--)
        {
            Instruction in = insns.get(j);
            Register dest = in.getRegister(0);
            if (dest == null || !dest.getName().equals(reg.getName()))
                continue;
            String mn = in.getMnemonicString();
            Scalar sc = in.getScalar(1);
            if (mn.equals("movk") && sc != null)
            {
                hi = sc.getUnsignedValue();   // movk Wd,#imm,LSL #16
            }
            else if (mn.equals("mov") && sc != null)
            {
                lo = sc.getUnsignedValue();
                break;                        // mov is the base; stop walking back
            }
            else
            {
                break;                        // reg clobbered by something else
            }
        }
        if (lo == null && hi == null)
            return null;
        return (lo == null ? 0L : lo) | (hi == null ? 0L : (hi << 16));
    }

    private static void addCommandId(Set<Integer> out, long id)
    {
        if (id >= 0 && id < MAX_PLAUSIBLE_COMMAND_ID)
            out.add((int) id);
    }

    private void logIpcTraceHashes(Multimap<Address, IPCTrace> processFuncTraces)
    {
        for (Address procFuncAddr : processFuncTraces.keySet())
        {
            IpcTraceHash traceHash = getIpcTraceHash(processFuncTraces.get(procFuncAddr));

            if (traceHash == null)
                continue;

            Msg.info(this, String.format(
                "IPC trace hash for proc_func 0x%X: %s / %s (%s / %s)",
                procFuncAddr.getOffset(), traceHash.hash, traceHash.alternateHash,
                traceHash.hashCode, traceHash.alternateHashCode));
        }
    }

    private Set<String> collectLocalInterfaceNames(List<IPCVTableEntry> vtEntries)
    {
        Map<String, Map<String, String>> databaseInterfaces = IPCDatabase.getInstance().getAllInterfaces();
        Set<String> out = new LinkedHashSet<>();

        for (IPCVTableEntry entry : vtEntries)
        {
            if (!entry.hasRealVtable)
                continue;

            String interfaceName = entry.abvName.replace("::vtable", "");

            if (interfaceName.startsWith("SRV_"))
                continue;

            if (databaseInterfaces.containsKey(interfaceName))
                out.add(interfaceName);
        }

        return out;
    }

    private IPCHashDatabase.HashMatch findUniqueHashInterfaceMatch(Address procFuncAddr,
                                                                    Collection<IPCTrace> traces,
                                                                    Set<String> localInterfaceNames)
    {
        IpcTraceHash traceHash = getIpcTraceHash(traces);

        if (traceHash == null)
            return null;

        IPCHashDatabase.HashMatch hashMatch = IPCHashDatabase.getInstance()
            .findMatch(traceHash.hash, traceHash.alternateHash);

        if (hashMatch == null)
            return null;

        if (!hashMatch.isUnique())
        {
            List<String> localCandidates = hashMatch.interfaces.stream()
                .filter(localInterfaceNames::contains)
                .distinct()
                .collect(Collectors.toList());

            if (localCandidates.size() == 1)
            {
                Msg.info(this, String.format(
                    "%s match for proc_func 0x%X is ambiguous but narrowed by local RTTI/vtable evidence: %s -> %s from %s",
                    hashMatch.formatSource(), procFuncAddr.getOffset(),
                    hashMatch.hash, localCandidates.get(0), hashMatch.interfaces));

                return hashMatch.narrowToInterface(localCandidates.get(0),
                    hashMatch.legacy300 ? "3.0.0 hash+local-rtti" : "hash+local-rtti");
            }

            Msg.info(this, String.format(
                "%s match for proc_func 0x%X is ambiguous: %s -> %s",
                hashMatch.formatSource(), procFuncAddr.getOffset(),
                hashMatch.hash, hashMatch.interfaces));
            return null;
        }

        return hashMatch;
    }

    private static IpcTraceHash getIpcTraceHash(Collection<IPCTrace> traces)
    {
        if (traces == null || traces.isEmpty())
            return null;

        List<IpcTraceHashPart> parts = new ArrayList<>();
        List<IPCTrace> orderedTraces = new ArrayList<>(traces);
        orderedTraces.sort(Comparator.comparingLong(trace -> trace.cmdId));

        for (IPCTrace trace : orderedTraces)
        {
            if (!trace.hasDescription() || trace.bytesIn < 0)
                continue;

            // Reproducible structural signature for this command. Order is fixed and must match the
            // hash-DB generator: buffers, out-words, out-interfaces, out-handles, in-handles, pid.
            // Earlier this only encoded inputs (+ an address-based out-object index), so interfaces
            // with identical inputs but different OUTPUTS collided; including outputs/handles fixes that.
            StringBuilder suffix = new StringBuilder();
            int cDescSizeExtra = 0;

            if (trace.hasBufferAttrs())
            {
                suffix.append(";b");

                for (int i = 0; i < trace.bufferAttrs.length; i++)
                {
                    int attr = trace.bufferAttrs[i];

                    if (i > 0)
                        suffix.append(",");

                    suffix.append(attr);

                    if (attr == 10 || attr == 34)
                        cDescSizeExtra += 2;
                }
            }

            if (trace.bytesOut > 0)
                suffix.append(";O").append((trace.bytesOut + 3) / 4);

            if (trace.outInterfaces > 0)
                suffix.append(";I").append(trace.outInterfaces);

            if (trace.outHandles > 0)
                suffix.append(";H").append(trace.outHandles);

            if (trace.inHandles > 0)
                suffix.append(";h").append(trace.inHandles);

            if (trace.pid)
                suffix.append(";p");

            suffix.append(")");

            String hashCode = String.format("%d(%d%s", trace.cmdId,
                (trace.bytesIn + 3 + cDescSizeExtra) / 4, suffix);
            String alternateHashCode = String.format("%d(%d%s", trace.cmdId,
                (trace.bytesIn + 3) / 4, suffix);
            Long vtOffset = trace.vtOffset != -1 ? trace.vtOffset : null;

            parts.add(new IpcTraceHashPart(vtOffset, hashCode, alternateHashCode));
        }

        if (parts.isEmpty())
            return null;

        parts.sort(Comparator
            .comparing((IpcTraceHashPart part) -> part.vtOffset == null)
            .thenComparingLong(part -> part.vtOffset != null ? part.vtOffset : 0));

        StringBuilder hashCode = new StringBuilder();
        StringBuilder alternateHashCode = new StringBuilder();

        for (IpcTraceHashPart part : parts)
        {
            hashCode.append(part.hashCode);
            alternateHashCode.append(part.alternateHashCode);
        }

        return new IpcTraceHash(sha224Hex16(hashCode.toString()),
            sha224Hex16(alternateHashCode.toString()),
            hashCode.toString(), alternateHashCode.toString());
    }

    private static String sha224Hex16(String value)
    {
        try
        {
            MessageDigest digest = MessageDigest.getInstance("SHA-224");
            byte[] hashed = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder();

            for (byte b : hashed)
                out.append(String.format("%02x", b & 0xFF));

            return out.substring(0, 16);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException("SHA-224 is not available", e);
        }
    }

    private static class IpcTraceHash
    {
        private final String hash;
        private final String alternateHash;
        private final String hashCode;
        private final String alternateHashCode;

        private IpcTraceHash(String hash, String alternateHash, String hashCode, String alternateHashCode)
        {
            this.hash = hash;
            this.alternateHash = alternateHash;
            this.hashCode = hashCode;
            this.alternateHashCode = alternateHashCode;
        }
    }

    private static class IpcTraceHashPart
    {
        private final Long vtOffset;
        private final String hashCode;
        private final String alternateHashCode;

        private IpcTraceHashPart(Long vtOffset, String hashCode, String alternateHashCode)
        {
            this.vtOffset = vtOffset;
            this.hashCode = hashCode;
            this.alternateHashCode = alternateHashCode;
        }
    }

    private static InterfaceMatch findBestInterfaceMatch(Map<String, Map<String, String>> allIfaces, Set<Long> emulatedCmds)
    {
        InterfaceMatch bestMatch = null;
        List<InterfaceMatch> goodMatches = new ArrayList<>();

        for (Map.Entry<String, Map<String, String>> dbEntry : allIfaces.entrySet())
        {
            Set<Long> dbCmds = parseCommandIds(dbEntry.getValue().keySet());
            int score = 0;

            for (Long cmdId : emulatedCmds)
            {
                if (dbCmds.contains(cmdId))
                    score++;
            }

            if (score == 0)
                continue;

            InterfaceMatch match = new InterfaceMatch(dbEntry.getKey(), score, emulatedCmds.size(), dbCmds);
            if (!match.isGoodEnough())
                continue;

            goodMatches.add(match);

            if (bestMatch == null || match.isBetterThan(bestMatch))
                bestMatch = match;
        }

        return bestMatch != null ? bestMatch.withExactCommandSetAmbiguity(goodMatches) : null;
    }

    private static InterfaceMatch findBestPartialInterfaceMatch(Map<String, Map<String, String>> allIfaces,
                                                                Set<Long> observedCmds,
                                                                int minimumScore)
    {
        InterfaceMatch bestMatch = null;
        List<InterfaceMatch> matches = new ArrayList<>();

        for (Map.Entry<String, Map<String, String>> dbEntry : allIfaces.entrySet())
        {
            Set<Long> dbCmds = parseCommandIds(dbEntry.getValue().keySet());
            int score = 0;

            for (Long cmdId : observedCmds)
            {
                if (dbCmds.contains(cmdId))
                    score++;
            }

            if (score < minimumScore)
                continue;

            InterfaceMatch match = new InterfaceMatch(dbEntry.getKey(), score, observedCmds.size(), dbCmds);
            matches.add(match);

            if (bestMatch == null || match.isBetterThan(bestMatch))
                bestMatch = match;
        }

        return bestMatch != null ? bestMatch.withExactCommandSetAmbiguity(matches) : null;
    }

    private static class InterfaceMatch
    {
        private final String iface;
        private final int score;
        private final int emulatedCmdCount;
        private final Set<Long> dbCommandIds;
        private final int dbCmdCount;
        private final int exactCommandSetMatchCount;
        private final List<String> exactCommandSetMatchExamples;

        private InterfaceMatch(String iface, int score, int emulatedCmdCount, Set<Long> dbCommandIds)
        {
            this(iface, score, emulatedCmdCount, dbCommandIds, 0, Collections.emptyList());
        }

        private InterfaceMatch(String iface, int score, int emulatedCmdCount,
                               Set<Long> dbCommandIds, int exactCommandSetMatchCount,
                               List<String> exactCommandSetMatchExamples)
        {
            this.iface = iface;
            this.score = score;
            this.emulatedCmdCount = emulatedCmdCount;
            this.dbCommandIds = Collections.unmodifiableSet(new LinkedHashSet<>(dbCommandIds));
            this.dbCmdCount = dbCommandIds.size();
            this.exactCommandSetMatchCount = exactCommandSetMatchCount;
            this.exactCommandSetMatchExamples = Collections.unmodifiableList(new ArrayList<>(exactCommandSetMatchExamples));
        }

        private InterfaceMatch withExactCommandSetAmbiguity(List<InterfaceMatch> matches)
        {
            List<String> exactMatches = matches.stream()
                .filter(match -> match.dbCommandIds.equals(this.dbCommandIds))
                .map(match -> match.iface)
                .sorted()
                .collect(Collectors.toList());

            return new InterfaceMatch(this.iface, this.score, this.emulatedCmdCount,
                this.dbCommandIds, exactMatches.size(),
                exactMatches.stream().limit(5).collect(Collectors.toList()));
        }

        private double emulatedCoverage()
        {
            return (double)this.score / this.emulatedCmdCount;
        }

        private double databaseCoverage()
        {
            return (double)this.score / this.dbCmdCount;
        }

        private boolean isGoodEnough()
        {
            if (this.emulatedCmdCount <= 2)
                return this.score == this.emulatedCmdCount && this.dbCmdCount <= this.emulatedCmdCount + 1;

            return (this.score >= 2 && this.emulatedCoverage() >= 0.3) ||
                (this.emulatedCmdCount <= 5 && this.score == this.emulatedCmdCount);
        }

        private boolean hasUniqueExactCommandSet()
        {
            return this.exactCommandSetMatchCount <= 1;
        }

        private boolean isBetterThan(InterfaceMatch other)
        {
            int cmp = Integer.compare(this.score, other.score);
            if (cmp != 0)
                return cmp > 0;

            cmp = Double.compare(this.emulatedCoverage(), other.emulatedCoverage());
            if (cmp != 0)
                return cmp > 0;

            cmp = Double.compare(this.databaseCoverage(), other.databaseCoverage());
            if (cmp != 0)
                return cmp > 0;

            return this.dbCmdCount < other.dbCmdCount;
        }

        private String formatAmbiguity()
        {
            if (this.hasUniqueExactCommandSet())
                return "unique exact cmd set";

            return String.format("exact cmd-set alternatives %d %s",
                this.exactCommandSetMatchCount, this.exactCommandSetMatchExamples);
        }
    }

    protected HashBiMap<Address, IPCVTableEntry> matchVtables(List<IPCVTableEntry> vtEntries, Set<Address> procFuncAddrs, Multimap<Address, IPCTrace> processFuncTraces)
    {
        // Map process func addrs to vtable addrs
        HashBiMap<Address, IPCVTableEntry> out = HashBiMap.create();
        
        // Filter out vtables with 0 functions - these are likely client/import proxy interfaces, not server/export dispatchers.
        List<IPCVTableEntry> dispatcherVtables = vtEntries.stream()
            .filter(entry -> entry.ipcFuncs.size() > 0)
            .collect(Collectors.toList());
        
        List<IPCVTableEntry> possibilities = Lists.newArrayList(dispatcherVtables.iterator());
        
        if (dispatcherVtables.size() < vtEntries.size())
        {
            Msg.info(this, String.format("Skipping %d client/import proxy vtables with 0 functions",
                vtEntries.size() - dispatcherVtables.size()));
        }
        
        for (Address procFuncAddr : procFuncAddrs)
        {
            // We've already found this address. No need to do it again
            if (out.containsKey(procFuncAddr))
                continue;
            
            List<IPCVTableEntry> filteredPossibilities = possibilities.stream().filter(vtEntry -> vtEntry.ipcFuncs.size() == getProcFuncVTableSize(processFuncTraces, procFuncAddr)).collect(Collectors.toList());
            
            // See if there is a single entry that *exactly* matches the vtable size
            if (filteredPossibilities.size() == 1)
            {
                IPCVTableEntry vtEntry = filteredPossibilities.get(0);
                out.put(procFuncAddr, vtEntry);
                possibilities.remove(vtEntry);
                continue;
            }
            
            filteredPossibilities = possibilities.stream().filter(vtEntry -> vtEntry.ipcFuncs.size() >= getProcFuncVTableSize(processFuncTraces, procFuncAddr)).collect(Collectors.toList());

            // See if there is a single entry that is equal to or greater than the vtable size
            if (filteredPossibilities.size() == 1)
            {
                IPCVTableEntry vtEntry = filteredPossibilities.get(0);
                out.put(procFuncAddr, vtEntry);
                possibilities.remove(vtEntry);
                continue;
            }
            
            // Iterate over all the possible vtables with a size greater than our current process function
            for (IPCVTableEntry filteredPossibility : filteredPossibilities)
            {
                List<Address> unlocatedProcFuncAddrs = procFuncAddrs.stream().filter(pFAddr -> !out.containsKey(pFAddr)).toList();
                
                // See if there is only a single trace set of size <= this vtable
                // For example, if the process func vtable size is found by emulation to be 0x100, and we have previously found vtables of the following sizes, which have yet to be located:
                // 0x10, 0x20, 0x60, 0x110, 0x230
                // We will run this loop for both 0x110 and 0x230. 
                // In the case of 0x110, we will then filter for sizes <= 0x110. These are 0x10, 0x20, 0x60 and 0x110
                // As there are four of these, the check will fail.
                if (unlocatedProcFuncAddrs.stream().filter(unlocatedProcFuncAddr -> getProcFuncVTableSize(processFuncTraces, unlocatedProcFuncAddr) <= filteredPossibility.ipcFuncs.size()).count() == 1)
                {
                    out.put(procFuncAddr, filteredPossibility);
                    possibilities.remove(filteredPossibility);
                    break;
                }
            }
        }
        
        List<Address> unlocatedProcFuncAddrs = procFuncAddrs.stream().filter(pFAddr -> !out.containsKey(pFAddr)).toList();
        
        for (Address addr : unlocatedProcFuncAddrs)
        {
            Msg.info(this, String.format("Unmatched process func at 0x%X. Calculated VTable Size: 0x%X", addr.getOffset(), getProcFuncVTableSize(processFuncTraces, addr)));
        }
        
        // Only report unmatched server/export dispatcher vtables (size > 0), as size-0 client/import proxy vtables are expected to not match.
        for (IPCVTableEntry entry : possibilities)
        {
            if (entry.ipcFuncs.size() > 0)
            {
                Msg.info(this, String.format("Unmatched IPC VTable entry at 0x%X. VTable Size: 0x%X", entry.addr.getOffset(), entry.ipcFuncs.size()));
            }
        }
        
        return out;
    }
    
    protected void markupIpc(Program program, TaskMonitor monitor, List<IPCVTableEntry> vtEntries,
                             HashBiMap<Address, Address> sTableProcessFuncMap,
                             Multimap<Address, IPCTrace> processFuncTraces,
                             HashBiMap<Address, IPCVTableEntry> procFuncVtMap,
                             Map<Address, SyntheticCommandFunctionTable> syntheticCommandTables)
    {
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();

        // Positional inference, computed up front so the markup names un-hash-matched (SRV_) interfaces
        // by DB position too -- same algorithm/result as the JSON export's _likely.
        Map<Long, MarkupInferenceNode> inferred =
            this.computeMarkupInference(vtEntries, procFuncVtMap, processFuncTraces);

        try
        {
            // Analyze and label any IPC info found
            for (IPCVTableEntry entry : vtEntries)
            {
                List<IPCTrace> ipcTraces = Lists.newArrayList();
                Address processFuncAddr = procFuncVtMap.inverse().get(entry);

                // An un-hash-matched SRV_ interface gets its positionally-inferred name applied to ALL
                // markup (vtable/s_Table label, command labels + names, comments). entry.abvName stays
                // SRV_ so we still detect the substitution.
                String rawNameNoSuffix = entry.abvName.replace("::vtable", "");
                MarkupInferenceNode inferredNode = processFuncAddr != null
                    ? inferred.get(processFuncAddr.getOffset()) : null;
                boolean nameInferred = inferredNode != null && rawNameNoSuffix.startsWith("SRV_");
                String entryNameNoSuffix = nameInferred ? inferredNode.inferredName : rawNameNoSuffix;

                if (processFuncAddr != null)
                {
                    Address sTableAddr = sTableProcessFuncMap.inverse().get(processFuncAddr);

                    if (sTableAddr != null)
                    {
                        IpcTraceHash traceHash = getIpcTraceHash(processFuncTraces.get(processFuncAddr));
                        StringBuilder ipcComment = new StringBuilder();

                        ipcComment.append("IPC INFORMATION\n");
                        ipcComment.append(String.format("s_Table Address:       0x%X", sTableAddr.getOffset()));

                        if (traceHash != null)
                        {
                            ipcComment.append("\n");
                            ipcComment.append(String.format("Interface hash:        %s", traceHash.hash));

                            if (!traceHash.hash.equals(traceHash.alternateHash))
                            {
                                ipcComment.append("\n");
                                ipcComment.append(String.format("Interface hash alt:    %s", traceHash.alternateHash));
                            }
                        }

                        if (nameInferred)
                        {
                            ipcComment.append("\n");
                            ipcComment.append(String.format("Name (inferred):       %s  [%s]",
                                inferredNode.inferredName, inferredNode.inferredBasis));
                        }

                        program.getListing().setComment(entry.addr, CommentType.PLATE, ipcComment.toString());
                    }

                    ipcTraces = Lists.newArrayList(processFuncTraces.get(processFuncAddr).iterator());
                }

                IpcTraceHash interfaceHash = getIpcTraceHash(ipcTraces);

                // Set the vtable/s_Table name. Created fresh on first analysis; for a positionally-
                // INFERRED name, also apply it over an existing SRV_ placeholder on RE-analysis and make
                // it primary, so the real name shows (a vtable address is unique, so this is safe).
                String vtLabel = entry.hasRealVtable
                    ? entryNameNoSuffix + "::vtable"
                    : entryNameNoSuffix + "::s_Table";

                if ((!this.hasImportedSymbol(program, entry.addr) || nameInferred)
                    && !this.hasSymbolNamed(program, entry.addr, vtLabel))
                {
                    // For shortened names, leave a comment so the user knows what the original name is
                    if (entry.hasRealVtable && !entry.fullName.equals(entry.abvName))
                        program.getListing().setComment(entry.addr, CommentType.REPEATABLE, entry.fullName);

                    Msg.info(this, String.format("Creating label for %s @ 0x%X", vtLabel, entry.addr.getOffset()));
                    Symbol vtSym = program.getSymbolTable().createLabel(entry.addr, vtLabel, null, SourceType.IMPORTED);
                    if (nameInferred && vtSym != null)
                        this.makeSymbolPrimaryIfNotUserNamed(program, entry.addr, vtSym);
                }

                if (!entry.hasRealVtable)
                {
                    SyntheticCommandFunctionTable commandTable =
                        syntheticCommandTables != null ? syntheticCommandTables.get(processFuncAddr) : null;
                    Set<Long> tableMarkedCommands = commandTable != null
                        ? this.markupSyntheticIpcCommandTable(program, ipcTraces, interfaceHash,
                            entryNameNoSuffix, commandTable, nameInferred)
                        : Collections.emptySet();
                    List<IPCTrace> fallbackTraces = ipcTraces.stream()
                        .filter(trace -> !tableMarkedCommands.contains(trace.cmdId))
                        .collect(Collectors.toList());

                    if (!fallbackTraces.isEmpty())
                        this.markupSyntheticIpcCommandSites(program, aSpace, fallbackTraces, interfaceHash,
                            entryNameNoSuffix, nameInferred);
                    continue;
                }
                
                // Annotate the four functions that exist for all ipc vtables.
                // These are frequently shared across interfaces, so labeling the
                // targets makes unrelated command labels pile up on common code.
                for (int i = 0; i < 4; i++)
                {
                    Address vtAddr = entry.addr.add(0x10 + i * 0x8);
                    String name = "";
                    
                    // Set vtable func data types to pointers
                    this.createPointer(program, vtAddr);

                    switch (i) {
                        case 0 -> name = "AddReference";
                        case 1 -> name = "Release";
                        case 2 -> name = "GetProxyInfo";
                        // Shared by everything
                        case 3 -> name = "nn::sf::IServiceObject::GetInterfaceTypeInfo";
                    }

                    program.getListing().setComment(vtAddr, CommentType.REPEATABLE, name);
                }
                
                for (int i = 0; i < entry.ipcFuncs.size(); i++)
                {
                    Address func = entry.ipcFuncs.get(i);
                    String name = null;
    
                    // Set vtable func data types to pointers
                    this.createPointer(program, entry.addr.add(0x30 + i * 0x8L));
                }
                
                for (IPCTrace trace : ipcTraces)
                {
                    // Safety precaution. I *think* these should've been filtered out earlier though.
                    if (trace.vtOffset == -1 || !trace.hasDescription())
                        continue;
                    
                    Address vtOffsetAddr = entry.addr.add(0x10 + trace.vtOffset);
                    Address ipcCmdImplAddr = aSpace.getAddress(program.getMemory().getLong(vtOffsetAddr));

                    Msg.debug(this, String.format("Looking up cmd: iface='%s' cmdId=%d", entryNameNoSuffix, trace.cmdId));
                    String cmdName = IPCDatabase.getInstance().getCommandName(entryNameNoSuffix, trace.cmdId);
                    Msg.debug(this, String.format("  result: %s", cmdName));
                    String label;
                    if (cmdName != null)
                        label = String.format("%s::[%d]%s", entryNameNoSuffix, trace.cmdId, cmdName);
                    else
                        label = String.format("%s::Cmd%d", entryNameNoSuffix, trace.cmdId);

                    // For an inferred interface, also (re)apply its command labels over SRV_ placeholders
                    // on re-analysis. These impl/target addresses are frequently SHARED thunks, so the
                    // label is added but NOT forced primary (avoids churning unrelated shared code).
                    boolean canMarkupImplAddr = nameInferred
                        || this.canMarkupIpcCommandAddress(program, ipcCmdImplAddr, label);

                    if (canMarkupImplAddr && !this.hasSymbolNamed(program, ipcCmdImplAddr, label))
                    {
                        try
                        {
                            program.getSymbolTable().createLabel(ipcCmdImplAddr, label, null, SourceType.IMPORTED);
                        }
                        catch (InvalidInputException e)
                        {
                            Msg.warn(this, String.format("Failed to create IPC command label '%s' at 0x%X: %s",
                                label, ipcCmdImplAddr.getOffset(), e.getMessage()));
                        }
                    }

                    Address ipcCmdTargetAddr = this.findDirectThunkTarget(program, ipcCmdImplAddr);

                    boolean canMarkupTargetAddr = ipcCmdTargetAddr != null
                        && (nameInferred || this.canMarkupIpcCommandAddress(program, ipcCmdTargetAddr, label));

                    if (canMarkupTargetAddr && !this.hasSymbolNamed(program, ipcCmdTargetAddr, label))
                    {
                        try
                        {
                            program.getSymbolTable().createLabel(ipcCmdTargetAddr, label, null, SourceType.IMPORTED);
                        }
                        catch (InvalidInputException e)
                        {
                            Msg.warn(this, String.format("Failed to create IPC command target label '%s' at 0x%X: %s",
                                label, ipcCmdTargetAddr.getOffset(), e.getMessage()));
                        }
                    }
                    
                    String wireLayout = this.formatLogicalWireLayout(program, trace, ipcCmdTargetAddr);

                    if (canMarkupImplAddr)
                    {
                        program.getListing().setComment(ipcCmdImplAddr, CommentType.PLATE,
                            this.formatIpcComment(trace, interfaceHash, entryNameNoSuffix, cmdName, ipcCmdImplAddr, wireLayout));
                    }

                    if (canMarkupTargetAddr)
                    {
                        program.getListing().setComment(ipcCmdTargetAddr, CommentType.PLATE,
                            this.formatIpcComment(trace, interfaceHash, entryNameNoSuffix, cmdName, ipcCmdImplAddr, wireLayout));
                        this.renameBranchTargetParams(program, trace, ipcCmdTargetAddr);
                    }
                }
            }
            
            // Annotate s_Tables
            for (Address stAddr : sTableProcessFuncMap.keySet())
            {
                this.createPointer(program, stAddr);
                
                if (!this.hasImportedSymbol(program, stAddr))
                {
                    Address procFuncAddr = sTableProcessFuncMap.get(stAddr);
                    String sTableName = String.format("SRV_S_TAB_%X", stAddr.getOffset());
                    
                    if (procFuncAddr != null)
                    {
                        IPCVTableEntry entry = procFuncVtMap.get(procFuncAddr);
                        
                        if (entry != null)
                        {
                            String stNameNoSuffix = entry.abvName.replace("::vtable", "");
                            MarkupInferenceNode stInferred = inferred.get(procFuncAddr.getOffset());
                            if (stInferred != null && stNameNoSuffix.startsWith("SRV_"))
                                stNameNoSuffix = stInferred.inferredName;   // inferred name on the s_Table too
                            sTableName = stNameNoSuffix + "::s_Table";
                        }
                    }
                    
                    program.getSymbolTable().createLabel(stAddr, sTableName, null, SourceType.IMPORTED);
                }
            }
        }
        catch (InvalidInputException | AddressOutOfBoundsException | MemoryAccessException e)
        {
            Msg.error(this, "Failed to markup IPC", e);
        }
    }

    private Set<Long> markupSyntheticIpcCommandTable(Program program, List<IPCTrace> ipcTraces,
                                                     IpcTraceHash interfaceHash, String entryNameNoSuffix,
                                                     SyntheticCommandFunctionTable commandTable, boolean nameInferred)
    {
        Set<Long> markedCommands = new LinkedHashSet<>();

        for (IPCTrace trace : ipcTraces)
        {
            if (trace.vtOffset == -1 || !trace.hasDescription())
                continue;

            Address ipcCmdImplAddr = commandTable.getFunction(trace.vtOffset);

            if (ipcCmdImplAddr == null)
                continue;

            Address slotAddr = commandTable.getSlotAddress(trace.vtOffset);
            this.createPointer(program, slotAddr);

            Msg.debug(this, String.format("Looking up cmd: iface='%s' cmdId=%d", entryNameNoSuffix, trace.cmdId));
            String cmdName = IPCDatabase.getInstance().getCommandName(entryNameNoSuffix, trace.cmdId);
            Msg.debug(this, String.format("  result: %s", cmdName));

            String label;
            if (cmdName != null)
                label = String.format("%s::[%d]%s", entryNameNoSuffix, trace.cmdId, cmdName);
            else
                label = String.format("%s::Cmd%d", entryNameNoSuffix, trace.cmdId);

            program.getListing().setComment(slotAddr, CommentType.REPEATABLE,
                String.format("IPC command table slot: %s +0x%X -> 0x%X, cmd %d",
                    entryNameNoSuffix, trace.vtOffset, ipcCmdImplAddr.getOffset(), trace.cmdId));

            boolean canMarkupImplAddr = nameInferred
                || this.canMarkupIpcCommandAddress(program, ipcCmdImplAddr, label);

            if (canMarkupImplAddr && !this.hasSymbolNamed(program, ipcCmdImplAddr, label))
            {
                try
                {
                    program.getSymbolTable().createLabel(ipcCmdImplAddr, label, null, SourceType.IMPORTED);
                }
                catch (InvalidInputException e)
                {
                    Msg.warn(this, String.format("Failed to create IPC command label '%s' at 0x%X: %s",
                        label, ipcCmdImplAddr.getOffset(), e.getMessage()));
                }
            }

            Address ipcCmdTargetAddr = this.findDirectThunkTarget(program, ipcCmdImplAddr);

            boolean canMarkupTargetAddr = ipcCmdTargetAddr != null
                && (nameInferred || this.canMarkupIpcCommandAddress(program, ipcCmdTargetAddr, label));

            if (canMarkupTargetAddr && !this.hasSymbolNamed(program, ipcCmdTargetAddr, label))
            {
                try
                {
                    program.getSymbolTable().createLabel(ipcCmdTargetAddr, label, null, SourceType.IMPORTED);
                }
                catch (InvalidInputException e)
                {
                    Msg.warn(this, String.format("Failed to create IPC command target label '%s' at 0x%X: %s",
                        label, ipcCmdTargetAddr.getOffset(), e.getMessage()));
                }
            }

            String wireLayout = this.formatLogicalWireLayout(program, trace, ipcCmdTargetAddr);

            if (canMarkupImplAddr)
            {
                program.getListing().setComment(ipcCmdImplAddr, CommentType.PLATE,
                    this.formatIpcComment(trace, interfaceHash, entryNameNoSuffix, cmdName, ipcCmdImplAddr,
                        wireLayout));
            }

            if (canMarkupTargetAddr)
            {
                program.getListing().setComment(ipcCmdTargetAddr, CommentType.PLATE,
                    this.formatIpcComment(trace, interfaceHash, entryNameNoSuffix, cmdName, ipcCmdImplAddr,
                        wireLayout));
                this.renameBranchTargetParams(program, trace, ipcCmdTargetAddr);
            }

            markedCommands.add(trace.cmdId);
        }

        return markedCommands;
    }

    private void markupSyntheticIpcCommandSites(Program program, AddressSpace aSpace, List<IPCTrace> ipcTraces,
                                                IpcTraceHash interfaceHash, String entryNameNoSuffix, boolean nameInferred)
    {
        BasicBlockModel blockModel = new BasicBlockModel(program);
        Map<Address, Set<Long>> commandIdsByFunctionEntry = new HashMap<>();

        for (IPCTrace trace : ipcTraces)
        {
            if (trace.lr == -1 || trace.vtOffset == -1 || !trace.hasDescription())
                continue;

            Address lrAddr = aSpace.getAddress(trace.lr);
            Address commandAnchorAddr = this.findCallsiteAddressBeforeLr(program, lrAddr);
            Function function = program.getFunctionManager().getFunctionContaining(commandAnchorAddr);

            if (function != null)
            {
                commandIdsByFunctionEntry
                    .computeIfAbsent(function.getEntryPoint(), k -> new LinkedHashSet<>())
                    .add(trace.cmdId);
            }
        }

        for (IPCTrace trace : ipcTraces)
        {
            if (trace.lr == -1 || trace.vtOffset == -1 || !trace.hasDescription())
                continue;

            Address lrAddr = aSpace.getAddress(trace.lr);
            Address commandAnchorAddr = this.findCallsiteAddressBeforeLr(program, lrAddr);
            Address dispatchSiteAddr = this.findSyntheticCommandLabelAddress(program, blockModel, commandAnchorAddr,
                commandIdsByFunctionEntry);
            MemoryBlock dispatchSiteBlock = program.getMemory().getBlock(dispatchSiteAddr);

            if (!this.isExecutableCodeBlock(program, dispatchSiteBlock))
                continue;

            Msg.debug(this, String.format("Looking up cmd: iface='%s' cmdId=%d", entryNameNoSuffix, trace.cmdId));
            String cmdName = IPCDatabase.getInstance().getCommandName(entryNameNoSuffix, trace.cmdId);
            Msg.debug(this, String.format("  result: %s", cmdName));

            String label;
            if (cmdName != null)
                label = String.format("%s::[%d]%s", entryNameNoSuffix, trace.cmdId, cmdName);
            else
                label = String.format("%s::Cmd%d", entryNameNoSuffix, trace.cmdId);

            boolean canMarkupDispatchSite = nameInferred
                || this.canMarkupIpcCommandAddress(program, dispatchSiteAddr, label);

            if (canMarkupDispatchSite && !this.hasSymbolNamed(program, dispatchSiteAddr, label))
            {
                try
                {
                    program.getSymbolTable().createLabel(dispatchSiteAddr, label, null, SourceType.IMPORTED);
                }
                catch (InvalidInputException e)
                {
                    Msg.warn(this, String.format("Failed to create IPC command dispatch label '%s' at 0x%X: %s",
                        label, dispatchSiteAddr.getOffset(), e.getMessage()));
                }
            }

            if (canMarkupDispatchSite)
            {
                String wireLayout = this.formatLogicalWireLayout(program, trace, null);
                program.getListing().setComment(dispatchSiteAddr, CommentType.PLATE,
                    this.formatIpcComment(trace, interfaceHash, entryNameNoSuffix, cmdName, dispatchSiteAddr, wireLayout));
            }
        }
    }

    private Address findCallsiteAddressBeforeLr(Program program, Address lrAddr)
    {
        Instruction instruction = program.getListing().getInstructionBefore(lrAddr);

        if (instruction != null && instruction.getFlowType().isCall())
            return instruction.getAddress();

        return lrAddr;
    }

    private Address findSyntheticCommandLabelAddress(Program program, BasicBlockModel blockModel, Address commandAnchorAddr,
                                                     Map<Address, Set<Long>> commandIdsByFunctionEntry)
    {
        Function function = program.getFunctionManager().getFunctionContaining(commandAnchorAddr);

        if (function != null)
        {
            Set<Long> commandIds = commandIdsByFunctionEntry.get(function.getEntryPoint());

            if (commandIds == null || commandIds.size() <= 1)
                return function.getEntryPoint();
        }

        return this.findContainingBasicBlockStart(blockModel, commandAnchorAddr);
    }

    private Address findContainingBasicBlockStart(BasicBlockModel blockModel, Address addr)
    {
        try
        {
            CodeBlock block = blockModel.getFirstCodeBlockContaining(addr, TaskMonitor.DUMMY);

            if (block != null && block.getFirstStartAddress() != null)
                return block.getFirstStartAddress();
        }
        catch (CancelledException e)
        {
            Msg.debug(this, String.format("Failed to find basic block containing 0x%X: %s",
                addr.getOffset(), e.getMessage()));
        }

        return addr;
    }

    private List<IPCInterfaceVTableGroup> markupInterfaceVtableGroups(Program program, Map<Address, String> rttiNames)
    {
        try
        {
            List<IPCInterfaceVTableGroup> groups = this.recoverInterfaceVtableGroups(program, rttiNames);

            if (groups.isEmpty())
            {
                Msg.info(this, "Recovered 0 IPC interface vtable groups");
                return groups;
            }

            for (IPCInterfaceVTableGroup group : groups)
            {
                String vtableLabel = group.interfaceName + "::vtable";

                if (!this.hasImportedSymbol(program, group.vtableAddr))
                    this.createImportedLabel(program, group.vtableAddr, vtableLabel);

                program.getListing().setComment(group.vtableAddr, CommentType.PLATE,
                    this.formatInterfaceVtableGroupComment(group));

                for (IPCInterfaceVTableSlot slot : group.slots)
                {
                    this.createPointer(program, slot.slotAddr);

                    String commandName = slot.commandId != null
                        ? group.commands.get(String.valueOf(slot.commandId))
                        : null;

                    program.getListing().setComment(slot.slotAddr, CommentType.REPEATABLE,
                        this.formatInterfaceVtableSlotComment(group, slot, commandName));

                    if (slot.commandId != null)
                    {
                        String label = commandName != null
                            ? String.format("%s::[%d]%s", group.interfaceName, slot.commandId, commandName)
                            : String.format("%s::Cmd%d", group.interfaceName, slot.commandId);

                        if (!this.hasImportedSymbol(program, slot.targetAddr)
                            && !this.hasSymbolNamed(program, slot.targetAddr, label))
                            this.createImportedLabel(program, slot.targetAddr, label);
                    }
                }

                long namedCommandSlots = group.slots.stream().filter(slot -> slot.commandId != null).count();

                if (group.clientImportOnly)
                {
                    Msg.info(this, String.format(
                        "Recovered SDK client/import interface group %s @ 0x%X: 0 text slots, %d database command names available",
                        group.interfaceName, group.vtableAddr.getOffset(), group.commands.size()));
                }
                else
                {
                    Msg.info(this, String.format(
                        "Recovered IPC interface vtable group %s @ 0x%X: %d text slots, %d command ids inferred",
                        group.interfaceName, group.vtableAddr.getOffset(), group.slots.size(), namedCommandSlots));
                }
            }

            return groups;
        }
        catch (Exception e)
        {
            Msg.warn(this, "Failed to recover IPC interface vtable groups: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Recovers the set of HIPC services this module connects to as a client, anchored on the
     * service-name string passed to {@code nn::sf::hipc::ConnectToHipcService} (see switchbrew
     * HIPC#Client).  Symbol-independent: when the connect wrapper is not named (stripped modules
     * like ns/ncm), it is identified as the function most commonly called by accessors that
     * reference exactly one service-name string.
     */
    private List<String> recoverConnectedServices(Program program)
    {
        try
        {
            if (IPCServiceDatabase.getInstance().isEmpty())
                return Collections.emptyList();

            ReferenceManager refMgr = program.getReferenceManager();
            FunctionManager fnMgr = program.getFunctionManager();
            TreeSet<String> services = new TreeSet<>();

            // Primary, robust, symbol-independent: a referenced marked string that is a known sm
            // service name is a connection.  This filters host-IO/op-name false positives and
            // recovers single-service modules (e.g. ncm -> fsp-srv) that frequency cannot.
            for (Data data : program.getListing().getDefinedData(true))
            {
                if (data == null || !(data.getValue() instanceof String))
                    continue;

                String value = (String) data.getValue();

                if (IPCServiceDatabase.getInstance().isKnownService(value)
                    && refMgr.hasReferencesTo(data.getAddress()))
                    services.add(value);
            }

            // Augmentation: strings passed to a named nn::sf::hipc::ConnectToHipcService discover
            // service names not yet in the known list (symbol-rich modules).
            for (Function f : fnMgr.getFunctions(true))
            {
                String name = f.getName(true);

                if (!name.contains("ConnectToHipcService") && !name.contains("ConnectToService"))
                    continue;

                for (Reference ref : refMgr.getReferencesTo(f.getEntryPoint()))
                {
                    Function caller = fnMgr.getFunctionContaining(ref.getFromAddress());

                    if (caller != null)
                        services.addAll(this.serviceNameStringsIn(program, caller));
                }
            }

            Msg.info(this, String.format("Recovered %d connected HIPC service(s): %s",
                services.size(), services));
            return new ArrayList<>(services);
        }
        catch (Exception e)
        {
            Msg.warn(this, "Failed to recover connected HIPC services: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Service-name strings referenced within a function body, matching the sm port-name shape.
     * Used to harvest the argument passed to a named ConnectToHipcService call.
     */
    private List<String> serviceNameStringsIn(Program program, Function function)
    {
        List<String> out = new ArrayList<>();
        Instruction insn = program.getListing().getInstructionAt(function.getEntryPoint());
        AddressSetView body = function.getBody();
        int n = 0;

        while (insn != null && n++ < 600 && body.contains(insn.getAddress()))
        {
            for (Reference ref : insn.getReferencesFrom())
            {
                Data data = program.getListing().getDataAt(ref.getToAddress());

                if (data != null && data.getValue() instanceof String
                    && this.isHipcServiceName((String) data.getValue()))
                    out.add((String) data.getValue());
            }

            insn = insn.getNext();
        }

        return out;
    }

    private boolean isHipcServiceName(String value)
    {
        int len = value.length();

        if (len < 2 || len > 8 || !Character.isLowerCase(value.charAt(0)))
            return false;

        for (int i = 0; i < len; i++)
        {
            char c = value.charAt(i);

            if (!(Character.isLowerCase(c) || Character.isDigit(c)
                || c == ':' || c == '-' || c == '.' || c == '_'))
                return false;
        }

        return true;
    }

    private ClientImportCandidateSet collectClientImportStubCandidates(Program program,
                                                                       List<IPCInterfaceVTableGroup> interfaceVtableGroups,
                                                                       SdkExtraDataProbeResult sdkExtraData)
    {
        List<ClientImportStubCandidate> raw = new ArrayList<>();

        if (sdkExtraData != null)
        {
            for (SdkCommandTableCandidate table : sdkExtraData.recordCandidates)
            {
                for (SdkCommandTableEntry entry : table.entries)
                {
                    raw.add(new ClientImportStubCandidate(entry.functionAddr, table.interfaceName,
                        entry.commandId, "sdk-record", entry.entryAddr));
                }
            }

            for (CmifProxyDescriptorCandidate candidate : sdkExtraData.cmifProxyCandidates)
            {
                raw.add(new ClientImportStubCandidate(candidate.functionAddr, candidate.interfaceName,
                    candidate.commandId, "cmif-rodata", candidate.descriptorAddr));
            }

            for (SdkPointerTableCandidate table : sdkExtraData.pointerCandidates)
                this.collectClientImportStubCandidatesFromPointerTable(program, raw, table,
                    sdkExtraData.clientImportInterfaces);
        }

        if (interfaceVtableGroups != null)
        {
            for (IPCInterfaceVTableGroup group : interfaceVtableGroups)
            {
                for (IPCInterfaceVTableSlot slot : group.slots)
                {
                    raw.add(new ClientImportStubCandidate(slot.targetAddr, group.interfaceName,
                        slot.commandId, "vtable", slot.slotAddr));
                }
            }
        }

        LinkedHashMap<Address, ClientImportStubCandidate> unique = new LinkedHashMap<>();

        for (ClientImportStubCandidate candidate : raw)
        {
            ClientImportStubCandidate existing = unique.get(candidate.stubAddr);

            if (existing == null || candidate.isBetterThan(existing))
                unique.put(candidate.stubAddr, candidate);
        }

        List<ClientImportStubCandidate> uniqueCandidates = new ArrayList<>(unique.values());
        uniqueCandidates.sort(ClientImportStubCandidate.PREFERRED_ORDER);
        return new ClientImportCandidateSet(raw, uniqueCandidates);
    }

    private void collectClientImportStubCandidatesFromPointerTable(Program program,
                                                                   List<ClientImportStubCandidate> out,
                                                                   SdkPointerTableCandidate table,
                                                                   Set<String> clientImportInterfaces)
    {
        SdkPointerTableSelection selection = this.selectSdkPointerTableInterface(table,
            clientImportInterfaces);

        if (selection == null)
            return;

        Map<String, String> commands = IPCDatabase.getInstance().getAllInterfaces().get(selection.interfaceName);
        Set<Long> knownCommandIds = commands != null
            ? parseCommandIds(commands.keySet())
            : Collections.emptySet();
        List<Long> orderedCommandIds = commands != null
            ? parseSortedCommandIds(commands.keySet())
            : Collections.emptyList();
        int slotLimit = Math.min(table.slotCount, CLIENT_IMPORT_EMU_STUB_LIMIT);

        for (int slotIndex = 0; slotIndex < slotLimit; slotIndex++)
        {
            Address slotAddr;

            try
            {
                slotAddr = table.tableAddr.add(slotIndex * 0x8L);
            }
            catch (AddressOutOfBoundsException e)
            {
                break;
            }

            Address targetAddr = this.tryReadExecutablePointer(program, slotAddr);

            if (targetAddr == null)
                continue;

            Long commandId = this.inferClientCommandIdForPointerSlot(program, targetAddr,
                knownCommandIds, orderedCommandIds, slotIndex, selection.commandSlotBase);
            out.add(new ClientImportStubCandidate(targetAddr, selection.interfaceName, commandId,
                "sdk-pointer", slotAddr));
        }
    }

    private Long inferClientCommandIdForPointerSlot(Program program, Address targetAddr,
                                                    Set<Long> knownCommandIds,
                                                    List<Long> orderedCommandIds,
                                                    int slotIndex, int commandSlotBase)
    {
        Long layoutCommandId = this.getPointerTableLayoutCommandId(orderedCommandIds,
            slotIndex, commandSlotBase);

        if (layoutCommandId != null)
            return layoutCommandId;

        if (knownCommandIds.isEmpty())
            return null;

        return this.inferClientCommandIdFromStub(program, targetAddr, knownCommandIds);
    }

    private Long getPointerTableLayoutCommandId(List<Long> orderedCommandIds,
                                                int slotIndex, int commandSlotBase)
    {
        if (commandSlotBase < 0 || orderedCommandIds.isEmpty() || slotIndex < commandSlotBase)
            return null;

        int commandIndex = slotIndex - commandSlotBase;

        if (commandIndex >= orderedCommandIds.size())
            return null;

        return orderedCommandIds.get(commandIndex);
    }

    private SdkPointerTableSelection selectSdkPointerTableInterface(SdkPointerTableCandidate table,
                                                                    Set<String> clientImportInterfaces)
    {
        List<SdkPointerTableSelection> shapeSelections =
            this.getSdkPointerTableShapeSelections(table);

        if (table.semanticMatch != null)
        {
            for (SdkPointerTableSelection selection : shapeSelections)
            {
                if (selection.interfaceName.equals(table.semanticMatch.iface))
                    return selection;
            }
        }

        if (clientImportInterfaces != null && !clientImportInterfaces.isEmpty())
        {
            List<SdkPointerTableSelection> localSelections = shapeSelections.stream()
                .filter(selection -> clientImportInterfaces.contains(selection.interfaceName))
                .toList();

            if (localSelections.size() == 1)
                return localSelections.get(0).withReason("local-shape");
        }

        if (shapeSelections.size() == 1)
            return shapeSelections.get(0);

        if (shapeSelections.isEmpty()
            && this.isStrongSdkPointerSemanticMatch(table.semanticMatch))
            return new SdkPointerTableSelection(table.semanticMatch.iface, -1, "semantic");

        return null;
    }

    private List<SdkPointerTableSelection> getSdkPointerTableShapeSelections(SdkPointerTableCandidate table)
    {
        LinkedHashMap<String, SdkPointerTableSelection> selections = new LinkedHashMap<>();

        for (String possibleInterface : table.possibleInterfaces)
        {
            SdkPointerTableSelection selection =
                this.parseSdkPointerTableShapeSelection(possibleInterface);

            if (selection != null)
                selections.put(selection.interfaceName + ":" + selection.commandSlotBase, selection);
        }

        return new ArrayList<>(selections.values());
    }

    private SdkPointerTableSelection parseSdkPointerTableShapeSelection(String possibleInterface)
    {
        if (possibleInterface.endsWith(" base+cmds"))
        {
            return new SdkPointerTableSelection(
                possibleInterface.substring(0, possibleInterface.length() - " base+cmds".length()),
                4, "shape");
        }

        if (possibleInterface.endsWith(" cmds"))
        {
            return new SdkPointerTableSelection(
                possibleInterface.substring(0, possibleInterface.length() - " cmds".length()),
                0, "shape");
        }

        return null;
    }

    private boolean isStrongSdkPointerSemanticMatch(InterfaceMatch match)
    {
        if (match == null)
            return false;

        return match.score >= 4 || (match.dbCmdCount <= 4 && match.score >= 2);
    }

    private String formatClientTerminationCounts(Map<String, Integer> terminationCounts)
    {
        return terminationCounts.entrySet().stream()
            .map(entry -> entry.getKey() + "=" + entry.getValue())
            .collect(Collectors.joining(", ", "{", "}"));
    }

    private String formatClientSourceStats(Map<String, ClientImportSourceStats> sourceStats)
    {
        return sourceStats.entrySet().stream()
            .map(entry -> {
                ClientImportSourceStats stats = entry.getValue();
                return String.format(
                    "%s={emulated=%d useful=%d staticCmd=%d cmd=%d send=%d sessionField=%d skippedLimit=%d terminations=%s}",
                    entry.getKey(), stats.emulated, stats.useful, stats.staticCommand,
                    stats.command, stats.send, stats.sessionField, stats.skippedLimit,
                    this.formatClientTerminationCounts(stats.terminations));
            })
            .collect(Collectors.joining(", ", "{", "}"));
    }

    private List<IPCInterfaceVTableGroup> recoverInterfaceVtableGroups(Program program,
                                                                        Map<Address, String> rttiNames)
            throws MemoryAccessException
    {
        List<IPCInterfaceVTableGroup> out = new ArrayList<>();

        if (rttiNames == null || rttiNames.isEmpty())
            return out;

        Map<String, Map<String, String>> allInterfaces = IPCDatabase.getInstance().getAllInterfaces();
        List<Map.Entry<Address, String>> namedVtables = new ArrayList<>(rttiNames.entrySet());
        namedVtables.sort(Comparator.comparingLong(entry -> entry.getKey().getOffset()));

        Set<Address> seen = new HashSet<>();
        Set<String> seenClientImportInterfaces = new HashSet<>();

        for (Map.Entry<Address, String> entry : namedVtables)
        {
            Address vtableAddr = entry.getKey();

            if (!seen.add(vtableAddr))
                continue;

            String interfaceName = stripVtableSuffix(entry.getValue());
            Map<String, String> commands = allInterfaces.get(interfaceName);

            if (commands == null || commands.isEmpty())
                continue;

            Set<Long> knownCommandIds = parseCommandIds(commands.keySet());

            if (knownCommandIds.isEmpty())
                continue;

            Address nextVtableAddr = findNextVtableAddress(namedVtables, vtableAddr);
            int slotCount = this.getInterfaceVtableScanSlotCount(vtableAddr, nextVtableAddr,
                commands.size());

            if (slotCount <= 0)
                continue;

            List<IPCInterfaceVTableSlot> slots = this.scanInterfaceVtableSlots(program, vtableAddr,
                slotCount, knownCommandIds);

            if (slots.isEmpty())
            {
                if (this.isSdkFssrvImportCandidate(program, interfaceName)
                    && seenClientImportInterfaces.add(interfaceName))
                {
                    out.add(new IPCInterfaceVTableGroup(interfaceName, vtableAddr, slotCount,
                        commands, slots, true));
                }

                continue;
            }

            out.add(new IPCInterfaceVTableGroup(interfaceName, vtableAddr, slotCount, commands, slots, false));
        }

        return out;
    }

    private static long alignUp(long value, long alignment)
    {
        long mask = alignment - 1;
        return (value + mask) & ~mask;
    }

    private static Address findNextVtableAddress(List<Map.Entry<Address, String>> namedVtables,
                                                 Address vtableAddr)
    {
        for (Map.Entry<Address, String> entry : namedVtables)
        {
            Address candidate = entry.getKey();

            if (candidate.getOffset() > vtableAddr.getOffset())
                return candidate;
        }

        return null;
    }

    private int getInterfaceVtableScanSlotCount(Address vtableAddr, Address nextVtableAddr, int commandCount)
    {
        // Four nn::sf base virtuals precede the generated command method slots.
        // Keep extra room for version-specific commands while capping noisy scans.
        int expectedSlotCount = Math.min(4 + commandCount + 16, 512);

        if (nextVtableAddr == null)
            return expectedSlotCount;

        long addressPoint = vtableAddr.getOffset() + 0x10;
        long availableBytes = nextVtableAddr.getOffset() - addressPoint;

        if (availableBytes <= 0)
            return 0;

        return Math.min(expectedSlotCount, (int)(availableBytes / 0x8));
    }

    private List<IPCInterfaceVTableSlot> scanInterfaceVtableSlots(Program program, Address vtableAddr,
                                                                   int slotCount, Set<Long> knownCommandIds)
            throws MemoryAccessException
    {
        List<IPCInterfaceVTableSlot> out = new ArrayList<>();
        Memory mem = program.getMemory();
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        Address addressPoint = vtableAddr.add(0x10);

        for (int slotIndex = 0; slotIndex < slotCount; slotIndex++)
        {
            Address slotAddr;

            try
            {
                slotAddr = addressPoint.add(slotIndex * 0x8L);
            }
            catch (AddressOutOfBoundsException e)
            {
                break;
            }

            MemoryBlock slotBlock = mem.getBlock(slotAddr);

            if (slotBlock == null || !slotBlock.isInitialized())
                break;

            if (this.isRttiVtableHeader(program, slotAddr))
                break;

            long rawTarget = mem.getLong(slotAddr);

            if (rawTarget == 0)
                continue;

            Address targetAddr;

            try
            {
                targetAddr = aSpace.getAddress(rawTarget);
            }
            catch (AddressOutOfBoundsException e)
            {
                continue;
            }

            MemoryBlock targetBlock = mem.getBlock(targetAddr);

            if (!this.isExecutableCodeBlock(program, targetBlock))
                continue;

            Long commandId = this.inferClientCommandIdFromStub(program, targetAddr, knownCommandIds);
            out.add(new IPCInterfaceVTableSlot(slotAddr, targetAddr, slotIndex * 0x8L, commandId));
        }

        return out;
    }

    private boolean isRttiVtableHeader(Program program, Address addr)
    {
        Memory mem = program.getMemory();
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();

        try
        {
            long offsetToTop = mem.getLong(addr);

            if (offsetToTop > 0 || offsetToTop < -0x100000L)
                return false;

            long rttiPtr = mem.getLong(addr.add(0x8));

            if (rttiPtr == 0)
                return false;

            Address rttiAddr = aSpace.getAddress(rttiPtr);
            MemoryBlock rttiBlock = mem.getBlock(rttiAddr);

            if (!this.isRttiDataBlock(program, rttiBlock))
                return false;

            long typeNamePtr = mem.getLong(rttiAddr.add(0x8));
            Address typeNameAddr = aSpace.getAddress(typeNamePtr);
            MemoryBlock typeNameBlock = mem.getBlock(typeNameAddr);

            return typeNameBlock != null && typeNameBlock.getName().startsWith(".rodata");
        }
        catch (AddressOutOfBoundsException | MemoryAccessException e)
        {
            return false;
        }
    }

    private Long inferClientCommandIdFromStub(Program program, Address functionAddr, Set<Long> knownCommandIds)
    {
        LinkedHashSet<Long> candidates = new LinkedHashSet<>();
        Instruction instruction = program.getListing().getInstructionAt(functionAddr);

        for (int i = 0; instruction != null && i < 160; i++)
        {
            this.collectKnownCommandScalars(instruction, knownCommandIds, candidates);

            String mnemonic = instruction.getMnemonicString();

            if ("ret".equals(mnemonic))
                break;

            FlowType flowType = instruction.getFlowType();

            if (flowType.isTerminal() && !flowType.isCall())
                break;

            instruction = instruction.getNext();
        }

        LinkedHashSet<Long> nonTinyCandidates = candidates.stream()
            .filter(candidate -> candidate >= 32)
            .collect(Collectors.toCollection(LinkedHashSet::new));

        if (nonTinyCandidates.size() == 1)
            return nonTinyCandidates.iterator().next();

        if (candidates.size() == 1)
            return candidates.iterator().next();

        return null;
    }

    private Map<Address, SyntheticCommandFunctionTable> findSyntheticCommandFunctionTables(
        Program program, Multimap<Address, IPCTrace> processFuncTraces,
        HashBiMap<Address, IPCVTableEntry> procFuncVtMap,
        List<IPCVTableEntry> vtEntries,
        HashBiMap<Address, Address> sTableProcessFuncMap)
            throws MemoryAccessException
    {
        Map<Address, SyntheticCommandFunctionTable> out = new HashMap<>();

        for (Map.Entry<Address, IPCVTableEntry> entry : procFuncVtMap.entrySet())
        {
            Address procFuncAddr = entry.getKey();
            IPCVTableEntry vtEntry = entry.getValue();

            if (vtEntry == null || vtEntry.hasRealVtable || !processFuncTraces.containsKey(procFuncAddr))
                continue;

            List<Long> vtOffsets = processFuncTraces.get(procFuncAddr).stream()
                .filter(trace -> trace.vtOffset != -1 && trace.hasDescription())
                .map(trace -> trace.vtOffset)
                .distinct()
                .sorted()
                .collect(Collectors.toList());

            Address sTableAddr = sTableProcessFuncMap != null
                ? sTableProcessFuncMap.inverse().get(procFuncAddr)
                : null;
            SyntheticCommandFunctionTable table = this.findSyntheticCommandFunctionTableFromVtables(
                program, vtOffsets, vtEntries, sTableAddr);

            if (table == null)
                table = this.findSyntheticCommandFunctionTable(program, vtOffsets);

            if (table == null)
                continue;

            out.put(procFuncAddr, table);
            Msg.info(this, String.format(
                "Recovered synthetic IPC command table for proc_func 0x%X (%s): table=0x%X score=%d/%d unique_funcs=%d%s%s",
                procFuncAddr.getOffset(), vtEntry.abvName, table.tableAddr.getOffset(),
                table.matchedSlotCount, table.requestedSlotCount, table.uniqueFunctionCount,
                table.referenced ? " referenced" : "",
                table.pointerRunStart ? " run-start" : ""));
        }

        return out;
    }

    private SyntheticCommandFunctionTable findSyntheticCommandFunctionTableFromVtables(
        Program program, List<Long> vtOffsets, List<IPCVTableEntry> vtEntries, Address sTableAddr)
    {
        int minimumScore = this.minimumSyntheticCommandTableScore(vtOffsets.size());

        if (minimumScore == Integer.MAX_VALUE || vtEntries == null || vtEntries.isEmpty())
            return null;

        SyntheticCommandFunctionTable best = null;
        boolean ambiguousBest = false;

        for (IPCVTableEntry vtEntry : vtEntries)
        {
            if (vtEntry == null || !vtEntry.hasRealVtable || vtEntry.ipcFuncs.isEmpty())
                continue;

            try
            {
                Address commandTableAddr = vtEntry.addr.add(0x10);
                Map<Long, Address> functionsByVtOffset = new LinkedHashMap<>();

                for (long vtOffset : vtOffsets)
                {
                    Address functionAddr = this.tryReadExecutablePointer(program,
                        commandTableAddr.add(vtOffset));

                    if (functionAddr != null)
                        functionsByVtOffset.put(vtOffset, functionAddr);
                }

                if (functionsByVtOffset.size() < minimumScore)
                    continue;

                Set<Address> uniqueFunctions = new LinkedHashSet<>(functionsByVtOffset.values());

                if (functionsByVtOffset.size() >= 4 && uniqueFunctions.size() < 2)
                    continue;

                Address previousSlotAddr = vtOffsets.get(0) >= 0x8
                    ? commandTableAddr.add(vtOffsets.get(0) - 0x8)
                    : null;
                boolean pointerRunStart = previousSlotAddr == null
                    || this.tryReadExecutablePointer(program, previousSlotAddr) == null;
                boolean referenced = program.getReferenceManager().getReferencesTo(commandTableAddr).hasNext()
                    || program.getReferenceManager().getReferencesTo(vtEntry.addr).hasNext();
                boolean hasSymbol = program.getSymbolTable().getPrimarySymbol(commandTableAddr) != null
                    || program.getSymbolTable().getPrimarySymbol(vtEntry.addr) != null;

                SyntheticCommandFunctionTable candidate = new SyntheticCommandFunctionTable(
                    commandTableAddr, functionsByVtOffset, vtOffsets.size(), pointerRunStart,
                    referenced, hasSymbol);

                SyntheticCandidateSelection selection =
                    this.compareSyntheticCommandTableCandidate(candidate, best, sTableAddr);

                if (selection == SyntheticCandidateSelection.BETTER)
                {
                    best = candidate;
                    ambiguousBest = false;
                }
                else if (selection == SyntheticCandidateSelection.AMBIGUOUS)
                {
                    ambiguousBest = true;
                }
            }
            catch (AddressOutOfBoundsException e)
            {
                continue;
            }
        }

        if (ambiguousBest)
        {
            Msg.debug(this, String.format(
                "Skipping vtable-backed synthetic IPC command table recovery: ambiguous candidates for offsets %s",
                formatHexOffsets(vtOffsets)));
            return null;
        }

        return best;
    }

    private SyntheticCommandFunctionTable findSyntheticCommandFunctionTable(Program program,
                                                                           List<Long> vtOffsets)
            throws MemoryAccessException
    {
        int minimumScore = this.minimumSyntheticCommandTableScore(vtOffsets.size());

        if (minimumScore == Integer.MAX_VALUE)
            return null;

        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        List<MemoryBlock> blocks = this.getCommandFunctionTableBlocks(program);
        List<Long> anchorOffsets = this.selectSyntheticCommandTableAnchorOffsets(vtOffsets);
        long maxOffset = vtOffsets.get(vtOffsets.size() - 1);
        SyntheticCommandFunctionTable best = null;
        boolean ambiguousBest = false;

        for (MemoryBlock block : blocks)
        {
            long start = alignUp(block.getStart().getOffset(), 0x8);
            long end = block.getEnd().getOffset();
            long lastTableStart = end - maxOffset - 7;

            if (lastTableStart < start)
                continue;

            for (long off = start; off <= lastTableStart; off += 0x8)
            {
                Address tableAddr = aSpace.getAddress(off);

                boolean anchorsMatch = true;
                for (long anchorOffset : anchorOffsets)
                {
                    if (this.tryReadExecutablePointer(program, tableAddr.add(anchorOffset)) == null)
                    {
                        anchorsMatch = false;
                        break;
                    }
                }

                if (!anchorsMatch)
                    continue;

                Map<Long, Address> functionsByVtOffset = new LinkedHashMap<>();
                for (long vtOffset : vtOffsets)
                {
                    Address functionAddr = this.tryReadExecutablePointer(program, tableAddr.add(vtOffset));

                    if (functionAddr != null)
                        functionsByVtOffset.put(vtOffset, functionAddr);
                }

                if (functionsByVtOffset.size() < minimumScore)
                    continue;

                Set<Address> uniqueFunctions = new LinkedHashSet<>(functionsByVtOffset.values());

                if (functionsByVtOffset.size() >= 4 && uniqueFunctions.size() < 2)
                    continue;

                long firstSlotOffset = off + vtOffsets.get(0);
                Address previousSlotAddr = firstSlotOffset >= block.getStart().getOffset() + 0x8
                    ? aSpace.getAddress(firstSlotOffset - 0x8)
                    : null;
                boolean pointerRunStart = previousSlotAddr == null
                    || this.tryReadExecutablePointer(program, previousSlotAddr) == null;
                boolean referenced = program.getReferenceManager().getReferencesTo(tableAddr).hasNext();
                boolean hasSymbol = program.getSymbolTable().getPrimarySymbol(tableAddr) != null;

                SyntheticCommandFunctionTable candidate = new SyntheticCommandFunctionTable(tableAddr,
                    functionsByVtOffset, vtOffsets.size(), pointerRunStart, referenced, hasSymbol);

                if (best == null || candidate.isBetterThan(best))
                {
                    best = candidate;
                    ambiguousBest = false;
                }
                else if (candidate.hasSameConfidenceAs(best))
                {
                    ambiguousBest = true;
                }
            }
        }

        if (ambiguousBest)
        {
            Msg.debug(this, String.format(
                "Skipping synthetic IPC command table recovery: ambiguous candidates for offsets %s",
                formatHexOffsets(vtOffsets)));
            return null;
        }

        return best;
    }

    private SyntheticCandidateSelection compareSyntheticCommandTableCandidate(
        SyntheticCommandFunctionTable candidate, SyntheticCommandFunctionTable best, Address anchorAddr)
    {
        if (best == null)
            return SyntheticCandidateSelection.BETTER;

        if (candidate.hasSameConfidenceAs(best))
        {
            if (anchorAddr != null)
            {
                long candidateDistance = this.addressDistance(candidate.tableAddr, anchorAddr);
                long bestDistance = this.addressDistance(best.tableAddr, anchorAddr);

                if (candidateDistance < bestDistance)
                    return SyntheticCandidateSelection.BETTER;

                if (candidateDistance > bestDistance)
                    return SyntheticCandidateSelection.WORSE;
            }

            return SyntheticCandidateSelection.AMBIGUOUS;
        }

        return candidate.isBetterThan(best)
            ? SyntheticCandidateSelection.BETTER
            : SyntheticCandidateSelection.WORSE;
    }

    private long addressDistance(Address a, Address b)
    {
        long aOffset = a.getOffset();
        long bOffset = b.getOffset();
        return aOffset >= bOffset ? aOffset - bOffset : bOffset - aOffset;
    }

    private List<MemoryBlock> getCommandFunctionTableBlocks(Program program)
    {
        List<MemoryBlock> out = new ArrayList<>();

        for (MemoryBlock block : program.getMemory().getBlocks())
        {
            String name = block.getName();

            if (block.isInitialized() && (name.equals(".data") || name.startsWith(".data.")))
                out.add(block);
        }

        out.sort(Comparator.comparingLong(block -> block.getStart().getOffset()));
        return out;
    }

    private int minimumSyntheticCommandTableScore(int slotCount)
    {
        if (slotCount < 4)
            return Integer.MAX_VALUE;

        if (slotCount <= 8)
            return slotCount;

        return Math.max(8, (slotCount * 3 + 3) / 4);
    }

    private List<Long> selectSyntheticCommandTableAnchorOffsets(List<Long> vtOffsets)
    {
        LinkedHashSet<Long> anchors = new LinkedHashSet<>();
        int size = vtOffsets.size();

        anchors.add(vtOffsets.get(0));
        anchors.add(vtOffsets.get(size / 2));
        anchors.add(vtOffsets.get(size - 1));

        if (size > 8)
        {
            anchors.add(vtOffsets.get(size / 4));
            anchors.add(vtOffsets.get((size * 3) / 4));
        }

        return new ArrayList<>(anchors);
    }

    private Address tryReadExecutablePointer(Program program, Address addr)
    {
        try
        {
            return this.readExecutablePointer(program, addr);
        }
        catch (AddressOutOfBoundsException | MemoryAccessException e)
        {
            return null;
        }
    }

    private SdkExtraDataProbeResult probeSdkExtraDataCommandTables(Program program,
                                                                   ElfCompatibilityProvider elfProvider,
                                                                   Map<Address, String> rttiNames,
                                                                   List<IPCInterfaceVTableGroup> interfaceVtableGroups)
    {
        List<ClientImportInterfaceAnchor> interfaceAnchors =
            this.findClientImportInterfaceAnchors(program, elfProvider);
        Set<String> clientImportInterfaces = interfaceAnchors.stream()
            .map(anchor -> anchor.interfaceName)
            .collect(Collectors.toCollection(LinkedHashSet::new));

        if (!this.isSdkLikeLayout(program)
            && !this.hasClientImportOnlyInterfaceGroups(interfaceVtableGroups)
            && !this.hasFssrvRttiInterfaceNames(rttiNames)
            && !clientImportInterfaces.stream().anyMatch(this::isFssrvInterfaceName))
            return SdkExtraDataProbeResult.EMPTY;

        List<MemoryBlock> blocks = this.getSdkExtraDataBlocks(program);

        if (blocks.isEmpty())
            return SdkExtraDataProbeResult.EMPTY;

        try
        {
            if (!clientImportInterfaces.isEmpty())
            {
                Msg.info(this, String.format(
                    "ClientIPC import interface strings: found %d database-backed interfaces: %s",
                    clientImportInterfaces.size(),
                    clientImportInterfaces.stream().limit(24).collect(Collectors.joining(", "))));
            }

            List<SdkCommandTableCandidate> recordCandidates =
                this.findSdkRecordCommandTableCandidates(program, blocks);
            List<SdkPointerTableCandidate> pointerCandidates =
                this.findSdkPointerTableCandidates(program, blocks);
            List<CmifProxyDescriptorCandidate> cmifProxyCandidates =
                this.findCmifProxyDescriptorCandidates(program, interfaceAnchors);
            long mixedPointerRegionCount = pointerCandidates.stream()
                .filter(candidate -> candidate.largeMixedRegion)
                .count();
            long pointerFragmentCount = pointerCandidates.size() - mixedPointerRegionCount;

            Msg.info(this, String.format(
                "SDK extra-data IPC fragment probe: scanned %s, found %d command-record fragments/candidates, %d dense pointer-run fragments/candidates, %d large mixed pointer regions, and %d CMIF proxy descriptor stubs",
                blocks.stream().map(MemoryBlock::getName).collect(Collectors.joining(", ")),
                recordCandidates.size(), pointerFragmentCount, mixedPointerRegionCount,
                cmifProxyCandidates.size()));

            for (SdkCommandTableCandidate candidate : recordCandidates.stream().limit(24).toList())
            {
                Msg.info(this, String.format(
                    "  SDK command-record %s %s @ 0x%X (%s): records=%d record_size=0x%X cmd_off=0x%X func_off=0x%X score=%d/%d cmds=%s",
                    candidate.isStrongTableCandidate() ? "table candidate" : "fragment",
                    candidate.interfaceName, candidate.tableAddr.getOffset(), candidate.blockName,
                    candidate.entries.size(), candidate.recordSize, candidate.commandIdOffset,
                    candidate.functionOffset, candidate.score, candidate.dbCommandCount,
                    formatCommandIds(candidate.commandIds())));
                this.markupSdkRecordCommandTableCandidate(program, candidate);
            }

            for (SdkPointerTableCandidate candidate : pointerCandidates.stream().limit(24).toList())
            {
                Msg.info(this, String.format(
                    "  SDK %s @ 0x%X (%s): slots=%d possible_interfaces=%s%s",
                    candidate.largeMixedRegion
                        ? "large mixed pointer region"
                        : "dense pointer-run fragment",
                    candidate.tableAddr.getOffset(), candidate.blockName, candidate.slotCount,
                    candidate.possibleInterfaces, candidate.formatSemanticSummary()));
                this.markupSdkPointerTableCandidate(program, candidate);
            }

            return new SdkExtraDataProbeResult(recordCandidates, pointerCandidates,
                cmifProxyCandidates, clientImportInterfaces);
        }
        catch (Exception e)
        {
            Msg.warn(this, "SDK extra-data IPC table probe failed: " + e.getMessage());
            return SdkExtraDataProbeResult.EMPTY;
        }
    }

    private boolean hasClientImportOnlyInterfaceGroups(List<IPCInterfaceVTableGroup> interfaceVtableGroups)
    {
        return interfaceVtableGroups != null
            && interfaceVtableGroups.stream().anyMatch(group -> group.clientImportOnly);
    }

    private boolean hasFssrvRttiInterfaceNames(Map<Address, String> rttiNames)
    {
        return rttiNames != null && rttiNames.values().stream()
            .map(IPCAnalyzer::stripVtableSuffix)
            .anyMatch(this::isFssrvInterfaceName);
    }

    private List<ClientImportInterfaceAnchor> findClientImportInterfaceAnchors(Program program,
                                                                              ElfCompatibilityProvider elfProvider)
    {
        Map<String, Map<String, String>> allInterfaces = IPCDatabase.getInstance().getAllInterfaces();
        List<ClientImportInterfaceAnchor> out = new ArrayList<>();
        Memory mem = program.getMemory();

        for (MemoryBlock block : mem.getBlocks())
        {
            if (!block.getName().startsWith(".rodata") || !block.isInitialized())
                continue;

            long pos = block.getStart().getOffset();
            long end = block.getEnd().getOffset();

            while (pos < end)
            {
                try
                {
                    String mangled = elfProvider.getReader().readAsciiString(pos);

                    if (!mangled.isEmpty() && mangled.length() <= 256)
                    {
                        String interfaceName = parseMangledTypeName(mangled);

                        if (allInterfaces.containsKey(interfaceName))
                        {
                            out.add(new ClientImportInterfaceAnchor(interfaceName,
                                program.getAddressFactory().getDefaultAddressSpace().getAddress(pos),
                                mangled));
                        }

                        pos += mangled.length() + 1L;
                    }
                    else
                    {
                        pos++;
                    }
                }
                catch (Exception e)
                {
                    pos++;
                }
            }
        }

        out.sort(Comparator.comparingLong(anchor -> anchor.stringAddr.getOffset()));
        return out;
    }

    private List<CmifProxyDescriptorCandidate> findCmifProxyDescriptorCandidates(
        Program program, List<ClientImportInterfaceAnchor> anchors)
    {
        if (anchors == null || anchors.isEmpty())
            return Collections.emptyList();

        Map<String, Map<String, String>> allInterfaces = IPCDatabase.getInstance().getAllInterfaces();
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        List<CmifProxyDescriptorCandidate> out = new ArrayList<>();
        List<CmifDescriptorRange> descriptorRanges =
            this.collectCmifDescriptorRanges(program, anchors, allInterfaces);
        Map<Long, LinkedHashSet<Address>> directReferences =
            this.findDirectCmifDescriptorReferences(program, descriptorRanges);

        if (!descriptorRanges.isEmpty())
        {
            Msg.info(this, String.format(
                "ClientIPC CMIF proxy descriptors: indexed %d direct instruction references across %d descriptor windows",
                directReferences.values().stream().mapToInt(Set::size).sum(),
                descriptorRanges.size()));
        }

        for (CmifDescriptorRange range : descriptorRanges)
        {
            ClientImportInterfaceAnchor anchor = range.anchor;
            Map<String, String> commands = allInterfaces.get(anchor.interfaceName);
            Set<Long> knownCommandIds = parseCommandIds(commands.keySet());
            LinkedHashMap<Address, CmifProxyDescriptorCandidate> perInterface = new LinkedHashMap<>();

            for (long off = range.start; off <= range.endInclusive; off += 0x4)
            {
                Address descriptorAddr = aSpace.getAddress(off);
                Iterator<Reference> references =
                    program.getReferenceManager().getReferencesTo(descriptorAddr);

                while (references.hasNext())
                {
                    Reference reference = references.next();
                    Address fromAddr = reference.getFromAddress();

                    if (!this.isExecutableCodeBlock(program, program.getMemory().getBlock(fromAddr)))
                        continue;

                    Function function = program.getFunctionManager().getFunctionContaining(fromAddr);
                    Address functionAddr = function != null ? function.getEntryPoint() : fromAddr;

                    this.addCmifProxyDescriptorCandidate(program, anchor, descriptorAddr,
                        functionAddr, knownCommandIds, perInterface);
                }

                for (Address functionAddr : directReferences.getOrDefault(off, new LinkedHashSet<>()))
                {
                    this.addCmifProxyDescriptorCandidate(program, anchor, descriptorAddr,
                        functionAddr, knownCommandIds, perInterface);
                }
            }

            if (!perInterface.isEmpty())
            {
                out.addAll(perInterface.values());
                Msg.info(this, String.format(
                    "ClientIPC CMIF proxy descriptors: %s string @ 0x%X -> %d descriptor-backed stubs",
                    anchor.interfaceName, anchor.stringAddr.getOffset(), perInterface.size()));
            }
        }

        out.sort(Comparator
            .comparing((CmifProxyDescriptorCandidate candidate) -> candidate.interfaceName)
            .thenComparingLong(candidate -> candidate.descriptorAddr.getOffset())
            .thenComparingLong(candidate -> candidate.functionAddr.getOffset()));
        return out;
    }

    private List<CmifDescriptorRange> collectCmifDescriptorRanges(
        Program program, List<ClientImportInterfaceAnchor> anchors,
        Map<String, Map<String, String>> allInterfaces)
    {
        List<CmifDescriptorRange> out = new ArrayList<>();

        for (int anchorIndex = 0; anchorIndex < anchors.size(); anchorIndex++)
        {
            ClientImportInterfaceAnchor anchor = anchors.get(anchorIndex);
            Map<String, String> commands = allInterfaces.get(anchor.interfaceName);

            if (commands == null || commands.isEmpty())
                continue;

            MemoryBlock block = program.getMemory().getBlock(anchor.stringAddr);

            if (block == null || !block.isInitialized() || !block.getName().startsWith(".rodata"))
                continue;

            long descriptorStart = alignUp(anchor.stringAddr.getOffset()
                + anchor.mangledName.length() + 1L, 0x4);
            long descriptorEnd = Math.min(block.getEnd().getOffset(), descriptorStart + 0x1000);

            if (anchorIndex + 1 < anchors.size())
            {
                long nextAnchor = anchors.get(anchorIndex + 1).stringAddr.getOffset();

                if (nextAnchor > descriptorStart)
                    descriptorEnd = Math.min(descriptorEnd, nextAnchor);
            }

            if (descriptorStart <= descriptorEnd)
                out.add(new CmifDescriptorRange(anchor, descriptorStart, descriptorEnd));
        }

        return out;
    }

    private void addCmifProxyDescriptorCandidate(Program program, ClientImportInterfaceAnchor anchor,
                                                 Address descriptorAddr, Address functionAddr,
                                                 Set<Long> knownCommandIds,
                                                 Map<Address, CmifProxyDescriptorCandidate> out)
    {
        if (out.containsKey(functionAddr))
            return;

        Long commandId = this.inferClientCommandIdFromStub(program, functionAddr, knownCommandIds);

        if (commandId == null && !this.isLikelyCmifClientFunction(program, functionAddr))
            return;

        out.put(functionAddr, new CmifProxyDescriptorCandidate(anchor.interfaceName,
            descriptorAddr, functionAddr, commandId));
    }

    private Map<Long, LinkedHashSet<Address>> findDirectCmifDescriptorReferences(
        Program program, List<CmifDescriptorRange> ranges)
    {
        Map<Long, LinkedHashSet<Address>> out = new HashMap<>();
        NavigableMap<Long, CmifDescriptorRange> rangeByStart = new TreeMap<>();

        for (CmifDescriptorRange range : ranges)
            rangeByStart.put(range.start, range);

        if (rangeByStart.isEmpty())
            return out;

        for (MemoryBlock block : program.getMemory().getBlocks())
        {
            if (!this.isExecutableCodeBlock(program, block))
                continue;

            Iterator<Instruction> instructions =
                program.getListing().getInstructions(
                    new AddressSet(block.getStart(), block.getEnd()), true);

            while (instructions.hasNext())
            {
                Instruction instruction = instructions.next();
                Address functionAddr = null;

                for (int operandIndex = 0; operandIndex < instruction.getNumOperands(); operandIndex++)
                {
                    for (Object object : instruction.getOpObjects(operandIndex))
                    {
                        Long value = null;

                        if (object instanceof Address address)
                            value = address.getOffset();
                        else if (object instanceof Scalar scalar)
                            value = scalar.getValue();

                        if (value == null)
                            continue;

                        Long descriptorAddr = normalizeDescriptorReference(value, rangeByStart);

                        if (descriptorAddr == null)
                            continue;

                        if (functionAddr == null)
                        {
                            Function function = program.getFunctionManager()
                                .getFunctionContaining(instruction.getAddress());
                            functionAddr = function != null
                                ? function.getEntryPoint()
                                : instruction.getAddress();
                        }

                        out.computeIfAbsent(descriptorAddr, ignored -> new LinkedHashSet<>())
                            .add(functionAddr);
                    }
                }
            }
        }

        return out;
    }

    private static Long normalizeDescriptorReference(long value,
                                                    NavigableMap<Long, CmifDescriptorRange> ranges)
    {
        Long descriptorAddr = normalizeDescriptorReferenceInRanges(value, ranges);

        if (descriptorAddr != null)
            return descriptorAddr;

        long unsigned32 = value & 0xFFFFFFFFL;

        return unsigned32 != value
            ? normalizeDescriptorReferenceInRanges(unsigned32, ranges)
            : null;
    }

    private static Long normalizeDescriptorReferenceInRanges(long value,
                                                             NavigableMap<Long, CmifDescriptorRange> ranges)
    {
        Map.Entry<Long, CmifDescriptorRange> entry = ranges.floorEntry(value);

        if (entry == null)
            return null;

        CmifDescriptorRange range = entry.getValue();

        if (value >= range.start && value <= range.endInclusive && ((value - range.start) & 0x3) == 0)
            return value;

        return null;
    }

    private boolean isLikelyCmifClientFunction(Program program, Address functionAddr)
    {
        Instruction instruction = program.getListing().getInstructionAt(functionAddr);

        for (int i = 0; instruction != null && i < 200; i++)
        {
            if (instructionContainsScalar(instruction, 0x49434653L)
                || instructionContainsScalar(instruction, 0x4F434653L))
                return true;

            if ("ret".equals(instruction.getMnemonicString()))
                break;

            FlowType flowType = instruction.getFlowType();

            if (flowType.isTerminal() && !flowType.isCall())
                break;

            instruction = instruction.getNext();
        }

        return false;
    }

    private static boolean instructionContainsScalar(Instruction instruction, long expectedValue)
    {
        for (int operandIndex = 0; operandIndex < instruction.getNumOperands(); operandIndex++)
        {
            for (Object object : instruction.getOpObjects(operandIndex))
            {
                if (!(object instanceof Scalar scalar))
                    continue;

                long value = scalar.getValue();

                if (value == expectedValue || (value & 0xFFFFFFFFL) == expectedValue)
                    return true;
            }
        }

        return false;
    }

    private List<MemoryBlock> getSdkExtraDataBlocks(Program program)
    {
        List<MemoryBlock> out = new ArrayList<>();

        for (MemoryBlock block : program.getMemory().getBlocks())
        {
            String name = block.getName();

            if (block.isInitialized() && (name.equals(".data") || name.startsWith(".data.")))
                out.add(block);
        }

        out.sort(Comparator.comparingLong(block -> block.getStart().getOffset()));
        return out;
    }

    private List<SdkCommandTableCandidate> findSdkRecordCommandTableCandidates(Program program,
                                                                               List<MemoryBlock> blocks)
            throws MemoryAccessException
    {
        Map<String, Map<String, String>> fssrvInterfaces = this.getFssrvInterfaceDatabase();
        Set<Long> knownCommandIds = this.collectCommandIds(fssrvInterfaces);
        List<SdkCommandTableCandidate> candidates = new ArrayList<>();
        int[] recordSizes = new int[] { 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40 };

        for (MemoryBlock block : blocks)
        {
            long start = alignUp(block.getStart().getOffset(), 0x8);
            long end = block.getEnd().getOffset();

            for (int recordSize : recordSizes)
            {
                for (int commandIdOffset = 0; commandIdOffset <= recordSize - 0x4; commandIdOffset += 0x4)
                {
                    for (int functionOffset = 0; functionOffset <= recordSize - 0x8; functionOffset += 0x8)
                    {
                        if (rangesOverlap(commandIdOffset, 0x4, functionOffset, 0x8))
                            continue;

                        long off = start;

                        while (off <= end - recordSize)
                        {
                            List<SdkCommandTableEntry> entries = this.readSdkCommandRecordRun(program,
                                off, end, recordSize, commandIdOffset, functionOffset, knownCommandIds);

                            if (entries.size() >= 4)
                            {
                                Set<Long> commandIds = entries.stream()
                                    .map(entry -> entry.commandId)
                                    .collect(Collectors.toCollection(LinkedHashSet::new));
                                InterfaceMatch match = findBestInterfaceMatch(fssrvInterfaces, commandIds);

                                if (match != null && match.score >= 4)
                                {
                                    Address tableAddr = program.getAddressFactory()
                                        .getDefaultAddressSpace().getAddress(off);
                                    candidates.add(new SdkCommandTableCandidate(match.iface, tableAddr,
                                        block.getName(), recordSize, commandIdOffset, functionOffset,
                                        match.score, match.dbCmdCount, entries));

                                    off += Math.max(recordSize, entries.size() * (long)recordSize);
                                    continue;
                                }
                            }

                            off += 0x8;
                        }
                    }
                }
            }
        }

        return this.dedupeSdkCommandTableCandidates(candidates);
    }

    private List<SdkCommandTableEntry> readSdkCommandRecordRun(Program program, long start, long blockEnd,
                                                               int recordSize, int commandIdOffset,
                                                               int functionOffset, Set<Long> knownCommandIds)
            throws MemoryAccessException
    {
        List<SdkCommandTableEntry> entries = new ArrayList<>();
        Set<Long> seenCommandIds = new HashSet<>();
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        long off = start;

        while (off <= blockEnd - recordSize)
        {
            Address recordAddr = aSpace.getAddress(off);
            Long commandId = this.readKnownCommandId(program, recordAddr.add(commandIdOffset), knownCommandIds);

            if (commandId == null || !seenCommandIds.add(commandId))
                break;

            Address functionAddr = this.readExecutablePointer(program, recordAddr.add(functionOffset));

            if (functionAddr == null)
                break;

            entries.add(new SdkCommandTableEntry(recordAddr, commandId, functionAddr));
            off += recordSize;
        }

        return entries;
    }

    private Long readKnownCommandId(Program program, Address addr, Set<Long> knownCommandIds)
            throws MemoryAccessException
    {
        Memory mem = program.getMemory();
        long value32 = Integer.toUnsignedLong(mem.getInt(addr));

        if (knownCommandIds.contains(value32))
            return value32;

        long value64;

        try
        {
            value64 = mem.getLong(addr);
        }
        catch (MemoryAccessException e)
        {
            return null;
        }

        if (value64 >= 0 && value64 <= 0xFFFFFFFFL && knownCommandIds.contains(value64))
            return value64;

        return null;
    }

    private Address readExecutablePointer(Program program, Address addr) throws MemoryAccessException
    {
        long rawTarget = program.getMemory().getLong(addr);

        if (rawTarget == 0)
            return null;

        Address targetAddr;

        try
        {
            targetAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(rawTarget);
        }
        catch (AddressOutOfBoundsException e)
        {
            return null;
        }

        if (!this.isExecutableCodeBlock(program, program.getMemory().getBlock(targetAddr)))
            return null;

        if (program.getListing().getDataAt(targetAddr) != null)
            return null;

        return targetAddr;
    }

    private List<SdkCommandTableCandidate> dedupeSdkCommandTableCandidates(
        List<SdkCommandTableCandidate> candidates)
    {
        candidates.sort(Comparator
            .comparingInt((SdkCommandTableCandidate candidate) -> candidate.entries.size()).reversed()
            .thenComparingInt(candidate -> candidate.score).reversed()
            .thenComparingLong(candidate -> candidate.tableAddr.getOffset())
            .thenComparingInt(candidate -> candidate.recordSize));

        List<SdkCommandTableCandidate> out = new ArrayList<>();

        for (SdkCommandTableCandidate candidate : candidates)
        {
            boolean overlapsExisting = out.stream()
                .anyMatch(existing -> candidate.overlaps(existing));

            if (!overlapsExisting)
                out.add(candidate);
        }

        out.sort(Comparator.comparingLong(candidate -> candidate.tableAddr.getOffset()));
        return out;
    }

    private List<SdkPointerTableCandidate> findSdkPointerTableCandidates(Program program,
                                                                         List<MemoryBlock> blocks)
            throws MemoryAccessException
    {
        List<SdkPointerTableCandidate> candidates = new ArrayList<>();
        Map<String, Map<String, String>> fssrvInterfaces = this.getFssrvInterfaceDatabase();
        Set<Long> knownCommandIds = this.collectCommandIds(fssrvInterfaces);

        for (MemoryBlock block : blocks)
        {
            long start = alignUp(block.getStart().getOffset(), 0x8);
            long end = block.getEnd().getOffset();
            long runStart = -1;
            int runCount = 0;

            for (long off = start; off <= end - 0x8; off += 0x8)
            {
                Address slotAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(off);
                Address targetAddr = this.readExecutablePointer(program, slotAddr);

                if (targetAddr != null)
                {
                    if (runStart == -1)
                        runStart = off;

                    runCount++;
                    continue;
                }

                this.addSdkPointerCandidateIfInteresting(program, candidates, block, runStart,
                    runCount, fssrvInterfaces, knownCommandIds);
                runStart = -1;
                runCount = 0;
            }

            this.addSdkPointerCandidateIfInteresting(program, candidates, block, runStart,
                runCount, fssrvInterfaces, knownCommandIds);
        }

        candidates.sort(Comparator
            .comparingLong((SdkPointerTableCandidate candidate) -> candidate.tableAddr.getOffset())
            .thenComparingInt(candidate -> candidate.slotCount));
        return candidates;
    }

    private void addSdkPointerCandidateIfInteresting(Program program,
                                                     List<SdkPointerTableCandidate> candidates,
                                                     MemoryBlock block, long runStart, int runCount,
                                                     Map<String, Map<String, String>> fssrvInterfaces,
                                                     Set<Long> knownCommandIds)
            throws MemoryAccessException
    {
        if (runStart == -1 || runCount < 4)
            return;

        List<String> possibleInterfaces = this.matchPointerRunInterfaceShapes(runCount, fssrvInterfaces);
        Set<Long> inferredCommandIds = this.inferCommandIdsFromPointerRun(program, runStart,
            runCount, knownCommandIds);
        InterfaceMatch semanticMatch = inferredCommandIds.isEmpty()
            ? null
            : findBestPartialInterfaceMatch(fssrvInterfaces, inferredCommandIds, 2);
        boolean largeMixedRegion = this.isLargeMixedPointerRegion(runCount, fssrvInterfaces);

        if (possibleInterfaces.isEmpty() && semanticMatch == null)
            return;

        Address tableAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(runStart);
        candidates.add(new SdkPointerTableCandidate(tableAddr, block.getName(), runCount,
            possibleInterfaces, inferredCommandIds, semanticMatch, largeMixedRegion));
    }

    private boolean isLargeMixedPointerRegion(int runCount,
                                              Map<String, Map<String, String>> fssrvInterfaces)
    {
        int largestExpectedSlots = fssrvInterfaces.values().stream()
            .mapToInt(commands -> commands.size() + 4)
            .max()
            .orElse(0);

        return largestExpectedSlots > 0
            && runCount > largestExpectedSlots + SDK_LARGE_POINTER_REGION_EXTRA_SLOTS;
    }

    private Set<Long> inferCommandIdsFromPointerRun(Program program, long runStart, int runCount,
                                                    Set<Long> knownCommandIds)
            throws MemoryAccessException
    {
        LinkedHashSet<Long> out = new LinkedHashSet<>();
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();

        for (int i = 0; i < runCount; i++)
        {
            Address slotAddr = aSpace.getAddress(runStart + i * 0x8L);
            Address targetAddr = this.readExecutablePointer(program, slotAddr);

            if (targetAddr == null)
                continue;

            Long commandId = this.inferClientCommandIdFromStub(program, targetAddr, knownCommandIds);

            if (commandId != null)
                out.add(commandId);
        }

        return out;
    }

    private List<String> matchPointerRunInterfaceShapes(int slotCount,
                                                        Map<String, Map<String, String>> fssrvInterfaces)
    {
        List<String> out = new ArrayList<>();

        for (Map.Entry<String, Map<String, String>> entry : fssrvInterfaces.entrySet())
        {
            int commandCount = entry.getValue().size();

            if (slotCount == commandCount)
            {
                out.add(entry.getKey() + " cmds");
            }
            else if (slotCount == commandCount + 4)
            {
                out.add(entry.getKey() + " base+cmds");
            }
        }

        return out.stream().limit(6).collect(Collectors.toList());
    }

    private void markupSdkRecordCommandTableCandidate(Program program,
                                                       SdkCommandTableCandidate candidate)
    {
        program.getListing().setComment(candidate.tableAddr, CommentType.PLATE,
            this.formatSdkRecordCommandTableComment(candidate));

        for (SdkCommandTableEntry entry : candidate.entries)
        {
            String commandName = IPCDatabase.getInstance().getCommandName(candidate.interfaceName,
                entry.commandId);
            program.getListing().setComment(entry.entryAddr, CommentType.REPEATABLE,
                String.format("SDK hypothetical IPC command-record: %s cmd %d (%s) -> 0x%X",
                    candidate.interfaceName, entry.commandId,
                    commandName != null ? commandName : "unknown",
                    entry.functionAddr.getOffset()));
        }
    }

    private void markupSdkPointerTableCandidate(Program program,
                                                 SdkPointerTableCandidate candidate)
    {
        program.getListing().setComment(candidate.tableAddr, CommentType.REPEATABLE,
            String.format("SDK hypothetical %s: slots=%d possible_interfaces=%s%s",
                candidate.largeMixedRegion
                    ? "mixed IPC pointer region"
                    : "dense IPC pointer table",
                candidate.slotCount, candidate.possibleInterfaces, candidate.formatSemanticSummary()));
    }

    private String formatSdkRecordCommandTableComment(SdkCommandTableCandidate candidate)
    {
        return String.format("""
            %s
            Source:           .data.* command-record probe
            Interface Guess:  %s
            Table Address:    0x%X
            Block:            %s
            Records:          0x%X
            Record Size:      0x%X
            Command ID Off:   0x%X
            Function Off:     0x%X
            Match Score:      %d/%d
            Command IDs:      %s
            """,
            candidate.isStrongTableCandidate()
                ? "SDK HYPOTHETICAL IPC COMMAND TABLE"
                : "SDK HYPOTHETICAL IPC COMMAND RECORD FRAGMENT",
            candidate.interfaceName,
            candidate.tableAddr.getOffset(),
            candidate.blockName,
            candidate.entries.size(),
            candidate.recordSize,
            candidate.commandIdOffset,
            candidate.functionOffset,
            candidate.score,
            candidate.dbCommandCount,
            formatCommandIds(candidate.commandIds()));
    }

    private Map<String, Map<String, String>> getFssrvInterfaceDatabase()
    {
        return IPCDatabase.getInstance().getAllInterfaces().entrySet().stream()
            .filter(entry -> this.isFssrvInterfaceName(entry.getKey()))
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                (left, right) -> left, LinkedHashMap::new));
    }

    private Set<Long> collectCommandIds(Map<String, Map<String, String>> interfaces)
    {
        LinkedHashSet<Long> out = new LinkedHashSet<>();

        for (Map<String, String> commands : interfaces.values())
            out.addAll(parseCommandIds(commands.keySet()));

        return out;
    }

    private static boolean rangesOverlap(int leftOffset, int leftSize, int rightOffset, int rightSize)
    {
        return leftOffset < rightOffset + rightSize && rightOffset < leftOffset + leftSize;
    }

    private void collectKnownCommandScalars(Instruction instruction, Set<Long> knownCommandIds,
                                             Set<Long> candidates)
    {
        for (int operandIndex = 0; operandIndex < instruction.getNumOperands(); operandIndex++)
        {
            for (Object object : instruction.getOpObjects(operandIndex))
            {
                if (!(object instanceof Scalar scalar))
                    continue;

                long value = scalar.getValue();

                if (knownCommandIds.contains(value))
                    candidates.add(value);

                long unsigned32 = value & 0xFFFFFFFFL;

                if (knownCommandIds.contains(unsigned32))
                    candidates.add(unsigned32);
            }
        }
    }

    private static Set<Long> parseCommandIds(Collection<String> commandIds)
    {
        LinkedHashSet<Long> out = new LinkedHashSet<>();

        for (String commandId : commandIds)
        {
            try
            {
                out.add(Long.parseLong(commandId));
            }
            catch (NumberFormatException e)
            {
                Msg.warn(IPCAnalyzer.class, String.format("Skipping non-integer IPC database command id '%s'", commandId));
            }
        }

        return out;
    }

    private static List<Long> parseSortedCommandIds(Collection<String> commandIds)
    {
        return parseCommandIds(commandIds).stream()
            .sorted()
            .collect(Collectors.toList());
    }

    private static String formatCommandIds(Collection<Long> commandIds)
    {
        return commandIds.stream()
            .sorted()
            .map(String::valueOf)
            .collect(Collectors.joining(", ", "[", "]"));
    }

    private static String formatHexOffsets(Collection<Long> offsets)
    {
        return offsets.stream()
            .sorted()
            .map(offset -> String.format("+0x%X", offset))
            .collect(Collectors.joining(", ", "[", "]"));
    }

    private String formatInterfaceVtableGroupComment(IPCInterfaceVTableGroup group)
    {
        if (group.clientImportOnly)
        {
            return String.format("""
                IPC INTERFACE VTABLE GROUP
                Source:           SDK client/import RTTI
                Interface:         %s
                VTable Address:    0x%X
                Address Point:     0x%X
                Scan Slots:        0x%X
                Text Slots:        0x%X
                Database Commands: 0x%X
                """,
                group.interfaceName,
                group.vtableAddr.getOffset(),
                group.vtableAddr.add(0x10).getOffset(),
                group.scanSlotCount,
                group.slots.size(),
                group.commands.size());
        }

        return String.format("""
            IPC INTERFACE VTABLE GROUP
            Interface:         %s
            VTable Address:    0x%X
            Address Point:     0x%X
            Scan Slots:        0x%X
            Text Slots:        0x%X
            Command IDs Found: 0x%X
            """,
            group.interfaceName,
            group.vtableAddr.getOffset(),
            group.vtableAddr.add(0x10).getOffset(),
            group.scanSlotCount,
            group.slots.size(),
            group.slots.stream().filter(slot -> slot.commandId != null).count());
    }

    private String formatInterfaceVtableSlotComment(IPCInterfaceVTableGroup group,
                                                     IPCInterfaceVTableSlot slot,
                                                     String commandName)
    {
        if (slot.commandId != null)
        {
            return String.format(
                "IPC interface vtable slot: %s +0x%X -> 0x%X, cmd %d (%s)",
                group.interfaceName, slot.vptrOffset, slot.targetAddr.getOffset(), slot.commandId,
                commandName != null ? commandName : "unknown");
        }

        return String.format(
            "IPC interface vtable slot: %s +0x%X -> 0x%X",
            group.interfaceName, slot.vptrOffset, slot.targetAddr.getOffset());
    }

    private void createImportedLabel(Program program, Address addr, String label)
    {
        try
        {
            program.getSymbolTable().createLabel(addr, label, null, SourceType.IMPORTED);
        }
        catch (InvalidInputException e)
        {
            Msg.warn(this, String.format("Failed to create label '%s' at 0x%X: %s",
                label, addr.getOffset(), e.getMessage()));
        }
    }

    private String formatIpcComment(IPCTrace trace, IpcTraceHash interfaceHash,
                                    String interfaceName, String cmdName,
                                    Address dispatchFuncAddr, String wireLayout)
    {
        StringBuilder comment = new StringBuilder();
        String libnxCmdCall = this.formatCommentCodeBlock(
            this.formatEstimatedLibnxCmdFunction(trace, interfaceName, cmdName, wireLayout));

        comment.append(String.format("""
            IPC INFORMATION
            Dispatch Func:     0x%X
            Command:           0x%X
            Command Dec:       %d
            Command Name:      %s
            Interface hash:    %s
            LR:                0x%X
            VT Offset:         0x%X
            Bytes In:          0x%X
            Bytes Out:         0x%X
            Buffer Count:      0x%X
            Wire Layout:       %s
            Libnx Cmd Call:
            %s
            """,
            dispatchFuncAddr.getOffset(), trace.cmdId, trace.cmdId,
            cmdName != null ? cmdName : "<unknown>",
            interfaceHash != null ? interfaceHash.hash : "<unknown>",
            trace.lr, trace.vtOffset,
            trace.bytesIn, trace.bytesOut, trace.bufferCount,
            wireLayout, libnxCmdCall));

        if (interfaceHash != null && !interfaceHash.hash.equals(interfaceHash.alternateHash))
        {
            comment.append(String.format("""
                Interface hash alt: %s
                """,
                interfaceHash.alternateHash));
        }

        if (trace.hasBufferAttrs())
        {
            comment.append(String.format("""
                Buffer Attrs:      %s
                Buffer Directions: %s
                Buffer Source:     %s
                In Buffers:        0x%X
                Out Buffers:       0x%X
                """,
                trace.formatBufferAttrs(), trace.formatBufferDirections(), trace.bufferAttrsSource,
                trace.getInBufferCount(), trace.getOutBufferCount()));
        }
        else if (trace.bufferCount == 0)
        {
            comment.append("""
                Buffer Attrs:      N/A
                Buffer Directions: N/A
                Buffer Source:     N/A
                """);
        }
        else
        {
            // Probe output is only here to help debug unknown buffer-attribute layouts.
            comment.append(String.format("""
                Buffer Attrs:      <unknown>
                Buffer Directions: <unknown>
                Buffer Source:     <unknown>
                Buffer Probe:      %s
                """,
                trace.bufferAttrsProbe != null ? trace.bufferAttrsProbe : "<none>"));
        }

        comment.append(String.format("""
            In Interfaces:     0x%X
            Out Interfaces:    0x%X
            In Handles:        0x%X
            Out Handles:       0x%X
            """,
            trace.inInterfaces, trace.outInterfaces, trace.inHandles, trace.outHandles));

        return comment.toString();
    }

    private String formatCommentCodeBlock(String value)
    {
        return "    " + value.replace("\n", "\n    ");
    }

    private String formatEstimatedLibnxCmdFunction(IPCTrace trace, String interfaceName, String cmdName,
                                                   String wireLayout)
    {
        String objectType = this.getEstimatedLibnxObjectType(interfaceName);
        String serviceExpr = objectType.equals("Service") ? "d" : "&d->s";
        String functionName = this.getEstimatedLibnxFunctionName(trace, cmdName);
        List<String> params = this.formatEstimatedLibnxFunctionParams(trace, objectType, wireLayout);
        String body = this.formatEstimatedLibnxCmdCall(trace, wireLayout, serviceExpr);

        return String.format("Result %s(\n%s\n) {\n    %s\n}",
            functionName, this.formatEstimatedLibnxFunctionSignatureParams(params),
            body.replace("\n", "\n    "));
    }

    private String formatEstimatedLibnxFunctionSignatureParams(List<String> params)
    {
        StringJoiner joiner = new StringJoiner(",\n");

        for (String param : params)
            joiner.add("    " + param);

        return joiner.toString();
    }

    private String formatEstimatedLibnxCmdCall(IPCTrace trace, String wireLayout, String serviceExpr)
    {
        String helperExpansion = this.tryFormatHelperEquivalentObjectDispatch(trace, wireLayout, serviceExpr);

        if (helperExpansion != null)
            return helperExpansion;

        String dispatchMacro = this.getFsObjectDispatchMacro(trace);
        List<String> args = new ArrayList<>();

        args.add(serviceExpr);
        args.add(Long.toString(trace.cmdId));

        if (trace.bytesIn > 0)
            args.add(this.formatEstimatedInDataArg(trace, wireLayout));

        if (trace.bytesOut > 0)
            args.add(this.formatEstimatedOutDataDispatchArg(trace, wireLayout));

        List<String> params = this.formatEstimatedDispatchParams(trace, wireLayout);

        if (params.isEmpty())
            return String.format("return %s(%s);", dispatchMacro, String.join(", ", args));

        StringBuilder out = new StringBuilder();
        out.append("return ").append(dispatchMacro).append("(").append(String.join(", ", args)).append(",\n");

        for (String param : params)
            out.append("    ").append(param).append("\n");

        out.append(");");
        return out.toString();
    }

    private String tryFormatHelperEquivalentObjectDispatch(IPCTrace trace, String wireLayout, String serviceExpr)
    {
        if (this.hasNoBuffers(trace) && this.hasNoExtraIpcResources(trace))
        {
            if (trace.bytesIn <= 0 && trace.bytesOut <= 0)
                return String.format("return _fsObjectDispatch(%s, %d);", serviceExpr, trace.cmdId);

            if (trace.bytesIn <= 0)
            {
                if (trace.bytesOut == 1)
                {
                    return String.format("""
                        u8 tmp=0;
                        Result rc = _fsObjectDispatchOut(%s, %d, tmp);
                        if (R_SUCCEEDED(rc) && out)
                            *out = tmp & 1;
                        return rc;""", serviceExpr, trace.cmdId);
                }

                if (trace.bytesOut == 4 || trace.bytesOut == 8)
                    return String.format("return _fsObjectDispatchOut(%s, %d, *out);",
                        serviceExpr, trace.cmdId);
            }
        }

        return null;
    }

    private List<String> formatEstimatedLibnxFunctionParams(IPCTrace trace, String objectType, String wireLayout)
    {
        List<String> params = new ArrayList<>();
        params.add(objectType + "* d");

        int bufferCount = this.getEstimatedBufferCount(trace);
        boolean inSizeOutBufferShape = this.isEstimatedInSizeOutBufferShape(trace, wireLayout);

        if (trace.bytesIn > 0 && !inSizeOutBufferShape)
            params.add(this.getEstimatedInDataParamType(trace, wireLayout) + " " +
                this.formatEstimatedInDataArg(trace, wireLayout));

        if (trace.bytesOut > 0)
            params.add(this.getEstimatedOutDataParamType(trace) + "* " +
                this.formatEstimatedOutDataArg(trace, wireLayout));

        if (bufferCount > 0)
        {
            List<String> bufferVars = this.getEstimatedBufferVarNames(trace, wireLayout, bufferCount);

            for (int i = 0; i < bufferVars.size(); i++)
            {
                String bufferVar = bufferVars.get(i);
                String pointerType = this.getEstimatedBufferPointerType(trace, i);

                params.add(pointerType + " " + bufferVar);
                params.add("size_t " + bufferVar + "_size");
            }
        }

        if (trace.bytesIn > 0 && inSizeOutBufferShape)
            params.add(this.getEstimatedInDataParamType(trace, wireLayout) + " " +
                this.formatEstimatedInDataArg(trace, wireLayout));

        if (trace.inInterfaces > 0)
            params.add(trace.inInterfaces == 1 ? "Service* in_object" : "Service** in_objects");

        if (trace.outInterfaces > 0)
            params.add(trace.outInterfaces == 1 ? "Service* out" : "Service** out_objects");

        if (trace.inHandles > 0)
            params.add(trace.inHandles == 1 ? "Handle in_handle" : "const Handle* in_handles");

        if (trace.outHandles > 0)
            params.add(trace.outHandles == 1 ? "Handle* out_handle" : "Handle* out_handles");

        return params;
    }

    private String getEstimatedLibnxObjectType(String interfaceName)
    {
        if (interfaceName == null || interfaceName.isBlank())
            return "Service";

        String simpleName = interfaceName;
        int namespaceIndex = simpleName.lastIndexOf("::");

        if (namespaceIndex >= 0)
            simpleName = simpleName.substring(namespaceIndex + 2);

        if (simpleName.startsWith("I") && simpleName.length() > 1)
            simpleName = simpleName.substring(1);

        if (interfaceName.contains("nn::fssrv::sf::"))
            return "Fs" + simpleName;

        return "Service";
    }

    private String getEstimatedLibnxFunctionName(IPCTrace trace, String cmdName)
    {
        String name = cmdName != null && !cmdName.isBlank() ? cmdName : "Cmd" + trace.cmdId;
        StringBuilder out = new StringBuilder();

        for (int i = 0; i < name.length(); i++)
        {
            char c = name.charAt(i);

            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' ||
                (i > 0 && c >= '0' && c <= '9'))
            {
                out.append(c);
            }
            else if (out.length() > 0 && out.charAt(out.length() - 1) != '_')
            {
                out.append('_');
            }
        }

        if (out.isEmpty())
            return "Cmd" + trace.cmdId;

        return out.toString();
    }

    private String getEstimatedBufferPointerType(IPCTrace trace, int index)
    {
        if (trace.hasBufferAttrs() && index < trace.bufferAttrs.length)
        {
            int attr = trace.bufferAttrs[index];
            boolean isIn = (attr & IPCTrace.BUFFER_ATTR_IN) != 0;
            boolean isOut = (attr & IPCTrace.BUFFER_ATTR_OUT) != 0;

            if (isIn && !isOut)
                return "const void*";
        }

        return "void*";
    }

    private String getEstimatedInDataParamType(IPCTrace trace, String wireLayout)
    {
        if (this.isEstimatedInSizeOutBufferShape(trace, wireLayout))
        {
            return "s64";
        }

        return this.getEstimatedScalarType(trace.bytesIn);
    }

    private String getEstimatedOutDataParamType(IPCTrace trace)
    {
        if (this.hasNoBuffers(trace) && this.hasNoExtraIpcResources(trace) &&
            trace.bytesIn <= 0 && trace.bytesOut == 1)
        {
            return "bool";
        }

        if (this.hasNoBuffers(trace) && this.hasNoExtraIpcResources(trace) &&
            trace.bytesIn <= 0 && trace.bytesOut == 8)
        {
            return "s64";
        }

        return this.getEstimatedScalarType(trace.bytesOut);
    }

    private String getEstimatedScalarType(long size)
    {
        if (size == 1)
            return "u8";
        if (size == 2)
            return "u16";
        if (size == 4)
            return "u32";
        if (size == 8)
            return "u64";

        return "void";
    }

    private boolean hasNoBuffers(IPCTrace trace)
    {
        return this.getEstimatedBufferCount(trace) <= 0;
    }

    private boolean hasNoExtraIpcResources(IPCTrace trace)
    {
        return trace.inInterfaces <= 0 && trace.outInterfaces <= 0 &&
            trace.inHandles <= 0 && trace.outHandles <= 0;
    }

    private int getEstimatedBufferCount(IPCTrace trace)
    {
        if (trace.hasBufferAttrs())
            return trace.bufferAttrs.length;

        return trace.bufferCount > 0 ? (int)trace.bufferCount : 0;
    }

    private boolean isEstimatedOutOnlyBuffer(IPCTrace trace, String wireLayout, int index)
    {
        if (trace.hasBufferAttrs() && index < trace.bufferAttrs.length)
        {
            int attr = trace.bufferAttrs[index];
            return (attr & IPCTrace.BUFFER_ATTR_OUT) != 0 && (attr & IPCTrace.BUFFER_ATTR_IN) == 0;
        }

        List<String> bufferTokens = this.getWireLayoutBufferTokens(wireLayout);

        if (index >= bufferTokens.size())
            return false;

        return bufferTokens.get(index).startsWith("out_buf");
    }

    private boolean isEstimatedInSizeOutBufferShape(IPCTrace trace, String wireLayout)
    {
        return trace.bytesIn == 8 && trace.bytesOut <= 0 && this.getEstimatedBufferCount(trace) == 1 &&
            this.hasNoExtraIpcResources(trace) && this.isEstimatedOutOnlyBuffer(trace, wireLayout, 0);
    }

    private String getFsObjectDispatchMacro(IPCTrace trace)
    {
        boolean hasInData = trace.bytesIn > 0;
        boolean hasOutData = trace.bytesOut > 0;

        if (hasInData && hasOutData)
            return "_fsObjectDispatchInOut";
        if (hasInData)
            return "_fsObjectDispatchIn";
        if (hasOutData)
            return "_fsObjectDispatchOut";

        return "_fsObjectDispatch";
    }

    private String formatEstimatedInDataArg(IPCTrace trace, String wireLayout)
    {
        if (this.isEstimatedInSizeOutBufferShape(trace, wireLayout))
        {
            return "size";
        }

        List<String> inputTokens = this.getWireLayoutInputTokens(wireLayout);

        if (inputTokens.size() == 1)
        {
            String token = inputTokens.get(0);

            if (!this.isSyntheticInputToken(token))
                return token;
        }

        return this.getEstimatedInDataTypeName(trace.bytesIn);
    }

    private String formatEstimatedOutDataArg(IPCTrace trace, String wireLayout)
    {
        List<String> outputTokens = this.getWireLayoutOutputTokens(wireLayout);

        if (outputTokens.size() == 1 && !this.isSyntheticOutputToken(outputTokens.get(0)))
            return outputTokens.get(0);

        return "out";
    }

    private String formatEstimatedOutDataDispatchArg(IPCTrace trace, String wireLayout)
    {
        String outArg = this.formatEstimatedOutDataArg(trace, wireLayout);
        String outType = this.getEstimatedOutDataParamType(trace);

        if (!outType.equals("void") && !outArg.startsWith("*"))
            return "*" + outArg;

        return outArg;
    }

    private String getEstimatedInDataTypeName(long bytesIn)
    {
        if (bytesIn == 1)
            return "in_u8";
        if (bytesIn == 2)
            return "in_u16";
        if (bytesIn == 4)
            return "in_u32";
        if (bytesIn == 8)
            return "in_u64";

        return "in";
    }

    private List<String> formatEstimatedDispatchParams(IPCTrace trace, String wireLayout)
    {
        List<String> params = new ArrayList<>();
        int bufferCount = this.getEstimatedBufferCount(trace);

        if (bufferCount > 0)
        {
            params.add(".buffer_attrs = {");

            for (int i = 0; i < bufferCount; i++)
                params.add("    " + this.formatEstimatedBufferAttr(trace, i) + ",");

            params.add("},");
            params.add(".buffers = {");

            List<String> bufferVars = this.getEstimatedBufferVarNames(trace, wireLayout, bufferCount);

            for (String bufferVar : bufferVars)
                params.add(String.format("    { %s, %s_size },", bufferVar, bufferVar));

            params.add("},");
        }

        if (trace.inInterfaces > 0)
        {
            params.add(String.format(".in_num_objects = %d,", trace.inInterfaces));
            params.add(".in_objects = { in_object },");
        }

        if (trace.outInterfaces > 0)
        {
            params.add(String.format(".out_num_objects = %d,", trace.outInterfaces));
            params.add(trace.outInterfaces == 1 ? ".out_objects = out," : ".out_objects = out_objects,");
        }

        if (trace.inHandles > 0)
        {
            params.add(String.format(".in_num_handles = %d,", trace.inHandles));
            params.add(".in_handles = { in_handle },");
        }

        if (trace.outHandles > 0)
        {
            params.add(".out_handle_attrs = { SfOutHandleAttr_HipcMove },");
            params.add(".out_handles = out_handle,");
        }

        return params;
    }

    private String formatEstimatedBufferAttr(IPCTrace trace, int index)
    {
        if (!trace.hasBufferAttrs() || index >= trace.bufferAttrs.length)
            return "/* unknown buffer attr */ 0";

        int attr = trace.bufferAttrs[index];
        List<String> flags = new ArrayList<>();

        if ((attr & 4) != 0)
            flags.add("SfBufferAttr_HipcMapAlias");
        if ((attr & 8) != 0)
            flags.add("SfBufferAttr_HipcPointer");
        if ((attr & 16) != 0)
            flags.add("SfBufferAttr_FixedSize");
        if ((attr & 32) != 0)
            flags.add("SfBufferAttr_HipcAutoSelect");
        if ((attr & 64) != 0)
            flags.add("SfBufferAttr_HipcMapTransferAllowsNonSecure");
        if ((attr & 128) != 0)
            flags.add("SfBufferAttr_HipcMapTransferAllowsNonDevice");
        if ((attr & IPCTrace.BUFFER_ATTR_IN) != 0)
            flags.add("SfBufferAttr_In");
        if ((attr & IPCTrace.BUFFER_ATTR_OUT) != 0)
            flags.add("SfBufferAttr_Out");

        if (flags.isEmpty())
            return "0";

        return String.join(" | ", flags);
    }

    private List<String> getEstimatedBufferVarNames(IPCTrace trace, String wireLayout, int bufferCount)
    {
        List<String> wireLayoutBuffers = this.getWireLayoutBufferTokens(wireLayout);
        List<String> bufferVars = new ArrayList<>();
        int inIndex = 0;
        int outIndex = 0;
        int inOutIndex = 0;

        for (int i = 0; i < bufferCount; i++)
        {
            String wireLayoutName = i < wireLayoutBuffers.size() ? wireLayoutBuffers.get(i) : null;
            String bufferVar = this.getNonSyntheticWireLayoutName(wireLayoutName);

            if (bufferVar == null)
            {
                int attr = trace.hasBufferAttrs() && i < trace.bufferAttrs.length ? trace.bufferAttrs[i] : 0;
                boolean isIn = (attr & IPCTrace.BUFFER_ATTR_IN) != 0;
                boolean isOut = (attr & IPCTrace.BUFFER_ATTR_OUT) != 0;

                if (isIn && isOut)
                    bufferVar = inOutIndex++ == 0 ? "buf" : "inout_buf" + (inOutIndex - 1);
                else if (isOut)
                    bufferVar = outIndex++ == 0 ? "dst" : "out_buf" + (outIndex - 1);
                else if (isIn)
                    bufferVar = inIndex++ == 0 ? "src" : "in_buf" + (inIndex - 1);
                else
                    bufferVar = "buffer" + i;
            }

            bufferVars.add(bufferVar);
        }

        return bufferVars;
    }

    private String getNonSyntheticWireLayoutName(String name)
    {
        if (name == null || name.isBlank())
            return null;

        if (name.matches("(in|out|inout)_buf\\d+") || name.matches("buffer\\d+"))
            return null;

        return name;
    }

    private List<String> getWireLayoutBufferTokens(String wireLayout)
    {
        return this.getWireLayoutTokens(wireLayout).stream()
            .filter(token -> token.matches("(in|out|inout)_buf\\d+") || token.matches("buffer\\d+") ||
                (token.endsWith("_buf") && !token.startsWith("in_data") && !token.startsWith("out_data")))
            .collect(Collectors.toList());
    }

    private List<String> getWireLayoutInputTokens(String wireLayout)
    {
        return this.getWireLayoutTokens(wireLayout).stream()
            .filter(token -> !this.isWireLayoutBufferToken(token))
            .filter(token -> !token.startsWith("out_data["))
            .filter(token -> !token.startsWith("buffers="))
            .collect(Collectors.toList());
    }

    private List<String> getWireLayoutOutputTokens(String wireLayout)
    {
        return this.getWireLayoutTokens(wireLayout).stream()
            .filter(token -> token.startsWith("out_data["))
            .collect(Collectors.toList());
    }

    private boolean isWireLayoutBufferToken(String token)
    {
        return token.matches("(in|out|inout)_buf\\d+") || token.matches("buffer\\d+") ||
            (token.endsWith("_buf") && !token.startsWith("in_data") && !token.startsWith("out_data"));
    }

    private boolean isSyntheticInputToken(String token)
    {
        return token.startsWith("in_data[") || token.matches("in_u(8|16|32|64)_\\d+");
    }

    private boolean isSyntheticOutputToken(String token)
    {
        return token.startsWith("out_data[");
    }

    private List<String> getWireLayoutTokens(String wireLayout)
    {
        if (wireLayout == null || wireLayout.isBlank() || wireLayout.equals("N/A"))
            return Collections.emptyList();

        return Arrays.stream(wireLayout.split(";"))
            .map(String::trim)
            .filter(token -> !token.isBlank() && !token.equals("N/A"))
            .collect(Collectors.toList());
    }

    private void exportIpcJson(Program program, List<IPCVTableEntry> vtEntries,
                               Multimap<Address, IPCTrace> processFuncTraces,
                               HashBiMap<Address, IPCVTableEntry> procFuncVtMap,
                               List<IPCInterfaceVTableGroup> interfaceVtableGroups,
                               Map<Address, SyntheticCommandFunctionTable> syntheticCommandTables,
                               List<String> connectedServices,
                               HashBiMap<Address, Address> sTableProcessFuncMap,
                               Map<String, ServiceUsageTracer.ServiceUsage> invokedCommands)
    {
        if (!this.exportIpcJson)
            return;

        File exportFile = this.getIpcJsonExportFile(program);

        if (exportFile == null)
            return;

        try
        {
            File parent = exportFile.getParentFile();

            if (parent != null && !parent.exists() && !parent.mkdirs())
            {
                Msg.warn(this, String.format("Failed to create IPC JSON export directory: %s", parent));
                return;
            }

            try (FileWriter writer = new FileWriter(exportFile))
            {
                writer.write(this.formatIpcJson(program, vtEntries, processFuncTraces,
                    procFuncVtMap, interfaceVtableGroups, syntheticCommandTables, connectedServices,
                    sTableProcessFuncMap, invokedCommands));
            }

            Msg.info(this, String.format("Exported IPC metadata JSON to %s", exportFile.getAbsolutePath()));
        }
        catch (IOException | MemoryAccessException e)
        {
            Msg.warn(this, String.format("Failed to export IPC metadata JSON to %s: %s",
                exportFile.getAbsolutePath(), e.getMessage()));
        }
    }

    private File getIpcJsonExportFile(Program program)
    {
        if (this.exportIpcJsonPath != null && !this.exportIpcJsonPath.isBlank())
            return new File(this.exportIpcJsonPath);

        String executablePath = program.getExecutablePath();

        if (executablePath == null || executablePath.isBlank())
        {
            Msg.warn(this, "IPC metadata JSON export requested, but no export path or executable path is available.");
            return null;
        }

        return new File(executablePath + ".ipc.json");
    }


    private String formatIpcJson(Program program, List<IPCVTableEntry> vtEntries,
                                 Multimap<Address, IPCTrace> processFuncTraces,
                                 HashBiMap<Address, IPCVTableEntry> procFuncVtMap,
                                 List<IPCInterfaceVTableGroup> interfaceVtableGroups,
                                 Map<Address, SyntheticCommandFunctionTable> syntheticCommandTables,
                                 List<String> connectedServices,
                                 HashBiMap<Address, Address> sTableProcessFuncMap,
                                 Map<String, ServiceUsageTracer.ServiceUsage> invokedCommands) throws MemoryAccessException
    {
        Map<String, IpcJsonInterfaceExport> exportInterfaces = new LinkedHashMap<>();
        Set<String> knownInterfaces = new LinkedHashSet<>(IPCDatabase.getInstance().getAllInterfaces().keySet());

        // Map every discovered/hash-named vtable address to its interface name, so an out-interface
        // captured during emulation can be named from the vtable it returned (and, failing that,
        // surfaced as "Unresolved>0x<addr>" instead of a bare null).
        Map<Long, String> vtableInterfaceNames = new HashMap<>();
        // Parallel map: address -> the returned object's SRV_<sTable> canary, so a command's
        // out-interface keeps its address-stable identity (_srv_outinterfaces) regardless of the name.
        Map<Long, String> vtableSrvNames = new HashMap<>();
        for (IPCVTableEntry vtEntry : vtEntries)
        {
            if (vtEntry.addr == null)
                continue;

            String name = stripVtableSuffix(vtEntry.abvName);
            Address pf = procFuncVtMap.inverse().get(vtEntry);
            Address st = pf != null ? sTableProcessFuncMap.inverse().get(pf) : null;
            long srvOff = st != null ? st.getOffset() : (pf != null ? pf.getOffset() : vtEntry.addr.getOffset());
            String srv = String.format("SRV_%X", srvOff);

            // The emulator may capture a returned out-interface by its vtable, s_Table OR proc_func
            // address -- index all three so the lookup resolves regardless of which one it saw.
            for (Long a : new Long[]{ vtEntry.addr.getOffset(),
                                      st != null ? st.getOffset() : null,
                                      pf != null ? pf.getOffset() : null })
            {
                if (a == null)
                    continue;
                vtableInterfaceNames.putIfAbsent(a, name);
                vtableSrvNames.putIfAbsent(a, srv);
            }
        }

        for (IPCVTableEntry entry : vtEntries)
        {
            Address processFuncAddr = procFuncVtMap.inverse().get(entry);

            if (processFuncAddr == null || !processFuncTraces.containsKey(processFuncAddr))
                continue;

            List<IPCTrace> traces = Lists.newArrayList(processFuncTraces.get(processFuncAddr).iterator());
            traces = traces.stream()
                .filter(trace -> trace.vtOffset != -1 && trace.hasDescription())
                .sorted(Comparator.comparingLong(trace -> trace.cmdId))
                .collect(Collectors.toList());

            if (traces.isEmpty())
                continue;

            // An ObjectImplFactory/templated vtable mangle that leaked through naming is not a usable
            // interface name: recover the real interface from its InterfaceInfo<...> arg, else fall back
            // to SRV_<procFunc> (unverified) rather than emitting the raw _ZTV... symbol.
            String interfaceName = this.resolveDiscoveredInterfaceName(entry.abvName, processFuncAddr.getOffset());

            // Each discovered server proc_func is a distinct object. When several share a name (e.g.
            // byte-identical interfaces that all hash-match the same DB name), DO NOT merge them away:
            // disambiguate the key with the proc_func address so every distinct interface is preserved.
            long procOff = processFuncAddr.getOffset();
            String key = interfaceName;
            IpcJsonInterfaceExport prior = exportInterfaces.get(key);
            if (prior != null && prior.address != procOff)
                key = interfaceName + "@0x" + Long.toHexString(procOff);

            IpcJsonInterfaceExport exportInterface = this.getOrCreateIpcJsonInterface(exportInterfaces,
                key, interfaceName, procOff);

            // The original SRV_<sTable> canary name, kept on EVERY interface (matched or not) as _srv,
            // so each interface always carries its address-stable identity regardless of how it's named.
            if (exportInterface.srvName == null)
            {
                Address sTableAddr = sTableProcessFuncMap != null
                    ? sTableProcessFuncMap.inverse().get(processFuncAddr) : null;
                long srvOff = sTableAddr != null ? sTableAddr.getOffset() : procOff;
                exportInterface.srvName = String.format("SRV_%X", srvOff);
            }

            this.applyTraceHashToIpcJsonInterface(exportInterface,
                getIpcTraceHash(processFuncTraces.get(processFuncAddr)));

            for (IPCTrace trace : traces)
            {
                IpcJsonCommandExport command = exportInterface.getOrCreateCommand(trace.cmdId);
                String commandName = IPCDatabase.getInstance().getCommandName(interfaceName, trace.cmdId);
                SyntheticCommandFunctionTable commandTable =
                    syntheticCommandTables != null ? syntheticCommandTables.get(processFuncAddr) : null;
                this.applyTraceToIpcJsonCommand(program, entry, interfaceName, trace,
                    commandName, command, knownInterfaces, commandTable, vtableInterfaceNames, vtableSrvNames);
            }
        }

        if (interfaceVtableGroups != null)
        {
            for (IPCInterfaceVTableGroup group : interfaceVtableGroups)
            {
                knownInterfaces.add(group.interfaceName);

                // No inference: a "client import only" group is just this interface's database
                // command names emitted because a (possibly mis-attributed) client-import vtable
                // was suspected -- with no recovered addresses.  Drop it entirely.
                if (group.clientImportOnly)
                    continue;

                // Groups may only AUGMENT an interface that was actually emulated (filling in DB command
                // names on existing commands). They must NOT create a standalone entry, nor a command,
                // out of database data alone -- that produced phantom "vt+name, no lr/func" items.
                IpcJsonInterfaceExport exportInterface = exportInterfaces.get(group.interfaceName);
                if (exportInterface == null)
                    continue;

                for (IPCInterfaceVTableSlot slot : group.slots)
                {
                    if (slot.commandId == null)
                        continue;

                    IpcJsonCommandExport command = exportInterface.commands.get(slot.commandId);
                    if (command == null)
                        continue;

                    if (command.name == null)
                        command.name = group.commands.get(String.valueOf(slot.commandId));
                }
            }
        }

        String serviceName = this.inferIpcJsonServiceName(program, exportInterfaces.keySet());
        String programIdentified = this.inferProgram(exportInterfaces.values());
        List<IpcJsonInterfaceExport> sortedInterfaces = this.sortIpcJsonInterfaces(exportInterfaces.values());
        this.inferLikelyNames(programIdentified, sortedInterfaces);
        this.applyIpcJsonLikelyResolution(sortedInterfaces);
        this.resolveOutInterfacesFromDiscovered(sortedInterfaces);
        StringBuilder out = new StringBuilder();
        boolean wroteInterface = false;

        out.append("{\n");
        out.append("  \"").append(this.escapeJson(serviceName)).append("\": {\n");

        if (programIdentified != null)
            out.append("    \"program_identified\": \"")
                .append(this.escapeJson(programIdentified)).append("\",\n");

        for (IpcJsonInterfaceExport exportInterface : sortedInterfaces)
        {
            if (exportInterface.commands.isEmpty())
                continue;

            if (wroteInterface)
                out.append(",\n");

            String interfaceKey = exportInterface.jsonKey != null
                ? exportInterface.jsonKey : exportInterface.interfaceName;
            out.append("    \"").append(this.escapeJson(interfaceKey)).append("\": {\n");

            boolean wroteInterfaceField = false;
            int commandIdWidth = exportInterface.commands.keySet().stream()
                .map(String::valueOf)
                .mapToInt(String::length)
                .max()
                .orElse(1);

            // _srv: the original SRV_<sTable> canary, on EVERY interface, regardless of how it's named
            if (exportInterface.srvName != null)
            {
                out.append("      \"_srv\": \"")
                    .append(this.escapeJson(exportInterface.srvName))
                    .append("\"");
                wroteInterfaceField = true;
            }

            if (exportInterface.interfaceHash != null)
            {
                if (wroteInterfaceField)
                    out.append(",\n");

                out.append("      \"_hash\": \"")
                    .append(this.escapeJson(exportInterface.interfaceHash))
                    .append("\"");
                wroteInterfaceField = true;
            }

            if (exportInterface.interfaceHashAlt != null &&
                !exportInterface.interfaceHashAlt.equals(exportInterface.interfaceHash))
            {
                if (wroteInterfaceField)
                    out.append(",\n");

                out.append("      \"_hash_alt\": \"")
                    .append(this.escapeJson(exportInterface.interfaceHashAlt))
                    .append("\"");
                wroteInterfaceField = true;
            }

            // The inferred name is now the KEY; _likely_basis stays as provenance marking it as
            // positionally inferred (not hash-proven).
            if (exportInterface.likelyBasis != null)
            {
                if (wroteInterfaceField)
                    out.append(",\n");

                out.append("      \"_likely_basis\": \"")
                    .append(this.escapeJson(exportInterface.likelyBasis)).append("\"");
                wroteInterfaceField = true;
            }

            for (IpcJsonCommandExport command : exportInterface.commands.values())
            {
                if (wroteInterfaceField)
                    out.append(",\n");

                String commandId = String.valueOf(command.commandId);
                out.append("      \"").append(commandId).append("\":");
                out.append(" ".repeat(commandIdWidth - commandId.length() + 1));
                this.appendIpcJsonCommand(out, command);
                wroteInterfaceField = true;
            }

            out.append("\n    }");
            wroteInterface = true;
        }

        if (connectedServices != null && !connectedServices.isEmpty())
        {
            if (wroteInterface)
                out.append(",\n");

            this.appendConnectedServices(out, connectedServices);

            if (invokedCommands != null && !invokedCommands.isEmpty())
            {
                out.append(",\n");
                this.appendInvokedCommands(out, invokedCommands);
            }
        }

        out.append("\n  }\n");
        out.append("}\n");
        return out.toString();
    }


    /**
     * Appends the {@code "_services"} section: the sorted list of HIPC services this module connects
     * to as a client (recovered from the {@code ConnectToHipcService} service-name strings).
     */
    /**
     * Recovers, per connected service, the commands this module ACTUALLY invokes (proven from real
     * ARM64 bytes via {@link ServiceUsageTracer}: connector -&gt; proxy vtable -&gt; offset-&gt;cmd, with
     * object type-flow so sub-interface calls resolve against their own vtable, not the root proxy).
     */
    private Map<String, ServiceUsageTracer.ServiceUsage> recoverInvokedCommands(Program program,
                                                                                List<String> connectedServices,
                                                                                Map<Address, String> rttiNames)
    {
        Map<String, ServiceUsageTracer.ServiceUsage> out = new LinkedHashMap<>();

        try
        {
            ServiceUsageTracer tracer = new ServiceUsageTracer(program);
            tracer.setRttiVtables(this.buildRttiVtableInterfaceMap(rttiNames));

            for (String service : connectedServices)
            {
                ServiceUsageTracer.ServiceUsage usage = tracer.trace(service);

                if (usage != null)
                    out.put(service, usage);
            }
        }
        catch (Exception e)
        {
            Msg.warn(this, "Failed to recover invoked IPC commands: " + e.getMessage());
        }

        return out;
    }

    /** The RTTI vtable->interface-fullname map (incl. client/proxy vtables), for the ServiceUsageTracer's
     *  fallbacks (lazy-singleton/template proxies the structural scans can't reach). Sourced from the RTTI
     *  name map, which is where the client proxy vtables live. {@code ::vtable} suffix stripped. */
    private Map<Long, String> buildRttiVtableInterfaceMap(Map<Address, String> rttiNames)
    {
        Map<Long, String> map = new HashMap<>();
        if (rttiNames != null)
            for (Map.Entry<Address, String> e : rttiNames.entrySet())
                if (e.getKey() != null && e.getValue() != null)
                    map.put(e.getKey().getOffset(), stripVtableSuffix(e.getValue()));
        return map;
    }

    /**
     * Mark up the CLIENT side in the program: for every proven invoked service command, label + comment
     * each call site (the invoking {@code blr}) and the cmd-id decode site, and label each service's
     * proxy vtable. Mirrors the JSON {@code _invokes} section. Purely additive (IMPORTED labels + EOL/
     * PLATE comments); never overrides a user-applied name or an existing comment.
     */
    private void markupInvokedCommands(Program program, Map<String, ServiceUsageTracer.ServiceUsage> invoked)
    {
        if (invoked == null || invoked.isEmpty())
            return;

        IPCDatabase database = IPCDatabase.getInstance();
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();

        for (ServiceUsageTracer.ServiceUsage usage : invoked.values())
        {
            String rootInterface = database.getServiceInterface(usage.serviceName, usage.rootCommands.keySet());

            if (usage.rootVtable != 0)
            {
                Address vtAddr = aSpace.getAddress(usage.rootVtable);
                this.tryCreateLabel(program, vtAddr, "proxy_" + this.shortInterfaceName(rootInterface, usage.serviceName));
                this.setCommentIfAbsent(program, vtAddr, CommentType.PLATE,
                    String.format("IPC client proxy vtable for service '%s'%s", usage.serviceName,
                        rootInterface != null ? " (" + rootInterface + ")" : ""));
            }

            for (Map.Entry<Long, ServiceUsageTracer.CommandProof> e : usage.rootCommands.entrySet())
                this.markupCommandProof(program, aSpace, database, usage.serviceName, rootInterface,
                    e.getKey(), e.getValue());

            for (Map.Entry<Long, TreeMap<Long, ServiceUsageTracer.CommandProof>> open
                    : usage.subCommandsByOpenCommand.entrySet())
            {
                String outIface = rootInterface != null
                    ? database.getOutInterface(rootInterface, open.getKey()) : null;
                for (Map.Entry<Long, ServiceUsageTracer.CommandProof> e : open.getValue().entrySet())
                    this.markupCommandProof(program, aSpace, database, usage.serviceName, outIface,
                        e.getKey(), e.getValue());
            }
        }
    }

    private void markupCommandProof(Program program, AddressSpace aSpace, IPCDatabase database,
            String service, String iface, long cmd, ServiceUsageTracer.CommandProof proof)
    {
        String name = iface != null ? database.getCommandName(iface, cmd) : null;
        String shortIface = this.shortInterfaceName(iface, service);
        String invokeLabel = "invoke_" + shortIface + "_" + (name != null ? name : "Cmd" + cmd);
        String invokeComment = String.format("IPC invoke -> %s::[%d]%s  (service %s)",
            iface != null ? iface : "?", cmd, name != null ? name : "", service);

        for (Long site : proof.callSites)
        {
            if (site == null || site == 0)
                continue;
            Address a = aSpace.getAddress(site);
            this.tryCreateLabel(program, a, invokeLabel);
            this.setCommentIfAbsent(program, a, CommentType.EOL, invokeComment);
        }

        if (proof.decodeSite != 0)
        {
            Address d = aSpace.getAddress(proof.decodeSite);
            this.tryCreateLabel(program, d, "cmdid_" + shortIface + "_" + cmd);
            this.setCommentIfAbsent(program, d, CommentType.EOL, String.format("IPC cmd id %d -> %s%s",
                cmd, iface != null ? iface : "?", name != null ? "::" + name : ""));
        }
    }

    /** Last interface-name component, sanitized to a label-safe identifier; falls back to the service. */
    private String shortInterfaceName(String iface, String service)
    {
        String base = iface != null && iface.contains("::")
            ? iface.substring(iface.lastIndexOf("::") + 2)
            : (iface != null ? iface : service);
        return base.replaceAll("[^A-Za-z0-9_]", "_");
    }

    private void tryCreateLabel(Program program, Address addr, String label)
    {
        try
        {
            if (!this.hasSymbolNamed(program, addr, label))
                program.getSymbolTable().createLabel(addr, label, null, SourceType.IMPORTED);
        }
        catch (InvalidInputException e)
        {
            Msg.warn(this, String.format("Failed to create client-invoke label '%s' at 0x%X: %s",
                label, addr.getOffset(), e.getMessage()));
        }
    }

    private void setCommentIfAbsent(Program program, Address addr, CommentType type, String comment)
    {
        if (program.getListing().getComment(type, addr) == null)
            program.getListing().setComment(addr, type, comment);
    }

    /**
     * Appends the {@code "_invokes"} section: per connected service, the proven commands invoked, each
     * carrying its full byte-level PROOF -- the vtable slot offset, the dispatch stub, the exact
     * instruction that materialises the command id ({@code decode}), and every call site that invokes
     * it. Root-interface commands sit under {@code "commands"}; sub-interface commands are grouped under
     * the root command that opens them (e.g. fsp-srv cmd 400 OpenDeviceOperator -&gt; the IDeviceOperator
     * commands invoked on its out-interface). Per command:
     * {@code {"vt_off":"0x..","stub":"0x..","decode":"0x..","calls":["0x..",..]}}.
     */
    private void appendInvokedCommands(StringBuilder out, Map<String, ServiceUsageTracer.ServiceUsage> invoked)
    {
        IPCDatabase database = IPCDatabase.getInstance();
        out.append("    \"_invokes\": {\n");

        boolean wroteService = false;

        for (ServiceUsageTracer.ServiceUsage usage : invoked.values())
        {
            if (wroteService)
                out.append(",\n");

            out.append("      \"").append(this.escapeJson(usage.serviceName)).append("\": {\n");

            // The service's root interface (e.g. fsp-srv -> IFileSystemProxy), used to resolve both
            // command names and the out-interface of each Open* sub-interface. The observed root
            // command ids disambiguate services that map to different interfaces across firmwares.
            String rootInterface = database.getServiceInterface(usage.serviceName, usage.rootCommands.keySet());
            boolean wroteField = false;

            if (rootInterface != null)
            {
                out.append("        \"interface\": \"").append(this.escapeJson(rootInterface)).append("\"");
                wroteField = true;
            }

            if (!usage.rootCommands.isEmpty())
            {
                if (wroteField)
                    out.append(",\n");
                out.append("        \"commands\": ")
                    .append(this.formatCommandProofMap(usage.rootCommands, rootInterface, "          "));
                wroteField = true;
            }

            if (!usage.subCommandsByOpenCommand.isEmpty())
            {
                if (wroteField)
                    out.append(",\n");

                out.append("        \"sub_interfaces\": {\n");

                boolean wroteSub = false;

                for (Map.Entry<Long, TreeMap<Long, ServiceUsageTracer.CommandProof>> e : usage.subCommandsByOpenCommand.entrySet())
                {
                    if (wroteSub)
                        out.append(",\n");

                    // Key = the Open* root command id and the out-interface it returns, e.g.
                    // "400 (nn::fssrv::sf::IDeviceOperator)". Sub commands resolve against that interface.
                    long openCmd = e.getKey();
                    String outIface = rootInterface != null ? database.getOutInterface(rootInterface, openCmd) : null;
                    String key = outIface != null ? (openCmd + " (" + outIface + ")") : String.valueOf(openCmd);
                    out.append("          \"").append(this.escapeJson(key)).append("\": ")
                        .append(this.formatCommandProofMap(e.getValue(), outIface, "            "));
                    wroteSub = true;
                }

                out.append("\n        }");
                wroteField = true;
            }

            out.append("\n      }");
            wroteService = true;
        }

        out.append("\n    }");
    }

    /**
     * Formats a {@code commandId -> CommandProof} map as a JSON object. Each command carries its name
     * (resolved against {@code interfaceName} via the IPC database, when known) followed by its proof:
     * {@code {"<cmd>": {"name":"..","vt_off":"0x..","stub":"0x..","cmd_proof_offset":"0x..",
     * "cmd_proof_instruction":"..","cmd_hex_and_dec":"0x.. / ..","calls":[..]}}}.
     */
    private String formatCommandProofMap(Map<Long, ServiceUsageTracer.CommandProof> commands,
                                         String interfaceName, String indent)
    {
        IPCDatabase database = IPCDatabase.getInstance();
        StringBuilder sb = new StringBuilder("{\n");
        boolean wrote = false;

        for (Map.Entry<Long, ServiceUsageTracer.CommandProof> e : commands.entrySet())
        {
            if (wrote)
                sb.append(",\n");

            ServiceUsageTracer.CommandProof p = e.getValue();
            String name = interfaceName != null ? database.getCommandName(interfaceName, e.getKey()) : null;

            sb.append(indent).append("\"").append(e.getKey()).append("\": { ");
            if (name != null)
                sb.append("\"name\": \"").append(this.escapeJson(name)).append("\", ");
            sb.append("\"vt_off\": \"0x").append(Long.toHexString(p.vtOffset)).append("\", ")
                .append("\"stub\": \"0x").append(Long.toHexString(p.stub)).append("\", ")
                .append("\"cmd_proof_offset\": \"0x").append(Long.toHexString(p.decodeSite)).append("\", ")
                .append("\"cmd_proof_instruction\": \"").append(this.escapeJson(p.decodeInstruction)).append("\", ")
                .append("\"cmd_hex_and_dec\": \"0x").append(Long.toHexString(p.command))
                    .append(" / ").append(p.command).append("\", ")
                .append("\"calls\": ").append(this.formatHexAddressArray(p.callSites))
                .append(" }");
            wrote = true;
        }

        sb.append("\n").append(indent.substring(2)).append("}");
        return sb.toString();
    }

    private String formatHexAddressArray(Collection<Long> addresses)
    {
        StringBuilder sb = new StringBuilder("[");
        boolean wrote = false;

        for (Long a : addresses)
        {
            if (wrote)
                sb.append(", ");

            sb.append("\"0x").append(Long.toHexString(a)).append("\"");
            wrote = true;
        }

        sb.append("]");
        return sb.toString();
    }

    private void appendConnectedServices(StringBuilder out, List<String> connectedServices)
    {
        out.append("    \"_services\": [");

        boolean wrote = false;

        for (String service : connectedServices)
        {
            if (wrote)
                out.append(", ");

            out.append("\"").append(this.escapeJson(service)).append("\"");
            wrote = true;
        }

        out.append("]");
    }

    private IpcJsonInterfaceExport getOrCreateIpcJsonInterface(Map<String, IpcJsonInterfaceExport> interfaces,
                                                                String key, String interfaceName, long address)
    {
        IpcJsonInterfaceExport exportInterface = interfaces.get(key);

        if (exportInterface == null)
        {
            exportInterface = new IpcJsonInterfaceExport(interfaceName, interfaces.size(), address);
            exportInterface.jsonKey = key;
            interfaces.put(key, exportInterface);
        }

        return exportInterface;
    }

    private void applyTraceHashToIpcJsonInterface(IpcJsonInterfaceExport exportInterface,
                                                  IpcTraceHash traceHash)
    {
        if (exportInterface == null || traceHash == null)
            return;

        if (exportInterface.interfaceHash == null)
            exportInterface.interfaceHash = traceHash.hash;
        else if (!exportInterface.interfaceHash.equals(traceHash.hash))
            Msg.warn(this, String.format(
                "Conflicting IPC JSON interface hash for %s: keeping %s, ignoring %s",
                exportInterface.interfaceName, exportInterface.interfaceHash, traceHash.hash));

        if (exportInterface.interfaceHashAlt == null)
            exportInterface.interfaceHashAlt = traceHash.alternateHash;
        else if (!exportInterface.interfaceHashAlt.equals(traceHash.alternateHash))
            Msg.warn(this, String.format(
                "Conflicting IPC JSON interface alt hash for %s: keeping %s, ignoring %s",
                exportInterface.interfaceName, exportInterface.interfaceHashAlt, traceHash.alternateHash));
    }

    private void applyTraceToIpcJsonCommand(Program program, IPCVTableEntry entry, String interfaceName,
                                             IPCTrace trace, String commandName,
                                             IpcJsonCommandExport command, Set<String> knownInterfaces,
                                             SyntheticCommandFunctionTable syntheticCommandTable,
                                             Map<Long, String> vtableInterfaceNames,
                                             Map<Long, String> vtableSrvNames)
    {
        command.vtOffset = trace.vtOffset;
        command.name = commandName != null ? commandName : command.name;

        // Unmatched dispatcher entries can be anchored at an s_Table/process_func instead of a real vtable.
        // Their emulated vtOffset is still useful, but reading entry.addr + 0x10 + vtOffset would invent a bogus func.
        Address implAddr = entry.hasRealVtable
            ? this.tryReadIpcCommandFunction(program, entry.addr, trace.vtOffset)
            : syntheticCommandTable != null ? syntheticCommandTable.getFunction(trace.vtOffset) : null;
        Address directTargetAddr = null;

        if (implAddr != null)
        {
            command.func = implAddr.getOffset();
            directTargetAddr = this.findDirectThunkTarget(program, implAddr);
        }

        command.wireOrder = this.formatLogicalWireLayout(program, trace, directTargetAddr);

        if (trace.lr != -1)
            command.lr = trace.lr;

        if (trace.bytesIn != -1)
            command.bytesIn = trace.bytesIn;

        if (trace.bytesOut != -1)
            command.bytesOut = trace.bytesOut;

        if (trace.hasBufferAttrs())
            command.bufferAttrs = Arrays.copyOf(trace.bufferAttrs, trace.bufferAttrs.length);
        else if (trace.bufferCount > 0)
            command.bufferCount = trace.bufferCount;

        if (trace.pid)
            command.pid = true;

        if (trace.inInterfaces > 0)
            command.inInterfaces = this.unknownJsonStringArray(trace.inInterfaces);

        if (trace.outInterfaces > 0)
        {
            command.outInterfaces = this.inferOutInterfaces(interfaceName, trace,
                commandName, knownInterfaces, vtableInterfaceNames);
            // The returned object's SRV_<sTable> canary (independent of how the out-interface is named).
            command.srvOutInterface = this.resolveOutInterfaceSrvFromTarget(trace, 0, vtableSrvNames);
        }

        if (trace.inHandles > 0)
            command.inHandles = this.inferHandleAttrs(trace.inHandles, 1);

        if (trace.outHandles > 0)
            command.outHandles = this.inferHandleAttrs(trace.outHandles,
                "nn::sf::hipc::detail::IHipcManager".equals(interfaceName) ? 2 : 1);
    }

    private Address tryReadIpcCommandFunction(Program program, Address vtableAddr, long vtOffset)
    {
        try
        {
            AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
            Memory mem = program.getMemory();
            Address slotAddr = vtableAddr.add(0x10 + vtOffset);
            MemoryBlock slotBlock = mem.getBlock(slotAddr);

            if (slotBlock == null || !slotBlock.isInitialized())
                return null;

            long rawTarget = mem.getLong(slotAddr);

            if (rawTarget == 0)
                return null;

            Address targetAddr = aSpace.getAddress(rawTarget);
            MemoryBlock targetBlock = mem.getBlock(targetAddr);

            if (!this.isExecutableCodeBlock(program, targetBlock))
                return null;

            return targetAddr;
        }
        catch (AddressOutOfBoundsException | MemoryAccessException e)
        {
            return null;
        }
    }

    private List<IpcJsonInterfaceExport> sortIpcJsonInterfaces(Collection<IpcJsonInterfaceExport> interfaces)
    {
        // Emit in DISCOVERY order: ascending by the discovered object's address (proc_func), which
        // matches the server s_Table layout (and the swipc .info ordering). This interleaves hash-named
        // and SRV_ interfaces in their true on-device sequence, so the export can be lined up 1:1 with a
        // per-program-ordered database to disambiguate byte-identical interfaces by position. Entries
        // with no address (e.g. client-import groups) sort last.
        List<IpcJsonInterfaceExport> out = new ArrayList<>(interfaces);
        out.sort(Comparator
            .comparingLong((IpcJsonInterfaceExport item) -> item.address == 0 ? Long.MAX_VALUE : item.address)
            .thenComparingInt(item -> item.discoveryOrder)
            .thenComparing(item -> item.interfaceName));
        return out;
    }

    private String inferIpcJsonServiceName(Program program, Collection<String> interfaceNames)
    {
        for (String interfaceName : interfaceNames)
        {
            if (interfaceName.startsWith("nn::fssrv::sf::"))
                return "fs";
        }

        String name = program.getName();

        if (name == null || name.isBlank())
            name = program.getExecutablePath();

        if (name == null || name.isBlank())
            return "unknown";

        String normalized = new File(name).getName().toLowerCase(Locale.ROOT);
        int dot = normalized.indexOf('.');

        if (dot > 0)
            normalized = normalized.substring(0, dot);

        normalized = normalized.replaceAll("[^a-z0-9_\\-]+", "_");
        return normalized.isBlank() ? "unknown" : normalized;
    }

    /** The interface name for a discovered server object: the (hash-matched) vtable name, with an
     *  ObjectImplFactory/templated mangle recovered to its real interface, else {@code SRV_<procFunc>}.
     *  Shared by the JSON export and the Ghidra markup so both classify/anchor identically. */
    private String resolveDiscoveredInterfaceName(String abvName, long procFuncOff)
    {
        String name = stripVtableSuffix(abvName);
        if (looksLikeUnresolvedMangle(name))
        {
            String recovered = extractInterfaceFromObjectImplFactory(name);
            name = recovered != null ? recovered
                : "SRV_" + Long.toHexString(procFuncOff).toUpperCase();
        }
        return name;
    }

    /** A discovered server interface, viewed for positional inference. Implemented by both the JSON
     *  export model (IpcJsonInterfaceExport) and the Ghidra-markup model, so ONE algorithm drives both. */
    private interface IpcInferenceNode
    {
        long inferProcOff();                 // proc_func address (discovery-order key, unique per object)
        String inferName();                  // hash-matched interface name, or SRV_<...> if unmatched
        Set<Long> inferCommandIds();         // recovered command ids
        void setInferred(String name, String basis);
    }

    /** Lightweight inference node for the Ghidra-markup path (the export uses IpcJsonInterfaceExport). */
    private static class MarkupInferenceNode implements IpcInferenceNode
    {
        private final long procOff;
        private final String name;
        private final Set<Long> commandIds;
        private String inferredName;
        private String inferredBasis;

        private MarkupInferenceNode(long procOff, String name, Set<Long> commandIds)
        {
            this.procOff = procOff;
            this.name = name;
            this.commandIds = commandIds;
        }

        @Override public long inferProcOff() { return this.procOff; }
        @Override public String inferName() { return this.name; }
        @Override public Set<Long> inferCommandIds() { return this.commandIds; }
        @Override public void setInferred(String name, String basis)
        {
            this.inferredName = name;
            this.inferredBasis = basis;
        }
    }

    /** Run the shared program-id + positional inference over the discovered server objects and return
     *  proc_func-offset -> inferred name (only for the SRV_ interfaces that anchored). Lets the Ghidra
     *  markup name un-hash-matched interfaces by position, identically to the JSON export. */
    private Map<Long, MarkupInferenceNode> computeMarkupInference(List<IPCVTableEntry> vtEntries,
            HashBiMap<Address, IPCVTableEntry> procFuncVtMap, Multimap<Address, IPCTrace> processFuncTraces)
    {
        List<MarkupInferenceNode> nodes = new ArrayList<>();
        for (IPCVTableEntry entry : vtEntries)
        {
            Address pf = procFuncVtMap.inverse().get(entry);
            if (pf == null || !processFuncTraces.containsKey(pf))
                continue;

            Set<Long> cmds = processFuncTraces.get(pf).stream()
                .filter(t -> t.vtOffset != -1 && t.hasDescription())
                .map(t -> t.cmdId)
                .collect(Collectors.toCollection(LinkedHashSet::new));
            if (cmds.isEmpty())
                continue;

            nodes.add(new MarkupInferenceNode(pf.getOffset(),
                this.resolveDiscoveredInterfaceName(entry.abvName, pf.getOffset()), cmds));
        }

        nodes.sort(Comparator.comparingLong(MarkupInferenceNode::inferProcOff));   // discovery order
        this.inferLikelyNames(this.inferProgram(nodes), nodes);

        Map<Long, MarkupInferenceNode> byProc = new HashMap<>();
        for (MarkupInferenceNode node : nodes)
            if (node.inferredName != null)
                byProc.put(node.procOff, node);
        return byProc;
    }

    /**
     * Identify which database "program" (wiki-page key) this binary most probably is, from its
     * hash-matched server interfaces. Returns the program (for {@code program_identified}) or null.
     *
     * <p>Proof rule (conservative): only interfaces that are (a) known in the database, (b) NOT in a
     * hash collision, and (c) listed under exactly one program may vote. The plurality program wins;
     * a tie proves nothing.
     */
    private String inferProgram(Collection<? extends IpcInferenceNode> interfaces)
    {
        IPCDatabase database = IPCDatabase.getInstance();
        IPCHashDatabase hashes = IPCHashDatabase.getInstance();
        Map<String, Map<String, String>> known = database.getAllInterfaces();

        Map<String, Integer> programVotes = new HashMap<>();

        for (IpcInferenceNode iface : interfaces)
        {
            if (iface.inferCommandIds().isEmpty() || !known.containsKey(iface.inferName()))
                continue;

            if (hashes.isCollisionInterface(iface.inferName()))
                continue;                                    // ambiguous hash -> not valid proof

            String program = database.getSingleProgramForInterface(iface.inferName());
            if (program != null)                             // single-program -> clean proof
                programVotes.merge(program, 1, Integer::sum);
        }

        if (programVotes.isEmpty())
            return null;

        String program = null;
        int best = -1;
        boolean tie = false;
        for (Map.Entry<String, Integer> vote : programVotes.entrySet())
        {
            if (vote.getValue() > best)
            {
                best = vote.getValue();
                program = vote.getKey();
                tie = false;
            }
            else if (vote.getValue() == best)
            {
                tie = true;
            }
        }
        if (tie)
            return null;                                     // ambiguous program -> prove nothing

        return program;
    }

    /**
     * Once the program is identified, name the un-hash-matched (SRV_) interfaces by POSITION. The
     * discovered interfaces are in discovery order (== the s_Table layout == the per-program database
     * order the user maintains), so the hash-matched interfaces act as anchors: a SRV_ gap between two
     * anchors must be the database interface(s) sitting between those anchors.
     *
     * <p>Strictly conservative -- it only fills a gap when (a) the anchors are monotonic in DB order
     * (discovery and DB orders agree) and (b) the number of SRV_ interfaces in the gap exactly equals
     * the number of DB interfaces between the anchors. Otherwise the SRV_ name is left untouched (the
     * canary survives). Result delivered via {@code setInferred(name, basis)}.
     */
    private void inferLikelyNames(String program, List<? extends IpcInferenceNode> sortedInterfaces)
    {
        if (program == null || sortedInterfaces.isEmpty())
            return;

        List<String> dbList = IPCDatabase.getInstance().getInterfacesForProgram(program);
        if (dbList.isEmpty())
            return;

        Map<String, Integer> dbIndex = new HashMap<>();
        for (int i = 0; i < dbList.size(); i++)
            dbIndex.putIfAbsent(dbList.get(i), i);

        // Alignment-relevant subsequence in discovery order: anchors (discovered name present in this
        // program's DB list) and unknowns (SRV_). Everything else (framework / cross-program out-
        // interfaces not part of P's sequence) is skipped.
        List<IpcInferenceNode> seq = new ArrayList<>();
        List<Integer> anchorIdx = new ArrayList<>();         // DB index for anchors, -1 for unknowns
        for (IpcInferenceNode iface : sortedInterfaces)
        {
            if (iface.inferCommandIds().isEmpty())
                continue;

            Integer idx = dbIndex.get(iface.inferName());
            boolean isSrv = iface.inferName().startsWith("SRV_");

            if (idx != null)
            {
                seq.add(iface);
                anchorIdx.add(idx);
            }
            else if (isSrv)
            {
                seq.add(iface);
                anchorIdx.add(-1);
            }
        }

        // Anchors must strictly increase in DB index along discovery order, else the two orders
        // disagree and positional inference is unsafe -> emit nothing.
        int prev = -1;
        for (int v : anchorIdx)
        {
            if (v < 0)
                continue;
            if (v <= prev)
                return;
            prev = v;
        }

        int n = dbList.size();
        int i = 0;
        while (i < seq.size())
        {
            if (anchorIdx.get(i) >= 0)
            {
                i++;
                continue;
            }

            int j = i;                                       // run of unknowns [i, j)
            while (j < seq.size() && anchorIdx.get(j) < 0)
                j++;

            int before = -1;
            for (int k = i - 1; k >= 0; k--)
                if (anchorIdx.get(k) >= 0) { before = anchorIdx.get(k); break; }

            int after = n;
            for (int k = j; k < seq.size(); k++)
                if (anchorIdx.get(k) >= 0) { after = anchorIdx.get(k); break; }

            int slots = after - before - 1;                  // DB interfaces strictly between anchors
            int unknowns = j - i;

            if (slots == unknowns && slots >= 1)
            {
                for (int u = 0; u < unknowns; u++)
                {
                    int dbpos = before + 1 + u;
                    seq.get(i + u).setInferred(dbList.get(dbpos),
                        String.format("DB position %d/%d in %s, anchored", dbpos + 1, n, program));
                }
            }
            // counts disagree -> ambiguous, leave the SRV_ canary untouched

            i = j;
        }
    }

    /**
     * Promote a positionally-inferred name to the emitted KEY and resolve its command names through it.
     * The original SRV_ stays available as {@code _srv}, and {@code _likely_basis} marks the name as
     * inferred (vs hash-proven). Duplicate resolved names are disambiguated with {@code @0x<addr>}, and
     * commands the database doesn't know stay unnamed so they still emit NOT_IN_DATABASE.
     */
    private void applyIpcJsonLikelyResolution(List<IpcJsonInterfaceExport> sortedInterfaces)
    {
        IPCDatabase database = IPCDatabase.getInstance();

        Set<String> usedKeys = new HashSet<>();
        for (IpcJsonInterfaceExport iface : sortedInterfaces)
            if (iface.likelyName == null)
                usedKeys.add(iface.jsonKey != null ? iface.jsonKey : iface.interfaceName);

        for (IpcJsonInterfaceExport iface : sortedInterfaces)
        {
            if (iface.likelyName == null)
                continue;

            String key = iface.likelyName;
            if (!usedKeys.add(key))
            {
                key = iface.likelyName + "@0x" + Long.toHexString(iface.address);
                usedKeys.add(key);
            }
            iface.jsonKey = key;

            for (IpcJsonCommandExport command : iface.commands.values())
            {
                if (command.name == null)
                    command.name = database.getCommandName(iface.likelyName, command.commandId);

                // The build pass resolved out-interfaces against the SRV_ name and fell back to a
                // hash-collision/heuristic guess; re-resolve through the now-known interface name. Only
                // override when the command actually returns an interface and the DB has a curated one.
                if (command.outInterfaces != null && !command.outInterfaces.isEmpty())
                {
                    String dbOut = database.getOutInterface(iface.likelyName, command.commandId);
                    if (dbOut != null)
                        command.outInterfaces.set(0, dbOut);
                }
            }
        }
    }

    /**
     * Final out-interface pass: an out-interface that points at one of THIS program's own discovered
     * objects but couldn't be named from its captured address (left as {@code Unresolved>0x..} or a bare
     * {@code SRV_..}) is upgraded to that object's real, final key. Matched via the per-command
     * {@code _srv_outinterfaces} canary against each interface's {@code _srv} -- so it also picks up the
     * positionally-INFERRED name applied after the build. Names already resolved (DB/hash) are left alone.
     */
    private void resolveOutInterfacesFromDiscovered(List<IpcJsonInterfaceExport> sortedInterfaces)
    {
        Map<String, String> srvToKey = new HashMap<>();
        for (IpcJsonInterfaceExport iface : sortedInterfaces)
            if (iface.srvName != null)
                srvToKey.putIfAbsent(iface.srvName,
                    iface.jsonKey != null ? iface.jsonKey : iface.interfaceName);

        for (IpcJsonInterfaceExport iface : sortedInterfaces)
            for (IpcJsonCommandExport command : iface.commands.values())
            {
                if (command.outInterfaces == null || command.outInterfaces.isEmpty()
                    || command.srvOutInterface == null)
                    continue;

                String cur = command.outInterfaces.get(0);
                if (cur != null && !cur.startsWith("Unresolved>") && !cur.startsWith("SRV_"))
                    continue;   // already a real name (DB/hash) -- keep it

                String finalKey = srvToKey.get(command.srvOutInterface);
                if (finalKey != null)
                    command.outInterfaces.set(0, finalKey);
            }
    }

    private void appendIpcJsonCommand(StringBuilder out, IpcJsonCommandExport command)
    {
        boolean[] wroteField = new boolean[] { false };

        out.append("{");

        if (command.vtOffset != null)
            this.appendJsonStringProperty(out, wroteField, "vt", this.formatHex(command.vtOffset),
                this.formatHex(command.vtOffset).length() < 5 ? 2 : 1);

        if (command.func != null)
            this.appendJsonStringProperty(out, wroteField, "func", this.formatHex(command.func));

        if (command.lr != null)
            this.appendJsonStringProperty(out, wroteField, "lr", this.formatHex(command.lr));

        if (command.bytesIn != null)
            this.appendJsonHexStringProperty(out, wroteField, "inbytes", command.bytesIn, 5);

        if (command.bytesOut != null)
            this.appendJsonHexStringProperty(out, wroteField, "outbytes", command.bytesOut, 5);

        if (command.bufferAttrs != null && command.bufferAttrs.length > 0)
        {
            this.appendJsonIntArrayProperty(out, wroteField, "buffers", command.bufferAttrs);

            List<Long> bufferEntrySizes = this.inferBufferEntrySizes(command);

            if (!bufferEntrySizes.isEmpty())
                this.appendJsonHexArrayProperty(out, wroteField, "buffer_entry_sizes", bufferEntrySizes);
        }
        else if (command.bufferCount != null && command.bufferCount > 0)
        {
            this.appendJsonNumberProperty(out, wroteField, "buffer_count", command.bufferCount);
        }

        if (command.pid)
            this.appendJsonBooleanProperty(out, wroteField, "pid", true);

        if (command.inInterfaces != null && !command.inInterfaces.isEmpty())
            this.appendJsonNullableStringArrayProperty(out, wroteField, "ininterfaces", command.inInterfaces);

        if (command.outInterfaces != null && !command.outInterfaces.isEmpty())
            this.appendJsonNullableStringArrayProperty(out, wroteField, "outinterfaces", command.outInterfaces);

        if (command.srvOutInterface != null)
            this.appendJsonStringProperty(out, wroteField, "_srv_outinterfaces", command.srvOutInterface);

        if (command.inHandles != null && command.inHandles.length > 0)
            this.appendJsonIntArrayProperty(out, wroteField, "inhandles", command.inHandles);

        if (command.outHandles != null && command.outHandles.length > 0)
            this.appendJsonIntArrayProperty(out, wroteField, "outhandles", command.outHandles);

        // A surfaced command the IPC database has no name for gets a loud, greppable marker
        // rather than a silently-missing field, so gaps in the database are obvious in the file.
        this.appendJsonStringProperty(out, wroteField, "name",
            command.name != null ? command.name : "NOT_IN_DATABASE");

        if (command.wireOrder != null)
            this.appendJsonStringProperty(out, wroteField, "wire_order", command.wireOrder);

        out.append("}");
    }

    private void appendJsonPropertyPrefix(StringBuilder out, boolean[] wroteField, String key)
    {
        if (wroteField[0])
            out.append(", ");

        out.append("\"").append(this.escapeJson(key)).append("\": ");
        wroteField[0] = true;
    }

    private void appendJsonStringProperty(StringBuilder out, boolean[] wroteField, String key, String value)
    {
        this.appendJsonStringProperty(out, wroteField, key, value, 1);
    }

    private void appendJsonStringProperty(StringBuilder out, boolean[] wroteField, String key, String value,
                                          int spacesAfterColon)
    {
        this.appendJsonPropertyPrefix(out, wroteField, key);
        if (spacesAfterColon > 1)
            out.append(" ".repeat(spacesAfterColon - 1));

        out.append("\"").append(this.escapeJson(value)).append("\"");
    }

    private void appendJsonNumberProperty(StringBuilder out, boolean[] wroteField, String key, long value)
    {
        this.appendJsonNumberProperty(out, wroteField, key, value, 0);
    }

    private void appendJsonNumberProperty(StringBuilder out, boolean[] wroteField, String key, long value,
                                          int minWidth)
    {
        this.appendJsonPropertyPrefix(out, wroteField, key);
        String formattedValue = String.valueOf(value);

        if (minWidth > formattedValue.length())
            out.append(" ".repeat(minWidth - formattedValue.length()));

        out.append(formattedValue);
    }

    private void appendJsonHexStringProperty(StringBuilder out, boolean[] wroteField, String key, long value,
                                             int minWidth)
    {
        this.appendJsonPropertyPrefix(out, wroteField, key);
        String formattedValue = this.formatHex(value);

        if (minWidth > formattedValue.length())
            out.append(" ".repeat(minWidth - formattedValue.length()));

        out.append("\"").append(formattedValue).append("\"");
    }

    private void appendJsonBooleanProperty(StringBuilder out, boolean[] wroteField, String key, boolean value)
    {
        this.appendJsonPropertyPrefix(out, wroteField, key);
        out.append(value ? "true" : "false");
    }

    private void appendJsonIntArrayProperty(StringBuilder out, boolean[] wroteField, String key, int[] values)
    {
        this.appendJsonPropertyPrefix(out, wroteField, key);
        out.append("[");

        for (int i = 0; i < values.length; i++)
        {
            if (i > 0)
                out.append(", ");

            out.append(values[i]);
        }

        out.append("]");
    }

    private void appendJsonHexArrayProperty(StringBuilder out, boolean[] wroteField, String key,
                                            List<Long> values)
    {
        this.appendJsonPropertyPrefix(out, wroteField, key);
        out.append("[");

        for (int i = 0; i < values.size(); i++)
        {
            if (i > 0)
                out.append(", ");

            out.append("\"").append(this.formatHex(values.get(i))).append("\"");
        }

        out.append("]");
    }

    private void appendJsonNullableStringArrayProperty(StringBuilder out, boolean[] wroteField, String key,
                                                       List<String> values)
    {
        this.appendJsonPropertyPrefix(out, wroteField, key);
        out.append("[");

        for (int i = 0; i < values.size(); i++)
        {
            if (i > 0)
                out.append(", ");

            String value = values.get(i);

            if (value == null)
                out.append("null");
            else
                out.append("\"").append(this.escapeJson(value)).append("\"");
        }

        out.append("]");
    }

    private List<String> unknownJsonStringArray(long count)
    {
        int safeCount = this.safeJsonArrayCount(count);
        List<String> out = new ArrayList<>(safeCount);

        for (int i = 0; i < safeCount; i++)
            out.add(null);

        return out;
    }

    private int[] inferHandleAttrs(long count, int attr)
    {
        int safeCount = this.safeJsonArrayCount(count);
        int[] out = new int[safeCount];

        Arrays.fill(out, attr);
        return out;
    }

    private int safeJsonArrayCount(long count)
    {
        if (count <= 0)
            return 0;

        return (int)Math.min(count, 64);
    }

    private List<String> inferOutInterfaces(String interfaceName, IPCTrace trace, String commandName,
                                            Set<String> knownInterfaces, Map<Long, String> vtableInterfaceNames)
    {
        int safeCount = this.safeJsonArrayCount(trace.outInterfaces);
        List<String> out = new ArrayList<>(safeCount);
        String inferred = this.inferSingleOutInterface(interfaceName, trace.cmdId, commandName, knownInterfaces);

        for (int i = 0; i < safeCount; i++)
        {
            String name = i == 0 ? inferred : null;

            // The command-name heuristic could not name this out-interface.  Fall back to the vtable
            // the emulator actually saw it return: name it if that vtable is a known/hash-matched
            // interface, otherwise surface the raw address as "Unresolved>0x<addr>" (never a bare null).
            if (name == null)
                name = this.resolveOutInterfaceFromTarget(trace, i, vtableInterfaceNames);

            out.add(name);
        }

        return out;
    }

    private String resolveOutInterfaceFromTarget(IPCTrace trace, int index,
                                                 Map<Long, String> vtableInterfaceNames)
    {
        if (!trace.hasOutInterfaceTarget(index))
            return null;

        long target = trace.outInterfaceTargets[index];
        String named = vtableInterfaceNames.get(target);

        return named != null ? named : String.format("Unresolved>0x%X", target);
    }

    /** The SRV_<sTable> canary of the object a command returns (its address-stable identity), kept as
     *  _srv_outinterfaces alongside the resolved name. Falls back to SRV_<vtable> if the returned vtable
     *  is not one of this program's discovered objects. */
    private String resolveOutInterfaceSrvFromTarget(IPCTrace trace, int index,
                                                    Map<Long, String> vtableSrvNames)
    {
        if (!trace.hasOutInterfaceTarget(index))
            return null;

        long target = trace.outInterfaceTargets[index];
        String srv = vtableSrvNames.get(target);

        return srv != null ? srv : String.format("SRV_%X", target);
    }

    private String inferSingleOutInterface(String interfaceName, long commandId, String commandName,
                                           Set<String> knownInterfaces)
    {
        // The curated database out-interface is AUTHORITATIVE: it resolves the hash collisions that
        // make a returned sub-interface vtable name as an unrelated interface, and it avoids spurious
        // command-name-substring matches (e.g. "DebugActivateOpenContextRetention" matching the
        // substring "Context" -> erpt::IContext, when the real out is account::ISessionObject).
        String dbOut = IPCDatabase.getInstance().getOutInterface(interfaceName, commandId);
        if (dbOut != null)
            return dbOut;

        String override = this.inferOutInterfaceOverride(interfaceName, commandId, commandName, knownInterfaces);

        if (override != null)
            return override;

        if (commandName == null || commandName.isBlank())
            return null;

        String normalizedCommandName = this.normalizeInterfaceMatchToken(commandName);
        String bestMatch = null;
        int bestLength = -1;

        for (String knownInterface : knownInterfaces)
        {
            String simpleName = this.simpleIpcInterfaceName(knownInterface);

            if (simpleName.startsWith("I") && simpleName.length() > 1)
                simpleName = simpleName.substring(1);

            if (simpleName.length() < 4)
                continue;

            String normalizedSimpleName = this.normalizeInterfaceMatchToken(simpleName);

            if (!normalizedCommandName.contains(normalizedSimpleName))
                continue;

            if (normalizedSimpleName.length() > bestLength)
            {
                bestMatch = knownInterface;
                bestLength = normalizedSimpleName.length();
            }
        }

        return bestMatch;
    }

    private String inferOutInterfaceOverride(String interfaceName, long commandId, String commandName,
                                             Set<String> knownInterfaces)
    {
        if ("nn::fssrv::sf::IFileSystem".equals(interfaceName))
        {
            if (commandId == 8)
                return this.knownInterface(knownInterfaces, "nn::fssrv::sf::IFile");

            if (commandId == 9)
                return this.knownInterface(knownInterfaces, "nn::fssrv::sf::IDirectory");
        }

        if ("nn::fssrv::sf::ISaveDataTransferManagerWithDivision".equals(interfaceName))
        {
            if (commandId == 32 || commandId == 33 || commandId == 34)
                return this.knownInterface(knownInterfaces, "nn::fssrv::sf::ISaveDataDivisionExporter");

            if (commandId == 63 || commandId == 68)
                return this.knownInterface(knownInterfaces, "nn::fssrv::sf::ISaveDataDivisionImporter");
        }

        if ("nn::fssrv::sf::ISaveDataDivisionExporter".equals(interfaceName))
        {
            if (commandId == 16)
                return this.knownInterface(knownInterfaces, "nn::fssrv::sf::ISaveDataChunkIterator");

            if (commandId == 48)
                return this.knownInterface(knownInterfaces, "nn::fssrv::sf::ISaveDataChunkExporter");
        }

        if ("nn::fssrv::sf::ISaveDataDivisionImporter".equals(interfaceName) && commandId == 48)
            return this.knownInterface(knownInterfaces, "nn::fssrv::sf::ISaveDataChunkImporter");

        if ("nn::fssrv::sf::ISaveDataTransferManagerForSaveDataRepair".equals(interfaceName))
        {
            if (commandId == 80 || commandId == 100)
                return this.knownInterface(knownInterfaces, "nn::fssrv::sf::ISaveDataDivisionExporter");

            if (commandId == 90 || commandId == 91 || commandId == 110)
                return this.knownInterface(knownInterfaces, "nn::fssrv::sf::ISaveDataDivisionImporter");
        }

        if ("nn::fssrv::sf::IFileSystemProxy".equals(interfaceName) && commandId == 82)
            return this.knownInterface(knownInterfaces, "nn::fssrv::sf::ISaveDataTransferManagerWithDivision");

        if ("nn::fssrv::sf::IFileSystemProxy".equals(interfaceName) && commandId == 83)
            return this.knownInterface(knownInterfaces, "nn::fssrv::sf::ISaveDataTransferManagerForSaveDataRepair");

        return null;
    }

    private String knownInterface(Set<String> knownInterfaces, String interfaceName)
    {
        return knownInterfaces.contains(interfaceName) ? interfaceName : null;
    }

    private String simpleIpcInterfaceName(String interfaceName)
    {
        int index = interfaceName.lastIndexOf("::");
        return index >= 0 ? interfaceName.substring(index + 2) : interfaceName;
    }

    private String normalizeInterfaceMatchToken(String value)
    {
        return value == null
            ? ""
            : value.replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ROOT);
    }

    private List<Long> inferBufferEntrySizes(IpcJsonCommandExport command)
    {
        if (command.bufferAttrs == null || command.bufferAttrs.length == 0)
            return Collections.emptyList();

        boolean hasFixedSizeBuffer = false;

        for (int attr : command.bufferAttrs)
        {
            if ((attr & 0x10) != 0)
            {
                hasFixedSizeBuffer = true;
                break;
            }
        }

        if (!hasFixedSizeBuffer)
            return Collections.emptyList();

        List<Long> out = new ArrayList<>();

        for (int attr : command.bufferAttrs)
        {
            if ((attr & 0x10) == 0)
            {
                out.add(0L);
                continue;
            }

            Long size = this.inferFixedBufferEntrySize(command, attr);

            if (size == null)
                return Collections.emptyList();

            out.add(size);
        }

        return out;
    }

    private Long inferFixedBufferEntrySize(IpcJsonCommandExport command, int attr)
    {
        if (attr == 25)
        {
            if ("CreateSaveDataFileSystemWithCreationInfo2".equals(command.name) ||
                ("nn::fssrv::sf::ISaveDataTransferManagerWithDivision".equals(command.interfaceName)
                    && "OpenSaveDataImporter".equals(command.name)))
                return 0x200L;

            return 0x301L;
        }

        if (attr == 26)
        {
            if ("GetAndClearErrorInfo".equals(command.name))
                return 0x100L;

            if ("GetSaveDataInfo".equals(command.name))
                return 0x60L;
        }

        return null;
    }

    private static class IpcJsonInterfaceExport implements IpcInferenceNode
    {
        private final String interfaceName;
        private final int discoveryOrder;
        private final long address;        // the discovered object's address (proc_func), unique per object
        private String jsonKey;            // the (possibly disambiguated) key this interface is emitted under
        private String interfaceHash;
        private String interfaceHashAlt;
        private String likelyName;         // positionally-inferred DB interface (SRV_ only)
        private String likelyBasis;        // human-readable basis for likelyName
        private String srvName;            // the SRV_<sTable> canary name, kept on EVERY interface as _srv
        private final TreeMap<Long, IpcJsonCommandExport> commands = new TreeMap<>();

        private IpcJsonInterfaceExport(String interfaceName, int discoveryOrder, long address)
        {
            this.interfaceName = interfaceName;
            this.discoveryOrder = discoveryOrder;
            this.address = address;
        }

        private IpcJsonCommandExport getOrCreateCommand(long commandId)
        {
            IpcJsonCommandExport command = this.commands.get(commandId);

            if (command == null)
            {
                command = new IpcJsonCommandExport(this.interfaceName, commandId);
                this.commands.put(commandId, command);
            }

            return command;
        }

        @Override public long inferProcOff() { return this.address; }
        @Override public String inferName() { return this.interfaceName; }
        @Override public Set<Long> inferCommandIds() { return this.commands.keySet(); }
        @Override public void setInferred(String name, String basis)
        {
            this.likelyName = name;
            this.likelyBasis = basis;
        }
    }

    private static class IpcJsonCommandExport
    {
        private final String interfaceName;
        private final long commandId;
        private Long vtOffset;
        private Long func;
        private Long lr;
        private Long bytesIn;
        private Long bytesOut;
        private Long bufferCount;
        private int[] bufferAttrs;
        private boolean pid;
        private List<String> inInterfaces;
        private List<String> outInterfaces;
        private String srvOutInterface;    // SRV_<sTable> canary of the returned out-interface object
        private int[] inHandles;
        private int[] outHandles;
        private String name;
        private String wireOrder;

        private IpcJsonCommandExport(String interfaceName, long commandId)
        {
            this.interfaceName = interfaceName;
            this.commandId = commandId;
        }
    }

    private String formatHex(long value)
    {
        return String.format("0x%X", value);
    }

    private String escapeJson(String value)
    {
        if (value == null)
            return "";

        StringBuilder out = new StringBuilder();

        for (int i = 0; i < value.length(); i++)
        {
            char c = value.charAt(i);

            switch (c)
            {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default ->
                {
                    if (c < 0x20)
                        out.append(String.format("\\u%04X", (int)c));
                    else
                        out.append(c);
                }
            }
        }

        return out.toString();
    }

    private String formatLogicalWireLayout(Program program, IPCTrace trace, Address ipcCmdTargetAddr)
    {
        try
        {
            String layout = this.tryFormatLogicalWireLayout(program, trace, ipcCmdTargetAddr);

            if (layout != null && !layout.isBlank())
                return layout;
        }
        catch (Exception e)
        {
            Msg.warn(this, String.format("Failed to infer logical IPC wire layout for command 0x%X: %s",
                trace.cmdId, e.getMessage()));
        }

        return trace.formatWireLayout();
    }

    private String tryFormatLogicalWireLayout(Program program, IPCTrace trace, Address ipcCmdTargetAddr)
    {
        if (ipcCmdTargetAddr == null)
            return null;

        TreeMap<Integer, String> orderedParams = new TreeMap<>();
        int expectedBufferCount = trace.hasBufferAttrs() ? trace.bufferAttrs.length : (int)trace.bufferCount;
        List<Integer> bufferParamOrdinals = Collections.emptyList();

        if (expectedBufferCount > 0)
        {
            bufferParamOrdinals = this.findBranchTargetBufferParamOrdinals(program, ipcCmdTargetAddr,
                expectedBufferCount);

            if (bufferParamOrdinals.size() != expectedBufferCount)
                return null;

            if (trace.hasBufferAttrs())
                orderedParams.putAll(this.getBranchTargetBufferParamNames(bufferParamOrdinals, trace.bufferAttrs));
            else
            {
                for (int i = 0; i < bufferParamOrdinals.size(); i++)
                    orderedParams.put(bufferParamOrdinals.get(i), "buffer" + i);
            }
        }

        Map<Integer, String> inputParamNames = this.findBranchTargetInputParamNames(program, trace,
            ipcCmdTargetAddr, bufferParamOrdinals);

        orderedParams.putAll(inputParamNames);

        if (trace.bytesIn > 0 && inputParamNames.isEmpty())
            this.addUnknownInputDataParam(program, trace, ipcCmdTargetAddr, bufferParamOrdinals, orderedParams);

        StringJoiner joiner = new StringJoiner("; ");

        for (String paramName : orderedParams.values())
            joiner.add(paramName);

        if (trace.bytesOut > 0)
            joiner.add(String.format("out_data[0x%X]", trace.bytesOut));

        String layout = joiner.toString();
        return layout.isEmpty() ? null : layout;
    }

    private void addUnknownInputDataParam(Program program, IPCTrace trace, Address ipcCmdTargetAddr,
                                          List<Integer> bufferParamOrdinals, TreeMap<Integer, String> orderedParams)
    {
        int inputOrdinal = this.findSingleNonBufferInputOrdinal(program, ipcCmdTargetAddr,
            new HashSet<>(bufferParamOrdinals));
        String inputName = String.format("in_data[0x%X]", trace.bytesIn);

        if (inputOrdinal >= 0)
            orderedParams.put(inputOrdinal, inputName);
        else if (!orderedParams.containsValue(inputName))
            orderedParams.put(Integer.MAX_VALUE - 1, inputName);
    }

    private int findSingleNonBufferInputOrdinal(Program program, Address ipcCmdTargetAddr,
                                                 Set<Integer> bufferParamOrdinals)
    {
        int maxOrdinal = this.findMaxReferencedParamOrdinal(program, ipcCmdTargetAddr);
        int foundOrdinal = -1;

        for (int ordinal = 1; ordinal <= maxOrdinal && ordinal <= 7; ordinal++)
        {
            if (bufferParamOrdinals.contains(ordinal))
                continue;

            if (foundOrdinal != -1)
                return -1;

            foundOrdinal = ordinal;
        }

        return foundOrdinal;
    }

    private void renameBranchTargetParams(Program program, IPCTrace trace, Address ipcCmdTargetAddr)
    {
        if (!trace.hasBufferAttrs() && trace.bytesIn <= 0)
            return;

        Function function = program.getFunctionManager().getFunctionAt(ipcCmdTargetAddr);

        if (function == null)
            return;

        List<Integer> bufferParamOrdinals = Collections.emptyList();
        int expectedBufferCount = trace.hasBufferAttrs() ? trace.bufferAttrs.length : (int)trace.bufferCount;

        if (expectedBufferCount > 0)
        {
            bufferParamOrdinals = this.findBranchTargetBufferParamOrdinals(program, ipcCmdTargetAddr,
                expectedBufferCount);

            if (bufferParamOrdinals.size() != expectedBufferCount)
            {
                Msg.debug(this, String.format(
                    "Skipping IPC branch target parameter rename at 0x%X: expected %d buffer params, found %d",
                    ipcCmdTargetAddr.getOffset(), expectedBufferCount, bufferParamOrdinals.size()));
                return;
            }
        }

        Map<Integer, String> bufferParamNames = trace.hasBufferAttrs()
            ? this.getBranchTargetBufferParamNames(bufferParamOrdinals, trace.bufferAttrs)
            : Collections.emptyMap();
        Map<Integer, String> inputParamNames = this.findBranchTargetInputParamNames(program, trace,
            ipcCmdTargetAddr, bufferParamOrdinals);

        if (bufferParamNames.isEmpty() && inputParamNames.isEmpty())
            return;

        int maxOrdinal = Math.max(
            bufferParamNames.keySet().stream().mapToInt(Integer::intValue).max().orElse(-1),
            inputParamNames.keySet().stream().mapToInt(Integer::intValue).max().orElse(-1));

        if (function.getParameterCount() <= maxOrdinal)
        {
            if (!this.commitBranchTargetRegisterParams(program, function, bufferParamNames, inputParamNames))
            {
                Msg.debug(this, String.format(
                    "Skipping IPC branch target parameter rename at 0x%X: function has %d params, needs ordinal %d",
                    ipcCmdTargetAddr.getOffset(), function.getParameterCount(), maxOrdinal));
                return;
            }
        }

        this.renameBranchTargetParams(program, function, ipcCmdTargetAddr, bufferParamNames);
        this.renameBranchTargetParams(program, function, ipcCmdTargetAddr, inputParamNames);
    }

    private Map<Integer, String> getBranchTargetBufferParamNames(List<Integer> bufferParamOrdinals, int[] bufferAttrs)
    {
        Map<Integer, String> bufferParamNames = new HashMap<>();
        int inIndex = 0;
        int outIndex = 0;
        int inOutIndex = 0;

        for (int i = 0; i < bufferAttrs.length; i++)
        {
            int attr = bufferAttrs[i];
            String name;

            boolean isIn = (attr & IPCTrace.BUFFER_ATTR_IN) != 0;
            boolean isOut = (attr & IPCTrace.BUFFER_ATTR_OUT) != 0;

            if (isIn && isOut)
                name = "inout_buf" + inOutIndex++;
            else if (isOut)
                name = "out_buf" + outIndex++;
            else if (isIn)
                name = "in_buf" + inIndex++;
            else
                continue;

            bufferParamNames.put(bufferParamOrdinals.get(i), name);
        }

        return bufferParamNames;
    }

    private void renameBranchTargetParams(Program program, Function function, Address ipcCmdTargetAddr,
                                          Map<Integer, String> paramNames)
    {
        for (Map.Entry<Integer, String> entry : paramNames.entrySet())
        {
            Parameter parameter = function.getParameter(entry.getKey());

            if (parameter == null || parameter.getName().equals(entry.getValue()))
                continue;

            try
            {
                parameter.setName(entry.getValue(), SourceType.ANALYSIS);
            }
            catch (DuplicateNameException | InvalidInputException e)
            {
                Msg.warn(this, String.format("Failed to rename IPC branch target parameter '%s' at 0x%X: %s",
                    entry.getValue(), ipcCmdTargetAddr.getOffset(), e.getMessage()));
            }
        }
    }

    private Map<Integer, String> findBranchTargetInputParamNames(Program program, IPCTrace trace,
                                                                  Address ipcCmdTargetAddr,
                                                                  List<Integer> bufferParamOrdinals)
    {
        if (trace.bytesIn <= 0)
            return Collections.emptyMap();

        Map<Integer, Integer> inputParamWidths = this.findBranchTargetInputParamWidths(program, ipcCmdTargetAddr,
            new HashSet<>(bufferParamOrdinals));

        int inferredBytes = inputParamWidths.values().stream().mapToInt(Integer::intValue).sum();

        if (inferredBytes != trace.bytesIn)
        {
            Msg.debug(this, String.format(
                "Skipping IPC input parameter rename at 0x%X: inferred 0x%X input bytes, expected 0x%X",
                ipcCmdTargetAddr.getOffset(), inferredBytes, trace.bytesIn));
            return Collections.emptyMap();
        }

        Map<Integer, String> inputParamNames = new LinkedHashMap<>();
        Map<Integer, Integer> typeCounts = new HashMap<>();

        for (Map.Entry<Integer, Integer> entry : inputParamWidths.entrySet())
        {
            String typeName = this.getInputParamTypeName(entry.getValue());

            if (typeName == null)
                continue;

            int index = typeCounts.getOrDefault(entry.getValue(), 0);
            typeCounts.put(entry.getValue(), index + 1);
            inputParamNames.put(entry.getKey(), "in_" + typeName + "_" + index);
        }

        return inputParamNames;
    }

    private Map<Integer, Integer> findBranchTargetInputParamWidths(Program program, Address ipcCmdTargetAddr,
                                                                    Set<Integer> bufferParamOrdinals)
    {
        Map<Integer, Integer> inputParamWidths = new LinkedHashMap<>();
        Map<String, Integer> registerParamOrdinals = new HashMap<>();

        for (int i = 0; i < 8; i++)
            registerParamOrdinals.put("x" + i, i);

        Instruction instruction = program.getListing().getInstructionAt(ipcCmdTargetAddr);

        for (int i = 0; instruction != null && i < 120; i++)
        {
            this.trackRegisterAlias(instruction, registerParamOrdinals);
            this.trackInputParamRegisterWidths(instruction, registerParamOrdinals, bufferParamOrdinals,
                inputParamWidths);
            instruction = instruction.getNext();
        }

        return inputParamWidths;
    }

    private void trackInputParamRegisterWidths(Instruction instruction, Map<String, Integer> registerParamOrdinals,
                                                Set<Integer> bufferParamOrdinals,
                                                Map<Integer, Integer> inputParamWidths)
    {
        for (int operandIndex = 0; operandIndex < instruction.getNumOperands(); operandIndex++)
        {
            for (Object object : instruction.getOpObjects(operandIndex))
            {
                if (!(object instanceof Register register))
                    continue;

                String normalizedName = this.normalizeRegisterName(register.getName());
                Integer ordinal = normalizedName != null ? registerParamOrdinals.get(normalizedName) : null;

                if (ordinal == null || ordinal == 0 || bufferParamOrdinals.contains(ordinal))
                    continue;

                int width = this.getRegisterScalarWidth(register.getName());

                if (width <= 0)
                    continue;

                inputParamWidths.merge(ordinal, width, Math::max);
            }
        }
    }

    private String getInputParamTypeName(int width)
    {
        return switch (width)
        {
            case 1 -> "u8";
            case 2 -> "u16";
            case 4 -> "u32";
            case 8 -> "u64";
            default -> null;
        };
    }

    private int getRegisterScalarWidth(String registerName)
    {
        if (registerName == null)
            return -1;

        String name = registerName.toLowerCase(Locale.ROOT);

        if (name.startsWith("w"))
            return 4;
        if (name.startsWith("x"))
            return 8;

        return -1;
    }

    private boolean commitBranchTargetRegisterParams(Program program, Function function,
                                                     Map<Integer, String> bufferParamNames,
                                                     Map<Integer, String> inputParamNames)
    {
        int maxOrdinal = Math.max(
            Math.max(
                bufferParamNames.keySet().stream().mapToInt(Integer::intValue).max().orElse(-1),
                inputParamNames.keySet().stream().mapToInt(Integer::intValue).max().orElse(-1)),
            this.findMaxReferencedParamOrdinal(program, function.getEntryPoint()));

        if (maxOrdinal < 0)
            return false;

        List<Variable> parameters = new ArrayList<>();

        try
        {
            for (int ordinal = 0; ordinal <= maxOrdinal; ordinal++)
            {
                Parameter existing = ordinal < function.getParameterCount() ? function.getParameter(ordinal) : null;
                String name = bufferParamNames.get(ordinal);

                if (name == null)
                    name = inputParamNames.get(ordinal);

                if (name == null)
                    name = existing != null && !existing.getName().isBlank() ? existing.getName() : "param_" + (ordinal + 1);

                Register register = program.getRegister("x" + ordinal);

                if (register == null)
                    return false;

                parameters.add(new ParameterImpl(name, Undefined8DataType.dataType, register, program,
                    SourceType.ANALYSIS));
            }

            function.replaceParameters(parameters, Function.FunctionUpdateType.CUSTOM_STORAGE, true,
                SourceType.ANALYSIS);
            return true;
        }
        catch (DuplicateNameException | InvalidInputException e)
        {
            Msg.warn(this, String.format("Failed to commit IPC branch target parameters at 0x%X: %s",
                function.getEntryPoint().getOffset(), e.getMessage()));
            return false;
        }
    }

    private List<Integer> findBranchTargetBufferParamOrdinals(Program program, Address ipcCmdTargetAddr,
                                                               int expectedBufferCount)
    {
        LinkedHashSet<Integer> bufferParamOrdinals = new LinkedHashSet<>();
        Map<String, Integer> registerParamOrdinals = new HashMap<>();

        for (int i = 0; i < 8; i++)
            registerParamOrdinals.put("x" + i, i);

        Instruction instruction = program.getListing().getInstructionAt(ipcCmdTargetAddr);

        for (int i = 0; instruction != null && i < 120 && bufferParamOrdinals.size() < expectedBufferCount; i++)
        {
            this.trackRegisterAlias(instruction, registerParamOrdinals);

            String baseRegister = this.getMemoryBaseRegister(instruction);

            if (baseRegister != null)
            {
                Integer ordinal = registerParamOrdinals.get(baseRegister);

                if (ordinal != null && ordinal > 0)
                    bufferParamOrdinals.add(ordinal);
            }

            instruction = instruction.getNext();
        }

        return Lists.newArrayList(bufferParamOrdinals.iterator());
    }

    private int findMaxReferencedParamOrdinal(Program program, Address functionAddr)
    {
        int maxOrdinal = -1;
        Instruction instruction = program.getListing().getInstructionAt(functionAddr);

        for (int i = 0; instruction != null && i < 120; i++)
        {
            for (int operandIndex = 0; operandIndex < instruction.getNumOperands(); operandIndex++)
            {
                for (Object object : instruction.getOpObjects(operandIndex))
                {
                    if (object instanceof Register register)
                    {
                        String normalizedName = this.normalizeRegisterName(register.getName());
                        int ordinal = this.getParamRegisterOrdinal(normalizedName);

                        if (ordinal >= 0)
                            maxOrdinal = Math.max(maxOrdinal, ordinal);
                    }
                }
            }

            instruction = instruction.getNext();
        }

        return maxOrdinal;
    }

    private int getParamRegisterOrdinal(String normalizedName)
    {
        if (normalizedName == null || !normalizedName.startsWith("x"))
            return -1;

        try
        {
            int ordinal = Integer.parseInt(normalizedName.substring(1));
            return ordinal >= 0 && ordinal <= 7 ? ordinal : -1;
        }
        catch (NumberFormatException e)
        {
            return -1;
        }
    }

    private void trackRegisterAlias(Instruction instruction, Map<String, Integer> registerParamOrdinals)
    {
        String mnemonic = instruction.getMnemonicString();

        if (!"mov".equals(mnemonic))
            return;

        Register destRegister = this.getOperandRegister(instruction, 0);

        if (destRegister == null)
            return;

        String destName = this.normalizeRegisterName(destRegister.getName());

        if (destName == null)
            return;

        Register sourceRegister = this.getOperandRegister(instruction, 1);

        if (sourceRegister == null)
        {
            registerParamOrdinals.remove(destName);
            return;
        }

        String sourceName = this.normalizeRegisterName(sourceRegister.getName());
        Integer sourceOrdinal = sourceName != null ? registerParamOrdinals.get(sourceName) : null;

        if (sourceOrdinal != null)
            registerParamOrdinals.put(destName, sourceOrdinal);
        else
            registerParamOrdinals.remove(destName);
    }

    private Register getOperandRegister(Instruction instruction, int operandIndex)
    {
        if (operandIndex >= instruction.getNumOperands())
            return null;

        for (Object object : instruction.getOpObjects(operandIndex))
        {
            if (object instanceof Register register)
                return register;
        }

        return null;
    }

    private String getMemoryBaseRegister(Instruction instruction)
    {
        for (int i = 0; i < instruction.getNumOperands(); i++)
        {
            String operand = instruction.getDefaultOperandRepresentation(i);

            if (operand == null || operand.indexOf('[') == -1)
                continue;

            Matcher matcher = AARCH64_MEMORY_BASE_PATTERN.matcher(operand);

            if (matcher.find())
                return this.normalizeRegisterName(matcher.group(1));
        }

        return null;
    }

    private String normalizeRegisterName(String registerName)
    {
        if (registerName == null)
            return null;

        registerName = registerName.toLowerCase(Locale.ROOT);

        if (registerName.startsWith("w"))
            return "x" + registerName.substring(1);

        if (registerName.startsWith("x"))
            return registerName;

        return null;
    }

    private Address findDirectThunkTarget(Program program, Address thunkAddr)
    {
        Instruction instruction = program.getListing().getInstructionAt(thunkAddr);

        for (int i = 0; instruction != null && i < 8; i++)
        {
            FlowType flowType = instruction.getFlowType();
            Address[] flows = instruction.getFlows();

            if (flowType.isComputed() || flowType.isConditional())
                return null;

            if (flows.length == 1 && (flowType.isJump() || flowType.isCall()) && flowType.isTerminal())
            {
                Address target = flows[0];

                if (target.equals(thunkAddr) || target.equals(instruction.getAddress()))
                    return null;

                return target;
            }

            if (flowType.isTerminal())
                return null;

            instruction = instruction.getNext();
        }

        return null;
    }

    protected int getProcFuncVTableSize(Multimap<Address, IPCTrace> processFuncTraces, Address procFuncAddr)
    {
        if (!processFuncTraces.containsKey(procFuncAddr) || processFuncTraces.get(procFuncAddr).isEmpty())
            return 0;
        
        IPCTrace maxTrace = null;
        
        for (IPCTrace trace : processFuncTraces.get(procFuncAddr))
        {
            if (trace.vtOffset == -1)
                continue;
            
            if (maxTrace == null || trace.vtOffset > maxTrace.vtOffset)
                maxTrace = trace;
        }
        
        if (maxTrace == null)
            return processFuncTraces.get(procFuncAddr).size();
        
        return (int)Math.max(processFuncTraces.get(procFuncAddr).size(), (maxTrace.vtOffset + 8 - 0x20) / 8);
    }
    
    private Program gotDataSymsProgram = null;
    private Map<Address, Address> gotDataSyms = null;
    
    /**
     * A map of relocated entries in the global offset table to their new values.
     */
    protected Map<Address, Address> getGotDataSyms(Program program, ElfCompatibilityProvider elfProvider) throws MemoryAccessException {
        if (gotDataSyms != null && gotDataSymsProgram == program)
            return this.gotDataSyms;
        
        Address baseAddr = program.getImageBase();
        gotDataSyms = new HashMap<>();
        gotDataSymsProgram = program;
        List<MemoryBlock> gotBlocks = this.getGotCandidateBlocks(program);

        if (gotBlocks.isEmpty())
        {
            Msg.warn(this, "Failed to locate GOT candidate blocks - no .got* or .data* blocks found.");
            return gotDataSyms;
        }
        
        for (NXRelocation reloc : elfProvider.getRelocations()) 
        {
            Address relocAddr = baseAddr.add(reloc.offset);

            if (!this.isAddressInAnyBlock(relocAddr, gotBlocks))
            {
                continue;
            }

            long off;

            if (reloc.r_type == R_FAKE_RELR) {
                reloc.addend = program.getMemory().getLong(baseAddr.add(reloc.offset)) - baseAddr.getOffset();
            }
            
            if (reloc.sym != null && reloc.sym.getSectionHeaderIndex() != ElfSectionHeaderConstants.SHN_UNDEF && reloc.sym.getValue() == 0)
            {
                off = reloc.sym.getValue();
            }
            else if (reloc.addend != 0)
            {
                off = reloc.addend;
            }
            else continue;
            
            // Target -> Value
           this.gotDataSyms.put(relocAddr, baseAddr.add(off));
        }
        
        return gotDataSyms;
    }

    private List<MemoryBlock> getGotCandidateBlocks(Program program)
    {
        List<MemoryBlock> gotBlocks = new ArrayList<>();
        List<MemoryBlock> dataBlocks = new ArrayList<>();
        boolean hasCanonicalGotBlock = false;
        boolean hasGotPltBlock = false;

        for (MemoryBlock block : program.getMemory().getBlocks())
        {
            String name = block.getName();

            if (name.equals(".got") || name.startsWith(".got."))
            {
                gotBlocks.add(block);
                hasCanonicalGotBlock |= name.equals(".got");
                hasGotPltBlock |= name.equals(".got.plt");
            }
            else if (name.equals(".data") || name.startsWith(".data."))
                dataBlocks.add(block);
        }

        if (hasCanonicalGotBlock)
            return gotBlocks;

        if (hasGotPltBlock)
        {
            Msg.info(this, "SDK-like layout detected: no canonical .got block, but .got.plt exists; using .got* and relocated .data blocks as GOT candidates.");
            gotBlocks.addAll(dataBlocks);
            return gotBlocks;
        }

        Msg.warn(this, "Failed to locate GOT candidate blocks - no canonical .got or SDK-like .got.plt layout found.");
        return Collections.emptyList();
    }

    private boolean isSdkLikeLayout(Program program)
    {
        boolean hasCanonicalGotBlock = false;
        boolean hasGotPltBlock = false;

        for (MemoryBlock block : program.getMemory().getBlocks())
        {
            String name = block.getName();
            hasCanonicalGotBlock |= name.equals(".got");
            hasGotPltBlock |= name.equals(".got.plt");
        }

        return !hasCanonicalGotBlock && hasGotPltBlock;
    }

    private boolean isRttiDataBlock(Program program, MemoryBlock block)
    {
        if (block == null)
            return false;

        String name = block.getName();

        if (name.equals(".data"))
            return true;

        return this.isSdkLikeLayout(program) && name.startsWith(".data.");
    }

    private boolean isExecutableCodeBlock(Program program, MemoryBlock block)
    {
        if (block == null)
            return false;

        String name = block.getName();

        if (name.equals(".text"))
            return true;

        return this.isSdkLikeLayout(program) && name.equals(".plt");
    }

    private boolean isFssrvInterfaceName(String interfaceName)
    {
        return interfaceName != null && interfaceName.startsWith(FSSRV_INTERFACE_PREFIX);
    }

    private boolean isFssrvInterfaceVtableName(String name)
    {
        return this.isFssrvInterfaceName(stripVtableSuffix(name));
    }

    private boolean isSdkFssrvImportCandidate(Program program, String interfaceName)
    {
        return this.isSdkLikeLayout(program) && this.isFssrvInterfaceName(interfaceName);
    }

    private boolean shouldPreferAssociatedRttiName(Program program, String currentName, String rttiResolvedName)
    {
        if (rttiResolvedName == null || rttiResolvedName.isBlank())
            return false;

        if (currentName == null || currentName.startsWith("SRV_"))
            return true;

        if (!this.isSdkLikeLayout(program) || !this.isFssrvInterfaceVtableName(rttiResolvedName))
            return false;

        return isClientProxyVtableGroupName(currentName)
            || currentName.startsWith("_ZTV")
            || currentName.startsWith("ZTV");
    }

    private String formatAssociatedRttiName(Program program, String currentName, String rttiResolvedName)
    {
        if (currentName == null || currentName.startsWith("SRV_"))
            return rttiResolvedName;

        if (!this.isSdkLikeLayout(program) || !this.isFssrvInterfaceVtableName(rttiResolvedName))
            return rttiResolvedName;

        if (!isClientProxyVtableGroupName(currentName)
            && !currentName.startsWith("_ZTV")
            && !currentName.startsWith("ZTV"))
            return rttiResolvedName;

        return stripVtableSuffix(rttiResolvedName) + "::client_proxy::vtable";
    }

    private boolean isAddressInAnyBlock(Address address, List<MemoryBlock> blocks)
    {
        long offset = address.getOffset();

        for (MemoryBlock block : blocks)
        {
            if (offset >= block.getStart().getOffset() && offset <= block.getEnd().getOffset())
                return true;
        }

        return false;
    }
    
public static String demangleIpcSymbol(String mangled)
{
    // Needed by the demangler
    if (!mangled.startsWith("_Z"))
        mangled = "_Z" + mangled;
 
    String out = mangled;
    
    try {
        // DemanglerUtil.demangle(Program, String, Address) is the non-deprecated overload
        // in Ghidra 12.1+. Both program and address may be null.
        List<DemangledObject> demangledObjects = DemanglerUtil.demangle(null, mangled, null);
        DemangledObject demangledObj = (demangledObjects == null || demangledObjects.isEmpty())
            ? null : demangledObjects.get(0);
        
        if (demangledObj != null)
        {
            StringBuilder builder = new StringBuilder(demangledObj.toString());
            int templateLevel = 0;
            
            //De-Ghidrify-template colons
            for (int i = 0; i < builder.length(); ++i) 
            {
                char ch = builder.charAt(i);
                
                if (ch == '<') 
                {
                    ++templateLevel;
                }
                else if (ch == '>' && templateLevel != 0) 
                {
                    --templateLevel;
                }

                if (templateLevel > 0 && ch == '-') 
                    builder.setCharAt(i, ':');
            }
            
            out = builder.toString();
        }
    } catch (Exception e) {
        // If demangling fails, just return the mangled name
        // This prevents crashes if the demangler encounters unexpected input
    }
    
    return out;
}
    
    public static String shortenIpcSymbol(String longSym)
    {
        String out = longSym;

        if (out.startsWith("_ZTV"))
            return parseMangledVtableName(out);

        String suffix = out.substring(out.lastIndexOf(':') + 1);
        
        if (out.startsWith("nn::sf::detail::ObjectImplFactoryWithStatelessAllocator<") || out.startsWith("nn::sf::detail::ObjectImplFactoryWithStatefulAllocator<"))
        {
            String abvNamePrefixOld = "nn::sf::detail::EmplacedImplHolder<";
            String abvNamePrefixNew = "_tO2N<";
            
            int abvNamePrefixOldIndex = out.indexOf(abvNamePrefixOld);
            int abvNamePrefixNewIndex = out.indexOf(abvNamePrefixNew);
            
            if (abvNamePrefixOldIndex != -1)
            {
                int abvNameStart = abvNamePrefixOldIndex + abvNamePrefixOld.length();
                out = out.substring(abvNameStart, out.indexOf(',', abvNameStart));
            }
            else if (abvNamePrefixNewIndex != -1)
            {
                int abvNameStart = abvNamePrefixNewIndex + abvNamePrefixNew.length();
                out = out.substring(abvNameStart, out.indexOf('>', abvNameStart));
            }
            
            out += "::" + suffix;
        }

        return out;
    }
    
    public boolean hasImportedSymbol(Program program, Address addr)
    {
        for (Symbol sym : program.getSymbolTable().getSymbols(addr))
        {
            if (sym.getSource() == SourceType.IMPORTED)
                return true;
        }
        
        return false;
    }

    public boolean hasSymbolNamed(Program program, Address addr, String name)
    {
        for (Symbol sym : program.getSymbolTable().getSymbols(addr))
        {
            if (sym.getName(true).equals(name) || sym.getName().equals(name))
                return true;
        }

        return false;
    }

    private boolean canMarkupIpcCommandAddress(Program program, Address addr, String label)
    {
        return this.hasSymbolNamed(program, addr, label) || !this.hasImportedSymbol(program, addr);
    }

    /** Make {@code sym} the primary symbol at {@code addr}, unless the user has applied their own name
     *  there (never override a USER_DEFINED label). Used to surface an inferred name over a SRV_ one. */
    private void makeSymbolPrimaryIfNotUserNamed(Program program, Address addr, Symbol sym)
    {
        for (Symbol s : program.getSymbolTable().getSymbols(addr))
            if (s.getSource() == SourceType.USER_DEFINED)
                return;
        sym.setPrimary();
    }
    
    protected int createPointer(Program program, Address address)
    {
        ghidra.program.model.listing.Listing listing = program.getListing();
        Data d = listing.getDataAt(address);

        // Data already defined here -- leave it untouched.
        if (d != null)
            return d.getLength();

        try
        {
            d = listing.createData(address, PointerDataType.dataType, 8);
        }
        catch (CodeUnitInsertionException e)
        {
            // A conflicting instruction occupies this pointer slot. A vtable slot must hold a
            // pointer, so the instruction is spurious (e.g. bytes wrongly disassembled over data);
            // clear it and lay the pointer down, repairing the slot.
            try
            {
                listing.clearCodeUnits(address, address.add(7), false);
                d = listing.createData(address, PointerDataType.dataType, 8);
            }
            catch (Exception e2)
            {
                Msg.error(this, String.format("Failed to create pointer at 0x%X", address.getOffset()), e2);
            }
        }

        return d != null ? d.getLength() : 0;
    }
    
    public static class IPCVTableEntry
    {
        public final String fullName;
        public final String abvName;
        public final Address addr;
        public final ImmutableList<Address> ipcFuncs;
        public final boolean hasRealVtable;
        
        private IPCVTableEntry(String fullName, String abvName, Address addr, List<Address> ipcFuncs)
        {
            this(fullName, abvName, addr, ipcFuncs, true);
        }

        private IPCVTableEntry(String fullName, String abvName, Address addr, List<Address> ipcFuncs,
                               boolean hasRealVtable)
        {
            this.fullName = fullName;
            this.abvName = abvName;
            this.addr = addr;
            this.ipcFuncs = ImmutableList.copyOf(ipcFuncs);
            this.hasRealVtable = hasRealVtable;
        }
    }

    private static class IPCInterfaceVTableGroup
    {
        public final String interfaceName;
        public final Address vtableAddr;
        public final int scanSlotCount;
        public final Map<String, String> commands;
        public final ImmutableList<IPCInterfaceVTableSlot> slots;
        public final boolean clientImportOnly;

        private IPCInterfaceVTableGroup(String interfaceName, Address vtableAddr, int scanSlotCount,
                                        Map<String, String> commands,
                                        List<IPCInterfaceVTableSlot> slots,
                                        boolean clientImportOnly)
        {
            this.interfaceName = interfaceName;
            this.vtableAddr = vtableAddr;
            this.scanSlotCount = scanSlotCount;
            this.commands = commands;
            this.slots = ImmutableList.copyOf(slots);
            this.clientImportOnly = clientImportOnly;
        }
    }

    private static class IPCInterfaceVTableSlot
    {
        public final Address slotAddr;
        public final Address targetAddr;
        public final long vptrOffset;
        public final Long commandId;

        private IPCInterfaceVTableSlot(Address slotAddr, Address targetAddr, long vptrOffset,
                                       Long commandId)
        {
            this.slotAddr = slotAddr;
            this.targetAddr = targetAddr;
            this.vptrOffset = vptrOffset;
            this.commandId = commandId;
        }
    }

    private static class ClientImportCandidateSet
    {
        public final int rawCount;
        public final int vtableCount;
        public final int sdkRecordCount;
        public final int cmifRodataCount;
        public final int sdkPointerCount;
        public final int staticCommandRawCount;
        public final int staticCommandUniqueCount;
        public final ImmutableList<ClientImportStubCandidate> uniqueCandidates;

        private ClientImportCandidateSet(List<ClientImportStubCandidate> raw,
                                         List<ClientImportStubCandidate> uniqueCandidates)
        {
            this.rawCount = raw.size();
            this.vtableCount = (int)raw.stream().filter(candidate -> candidate.source.equals("vtable")).count();
            this.sdkRecordCount = (int)raw.stream().filter(candidate -> candidate.source.equals("sdk-record")).count();
            this.cmifRodataCount = (int)raw.stream().filter(candidate -> candidate.source.equals("cmif-rodata")).count();
            this.sdkPointerCount = (int)raw.stream().filter(candidate -> candidate.source.equals("sdk-pointer")).count();
            this.staticCommandRawCount = (int)raw.stream()
                .filter(candidate -> candidate.expectedCommandId != null).count();
            this.staticCommandUniqueCount = (int)uniqueCandidates.stream()
                .filter(candidate -> candidate.expectedCommandId != null).count();
            this.uniqueCandidates = ImmutableList.copyOf(uniqueCandidates);
        }
    }

    private static class ClientImportSourceStats
    {
        public int emulated = 0;
        public int useful = 0;
        public int staticCommand = 0;
        public int command = 0;
        public int send = 0;
        public int sessionField = 0;
        public int skippedLimit = 0;
        public final Map<String, Integer> terminations = new TreeMap<>();
    }

    private static class ClientImportStubCandidate
    {
        private static final Comparator<ClientImportStubCandidate> PREFERRED_ORDER = Comparator
            .comparingInt(ClientImportStubCandidate::confidenceScore).reversed()
            .thenComparing(candidate -> candidate.interfaceName != null ? candidate.interfaceName : "")
            .thenComparingLong(candidate -> candidate.expectedCommandId != null
                ? candidate.expectedCommandId
                : Long.MAX_VALUE)
            .thenComparingLong(candidate -> candidate.sourceAddr.getOffset())
            .thenComparingLong(candidate -> candidate.stubAddr.getOffset());

        public final Address stubAddr;
        public final String interfaceName;
        public final Long expectedCommandId;
        public final String source;
        public final Address sourceAddr;

        private ClientImportStubCandidate(Address stubAddr, String interfaceName,
                                          Long expectedCommandId, String source, Address sourceAddr)
        {
            this.stubAddr = stubAddr;
            this.interfaceName = interfaceName;
            this.expectedCommandId = expectedCommandId;
            this.source = source;
            this.sourceAddr = sourceAddr;
        }

        private boolean isBetterThan(ClientImportStubCandidate other)
        {
            return this.confidenceScore() > other.confidenceScore();
        }

        private int confidenceScore()
        {
            int score = 0;

            if (this.expectedCommandId != null)
                score += 8;

            if (this.interfaceName != null)
                score += 4;

            if (this.source.equals("sdk-record"))
                score += 4;
            else if (this.source.equals("cmif-rodata"))
                score += 3;
            else if (this.source.equals("sdk-pointer"))
                score += 2;

            return score;
        }
    }

    private static class SdkPointerTableSelection
    {
        public final String interfaceName;
        public final int commandSlotBase;
        public final String reason;

        private SdkPointerTableSelection(String interfaceName, int commandSlotBase,
                                         String reason)
        {
            this.interfaceName = interfaceName;
            this.commandSlotBase = commandSlotBase;
            this.reason = reason;
        }

        private SdkPointerTableSelection withReason(String reason)
        {
            return new SdkPointerTableSelection(this.interfaceName, this.commandSlotBase, reason);
        }
    }

    private static class SdkExtraDataProbeResult
    {
        public static final SdkExtraDataProbeResult EMPTY =
            new SdkExtraDataProbeResult(Collections.emptyList(), Collections.emptyList(),
                Collections.emptyList(), Collections.emptySet());

        public final ImmutableList<SdkCommandTableCandidate> recordCandidates;
        public final ImmutableList<SdkPointerTableCandidate> pointerCandidates;
        public final ImmutableList<CmifProxyDescriptorCandidate> cmifProxyCandidates;
        public final Set<String> clientImportInterfaces;

        private SdkExtraDataProbeResult(List<SdkCommandTableCandidate> recordCandidates,
                                        List<SdkPointerTableCandidate> pointerCandidates,
                                        List<CmifProxyDescriptorCandidate> cmifProxyCandidates,
                                        Set<String> clientImportInterfaces)
        {
            this.recordCandidates = ImmutableList.copyOf(recordCandidates);
            this.pointerCandidates = ImmutableList.copyOf(pointerCandidates);
            this.cmifProxyCandidates = ImmutableList.copyOf(cmifProxyCandidates);
            this.clientImportInterfaces =
                Collections.unmodifiableSet(new LinkedHashSet<>(clientImportInterfaces));
        }
    }

    private static class ClientImportInterfaceAnchor
    {
        public final String interfaceName;
        public final Address stringAddr;
        public final String mangledName;

        private ClientImportInterfaceAnchor(String interfaceName, Address stringAddr,
                                            String mangledName)
        {
            this.interfaceName = interfaceName;
            this.stringAddr = stringAddr;
            this.mangledName = mangledName;
        }
    }

    private static class CmifDescriptorRange
    {
        public final ClientImportInterfaceAnchor anchor;
        public final long start;
        public final long endInclusive;

        private CmifDescriptorRange(ClientImportInterfaceAnchor anchor, long start, long endInclusive)
        {
            this.anchor = anchor;
            this.start = start;
            this.endInclusive = endInclusive;
        }
    }

    private static class CmifProxyDescriptorCandidate
    {
        public final String interfaceName;
        public final Address descriptorAddr;
        public final Address functionAddr;
        public final Long commandId;

        private CmifProxyDescriptorCandidate(String interfaceName, Address descriptorAddr,
                                             Address functionAddr, Long commandId)
        {
            this.interfaceName = interfaceName;
            this.descriptorAddr = descriptorAddr;
            this.functionAddr = functionAddr;
            this.commandId = commandId;
        }
    }

    private static class SdkCommandTableCandidate
    {
        public final String interfaceName;
        public final Address tableAddr;
        public final String blockName;
        public final int recordSize;
        public final int commandIdOffset;
        public final int functionOffset;
        public final int score;
        public final int dbCommandCount;
        public final ImmutableList<SdkCommandTableEntry> entries;

        private SdkCommandTableCandidate(String interfaceName, Address tableAddr, String blockName,
                                         int recordSize, int commandIdOffset, int functionOffset,
                                         int score, int dbCommandCount,
                                         List<SdkCommandTableEntry> entries)
        {
            this.interfaceName = interfaceName;
            this.tableAddr = tableAddr;
            this.blockName = blockName;
            this.recordSize = recordSize;
            this.commandIdOffset = commandIdOffset;
            this.functionOffset = functionOffset;
            this.score = score;
            this.dbCommandCount = dbCommandCount;
            this.entries = ImmutableList.copyOf(entries);
        }

        private Set<Long> commandIds()
        {
            return this.entries.stream()
                .map(entry -> entry.commandId)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        }

        private long endOffset()
        {
            return this.tableAddr.getOffset() + (long)this.recordSize * this.entries.size();
        }

        private boolean overlaps(SdkCommandTableCandidate other)
        {
            if (!this.blockName.equals(other.blockName))
                return false;

            long thisStart = this.tableAddr.getOffset();
            long otherStart = other.tableAddr.getOffset();
            return thisStart < other.endOffset() && otherStart < this.endOffset();
        }

        private boolean isStrongTableCandidate()
        {
            return this.score == this.dbCommandCount
                || (this.score >= 8 && this.score * 2 >= this.dbCommandCount);
        }
    }

    private static class SdkCommandTableEntry
    {
        public final Address entryAddr;
        public final long commandId;
        public final Address functionAddr;

        private SdkCommandTableEntry(Address entryAddr, long commandId, Address functionAddr)
        {
            this.entryAddr = entryAddr;
            this.commandId = commandId;
            this.functionAddr = functionAddr;
        }
    }

    private enum SyntheticCandidateSelection
    {
        BETTER,
        WORSE,
        AMBIGUOUS
    }

    private static class SyntheticCommandFunctionTable
    {
        public final Address tableAddr;
        public final Map<Long, Address> functionsByVtOffset;
        public final int requestedSlotCount;
        public final int matchedSlotCount;
        public final int uniqueFunctionCount;
        public final boolean pointerRunStart;
        public final boolean referenced;
        public final boolean hasSymbol;

        private SyntheticCommandFunctionTable(Address tableAddr, Map<Long, Address> functionsByVtOffset,
                                              int requestedSlotCount, boolean pointerRunStart,
                                              boolean referenced, boolean hasSymbol)
        {
            this.tableAddr = tableAddr;
            this.functionsByVtOffset = Collections.unmodifiableMap(new LinkedHashMap<>(functionsByVtOffset));
            this.requestedSlotCount = requestedSlotCount;
            this.matchedSlotCount = functionsByVtOffset.size();
            this.uniqueFunctionCount = new LinkedHashSet<>(functionsByVtOffset.values()).size();
            this.pointerRunStart = pointerRunStart;
            this.referenced = referenced;
            this.hasSymbol = hasSymbol;
        }

        private Address getSlotAddress(long vtOffset)
        {
            return this.tableAddr.add(vtOffset);
        }

        private Address getFunction(long vtOffset)
        {
            return this.functionsByVtOffset.get(vtOffset);
        }

        private boolean isBetterThan(SyntheticCommandFunctionTable other)
        {
            int cmp = Integer.compare(this.matchedSlotCount, other.matchedSlotCount);
            if (cmp != 0)
                return cmp > 0;

            if (this.referenced != other.referenced)
                return this.referenced;

            if (this.pointerRunStart != other.pointerRunStart)
                return this.pointerRunStart;

            if (this.hasSymbol != other.hasSymbol)
                return this.hasSymbol;

            cmp = Integer.compare(this.uniqueFunctionCount, other.uniqueFunctionCount);
            if (cmp != 0)
                return cmp > 0;

            return this.tableAddr.getOffset() < other.tableAddr.getOffset();
        }

        private boolean hasSameConfidenceAs(SyntheticCommandFunctionTable other)
        {
            return this.matchedSlotCount == other.matchedSlotCount
                && this.uniqueFunctionCount == other.uniqueFunctionCount
                && this.referenced == other.referenced
                && this.pointerRunStart == other.pointerRunStart
                && this.hasSymbol == other.hasSymbol;
        }
    }

    private static class SdkPointerTableCandidate
    {
        public final Address tableAddr;
        public final String blockName;
        public final int slotCount;
        public final ImmutableList<String> possibleInterfaces;
        public final Set<Long> inferredCommandIds;
        public final InterfaceMatch semanticMatch;
        public final boolean largeMixedRegion;

        private SdkPointerTableCandidate(Address tableAddr, String blockName, int slotCount,
                                         List<String> possibleInterfaces,
                                         Set<Long> inferredCommandIds,
                                         InterfaceMatch semanticMatch,
                                         boolean largeMixedRegion)
        {
            this.tableAddr = tableAddr;
            this.blockName = blockName;
            this.slotCount = slotCount;
            this.possibleInterfaces = ImmutableList.copyOf(possibleInterfaces);
            this.inferredCommandIds = Collections.unmodifiableSet(new LinkedHashSet<>(inferredCommandIds));
            this.semanticMatch = semanticMatch;
            this.largeMixedRegion = largeMixedRegion;
        }

        private String formatSemanticSummary()
        {
            if (this.inferredCommandIds.isEmpty())
                return "";

            if (this.semanticMatch == null)
            {
                return String.format(" inferred_cmds=%s",
                    formatCommandIds(this.inferredCommandIds));
            }

            return String.format(" partial_semantic_match=%s score=%d/%d inferred_cmds=%s",
                this.semanticMatch.iface, this.semanticMatch.score, this.semanticMatch.dbCmdCount,
                formatCommandIds(this.inferredCommandIds));
        }
    }

    private Map<Address, String> buildRttiNameMap(Program program, ElfCompatibilityProvider elfProvider)
            throws MemoryAccessException, IOException
    {
        Map<Address, String> result = new HashMap<>();
        Memory mem = program.getMemory();
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();

        // Step 1: collect all mangled type name strings from rodata blocks,
        // keyed by their address.
        Map<Long, String> stringAddrToName = new HashMap<>();

        for (MemoryBlock block : mem.getBlocks())
        {
            if (!block.getName().startsWith(".rodata") || !block.isInitialized())
                continue;

            long start = block.getStart().getOffset();
            long end   = block.getEnd().getOffset();

            // Scan for null-terminated strings that look like mangled type names
            long pos = start;
            while (pos < end)
            {
                try
                {
                    String s = elfProvider.getReader().readAsciiString(pos);
                    if (s.length() >= 4 && s.length() <= 256
                        && (Character.isDigit(s.charAt(0)) || s.charAt(0) == 'N'))
                    {
                        // Looks like a mangled Itanium type name
                        stringAddrToName.put(pos, s);
                    }
                    pos += s.length() + 1;
                    if (s.isEmpty()) pos = pos + 1; // skip runs of nulls faster
                }
                catch (Exception e) { pos++; }
            }
        }

        Msg.info(this, String.format("RTTI scan: found %d candidate type name strings", stringAddrToName.size()));

        if (stringAddrToName.isEmpty())
            return result;

        // Step 2: scan .data to find type_info objects.
        // type_info layout (Itanium ABI):
        //   +0x00  ptr to type_info vtable (e.g. __si_class_type_info)
        //   +0x08  ptr to type name string (in rodata)
        // We find these by looking for .data pointers into our string set.

        Map<Long, Long> stringAddrToTypeInfo = new HashMap<>(); // typeInfoAddr -> stringAddr

        for (MemoryBlock block : mem.getBlocks())
        {
            if (!this.isRttiDataBlock(program, block) || !block.isInitialized())
                continue;

            long start = block.getStart().getOffset();
            long end   = block.getEnd().getOffset();

            for (long off = start; off <= end - 0x10; off += 0x8)
            {
                long val;
                try { val = mem.getLong(aSpace.getAddress(off)); }
                catch (MemoryAccessException e) { continue; }

                if (stringAddrToName.containsKey(val))
                {
                    // off is type_info+0x8, so type_info is at off-0x8
                    long typeInfoAddr = off - 0x8;
                    stringAddrToTypeInfo.put(typeInfoAddr, val);
                }
            }
        }

        Msg.info(this, String.format("RTTI scan: found %d type_info objects", stringAddrToTypeInfo.size()));

        // Step 3: scan .data for vtables pointing to these type_info objects.
        // vtable layout: [offset_to_top=0][rtti_ptr=type_info_addr][vfuncs...]
        // vtable+0x08 == type_info address

        String pendingInterfaceVtableName = null;
        long pendingInterfaceVtableOff = 0;

        for (MemoryBlock block : mem.getBlocks())
        {
            if (!this.isRttiDataBlock(program, block) || !block.isInitialized())
                continue;

            long start = block.getStart().getOffset();
            long end   = block.getEnd().getOffset();

            for (long off = start; off <= end - 0x10; off += 0x8)
            {
                long val;
                try { val = mem.getLong(aSpace.getAddress(off + 0x8)); }
                catch (MemoryAccessException e) { continue; }

                if (!stringAddrToTypeInfo.containsKey(val))
                    continue;

                long stringAddr = stringAddrToTypeInfo.get(val);
                String mangledTypeName = stringAddrToName.get(stringAddr);

                // Demangle: _ZTV prefix = vtable for X
                String symbol = "_ZTV" + mangledTypeName;
                String demangled = demangleIpcSymbol(symbol);

                Msg.debug(this, String.format("Demangling '%s' -> '%s'", symbol, demangled));

                // If demangling failed (returned the mangled form), skip non-IPC vtables
                // but store what we have regardless
                String shortName;
                if (demangled.equals(symbol) || demangled.startsWith("_ZTV"))
                {
                    // Demangling failed — try to extract a useful name from the raw string.
                    // Raw Itanium: N2nn5fssrv2sf16IFileSystemProxyE
                    // We can parse it manually as a fallback.
                    shortName = parseMangledTypeName(mangledTypeName) + "::vtable";
                }
                else
                {
                    shortName = shortenIpcSymbol(demangled);
                }

                boolean mappedFromPendingInterface = false;
                String originalShortName = shortName;

                if (!isPotentialIpcVtableName(shortName))
                {
                    if (pendingInterfaceVtableName != null
                        && isClientProxyVtableGroupName(shortName)
                        && off >= pendingInterfaceVtableOff
                        && off - pendingInterfaceVtableOff <= 0x400)
                    {
                        shortName = pendingInterfaceVtableName;
                        mappedFromPendingInterface = true;
                        Msg.info(this, String.format(
                            "RTTI scan: associating client/proxy vtable 0x%X (%s) with pending interface %s from 0x%X",
                            off, originalShortName, shortName, pendingInterfaceVtableOff));
                    }
                    else
                    {
                        Msg.debug(this, String.format("RTTI scan: skipping non-IPC vtable 0x%X -> %s", off, shortName));
                        continue;
                    }
                }

                Address vtAddr = aSpace.getAddress(off);

                // Verify this is actually a dispatcher vtable by checking that +0x30 points into executable code.
                // If not, try +0x8 in case the address is off by one slot.
                try
                {
                    long funcPtr = mem.getLong(vtAddr.add(0x30));
                    Address funcAddr = aSpace.getAddress(funcPtr);
                    MemoryBlock funcBlock = mem.getBlock(funcAddr);
                    
                    if (!this.isExecutableCodeBlock(program, funcBlock))
                    {
                        // Try shifting by +0x8
                        Address shiftedVtAddr = vtAddr.add(0x8);
                        long shiftedFuncPtr = mem.getLong(shiftedVtAddr.add(0x30));
                        Address shiftedFuncAddr = aSpace.getAddress(shiftedFuncPtr);
                        MemoryBlock shiftedFuncBlock = mem.getBlock(shiftedFuncAddr);
                        
                        if (this.isExecutableCodeBlock(program, shiftedFuncBlock))
                        {
                            Msg.info(this, String.format("RTTI scan: shifting vtable 0x%X -> 0x%X (first func in executable block after +0x8)", off, shiftedVtAddr.getOffset()));
                            vtAddr = shiftedVtAddr;
                        }
                        else
                        {
                            // Neither offset has .text functions — skip this entry
                            Msg.debug(this, String.format("RTTI scan: skipping 0x%X, no executable functions at +0x30 or +0x38", off));
                            if (isConcreteServiceInterfaceVtableName(shortName) || mappedFromPendingInterface)
                            {
                                result.put(vtAddr, shortName);
                                Msg.info(this, String.format("RTTI resolved sparse/client interface group: 0x%X -> %s", vtAddr.getOffset(), shortName));

                                if (mappedFromPendingInterface)
                                {
                                    pendingInterfaceVtableName = null;
                                }
                                else if (isConcreteServiceInterfaceVtableName(shortName))
                                {
                                    pendingInterfaceVtableName = shortName;
                                    pendingInterfaceVtableOff = off;
                                    Msg.debug(this, String.format("RTTI scan: pending interface name %s from 0x%X", shortName, off));
                                }
                            }
                            continue;
                        }
                    }
                }
                catch (MemoryAccessException e)
                {
                    continue;
                }

                if (isGenericServiceObjectImplVtableName(shortName)
                    && pendingInterfaceVtableName != null
                    && off >= pendingInterfaceVtableOff
                    && off - pendingInterfaceVtableOff <= 0x200)
                {
                    Msg.info(this, String.format("RTTI scan: mapping generic service vtable 0x%X to pending interface %s from 0x%X",
                        vtAddr.getOffset(), pendingInterfaceVtableName, pendingInterfaceVtableOff));
                    shortName = pendingInterfaceVtableName;
                    pendingInterfaceVtableName = null;
                }

                result.put(vtAddr, shortName);
                Msg.info(this, String.format("RTTI resolved: 0x%X -> %s", vtAddr.getOffset(), shortName));

                if (mappedFromPendingInterface)
                    pendingInterfaceVtableName = null;
            }
        }

        Msg.info(this, String.format("RTTI scan: resolved %d vtable names", result.size()));
        return result;
    }

    private static String parseMangledTypeName(String mangled)
    {
        // Parses Itanium nested name encoding like:
        // N2nn5fssrv2sf16IFileSystemProxyE -> nn::fssrv::sf::IFileSystemProxy
        // N2nn2sf14IServiceObjectE         -> nn::sf::IServiceObject
        if (mangled.startsWith("N") && mangled.endsWith("E"))
        {
            StringBuilder result = new StringBuilder();
            int i = 1; // skip leading N
            int end = mangled.length() - 1; // skip trailing E
            
            while (i < end)
            {
                // Read length prefix
                int numStart = i;
                while (i < end && Character.isDigit(mangled.charAt(i)))
                    i++;
                
                if (i == numStart)
                    break; // no digits found, malformed
                
                int len;
                try { len = Integer.parseInt(mangled.substring(numStart, i)); }
                catch (NumberFormatException e) { break; }
                
                if (i + len > end)
                    break;
                
                if (result.length() > 0)
                    result.append("::");
                result.append(mangled, i, i + len);
                i += len;
            }
            
            return result.length() > 0 && i == end ? result.toString() : mangled;
        }
        
        // Simple non-nested name like 14IServiceObject -> just the name part
        int i = 0;
        while (i < mangled.length() && Character.isDigit(mangled.charAt(i)))
            i++;
        if (i > 0 && i < mangled.length())
            return mangled.substring(i);
        
        return mangled;
    }

    /** True if a name is an unresolved/templated vtable mangle that leaked through naming (e.g. an
     *  ObjectImplFactory wrapper the simple parser could not handle). */
    private static boolean looksLikeUnresolvedMangle(String name)
    {
        return name != null && (name.startsWith("_ZTV") || name.contains("ObjectImplFactory"));
    }

    /**
     * Recover the interface from an ObjectImplFactory vtable mangle, which embeds the real interface as
     * the first type argument of {@code InterfaceInfo<...>}, e.g.
     * {@code _ZTVN2nn2sf6detail38ObjectImplFactoryWithStatefulAllocatorINS0_13InterfaceInfoINS_4anif6detail23ISfDriverServiceCreatorEE...}
     * -> {@code nn::anif::detail::ISfDriverServiceCreator}. Returns null if it can't be parsed
     * confidently (only the common {@code S_ = nn} substitution is resolved). Operates on the raw
     * Itanium mangle (the form that actually leaks here).
     */
    private static String extractInterfaceFromObjectImplFactory(String mangled)
    {
        if (mangled == null)
            return null;

        int marker = mangled.indexOf("InterfaceInfo");
        if (marker < 0)
            return null;

        int i = marker + "InterfaceInfo".length();
        if (i >= mangled.length() || mangled.charAt(i++) != 'I')   // template-args start
            return null;
        if (i >= mangled.length() || mangled.charAt(i++) != 'N')   // nested-name start
            return null;

        StringBuilder out = new StringBuilder();
        if (i < mangled.length() && mangled.charAt(i) == 'S')      // leading substitution
        {
            int j = mangled.indexOf('_', i);
            if (j < 0)
                return null;
            if (!mangled.substring(i, j + 1).equals("S_"))         // only S_ (== "nn") is safe to resolve
                return null;
            out.append("nn");
            i = j + 1;
        }

        while (i < mangled.length() && mangled.charAt(i) != 'E')
        {
            int numStart = i;
            while (i < mangled.length() && Character.isDigit(mangled.charAt(i)))
                i++;
            if (i == numStart)
                return null;
            int len;
            try { len = Integer.parseInt(mangled.substring(numStart, i)); }
            catch (NumberFormatException e) { return null; }
            if (i + len > mangled.length())
                return null;
            if (out.length() > 0)
                out.append("::");
            out.append(mangled, i, i + len);
            i += len;
        }

        return out.length() > 0 ? out.toString() : null;
    }

    private static boolean isPotentialIpcVtableName(String name)
    {
        if (name == null || !name.endsWith("::vtable"))
            return false;

        String typeName = name.substring(0, name.length() - "::vtable".length());

        if (typeName.startsWith("SRV_"))
            return true;

        if (!typeName.startsWith("nn::"))
            return false;

        return typeName.contains("::sf::")
            || typeName.contains("::cmif::")
            || typeName.contains("::hipc::")
            || typeName.contains("ServiceObject")
            || typeName.contains("Interface")
            || typeName.matches(".*::I[A-Z].*");
    }

    private static String stripVtableSuffix(String name)
    {
        if (name == null)
            return "";

        return name.endsWith("::vtable")
            ? name.substring(0, name.length() - "::vtable".length())
            : name;
    }

    private static boolean isClientProxyVtableGroupName(String name)
    {
        if (name == null)
            return false;

        String typeName = stripVtableSuffix(name);

        if (IPCDatabase.getInstance().getAllInterfaces().containsKey(typeName))
            return false;

        return name.contains("CmifProxyInfo")
            || name.contains("CmifBaseObject")
            || name.contains("ProxyBaseObject")
            || name.contains("ProxyKindBase")
            || (name.contains("cmif") && name.contains("client"))
            || (name.contains("hipc") && name.contains("client"))
            || (name.contains("_ZTV") && name.contains("Proxy"));
    }

    private static boolean isConcreteServiceInterfaceVtableName(String name)
    {
        if (!isPotentialIpcVtableName(name))
            return false;

        String typeName = name.substring(0, name.length() - "::vtable".length());
        if (typeName.startsWith("nn::sf::"))
            return false;

        return typeName.matches(".*::I[A-Z].*");
    }

    private static boolean isGenericServiceObjectImplVtableName(String name)
    {
        return "nn::sf::impl::detail::ServiceObjectImplBase2::vtable".equals(name);
    }

    private static String parseMangledVtableName(String mangled)
    {
        String typeName = mangled;

        if (typeName.startsWith("_ZTV"))
            typeName = typeName.substring(4);
        else if (typeName.startsWith("ZTV"))
            typeName = typeName.substring(3);

        String parsed = parseMangledTypeName(typeName);
        if (parsed.equals(typeName))
            return mangled;

        return parsed + "::vtable";
    }

}