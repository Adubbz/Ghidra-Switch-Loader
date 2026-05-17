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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
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
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.compress.utils.Lists;
import org.python.google.common.collect.HashBiMap;
import org.python.google.common.collect.Sets;

import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static adubbz.nx.common.ElfCompatibilityProvider.R_FAKE_RELR;

public class IPCAnalyzer extends AbstractAnalyzer 
{
    private static final Pattern AARCH64_MEMORY_BASE_PATTERN = Pattern.compile("\\[\\s*([xw]\\d+|sp)\\b", Pattern.CASE_INSENSITIVE);

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
        // TODO: Symbol options
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
    {
        Memory memory = program.getMemory();
        MemoryBlock text = memory.getBlock(".text");
        MemoryBlock data = memory.getBlock(".data");
        ElfCompatibilityProvider elfCompatProvider = new ElfCompatibilityProvider(program, false);
        
        Msg.info(this, "Beginning IPC analysis...");
        
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
            HashBiMap<Address, IPCVTableEntry> procFuncVtMap = this.matchVtables(vtEntries, sTableProcessFuncMap.values(), processFuncTraces);

            // NOW patch names using emulated command IDs against database
            Map<String, Map<String, String>> allIfaces = IPCDatabase.getInstance().getAllInterfaces();

            // Pass 1: rename SRV_ vtable entries that were matched by size but not named by RTTI
            for (int i = 0; i < vtEntries.size(); i++)
            {
                IPCVTableEntry entry = vtEntries.get(i);
                if (!entry.abvName.startsWith("SRV_"))
                    continue;

                Address procFuncAddr = procFuncVtMap.inverse().get(entry);
                if (procFuncAddr == null || !processFuncTraces.containsKey(procFuncAddr))
                    continue;

                Set<Long> emulatedCmds = processFuncTraces.get(procFuncAddr).stream()
                    .filter(t -> t.vtOffset != -1)
                    .map(t -> t.cmdId)
                    .collect(Collectors.toSet());

                if (emulatedCmds.isEmpty()) continue;

                InterfaceMatch bestMatch = findBestInterfaceMatch(allIfaces, emulatedCmds);

                if (bestMatch != null)
                {
                    String fullName = bestMatch.iface + "::vtable";
                    String shortName = shortenIpcSymbol(fullName);
                    Msg.info(this, String.format("Cmd-matched: %s -> %s (score %d/%d)",
                        entry.abvName, shortName, bestMatch.score, emulatedCmds.size()));

                    IPCVTableEntry newEntry = new IPCVTableEntry(fullName, shortName, entry.addr, entry.ipcFuncs);
                    vtEntries.set(i, newEntry);

                    Address procFuncAddrForEntry = procFuncVtMap.inverse().get(entry);
                    if (procFuncAddrForEntry != null)
                        procFuncVtMap.forcePut(procFuncAddrForEntry, newEntry);
                }
            }

            // Pass 2: handle process functions that have no vtable match at all
            // (their vtable was only found as a proxy, not a dispatcher)
            for (Address procFuncAddr : sTableProcessFuncMap.values())
            {
                if (procFuncVtMap.containsKey(procFuncAddr))
                    continue;

                if (!processFuncTraces.containsKey(procFuncAddr))
                    continue;

                Set<Long> emulatedCmds = processFuncTraces.get(procFuncAddr).stream()
                    .filter(t -> t.vtOffset != -1)
                    .map(t -> t.cmdId)
                    .collect(Collectors.toSet());

                if (emulatedCmds.isEmpty()) continue;

                InterfaceMatch bestMatch = findBestInterfaceMatch(allIfaces, emulatedCmds);

                if (bestMatch != null)
                {
                    String fullName = bestMatch.iface + "::vtable";
                    String shortName = shortenIpcSymbol(fullName);
                    Msg.info(this, String.format("Cmd-matched unmatched proc_func 0x%X -> %s (score %d/%d)",
                        procFuncAddr.getOffset(), bestMatch.iface, bestMatch.score, emulatedCmds.size()));

                    Address sTableAddr = sTableProcessFuncMap.inverse().get(procFuncAddr);
                    IPCVTableEntry newEntry = new IPCVTableEntry(fullName, shortName,
                        sTableAddr != null ? sTableAddr : procFuncAddr, new ArrayList<>());
                    vtEntries.add(newEntry);
                    procFuncVtMap.forcePut(procFuncAddr, newEntry);
                }
            }

            this.markupIpc(program, monitor, vtEntries, sTableProcessFuncMap, processFuncTraces, procFuncVtMap);
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
            if (vtBlock == null || !vtBlock.getName().equals(".data"))
                continue;
            
            try
            {
                Address rttiAddr = aSpace.getAddress(mem.getLong(vtAddr.add(8)));
                MemoryBlock rttiBlock = mem.getBlock(rttiAddr);
                
                // RTTI is only found in the data block
                if (rttiBlock == null || !rttiBlock.getName().equals(".data"))
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
            Msg.warn(this, "Failed to locate vtables - No known addresses found!");
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
                if (vtBlock != null && vtBlock.getName().equals(".data"))
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
                else if (!rttiBaseBlock.getName().equals(".data"))
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

            // FIX 3: if inline RTTI didn't resolve a name, fall back to the pre-built rttiNames map
            if (name.startsWith("SRV_") && rttiNames != null && rttiNames.containsKey(vtAddr))
            {
                String rttiResolved = rttiNames.get(vtAddr);
                Msg.info(this, String.format("VT 0x%X: using rttiNames fallback -> '%s'", vtOff, rttiResolved));
                name = rttiResolved;
            }
            
            Map<Address, Address> gotDataSyms = this.getGotDataSyms(program, elfProvider);
            List<Address> implAddrs = new ArrayList<>();
            long funcVtOff = 0x30;
            long funcOff;
            
            // Find all ipc impl functions in the vtable
            while ((funcOff = mem.getLong(vtAddr.add(funcVtOff))) != 0)
            {
                Address funcAddr = aSpace.getAddress(funcOff);
                MemoryBlock funcAddrBlock = mem.getBlock(funcAddr);
                
                if (funcAddrBlock != null && funcAddrBlock.getName().equals(".text"))
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
            
                if (gotDataSyms.containsValue(vtAddr.add(funcVtOff)))
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
                Msg.warn(this, String.format("Insufficient unique addresses for vtable at 0x%X (found %d functions, %d unique)", 
                    vtAddr.getOffset(), implAddrs.size(), uniqueAddrs.size()));
                
                for (Address addr : uniqueAddrs)
                {
                    Msg.info(this, String.format("    Found: 0x%X", addr.getOffset()));
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
                    for (pRetOff = processFuncOffset; pRetOff < text.getEnd().getOffset(); pRetOff += 0x4)
                    {
                        long rval = elfProvider.getReader().readUnsignedInt(pRetOff);
                        if (rval == 0xD65F03C0L)
                            break;
                    }

                    if (pRetOff > off)
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
        
        Multimap<Address, IPCTrace> map = HashMultimap.create();
        
        int maxProgress = procFuncAddrs.size() * cmdsToTry.size();
        int progress = 0;
        
        monitor.setMessage("Emulating IPC process functions...");
        monitor.initialize(maxProgress);
        
        for (Address procFuncAddr : procFuncAddrs)
        {
            for (int cmd : cmdsToTry)
            {
                IPCTrace trace = ipcEmu.emulateCommand(procFuncAddr, cmd);
                
                if (trace.hasDescription())
                    map.put(procFuncAddr, trace);
            
                progress++;
                monitor.setProgress(progress);
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

    private static InterfaceMatch findBestInterfaceMatch(Map<String, Map<String, String>> allIfaces, Set<Long> emulatedCmds)
    {
        InterfaceMatch bestMatch = null;

        for (Map.Entry<String, Map<String, String>> dbEntry : allIfaces.entrySet())
        {
            Set<String> dbCmds = dbEntry.getValue().keySet();
            int score = 0;

            for (Long cmdId : emulatedCmds)
            {
                if (dbCmds.contains(String.valueOf(cmdId)))
                    score++;
            }

            if (score == 0)
                continue;

            InterfaceMatch match = new InterfaceMatch(dbEntry.getKey(), score, emulatedCmds.size(), dbCmds.size());
            if (!match.isGoodEnough())
                continue;

            if (bestMatch == null || match.isBetterThan(bestMatch))
                bestMatch = match;
        }

        return bestMatch;
    }

    private static class InterfaceMatch
    {
        private final String iface;
        private final int score;
        private final int emulatedCmdCount;
        private final int dbCmdCount;

        private InterfaceMatch(String iface, int score, int emulatedCmdCount, int dbCmdCount)
        {
            this.iface = iface;
            this.score = score;
            this.emulatedCmdCount = emulatedCmdCount;
            this.dbCmdCount = dbCmdCount;
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
    }

    protected HashBiMap<Address, IPCVTableEntry> matchVtables(List<IPCVTableEntry> vtEntries, Set<Address> procFuncAddrs, Multimap<Address, IPCTrace> processFuncTraces)
    {
        // Map process func addrs to vtable addrs
        HashBiMap<Address, IPCVTableEntry> out = HashBiMap.create();
        
        // Filter out vtables with 0 functions - these are likely proxy/client interfaces, not dispatchers
        List<IPCVTableEntry> dispatcherVtables = vtEntries.stream()
            .filter(entry -> entry.ipcFuncs.size() > 0)
            .collect(Collectors.toList());
        
        List<IPCVTableEntry> possibilities = Lists.newArrayList(dispatcherVtables.iterator());
        
        if (dispatcherVtables.size() < vtEntries.size())
        {
            Msg.info(this, String.format("Skipping %d proxy/client vtables with 0 functions", 
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
        
        // Only report unmatched dispatcher vtables (size > 0), as size-0 proxy vtables are expected to not match
        for (IPCVTableEntry entry : possibilities)
        {
            if (entry.ipcFuncs.size() > 0)
            {
                Msg.info(this, String.format("Unmatched IPC VTable entry at 0x%X. VTable Size: 0x%X", entry.addr.getOffset(), entry.ipcFuncs.size()));
            }
        }
        
        return out;
    }
    
    protected void markupIpc(Program program, TaskMonitor monitor, List<IPCVTableEntry> vtEntries, HashBiMap<Address, Address> sTableProcessFuncMap, Multimap<Address, IPCTrace> processFuncTraces, HashBiMap<Address, IPCVTableEntry> procFuncVtMap)
    {
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        
        try
        {
            // Analyze and label any IPC info found
            for (IPCVTableEntry entry : vtEntries)
            {
                List<IPCTrace> ipcTraces = Lists.newArrayList();
                Address processFuncAddr = procFuncVtMap.inverse().get(entry);
                
                if (processFuncAddr != null)
                {
                    Address sTableAddr = sTableProcessFuncMap.inverse().get(processFuncAddr);
                    String ipcComment = ""                +
                            "IPC INFORMATION\n"           +
                            "s_Table Address:       0x%X";
                    
                    if (sTableAddr != null)
                    {
                        ipcComment = String.format(ipcComment, sTableAddr.getOffset());
                        program.getListing().setComment(entry.addr, CommentType.PLATE, ipcComment);
                    }
                    
                    ipcTraces = Lists.newArrayList(processFuncTraces.get(processFuncAddr).iterator());
                }
                    
                String entryNameNoSuffix = entry.abvName.replace("::vtable", "");
                
                // Set the vtable name
                if (!this.hasImportedSymbol(program, entry.addr))
                {
                    // For shortened names, leave a comment so the user knows what the original name is
                    if (!entry.fullName.equals(entry.abvName))
                        program.getListing().setComment(entry.addr, CommentType.REPEATABLE, entry.fullName);
                    
                    Msg.info(this, String.format("Creating label for %s @ 0x%X", entry.abvName, entry.addr.getOffset()));
                    program.getSymbolTable().createLabel(entry.addr, entry.abvName, null, SourceType.IMPORTED);
                }
                
                // Label the four functions that exist for all ipc vtables
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
                             
                    if (i == 3) // For now, only label GetInterfaceTypeInfo. We need better heuristics for the others as they may be shared.
                    {
                        Address funcAddr = aSpace.getAddress(program.getMemory().getLong(vtAddr));
                        
                        if (!this.hasImportedSymbol(program, funcAddr))
                            program.getSymbolTable().createLabel(funcAddr, name, null, SourceType.IMPORTED);
                    }
                    else
                    {
                        program.getListing().setComment(vtAddr, CommentType.REPEATABLE, name);
                    }
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

                    if (!this.hasSymbolNamed(program, ipcCmdImplAddr, label))
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
                    if (ipcCmdTargetAddr != null && !this.hasSymbolNamed(program, ipcCmdTargetAddr, label))
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
                    
                    program.getListing().setComment(ipcCmdImplAddr, CommentType.PLATE,
                        this.formatIpcComment(trace, cmdName, ipcCmdImplAddr));

                    if (ipcCmdTargetAddr != null)
                    {
                        program.getListing().setComment(ipcCmdTargetAddr, CommentType.PLATE,
                            this.formatIpcComment(trace, cmdName, ipcCmdImplAddr));
                        this.renameBranchTargetBufferParams(program, trace, ipcCmdTargetAddr);
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
                            String entryNameNoSuffix = entry.abvName.replace("::vtable", "");
                            sTableName = entryNameNoSuffix + "::s_Table";
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

    private String formatIpcComment(IPCTrace trace, String cmdName, Address dispatchFuncAddr)
    {
        StringBuilder comment = new StringBuilder();

        comment.append(String.format("""
            IPC INFORMATION
            Dispatch Func:     0x%X
            Command:           0x%X
            Command Dec:       %d
            Command Name:      %s
            LR:                0x%X
            VT Offset:         0x%X
            Bytes In:          0x%X
            Bytes Out:         0x%X
            Buffer Count:      0x%X
            """,
            dispatchFuncAddr.getOffset(), trace.cmdId, trace.cmdId,
            cmdName != null ? cmdName : "<unknown>",
            trace.lr, trace.vtOffset,
            trace.bytesIn, trace.bytesOut, trace.bufferCount));

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

    private void renameBranchTargetBufferParams(Program program, IPCTrace trace, Address ipcCmdTargetAddr)
    {
        if (!trace.hasBufferAttrs())
            return;

        Function function = program.getFunctionManager().getFunctionAt(ipcCmdTargetAddr);

        if (function == null)
            return;

        List<Integer> bufferParamOrdinals = this.findBranchTargetBufferParamOrdinals(program, ipcCmdTargetAddr,
            trace.bufferAttrs.length);

        if (bufferParamOrdinals.size() != trace.bufferAttrs.length)
        {
            Msg.debug(this, String.format(
                "Skipping IPC buffer parameter rename at 0x%X: expected %d buffer params, found %d",
                ipcCmdTargetAddr.getOffset(), trace.bufferAttrs.length, bufferParamOrdinals.size()));
            return;
        }

        int maxOrdinal = bufferParamOrdinals.stream().mapToInt(Integer::intValue).max().orElse(-1);

        if (function.getParameterCount() <= maxOrdinal)
        {
            if (!this.commitBranchTargetRegisterParams(program, function, bufferParamOrdinals, trace.bufferAttrs))
            {
                Msg.debug(this, String.format(
                    "Skipping IPC buffer parameter rename at 0x%X: function has %d params, needs ordinal %d",
                    ipcCmdTargetAddr.getOffset(), function.getParameterCount(), maxOrdinal));
                return;
            }
        }

        int inIndex = 0;
        int outIndex = 0;
        int inOutIndex = 0;

        for (int i = 0; i < trace.bufferAttrs.length; i++)
        {
            int attr = trace.bufferAttrs[i];
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

            Parameter parameter = function.getParameter(bufferParamOrdinals.get(i));

            if (parameter == null || parameter.getName().equals(name))
                continue;

            try
            {
                parameter.setName(name, SourceType.ANALYSIS);
            }
            catch (DuplicateNameException | InvalidInputException e)
            {
                Msg.warn(this, String.format("Failed to rename IPC buffer parameter '%s' at 0x%X: %s",
                    name, ipcCmdTargetAddr.getOffset(), e.getMessage()));
            }
        }
    }

    private boolean commitBranchTargetRegisterParams(Program program, Function function,
                                                     List<Integer> bufferParamOrdinals, int[] bufferAttrs)
    {
        int maxOrdinal = Math.max(
            bufferParamOrdinals.stream().mapToInt(Integer::intValue).max().orElse(-1),
            this.findMaxReferencedParamOrdinal(program, function.getEntryPoint()));

        if (maxOrdinal < 0)
            return false;

        Map<Integer, String> bufferParamNames = new HashMap<>();
        int inIndex = 0;
        int outIndex = 0;
        int inOutIndex = 0;

        for (int i = 0; i < bufferAttrs.length; i++)
        {
            int attr = bufferAttrs[i];
            boolean isIn = (attr & IPCTrace.BUFFER_ATTR_IN) != 0;
            boolean isOut = (attr & IPCTrace.BUFFER_ATTR_OUT) != 0;
            String name;

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

        List<Variable> parameters = new ArrayList<>();

        try
        {
            for (int ordinal = 0; ordinal <= maxOrdinal; ordinal++)
            {
                Parameter existing = ordinal < function.getParameterCount() ? function.getParameter(ordinal) : null;
                String name = bufferParamNames.get(ordinal);

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
    
    private Map<Address, Address> gotDataSyms = null;
    
    /**
     * A map of relocated entries in the global offset table to their new values.
     */
    protected Map<Address, Address> getGotDataSyms(Program program, ElfCompatibilityProvider elfProvider) throws MemoryAccessException {
        if (gotDataSyms != null)
            return this.gotDataSyms;
        
        Address baseAddr = program.getImageBase();
        gotDataSyms = new HashMap<>();
        MemoryBlock gotBlock = program.getMemory().getBlock(".got");
        
        for (NXRelocation reloc : elfProvider.getRelocations()) 
        {
            if (baseAddr.add(reloc.offset).getOffset() < gotBlock.getStart().getOffset() || baseAddr.add(reloc.offset).getOffset() > gotBlock.getEnd().getOffset() + 1)
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
           this.gotDataSyms.put(baseAddr.add(reloc.offset), baseAddr.add(off));
        }
        
        return gotDataSyms;
    }
    
public static String demangleIpcSymbol(String mangled)
{
    // Needed by the demangler
    if (!mangled.startsWith("_Z"))
        mangled = "_Z" + mangled;
 
    String out = mangled;
    
    try {
        // Use the new API: demangle(Program, String, Address)
        // Pass null for Program and Address since we're in a static method
        // This returns a List<DemangledObject>
        List<DemangledObject> demangledObjects = DemanglerUtil.demangle(null, mangled, null);
        
        // Use the first result if available
        if (demangledObjects != null && !demangledObjects.isEmpty())
        {
            DemangledObject demangledObj = demangledObjects.get(0);
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
    
    protected int createPointer(Program program, Address address)
    {
        Data d = program.getListing().getDataAt(address);
        
        if (d == null) 
        {
            try 
            {
                d = program.getListing().createData(address, PointerDataType.dataType, 8);
            } 
            catch (CodeUnitInsertionException e)
            {
                Msg.error(this, String.format("Failed to create pointer at 0x%X", address.getOffset()), e);
            }
        }
        
        return d.getLength();
    }
    
    public static class IPCVTableEntry
    {
        public final String fullName;
        public final String abvName;
        public final Address addr;
        public final ImmutableList<Address> ipcFuncs;
        
        private IPCVTableEntry(String fullName, String abvName, Address addr, List<Address> ipcFuncs)
        {
            this.fullName = fullName;
            this.abvName = abvName;
            this.addr = addr;
            this.ipcFuncs = ImmutableList.copyOf(ipcFuncs);
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
            if (!block.getName().equals(".data") || !block.isInitialized())
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
            if (!block.getName().equals(".data") || !block.isInitialized())
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

                if (!isPotentialIpcVtableName(shortName))
                {
                    Msg.debug(this, String.format("RTTI scan: skipping non-IPC vtable 0x%X -> %s", off, shortName));
                    continue;
                }

                Address vtAddr = aSpace.getAddress(off);

                // Verify this is actually a dispatcher vtable by checking that +0x30 points into .text.
                // If not, try +0x8 in case the address is off by one slot.
                try
                {
                    long funcPtr = mem.getLong(vtAddr.add(0x30));
                    Address funcAddr = aSpace.getAddress(funcPtr);
                    MemoryBlock funcBlock = mem.getBlock(funcAddr);
                    
                    if (funcBlock == null || !funcBlock.getName().equals(".text"))
                    {
                        // Try shifting by +0x8
                        Address shiftedVtAddr = vtAddr.add(0x8);
                        long shiftedFuncPtr = mem.getLong(shiftedVtAddr.add(0x30));
                        Address shiftedFuncAddr = aSpace.getAddress(shiftedFuncPtr);
                        MemoryBlock shiftedFuncBlock = mem.getBlock(shiftedFuncAddr);
                        
                        if (shiftedFuncBlock != null && shiftedFuncBlock.getName().equals(".text"))
                        {
                            Msg.info(this, String.format("RTTI scan: shifting vtable 0x%X -> 0x%X (first func in .text after +0x8)", off, shiftedVtAddr.getOffset()));
                            vtAddr = shiftedVtAddr;
                        }
                        else
                        {
                            // Neither offset has .text functions — skip this entry
                            Msg.debug(this, String.format("RTTI scan: skipping 0x%X, no .text functions at +0x30 or +0x38", off));
                            if (isConcreteServiceInterfaceVtableName(shortName))
                            {
                                pendingInterfaceVtableName = shortName;
                                pendingInterfaceVtableOff = off;
                                Msg.debug(this, String.format("RTTI scan: pending interface name %s from 0x%X", shortName, off));
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
