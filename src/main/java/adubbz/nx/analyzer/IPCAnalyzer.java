/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.analyzer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.compress.utils.Lists;
import org.python.google.common.collect.HashBiMap;
import org.python.google.common.collect.Sets;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Multimap;

import adubbz.nx.analyzer.ipc.IPCEmulator;
import adubbz.nx.analyzer.ipc.IPCTrace;
import adubbz.nx.common.ElfCompatibilityProvider;
import adubbz.nx.common.NXRelocation;
import adubbz.nx.loader.SwitchLoader;
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
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class IPCAnalyzer extends AbstractAnalyzer 
{
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
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException 
    {
        Memory memory = program.getMemory();
        MemoryBlock text = memory.getBlock(".text");
        MemoryBlock rodata = memory.getBlock(".rodata");
        MemoryBlock data = memory.getBlock(".data");
        ElfCompatibilityProvider elfCompatProvider = new ElfCompatibilityProvider(program);
        
        Msg.info(this, "Beginning IPC analysis...");
        
        if (text == null || rodata == null || data == null)
            return true;
        
        try
        {
            List<Address> vtAddrs = this.locateIpcVtables(program, elfCompatProvider);
            List<IPCVTableEntry> vtEntries = this.createVTableEntries(program, elfCompatProvider, vtAddrs);
            HashBiMap<Address, Address> sTableProcessFuncMap = this.locateSTables(program, elfCompatProvider);
            Multimap<Address, IPCTrace> processFuncTraces = this.emulateProcessFunctions(program, monitor, sTableProcessFuncMap.values());
            HashBiMap<Address, IPCVTableEntry> procFuncVtMap = this.matchVtables(vtEntries, sTableProcessFuncMap.values(), processFuncTraces);
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
        
        Msg.info(this, "Locating IPC vtables...");
        
        // NOTE: We can't get the .<bla> block and check if it contains an address, as there may be multiple
        // blocks with the same name, which Ghidra doesn't account for.
        
        // Locate some initial vtables based on RTTI
        for (Address vtAddr : gotDataSyms.values()) 
        {
            MemoryBlock vtBlock = mem.getBlock(vtAddr);
            
            try
            {
                if (vtBlock != null && vtBlock.getName().equals(".data"))
                {
                    Address rttiAddr = aSpace.getAddress(mem.getLong(vtAddr.add(8)));
                    MemoryBlock rttiBlock = mem.getBlock(rttiAddr);
                    
                    if (rttiBlock != null && rttiBlock.getName().equals(".data"))
                    {
                        Address thisAddr = aSpace.getAddress(mem.getLong(rttiAddr.add(0x8)));
                        MemoryBlock thisBlock = mem.getBlock(thisAddr);
                        
                        if (thisBlock != null && thisBlock.getName().equals(".rodata"))
                        {
                            String symbol = elfProvider.getReader().readTerminatedString(thisAddr.getOffset(), '\0');
                            
                            if (symbol.isEmpty() || symbol.length() > 512)
                                continue;
                            
                            if (symbol.contains("UnmanagedServiceObject") || symbol.equals("N2nn2sf4cmif6server23CmifServerDomainManager6DomainE"))
                            {
                                knownVTabAddrs.put(symbol, vtAddr);
                                Msg.info(this, String.format("Service sym %s at 0x%X", symbol, thisAddr.getOffset()));
                            }
                        }
                    }
                }
            }
            catch (MemoryAccessException e) // Skip entries with out of bounds offsets
            {
                continue;
            }
        }
        
        if (knownVTabAddrs.isEmpty())
            return out;
        
        // All IServiceObjects share a common non-overridable virtual function at vt + 0x20
        // and thus that value can be used to distinguish a virtual table vs a non-virtual table.
        // Here we locate the address of that function.
        long knownAddress = 0;
        
        for (Address addr : knownVTabAddrs.values())
        {
            long curKnownAddr = mem.getLong(addr.add(0x20));
            
            if (knownAddress == 0)
            {
                knownAddress = curKnownAddr; 
            }
            else if (knownAddress != curKnownAddr) 
                return out;
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
                    if (knownAddress == mem.getLong(vtAddr.add(0x20)))
                    {
                        out.add(vtAddr);
                    }
                }
            }
            catch (MemoryAccessException e) // Skip entries with out of bounds offsets
            {
                continue;
            }
        }
        
        return out;
    }
    
    protected List<IPCVTableEntry> createVTableEntries(Program program, ElfCompatibilityProvider elfProvider, List<Address> vtAddrs) throws MemoryAccessException, AddressOutOfBoundsException, IOException
    {
        List<IPCVTableEntry> out = Lists.newArrayList();
        Memory mem = program.getMemory();
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        
        for (Address vtAddr : vtAddrs)
        {
            long vtOff = vtAddr.getOffset();
            long rttiBase = mem.getLong(vtAddr.add(0x8));
            String name = String.format("SRV_%X::vtable", vtOff);
            
            // Attempt to find the name if the vtable has RTTI
            if (rttiBase != 0)
            {
                Address rttiBaseAddr = aSpace.getAddress(rttiBase);
                MemoryBlock rttiBaseBlock = mem.getBlock(rttiBaseAddr);
                
                // RTTI must be within the data block
                if (rttiBaseBlock != null && rttiBaseBlock.getName().equals(".data"))
                {
                    Address thisAddr = aSpace.getAddress(mem.getLong(rttiBaseAddr.add(0x8)));
                    MemoryBlock thisBlock = mem.getBlock(thisAddr);
                    
                    if (thisBlock != null && thisBlock.getName().equals(".rodata"))
                    {
                        String symbol = elfProvider.getReader().readTerminatedString(thisAddr.getOffset(), '\0');
                        
                        if (!symbol.isEmpty() && symbol.length() <= 512)
                        {
                            if (!symbol.startsWith("_Z"))
                                symbol = "_ZTV" + symbol;
                            
                            name = demangleIpcSymbol(symbol);
                        }
                    }
                }
            }
            
            Map<Address, Address> gotDataSyms = this.getGotDataSyms(program, elfProvider);
            List<Address> implAddrs = new ArrayList<>();
            long funcVtOff = 0x30;
            long funcOff = 0;
            
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
                else break;
            
                if (gotDataSyms.values().contains(vtAddr.add(funcVtOff)))
                {
                    break;
                }
            }
            
            Set<Address> uniqueAddrs = new HashSet<Address>(implAddrs);
            
            // There must be either 1 unique function without repeats, or more than one unique function with repeats allowed
            if (uniqueAddrs.size() <= 1 && implAddrs.size() != 1)
            {
                Msg.info(this, String.format("Insufficient unique addresses for vtable at 0x%X", vtAddr.getOffset()));
                
                for (Address addr : uniqueAddrs)
                {
                    Msg.info(this, String.format("    Found: 0x%X", addr.getOffset()));
                }
                
                implAddrs.clear();
            }
            
            // Some IPC symbols are very long and Ghidra crops them off far too early by default.
            // Let's shorten these.
            String shortName = shortenIpcSymbol(name);
            
            out.add(new IPCVTableEntry(name, shortName, vtAddr, implAddrs));
        }
        
        return out;
    }
    
    protected HashBiMap<Address, Address> locateSTables(Program program, ElfCompatibilityProvider elfProvider)
    {
        HashBiMap<Address, Address> out = HashBiMap.create();
        List<Pair<Long, Long>> candidates = new ArrayList<>();
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        Address baseAddr = program.getImageBase();
        Memory mem = program.getMemory();
        
        for (NXRelocation reloc : elfProvider.getRelocations()) 
        {
            if (reloc.addend > 0)
                candidates.add(new Pair(baseAddr.getOffset() + reloc.addend, baseAddr.getOffset() + reloc.offset));
        }
        
        candidates.sort((a, b) -> a.first.compareTo(b.first));
        
        
        // 5.x: match on the "SFCI" constant used in the template of s_Table
        //   MOV  W?, #0x4653
        //   MOVK W?, #0x4943, LSL#16
        long movMask  = 0x5288CAL;
        long movkMask = 0x72A928L;
        
        MemoryBlock text = mem.getBlock(".text"); // Text is one of the few blocks that isn't split
        
        try
        {
            for (long off = text.getStart().getOffset(); off < text.getEnd().getOffset(); off += 0x4)
            {
                long val1 = (elfProvider.getReader().readUnsignedInt(off) & 0xFFFFFF00L) >> 8;
                long val2 = (elfProvider.getReader().readUnsignedInt(off + 0x4) & 0xFFFFFF00L) >> 8;
                
                // Match on a sequence of MOV, MOVK
                if (val1 == movMask && val2 == movkMask)
                {
                    long processFuncOffset = 0;
                    long sTableOffset = 0;
                    
                    // Find the candidate after our offset, then pick the one before that
                    for (Pair<Long, Long> candidate : candidates)
                    {
                        if (candidate.first > off)
                            break;
                        
                        processFuncOffset = candidate.first;
                        sTableOffset = candidate.second;
                    }
                    
                    long pRetOff;
                    
                    // Make sure our SFCI offset is within the process function by matching on the
                    // RET instruction
                    for (pRetOff = processFuncOffset; pRetOff < text.getEnd().getOffset(); pRetOff += 0x4)
                    {
                        long rval = elfProvider.getReader().readUnsignedInt(pRetOff);
                        
                        // RET
                        if (rval == 0xD65F03C0L)
                            break;
                    }
                    
                    if (pRetOff > off)
                    {
                        Address stAddr = aSpace.getAddress(sTableOffset);
                        Address pFuncAddr = aSpace.getAddress(processFuncOffset);
                        out.put(stAddr, pFuncAddr);
                    }
                }
            }
        }
        catch (IOException e)
        {
            Msg.error(this, "Failed to locate s_Tables", e);
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
            
            traces.sort((a, b) -> ((Long)a.cmdId).compareTo(b.cmdId));
            
            for (IPCTrace trace : traces)
            {
                out.put(procFuncAddr, trace);
            }
        }
        
        return out;
    }
    
    protected HashBiMap<Address, IPCVTableEntry> matchVtables(List<IPCVTableEntry> vtEntries, Set<Address> procFuncAddrs, Multimap<Address, IPCTrace> processFuncTraces)
    {
        // Map process func addrs to vtable addrs
        HashBiMap<Address, IPCVTableEntry> out = HashBiMap.create();
        List<IPCVTableEntry> possibilities = Lists.newArrayList(vtEntries.iterator());
        
        for (Address procFuncAddr : procFuncAddrs)
        {
            // We've already found this address. No need to do it again
            if (out.keySet().contains(procFuncAddr))
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
                List<Address> unlocatedProcFuncAddrs = procFuncAddrs.stream().filter(pFAddr -> !out.keySet().contains(pFAddr)).collect(Collectors.toList());
                
                // See if there is only a single trace set of size <= this vtable
                // For example, if the process func vtable size is found by emulation to be 0x100, and we have previously found vtables of the following sizes, which have yet to be located:
                // 0x10, 0x20, 0x60, 0x110, 0x230
                // We will run this loop for both 0x110 and 0x230. 
                // In the case of 0x110, we will then filter for sizes <= 0x110. These are 0x10, 0x20, 0x60 and 0x110
                // As there are four of these, the check will fail.
                if (unlocatedProcFuncAddrs.stream().filter(unlocatedProcFuncAddr -> getProcFuncVTableSize(processFuncTraces, unlocatedProcFuncAddr) <= filteredPossibility.ipcFuncs.size()).collect(Collectors.toList()).size() == 1)
                {
                    out.put(procFuncAddr, filteredPossibility);
                    possibilities.remove(filteredPossibility);
                    break;
                }
            }
        }
        
        List<Address> unlocatedProcFuncAddrs = procFuncAddrs.stream().filter(pFAddr -> !out.keySet().contains(pFAddr)).collect(Collectors.toList());
        
        for (Address addr : unlocatedProcFuncAddrs)
        {
            Msg.info(this, String.format("Unmatched process func at 0x%X. Calculated VTable Size: 0x%X", addr.getOffset(), getProcFuncVTableSize(processFuncTraces, addr)));
        }
        
        for (IPCVTableEntry entry : possibilities)
        {
            Msg.info(this, String.format("Unmatched IPC VTable entry at 0x%X. VTable Size: 0x%X", entry.addr.getOffset(), entry.ipcFuncs.size()));
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
                        program.getListing().setComment(entry.addr, CodeUnit.PLATE_COMMENT, ipcComment);
                    }
                    
                    ipcTraces = Lists.newArrayList(processFuncTraces.get(processFuncAddr).iterator());
                }
                    
                String entryNameNoSuffix = entry.abvName.replace("::vtable", "");
                
                // Set the vtable name
                if (!this.hasImportedSymbol(program, entry.addr))
                {
                    // For shortened names, leave a comment so the user knows what the original name is
                    if (entry.fullName != entry.abvName)
                        program.getListing().setComment(entry.addr, CodeUnit.REPEATABLE_COMMENT, entry.fullName);
                    
                    program.getSymbolTable().createLabel(entry.addr, entry.abvName, null, SourceType.IMPORTED);
                }
                
                // Label the four functions that exist for all ipc vtables
                for (int i = 0; i < 4; i++)
                {
                    Address vtAddr = entry.addr.add(0x10 + i * 0x8);
                    String name = "";
                    
                    // Set vtable func data types to pointers
                    this.createPointer(program, vtAddr);
                    
                    switch (i)
                    {
                        case 0:
                            name = "AddReference";
                            break;
                            
                        case 1:
                            name = "Release";
                            break;
                            
                        case 2:
                            name = "GetProxyInfo";
                            break;
                            
                        case 3: // Shared by everything
                            name = "nn::sf::IServiceObject::GetInterfaceTypeInfo";
                            break;
                    }
                             
                    if (i == 3) // For now, only label GetInterfaceTypeInfo. We need better heuristics for the others as they may be shared.
                    {
                        Address funcAddr = aSpace.getAddress(program.getMemory().getLong(vtAddr));
                        
                        if (!this.hasImportedSymbol(program, funcAddr))
                            program.getSymbolTable().createLabel(funcAddr, name, null, SourceType.IMPORTED);
                    }
                    else
                    {
                        program.getListing().setComment(vtAddr, CodeUnit.REPEATABLE_COMMENT, name);
                    }
                }
                
                for (int i = 0; i < entry.ipcFuncs.size(); i++)
                {
                    Address func = entry.ipcFuncs.get(i);
                    String name = null;
    
                    // Set vtable func data types to pointers
                    this.createPointer(program, entry.addr.add(0x30 + i * 0x8));
                }
                
                for (IPCTrace trace : ipcTraces)
                {
                    // Safety precaution. I *think* these should've been filtered out earlier though.
                    if (trace.vtOffset == -1 || !trace.hasDescription())
                        continue;
                    
                    Address vtOffsetAddr = entry.addr.add(0x10 + trace.vtOffset);
                    Address ipcCmdImplAddr = aSpace.getAddress(program.getMemory().getLong(vtOffsetAddr));
                    
                    if (!this.hasImportedSymbol(program, ipcCmdImplAddr))
                        program.getSymbolTable().createLabel(ipcCmdImplAddr, String.format("%s::Cmd%d", entryNameNoSuffix, trace.cmdId), null, SourceType.IMPORTED);
                    
                    String implComment = ""         +
                            "IPC INFORMATION\n"       +
                            "Bytes In:       0x%X\n"  +
                            "Bytes Out:      0x%X\n"  +
                            "Buffer Count:   0x%X\n"  +
                            "In Interfaces:  0x%X\n"  +
                            "Out Interfaces: 0x%X\n"  +
                            "In Handles:     0x%X\n"  +
                            "Out Handles:    0x%X";
                    
                    implComment = String.format(implComment, trace.bytesIn, trace.bytesOut, trace.bufferCount, trace.inInterfaces, trace.outInterfaces, trace.inHandles, trace.outHandles);
                    program.getListing().setComment(ipcCmdImplAddr, CodeUnit.PLATE_COMMENT, implComment);
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
        
        return (int)Math.max(processFuncTraces.get(procFuncAddr).size(), (maxTrace.vtOffset + 8 - 0x20) / 8);
    }
    
    private Map<Address, Address> gotDataSyms = null;
    
    /**
     * A map of relocated entries in the global offset table to their new values.
     */
    protected Map<Address, Address> getGotDataSyms(Program program, ElfCompatibilityProvider elfProvider)
    {
        if (gotDataSyms != null)
            return this.gotDataSyms;
        
        Address baseAddr = program.getImageBase();
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        gotDataSyms = new HashMap<Address, Address>();
        
        for (NXRelocation reloc : elfProvider.getRelocations()) 
        {
            long off;
            
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
        DemangledObject demangledObj = DemanglerUtil.demangle(mangled);
        
        // Where possible, replace the mangled symbol with a demangled one
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
        
        return out;
    }
    
    public static String shortenIpcSymbol(String longSym)
    {
        String out = longSym;
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
    
    protected int createPointer(Program program, Address address)
    {
        Data d = program.getListing().getDataAt(address);
        
        if (d == null) 
        {
            try 
            {
                d = program.getListing().createData(address, PointerDataType.dataType, 8);
            } 
            catch (CodeUnitInsertionException | DataTypeConflictException e) 
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
}
