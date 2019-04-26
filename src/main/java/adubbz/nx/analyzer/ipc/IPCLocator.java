/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.analyzer.ipc;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.compress.utils.Lists;
import org.python.google.common.collect.HashBiMap;
import org.python.google.common.collect.ImmutableBiMap;
import org.python.google.common.collect.Maps;
import org.python.google.common.collect.Sets;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Multimap;

import adubbz.nx.analyzer.ipc.IPCLocator.IPCVTableEntry;
import adubbz.nx.common.NXRelocation;
import adubbz.nx.loader.nxo.NXOAdapter;
import adubbz.nx.loader.nxo.NXOHeader;
import adubbz.nx.loader.nxo.NXOSection;
import adubbz.nx.loader.nxo.NXOSectionType;
import generic.stl.Pair;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.pcode.emulate.BreakTable;
import ghidra.pcode.emulate.BreakTableCallBack;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.memstate.MemoryBank;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.pcode.memstate.MemoryPageBank;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class IPCLocator 
{
    protected Program program;
    protected AddressSpace aSpace;
    protected NXOHeader nxo;
    protected TaskMonitor monitor;
    
    protected List<Address> vtAddrs = new ArrayList<>();
    protected HashBiMap<Address, Address> sTableProcessFuncMap = HashBiMap.create();
    protected Multimap<Address, IPCTrace> processFuncTraces = HashMultimap.create();
    protected HashBiMap<Address, IPCVTableEntry> procFuncVtMap = HashBiMap.create();
    
    protected List<IPCVTableEntry> vtEntries = new ArrayList<>();
    
    public IPCLocator(Program program, AddressSpace aSpace, NXOHeader nxo, TaskMonitor monitor)
    {
        this.program = program;
        this.aSpace = aSpace;
        this.nxo = nxo;
        this.monitor = monitor;
        
        try
        {
            this.locateIpcVtables();
            this.createVTableEntries(vtAddrs);
            this.locateSTables();
            this.emulateProcessFunctions();
            this.matchVtables();
        }
        catch (Exception e)
        {
            Msg.error(this, "Failed to analyze binary IPC.", e);
        }
    }
    
    protected void locateIpcVtables() throws MemoryAccessException, AddressOutOfBoundsException, IOException
    {
        NXOAdapter adapter = this.nxo.getAdapter();
        NXOSection rodata = adapter.getSection(NXOSectionType.RODATA);
        NXOSection data = adapter.getSection(NXOSectionType.DATA);
        Memory mem = this.program.getMemory();
        SymbolTable symbolTable = this.program.getSymbolTable();
        
        Map<String, Long> knownVTabOffsets = new HashMap<>();
        
        // Locate some initial vtables based on RTTI
        for (Address vtAddr : this.getGotDataSyms().values()) 
        {
            try
            {
                long vtOff = vtAddr.getOffset() - this.nxo.getBaseAddress();
                
                if (vtOff >= data.getOffset() && vtOff < (data.getOffset() + data.getSize()))
                {
                    long rttiOffset = mem.getLong(vtAddr.add(8)) - this.nxo.getBaseAddress();
                    
                    if (rttiOffset >= data.getOffset() && rttiOffset < (data.getOffset() + data.getSize()))
                    {
                        long thisOffset = mem.getLong(this.aSpace.getAddress(this.nxo.getBaseAddress() + rttiOffset + 8)) - this.nxo.getBaseAddress();
                        
                        if (thisOffset >= rodata.getOffset() && thisOffset < (rodata.getOffset() + rodata.getSize()))
                        {
                            String symbol = adapter.getMemoryReader().readTerminatedString(thisOffset, '\0');
                            
                            if (symbol.isEmpty() || symbol.length() > 512)
                                continue;
                            
                            if (symbol.contains("UnmanagedServiceObject") || symbol.equals("N2nn2sf4cmif6server23CmifServerDomainManager6DomainE"))
                            {
                                knownVTabOffsets.put(symbol, vtOff);
                                Msg.info(this, String.format("Service sym %s at 0x%X", symbol, this.nxo.getBaseAddress() + thisOffset));
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
        
        if (knownVTabOffsets.isEmpty())
            return;
        
        // All IServiceObjects share a common non-overridable virtual function at vt + 0x20
        // and thus that value can be used to distinguish a virtual table vs a non-virtual table.
        // Here we locate the address of that function.
        long knownAddress = 0;
        
        for (long off : knownVTabOffsets.values())
        {
            long curKnownAddr = mem.getLong(this.aSpace.getAddress(this.nxo.getBaseAddress() + off + 0x20));
            
            if (knownAddress == 0)
            {
                knownAddress = curKnownAddr; 
            }
            else if (knownAddress != curKnownAddr) return;
        }
        
        Msg.info(this, String.format("Known service address: 0x%x", knownAddress));
        
        // Use the known function to find all IPC vtables
        for (Address vtAddr : this.getGotDataSyms().values()) 
        {
            try
            {
                long vtOff = vtAddr.getOffset() - this.nxo.getBaseAddress();
                    
                if (vtOff >= data.getOffset() && vtOff < (data.getOffset() + data.getSize()))
                {
                    if (knownAddress == mem.getLong(vtAddr.add(0x20)))
                    {
                        this.vtAddrs.add(vtAddr);
                    }
                }
            }
            catch (MemoryAccessException e) // Skip entries with out of bounds offsets
            {
                continue;
            }
        }
    }
    
    protected void createVTableEntries(List<Address> vtAddrs) throws MemoryAccessException, AddressOutOfBoundsException, IOException
    {
        Memory mem = this.program.getMemory();
        NXOAdapter adapter = this.nxo.getAdapter();
        NXOSection text = adapter.getSection(NXOSectionType.TEXT);
        NXOSection data = adapter.getSection(NXOSectionType.DATA);
        NXOSection rodata = adapter.getSection(NXOSectionType.RODATA);
        
        for (Address vtAddr : vtAddrs)
        {
            long vtOff = vtAddr.getOffset();
            long rttiBase = mem.getLong(this.aSpace.getAddress(vtOff + 0x8)) - this.nxo.getBaseAddress();
            String name = String.format("SRV_%X::vtable", vtOff);
            
            // Attempt to find the name if the vtable has RTTI
            if (rttiBase != 0)
            {
                // RTTI must be within the data block
                if (rttiBase >= data.getOffset() && rttiBase < (data.getOffset() + data.getSize()))
                {
                    long thisOff = mem.getLong(this.aSpace.getAddress(this.nxo.getBaseAddress() + rttiBase + 8)) - this.nxo.getBaseAddress();
                    
                    if (thisOff >= rodata.getOffset() && thisOff < (rodata.getOffset() + rodata.getSize()))
                    {
                        String symbol = adapter.getMemoryReader().readTerminatedString(thisOff, '\0');
                        
                        if (!symbol.isEmpty() && symbol.length() <= 512)
                        {
                            if (!symbol.startsWith("_Z"))
                                symbol = "_ZTV" + symbol;
                            
                            name = demangleIpcSymbol(symbol);
                        }
                    }
                }
            }
            
            List<Address> implAddrs = new ArrayList<>();
            long funcVtOff = 0x30;
            long funcOff = 0;
            
            // Find all ipc impl functions in the vtable
            while ((funcOff = mem.getLong(vtAddr.add(funcVtOff))) != 0)
            {
                long funcRelOff = funcOff - this.nxo.getBaseAddress();
                
                if (funcRelOff >= text.getOffset() && funcRelOff < (text.getOffset() + text.getSize()))
                {
                    implAddrs.add(this.aSpace.getAddress(funcOff));
                    funcVtOff += 0x8;
                }
                else break;
            
                if (this.getGotDataSyms().values().contains(vtAddr.add(funcVtOff)))
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
            
            this.vtEntries.add(new IPCVTableEntry(name, shortName, vtAddr, implAddrs));
        }
    }
    
    protected void locateSTables() throws IOException
    {
        List<Pair<Long, Long>> candidates = new ArrayList<>();
        
        for (NXRelocation reloc : this.nxo.getRelocations()) 
        {
            if (reloc.addend > 0)
                candidates.add(new Pair(reloc.addend, reloc.offset));
        }
        
        candidates.sort((a, b) -> a.first.compareTo(b.first));
        
        NXOAdapter adapter = this.nxo.getAdapter();
        NXOSection text = adapter.getSection(NXOSectionType.TEXT);
        
        // 5.x: match on the "SFCI" constant used in the template of s_Table
        //   MOV  W?, #0x4653
        //   MOVK W?, #0x4943, LSL#16
        long movMask  = 0x5288CAL;
        long movkMask = 0x72A928L;
        
        for (long off = text.getOffset(); off < (text.getOffset() + text.getSize()); off += 0x4)
        {
            long val1 = (this.nxo.getAdapter().getMemoryReader().readUnsignedInt(off) & 0xFFFFFF00L) >> 8;
            long val2 = (this.nxo.getAdapter().getMemoryReader().readUnsignedInt(off + 0x4) & 0xFFFFFF00L) >> 8;
            
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
                for (pRetOff = processFuncOffset; pRetOff < (text.getOffset() + text.getSize()); pRetOff += 0x4)
                {
                    long rval = this.nxo.getAdapter().getMemoryReader().readUnsignedInt(pRetOff);
                    
                    // RET
                    if (rval == 0xD65F03C0L)
                        break;
                }
                
                if (pRetOff > off)
                {
                    Address stAddr = this.aSpace.getAddress(this.nxo.getBaseAddress() + sTableOffset);
                    Address pFuncAddr = this.aSpace.getAddress(this.nxo.getBaseAddress() + processFuncOffset);
                    this.sTableProcessFuncMap.put(stAddr, pFuncAddr);
                }
            }
        }
    }
    
    protected void emulateProcessFunctions() throws MemoryAccessException
    {
        IPCEmulator ipcEmu = new IPCEmulator(this.program, this);
        Set<Integer> cmdsToTry = Sets.newHashSet();
        
        // Bruteforce 0-1000
        //for (int i = 0; i <= 1000; i++)
            //cmdsToTry.add(i);
        
        // The rest we add ourselves. From SwIPC. Duplicates are avoided by using a set
        int[] presets = new int[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 4201, 106, 107, 108, 4205, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 20501, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 2413, 8216, 150, 151, 2201, 2202, 2203, 2204, 2205, 2207, 10400, 2209, 8219, 8220, 8221, 30900, 30901, 30902, 8223, 90300, 190, 8224, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 220, 20701, 222, 223, 230, 231, 250, 251, 252, 2301, 2302, 255, 256, 10500, 261, 2312, 280, 290, 291, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 2101, 20800, 20801, 322, 323, 2102, 8250, 350, 2400, 2401, 2402, 2403, 2404, 2405, 10600, 10601, 2411, 2412, 2450, 2414, 8253, 10610, 2451, 2421, 2422, 2424, 8255, 2431, 8254, 2433, 2434, 406, 8257, 400, 401, 402, 403, 404, 405, 10300, 407, 408, 409, 410, 411, 2460, 20900, 8252, 412, 2501, 10700, 10701, 10702, 8200, 1106, 1107, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511, 512, 513, 520, 521, 90200, 8201, 90201, 540, 30810, 542, 543, 544, 545, 546, 30811, 30812, 8202, 8203, 8291, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 614, 8295, 620, 8204, 8296, 630, 105, 640, 4203, 8225, 2050, 109, 30830, 2052, 8256, 700, 701, 702, 703, 704, 705, 706, 707, 708, 709, 8207, 20600, 8208, 49900, 751, 11000, 127, 8209, 800, 801, 802, 803, 804, 805, 806, 821, 822, 823, 824, 8211, 850, 851, 852, 7000, 2055, 900, 901, 902, 903, 904, 905, 906, 907, 908, 909, 3000, 3001, 3002, 160, 8012, 8217, 8013, 320, 997, 998, 999, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1020, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1061, 1062, 1063, 21000, 1100, 1101, 1102, 2053, 5202, 5203, 8218, 3200, 3201, 3202, 3203, 3204, 3205, 3206, 3207, 3208, 3209, 3210, 3211, 3214, 3215, 3216, 3217, 40100, 40101, 541, 1200, 1201, 1202, 1203, 1204, 1205, 1206, 1207, 1208, 8292, 547, 20500, 8293, 2054, 2601, 8294, 40200, 40201, 1300, 1301, 1302, 1303, 1304, 8227, 20700, 221, 8228, 8297, 8229, 4206, 1400, 1401, 1402, 1403, 1404, 1405, 1406, 1411, 1421, 1422, 1423, 1424, 30100, 30101, 30102, 1431, 1432, 30110, 30120, 30121, 1451, 1452, 1453, 1454, 1455, 1456, 1457, 1458, 1471, 1472, 1473, 1474, 1500, 1501, 1502, 1503, 1504, 1505, 2300, 30200, 30201, 30202, 30203, 30204, 30205, 30210, 30211, 30212, 30213, 30214, 30215, 30216, 30217, 260, 1600, 1601, 1602, 1603, 60001, 60002, 30300, 2051, 20100, 20101, 20102, 20103, 20104, 20110, 1700, 1701, 1702, 1703, 8222, 30400, 30401, 30402, 631, 20200, 20201, 1800, 1801, 1802, 1803, 2008, 10011, 30500, 7992, 7993, 7994, 7995, 7996, 7997, 7998, 7999, 8000, 8001, 8002, 8011, 20300, 20301, 8021, 1900, 1901, 1902, 6000, 6001, 6002, 10100, 10101, 10102, 10110, 30820, 321, 1941, 1951, 1952, 1953, 8100, 20400, 20401, 8210, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 10200, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 10211, 2020, 2021, 30700, 2030, 2031, 8251, 90100, 90101, 90102 };
        
        for (int preset : presets)
            cmdsToTry.add(preset);
        
        Multimap<Address, IPCTrace> map = HashMultimap.create();
        
        int maxProgress = this.getProcessFuncAddrs().size() * cmdsToTry.size();
        int progress = 0;
        
        monitor.setMessage("Emulating IPC process functions...");
        monitor.initialize(maxProgress);
        
        for (Address procFuncAddr : this.getProcessFuncAddrs())
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
                this.processFuncTraces.put(procFuncAddr, trace);
            }
        }     
    }
    
    protected int getProcFuncVTableSize(Address procFuncAddr)
    {
        if (!this.processFuncTraces.containsKey(procFuncAddr) || this.processFuncTraces.get(procFuncAddr).isEmpty())
            return 0;
        
        IPCTrace maxTrace = null;
        
        for (IPCTrace trace : this.processFuncTraces.get(procFuncAddr))
        {
            if (trace.vtOffset == -1)
                continue;
            
            if (maxTrace == null || trace.vtOffset > maxTrace.vtOffset)
                maxTrace = trace;
        }
        
        return (int)Math.max(this.processFuncTraces.get(procFuncAddr).size(), (maxTrace.vtOffset + 8 - 0x20) / 8);
    }
    
    protected void matchVtables()
    {
        // Map process func addrs to vtable addrs
        List<IPCVTableEntry> possibilities = Lists.newArrayList(this.getVTableEntries().iterator());
        
        for (Address procFuncAddr : this.getProcessFuncAddrs())
        {
            // We've already found this address. No need to do it again
            if (this.procFuncVtMap.keySet().contains(procFuncAddr))
                continue;
            
            List<IPCVTableEntry> filteredPossibilities = possibilities.stream().filter(vtEntry -> vtEntry.ipcFuncs.size() == getProcFuncVTableSize(procFuncAddr)).collect(Collectors.toList());
            
            // See if there is a single entry that *exactly* matches the vtable size
            if (filteredPossibilities.size() == 1)
            {
                IPCVTableEntry vtEntry = filteredPossibilities.get(0);
                this.procFuncVtMap.put(procFuncAddr, vtEntry);
                possibilities.remove(vtEntry);
                continue;
            }
            
            filteredPossibilities = possibilities.stream().filter(vtEntry -> vtEntry.ipcFuncs.size() >= getProcFuncVTableSize(procFuncAddr)).collect(Collectors.toList());

            // See if there is a single entry that is equal to or greater than the vtable size
            if (filteredPossibilities.size() == 1)
            {
                IPCVTableEntry vtEntry = filteredPossibilities.get(0);
                this.procFuncVtMap.put(procFuncAddr, vtEntry);
                possibilities.remove(vtEntry);
                continue;
            }
            
            // Iterate over all the possible vtables with a size greater than our current process function
            for (IPCVTableEntry filteredPossibility : filteredPossibilities)
            {
                List<Address> unlocatedProcFuncAddrs = this.getProcessFuncAddrs().stream().filter(pFAddr -> !procFuncVtMap.keySet().contains(pFAddr)).collect(Collectors.toList());
                
                // See if there is only a single trace set of size <= this vtable
                // For example, if the process func vtable size is found by emulation to be 0x100, and we have previously found vtables of the following sizes, which have yet to be located:
                // 0x10, 0x20, 0x60, 0x110, 0x230
                // We will run this loop for both 0x110 and 0x230. 
                // In the case of 0x110, we will then filter for sizes <= 0x110. These are 0x10, 0x20, 0x60 and 0x110
                // As there are four of these, the check will fail.
                if (unlocatedProcFuncAddrs.stream().filter(unlocatedProcFuncAddr -> getProcFuncVTableSize(unlocatedProcFuncAddr) <= filteredPossibility.ipcFuncs.size()).collect(Collectors.toList()).size() == 1)
                {
                    this.procFuncVtMap.put(procFuncAddr, filteredPossibility);
                    possibilities.remove(filteredPossibility);
                    break;
                }
            }
        }
        
        List<Address> unlocatedProcFuncAddrs = this.getProcessFuncAddrs().stream().filter(pFAddr -> !procFuncVtMap.keySet().contains(pFAddr)).collect(Collectors.toList());
        
        for (Address addr : unlocatedProcFuncAddrs)
        {
            Msg.info(this, String.format("Unmatched process func at 0x%X. Calculated VTable Size: 0x%X", addr.getOffset(), getProcFuncVTableSize(addr)));
        }
        
        for (IPCVTableEntry entry : possibilities)
        {
            Msg.info(this, String.format("Unmatched IPC VTable entry at 0x%X. VTable Size: 0x%X", entry.addr.getOffset(), entry.ipcFuncs.size()));
        }
    }
    
    private Map<Address, Address> gotDataSyms = null;
    
    /**
     * A map of relocated entries in the global offset table to their new values.
     */
    protected Map<Address, Address> getGotDataSyms()
    {
        if (gotDataSyms != null)
            return this.gotDataSyms;
        
        gotDataSyms = new HashMap<Address, Address>();
        
        for (NXRelocation reloc : this.nxo.getRelocations()) 
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
           this.gotDataSyms.put(this.aSpace.getAddress(this.nxo.getBaseAddress() + reloc.offset), this.aSpace.getAddress(this.nxo.getBaseAddress() + off));
        }
        
        return gotDataSyms;
    }
    
    public ImmutableList<IPCVTableEntry> getVTableEntries()
    {
        return ImmutableList.copyOf(this.vtEntries);
    }
    
    public ImmutableSet<Address> getSTableAddrs()
    {
        return ImmutableSet.copyOf(this.sTableProcessFuncMap.keySet());
    }
    
    public ImmutableList<Address> getProcessFuncAddrs()
    {
        return ImmutableList.copyOf(this.sTableProcessFuncMap.values());
    }
    
    public Address getProcFuncAddrFromSTableAddr(Address sTableAddr)
    {
        return this.sTableProcessFuncMap.get(sTableAddr);
    }
    
    public Address getSTableFromProcessFuncAddr(Address procFuncAddr)
    {
        return this.sTableProcessFuncMap.inverse().get(procFuncAddr);
    }
    
    public IPCVTableEntry getIPCVTableEntryFromProcessFuncAddr(Address processFuncAddr)
    {
        return this.procFuncVtMap.get(processFuncAddr);
    }
    
    public Address getProcessFuncAddrFromVtEntry(IPCVTableEntry entry)
    {
        return this.procFuncVtMap.inverse().get(entry);
    }
    
    public Collection<IPCTrace> getProcessFuncTraces(Address processFuncAddr)
    {
        return this.processFuncTraces.get(processFuncAddr);
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
