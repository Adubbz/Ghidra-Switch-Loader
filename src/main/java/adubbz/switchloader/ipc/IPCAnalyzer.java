/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.switchloader.ipc;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.python.google.common.collect.Maps;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;

import adubbz.switchloader.common.NXRelocation;
import adubbz.switchloader.nxo.NXOAdapter;
import adubbz.switchloader.nxo.NXOHeader;
import adubbz.switchloader.nxo.NXOSection;
import adubbz.switchloader.nxo.NXOSectionType;
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

public class IPCAnalyzer 
{
    protected Program program;
    protected AddressSpace aSpace;
    protected NXOHeader nxo;
    
    protected List<Address> vtAddrs = new ArrayList<>();
    protected Map<Address, Address> sTableProcessFuncMap = Maps.newHashMap();
    
    protected List<IPCVTableEntry> vtEntries = new ArrayList<>();
    
    public IPCAnalyzer(Program program, AddressSpace aSpace, NXOHeader nxo)
    {
        this.program = program;
        this.aSpace = aSpace;
        this.nxo = nxo;
        
        try
        {
            this.locateIpcVtables();
            this.createVTableEntries(vtAddrs);
            this.locateSTables();
            this.emulateProcessFunctions();
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
            
            // There must be either 1 unique function without repeats, or more than one unique function with repeats allowed
            if (new HashSet<Address>(implAddrs).size() <= 1 && implAddrs.size() != 1)
            {
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
        
        for (Address procFuncAddr : this.getProcessFuncAddrs())
        {
            IPCTrace trace = ipcEmu.emulateCommand(procFuncAddr, 10);
            trace.printTrace();
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
    
    public List<IPCVTableEntry> getVTableEntries()
    {
        return this.vtEntries;
    }
    
    public Set<Address> getSTableAddrs()
    {
        return this.sTableProcessFuncMap.keySet();
    }
    
    public Collection<Address> getProcessFuncAddrs()
    {
        return this.sTableProcessFuncMap.values();
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
        
        if (out.startsWith("nn::sf::detail::ObjectImplFactoryWithStatelessAllocator<"))
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
        public final List<Address> ipcFuncs;
        
        private IPCVTableEntry(String fullName, String abvName, Address addr, List<Address> ipcFuncs)
        {
            this.fullName = fullName;
            this.abvName = abvName;
            this.addr = addr;
            this.ipcFuncs = ipcFuncs;
        }
    }
}
