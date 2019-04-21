/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.switchloader.common;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import adubbz.switchloader.nxo.NXOAdapter;
import adubbz.switchloader.nxo.NXOHeader;
import adubbz.switchloader.nxo.NXOSection;
import adubbz.switchloader.nxo.NXOSectionType;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;

public class IPCAnalyzer 
{
    protected Program program;
    protected AddressSpace aSpace;
    protected NXOHeader nxo;
    
    protected List<VTableEntry> vtEntries = new ArrayList<>();
    
    public IPCAnalyzer(Program program, AddressSpace aSpace, NXOHeader nxo)
    {
        this.program = program;
        this.aSpace = aSpace;
        this.nxo = nxo;
        
        try
        {
            List<Address> vtAddrs = this.locateIpcVtables();
            this.createVTableEntries(vtAddrs);
        }
        catch (Exception e)
        {
            Msg.error(this, "Failed to analyze binary IPC.", e);
        }
    }
    
    protected List<Address> locateIpcVtables() throws MemoryAccessException, AddressOutOfBoundsException, IOException
    {
        List<Address> out = new ArrayList<>();
        NXOAdapter adapter = this.nxo.getAdapter();
        NXOSection rodata = adapter.getSection(NXOSectionType.RODATA);
        NXOSection data = adapter.getSection(NXOSectionType.DATA);
        SymbolTable symbolTable = this.program.getSymbolTable();
        
        Map<String, Long> knownVTabOffsets = new HashMap<>();
        
        // Locate some initial vtables based on RTTI
        for (NXRelocation reloc : this.nxo.getRelocations()) 
        {
            try
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
                
                if (off >= data.getOffset() && off < (data.getOffset() + data.getSize()))
                {
                    long rttiOffset = this.program.getMemory().getLong(this.aSpace.getAddress(this.nxo.getBaseAddress() + off + 8)) - this.nxo.getBaseAddress();
                    
                    if (rttiOffset >= data.getOffset() && rttiOffset < (data.getOffset() + data.getSize()))
                    {
                        long thisOffset = this.program.getMemory().getLong(this.aSpace.getAddress(this.nxo.getBaseAddress() + rttiOffset + 8)) - this.nxo.getBaseAddress();
                        
                        if (thisOffset >= rodata.getOffset() && thisOffset < (rodata.getOffset() + rodata.getSize()))
                        {
                            String symbol = adapter.getMemoryReader().readTerminatedString(thisOffset, '\0');
                            
                            if (symbol.isEmpty() || symbol.length() > 512)
                                continue;
                            
                            if (symbol.contains("UnmanagedServiceObject") || symbol.equals("N2nn2sf4cmif6server23CmifServerDomainManager6DomainE"))
                            {
                                knownVTabOffsets.put(symbol, off);
                                Msg.info(this, String.format("Service sym %s at 0x%X", symbol, this.nxo.getBaseAddress() + thisOffset));
                            }
                        }
                    }
                }
            }
            catch (MemoryAccessException e)
            {
                continue;
            }
        }
        
        if (knownVTabOffsets.isEmpty())
            return out;
        
        // All IServiceObjects share a common non-overridable virtual function at vt + 0x20
        // and thus that value can be used to distinguish a virtual table vs a non-virtual table.
        // Here we locate the address of that function.
        long knownAddress = 0;
        
        for (long off : knownVTabOffsets.values())
        {
            long curKnownAddr = this.program.getMemory().getLong(this.aSpace.getAddress(this.nxo.getBaseAddress() + off + 0x20));
            
            if (knownAddress == 0)
            {
                knownAddress = curKnownAddr; 
            }
            else if (knownAddress != curKnownAddr) return out;
        }
        
        Msg.info(this, String.format("Known service address: 0x%x", knownAddress));
        
        // Use the known function to find all IPC vtables
        for (NXRelocation reloc : this.nxo.getRelocations()) 
        {
            try
            {
                long vtOff;
                
                if (reloc.sym != null && reloc.sym.getSectionHeaderIndex() != ElfSectionHeaderConstants.SHN_UNDEF && reloc.sym.getValue() == 0)
                {
                    vtOff = reloc.sym.getValue();
                }
                else if (reloc.addend != 0)
                {
                    vtOff = reloc.addend;
                }
                else continue;
                
                if (vtOff >= data.getOffset() && vtOff < (data.getOffset() + data.getSize()))
                {
                    if (knownAddress == this.program.getMemory().getLong(this.aSpace.getAddress(this.nxo.getBaseAddress() + vtOff + 0x20)))
                    {
                        Address vtAddr = this.aSpace.getAddress(this.nxo.getBaseAddress() + vtOff);
                        out.add(vtAddr);
                    }
                }
            }
            catch (MemoryAccessException e)
            {
                continue;
            }
        }
        
        return out;
    }
    
    protected void createVTableEntries(List<Address> vtAddrs) throws MemoryAccessException, AddressOutOfBoundsException, IOException, DemangledException
    {
        Memory mem = this.program.getMemory();
        NXOAdapter adapter = this.nxo.getAdapter();
        NXOSection data = adapter.getSection(NXOSectionType.DATA);
        NXOSection rodata = adapter.getSection(NXOSectionType.RODATA);
        
        for (Address vtAddr : vtAddrs)
        {
            long vtOff = vtAddr.getOffset();
            long rttiBase = mem.getLong(this.aSpace.getAddress(vtOff + 0x8)) - this.nxo.getBaseAddress();
            String name = String.format("SRV_VTAB_%X", vtOff);
            
            // VTable has no RTTI information
            if (rttiBase != 0)
            {
                // RTTI must be within the data block
                if (rttiBase >= data.getOffset() && rttiBase < (data.getOffset() + data.getSize()))
                {
                    long thisOff = this.program.getMemory().getLong(this.aSpace.getAddress(this.nxo.getBaseAddress() + rttiBase + 8)) - this.nxo.getBaseAddress();
                    
                    if (thisOff >= rodata.getOffset() && thisOff < (rodata.getOffset() + rodata.getSize()))
                    {
                        String symbol = adapter.getMemoryReader().readTerminatedString(thisOff, '\0');
                        
                        if (!symbol.isEmpty() && symbol.length() <= 512)
                        {
                            name = demangleIpcSymbol(symbol);
                        }
                    }
                }
            }
       
            this.vtEntries.add(new VTableEntry(name, vtAddr));
        }
    }
    
    public List<VTableEntry> getVTableEntries()
    {
        return this.vtEntries;
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
    
    public static class VTableEntry
    {
        public final String name;
        public final Address addr;
        
        private VTableEntry(String name, Address addr)
        {
            this.name = name;
            this.addr = addr;
        }
    }
}
