/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.switchloader.nxo;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.common.collect.ImmutableList;

import adubbz.switchloader.common.NXRelocation;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.elf.ElfDynamic;
import ghidra.app.util.bin.format.elf.ElfDynamicTable;
import ghidra.app.util.bin.format.elf.ElfDynamicType;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfStringTable;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;
import ghidra.app.util.bin.format.elf.extend.ElfExtensionFactory;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.app.util.bin.format.elf.relocation.AARCH64_ElfRelocationConstants;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

public class NXOHeader 
{
    private NXOAdapter adapter;
    private ElfHeader dummyElfHeader;
    private FactoryBundledWithBinaryReader factoryReader;
    
    protected final long baseAddress;
    
    protected ElfDynamicTable dynamicTable;
    protected ElfStringTable stringTable;
    protected ElfSymbolTable symbolTable;
    
    protected String[] dynamicLibraryNames;
    protected List<NXRelocation> relocs = new ArrayList<>();
    protected List<NXRelocation> pltRelocs = new ArrayList<>();
    
    public NXOHeader(NXOAdapter adapter, long baseAddress)
    {
        this.adapter = adapter;
        this.baseAddress = baseAddress;
        
        this.parse();
    }
    
    private void parse()
    {
        if (this.adapter.getMOD0() == null)
        {
            Msg.error(this, "Failed to read MOD0. Parsing is unable to proceed.");
            return;
        }
        
        this.dummyElfHeader = new DummyElfHeader();
        this.factoryReader = new FactoryBundledWithBinaryReader(RethrowContinuesFactory.INSTANCE, this.adapter.getMemoryProvider(), true);
        
        try
        {
            this.parseDynamicTable();
            this.parseStringTables();
            this.parseDynamicLibraryNames();
            this.parseSymbolTables();
            this.parseRelocations();
        }
        catch (Exception e)
        {
            Msg.error(this, "Failed to parse NXO dynamics.");
            e.printStackTrace();
        }
    }

    protected void parseDynamicTable() throws IOException
    {
        this.dynamicTable = ElfDynamicTable.createDynamicTable(this.factoryReader, this.dummyElfHeader, this.adapter.getMOD0().getDynamicOffset(), this.adapter.getMOD0().getDynamicOffset());
    }
    
    protected void parseStringTables() throws IOException, NotFoundException
    {
        long dynamicStringTableAddr = -1;
        long dynamicStringTableSize = -1;
        
        dynamicStringTableAddr = dynamicTable.getDynamicValue(ElfDynamicType.DT_STRTAB);
        dynamicStringTableSize = dynamicTable.getDynamicValue(ElfDynamicType.DT_STRSZ);

        long stringTableAddrOffset = this.baseAddress + dynamicStringTableAddr;
        this.stringTable = ElfStringTable.createElfStringTable(new FactoryBundledWithBinaryReader(RethrowContinuesFactory.INSTANCE, this.getAdapter().getMemoryProvider(), true), this.dummyElfHeader,
                null, dynamicStringTableAddr, stringTableAddrOffset, dynamicStringTableSize);
    }
    
    protected void parseDynamicLibraryNames()
    {
        if (this.dynamicTable == null) 
        {
            this.dynamicLibraryNames = new String[0];
            return;
        }

        ElfDynamic[] needed = dynamicTable.getDynamics(ElfDynamicType.DT_NEEDED);
        this.dynamicLibraryNames = new String[needed.length];
        for (int i = 0; i < needed.length; i++) 
        {
            if (this.stringTable != null) 
            {
                try 
                {
                    this.dynamicLibraryNames[i] = this.stringTable.readString(this.adapter.getMemoryReader(), needed[i].getValue());
                }
                catch (Exception e) 
                {
                    // ignore
                }
            }
            if (this.dynamicLibraryNames[i] == null) {
                this.dynamicLibraryNames[i] = "UNK_LIB_NAME_" + i;
            }
        }
    }
    
    protected void parseSymbolTables() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException, NotFoundException, NoSuchMethodException, SecurityException, IOException
    {
        long symbolTableOff = this.dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMTAB);
        long symbolEntrySize = this.dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMENT);
        long dtHashOff = this.dynamicTable.getDynamicValue(ElfDynamicType.DT_HASH);
        long nchain = this.adapter.getMemoryReader().readUnsignedInt(dtHashOff + 4);
        long symbolTableSize = nchain * symbolEntrySize;
        
        Method m = ElfSymbolTable.class.getDeclaredMethod("createElfSymbolTable", FactoryBundledWithBinaryReader.class, ElfHeader.class, ElfSectionHeader.class, long.class, long.class, 
                long.class, long.class, ElfStringTable.class, boolean.class);
        m.setAccessible(true);
        
        this.symbolTable = (ElfSymbolTable)m.invoke(null, this.factoryReader, this.dummyElfHeader, null,
                symbolTableOff,
                symbolTableOff + this.baseAddress,
                symbolTableSize,
                symbolEntrySize,
                this.stringTable, true);
    }
    
    protected void parseRelocations() throws NotFoundException, IOException
    {
        if (this.dynamicTable.containsDynamicValue(ElfDynamicType.DT_REL.value)) 
        {
            Msg.info(this, "Processing DT_REL relocations...");
            processRelocations(this.adapter.getMemoryReader(), this.relocs, this.symbolTable,
                    (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_REL),
                    (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_RELSZ));
        }
        
        if (this.dynamicTable.containsDynamicValue(ElfDynamicType.DT_RELA)) 
        {
            Msg.info(this, "Processing DT_RELA relocations...");
            processRelocations(this.adapter.getMemoryReader(), this.relocs, this.symbolTable,
                    (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_RELA),
                    (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_RELASZ));
        }
        
        if (this.dynamicTable.containsDynamicValue(ElfDynamicType.DT_JMPREL)) 
        {
            Msg.info(this, "Processing JMPREL relocations...");
            this.processRelocations(this.adapter.getMemoryReader(), this.pltRelocs, this.symbolTable,
                    (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_JMPREL),
                    (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_PLTRELSZ));
            this.relocs.addAll(this.pltRelocs);
            
            this.pltRelocs.sort(Comparator.comparing(reloc -> reloc.offset));
        }
    }
    
    private Set<Long> processRelocations(BinaryReader provider, List<NXRelocation> relocs, ElfSymbolTable symtab, long rel, long relsz) throws IOException 
    {
        Set<Long> locations = new HashSet<Long>();
        
        for (long i = 0; i < relsz / 0x18; i++) 
        {
            long offset = provider.readLong(rel + i * 0x18);
            long info = provider.readLong(rel + i * 0x18 + 8);
            long addend = provider.readLong(rel + i * 0x18 + 0x10);
            
            long r_type = info & 0xffffffffL;
            long r_sym = info >> 32;
        
            ElfSymbol sym;
            if (r_sym != 0) {
                // Note: getSymbolAt doesn't work as it relies on getValue() being the address, which doesn't appear to be the case for imports
                sym = symtab.getSymbols()[(int)r_sym];
            } else {
                sym = null;
            }
            
            if (r_type != AARCH64_ElfRelocationConstants.R_AARCH64_TLSDESC)
            {
                locations.add(offset);
            }
            relocs.add(new NXRelocation(offset, r_type, sym, addend));
        }
        return locations;
    }
    
    public NXOAdapter getAdapter()
    {
        return this.adapter;
    }
    
    public long getBaseAddress()
    {
        return this.baseAddress;
    }
    
    public ElfDynamicTable getDynamicTable()
    {
        return this.dynamicTable;
    }
    
    public ElfStringTable getStringTable()
    {
        return this.stringTable;
    }
    
    public ElfSymbolTable getSymbolTable()
    {
        return this.symbolTable;
    }
    
    public String[] getDynamicLibraryNames() 
    {
        return this.dynamicLibraryNames;
    }
    
    public ImmutableList<NXRelocation> getRelocations()
    {
        return ImmutableList.copyOf(this.relocs);
    }
    
    public ImmutableList<NXRelocation> getPltRelocations()
    {
        return ImmutableList.copyOf(this.pltRelocs);
    }
    
    // Fake only what is needed for an elf dynamic table
    private class DummyElfHeader extends ElfHeader
    {
        private HashMap<Integer, ElfDynamicType> dynamicTypeMap;
        
        public DummyElfHeader()
        {
            dynamicTypeMap = new HashMap<>();
            ElfDynamicType.addDefaultTypes(this.dynamicTypeMap);

            ElfLoadAdapter extensionAdapter = ElfExtensionFactory.getLoadAdapter(this);
            if (extensionAdapter != null) 
            {
                extensionAdapter.addDynamicTypes(this.dynamicTypeMap);
            }
        }
        
        @Override
        protected HashMap<Integer, ElfDynamicType> getDynamicTypeMap() 
        {
            return this.dynamicTypeMap;
        }

        @Override
        public ElfDynamicType getDynamicType(int type) 
        {
            if (this.dynamicTypeMap != null) 
            {
                return this.dynamicTypeMap.get(type);
            }
            return null; // not found
        }
        
        @Override
        public long adjustAddressForPrelink(long address) 
        {
            return address;
        }
        
        @Override
        public long unadjustAddressForPrelink(long address) 
        {
            return address;
        }
        
        @Override
        public boolean is32Bit() 
        {
            return false;
        }
    }
}
