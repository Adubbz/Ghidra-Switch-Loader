/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.common;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import adubbz.nx.util.FullMemoryByteProvider;
import adubbz.nx.util.LegacyFactoryBundledWithBinaryReader;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

public class ElfCompatibilityProvider 
{
    private Program program;
    private ByteProvider provider;
    private FactoryBundledWithBinaryReader factoryReader;
    
    private ElfHeader dummyElfHeader;
    
    protected ElfDynamicTable dynamicTable;
    protected ElfStringTable stringTable;
    protected ElfSymbolTable symbolTable;
    
    protected String[] dynamicLibraryNames;
    protected List<NXRelocation> relocs = new ArrayList<>();
    protected List<NXRelocation> pltRelocs = new ArrayList<>();
    
    public ElfCompatibilityProvider(Program program, ByteProvider provider)
    {
        this.program = program;
        this.provider = provider;
        this.factoryReader = new LegacyFactoryBundledWithBinaryReader(RethrowContinuesFactory.INSTANCE, this.provider, true);
        this.dummyElfHeader = new DummyElfHeader();
    }
    
    public ElfCompatibilityProvider(Program program)
    {
        this(program, new FullMemoryByteProvider(program));
    }
    
    public ElfDynamicTable getDynamicTable()
    {
        if (this.dynamicTable != null)
            return this.dynamicTable;
        
        MemoryBlock dynamic = this.getDynamicBlock();
        
        if (dynamic == null) return null;
        
        try
        {
            this.dynamicTable = ElfDynamicTable.createDynamicTable(this.factoryReader, this.dummyElfHeader, dynamic.getStart().getOffset(), dynamic.getStart().getOffset());
        }
        catch (IOException e)
        {
            Msg.error(this, "Failed to create dynamic table", e);
        }
        
        return this.dynamicTable;
    }
    
    public ElfStringTable getStringTable()
    {
        if (this.stringTable != null)
            return this.stringTable;
        
        ElfDynamicTable dynamicTable = this.getDynamicTable();
        
        if (dynamicTable == null || !dynamicTable.containsDynamicValue(ElfDynamicType.DT_STRTAB)) 
            return null;
        
        try
        {
            long dynamicStringTableAddr = this.program.getImageBase().getOffset() + dynamicTable.getDynamicValue(ElfDynamicType.DT_STRTAB);
            long dynamicStringTableSize = dynamicTable.getDynamicValue(ElfDynamicType.DT_STRSZ);
    
            this.stringTable = ElfStringTable.createElfStringTable(this.factoryReader, this.dummyElfHeader,
                    null, dynamicStringTableAddr, dynamicStringTableAddr, dynamicStringTableSize);
        }
        catch (IOException | NotFoundException e)
        {
            Msg.error(this, "Failed to create string table", e);
        }
        
        return this.stringTable;
    }
    
    public String[] getDynamicLibraryNames()
    {
        if (this.dynamicLibraryNames != null)
            return this.dynamicLibraryNames;
        
        ElfDynamicTable dynamicTable = this.getDynamicTable();
        ElfStringTable stringTable = this.getStringTable();
        
        if (dynamicTable == null) return new String[0];
        
        ElfDynamic[] needed = dynamicTable.getDynamics(ElfDynamicType.DT_NEEDED);
        this.dynamicLibraryNames = new String[needed.length];
        for (int i = 0; i < needed.length; i++) 
        {
            if (stringTable != null) 
            {
                try 
                {
                    this.dynamicLibraryNames[i] = stringTable.readString(this.factoryReader, needed[i].getValue());
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
        
        return this.dynamicLibraryNames;
    }
    
    public ElfSymbolTable getSymbolTable()
    {
        if (this.symbolTable != null)
            return this.symbolTable;
        
        ElfDynamicTable dynamicTable = this.getDynamicTable();
        ElfStringTable stringTable = this.getStringTable();
        
        if (dynamicTable == null || stringTable == null) 
            return null;
        
        try
        {
            long symbolTableOff = dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMTAB) + this.program.getImageBase().getOffset();
            long symbolEntrySize = dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMENT);
            long dtHashOff = dynamicTable.getDynamicValue(ElfDynamicType.DT_HASH);
            long nchain = this.factoryReader.readUnsignedInt(this.program.getImageBase().getOffset() + dtHashOff + 4);
            long symbolTableSize = nchain * symbolEntrySize;
            
            Method m = ElfSymbolTable.class.getDeclaredMethod("createElfSymbolTable", FactoryBundledWithBinaryReader.class, ElfHeader.class, ElfSectionHeader.class, long.class, long.class, 
                    long.class, long.class, ElfStringTable.class, boolean.class);
            m.setAccessible(true);
            
            symbolTable = (ElfSymbolTable)m.invoke(null, this.factoryReader, this.dummyElfHeader, null,
                    symbolTableOff,
                    symbolTableOff,
                    symbolTableSize,
                    symbolEntrySize,
                    stringTable, true);
        }
        catch (NoSuchMethodException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | NotFoundException | IOException e)
        {
            Msg.error(this, "Failed to create symbol table", e);
        }
        
        return this.symbolTable;
    }
    
    public List<NXRelocation> getPltRelocations()
    {
        if (!this.pltRelocs.isEmpty())
            return this.pltRelocs;
        
        ElfDynamicTable dynamicTable = this.getDynamicTable();
        ElfSymbolTable symbolTable = this.getSymbolTable();
        
        if (dynamicTable == null || symbolTable == null)
            return this.pltRelocs;
        
        try
        {
            if (this.dynamicTable.containsDynamicValue(ElfDynamicType.DT_JMPREL)) 
            {
                Msg.info(this, "Processing JMPREL relocations...");
                this.processRelocations(this.pltRelocs, symbolTable,
                        (long)dynamicTable.getDynamicValue(ElfDynamicType.DT_JMPREL),
                        (long)dynamicTable.getDynamicValue(ElfDynamicType.DT_PLTRELSZ));
    
                this.pltRelocs.sort(Comparator.comparing(reloc -> reloc.offset));
            }
        }
        catch (NotFoundException | IOException e)
        {
            Msg.error(this, "Failed to get plt relocations", e);
        }
        
        return this.pltRelocs;
    }
    
    public List<NXRelocation> getRelocations()
    {
        if (!this.relocs.isEmpty())
            return this.relocs;
        
        ElfDynamicTable dynamicTable = this.getDynamicTable();
        ElfSymbolTable symbolTable = this.getSymbolTable();
        
        if (dynamicTable == null || symbolTable == null)
            return this.relocs;
        
        try
        {
            if (dynamicTable.containsDynamicValue(ElfDynamicType.DT_REL.value)) 
            {
                Msg.info(this, "Processing DT_REL relocations...");
                processRelocations(this.relocs, this.symbolTable,
                        (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_REL),
                        (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_RELSZ));
            }
            
            if (dynamicTable.containsDynamicValue(ElfDynamicType.DT_RELA)) 
            {
                Msg.info(this, "Processing DT_RELA relocations...");
                processRelocations(this.relocs, this.symbolTable,
                        (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_RELA),
                        (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_RELASZ));
            }
        }
        catch (NotFoundException | IOException e)
        {
            Msg.error(this, "Failed to get relocations", e);
        }
        
        this.relocs.addAll(this.getPltRelocations());
        return this.relocs;
    }
    
    private Set<Long> processRelocations(List<NXRelocation> relocs, ElfSymbolTable symtab, long rel, long relsz) throws IOException 
    {
        Set<Long> locations = new HashSet<Long>();
        
        for (long i = 0; i < relsz / 0x18; i++) 
        {
            long base = this.program.getImageBase().getOffset();
            long offset = this.factoryReader.readLong(base + rel + i * 0x18);
            long info = this.factoryReader.readLong(base + rel + i * 0x18 + 8);
            long addend = this.factoryReader.readLong(base + rel + i * 0x18 + 0x10);
            
            long r_type = info & 0xffffffffL;
            long r_sym = info >> 32;
        
            ElfSymbol sym;
            if (r_sym != 0) {
                // Note: getSymbolAt doesn't work as it relies on getValue() being the address, which is 0 for imports.
                // We manually correct the value later to point to the fake external block.
                sym = symtab.getSymbols()[(int)r_sym];
            } else {
                sym = null;
            }
            
            if (r_type != AARCH64_ElfRelocationConstants.R_AARCH64_TLSDESC)
            {
                locations.add(offset);
            }
            relocs.add(new NXRelocation(offset, r_sym, r_type, sym, addend));
        }
        return locations;
    }
    
    protected MemoryBlock getDynamicBlock()
    {
        return this.program.getMemory().getBlock(".dynamic");
    }
    
    public BinaryReader getReader()
    {
        return this.factoryReader;
    }
    
    // Fake only what is needed for an elf dynamic table
    public static class DummyElfHeader extends ElfHeader
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
