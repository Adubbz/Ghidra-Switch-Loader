/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.common;

import adubbz.nx.util.FullMemoryByteProvider;
import adubbz.nx.util.LegacyBinaryReader;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.extend.ElfExtensionFactory;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.app.util.bin.format.elf.relocation.AARCH64_ElfRelocationConstants;
import ghidra.app.util.bin.format.elf.relocation.ARM_ElfRelocationConstants;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

import java.io.IOException;
import java.util.*;

public class ElfCompatibilityProvider 
{
    public static final int R_FAKE_RELR = -1;

    private Program program;
    private ByteProvider provider;
    private BinaryReader binaryReader;
    boolean isAarch32;
    
    private ElfHeader dummyElfHeader;
    
    protected ElfDynamicTable dynamicTable;
    protected ElfStringTable stringTable;
    protected ElfSymbolTable symbolTable;
    
    protected String[] dynamicLibraryNames;
    protected List<NXRelocation> relocs = new ArrayList<>();
    protected List<NXRelocation> pltRelocs = new ArrayList<>();
    
    public ElfCompatibilityProvider(Program program, ByteProvider provider, boolean isAarch32)
    {
        this.program = program;
        this.provider = provider;
        this.binaryReader = new LegacyBinaryReader(this.provider, true);
        this.isAarch32 = isAarch32;
        try {
            this.dummyElfHeader = new DummyElfHeader(isAarch32);
        } catch (ElfException e) {
            Msg.error(this, "Couldn't construct DummyElfHeader", e);
        }
    }
    
    public ElfCompatibilityProvider(Program program, boolean isAarch32)
    {
        this(program, new FullMemoryByteProvider(program), isAarch32);
    }
    
    public ElfDynamicTable getDynamicTable()
    {
        if (this.dynamicTable != null)
            return this.dynamicTable;

        MemoryBlock dynamic = this.getDynamicBlock();
        
        if (dynamic == null) return null;
        
        try
        {
            this.dynamicTable = new ElfDynamicTable(this.binaryReader, this.dummyElfHeader, dynamic.getStart().getOffset(), dynamic.getStart().getOffset());
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
    
            this.stringTable = new ElfStringTable(this.dummyElfHeader,
                    null, dynamicStringTableAddr, dynamicStringTableAddr, dynamicStringTableSize);
        }
        catch (NotFoundException e)
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
                    this.dynamicLibraryNames[i] = stringTable.readString(this.binaryReader, needed[i].getValue());
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
            long nchain = this.binaryReader.readUnsignedInt(this.program.getImageBase().getOffset() + dtHashOff + 4);
            long symbolTableSize = nchain * symbolEntrySize;
            
            symbolTable = new ElfSymbolTable(this.binaryReader, this.dummyElfHeader, null,
                    symbolTableOff,
                    symbolTableOff,
                    symbolTableSize,
                    symbolEntrySize,
                    stringTable, null, true);
        }
        catch (IllegalArgumentException | NotFoundException | IOException e)
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
                        dynamicTable.getDynamicValue(ElfDynamicType.DT_JMPREL),
                        dynamicTable.getDynamicValue(ElfDynamicType.DT_PLTRELSZ));
    
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
            if (dynamicTable.containsDynamicValue(ElfDynamicType.DT_REL))
            {
                Msg.info(this, "Processing DT_REL relocations...");
                processRelocations(this.relocs, this.symbolTable,
                        this.dynamicTable.getDynamicValue(ElfDynamicType.DT_REL),
                        this.dynamicTable.getDynamicValue(ElfDynamicType.DT_RELSZ));
            }
            
            if (dynamicTable.containsDynamicValue(ElfDynamicType.DT_RELA)) 
            {
                Msg.info(this, "Processing DT_RELA relocations...");
                processRelocations(this.relocs, this.symbolTable,
                        this.dynamicTable.getDynamicValue(ElfDynamicType.DT_RELA),
                        this.dynamicTable.getDynamicValue(ElfDynamicType.DT_RELASZ));
            }

            if (dynamicTable.containsDynamicValue(ElfDynamicType.DT_RELR)) {
                Msg.info(this, "Processing DT_RELR relocations...");
                processReadOnlyRelocations(this.relocs,
                        this.dynamicTable.getDynamicValue(ElfDynamicType.DT_RELR),
                        this.dynamicTable.getDynamicValue(ElfDynamicType.DT_RELRSZ));
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
        long base = this.program.getImageBase().getOffset();
        Set<Long> locations = new HashSet<>();
        int relocSize = this.isAarch32 ? 0x8 : 0x18;

        for (long i = 0; i < relsz / relocSize; i++) 
        {
            long offset;
            long info;
            long addend;
            
            long r_type;
            long r_sym;
        
            // Assumes all aarch32 relocs have no addends,
            // and all 64-bit ones do.
            if (this.isAarch32)
            {
                offset = this.binaryReader.readInt(base + rel + i * 0x8);
                info = this.binaryReader.readInt(base + rel + i * 0x8 + 4);
                addend = 0;
                r_type = info & 0xff;
                r_sym = info >> 8;
            }
            else
            {
                offset = this.binaryReader.readLong(base + rel + i * 0x18);
                info = this.binaryReader.readLong(base + rel + i * 0x18 + 8);
                addend = this.binaryReader.readLong(base + rel + i * 0x18 + 0x10);
                r_type = info & 0xffffffffL;
                r_sym = info >> 32;
            }
        
            ElfSymbol sym;
            if (r_sym != 0) {
                // Note: getSymbolAt doesn't work as it relies on getValue() being the address, which is 0 for imports.
                // We manually correct the value later to point to the fake external block.
                sym = symtab.getSymbols()[(int)r_sym];
            } else {
                sym = null;
            }
            
            if (r_type != AARCH64_ElfRelocationConstants.R_AARCH64_TLSDESC && r_type != ARM_ElfRelocationConstants.R_ARM_TLS_DESC)
            {
                locations.add(offset);
            }
            relocs.add(new NXRelocation(offset, r_sym, r_type, sym, addend));
        }
        return locations;
    }

    private Set<Long> processReadOnlyRelocations(List<NXRelocation> relocs, long relr, long relrsz) throws IOException
    {
        long base = this.program.getImageBase().getOffset();
        Set<Long> locations = new HashSet<>();
        int relocSize = 0x8;

        long where = 0;
        for (long entryNumber = 0; entryNumber < relrsz / relocSize; entryNumber++)
        {
            long entry = this.binaryReader.readLong(base + relr + entryNumber * relocSize);

            if ((entry & 1) != 0) {
                entry >>= 1;
                long i = 0;
                while (i < (relocSize * 8) - 1) {
                    if ((entry & (1L << i)) != 0) {
                        locations.add(where + i * relocSize);
                        relocs.add(new NXRelocation(where + i * relocSize, 0, R_FAKE_RELR, null, 0));
                    }
                    i++;
                }
                where += relocSize * ((relocSize * 8) - 1);
            }
            else {
                where = entry;
                locations.add(where);
                relocs.add(new NXRelocation(where, 0, R_FAKE_RELR, null, 0));
                where += relocSize;
            }
        }
        return locations;
    }
    
    protected MemoryBlock getDynamicBlock()
    {
        return this.program.getMemory().getBlock(".dynamic");
    }
    
    public BinaryReader getReader()
    {
        return this.binaryReader;
    }
    
    // Fake only what is needed for an elf dynamic table
    public static class DummyElfHeader extends ElfHeader
    {
        boolean isAarch32;
        private HashMap<Integer, ElfDynamicType> dynamicTypeMap;
        
        public DummyElfHeader(boolean isAarch32) throws ElfException {
            super(new ByteArrayProvider(Arrays.copyOf(ElfConstants.MAGIC_BYTES, ElfConstants.EI_NIDENT + 18)), s -> {});

            this.isAarch32 = isAarch32;
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
            return this.isAarch32;
        }
        
        @Override
        public boolean is64Bit()
        {
            return !this.isAarch32;
        }
    }
}
