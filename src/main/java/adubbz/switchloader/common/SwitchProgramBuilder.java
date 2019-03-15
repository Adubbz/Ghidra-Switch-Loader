/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.switchloader.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;

import adubbz.switchloader.util.ByteUtil;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfDynamicTable;
import ghidra.app.util.bin.format.elf.ElfDynamicType;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.ElfStringTable;
import ghidra.app.util.bin.format.elf.extend.ElfExtensionFactory;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public abstract class SwitchProgramBuilder 
{
    protected ByteProvider fileByteProvider;
    protected ByteProvider memoryByteProvider;
    protected BinaryReader memoryBinaryReader;
    protected Program program;
    protected MemoryBlockUtil mbu;
    
    long baseAddress;
    protected AddressSpace aSpace;
    protected InitializedSectionManager sectionManager;

    protected int textOffset;
    protected int rodataOffset;
    protected int dataOffset;
    protected int textSize;
    protected int rodataSize;
    protected int dataSize;
    
    protected MOD0Header mod0;
    protected ElfHeader dummyElfHeader;
    protected ElfDynamicTable dynamicTable;
    
    protected SwitchProgramBuilder(ByteProvider provider, Program program, MemoryConflictHandler handler)
    {
        this.fileByteProvider = provider;
        this.program = program;
        this.mbu = new MemoryBlockUtil(program, handler);
    }
    
    protected void load(TaskMonitor monitor)
    {
        this.baseAddress = 0x7100000000L;
        this.aSpace = program.getAddressFactory().getDefaultAddressSpace();
        this.sectionManager = new InitializedSectionManager(monitor, this.mbu, this.aSpace, this.baseAddress);
        
        try 
        {
            // Set the base address
            this.program.setImageBase(aSpace.getAddress(this.baseAddress), true);
            this.loadDefaultSegments(monitor);
            this.memoryBinaryReader = new BinaryReader(this.memoryByteProvider, true);
            
            // Setup memory blocks
            InputStream textInputStream = this.memoryByteProvider.getInputStream(this.textOffset);
            InputStream rodataInputStream = this.memoryByteProvider.getInputStream(this.rodataOffset);
            InputStream dataInputStream = this.memoryByteProvider.getInputStream(this.dataOffset);
            
            this.sectionManager.addSection(".text", this.textOffset, textInputStream, this.textSize, true, false, true);
            this.sectionManager.addSection(".rodata", this.rodataOffset, rodataInputStream, this.rodataSize, true, false, false);
            this.sectionManager.addSection(".data", this.dataOffset, dataInputStream, this.dataSize, true, true, false);
            
            // Load MOD0
            this.loadMod0();
            this.dummyElfHeader = new DummyElfHeader();
            
            // Create the dynamic table and its memory block
            this.dynamicTable = ElfDynamicTable.createDynamicTable(new FactoryBundledWithBinaryReader(RethrowContinuesFactory.INSTANCE, this.memoryByteProvider, true), this.dummyElfHeader, this.mod0.getDynamicOffset(), this.mod0.getDynamicOffset());
            this.sectionManager.addSection(".dynamic", this.mod0.getDynamicOffset(), this.memoryByteProvider.getInputStream(this.mod0.getDynamicOffset()), this.dynamicTable.getLength(), true, true, false);

            // Create dynamic sections
            this.optionallyCreateDynBlock(".dynstr", ElfDynamicType.DT_STRTAB, ElfDynamicType.DT_STRSZ);
            this.optionallyCreateDynBlock(".init_array", ElfDynamicType.DT_INIT_ARRAY, ElfDynamicType.DT_INIT_ARRAYSZ);
            this.optionallyCreateDynBlock(".fini_array", ElfDynamicType.DT_FINI_ARRAY, ElfDynamicType.DT_FINI_ARRAYSZ);
            this.optionallyCreateDynBlock(".rela.dyn", ElfDynamicType.DT_RELA, ElfDynamicType.DT_RELASZ);
            this.optionallyCreateDynBlock(".rel.dyn", ElfDynamicType.DT_REL, ElfDynamicType.DT_RELSZ);
            this.optionallyCreateDynBlock(".rela.plt", ElfDynamicType.DT_JMPREL, ElfDynamicType.DT_PLTRELSZ);
            
            this.createDynSymBlock();
            
            this.sectionManager.finalizeSections();
            this.parseStringTable();
            
            // Create BSS
            this.mbu.createUninitializedBlock(false, ".bss", aSpace.getAddress(baseAddress + this.mod0.getBssStartOffset()), this.mod0.getBssSize(), "", null, true, true, false);
        } 
        catch (AddressOverflowException | LockException | IllegalStateException | AddressOutOfBoundsException | IOException | NotFoundException | CodeUnitInsertionException | DataTypeConflictException e) 
        {
            
        }
    }
    
    protected abstract void loadDefaultSegments(TaskMonitor monitor) throws IOException, AddressOverflowException, AddressOutOfBoundsException;
    
    protected void loadMod0() throws IOException
    {
        int mod0Offset = this.memoryBinaryReader.readInt(this.textOffset + 4);
        this.mod0 = new MOD0Header(this.memoryBinaryReader, mod0Offset, mod0Offset);
    }
    
    protected void createDynSymBlock() throws NotFoundException, IOException
    {
        long symbolTableOff = this.dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMTAB);
        long symbolEntrySize = this.dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMENT);
        long dtHashOff = this.dynamicTable.getDynamicValue(ElfDynamicType.DT_HASH);
        long nchain = this.memoryBinaryReader.readUnsignedInt(dtHashOff + 4);
        Msg.info(this, "Symbol table size " + (nchain * symbolEntrySize));
        
        this.sectionManager.addSectionInheritPerms(".dynsym", symbolTableOff, this.memoryByteProvider.getInputStream(symbolTableOff), nchain * symbolEntrySize);
    }
    
    protected void parseStringTable() throws IOException, AddressOverflowException, CodeUnitInsertionException, DataTypeConflictException
    {
        long dynamicStringTableAddr = -1;
        long dynamicStringTableSize = -1;
        
        try 
        {
            dynamicStringTableAddr = dynamicTable.getDynamicValue(ElfDynamicType.DT_STRTAB);
            dynamicStringTableSize = dynamicTable.getDynamicValue(ElfDynamicType.DT_STRSZ);
        }
        catch (NotFoundException e) {
            Msg.warn(this, "Binary does not contain a dynamic string table (DT_STRTAB)");
            return;
        }

        long stringTableAddrOffset = this.baseAddress + dynamicStringTableAddr;
        ElfStringTable stringTable = ElfStringTable.createElfStringTable(new FactoryBundledWithBinaryReader(RethrowContinuesFactory.INSTANCE, this.memoryByteProvider, true), this.dummyElfHeader,
                null, dynamicStringTableAddr, stringTableAddrOffset, dynamicStringTableSize);
        
        Address address = this.aSpace.getAddress(stringTableAddrOffset);
        Address end = address.addNoWrap(stringTable.getLength() - 1);
        
        while (address.compareTo(end) < 0) 
        {
            int length = createString(address);
            address = address.addNoWrap(length);
        }
    }
    
    protected int createString(Address address) throws CodeUnitInsertionException, DataTypeConflictException 
    {
        Data d = this.program.getListing().getDataAt(address);
        
        if (d == null || !TerminatedStringDataType.dataType.isEquivalent(d.getDataType())) 
        {
            d = this.program.getListing().createData(address, TerminatedStringDataType.dataType, -1);
        }
        
        return d.getLength();
    }
    
    protected void optionallyCreateDynBlock(String name, ElfDynamicType offsetType, ElfDynamicType sizeType) throws NotFoundException, IOException
    {
        if (this.dynamicTable.containsDynamicValue(offsetType) && this.dynamicTable.containsDynamicValue(sizeType))
        {
            long offset = this.dynamicTable.getDynamicValue(offsetType);
            long size = this.dynamicTable.getDynamicValue(sizeType);
            
            if (size > 0)
            {
                Msg.info(this, String.format("Created dyn block %s at 0x%X of size 0x%X", name, offset, size));
                this.sectionManager.addSectionInheritPerms(name, offset, this.memoryByteProvider.getInputStream(offset), size);
            }
        }
    }
    
    // Fake only what is needed for an elf dynamic table
    private static class DummyElfHeader extends ElfHeader
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
        public boolean is32Bit() 
        {
            return false;
        }
    }
}
