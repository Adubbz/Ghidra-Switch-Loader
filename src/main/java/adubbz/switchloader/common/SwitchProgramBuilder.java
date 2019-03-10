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
import ghidra.app.util.bin.format.elf.extend.ElfExtensionFactory;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public abstract class SwitchProgramBuilder 
{
    protected ByteProvider fileByteProvider;
    protected ByteProvider memoryByteProvider;
    protected BinaryReader memoryBinaryReader;
    protected Program program;
    protected MemoryBlockUtil mbu;

    protected int textOffset;
    protected int rodataOffset;
    protected int dataOffset;
    protected int textSize;
    protected int rodataSize;
    protected int dataSize;
    
    protected MOD0Header mod0;
    protected ElfDynamicTable dynamicTable;
    
    protected SwitchProgramBuilder(ByteProvider provider, Program program, MemoryConflictHandler handler)
    {
        this.fileByteProvider = provider;
        this.program = program;
        this.mbu = new MemoryBlockUtil(program, handler);
    }
    
    protected void load(TaskMonitor monitor)
    {
        long baseAddress = 0x7100000000L;
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        
        try 
        {
            // Set the base address
            this.program.setImageBase(aSpace.getAddress(baseAddress), true);
            this.loadDefaultSegments(monitor);
            this.memoryBinaryReader = new BinaryReader(this.memoryByteProvider, true);
            
            // Setup memory blocks
            InputStream textInputStream = this.memoryByteProvider.getInputStream(this.textOffset);
            InputStream rodataInputStream = this.memoryByteProvider.getInputStream(this.rodataOffset);
            InputStream dataInputStream = this.memoryByteProvider.getInputStream(this.dataOffset);
            
            this.mbu.createInitializedBlock(".text", aSpace.getAddress(baseAddress + this.textOffset), textInputStream, this.textSize, "", null, true, false, true, monitor);
            this.mbu.createInitializedBlock(".rodata", aSpace.getAddress(baseAddress + this.rodataOffset), rodataInputStream, this.rodataSize, "", null, true, false, false, monitor);
            this.mbu.createInitializedBlock(".data", aSpace.getAddress(baseAddress + this.dataOffset), dataInputStream, this.dataSize, "", null, true, true, false, monitor);
            
            // Load MOD0 to create the BSS
            this.loadMod0();
            this.mbu.createUninitializedBlock(false, ".bss", aSpace.getAddress(baseAddress + this.mod0.getBssStartOffset()), this.mod0.getBssSize(), "", null, true, true, false);
        
            // Create the dynamic table and its memory block
            this.dynamicTable = ElfDynamicTable.createDynamicTable(new FactoryBundledWithBinaryReader(RethrowContinuesFactory.INSTANCE, this.memoryByteProvider, true), new DummyElfHeader(), this.mod0.getDynamicOffset(), this.mod0.getDynamicOffset());
            this.mbu.createInitializedBlock(".dynamic", aSpace.getAddress(baseAddress + this.mod0.getDynamicOffset()), this.memoryByteProvider.getInputStream(this.mod0.getDynamicOffset()), this.dynamicTable.getLength(), "", null, true, true, false, monitor);
            
            // TODO: Memory block conflict resolution
            
            // Create sections
            // processStringTables
        } 
        catch (AddressOverflowException | LockException | IllegalStateException | AddressOutOfBoundsException | IOException e) 
        {
            
        }
    }
    
    protected abstract void loadDefaultSegments(TaskMonitor monitor) throws IOException, AddressOverflowException, AddressOutOfBoundsException;
    
    protected void loadMod0() throws IOException
    {
        int mod0Offset = this.memoryBinaryReader.readInt(this.textOffset + 4);
        this.mod0 = new MOD0Header(this.memoryBinaryReader, mod0Offset, mod0Offset);
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
