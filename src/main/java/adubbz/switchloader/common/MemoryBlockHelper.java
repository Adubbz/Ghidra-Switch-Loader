package adubbz.switchloader.common;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import adubbz.switchloader.util.ByteUtil;
import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfStringTable;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public class MemoryBlockHelper 
{
    private TaskMonitor monitor;
    private Program program;
    private ByteProvider byteProvider;
    private MemoryBlockUtil mbu;
    private long baseAddress;
    
    private List<String> sectionsToInit = new ArrayList<>();

    public MemoryBlockHelper(TaskMonitor monitor, Program program, ByteProvider byteProvider, MemoryBlockUtil mbu, long baseAddress)
    {
        this.monitor = monitor;
        this.program = program;
        this.byteProvider = byteProvider;
        this.mbu = mbu;
        this.baseAddress = baseAddress;
    }

    public MemoryBlock addManualDeferredSection(String name, long addressOffset, InputStream dataInput, long dataSize, boolean read, boolean write, boolean execute)
    {
        AddressSpace addressSpace = this.program.getAddressFactory().getDefaultAddressSpace();
        MemoryBlock mb = null;
        
        try 
        {
            mb = this.mbu.createUninitializedBlock(false, name, addressSpace.getAddress(this.baseAddress + addressOffset), dataSize, "", null, read, write, execute);
            
            if (mb == null)
            {
                Msg.error(this, this.mbu.getMessages());
            }
        } 
        catch (AddressOutOfBoundsException e) 
        {
            e.printStackTrace();
        }
        
        return mb;
    }
    
    public void addDeferredSection(String name, long addressOffset, InputStream dataInput, long dataSize, boolean read, boolean write, boolean execute)
    {
        MemoryBlock mb = this.addManualDeferredSection(name, addressOffset, dataInput, dataSize, read, write, execute);
        
        if (mb != null)
        {
            this.sectionsToInit.add(mb.getName());
        }
    }
    
    public void addSection(String name, long addressOffset, InputStream dataInput, long dataSize, boolean read, boolean write, boolean execute) throws AddressOverflowException, AddressOutOfBoundsException
    {
        AddressSpace addressSpace = this.program.getAddressFactory().getDefaultAddressSpace();
        this.mbu.createInitializedBlock(name, addressSpace.getAddress(this.baseAddress + addressOffset), dataInput, dataSize, "", null, read, write, execute, this.monitor);
    }
    
    public void finalizeSection(String name) throws LockException, NotFoundException, MemoryAccessException, IOException
    {
        Memory memory = this.program.getMemory();
        Msg.info(this, "Attempting to manually finalize " + name);
        
        for (MemoryBlock block : memory.getBlocks())
        {
            if (block.getName().equals(name))
            {
                Msg.info(this, "Manually finalizing " + name);
                memory.convertToInitialized(block, (byte)0);
                byte[] data = this.byteProvider.readBytes(block.getStart().getOffset() - this.baseAddress, block.getSize());
                block.putBytes(block.getStart(), data);
            }
        }
    }
    
    public void finalizeSections() throws LockException, NotFoundException, MemoryAccessException, IOException
    {
        Memory memory = this.program.getMemory();
        
        for (MemoryBlock block : memory.getBlocks())
        {
            if (this.sectionsToInit.contains(block.getName()))
            {
                memory.convertToInitialized(block, (byte)0);
                byte[] data = this.byteProvider.readBytes(block.getStart().getOffset() - this.baseAddress, block.getSize());
                block.putBytes(block.getStart(), data);
            }
        }
    }
    
    private class DeferredInitSection
    {
        private MemoryBlock block;
        private InputStream dataInput;
        
        public DeferredInitSection(MemoryBlock block, InputStream dataInput)
        {
            this.block = block;
            this.dataInput = dataInput;
        }
    }
}
