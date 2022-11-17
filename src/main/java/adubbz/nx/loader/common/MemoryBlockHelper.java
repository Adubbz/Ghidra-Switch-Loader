/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.common;

import java.util.List;

import org.apache.commons.compress.utils.Lists;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class MemoryBlockHelper 
{
    private TaskMonitor monitor;
    private Program program;
    private ByteProvider byteProvider;
    private MessageLog log;

    public MemoryBlockHelper(TaskMonitor monitor, Program program, ByteProvider byteProvider)
    {
        this.monitor = monitor;
        this.program = program;
        this.byteProvider = byteProvider;
        this.log = new MessageLog();
    }
    
    public void addSection(String name, long addressOffset, long offset, long length, boolean read, boolean write, boolean execute)
    {
        try
        {
            FileBytes fileBytes = MemoryBlockUtils.createFileBytes(this.program, this.byteProvider, offset, length, this.monitor);
            MemoryBlockUtils.createInitializedBlock(this.program, false, name, this.program.getImageBase().add(addressOffset), fileBytes, 0, length, "", null, read, write, execute, this.log);
        }
        catch (Exception e)
        {
            Msg.error(this, "Failed to add section " + name, e);
        }
        
        this.flushLog();
    }
    
    private void addUniqueSection(String name, long addressOffset, long offset, long length, boolean read, boolean write, boolean execute)
    {
        Memory memory = this.program.getMemory();
        Address startAddr = this.program.getImageBase().add(addressOffset);
        Address endAddr = startAddr.add(length);
        String newBlockName = name;
        int nameCounter = 0;
        
        while (memory.getBlock(newBlockName) != null)
        {
            nameCounter++;
            newBlockName = name + "." + nameCounter; 
        }
        
        Msg.info(this, "Adding unique section " + newBlockName + " from " + startAddr + " to " + endAddr);
        this.addSection(newBlockName, offset, offset, length, read, write, execute);
    }
    
    public void addFillerSection(String name, long addressOffset, long length, boolean read, boolean write, boolean execute)
    {
        Memory memory = this.program.getMemory();
        Address startAddr = this.program.getImageBase().add(addressOffset);
        Address endAddr = startAddr.add(length);
        AddressRange range = new AddressRangeImpl(startAddr, endAddr);
        
        List<MemoryBlock> blocksInRange = Lists.newArrayList();
        
        for (MemoryBlock block : memory.getBlocks())
        {
            AddressRange blockRange = new AddressRangeImpl(block.getStart(), block.getEnd());
            
            if (range.intersects(blockRange))
            {
                blocksInRange.add(block);
            }
        }
        
        if (blocksInRange.isEmpty())
        {
            Msg.info(this, "Adding filler section " + name + " from " + startAddr + " to " + endAddr);
            this.addSection(name, addressOffset, addressOffset, range.getLength(), read, write, execute);
            return;
        }
        
        Address fillerBlockStart = startAddr;
        AddressRange fillerBlockRange;
        
        for (MemoryBlock block : blocksInRange)
        {
            fillerBlockRange = new AddressRangeImpl(fillerBlockStart, block.getStart());
            
            if (fillerBlockRange.getLength() > 2)
            {
                long offset = fillerBlockRange.getMinAddress().subtract(this.program.getImageBase());
                this.addUniqueSection(name, offset, offset, fillerBlockRange.getLength() - 1, read, write, execute);
            }
            
            fillerBlockStart = block.getEnd().add(1);
        }
        
        fillerBlockRange = new AddressRangeImpl(fillerBlockStart, endAddr);
        
        if (fillerBlockRange.getLength() > 2)
        {
            long offset = fillerBlockRange.getMinAddress().subtract(this.program.getImageBase());
            this.addUniqueSection(name, offset, offset, fillerBlockRange.getLength() - 1, read, write, execute);
        }
    }
    
    public void flushLog()
    {
        if (this.log.hasMessages())
        {
            Msg.info(this, this.log.toString());
            this.log.clear();
        }
    }
}
