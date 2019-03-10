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

import adubbz.switchloader.util.ByteUtil;
import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
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
    protected ByteProvider provider;
    protected Program program;
    protected MemoryBlockUtil mbu;
    
    protected byte[] full;

    protected int textOffset;
    protected int rodataOffset;
    protected int dataOffset;
    protected int textSize;
    protected int rodataSize;
    protected int dataSize;
    
    protected MOD0Header mod0;
    
    protected SwitchProgramBuilder(ByteProvider provider, Program program, MemoryConflictHandler handler)
    {
        this.provider = provider;
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
            
            // Setup memory blocks
            InputStream textInputStream = new ByteArrayInputStream(this.full, this.textOffset, this.textSize);
            InputStream rodataInputStream = new ByteArrayInputStream(this.full, this.rodataOffset, this.rodataSize);
            InputStream dataInputStream = new ByteArrayInputStream(this.full, this.dataOffset, this.dataSize);
            
            this.mbu.createInitializedBlock(".text", aSpace.getAddress(baseAddress + this.textOffset), textInputStream, this.textSize, "", null, true, false, true, monitor);
            this.mbu.createInitializedBlock(".rodata", aSpace.getAddress(baseAddress + this.rodataOffset), rodataInputStream, this.rodataSize, "", null, true, false, false, monitor);
            this.mbu.createInitializedBlock(".data", aSpace.getAddress(baseAddress + this.dataOffset), dataInputStream, this.dataSize, "", null, true, true, false, monitor);
            
            // Load MOD0 to create the BSS
            this.loadMod0();
            this.mbu.createUninitializedBlock(false, ".bss", aSpace.getAddress(baseAddress + this.mod0.getBssStartOffset()), this.mod0.getBssSize(), "", null, true, true, false);
        } 
        catch (AddressOverflowException | LockException | IllegalStateException | AddressOutOfBoundsException | IOException e) 
        {
            
        }
    }
    
    protected abstract void loadDefaultSegments(TaskMonitor monitor) throws IOException, AddressOverflowException, AddressOutOfBoundsException;
    
    protected void loadMod0() throws IOException
    {
        int mod0Offset = ByteBuffer.wrap(this.full, this.textOffset + 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        byte[] mod0Bytes = new byte[0x1C];
        System.arraycopy(this.full, mod0Offset, mod0Bytes, 0, mod0Bytes.length);
        BinaryReader mod0Reader = new BinaryReader(new ByteArrayProvider(mod0Bytes), true);
        this.mod0 = new MOD0Header(mod0Reader, mod0Offset);
    }
}
