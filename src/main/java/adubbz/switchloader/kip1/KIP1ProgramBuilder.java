/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package adubbz.switchloader.kip1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import adubbz.switchloader.ByteUtil;
import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class KIP1ProgramBuilder
{
    private KIP1Header kip1;
    private Program program;
    private ByteProvider provider;
    private MemoryBlockUtil mbu;
    
    private byte[] text;
    private byte[] rodata;
    private byte[] data;
    
    protected KIP1ProgramBuilder(KIP1Header kip1, ByteProvider provider, Program program, MemoryConflictHandler handler)
    {
        this.kip1 = kip1;
        this.provider = provider;
        this.program = program;
        this.mbu = new MemoryBlockUtil(program, handler);
    }
    
    public static void loadKIP1(KIP1Header header, ByteProvider provider, Program program, MemoryConflictHandler conflictHandler, TaskMonitor monitor)
    {
        KIP1ProgramBuilder builder = new KIP1ProgramBuilder(header, provider, program, conflictHandler);
        builder.load(monitor);
    }
    
    protected void load(TaskMonitor monitor)
    {
        long baseAddress = 0x7100000000L;
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        
        try 
        {
            // Set the base address
            this.program.setImageBase(aSpace.getAddress(baseAddress), true);
            this.setupDefaultSegments(monitor);
        } 
        catch (AddressOverflowException | LockException | IllegalStateException | AddressOutOfBoundsException | IOException e) 
        {
        }
    }
    
    private void setupDefaultSegments(TaskMonitor monitor) throws IOException, AddressOverflowException, AddressOutOfBoundsException
    {
        long baseAddress = 0x7100000000L;
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        
        KIP1SectionHeader textHeader = this.kip1.getSectionHeader(KIP1SectionType.TEXT);
        KIP1SectionHeader rodataHeader = this.kip1.getSectionHeader(KIP1SectionType.RODATA);
        KIP1SectionHeader dataHeader = this.kip1.getSectionHeader(KIP1SectionType.DATA);
        KIP1SectionHeader bssHeader = this.kip1.getSectionHeader(KIP1SectionType.BSS);
        
        this.text = new byte[textHeader.getDecompressedSize()];
        this.rodata = new byte[rodataHeader.getDecompressedSize()];
        this.data = new byte[dataHeader.getDecompressedSize()];
        
        if (this.kip1.isSectionCompressed(KIP1SectionType.TEXT))
        {
            byte[] compressedText = this.provider.readBytes(this.kip1.getSectionFileOffset(KIP1SectionType.TEXT), textHeader.getCompressedSize());
            ByteUtil.kip1BlzDecompress(this.text, compressedText);
        }
        else
        {
            this.text = this.provider.readBytes(this.kip1.getSectionFileOffset(KIP1SectionType.TEXT), textHeader.getDecompressedSize());
        }
        
        if (this.kip1.isSectionCompressed(KIP1SectionType.RODATA))
        {
            byte[] compressedRodata = this.provider.readBytes(this.kip1.getSectionFileOffset(KIP1SectionType.RODATA), rodataHeader.getCompressedSize());
            ByteUtil.kip1BlzDecompress(this.rodata, compressedRodata);
        }
        else
        {
            this.rodata = this.provider.readBytes(this.kip1.getSectionFileOffset(KIP1SectionType.RODATA), rodataHeader.getDecompressedSize());
        }
        
        if (this.kip1.isSectionCompressed(KIP1SectionType.DATA))
        {
            byte[] compressedData = this.provider.readBytes(this.kip1.getSectionFileOffset(KIP1SectionType.DATA), dataHeader.getCompressedSize());
            ByteUtil.kip1BlzDecompress(this.data, compressedData);
        }
        else
        {
            Msg.info(this, "KIP1 Data Offset: " + this.kip1.getSectionFileOffset(KIP1SectionType.DATA));
            this.data = this.provider.readBytes(this.kip1.getSectionFileOffset(KIP1SectionType.DATA), dataHeader.getDecompressedSize());
        }
        
        InputStream textInputStream = new ByteArrayInputStream(this.text);
        InputStream rodataInputStream = new ByteArrayInputStream(this.rodata);
        InputStream dataInputStream = new ByteArrayInputStream(this.data);
        
        this.mbu.createInitializedBlock(".text", aSpace.getAddress(baseAddress + textHeader.getOutOffset()), textInputStream, this.text.length, "", null, true, false, true, monitor);
        this.mbu.createInitializedBlock(".rodata", aSpace.getAddress(baseAddress + rodataHeader.getOutOffset()), rodataInputStream, this.rodata.length, "", null, true, false, false, monitor);
        this.mbu.createInitializedBlock(".data", aSpace.getAddress(baseAddress + dataHeader.getOutOffset()), dataInputStream, this.data.length, "", null, true, true, false, monitor);
        this.mbu.createUninitializedBlock(false, ".bss", aSpace.getAddress(baseAddress + bssHeader.getOutOffset()), bssHeader.getDecompressedSize(), "", null, true, true, false);
    }
}
