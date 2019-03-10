/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package adubbz.switchloader.kip1;

import java.io.IOException;

import adubbz.switchloader.common.SectionType;
import adubbz.switchloader.common.SwitchProgramBuilder;
import adubbz.switchloader.util.ByteUtil;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class KIP1ProgramBuilder extends SwitchProgramBuilder
{
    private KIP1Header kip1;
    
    protected KIP1ProgramBuilder(KIP1Header kip1, ByteProvider provider, Program program, MemoryConflictHandler handler)
    {
        super(provider, program, handler);
        this.kip1 = kip1;
    }
    
    public static void loadKIP1(KIP1Header header, ByteProvider provider, Program program, MemoryConflictHandler conflictHandler, TaskMonitor monitor)
    {
        KIP1ProgramBuilder builder = new KIP1ProgramBuilder(header, provider, program, conflictHandler);
        builder.load(monitor);
    }
    
    @Override
    protected void loadDefaultSegments(TaskMonitor monitor) throws IOException, AddressOverflowException, AddressOutOfBoundsException
    {
        long baseAddress = 0x7100000000L;
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        
        KIP1SectionHeader textHeader = this.kip1.getSectionHeader(SectionType.TEXT);
        KIP1SectionHeader rodataHeader = this.kip1.getSectionHeader(SectionType.RODATA);
        KIP1SectionHeader dataHeader = this.kip1.getSectionHeader(SectionType.DATA);
        KIP1SectionHeader bssHeader = this.kip1.getSectionHeader(SectionType.BSS);
        
        this.textOffset = textHeader.getOutOffset();
        this.rodataOffset = rodataHeader.getOutOffset();
        this.dataOffset = dataHeader.getOutOffset();
        this.textSize = textHeader.getDecompressedSize();
        this.rodataSize = rodataHeader.getDecompressedSize();
        this.dataSize = dataHeader.getDecompressedSize();
        
        // The data section is last, so we use its offset + decompressed size
        this.full = new byte[this.dataOffset + this.dataSize];
        
        byte[] decompressedText;
        byte[] decompressedRodata;
        byte[] decompressedData;
        
        if (this.kip1.isSectionCompressed(SectionType.TEXT))
        {
            byte[] compressedText = this.provider.readBytes(this.kip1.getSectionFileOffset(SectionType.TEXT), textHeader.getCompressedSize());
            decompressedText = new byte[this.textSize];
            ByteUtil.kip1BlzDecompress(decompressedText, compressedText);
        }
        else
        {
            decompressedText = this.provider.readBytes(this.kip1.getSectionFileOffset(SectionType.TEXT), this.textSize);
        }
        
        System.arraycopy(decompressedText, 0, this.full, this.textOffset, this.textSize);
        
        if (this.kip1.isSectionCompressed(SectionType.RODATA))
        {
            byte[] compressedRodata = this.provider.readBytes(this.kip1.getSectionFileOffset(SectionType.RODATA), rodataHeader.getCompressedSize());
            decompressedRodata = new byte[this.rodataSize];
            ByteUtil.kip1BlzDecompress(decompressedRodata, compressedRodata);
        }
        else
        {
            decompressedRodata = this.provider.readBytes(this.kip1.getSectionFileOffset(SectionType.RODATA), this.rodataSize);
        }
        
        System.arraycopy(decompressedRodata, 0, this.full, this.rodataOffset, this.rodataSize);
        
        if (this.kip1.isSectionCompressed(SectionType.DATA))
        {
            byte[] compressedData = this.provider.readBytes(this.kip1.getSectionFileOffset(SectionType.DATA), dataHeader.getCompressedSize());
            decompressedData = new byte[this.dataSize];
            ByteUtil.kip1BlzDecompress(decompressedData, compressedData);
        }
        else
        {
            decompressedData = this.provider.readBytes(this.kip1.getSectionFileOffset(SectionType.DATA), this.dataSize);
        }
        
        System.arraycopy(decompressedData, 0, this.full, this.dataOffset, this.dataSize);
    }
}
