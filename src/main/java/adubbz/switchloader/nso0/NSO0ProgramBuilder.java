/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.switchloader.nso0;

import java.io.IOException;

import adubbz.switchloader.common.SectionType;
import adubbz.switchloader.common.SwitchProgramBuilder;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import net.jpountz.lz4.LZ4Factory;
import net.jpountz.lz4.LZ4FastDecompressor;

public class NSO0ProgramBuilder extends SwitchProgramBuilder
{
    private NSO0Header nso0;
    
    protected NSO0ProgramBuilder(NSO0Header nso0, ByteProvider provider, Program program, MemoryConflictHandler handler)
    {
        super(provider, program, handler);
        this.nso0 = nso0;
    }
    
    public static void loadNSO0(NSO0Header header, ByteProvider provider, Program program, MemoryConflictHandler conflictHandler, TaskMonitor monitor)
    {
        NSO0ProgramBuilder builder = new NSO0ProgramBuilder(header, provider, program, conflictHandler);
        builder.load(monitor);
    }
    
    @Override
    protected void loadDefaultSegments(TaskMonitor monitor) throws IOException, AddressOverflowException, AddressOutOfBoundsException
    {
        long baseAddress = 0x7100000000L;
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        LZ4Factory factory = LZ4Factory.fastestInstance();
        LZ4FastDecompressor decompressor = factory.fastDecompressor();
        
        NSO0SectionHeader textHeader = this.nso0.getSectionHeader(SectionType.TEXT);
        NSO0SectionHeader rodataHeader = this.nso0.getSectionHeader(SectionType.RODATA);
        NSO0SectionHeader dataHeader = this.nso0.getSectionHeader(SectionType.DATA);
        
        this.textOffset = textHeader.getMemoryOffset();
        this.rodataOffset = rodataHeader.getMemoryOffset();
        this.dataOffset = dataHeader.getMemoryOffset();
        this.textSize = textHeader.getDecompressedSize();
        this.rodataSize = rodataHeader.getDecompressedSize();
        this.dataSize = dataHeader.getDecompressedSize();
        
        // The data section is last, so we use its offset + decompressed size
        byte[] full = new byte[this.dataOffset + this.dataSize];
        byte[] decompressedText;
        byte[] decompressedRodata;
        byte[] decompressedData;
        
        if (this.nso0.isSectionCompressed(SectionType.TEXT))
        {
            byte[] compressedText = this.fileByteProvider.readBytes(this.nso0.getSectionFileOffset(SectionType.TEXT), this.nso0.getCompressedSectionSize(SectionType.TEXT));
            decompressedText = new byte[this.textSize];
            decompressor.decompress(compressedText, decompressedText);
        }
        else
        {
            decompressedText = this.fileByteProvider.readBytes(this.nso0.getSectionFileOffset(SectionType.TEXT), this.textSize);
        }
        
        System.arraycopy(decompressedText, 0, full, this.textOffset, this.textSize);
        
        if (this.nso0.isSectionCompressed(SectionType.RODATA))
        {
            byte[] compressedRodata = this.fileByteProvider.readBytes(this.nso0.getSectionFileOffset(SectionType.RODATA), this.nso0.getCompressedSectionSize(SectionType.RODATA));
            decompressedRodata = new byte[this.rodataSize];
            decompressor.decompress(compressedRodata, decompressedRodata);
        }
        else
        {
            decompressedRodata = this.fileByteProvider.readBytes(this.nso0.getSectionFileOffset(SectionType.RODATA), this.rodataSize);
        }
        
        System.arraycopy(decompressedRodata, 0, full, this.rodataOffset, this.rodataSize);
        
        if (this.nso0.isSectionCompressed(SectionType.DATA))
        {
            byte[] compressedData = this.fileByteProvider.readBytes(this.nso0.getSectionFileOffset(SectionType.DATA), this.nso0.getCompressedSectionSize(SectionType.DATA));
            decompressedData = new byte[this.dataSize];
            decompressor.decompress(compressedData, decompressedData);
        }
        else
        {
            decompressedData = this.fileByteProvider.readBytes(this.nso0.getSectionFileOffset(SectionType.DATA), this.dataSize);
        }
        
        System.arraycopy(decompressedData, 0, full, this.dataOffset, this.dataSize);
        this.memoryByteProvider = new ByteArrayProvider(full);
    }
}
