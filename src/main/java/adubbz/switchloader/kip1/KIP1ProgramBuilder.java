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
import adubbz.switchloader.SectionType;
import adubbz.switchloader.SwitchProgramBuilder;
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
        
        this.text = new byte[textHeader.getDecompressedSize()];
        this.rodata = new byte[rodataHeader.getDecompressedSize()];
        this.data = new byte[dataHeader.getDecompressedSize()];
        
        if (this.kip1.isSectionCompressed(SectionType.TEXT))
        {
            byte[] compressedText = this.provider.readBytes(this.kip1.getSectionFileOffset(SectionType.TEXT), textHeader.getCompressedSize());
            ByteUtil.kip1BlzDecompress(this.text, compressedText);
        }
        else
        {
            this.text = this.provider.readBytes(this.kip1.getSectionFileOffset(SectionType.TEXT), textHeader.getDecompressedSize());
        }
        
        if (this.kip1.isSectionCompressed(SectionType.RODATA))
        {
            byte[] compressedRodata = this.provider.readBytes(this.kip1.getSectionFileOffset(SectionType.RODATA), rodataHeader.getCompressedSize());
            ByteUtil.kip1BlzDecompress(this.rodata, compressedRodata);
        }
        else
        {
            this.rodata = this.provider.readBytes(this.kip1.getSectionFileOffset(SectionType.RODATA), rodataHeader.getDecompressedSize());
        }
        
        if (this.kip1.isSectionCompressed(SectionType.DATA))
        {
            byte[] compressedData = this.provider.readBytes(this.kip1.getSectionFileOffset(SectionType.DATA), dataHeader.getCompressedSize());
            ByteUtil.kip1BlzDecompress(this.data, compressedData);
        }
        else
        {
            this.data = this.provider.readBytes(this.kip1.getSectionFileOffset(SectionType.DATA), dataHeader.getDecompressedSize());
        }
        
        this.textOffset = textHeader.getOutOffset();
        this.rodataOffset = rodataHeader.getOutOffset();
        this.dataOffset = dataHeader.getOutOffset();
        this.bssOffset = bssHeader.getOutOffset();
        this.bssSize = bssHeader.getDecompressedSize();
    }
}
