/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.switchloader.nro0;

import java.io.IOException;

import adubbz.switchloader.common.SectionType;
import adubbz.switchloader.common.SwitchProgramBuilder;
import adubbz.switchloader.util.ByteUtil;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;


public class NRO0ProgramBuilder extends SwitchProgramBuilder
{
    private NRO0Header nro0;
    
    protected NRO0ProgramBuilder(NRO0Header nro0, ByteProvider provider, Program program, MemoryConflictHandler handler)
    {
        super(provider, program, handler);
        this.nro0 = nro0;
    }
    
    public static void loadNRO0(NRO0Header header, ByteProvider provider, Program program, MemoryConflictHandler conflictHandler, TaskMonitor monitor)
    {
        NRO0ProgramBuilder builder = new NRO0ProgramBuilder(header, provider, program, conflictHandler);
        builder.load(monitor);
    }
    
    @Override
    protected void loadDefaultSegments(TaskMonitor monitor) throws IOException, AddressOverflowException, AddressOutOfBoundsException
    {
        long baseAddress = 0x7100000000L;
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        
        NRO0SectionHeader textHeader = this.nro0.getSectionHeader(SectionType.TEXT);
        NRO0SectionHeader rodataHeader = this.nro0.getSectionHeader(SectionType.RODATA);
        NRO0SectionHeader dataHeader = this.nro0.getSectionHeader(SectionType.DATA);
        
        this.textOffset = textHeader.getFileOffset();
        this.rodataOffset = rodataHeader.getFileOffset();
        this.dataOffset = dataHeader.getFileOffset();
        this.textSize = textHeader.getSize();
        this.rodataSize = rodataHeader.getSize();
        this.dataSize = dataHeader.getSize();
        
        // The data section is last, so we use its offset + decompressed size
        byte[] full = new byte[this.dataOffset + this.dataSize];
        
        byte[] text = this.fileByteProvider.readBytes(textHeader.getFileOffset(), this.textSize);
		System.arraycopy(text, 0, full, this.textOffset, this.textSize);
        
        byte[] rodata = this.fileByteProvider.readBytes(rodataHeader.getFileOffset(), this.rodataSize);
		System.arraycopy(rodata, 0, full, this.rodataOffset, this.rodataSize);
        
        byte[] data = this.fileByteProvider.readBytes(dataHeader.getFileOffset(), this.dataSize);
		System.arraycopy(data, 0, full, this.dataOffset, this.dataSize);
        this.memoryByteProvider = new ByteArrayProvider(full);
    }
}
