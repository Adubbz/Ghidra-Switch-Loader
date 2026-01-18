/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nro0;

import java.io.IOException;

import adubbz.nx.loader.nxo.MOD0Adapter;
import adubbz.nx.loader.nxo.NXOSection;
import adubbz.nx.loader.nxo.NXOSectionType;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class NRO0Adapter extends MOD0Adapter
{
    protected NRO0Header nro0;
    
    protected ByteProvider memoryProvider;
    protected NXOSection[] sections;
    
    public NRO0Adapter(Program program, ByteProvider fileProvider)
    {
        super(program, fileProvider);
        
        try
        {
            this.read();
        }
        catch (IOException e)
        {
            Msg.error(this, "Failed to read NRO0");
            e.printStackTrace();
        }
    }
    
    private void read() throws IOException
    {
        this.nro0 = new NRO0Header(this.fileReader, 0x0);
        
        NRO0SectionHeader textHeader = this.nro0.getSectionHeader(NXOSectionType.TEXT);
        NRO0SectionHeader rodataHeader = this.nro0.getSectionHeader(NXOSectionType.RODATA);
        NRO0SectionHeader dataHeader = this.nro0.getSectionHeader(NXOSectionType.DATA);

        long textOffset = textHeader.getFileOffset();
        long rodataOffset = rodataHeader.getFileOffset();
        long dataOffset = dataHeader.getFileOffset();
        long textSize = textHeader.getSize();
        long rodataSize = rodataHeader.getSize();
        long dataSize = dataHeader.getSize();

        // The data section is last, so we use its offset + decompressed size
        byte[] full = new byte[Math.toIntExact(dataOffset + dataSize)];

        byte[] text = this.fileProvider.readBytes(textHeader.getFileOffset(), textSize);
        System.arraycopy(text, 0, full, Math.toIntExact(textOffset), Math.toIntExact(textSize));

        byte[] rodata = this.fileProvider.readBytes(rodataHeader.getFileOffset(), rodataSize);
        System.arraycopy(rodata, 0, full, Math.toIntExact(rodataOffset), Math.toIntExact(rodataSize));

        byte[] data = this.fileProvider.readBytes(dataHeader.getFileOffset(), dataSize);
        System.arraycopy(data, 0, full, Math.toIntExact(dataOffset), Math.toIntExact(dataSize));
        this.memoryProvider = new ByteArrayProvider(full);
        
        this.sections = new NXOSection[3];
        this.sections[NXOSectionType.TEXT.ordinal()] = new NXOSection(NXOSectionType.TEXT, textOffset, textSize);
        this.sections[NXOSectionType.RODATA.ordinal()] = new NXOSection(NXOSectionType.RODATA, rodataOffset, rodataSize);
        this.sections[NXOSectionType.DATA.ordinal()] = new NXOSection(NXOSectionType.DATA, dataOffset, dataSize);
    }

    @Override
    public ByteProvider getMemoryProvider() 
    {
        return this.memoryProvider;
    }

    @Override
    public NXOSection[] getSections() 
    {
        return this.sections;
    }
}
