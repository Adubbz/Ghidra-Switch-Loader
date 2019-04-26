/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.kip1;

import java.io.IOException;

import adubbz.nx.loader.nxo.NXOAdapter;
import adubbz.nx.loader.nxo.NXOSection;
import adubbz.nx.loader.nxo.NXOSectionType;
import adubbz.nx.util.ByteUtil;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.util.Msg;

public class KIP1Adapter extends NXOAdapter
{
    protected ByteProvider fileProvider;
    protected BinaryReader fileReader;
    protected KIP1Header kip1;
    
    protected ByteProvider memoryProvider;
    protected NXOSection[] sections;
    
    public KIP1Adapter(ByteProvider fileProvider)
    {
        this.fileProvider = fileProvider;
        this.fileReader = new BinaryReader(this.fileProvider, true);
        
        try
        {
            this.read();
        }
        catch (IOException e)
        {
            Msg.error(this, "Failed to read KIP1");
            e.printStackTrace();
        }
    }
    
    private void read() throws IOException
    {
        this.kip1 = new KIP1Header(this.fileReader, 0x0);
        
        KIP1SectionHeader textHeader = this.kip1.getSectionHeader(NXOSectionType.TEXT);
        KIP1SectionHeader rodataHeader = this.kip1.getSectionHeader(NXOSectionType.RODATA);
        KIP1SectionHeader dataHeader = this.kip1.getSectionHeader(NXOSectionType.DATA);
        
        int textOffset = textHeader.getOutOffset();
        int rodataOffset = rodataHeader.getOutOffset();
        int dataOffset = dataHeader.getOutOffset();
        int textSize = textHeader.getDecompressedSize();
        int rodataSize = rodataHeader.getDecompressedSize();
        int dataSize = dataHeader.getDecompressedSize();
        
        // The data section is last, so we use its offset + decompressed size
        byte[] full = new byte[dataOffset + dataSize];
        byte[] decompressedText;
        byte[] decompressedRodata;
        byte[] decompressedData;
        
        if (this.kip1.isSectionCompressed(NXOSectionType.TEXT))
        {
            byte[] compressedText = this.fileProvider.readBytes(this.kip1.getSectionFileOffset(NXOSectionType.TEXT), this.kip1.getCompressedSectionSize(NXOSectionType.TEXT));
            decompressedText = ByteUtil.kip1BlzDecompress(compressedText, textSize);
        }
        else
        {
            decompressedText = this.fileProvider.readBytes(this.kip1.getSectionFileOffset(NXOSectionType.TEXT), textSize);
        }
        
        System.arraycopy(decompressedText, 0, full, textOffset, textSize);
        
        if (this.kip1.isSectionCompressed(NXOSectionType.RODATA))
        {
            byte[] compressedRodata = this.fileProvider.readBytes(this.kip1.getSectionFileOffset(NXOSectionType.RODATA), this.kip1.getCompressedSectionSize(NXOSectionType.RODATA));
            decompressedRodata = ByteUtil.kip1BlzDecompress(compressedRodata, rodataSize);
        }
        else
        {
            decompressedRodata = this.fileProvider.readBytes(this.kip1.getSectionFileOffset(NXOSectionType.RODATA), rodataSize);
        }
        
        System.arraycopy(decompressedRodata, 0, full, rodataOffset, rodataSize);
        
        if (this.kip1.isSectionCompressed(NXOSectionType.DATA))
        {
            byte[] compressedData = this.fileProvider.readBytes(this.kip1.getSectionFileOffset(NXOSectionType.DATA), this.kip1.getCompressedSectionSize(NXOSectionType.DATA));
            decompressedData = ByteUtil.kip1BlzDecompress(compressedData, dataSize);
        }
        else
        {
            decompressedData = this.fileProvider.readBytes(this.kip1.getSectionFileOffset(NXOSectionType.DATA), dataSize);
        }
        
        System.arraycopy(decompressedData, 0, full, dataOffset, dataSize);
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
