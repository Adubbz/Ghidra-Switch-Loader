/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.switchloader.nso0;

import java.io.IOException;

import adubbz.switchloader.nxo.NXOAdapter;
import adubbz.switchloader.nxo.NXOSection;
import adubbz.switchloader.nxo.NXOSectionType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.util.Msg;
import net.jpountz.lz4.LZ4Factory;
import net.jpountz.lz4.LZ4FastDecompressor;

public class NSO0Adapter extends NXOAdapter
{
    protected ByteProvider fileProvider;
    protected BinaryReader fileReader;
    protected NSO0Header nso0;
    
    protected ByteProvider memoryProvider;
    protected NXOSection[] sections;
    
    public NSO0Adapter(ByteProvider fileProvider)
    {
        this.fileProvider = fileProvider;
        this.fileReader = new BinaryReader(this.fileProvider, true);
        
        try
        {
            this.read();
        }
        catch (IOException e)
        {
            Msg.error(this, "Failed to read NSO0");
            e.printStackTrace();
        }
    }
    
    private void read() throws IOException
    {
        this.nso0 = new NSO0Header(this.fileReader, 0x0);
        
        LZ4Factory factory = LZ4Factory.fastestInstance();
        LZ4FastDecompressor decompressor = factory.fastDecompressor();
        
        NSO0SectionHeader textHeader = this.nso0.getSectionHeader(NXOSectionType.TEXT);
        NSO0SectionHeader rodataHeader = this.nso0.getSectionHeader(NXOSectionType.RODATA);
        NSO0SectionHeader dataHeader = this.nso0.getSectionHeader(NXOSectionType.DATA);
        
        int textOffset = textHeader.getMemoryOffset();
        int rodataOffset = rodataHeader.getMemoryOffset();
        int dataOffset = dataHeader.getMemoryOffset();
        int textSize = textHeader.getDecompressedSize();
        int rodataSize = rodataHeader.getDecompressedSize();
        int dataSize = dataHeader.getDecompressedSize();
        
        // The data section is last, so we use its offset + decompressed size
        byte[] full = new byte[dataOffset + dataSize];
        byte[] decompressedText;
        byte[] decompressedRodata;
        byte[] decompressedData;
        
        if (this.nso0.isSectionCompressed(NXOSectionType.TEXT))
        {
            byte[] compressedText = this.fileProvider.readBytes(this.nso0.getSectionFileOffset(NXOSectionType.TEXT), this.nso0.getCompressedSectionSize(NXOSectionType.TEXT));
            decompressedText = new byte[textSize];
            decompressor.decompress(compressedText, decompressedText);
        }
        else
        {
            decompressedText = this.fileProvider.readBytes(this.nso0.getSectionFileOffset(NXOSectionType.TEXT), textSize);
        }
        
        System.arraycopy(decompressedText, 0, full, textOffset, textSize);
        
        if (this.nso0.isSectionCompressed(NXOSectionType.RODATA))
        {
            byte[] compressedRodata = this.fileProvider.readBytes(this.nso0.getSectionFileOffset(NXOSectionType.RODATA), this.nso0.getCompressedSectionSize(NXOSectionType.RODATA));
            decompressedRodata = new byte[rodataSize];
            decompressor.decompress(compressedRodata, decompressedRodata);
        }
        else
        {
            decompressedRodata = this.fileProvider.readBytes(this.nso0.getSectionFileOffset(NXOSectionType.RODATA), rodataSize);
        }
        
        System.arraycopy(decompressedRodata, 0, full, rodataOffset, rodataSize);
        
        if (this.nso0.isSectionCompressed(NXOSectionType.DATA))
        {
            byte[] compressedData = this.fileProvider.readBytes(this.nso0.getSectionFileOffset(NXOSectionType.DATA), this.nso0.getCompressedSectionSize(NXOSectionType.DATA));
            decompressedData = new byte[dataSize];
            decompressor.decompress(compressedData, decompressedData);
        }
        else
        {
            decompressedData = this.fileProvider.readBytes(this.nso0.getSectionFileOffset(NXOSectionType.DATA), dataSize);
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
