/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nso0;

import adubbz.nx.util.ZbicUtil;
import adubbz.nx.common.ZbicException;

import java.io.IOException;

import adubbz.nx.loader.nxo.MOD0Adapter;
import adubbz.nx.loader.nxo.NXOSection;
import adubbz.nx.loader.nxo.NXOSectionType;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import net.jpountz.lz4.LZ4Factory;
import net.jpountz.lz4.LZ4FastDecompressor;

public class NSO0Adapter extends MOD0Adapter
{
    protected NSO0Header nso0;
    
    protected ByteProvider memoryProvider;
    protected NXOSection[] sections;
    
    public NSO0Adapter(Program program, ByteProvider fileProvider)
    {
        super(program, fileProvider);
        
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
        
        if (this.nso0.getModuleName() != null)
            Msg.info(this, "Module name: " + this.nso0.getModuleName());

        LZ4Factory factory = LZ4Factory.fastestInstance();
        LZ4FastDecompressor lz4 = factory.fastDecompressor();

        NSO0SectionHeader textHeader  = this.nso0.getSectionHeader(NXOSectionType.TEXT);
        NSO0SectionHeader rodataHeader = this.nso0.getSectionHeader(NXOSectionType.RODATA);
        NSO0SectionHeader dataHeader  = this.nso0.getSectionHeader(NXOSectionType.DATA);

        long textOffset  = textHeader.getMemoryOffset();
        long rodataOffset = rodataHeader.getMemoryOffset();
        long dataOffset  = dataHeader.getMemoryOffset();
        long textSize    = textHeader.getDecompressedSize();
        long rodataSize  = rodataHeader.getDecompressedSize();
        long dataSize    = dataHeader.getDecompressedSize();

        byte[] full = new byte[Math.toIntExact(dataOffset + dataSize)];

        boolean isZbic = this.nso0.isZbic();

        // TEXT
        byte[] decompressedText = decompressSection(
            NXOSectionType.TEXT, textSize, isZbic, lz4);
        System.arraycopy(decompressedText, 0, full,
            Math.toIntExact(textOffset), Math.toIntExact(textSize));

        // RODATA
        byte[] decompressedRodata = decompressSection(
            NXOSectionType.RODATA, rodataSize, isZbic, lz4);
        System.arraycopy(decompressedRodata, 0, full,
            Math.toIntExact(rodataOffset), Math.toIntExact(rodataSize));

        // DATA
        byte[] decompressedData = decompressSection(
            NXOSectionType.DATA, dataSize, isZbic, lz4);
        System.arraycopy(decompressedData, 0, full,
            Math.toIntExact(dataOffset), Math.toIntExact(dataSize));

        this.memoryProvider = new ByteArrayProvider(full);

        this.sections = new NXOSection[3];
        this.sections[NXOSectionType.TEXT.ordinal()]   = new NXOSection(NXOSectionType.TEXT,   textOffset,  textSize);
        this.sections[NXOSectionType.RODATA.ordinal()] = new NXOSection(NXOSectionType.RODATA, rodataOffset, rodataSize);
        this.sections[NXOSectionType.DATA.ordinal()]   = new NXOSection(NXOSectionType.DATA,   dataOffset,  dataSize);
    }

    private byte[] decompressSection(NXOSectionType type, long decompSize,
                                    boolean isZbic, LZ4FastDecompressor lz4)
        throws IOException
    {
        if (!this.nso0.isSectionCompressed(type))
        {
            return this.fileProvider.readBytes(
                this.nso0.getSectionFileOffset(type), decompSize);
        }

        byte[] compressed = this.fileProvider.readBytes(
            this.nso0.getSectionFileOffset(type),
            this.nso0.getCompressedSectionSize(type));

        if (isZbic)
        {
            try
            {
                byte[] out = ZbicUtil.decompress(compressed);
                if (out.length != decompSize)
                {
                    throw new IOException(String.format(
                        "ZBIC %s size mismatch: got %d, expected %d",
                        type, out.length, decompSize));
                }
                return out;
            }
            catch (ZbicException e)
            {
                throw new IOException("Failed to decompress ZBIC " + type + " section", e);
            }
        }
        else
        {
            byte[] out = new byte[Math.toIntExact(decompSize)];
            lz4.decompress(compressed, out);
            return out;
        }
    }

    public String getModuleName()
    {
        return this.nso0.getModuleName();
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
