/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nro0;

import java.io.IOException;

import adubbz.nx.common.InvalidMagicException;
import adubbz.nx.loader.nxo.NXOSectionType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class NRO0Header 
{
    private long mod0Offset;
    private String magic;
    private int version;
    private long size;
    private long flags;
    private NRO0SectionHeader textHeader;
    private NRO0SectionHeader rodataHeader;
    private NRO0SectionHeader dataHeader;
    private long bssSize;
    private byte[] buildId;
    private NRO0SectionHeader apiInfo;
    private NRO0SectionHeader dynstr;
    private NRO0SectionHeader dynsym;

    public NRO0Header(BinaryReader reader, int readerOffset)
    {
        long prevPointerIndex = reader.getPointerIndex();
        
        reader.setPointerIndex(readerOffset);
        this.readHeader(reader);
        
        // Restore the previous pointer index
        reader.setPointerIndex(prevPointerIndex);
    }

    private void readHeader(BinaryReader reader)
    {
        try 
        {
            reader.readNextUnsignedInt(); // Reserved
            this.mod0Offset = reader.readNextUnsignedInt();
            reader.readNextLong(); // Padding
            this.magic = reader.readNextAsciiString(4);
            
            if (!this.magic.equals("NRO0"))
                throw new InvalidMagicException("NRO0");
            
            this.version = reader.readNextUnsignedByte();
            this.size = reader.readNextUnsignedInt();
            this.flags = reader.readNextUnsignedInt();
            this.textHeader = new NRO0SectionHeader(reader);
            this.rodataHeader = new NRO0SectionHeader(reader);
            this.dataHeader = new NRO0SectionHeader(reader);
            this.bssSize = reader.readNextUnsignedInt();
            reader.readNextUnsignedInt(); // Reserved
            this.buildId = reader.readNextByteArray(0x20);
            reader.readNextUnsignedInt(); // Reserved
            this.apiInfo = new NRO0SectionHeader(reader);
            this.dynstr = new NRO0SectionHeader(reader);
            this.dynsym = new NRO0SectionHeader(reader);
        } 
        catch (IOException e) 
        {
            Msg.error(this, "Failed to read NRO0 header");
        }
    }

    public NRO0SectionHeader getSectionHeader(NXOSectionType type)
    {
        return switch (type) {
            case TEXT -> this.textHeader;
            case RODATA -> this.rodataHeader;
            case DATA -> this.dataHeader;
            default -> null;
        };
    }

    public long getBssSize()
    {
        return this.bssSize;
    }
}
