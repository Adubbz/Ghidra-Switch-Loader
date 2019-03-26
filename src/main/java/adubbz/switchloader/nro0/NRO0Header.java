/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.switchloader.nro0;

import java.io.IOException;

import adubbz.switchloader.common.InvalidMagicException;
import adubbz.switchloader.common.SectionType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class NRO0Header 
{
    private int mod0Offset;
    private String magic;
    private int version;
    private int size;
    private int flags;
    private NRO0SectionHeader textHeader;
    private NRO0SectionHeader rodataHeader;
    private NRO0SectionHeader dataHeader;
    private int bssSize;
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
            reader.readNextInt(); // Reserved
            this.mod0Offset = reader.readNextInt();
            reader.readNextLong(); // Padding
            this.magic = reader.readNextAsciiString(4);
            
            if (!this.magic.equals("NRO0"))
                throw new InvalidMagicException("NRO0");
            
            this.version = reader.readNextInt();
            this.size = reader.readNextInt();
            this.flags = reader.readNextInt();
            this.textHeader = new NRO0SectionHeader(reader);
            this.rodataHeader = new NRO0SectionHeader(reader);
            this.dataHeader = new NRO0SectionHeader(reader);
            this.bssSize = reader.readNextInt();
            reader.readNextInt(); // Reserved
            this.buildId = reader.readNextByteArray(0x20);
            reader.readNextInt(); // Reserved
            this.apiInfo = new NRO0SectionHeader(reader);
            this.dynstr = new NRO0SectionHeader(reader);
            this.dynsym = new NRO0SectionHeader(reader);
        } 
        catch (IOException e) 
        {
            Msg.error(this, "Failed to read NRO0 header");
        }
    }

    public NRO0SectionHeader getSectionHeader(SectionType type)
    {
        switch (type)
        {
            case TEXT:
                return this.textHeader;
    
            case RODATA:
                return this.rodataHeader;
    
            case DATA:
                return this.dataHeader;
    
            default:
                return null;
        }
    }

    public int getBssSize()
    {
        return this.bssSize;
    }
}
