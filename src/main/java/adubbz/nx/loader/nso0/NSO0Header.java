/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nso0;

import java.io.IOException;

import adubbz.nx.common.InvalidMagicException;
import adubbz.nx.loader.nxo.NXOSectionType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class NSO0Header 
{
    private String magic;
    private int version;
    private int flags;
    private NSO0SectionHeader textHeader;
    private int moduleOffset;
    private NSO0SectionHeader rodataHeader;
    private int moduleFileSize;
    private NSO0SectionHeader dataHeader;
    private int bssSize;
    private byte[] buildId;
    private int compressedTextSize;
    private int compressedRodataSize;
    private int compressedDataSize;
    
    public NSO0Header(BinaryReader reader, int readerOffset)
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
            this.magic = reader.readNextAsciiString(4);
            
            if (!this.magic.equals("NSO0"))
                throw new InvalidMagicException("NSO0");
            
            this.version = reader.readNextInt();
            reader.readNextInt(); // Reserved
            this.flags = reader.readNextInt();
            this.textHeader = new NSO0SectionHeader(reader);
            this.moduleOffset = reader.readNextInt();
            this.rodataHeader = new NSO0SectionHeader(reader);
            this.moduleFileSize = reader.readNextInt();
            this.dataHeader = new NSO0SectionHeader(reader);
            this.bssSize = reader.readNextInt();
            this.buildId = reader.readNextByteArray(0x20);
            this.compressedTextSize = reader.readNextInt();
            this.compressedRodataSize = reader.readNextInt();
            this.compressedDataSize = reader.readNextInt();
        } 
        catch (IOException e) 
        {
            Msg.error(this, "Failed to read NSO0 header");
        }
    }
    
    public NSO0SectionHeader getSectionHeader(NXOSectionType type)
    {
        return switch (type) {
            case TEXT -> this.textHeader;
            case RODATA -> this.rodataHeader;
            case DATA -> this.dataHeader;
            default -> null;
        };
    }
    
    public long getSectionFileOffset(NXOSectionType type)
    {
        return switch (type) {
            case TEXT -> this.textHeader.getFileOffset();
            case RODATA -> this.rodataHeader.getFileOffset();
            case DATA -> this.dataHeader.getFileOffset();
            default -> 0;
        };
    }
    
    public int getCompressedSectionSize(NXOSectionType type)
    {
        return switch (type) {
            case TEXT -> this.compressedTextSize;
            case RODATA -> this.compressedRodataSize;
            case DATA -> this.compressedDataSize;
            case BSS -> this.bssSize;
        };
    }
    
    public boolean isSectionCompressed(NXOSectionType type)
    {
        int index = type.ordinal();
        
        if (index > 2)
            return false;
        
        int flagMask = 1 << index;
        return (this.flags & flagMask) > 0;
    }
    
    public int getBssSize()
    {
        return this.bssSize;
    }
}
