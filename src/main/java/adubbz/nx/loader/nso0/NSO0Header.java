/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nso0;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import adubbz.nx.common.InvalidMagicException;
import adubbz.nx.loader.nxo.NXOSectionType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class NSO0Header 
{
    public static final int HEADER_SIZE = 0x100;
    
    private String magic;
    private long version;
    private long flags;
    private NSO0SectionHeader textHeader;
    private long moduleNameOffset;
    private NSO0SectionHeader rodataHeader;
    private long moduleNameSize;
    private NSO0SectionHeader dataHeader;
    private long bssSize;
    private byte[] buildId;
    private long compressedTextSize;
    private long compressedRodataSize;
    private long compressedDataSize;
    private String moduleName;
    
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
            
            this.version = reader.readNextUnsignedInt();
            reader.readNextUnsignedInt(); // Reserved
            this.flags = reader.readNextUnsignedInt();
            this.textHeader = new NSO0SectionHeader(reader);
            this.moduleNameOffset = reader.readNextUnsignedInt();
            this.rodataHeader = new NSO0SectionHeader(reader);
            this.moduleNameSize = reader.readNextUnsignedInt();
            this.dataHeader = new NSO0SectionHeader(reader);
            this.bssSize = reader.readNextUnsignedInt();
            this.buildId = reader.readNextByteArray(0x20);
            this.compressedTextSize = reader.readNextUnsignedInt();
            this.compressedRodataSize = reader.readNextUnsignedInt();
            this.compressedDataSize = reader.readNextUnsignedInt();
            this.readModuleName(reader);
        } 
        catch (IOException e) 
        {
            Msg.error(this, "Failed to read NSO0 header");
        }
    }
    
    // 20.0.0+ stores the module name right after the header. ModuleNameOffset is always
    // the header size. ModuleNameSize may or may not include a terminator, and the name may
    // be padded before .text (e.g. "main" with size 4 and .text at 0x110). Older NSOs leave
    // these fields as reserved values (size 0), so only accept a name that fits before .text.
    private void readModuleName(BinaryReader reader) throws IOException
    {
        long textFileOffset = this.textHeader.getFileOffset();

        if (this.moduleNameOffset != HEADER_SIZE || this.moduleNameSize == 0 ||
                HEADER_SIZE + this.moduleNameSize > textFileOffset || textFileOffset > reader.length())
            return;
        
        byte[] name = reader.readByteArray(HEADER_SIZE, (int)this.moduleNameSize);
        int length = 0;
        
        while (length < name.length && name[length] != 0)
            length++;
        
        if (length > 0)
            this.moduleName = new String(name, 0, length, StandardCharsets.UTF_8);
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
    
    public long getCompressedSectionSize(NXOSectionType type)
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
    
    public long getBssSize()
    {
        return this.bssSize;
    }

    /**
     * @return the embedded module name (20.0.0+), or null if absent.
     */
    public String getModuleName()
    {
        return this.moduleName;
    }

    public boolean isZbic()
    {
        return (this.flags & 0x80L) != 0;
    }
}
