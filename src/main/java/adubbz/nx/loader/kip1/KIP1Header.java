/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.kip1;

import java.io.IOException;

import adubbz.nx.common.InvalidMagicException;
import adubbz.nx.loader.nxo.NXOSectionType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class KIP1Header 
{
    private String magic;
    private String name;
    private long tid;
    private int processCategory;
    private byte mainThreadPriority;
    private byte defaultCpuCore;
    private byte flags;
    
    private KIP1SectionHeader[] sectionHeaders = new KIP1SectionHeader[6];
    
    public KIP1Header(BinaryReader reader, int readerOffset)
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
            
            if (!this.magic.equals("KIP1"))
                throw new InvalidMagicException("KIP1");
            
            this.name = reader.readNextAsciiString(12);
            this.tid = reader.readNextLong();
            this.processCategory = reader.readNextInt();
            this.mainThreadPriority = reader.readNextByte();
            this.defaultCpuCore = reader.readNextByte();
            reader.readNextByte(); // Unused
            this.flags = reader.readNextByte();
            
            for (int i = 0; i < this.sectionHeaders.length; i++)
            {
                this.sectionHeaders[i] = new KIP1SectionHeader(reader);
            }
        } 
        catch (IOException e) 
        {
            Msg.error(this, "Failed to read KIP1 header");
        }
    }
    
    public KIP1SectionHeader getSectionHeader(NXOSectionType type)
    {
        return this.sectionHeaders[type.ordinal()];
    }
    
    public long getSectionFileOffset(NXOSectionType type)
    {
        if (type == NXOSectionType.TEXT)
            return 0x100;
        else
        {
            NXOSectionType prevType = NXOSectionType.values()[type.ordinal() - 1];
            KIP1SectionHeader prevHeader = this.getSectionHeader(prevType);
            return this.getSectionFileOffset(prevType) + prevHeader.getCompressedSize();
        }
    }
    
    public int getCompressedSectionSize(NXOSectionType type)
    {
        return this.sectionHeaders[type.ordinal()].getCompressedSize();
    }
    
    public boolean isSectionCompressed(NXOSectionType type)
    {
        int index = type.ordinal();
        
        if (index > 2)
            return false;
        
        int flagMask = 1 << index;
        return (this.flags & flagMask) > 0;
    }
}
