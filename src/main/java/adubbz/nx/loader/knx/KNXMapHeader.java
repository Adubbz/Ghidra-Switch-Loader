/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.knx;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class KNXMapHeader 
{
    private long textOffset;
    private long textEndOffset;
    private long rodataOffset;
    private long rodataEndOffset;
    private long dataOffset;
    private long dataEndOffset;
    private long bssOffset;
    private long bssEndOffset;
    private long ini1Offset;
    private long dynamicOffset;
    private long initArrayOffset;
    private long initArrayEndOffset;
    
    public KNXMapHeader(BinaryReader reader, int readerOffset)
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
            this.textOffset = reader.readNextUnsignedInt();
            this.textEndOffset = reader.readNextUnsignedInt();
            this.rodataOffset = reader.readNextUnsignedInt();
            this.rodataEndOffset = reader.readNextUnsignedInt();
            this.dataOffset = reader.readNextUnsignedInt();
            this.dataEndOffset = reader.readNextUnsignedInt();
            this.bssOffset = reader.readNextUnsignedInt();
            this.bssEndOffset = reader.readNextUnsignedInt();
            this.ini1Offset = reader.readNextUnsignedInt();
            this.dynamicOffset = reader.readNextUnsignedInt();
            this.initArrayOffset = reader.readNextUnsignedInt();
            this.initArrayEndOffset = reader.readNextUnsignedInt();
        } 
        catch (IOException e) 
        {
            Msg.error(this, "Failed to read KNX Map header");
        }
    }
    
    public long getTextFileOffset()
    {
        return this.textOffset;
    }
    
    public long getTextSize()
    {
        return this.textEndOffset - this.textOffset;
    }
    
    public long getRodataFileOffset()
    {
        return this.rodataOffset;
    }
    
    public long getRodataSize()
    {
        return this.rodataEndOffset - this.rodataOffset;
    }
    
    public long getDataFileOffset()
    {
        return this.dataOffset;
    }
    
    public long getDataSize()
    {
        return this.dataEndOffset - this.dataOffset;
    }
    
    public long getBssFileOffset()
    {
        return this.bssOffset;
    }
    
    public long getBssSize()
    {
        return this.bssEndOffset - this.bssOffset;
    }
    
    public long getDynamicOffset()
    {
        return this.dynamicOffset;
    }
}
