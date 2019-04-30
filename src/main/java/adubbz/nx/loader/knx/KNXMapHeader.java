/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.knx;

import java.io.IOException;

import adubbz.nx.common.InvalidMagicException;
import adubbz.nx.loader.nro0.NRO0SectionHeader;
import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class KNXMapHeader 
{
    private int textOffset;
    private int textEndOffset;
    private int rodataOffset;
    private int rodataEndOffset;
    private int dataOffset;
    private int dataEndOffset;
    private int bssOffset;
    private int bssEndOffset;
    private int ini1Offset;
    private int dynamicOffset;
    private int initArrayOffset;
    private int initArrayEndOffset;
    
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
            this.textOffset = reader.readNextInt();
            this.textEndOffset = reader.readNextInt();
            this.rodataOffset = reader.readNextInt();
            this.rodataEndOffset = reader.readNextInt();
            this.dataOffset = reader.readNextInt();
            this.dataEndOffset = reader.readNextInt();
            this.bssOffset = reader.readNextInt();
            this.bssEndOffset = reader.readNextInt();
            this.ini1Offset = reader.readNextInt();
            this.dynamicOffset = reader.readNextInt();
            this.initArrayOffset = reader.readNextInt();
            this.initArrayEndOffset = reader.readNextInt();
        } 
        catch (IOException e) 
        {
            Msg.error(this, "Failed to read KNX Map header");
        }
    }
    
    public int getTextFileOffset()
    {
        return this.textOffset;
    }
    
    public int getTextSize()
    {
        return this.textEndOffset - this.textOffset;
    }
    
    public int getRodataFileOffset()
    {
        return this.rodataOffset;
    }
    
    public int getRodataSize()
    {
        return this.rodataEndOffset - this.rodataOffset;
    }
    
    public int getDataFileOffset()
    {
        return this.dataOffset;
    }
    
    public int getDataSize()
    {
        return this.dataEndOffset - this.dataOffset;
    }
    
    public int getBssFileOffset()
    {
        return this.bssOffset;
    }
    
    public int getBssSize()
    {
        return this.bssEndOffset - this.bssOffset;
    }
    
    public int getDynamicOffset()
    {
        return this.dynamicOffset;
    }
}
