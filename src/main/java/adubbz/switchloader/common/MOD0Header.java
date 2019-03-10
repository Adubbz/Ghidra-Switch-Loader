/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.switchloader.common;

import java.io.IOException;

import adubbz.switchloader.kip1.KIP1SectionHeader;
import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class MOD0Header 
{
    private String magic;
    private int dynamicOffset;
    private int bssStartOffset;
    private int bssEndOffset;
    private int ehFrameHdrStartOffset;
    private int ehFrameHdrEndOffset;
    private int runtimeModuleOffset;
    
    public MOD0Header(BinaryReader reader, int startOffset)
    {
        this.readHeader(reader, startOffset);
    }
    
    private void readHeader(BinaryReader reader, int startOffset)
    {
        try 
        {
            this.magic = reader.readNextAsciiString(4);
            this.dynamicOffset = startOffset + reader.readNextInt();
            this.bssStartOffset = startOffset + reader.readNextInt();
            this.bssEndOffset = startOffset + reader.readNextInt();
            this.ehFrameHdrStartOffset = startOffset + reader.readNextInt();
            this.ehFrameHdrEndOffset = startOffset + reader.readNextInt();
            this.runtimeModuleOffset = startOffset + reader.readNextInt();
        } 
        catch (IOException e) 
        {
            Msg.error(this, "Failed to read MOD0 header", e);
        }
    }
    
    public int getDynamicOffset() 
    {
        return this.dynamicOffset;
    }

    public int getBssStartOffset()
    {
        return this.bssStartOffset;
    }
    
    public int getBssEndOffset()
    {
        return this.bssEndOffset;
    }
    
    public int getBssSize()
    {
        return this.bssEndOffset - this.bssStartOffset;
    }
    
    public int getEhFrameHdrStartOffset()
    {
        return this.ehFrameHdrStartOffset;
    }
    
    public int getEhFrameHdrEndOffset()
    {
        return this.ehFrameHdrEndOffset;
    }
    
    public int getRuntimeModuleOffset()
    {
        return this.runtimeModuleOffset;
    }
}
