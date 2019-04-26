/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nxo;

import java.io.IOException;

import adubbz.nx.loader.common.InvalidMagicException;
import adubbz.nx.loader.kip1.KIP1SectionHeader;
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
    
    // libnx extensions
    private String lnxMagic;
    private int lnxGotStart;
    private int lnxGotEnd;
    
    public MOD0Header(BinaryReader reader, int readerOffset, int mod0StartOffset) throws InvalidMagicException, IOException
    {
        long prevPointerIndex = reader.getPointerIndex();
        
        reader.setPointerIndex(readerOffset);
        this.readHeader(reader, mod0StartOffset);
        
        // Restore the previous pointer index
        reader.setPointerIndex(prevPointerIndex);
    }
    
    private void readHeader(BinaryReader reader, int mod0StartOffset) throws InvalidMagicException, IOException
    {
        this.magic = reader.readNextAsciiString(4);
        
        if (!this.magic.equals("MOD0"))
            throw new InvalidMagicException("MOD0");
        
        this.dynamicOffset = mod0StartOffset + reader.readNextInt();
        this.bssStartOffset = mod0StartOffset + reader.readNextInt();
        this.bssEndOffset = mod0StartOffset + reader.readNextInt();
        this.ehFrameHdrStartOffset = mod0StartOffset + reader.readNextInt();
        this.ehFrameHdrEndOffset = mod0StartOffset + reader.readNextInt();
        this.runtimeModuleOffset = mod0StartOffset + reader.readNextInt();
        
        this.lnxMagic = reader.readNextAsciiString(4);
        
        if (this.lnxMagic.equals("LNY0"))
        {
            Msg.info(this, "Detected Libnx MOD0 extension");
            this.lnxGotStart = mod0StartOffset + reader.readNextInt();
            this.lnxGotEnd = mod0StartOffset + reader.readNextInt();
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
    
    // libnx extensions
    public boolean hasLibnxExtension()
    {
        return this.lnxMagic.equals("LNY0");
    }
    
    public int getLibnxGotStart()
    {
        return this.lnxGotStart;
    }
    
    public int getLibnxGotEnd()
    {
        return this.lnxGotEnd;
    }
}
