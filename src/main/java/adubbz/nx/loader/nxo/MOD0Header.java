/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nxo;

import java.io.IOException;

import adubbz.nx.common.InvalidMagicException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class MOD0Header 
{
    private String magic;
    private long dynamicOffset;
    private long bssStartOffset;
    private long bssEndOffset;
    private long ehFrameHdrStartOffset;
    private long ehFrameHdrEndOffset;
    private long runtimeModuleOffset;
    
    // libnx extensions
    private String lnxMagic;
    private long lnxGotStart;
    private long lnxGotEnd;
    
    public MOD0Header(BinaryReader reader, long readerOffset, long mod0StartOffset) throws InvalidMagicException, IOException
    {
        long prevPointerIndex = reader.getPointerIndex();
        
        reader.setPointerIndex(readerOffset);
        this.readHeader(reader, mod0StartOffset);
        
        // Restore the previous pointer index
        reader.setPointerIndex(prevPointerIndex);
    }
    
    private void readHeader(BinaryReader reader, long mod0StartOffset) throws InvalidMagicException, IOException
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
    
    public long getDynamicOffset() 
    {
        return this.dynamicOffset;
    }

    public long getBssStartOffset()
    {
        return this.bssStartOffset;
    }
    
    public long getBssEndOffset()
    {
        return this.bssEndOffset;
    }
    
    public long getBssSize()
    {
        return this.bssEndOffset - this.bssStartOffset;
    }
    
    public long getEhFrameHdrStartOffset()
    {
        return this.ehFrameHdrStartOffset;
    }
    
    public long getEhFrameHdrEndOffset()
    {
        return this.ehFrameHdrEndOffset;
    }
    
    public long getRuntimeModuleOffset()
    {
        return this.runtimeModuleOffset;
    }
    
    // libnx extensions
    public boolean hasLibnxExtension()
    {
        return this.lnxMagic.equals("LNY0");
    }
    
    public long getLibnxGotStart()
    {
        return this.lnxGotStart;
    }
    
    public long getLibnxGotEnd()
    {
        return this.lnxGotEnd;
    }
}
