/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package adubbz.nx.loader.kip1;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

public class KIP1SectionHeader 
{
    private long outOffset;
    private long decompressedSize;
    private long compressedSize;
    private long attributes;
    
    public KIP1SectionHeader(BinaryReader reader)
    {
        this.readHeader(reader);
    }
    
    private void readHeader(BinaryReader reader)
    {
        try
        {
            this.outOffset = reader.readNextUnsignedInt();
            this.decompressedSize = reader.readNextUnsignedInt();
            this.compressedSize = reader.readNextUnsignedInt();
            this.attributes = reader.readNextUnsignedInt();
        } 
        catch (IOException e) 
        {
            Msg.error(this, "Failed to read KIP1 section header");
        }
    }
    
    public long getOutOffset()
    {
        return this.outOffset;
    }
    
    public long getDecompressedSize()
    {
        return this.decompressedSize;
    }
    
    /* 
     * NOTE: This will be the same as the decompressed size when
     * no compression is applied.
     */
    public long getCompressedSize()
    {
        return this.compressedSize;
    }
    
    public long getAttributes()
    {
        return this.attributes;
    }
}
