/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package adubbz.switchloader.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.util.Msg;

public class ByteUtil 
{
    public static byte[] kip1BlzDecompress(byte[] compressed, int decompressedSize)
    {
        int uncompressedAdditionalSize = ByteBuffer.wrap(compressed, compressed.length - 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int headerSize = ByteBuffer.wrap(compressed, compressed.length - 8, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int compressedAndHeaderSize = ByteBuffer.wrap(compressed, compressed.length - 12, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        
        int compressedStart = compressed.length - compressedAndHeaderSize;
        int compressedOffset = compressedAndHeaderSize - headerSize;
        int outOffset = compressedAndHeaderSize + uncompressedAdditionalSize;
        
        byte out[] = new byte[decompressedSize];
        System.arraycopy(compressed, 0, out, 0, compressed.length);
        
        while (outOffset > 0)
        {
            byte control = out[compressedStart + --compressedOffset];
            
            for (int i = 0; i < 8; i++)
            {
                if ((control & 0x80) > 0)
                {
                    if (compressedOffset < 2)
                        throw new IndexOutOfBoundsException("Compression out of bounds!");
                    
                    compressedOffset -= 2;
                    
                    // Java has no concept of unsigned bytes, so when converting them to ints it'll think they're sometimes
                    // negative. We obviously don't want this.
                    int segmentValue = (Byte.toUnsignedInt(out[compressedStart + compressedOffset + 1]) << 8) | Byte.toUnsignedInt(out[compressedStart + compressedOffset]);
                    int segmentSize = ((segmentValue >> 12) & 0xF) + 3;
                    int segmentOffset = (segmentValue & 0x0FFF) + 3;
                    
                    if (outOffset < segmentSize)
                    {
                        /* Kernel restricts segment copy to stay in bounds. */
                        segmentSize = outOffset;
                    }
                    
                    outOffset -= segmentSize;
                    
                    for (int j = 0; j < segmentSize; j++)
                    {
                        out[compressedStart + outOffset + j] = out[compressedStart + outOffset + j + segmentOffset];
                    }
                }
                else
                {
                    if (compressedOffset < 1)
                        throw new IndexOutOfBoundsException("Compression out of bounds!");
                    
                    out[compressedStart + --outOffset] = out[compressedStart + --compressedOffset];
                }
                
                control <<= 1;
                
                if (outOffset == 0)
                    break;
            }
        }
        
        return out;
    }
    
    public static void logBytes(byte[] data)
    {
        StringBuilder sb = new StringBuilder();
        int lineWidth = 0;
        
        for (byte b : data) 
        {
            sb.append(String.format("%02X ", b));
            lineWidth++;
            
            if (lineWidth >= 16)
            {
                sb.append("\n");
                lineWidth = 0;
            }
        }
        
        Msg.info(null, sb.toString());
    }
}
