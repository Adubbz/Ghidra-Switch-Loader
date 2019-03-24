/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package adubbz.switchloader.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import adubbz.switchloader.common.SectionType;
import ghidra.util.Msg;

public class ByteUtil 
{
    public static byte[] kip1BlzDecompress(byte[] compressed)
    {
        int compressedSize = ByteBuffer.wrap(compressed, compressed.length - 12, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int initIndex = ByteBuffer.wrap(compressed, compressed.length - 8, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int uncompressedAdditionalSize = ByteBuffer.wrap(compressed, compressed.length - 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int decompressedSize = compressed.length + uncompressedAdditionalSize;
        byte[] decompressed = new byte[decompressedSize];
        
        // Copy the compressed array to the decompressed array
        System.arraycopy(compressed, 0, decompressed, 0, compressed.length);
        Arrays.fill(decompressed, compressed.length, decompressed.length - 1, (byte)0);
        
        // Homebrew kips often have a mismatch. This is probably a bug with elf2kip.
        if (compressed.length != compressedSize)
        {
            Msg.warn(null, String.format("Compressed size mismatch. Given 0x%x bytes, expected 0x%x.", compressed.length, compressedSize));
            
            if (compressed.length < compressedSize)
                throw new IllegalArgumentException("In buffer is too small!");
            
            byte[] tmp = new byte[compressedSize];
            System.arraycopy(compressed, compressed.length - compressedSize, tmp, 0, compressedSize);
            compressed = tmp;
        }
        
        if (compressedSize + uncompressedAdditionalSize == 0)
        {
            throw new IllegalArgumentException("Compressed size is zero!");
        }
        
        int index = compressedSize - initIndex;
        int outIndex = decompressedSize;
        byte control = 0;
        
        while (outIndex > 0)
        {
            index--;
            // Wrap back around
            if (index < 0) index = compressed.length - 1;
            
            control = compressed[index];
            
            for (int i = 0; i < 8; i++)
            {
                if ((control & 0x80) > 0)
                {
                    if (index < 2)
                    {
                        throw new IndexOutOfBoundsException("Compression out of bounds!");
                    }
                    
                    index -= 2;
                    
                    // Java has no concept of unsigned bytes, so when converting them to ints it'll think they're sometimes
                    // negative. We obviously don't want this.
                    int segmentOffset = Byte.toUnsignedInt(compressed[index]) | (Byte.toUnsignedInt(compressed[index + 1]) << 8);
                    int segmentSize = ((segmentOffset >> 12) & 0xF) + 3;
                    
                    segmentOffset &= 0x0FFF;
                    segmentOffset += 2;
                    
                    if (outIndex < segmentSize)
                        throw new IndexOutOfBoundsException("Compression out of bounds!");
                    
                    for (int j = 0; j < segmentSize; j++)
                    {
                        if (outIndex + segmentOffset >= decompressedSize)
                        {
                            throw new IndexOutOfBoundsException("Compression out of bounds!");
                        }
                        
                        byte data = decompressed[outIndex + segmentOffset];
                        outIndex--;
                        decompressed[outIndex] = data;
                    }
                }
                else
                {
                    if (outIndex < 1)
                        throw new IndexOutOfBoundsException("Compression out of bounds!");
                    
                    outIndex--;
                    index--;
                    
                    // Wrap back around
                    if (index < 0) index = compressed.length - 1;
                    
                    decompressed[outIndex] = compressed[index];
                }
                
                control <<= 1;
                control &= 0xFF;
                
                if (outIndex == 0)
                    break;
            }
        }
        
        return decompressed;
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
