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

import ghidra.util.Msg;

public class ByteUtil 
{
    public static void kip1BlzDecompress(byte[] out, byte[] in)
    {
        int compressedSize = ByteBuffer.wrap(in, in.length - 12, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int initIndex = ByteBuffer.wrap(in, in.length - 8, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int uncompressedAdditionalSize = ByteBuffer.wrap(in, in.length - 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        
        if (in.length != compressedSize)
        {
            if (in.length < compressedSize)
                throw new IllegalArgumentException("In buffer is too small!");
            
            System.arraycopy(in, 0, in, 0, compressedSize);
        }
        
        if (compressedSize + uncompressedAdditionalSize == 0)
        {
            Msg.error(null, "Compressed size is zero!");
            return;
        }
        
        // Copy the compressed array to the decompressed array
        System.arraycopy(in, 0, out, 0, compressedSize);
        Arrays.fill(out, compressedSize, out.length - 1, (byte)0);
        
        int decompressedSize = in.length + uncompressedAdditionalSize;
        int index = compressedSize - initIndex;
        int outIndex = decompressedSize;
        byte control = 0;
        
        while (outIndex > 0)
        {
            index--;
            control = in[index];
            
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
                    int segmentOffset = Byte.toUnsignedInt(in[index]) | (Byte.toUnsignedInt(in[index + 1]) << 8);
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
                        
                        byte data = out[outIndex + segmentOffset];
                        outIndex--;
                        out[outIndex] = data;
                    }
                }
                else
                {
                    if (outIndex < 1)
                        throw new IndexOutOfBoundsException("Compression out of bounds!");
                    
                    outIndex--;
                    index--;
                    out[outIndex] = in[index];
                }
                
                control <<= 1;
                control &= 0xFF;
                
                if (outIndex == 0)
                    break;
            }
        }
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
