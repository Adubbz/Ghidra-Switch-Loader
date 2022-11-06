/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.util;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class LegacyBinaryReader extends BinaryReader
{
    public LegacyBinaryReader(ByteProvider provider, boolean isLittleEndian)
    {
        super(provider, isLittleEndian);
    }

    // readAsciiString no longer works correctly as of Ghidra 9.1. Here we revert back to the old version
    @Override
    public String readAsciiString(long index) throws IOException 
    {
        StringBuffer buffer = new StringBuffer();
        while (true) {
            if (index == this.getByteProvider().length()) {
                // reached the end of the bytes and found no non-ascii data
                break;
            }
            byte b = this.getByteProvider().readByte(index++);
            if ((b >= 32) && (b <= 126)) {
                buffer.append((char) b);
            }
            else {
                break;
            }
        }
        return buffer.toString().trim();
    }
}
