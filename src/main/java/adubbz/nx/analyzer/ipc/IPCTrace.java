/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.analyzer.ipc;

import java.util.StringJoiner;

public class IPCTrace 
{
    public static final int BUFFER_ATTR_IN = 1;
    public static final int BUFFER_ATTR_OUT = 2;

    public final long cmdId;
    public final long procFuncAddr;
    
    public long bytesIn = -1;
    public long bytesOut = -1;
    public long bufferCount = -1;
    public int[] bufferAttrs = null;
    public String bufferAttrsSource = null;
    public String bufferAttrsProbe = null;
    public long inInterfaces = -1;
    public long outInterfaces = -1;
    public long inHandles = -1;
    public long outHandles = -1;
    public long lr = -1;
    
    public long vtOffset = -1;
    public boolean timedOut = false;
    
    public IPCTrace(int cmdId, long procFuncAddr)
    {
        this.cmdId = cmdId;
        this.procFuncAddr = procFuncAddr;
    }
    
    public boolean hasDescription()
    {
        return bytesIn != -1 || bytesOut != -1 || bufferCount != -1 || inInterfaces != -1 ||
                outInterfaces != -1 || inHandles != -1 || outHandles != -1 || lr != -1;
    }

    public boolean hasBufferAttrs()
    {
        return this.bufferAttrs != null && this.bufferAttrs.length > 0;
    }

    public int getInBufferCount()
    {
        return this.getBufferCountByAttr(BUFFER_ATTR_IN);
    }

    public int getOutBufferCount()
    {
        return this.getBufferCountByAttr(BUFFER_ATTR_OUT);
    }

    public String formatBufferAttrs()
    {
        StringJoiner joiner = new StringJoiner(", ", "[", "]");

        if (this.bufferAttrs != null)
        {
            for (int attr : this.bufferAttrs)
                joiner.add(String.format("%d", attr));
        }

        return joiner.toString();
    }

    public String formatBufferDirections()
    {
        StringJoiner joiner = new StringJoiner(", ", "[", "]");

        if (this.bufferAttrs != null)
        {
            for (int attr : this.bufferAttrs)
                joiner.add(formatBufferDirection(attr));
        }

        return joiner.toString();
    }

    private int getBufferCountByAttr(int attrMask)
    {
        int count = 0;

        if (this.bufferAttrs != null)
        {
            for (int attr : this.bufferAttrs)
            {
                if ((attr & attrMask) != 0)
                    count++;
            }
        }

        return count;
    }

    private static String formatBufferDirection(int attr)
    {
        boolean isIn = (attr & BUFFER_ATTR_IN) != 0;
        boolean isOut = (attr & BUFFER_ATTR_OUT) != 0;

        if (isIn && isOut)
            return "in/out";
        if (isIn)
            return "in";
        if (isOut)
            return "out";

        return "unknown";
    }
    
    public boolean isCorrect()
    {
        if (!this.hasDescription())
        {
            return !this.timedOut;
        }

        return vtOffset != -1;
    }
}
