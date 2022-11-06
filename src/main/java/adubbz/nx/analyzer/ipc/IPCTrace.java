/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.analyzer.ipc;

import ghidra.util.Msg;

public class IPCTrace 
{
    public final long cmdId;
    public final long procFuncAddr;
    
    public long bytesIn = -1;
    public long bytesOut = -1;
    public long bufferCount = -1;
    public long inInterfaces = -1;
    public long outInterfaces = -1;
    public long inHandles = -1;
    public long outHandles = -1;
    public long lr = -1;
    
    public long vtOffset = -1;
    
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
    
    public boolean isCorrect()
    {
        if (!this.hasDescription())
        {
            return true;
        }

        return vtOffset != -1;
    }
    
    public void printTrace()
    {
        String out = "\n--------------------\n"+
                     "0x%X, Cmd 0x%X      \n"  +
                     "--------------------\n"  +
                     "Lr:             0x%X\n"  +
                     "Vt:             0x%X\n"  +
                     "Bytes In:       0x%X\n"  +
                     "Bytes Out:      0x%X\n"  +
                     "Buffer Count:   0x%X\n"  +
                     "In Interfaces:  0x%X\n"  +
                     "Out Interfaces: 0x%X\n"  +
                     "In Handles:     0x%X\n"  +
                     "Out Handles:    0x%X\n"  +
                     "--------------------\n";
        
        out = String.format(out, procFuncAddr, cmdId, lr, vtOffset, bytesIn, bytesOut, bufferCount, inInterfaces,
                            outInterfaces, inHandles, outHandles);
        Msg.info(this, out);
    }
}
