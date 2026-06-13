/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.analyzer.ipc;

import java.util.Arrays;
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
    /**
     * vtable addresses of the output-interface implementations discovered during emulation.
     * Indexed 0..outInterfaces-1.  Unset slots hold {@code -1L}.
     * Primitive {@code long[]} is used instead of {@code Long[]} to avoid per-element boxing.
     */
    public long[] outInterfaceTargets = null;
    public long inHandles = -1;
    public long outHandles = -1;
    public long lr = -1;
    public boolean pid = false;
    
    public long vtOffset = -1;
    public boolean timedOut = false;
    /**
     * Set to true when the emulation loop exits cleanly via PC==0 (i.e., a synthetic
     * RET reached our HLE boundary), as opposed to a timeout, a PcodeExecutionException,
     * or a loop-limit break.  Used by {@link #isCorrect()} to distinguish "emulation
     * never saw PrepareForProcess but terminated normally" from "emulation crashed".
     */
    public boolean cleanReturn = false;
    public int validationAttempts = 0;
    public String validationProfile = null;
    public int instructionsExecuted = 0;
    public int coreTraceInstructionCount = -1;
    public int completeTraceInstructionCount = -1;
    public int uninitializedLocalReads = 0;
    public String firstUninitializedLocalRead = null;

    public IPCTrace(long cmdId, long procFuncAddr)
    {
        this.cmdId = cmdId;
        this.procFuncAddr = procFuncAddr;
    }
    
    public boolean hasDescription()
    {
        return bytesIn != -1 || bytesOut != -1 || bufferCount != -1 || inInterfaces != -1 ||
                outInterfaces != -1 || inHandles != -1 || outHandles != -1 || lr != -1 || pid;
    }

    public boolean hasBufferAttrs()
    {
        return this.bufferAttrs != null && this.bufferAttrs.length > 0;
    }

    public void initializeOutInterfaceTargets()
    {
        if (this.outInterfaces > 0 && this.outInterfaces <= Integer.MAX_VALUE)
        {
            this.outInterfaceTargets = new long[(int)this.outInterfaces];
            Arrays.fill(this.outInterfaceTargets, -1L);
        }
    }

    public void setOutInterfaceTarget(int index, long target)
    {
        if (index < 0)
            return;

        if (this.outInterfaceTargets == null)
            this.initializeOutInterfaceTargets();

        if (this.outInterfaceTargets != null && index < this.outInterfaceTargets.length)
            this.outInterfaceTargets[index] = target;
    }

    /**
     * Returns true if the slot at {@code index} has been populated by the emulator.
     * Use instead of a null check now that {@code outInterfaceTargets} is {@code long[]}.
     */
    public boolean hasOutInterfaceTarget(int index)
    {
        return this.outInterfaceTargets != null
            && index >= 0
            && index < this.outInterfaceTargets.length
            && this.outInterfaceTargets[index] != -1L;
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

    public String formatWireLayout()
    {
        StringJoiner joiner = new StringJoiner("; ");

        if (this.bytesIn > 0)
            joiner.add(String.format("in_data[0x%X]", this.bytesIn));

        if (this.bytesOut > 0)
            joiner.add(String.format("out_data[0x%X]", this.bytesOut));

        if (this.hasBufferAttrs())
            joiner.add("buffers=" + this.formatBufferDirections());
        else if (this.bufferCount > 0)
            joiner.add(String.format("buffers[0x%X]=<unknown>", this.bufferCount));

        String layout = joiner.toString();
        return layout.isEmpty() ? "N/A" : layout;
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
            // A trace with no metadata is only acceptable if execution reached a clean
            // return (PC==0 via our HLE boundary).  Crashes (PcodeExecutionException)
            // and timeouts both leave cleanReturn=false and must not be accepted.
            return this.cleanReturn && !this.timedOut;
        }

        return vtOffset != -1;
    }
}