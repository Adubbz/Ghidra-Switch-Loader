/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package adubbz.nx.loader.kip1;

import adubbz.nx.loader.common.NXProgramBuilder;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class KIP1ProgramBuilder extends NXProgramBuilder
{
    protected KIP1ProgramBuilder(ByteProvider provider, Program program, MemoryConflictHandler handler)
    {
        super(program, provider, new KIP1Adapter(program, provider), handler);
    }
    
    public static void loadKIP1(ByteProvider provider, Program program, MemoryConflictHandler conflictHandler, TaskMonitor monitor)
    {
        KIP1ProgramBuilder builder = new KIP1ProgramBuilder(provider, program, conflictHandler);
        builder.load(monitor);
    }
    
    @Override
    protected void load(TaskMonitor monitor)
    {
        super.load(monitor);
        
        // KIP1s always start with a branch instruction at the start of their text
        this.createEntryFunction("entry", this.nxo.getBaseAddress(), monitor);
    }
}
