/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.knx;

import adubbz.nx.loader.common.NXProgramBuilder;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class KNXProgramBuilder extends NXProgramBuilder
{
    protected KNXProgramBuilder(ByteProvider provider, Program program) 
    {
        super(program, provider, new KNXAdapter(program, provider));
    }

    public static void loadKNX(ByteProvider provider, Program program, TaskMonitor monitor)
    {
        KNXProgramBuilder builder = new KNXProgramBuilder(provider, program);
        builder.load(monitor);
    }
}
