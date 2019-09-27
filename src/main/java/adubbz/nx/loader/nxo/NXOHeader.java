/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nxo;

import ghidra.program.model.listing.Program;

public class NXOHeader 
{
    private NXOAdapter adapter;
    
    protected final long baseAddress;
    public NXOHeader(Program program, NXOAdapter adapter, long baseAddress)
    {
        this.adapter = adapter;
        this.baseAddress = baseAddress;
    }
    
    public NXOAdapter getAdapter()
    {
        return this.adapter;
    }
    
    public long getBaseAddress()
    {
        return this.baseAddress;
    }
}
