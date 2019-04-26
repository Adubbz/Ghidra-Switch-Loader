/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.common;

import ghidra.app.util.bin.format.elf.ElfSymbol;

public class NXRelocation 
{
    public NXRelocation(long offset, long r_sym, long r_type, ElfSymbol sym, long addend) 
    {
        this.offset = offset;
        this.r_sym = r_sym;
        this.r_type = r_type;
        this.sym = sym;
        this.addend = addend;
    }
    
    public long offset;
    public long r_sym;
    public long r_type;
    public ElfSymbol sym;
    public long addend;
}