/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nxo;

import java.io.IOException;

import adubbz.nx.common.InvalidMagicException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.util.Msg;

/**
 * Abstracts away the differences between different Switch file formats.
 */
public abstract class NXOAdapter 
{
    protected BinaryReader memoryReader;
    protected MOD0Header mod0;
    
    public BinaryReader getMemoryReader()
    {
        if (this.memoryReader != null)
            return this.memoryReader;
        
        this.memoryReader = new BinaryReader(this.getMemoryProvider(), true);
        return this.memoryReader;
    }
    
    public MOD0Header getMOD0()
    {
        if (this.mod0 != null)
            return this.mod0;
        
        try 
        {
            int mod0Offset = this.getMemoryReader().readInt(this.getSection(NXOSectionType.TEXT).getOffset() + 4);
        
            if (Integer.toUnsignedLong(mod0Offset) >= this.getMemoryProvider().length())
                throw new IllegalArgumentException("Mod0 offset is outside the binary!");
            
            this.mod0 = new MOD0Header(this.getMemoryReader(), mod0Offset, mod0Offset);
            return this.mod0;
        }
        catch (InvalidMagicException e)
        {
            Msg.error(this, "Invalid MOD0 magic.");
            e.printStackTrace();
        }
        catch (IOException e) 
        {
            Msg.error(this, "Failed to read MOD0.");
            e.printStackTrace();
        }
        
        return null;
    }
    
    public NXOSection getSection(NXOSectionType type)
    {
        return this.getSections()[type.ordinal()];
    }
    
    public abstract ByteProvider getMemoryProvider();
    public abstract NXOSection[] getSections();
}
