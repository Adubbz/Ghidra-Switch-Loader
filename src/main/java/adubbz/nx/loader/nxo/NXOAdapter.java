/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nxo;

import java.io.IOException;

import com.google.common.collect.ImmutableList;

import adubbz.nx.common.ElfCompatibilityProvider;
import adubbz.nx.common.NXRelocation;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.format.elf.ElfDynamicTable;
import ghidra.app.util.bin.format.elf.ElfStringTable;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Abstracts away the differences between different Switch file formats.
 */
public abstract class NXOAdapter 
{
    protected Program program;
    protected BinaryReader memoryReader;
    protected ElfCompatibilityProvider elfProvider;
    
    public NXOAdapter(Program program)
    {
        this.program = program;
    }
    
    public abstract ByteProvider getMemoryProvider();
    
    public BinaryReader getMemoryReader()
    {
        if (this.memoryReader != null)
            return this.memoryReader;
        
        this.memoryReader = new BinaryReader(this.getMemoryProvider(), true);
        return this.memoryReader;
    }
    
    public abstract long getDynamicOffset();
    public abstract long getDynamicSize();
    
    public abstract long getBssOffset();
    public abstract long getBssSize();
    
    public abstract long getGotOffset();
    public abstract long getGotSize();
    
    public ElfDynamicTable getDynamicTable()
    {
        return this.getElfProvider().getDynamicTable();
    }
    
    public ElfStringTable getStringTable()
    {
        return this.getElfProvider().getStringTable();
    }
    
    public ElfSymbolTable getSymbolTable()
    {
        return this.getElfProvider().getSymbolTable();
    }
    
    public String[] getDynamicLibraryNames() 
    {
        return this.getElfProvider().getDynamicLibraryNames();
    }
    
    public ImmutableList<NXRelocation> getRelocations()
    {
        return ImmutableList.copyOf(this.getElfProvider().getRelocations());
    }
    
    public ImmutableList<NXRelocation> getPltRelocations()
    {
        return ImmutableList.copyOf(this.getElfProvider().getPltRelocations());
    }
    
    public ElfCompatibilityProvider getElfProvider()
    {
        if (this.elfProvider != null)
            return this.elfProvider;
        
        long baseAddress = this.program.getImageBase().getOffset();
        long memoryProviderLength = 0x0;
        
        try 
        {
            memoryProviderLength = this.getMemoryProvider().length();
        } 
        catch (IOException e) 
        {
            Msg.error(this, "Failed to get memory provider length", e);
        }
        
        this.elfProvider = new ElfCompatibilityProvider(program, new ByteProviderWrapper(this.getMemoryProvider(), -baseAddress, memoryProviderLength));
        
        return this.elfProvider;
    }
    
    public NXOSection getSection(NXOSectionType type)
    {
        return this.getSections()[type.ordinal()];
    }
    
    public abstract NXOSection[] getSections();
}
