/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nxo;

import java.io.IOException;

import adubbz.nx.common.ElfCompatibilityProvider;
import adubbz.nx.common.InvalidMagicException;
import adubbz.nx.common.NXRelocation;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.elf.ElfDynamic;
import ghidra.app.util.bin.format.elf.ElfDynamicTable;
import ghidra.app.util.bin.format.elf.ElfDynamicType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

/*
 * An adapter implementation for binaries with a MOD0 section.
 */
public abstract class MOD0Adapter extends NXOAdapter
{
    protected Program program;
    protected MOD0Header mod0;
    
    public MOD0Adapter(Program program, ByteProvider fileProvider)
    {
        super(fileProvider);
        this.program = program;
    }
    
    @Override
    public long getDynamicOffset()
    {
        MOD0Header mod0 = this.getMOD0();
        
        if (mod0 == null)
            return 0;
        
        return mod0.getDynamicOffset();
    }
    
    @Override
    public long getDynamicSize()
    {
        assert this.program != null;
        
        if (this.getElfProvider(this.program).getDynamicTable() != null)
            return this.getElfProvider(this.program).getDynamicTable().getLength();
        
        long dtSize = 0;
        var factoryReader = new FactoryBundledWithBinaryReader(RethrowContinuesFactory.INSTANCE, this.getMemoryProvider(), true);
        factoryReader.setPointerIndex(this.getDynamicOffset());
        
        try
        {
            while (true) 
            {
                ElfDynamic dyn = ElfDynamic.createElfDynamic(factoryReader, new ElfCompatibilityProvider.DummyElfHeader(this.isAarch32()));
                dtSize += dyn.sizeof();
                if (dyn.getTag() == ElfDynamicType.DT_NULL.value) 
                {
                    break;
                }
            }
        }
        catch (IOException e)
        {
            Msg.error(this, "Failed to get dynamic size", e);
        }
        
        return dtSize;
    }
    
    @Override
    public long getBssOffset()
    {
        MOD0Header mod0 = this.getMOD0();
        
        if (mod0 == null)
            return 0;
        
        return mod0.getBssStartOffset();
    }
    
    @Override
    public long getBssSize()
    {
        MOD0Header mod0 = this.getMOD0();
        
        if (mod0 == null)
            return 0;
        
        return mod0.getBssSize();
    }
    
    @Override
    public long getGotOffset()
    {
        MOD0Header mod0 = this.getMOD0();
        
        if (mod0 == null)
            return 0;
        
        if (mod0.hasLibnxExtension())
        {
            return mod0.getLibnxGotStart() + this.program.getImageBase().getOffset();
        }
        
        MemoryBlock gotPlt = this.program.getMemory().getBlock(".got.plt");
        
        if (gotPlt == null)
            return 0;
        
        return gotPlt.getEnd().getOffset() + 1;
    }
    
    private long gotSize = 0;
    
    @Override
    public long getGotSize()
    {
        assert this.program != null;
        
        if (this.gotSize > 0)
            return this.gotSize;
        
        MOD0Header mod0 = this.getMOD0();
        
        if (mod0 == null)
            return 0;
        
        if (mod0.hasLibnxExtension())
        {
            this.gotSize = mod0.getLibnxGotEnd() - mod0.getLibnxGotStart();
            return this.gotSize;
        }
        
        ElfDynamicTable dt = this.getDynamicTable(this.program);
        long baseAddr = this.program.getImageBase().getOffset();
        long gotEnd = this.getGotOffset() + this.getOffsetSize();
        boolean good = false;
        
        if (dt == null || gotEnd == this.getOffsetSize())
            return 0;
        
        try 
        {
            while (!dt.containsDynamicValue(ElfDynamicType.DT_INIT_ARRAY) || gotEnd < (baseAddr + dt.getDynamicValue(ElfDynamicType.DT_INIT_ARRAY)))
            {
                boolean foundOffset = false;
                
                for (NXRelocation reloc : this.getRelocations(this.program))
                {
                    if ((baseAddr + reloc.offset) == gotEnd)
                    {
                        foundOffset = true;
                        break;
                    }
                }
                
                if (!foundOffset)
                    break;
                
                good = true;
                gotEnd += this.getOffsetSize();
            }
        } 
        catch (NotFoundException e) 
        {
            Msg.error(this, "Failed to get got size", e);
            return 0;
        }
        
        if (good)
        {
            this.gotSize = gotEnd - this.getGotOffset();
            return this.gotSize;
        }
        
        return 0;
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
            Msg.error(this, "Invalid MOD0 magic.", e);
        }
        catch (IOException e) 
        {
            Msg.error(this, "Failed to read MOD0.", e);
        }
        
        return null;
    }
}
