/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.nxo;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.common.collect.ImmutableList;

import adubbz.nx.common.ElfCompatibilityProvider;
import adubbz.nx.common.NXRelocation;
import adubbz.nx.util.ByteUtil;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.elf.ElfDynamic;
import ghidra.app.util.bin.format.elf.ElfDynamicTable;
import ghidra.app.util.bin.format.elf.ElfDynamicType;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfStringTable;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;
import ghidra.app.util.bin.format.elf.extend.ElfExtensionFactory;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.app.util.bin.format.elf.relocation.AARCH64_ElfRelocationConstants;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

public class NXOHeader 
{
    private NXOAdapter adapter;
    private ElfCompatibilityProvider elfCompatProvider;
    
    protected final long baseAddress;
    public NXOHeader(Program program, NXOAdapter adapter, long baseAddress)
    {
        this.adapter = adapter;
        this.baseAddress = baseAddress;
        long memoryProviderLength = 0x0;
        
        try 
        {
            memoryProviderLength = adapter.getMemoryProvider().length();
        } 
        catch (IOException e) 
        {
            Msg.error(this, "Failed to get memory provider length", e);
        }
        
        this.elfCompatProvider = new ElfCompatibilityProvider(program, new ByteProviderWrapper(adapter.getMemoryProvider(), -baseAddress, memoryProviderLength));
    }
    
    public NXOAdapter getAdapter()
    {
        return this.adapter;
    }
    
    public long getBaseAddress()
    {
        return this.baseAddress;
    }
    
    public long getDynamicSize()
    {
        if (this.getDynamicTable() != null)
            return this.getDynamicTable().getLength();
        
        long dtSize = 0;
        var factoryReader = new FactoryBundledWithBinaryReader(RethrowContinuesFactory.INSTANCE, this.adapter.getMemoryProvider(), true);
        factoryReader.setPointerIndex(this.adapter.getMOD0().getDynamicOffset());
        
        try
        {
            while (true) 
            {
                ElfDynamic dyn = ElfDynamic.createElfDynamic(factoryReader, new ElfCompatibilityProvider.DummyElfHeader());
                dtSize += 16; // 64 bit
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
    
    public ElfDynamicTable getDynamicTable()
    {
        return this.elfCompatProvider.getDynamicTable();
    }
    
    public ElfStringTable getStringTable()
    {
        return this.elfCompatProvider.getStringTable();
    }
    
    public ElfSymbolTable getSymbolTable()
    {
        return this.elfCompatProvider.getSymbolTable();
    }
    
    public String[] getDynamicLibraryNames() 
    {
        return this.elfCompatProvider.getDynamicLibraryNames();
    }
    
    public ImmutableList<NXRelocation> getRelocations()
    {
        return ImmutableList.copyOf(this.elfCompatProvider.getRelocations());
    }
    
    public ImmutableList<NXRelocation> getPltRelocations()
    {
        return ImmutableList.copyOf(this.elfCompatProvider.getPltRelocations());
    }
    

}
