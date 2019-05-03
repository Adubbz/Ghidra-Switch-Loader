/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.knx;

import java.io.IOException;

import adubbz.nx.common.ElfCompatibilityProvider;
import adubbz.nx.common.NXRelocation;
import adubbz.nx.loader.nxo.MOD0Adapter;
import adubbz.nx.loader.nxo.MOD0Header;
import adubbz.nx.loader.nxo.NXOAdapter;
import adubbz.nx.loader.nxo.NXOSection;
import adubbz.nx.loader.nxo.NXOSectionType;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.elf.ElfDynamic;
import ghidra.app.util.bin.format.elf.ElfDynamicTable;
import ghidra.app.util.bin.format.elf.ElfDynamicType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

// We don't have a MOD0, but inherit from the adapter anyway to reduce redundancy
public class KNXAdapter extends MOD0Adapter
{
    protected ByteProvider fileProvider;
    protected BinaryReader fileReader;
    protected KNXMapHeader map;
    
    protected ByteProvider memoryProvider;
    protected NXOSection[] sections;
    
    public KNXAdapter(Program program, ByteProvider fileProvider)
    {
        super(program);
        
        this.fileProvider = fileProvider;
        this.fileReader = new BinaryReader(this.fileProvider, true);
        
        try
        {
            this.read();
        }
        catch (IOException e)
        {
            Msg.error(this, "Failed to read KNX");
            e.printStackTrace();
        }
    }
    
    private void read() throws IOException
    {
        Msg.info(this, "Reading...");
        
        this.fileReader.setPointerIndex(0);
        
        while (this.fileReader.getPointerIndex() < 0x2000)
        {
            long candidate = this.fileReader.readNextInt();
            
            if (candidate == 0xD51C403E)
            {
                break;
            }
        }
        
        if (this.fileReader.getPointerIndex() >= 0x2000)
            throw new RuntimeException("Failed to find map offset");
        
        long mapOffset = this.fileReader.getPointerIndex() - 0x34;
        this.map = new KNXMapHeader(this.fileReader, (int)mapOffset);
        
        int textOffset = this.map.getTextFileOffset();
        int rodataOffset = this.map.getRodataFileOffset();
        int dataOffset = this.map.getDataFileOffset();
        int textSize = this.map.getTextSize();
        int rodataSize = this.map.getRodataSize();
        int dataSize = this.map.getDataSize();

        Msg.info(this, String.format("Text size: 0x%X", textSize));
        
        // The data section is last, so we use its offset + decompressed size
        byte[] full = new byte[dataOffset + dataSize];

        byte[] text = this.fileProvider.readBytes(textOffset, textSize);
        System.arraycopy(text, 0, full, textOffset, textSize);

        byte[] rodata = this.fileProvider.readBytes(rodataOffset, rodataSize);
        System.arraycopy(rodata, 0, full, rodataOffset, rodataSize);

        byte[] data = this.fileProvider.readBytes(dataOffset, dataSize);
        System.arraycopy(data, 0, full, dataOffset, dataSize);
        this.memoryProvider = new ByteArrayProvider(full);
        
        this.sections = new NXOSection[3];
        this.sections[NXOSectionType.TEXT.ordinal()] = new NXOSection(NXOSectionType.TEXT, textOffset, textSize);
        this.sections[NXOSectionType.RODATA.ordinal()] = new NXOSection(NXOSectionType.RODATA, rodataOffset, rodataSize);
        this.sections[NXOSectionType.DATA.ordinal()] = new NXOSection(NXOSectionType.DATA, dataOffset, dataSize);
    }

    @Override
    public ByteProvider getMemoryProvider() 
    {
        return this.memoryProvider;
    }

    @Override
    public NXOSection[] getSections() 
    {
        return this.sections;
    }

    @Override
    public long getDynamicOffset() 
    {
        return this.map.getDynamicOffset();
    }

    @Override
    public long getBssOffset()
    {
        return this.map.getBssFileOffset();
    }
    
    @Override
    public long getBssSize()
    {
        return this.map.getBssSize();
    }
    
    @Override
    public long getGotOffset()
    {
        ElfDynamicTable dt = this.getDynamicTable();
        
        if (dt == null)
            return 0;
        
        return dt.getAddressOffset() + dt.getLength();
    }
    
    @Override
    public long getGotSize()
    {
        ElfDynamicTable dt = this.getDynamicTable();
        
        if (dt == null || !dt.containsDynamicValue(ElfDynamicType.DT_INIT_ARRAY))
            return 0;
        
        try 
        {
            return this.program.getImageBase().getOffset() + dt.getDynamicValue(ElfDynamicType.DT_INIT_ARRAY) - this.getGotOffset();
        } 
        catch (NotFoundException e) 
        {
            return 0;
        }
    }
}
