package adubbz.switchloader.nso;

import java.io.IOException;

import adubbz.switchloader.ByteUtil;
import adubbz.switchloader.SectionType;
import adubbz.switchloader.SwitchProgramBuilder;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import net.jpountz.lz4.LZ4Factory;
import net.jpountz.lz4.LZ4FastDecompressor;

public class NSO0ProgramBuilder extends SwitchProgramBuilder
{
    private NSO0Header nso0;
    
    protected NSO0ProgramBuilder(NSO0Header nso0, ByteProvider provider, Program program, MemoryConflictHandler handler)
    {
        super(provider, program, handler);
        this.nso0 = nso0;
    }
    
    public static void loadNSO0(NSO0Header header, ByteProvider provider, Program program, MemoryConflictHandler conflictHandler, TaskMonitor monitor)
    {
        NSO0ProgramBuilder builder = new NSO0ProgramBuilder(header, provider, program, conflictHandler);
        builder.load(monitor);
    }
    
    @Override
    protected void loadDefaultSegments(TaskMonitor monitor) throws IOException, AddressOverflowException, AddressOutOfBoundsException
    {
        long baseAddress = 0x7100000000L;
        AddressSpace aSpace = program.getAddressFactory().getDefaultAddressSpace();
        LZ4Factory factory = LZ4Factory.fastestInstance();
        LZ4FastDecompressor decompressor = factory.fastDecompressor();
        
        NSO0SectionHeader textHeader = this.nso0.getSectionHeader(SectionType.TEXT);
        NSO0SectionHeader rodataHeader = this.nso0.getSectionHeader(SectionType.RODATA);
        NSO0SectionHeader dataHeader = this.nso0.getSectionHeader(SectionType.DATA);
        
        this.text = new byte[textHeader.getDecompressedSize()];
        this.rodata = new byte[rodataHeader.getDecompressedSize()];
        this.data = new byte[dataHeader.getDecompressedSize()];
        
        byte[] compressedText = this.provider.readBytes(textHeader.getFileOffset(), this.nso0.getCompressedSectionSize(SectionType.TEXT));
        decompressor.decompress(compressedText, this.text);
        
        byte[] compressedRodata = this.provider.readBytes(rodataHeader.getFileOffset(), this.nso0.getCompressedSectionSize(SectionType.RODATA));
        decompressor.decompress(compressedRodata, this.rodata);
        
        byte[] compressedData = this.provider.readBytes(dataHeader.getFileOffset(), this.nso0.getCompressedSectionSize(SectionType.DATA));
        decompressor.decompress(compressedData, this.data);
        
        this.textOffset = textHeader.getMemoryOffset();
        this.rodataOffset = rodataHeader.getMemoryOffset();
        this.dataOffset = dataHeader.getMemoryOffset();
        this.bssOffset = this.dataOffset + this.data.length; // TODO: This is wrong. It should be read from the MOD0
        this.bssSize = this.nso0.getBssSize();
    }
}
