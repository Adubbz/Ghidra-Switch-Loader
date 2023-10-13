/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.loader.common;

import adubbz.nx.common.NXRelocation;
import adubbz.nx.loader.nxo.NXO;
import adubbz.nx.loader.nxo.NXOAdapter;
import adubbz.nx.loader.nxo.NXOSection;
import adubbz.nx.loader.nxo.NXOSectionType;
import adubbz.nx.util.UIUtil;
import com.google.common.collect.ImmutableList;
import com.google.common.primitives.Longs;
import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfDynamicType;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.ElfStringTable;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.relocation.AARCH64_ElfRelocationConstants;
import ghidra.app.util.bin.format.elf.relocation.ARM_ElfRelocationConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static adubbz.nx.common.ElfCompatibilityProvider.R_FAKE_RELR;

public class NXProgramBuilder 
{
    protected ByteProvider fileByteProvider;
    protected Program program;
    protected NXO nxo;
    
    protected AddressSpace aSpace;
    protected MemoryBlockHelper memBlockHelper;
    
    protected List<PltEntry> pltEntries = new ArrayList<>();
    
    protected int undefSymbolCount;
    
    public NXProgramBuilder(Program program, ByteProvider provider, NXOAdapter adapter)
    {
        this.program = program;
        this.fileByteProvider = provider;
        this.nxo = new NXO(program, adapter, program.getImageBase().getOffset());
    }
    
    public void load(TaskMonitor monitor)
    {
        NXOAdapter adapter = this.nxo.getAdapter();
        ByteProvider memoryProvider = adapter.getMemoryProvider();
        this.aSpace = program.getAddressFactory().getDefaultAddressSpace();
        
        try 
        {
            this.memBlockHelper = new MemoryBlockHelper(monitor, this.program, memoryProvider);
            
            NXOSection text = adapter.getSection(NXOSectionType.TEXT);
            NXOSection rodata = adapter.getSection(NXOSectionType.RODATA);
            NXOSection data = adapter.getSection(NXOSectionType.DATA);
            
            if (adapter.getDynamicSize() == 0)
            {
                // We can't create .dynamic, so work with what we've got.
                return;
            }
            
            this.memBlockHelper.addSection(".dynamic", adapter.getDynamicOffset(), adapter.getDynamicOffset(), adapter.getDynamicSize(), true, true, false);

            // Create dynamic sections
            this.tryCreateDynBlock(".dynstr", ElfDynamicType.DT_STRTAB, ElfDynamicType.DT_STRSZ);
            this.tryCreateDynBlock(".init_array", ElfDynamicType.DT_INIT_ARRAY, ElfDynamicType.DT_INIT_ARRAYSZ);
            this.tryCreateDynBlock(".fini_array", ElfDynamicType.DT_FINI_ARRAY, ElfDynamicType.DT_FINI_ARRAYSZ);
            this.tryCreateDynBlock(".rela.dyn", ElfDynamicType.DT_RELA, ElfDynamicType.DT_RELASZ);
            this.tryCreateDynBlock(".rel.dyn", ElfDynamicType.DT_REL, ElfDynamicType.DT_RELSZ);
            this.tryCreateDynBlock(".relr.dyn", ElfDynamicType.DT_RELR, ElfDynamicType.DT_RELRSZ);
            
            if (adapter.isAarch32())
            {
                this.tryCreateDynBlock(".rel.plt", ElfDynamicType.DT_JMPREL, ElfDynamicType.DT_PLTRELSZ);
            }
            else
            {
                this.tryCreateDynBlock(".rela.plt", ElfDynamicType.DT_JMPREL, ElfDynamicType.DT_PLTRELSZ);
            }

            this.tryCreateDynBlockWithRange(".hash", ElfDynamicType.DT_HASH, ElfDynamicType.DT_GNU_HASH);
            this.tryCreateDynBlockWithRange(".gnu.hash", ElfDynamicType.DT_GNU_HASH, ElfDynamicType.DT_SYMTAB);
            
            if (adapter.getSymbolTable(this.program) != null)
            {
                Msg.info(this, String.format("String table offset %X, base addr %X", adapter.getSymbolTable(this.program).getFileOffset(), this.nxo.getBaseAddress()));
                this.memBlockHelper.addSection(".dynsym", adapter.getSymbolTable(this.program).getFileOffset() - this.nxo.getBaseAddress(), adapter.getSymbolTable(this.program).getFileOffset() - this.nxo.getBaseAddress(), adapter.getSymbolTable(this.program).getLength(), true, false, false);
            }
            
            this.setupRelocations();
            this.createGlobalOffsetTable();
            
            this.memBlockHelper.addFillerSection(".text", text.getOffset(), text.getSize(), true, false, true);
            this.memBlockHelper.addFillerSection(".rodata", rodata.getOffset(), rodata.getSize(), true, false, false);
            this.memBlockHelper.addFillerSection(".data", data.getOffset(), data.getSize(), true, true, false);
            
            this.setupStringTable();
            this.setupSymbolTable();
            
            // Create BSS. This needs to be done before the EXTERNAL block is created in setupImports
            Address bssStartAddr = aSpace.getAddress(this.nxo.getBaseAddress() + adapter.getBssOffset());
            Msg.info(this, String.format("Created bss from 0x%X to 0x%X", bssStartAddr.getOffset(), bssStartAddr.getOffset() + adapter.getBssSize()));
            MemoryBlockUtils.createUninitializedBlock(this.program, false, ".bss", bssStartAddr, adapter.getBssSize(), "", null, true, true, false, new MessageLog());
            
            this.setupImports(monitor);
            this.performRelocations();
            
            // Set all data in the GOT to the pointer data type
            // NOTE: Currently the got range may be null in e.g. old libnx nros
            // We may want to manually figure this out ourselves in future.
            if (adapter.getGotSize() > 0)
            {
                for (Address addr = this.aSpace.getAddress(adapter.getGotOffset()); addr.compareTo(this.aSpace.getAddress(adapter.getGotOffset() + adapter.getGotSize())) < 0; addr = addr.add(adapter.getOffsetSize()))
                {
                    this.createPointer(addr);
                }
            }
        }
        catch (IOException | NotFoundException | AddressOverflowException | AddressOutOfBoundsException | CodeUnitInsertionException | MemoryAccessException | InvalidInputException e)
        {
            e.printStackTrace();
        }
        
        // Ensure memory blocks are ordered from first to last.
        // Normally they are ordered by the order they are added.
        UIUtil.sortProgramTree(this.program);
    }
    
    public NXO getNxo()
    {
        return this.nxo;
    }
    
    protected void setupStringTable() throws AddressOverflowException, CodeUnitInsertionException
    {
       NXOAdapter adapter = this.nxo.getAdapter();
       ElfStringTable stringTable = adapter.getStringTable(this.program);
       
       if (stringTable == null)
           return;
       
       long stringTableAddrOffset = stringTable.getAddressOffset();
        
        Address address = this.aSpace.getAddress(stringTableAddrOffset);
        Address end = address.addNoWrap(stringTable.getLength() - 1);
        
        while (address.compareTo(end) < 0) 
        {
            int length = this.createString(address);
            address = address.addNoWrap(length);
        }
    }
    
    protected void setupSymbolTable()
    {
        NXOAdapter adapter = this.nxo.getAdapter();
        
        if (adapter.getSymbolTable(this.program) != null)
        {
            for (ElfSymbol elfSymbol : adapter.getSymbolTable(this.program).getSymbols()) 
            {
                String symName = elfSymbol.getNameAsString();
    
                if (elfSymbol.getSectionHeaderIndex() == ElfSectionHeaderConstants.SHN_UNDEF && symName != null && !symName.isEmpty())
                {
                    // NOTE: We handle adding these symbols later
                    this.undefSymbolCount++;
                }
                else
                {
                    Address address = this.aSpace.getAddress(this.nxo.getBaseAddress() + elfSymbol.getValue());
                    this.evaluateElfSymbol(elfSymbol, address, false);
                }
            }
        }
    }
    
    protected void setupRelocations() throws AddressOutOfBoundsException, NotFoundException, IOException {
        NXOAdapter adapter = this.nxo.getAdapter();
        ByteProvider memoryProvider = adapter.getMemoryProvider();
        BinaryReader memoryReader = adapter.getMemoryReader();
        ImmutableList<NXRelocation> pltRelocs = adapter.getPltRelocations(this.program);
        
        if (pltRelocs.isEmpty())
        {
            Msg.info(this, "No plt relocations found.");
            return;
        }
            
        long pltGotStart = pltRelocs.get(0).offset;
        long pltGotEnd = pltRelocs.get(pltRelocs.size() - 1).offset + adapter.getOffsetSize();
        
        if (adapter.getDynamicTable(this.program).containsDynamicValue(ElfDynamicType.DT_PLTGOT))
        {
            long pltGotOff = adapter.getDynamicTable(this.program).getDynamicValue(ElfDynamicType.DT_PLTGOT);
            this.memBlockHelper.addSection(".got.plt", pltGotOff, pltGotOff, pltGotEnd - pltGotOff, true, false, false);
        }
        
        // Only add .plt on aarch64
        if (adapter.isAarch32())
        {
            return;
        }
        
        int last = 12;
        
        while (true)
        {
            int pos = -1;
            
            for (int i = last; i < adapter.getSection(NXOSectionType.TEXT).getSize(); i++)
            {
                if (memoryReader.readInt(i) == 0xD61F0220)
                {
                    pos = i;
                    break;
                }
            }
            
            if (pos == -1) break;
            last = pos + 1;
            if ((pos % 4) != 0) continue;
            
            int off = pos - 12;
            long a = Integer.toUnsignedLong(memoryReader.readInt(off));
            long b = Integer.toUnsignedLong(memoryReader.readInt(off + 4));
            long c = Integer.toUnsignedLong(memoryReader.readInt(off + 8));
            long d = Integer.toUnsignedLong(memoryReader.readInt(off + 12));

            if (d == 0xD61F0220L && (a & 0x9f00001fL) == 0x90000010L && (b & 0xffe003ffL) == 0xf9400211L)
            {
                long base = off & ~0xFFFL;
                long immhi = (a >> 5) & 0x7ffffL;
                long immlo = (a >> 29) & 3;
                long paddr = base + ((immlo << 12) | (immhi << 14));
                long poff = ((b >> 10) & 0xfffL) << 3;
                long target = paddr + poff;
                if (pltGotStart <= target && target < pltGotEnd)
                    this.pltEntries.add(new PltEntry(off, target));
            }
        }

        if (!this.pltEntries.isEmpty()) {
            long pltStart = this.pltEntries.get(0).off;
            long pltEnd = this.pltEntries.get(this.pltEntries.size() - 1).off + 0x10;
            this.memBlockHelper.addSection(".plt", pltStart, pltStart, pltEnd - pltStart, true, false, false);
        }
        else {
            // TODO: Find a way to locate the plt in CFI-enabled binaries.
            Msg.error(this, "No PLT entries found, does this binary have CFI enabled? This loader currently can't locate the plt in them.");
        }
    }
    
    protected void createGlobalOffsetTable() throws AddressOutOfBoundsException
    {
        NXOAdapter adapter = this.nxo.getAdapter();
        ByteProvider memoryProvider = adapter.getMemoryProvider();
        
        // .got.plt needs to have been created first
        long gotStartOff = adapter.getGotOffset() - this.nxo.getBaseAddress();
        long gotSize = adapter.getGotSize();
        
        if (gotSize > 0)
        {
            Msg.info(this, String.format("Created got from 0x%X to 0x%X", gotStartOff, gotStartOff + gotSize));
            this.memBlockHelper.addSection(".got", gotStartOff, gotStartOff, gotSize, true, false, false);
        }
    }
    
    protected void performRelocations() throws MemoryAccessException, InvalidInputException, AddressOutOfBoundsException
    {
        NXOAdapter adapter = this.nxo.getAdapter();
        Map<Long, String> gotNameLookup = new HashMap<>(); 
        
        // Relocations again
        for (NXRelocation reloc : adapter.getRelocations(this.program)) 
        {
            Address target = this.aSpace.getAddress(reloc.offset + this.nxo.getBaseAddress());
            long originalValue = adapter.isAarch32() ? this.program.getMemory().getInt(target) : this.program.getMemory().getLong(target);
            
            if (reloc.r_type == ARM_ElfRelocationConstants.R_ARM_GLOB_DAT ||
                    reloc.r_type == ARM_ElfRelocationConstants.R_ARM_JUMP_SLOT ||
                    reloc.r_type == ARM_ElfRelocationConstants.R_ARM_ABS32) 
                {
                    if (reloc.sym == null) 
                    {
                        Msg.error(this, String.format("Error: Relocation at %x failed", target.getOffset()));
                    } 
                    else 
                    {
                        program.getMemory().setInt(target, (int)(reloc.sym.getValue() + this.nxo.getBaseAddress()));
                    }
                } 
            else if (reloc.r_type == ARM_ElfRelocationConstants.R_ARM_RELATIVE)
            {
                program.getMemory().setInt(target, (int)(program.getMemory().getInt(target) + this.nxo.getBaseAddress()));
            }
            else if (reloc.r_type == AARCH64_ElfRelocationConstants.R_AARCH64_GLOB_DAT ||
                reloc.r_type == AARCH64_ElfRelocationConstants.R_AARCH64_JUMP_SLOT ||
                reloc.r_type == AARCH64_ElfRelocationConstants.R_AARCH64_ABS64) 
            {
                if (reloc.sym == null) 
                {
                    // Ignore these sorts of errors, the IDA loader fails on some relocations too.
                    // It doesn't appear to be a Ghidra specific issue.
                    //Msg.error(this, String.format("Error: Relocation at %x failed", target.getOffset()));
                } 
                else 
                {
                    program.getMemory().setLong(target, reloc.sym.getValue() + this.nxo.getBaseAddress() + reloc.addend);
                    
                    if (reloc.addend == 0)
                        gotNameLookup.put(reloc.offset, reloc.sym.getNameAsString());
                }
            } 
            else if (reloc.r_type == AARCH64_ElfRelocationConstants.R_AARCH64_RELATIVE) 
            {
                program.getMemory().setLong(target, this.nxo.getBaseAddress() + reloc.addend);
            }
            else if (reloc.r_type == R_FAKE_RELR) {
                if (this.nxo.getAdapter().isAarch32()) {
                    // TODO: Add RELRO support for 32-bit
                    Msg.error(this, "TODO: RELRO support for 32-bit");
                    continue;
                }

                program.getMemory().setLong(target, this.nxo.getBaseAddress() + originalValue);
            }
            else 
            {
                Msg.info(this, String.format("TODO: r_type 0x%x", reloc.r_type));
            }
            
            long newValue = adapter.isAarch32() ? this.program.getMemory().getInt(target) : this.program.getMemory().getLong(target);
            
            // Store relocations for Ghidra's relocation table view
            if (newValue != originalValue)
            {
                String symbolName = null;
                
                if (reloc.sym != null) 
                {
                    symbolName = reloc.sym.getNameAsString();
                }

                // Status APPLIED: "Relocation was applied successfully and resulted in the modification of memory bytes."
                program.getRelocationTable().add(target, Relocation.Status.APPLIED,(int)reloc.r_type, new long[] { reloc.r_sym }, Longs.toByteArray(originalValue), symbolName);
            }
        }
        
        for (PltEntry entry : this.pltEntries)
        {
            if (gotNameLookup.containsKey(entry.target))
            {
                long addr = this.nxo.getBaseAddress() + entry.off;
                String name = gotNameLookup.get(entry.target);
                // TODO: Mark as func
                if (name != null && !name.isEmpty())
                {
                    this.createSymbol(this.aSpace.getAddress(addr), name, false, false, null);
                }
            }
        }
    }
    
    protected void setupImports(TaskMonitor monitor)
    {
        NXOAdapter adapter = this.nxo.getAdapter();
        this.processImports(monitor);
        
        if (this.undefSymbolCount == 0)
            return;
        
        // Create the fake EXTERNAL block after everything else
        long lastAddrOff = this.nxo.getBaseAddress(); 
        
        for (MemoryBlock block : this.program.getMemory().getBlocks())
        {
            if (block.getEnd().getOffset() > lastAddrOff)
                lastAddrOff = block.getEnd().getOffset();
        }
        
        int undefEntrySize = adapter.getOffsetSize(); // We create fake 1 byte functions for imports
        long externalBlockAddrOffset = ((lastAddrOff + 0xFFF) & ~0xFFF) + undefEntrySize; // plus 1 so we don't end up on the "end" symbol
        
        // Create the block where imports will be located
        this.createExternalBlock(this.aSpace.getAddress(externalBlockAddrOffset), (long) this.undefSymbolCount * undefEntrySize);

        // Handle imported symbols
        if (adapter.getSymbolTable(this.program) != null)
        {
            for (ElfSymbol elfSymbol : adapter.getSymbolTable(this.program).getSymbols())
            {
                String symName = elfSymbol.getNameAsString();

                if (elfSymbol.getSectionHeaderIndex() == ElfSectionHeaderConstants.SHN_UNDEF && symName != null && !symName.isEmpty())
                {
                    Address address = this.aSpace.getAddress(externalBlockAddrOffset);
                    try {
                        Field elfSymbolValue = elfSymbol.getClass().getDeclaredField("st_value");
                        elfSymbolValue.setAccessible(true);
                        // Fix the value to be non-zero, instead pointing to our fake EXTERNAL block
                        elfSymbolValue.set(elfSymbol, externalBlockAddrOffset);
                    } catch (NoSuchFieldException | IllegalAccessException e) {
                        Msg.error(this, "Couldn't find or set st_value field in ElfSymbol.", e);
                    }
                    this.evaluateElfSymbol(elfSymbol, address, true);
                    externalBlockAddrOffset += undefEntrySize;
                }
            }
        }
    }
    
    private void createExternalBlock(Address addr, long size) 
    {
        try 
        {
            MemoryBlock block = this.program.getMemory().createUninitializedBlock("EXTERNAL", addr, size, false);

            // assume any value in external is writable.
            block.setWrite(true);
            block.setSourceName("Switch Loader");
            block.setComment("NOTE: This block is artificial and is used to make relocations work correctly");
        }
        catch (Exception e) 
        {
            Msg.error(this, "Error creating external memory block: " + " - " + e.getMessage());
        }
    }
    
    private void processImports(TaskMonitor monitor) 
    {
        NXOAdapter adapter = this.nxo.getAdapter();
        
        if (monitor.isCancelled())
            return;

        monitor.setMessage("Processing imports...");

        ExternalManager extManager = program.getExternalManager();
        String[] neededLibs = adapter.getDynamicLibraryNames(this.program);
        
        for (String neededLib : neededLibs) 
        {
            try {
                extManager.setExternalPath(neededLib, null, false);
            }
            catch (InvalidInputException e) {
                Msg.error(this, "Bad library name: " + neededLib);
            }
        }
    }
    
    public Address createEntryFunction(String name, long entryAddr, TaskMonitor monitor) 
    {
        Address entryAddress = this.aSpace.getAddress(entryAddr);

        // TODO: Entry may refer to a pointer - make sure we have execute permission
        MemoryBlock block = this.program.getMemory().getBlock(entryAddress);
        
        if (block == null || !block.isExecute()) 
        {
            return entryAddress;
        }

        Function function = program.getFunctionManager().getFunctionAt(entryAddress);
        
        if (function != null) 
        {
            program.getSymbolTable().addExternalEntryPoint(entryAddress);
            return entryAddress; // symbol-based function already created
        }

        try 
        {
            this.createOneByteFunction(name, entryAddress, true);
        }
        catch (Exception e) 
        {
            Msg.error(this, "Could not create symbol at entry point: " + e);
        }

        return entryAddress;
    }
    
    protected int createString(Address address) throws CodeUnitInsertionException
    {
        Data d = this.program.getListing().getDataAt(address);
        
        if (d == null || !TerminatedStringDataType.dataType.isEquivalent(d.getDataType())) 
        {
            d = this.program.getListing().createData(address, TerminatedStringDataType.dataType, -1);
        }
        
        return d.getLength();
    }
    
    protected int createPointer(Address address) throws CodeUnitInsertionException
    {
        NXOAdapter adapter = this.nxo.getAdapter();
        Data d = this.program.getListing().getDataAt(address);
        
        if (d == null || !PointerDataType.dataType.isEquivalent(d.getDataType())) 
        {
            d = this.program.getListing().createData(address, PointerDataType.dataType, adapter.getOffsetSize());
        }
        
        return d.getLength();
    }
    
    private void evaluateElfSymbol(ElfSymbol elfSymbol, Address address, boolean isFakeExternal)
    {
        try
        {
            if (elfSymbol.isSection()) {
                // Do not add section symbols to program symbol table
                return;
            }
    
            String name = elfSymbol.getNameAsString();
            if (name == null || name.isEmpty()) {
                return;
            }
    
            boolean isPrimary = (elfSymbol.getType() == ElfSymbol.STT_FUNC) ||
                (elfSymbol.getType() == ElfSymbol.STT_OBJECT) || (elfSymbol.getSize() != 0);
            // don't displace existing primary unless symbol is a function or object symbol
            if (name.contains("@")) {
                isPrimary = false; // do not make version symbol primary
            }
            else if (!isPrimary && (elfSymbol.isGlobal() || elfSymbol.isWeak())) {
                Symbol existingSym = program.getSymbolTable().getPrimarySymbol(address);
                isPrimary = (existingSym == null);
            }
    
            this.createSymbol(address, name, isPrimary, elfSymbol.isAbsolute(), null);
    
            // NOTE: treat weak symbols as global so that other programs may link to them.
            // In the future, we may want additional symbol flags to denote the distinction
            if ((elfSymbol.isGlobal() || elfSymbol.isWeak()) && !isFakeExternal) 
            {
                program.getSymbolTable().addExternalEntryPoint(address);
            }
            
            if (elfSymbol.getType() == ElfSymbol.STT_FUNC) 
            {
                Function existingFunction = program.getFunctionManager().getFunctionAt(address);
                if (existingFunction == null) {
                    Function f = createOneByteFunction(null, address, false);
                    if (f != null) {
                        if (isFakeExternal && !f.isThunk()) {
                            ExternalLocation extLoc = program.getExternalManager().addExtFunction(Library.UNKNOWN, name, null, SourceType.IMPORTED);
                            f.setThunkedFunction(extLoc.getFunction());
                            // revert thunk function symbol to default source
                            Symbol s = f.getSymbol();
                            if (s.getSource() != SourceType.DEFAULT) {
                                program.getSymbolTable().removeSymbolSpecial(f.getSymbol());
                            }
                        }
                    }
                }
            }
        }
        catch (DuplicateNameException | InvalidInputException e)
        {
            e.printStackTrace();
        }
    }
    
    public Function createOneByteFunction(String name, Address address, boolean isEntry) 
    {
        Function function = null;
        try 
        {
            FunctionManager functionMgr = program.getFunctionManager();
            function = functionMgr.getFunctionAt(address);
            if (function == null) {
                function = functionMgr.createFunction(null, address, new AddressSet(address), SourceType.IMPORTED);
            }
        }
        catch (Exception e) 
        {
            Msg.error(this, "Error while creating function at " + address + ": " + e.getMessage());
        }

        try 
        {
            if (name != null) 
            {
                createSymbol(address, name, true, false, null);
            }
            if (isEntry) {
                program.getSymbolTable().addExternalEntryPoint(address);
            }
        }
        catch (Exception e) {
            Msg.error(this, "Error while creating symbol " + name + " at " + address + ": " + e.getMessage());
        }
        return function;
    }
    
    public Symbol createSymbol(Address addr, String name, boolean isPrimary, boolean pinAbsolute, Namespace namespace) throws InvalidInputException 
    {
        // TODO: At this point, we should be marking as data or code
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol sym = symbolTable.createLabel(addr, name, namespace, SourceType.IMPORTED);
        if (isPrimary) {
            checkPrimary(sym);
        }
        if (pinAbsolute && !sym.isPinned()) {
            sym.setPinned(true);
        }
        return sym;
    }
    
    private Symbol checkPrimary(Symbol sym) 
    {
        if (sym == null || sym.isPrimary()) 
        {
            return sym;
        }

        String name = sym.getName();
        Address addr = sym.getAddress();

        if (name.indexOf("@") > 0) { // <sym>@<version> or <sym>@@<version>
            return sym; // do not make versioned symbols primary
        }

        // if starts with a $, probably a markup symbol, like $t,$a,$d
        if (name.startsWith("$")) {
            return sym;
        }

        // if sym starts with a non-letter give preference to an existing symbol which does
        if (!Character.isAlphabetic(name.codePointAt(0))) {
            Symbol primarySymbol = program.getSymbolTable().getPrimarySymbol(addr);
            if (primarySymbol != null && primarySymbol.getSource() != SourceType.DEFAULT &&
                Character.isAlphabetic(primarySymbol.getName().codePointAt(0))) {
                return sym;
            }
        }

        SetLabelPrimaryCmd cmd = new SetLabelPrimaryCmd(addr, name, sym.getParentNamespace());
        if (cmd.applyTo(program)) {
            return program.getSymbolTable().getSymbol(name, addr, sym.getParentNamespace());
        }

        Msg.error(this, cmd.getStatusMsg());

        return sym;
    }
    
    public boolean hasImportedSymbol(Address addr)
    {
        for (Symbol sym : program.getSymbolTable().getSymbols(addr))
        {
            if (sym.getSource() == SourceType.IMPORTED)
                return true;
        }
        
        return false;
    }
    
    protected void tryCreateDynBlock(String name, ElfDynamicType offsetType, ElfDynamicType sizeType)
    {
        NXOAdapter adapter = this.nxo.getAdapter();
        
        try
        {
            if (adapter.getDynamicTable(this.program).containsDynamicValue(offsetType) && adapter.getDynamicTable(this.program).containsDynamicValue(sizeType))
            {
                long offset = adapter.getDynamicTable(this.program).getDynamicValue(offsetType);
                long size = adapter.getDynamicTable(this.program).getDynamicValue(sizeType);
                
                if (size > 0)
                {
                    Msg.info(this, String.format("Created dyn block %s at 0x%X of size 0x%X", name, offset, size));
                    this.memBlockHelper.addSection(name, offset, offset, size, true, false, false);
                }
            }
        }
        catch (NotFoundException | AddressOutOfBoundsException e)
        {
            Msg.warn(this, String.format("Couldn't create dyn block %s. It may be absent.", name), e);
        }
    }
    
    protected void tryCreateDynBlockWithRange(String name, ElfDynamicType start, ElfDynamicType end)
    {
        NXOAdapter adapter = this.nxo.getAdapter();
        
        try
        {
            if (adapter.getDynamicTable(this.program).containsDynamicValue(start) && adapter.getDynamicTable(this.program).containsDynamicValue(end))
            {
                long offset = adapter.getDynamicTable(this.program).getDynamicValue(start);
                long size = adapter.getDynamicTable(this.program).getDynamicValue(end) - offset;
                
                if (size > 0)
                {
                    Msg.info(this, String.format("Created dyn block %s at 0x%X of size 0x%X", name, offset, size));
                    this.memBlockHelper.addSection(name, offset, offset, size, true, false, false);
                }
            }
        }
        catch (NotFoundException | AddressOutOfBoundsException e)
        {
            Msg.warn(this, String.format("Couldn't create dyn block %s. It may be absent.", name), e);
        }
    }
    
    private static class PltEntry
    {
        long off;
        long target;
        
        public PltEntry(long offset, long target)
        {
            this.off = offset;
            this.target = target;
        }
    }
}
