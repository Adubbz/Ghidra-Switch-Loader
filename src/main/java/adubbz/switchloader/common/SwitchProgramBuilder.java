/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.switchloader.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import adubbz.switchloader.util.ByteUtil;
import adubbz.switchloader.util.UIUtil;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfDynamicTable;
import ghidra.app.util.bin.format.elf.ElfDynamicType;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.bin.format.elf.ElfStringTable;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.ElfSymbolTable;
import ghidra.app.util.bin.format.elf.extend.ElfExtensionFactory;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.app.util.bin.format.elf.relocation.AARCH64_ElfRelocationConstants;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public abstract class SwitchProgramBuilder 
{
    protected ByteProvider fileByteProvider;
    protected ByteProvider memoryByteProvider;
    protected BinaryReader memoryBinaryReader;
    protected FactoryBundledWithBinaryReader factoryReader;
    protected Program program;
    protected MemoryBlockUtil mbu;
    
    long baseAddress;
    protected AddressSpace aSpace;
    protected MemoryBlockHelper memBlockHelper;

    protected int textOffset;
    protected int rodataOffset;
    protected int dataOffset;
    protected int textSize;
    protected int rodataSize;
    protected int dataSize;
    
    protected MOD0Header mod0;
    protected ElfHeader dummyElfHeader;
    protected ElfDynamicTable dynamicTable;
    protected ElfStringTable stringTable;
    protected ElfSymbolTable symbolTable;
    protected ArrayList<Relocation> relocs = new ArrayList<>();
    protected ArrayList<PltEntry> pltEntries = new ArrayList<>();
    
    protected long symbolTableOff;
    protected long symbolEntrySize;
    protected long symbolTableSize;
    
    
    protected SwitchProgramBuilder(ByteProvider provider, Program program, MemoryConflictHandler handler)
    {
        this.fileByteProvider = provider;
        this.program = program;
        this.mbu = new MemoryBlockUtil(program, handler);
    }
    
    protected void load(TaskMonitor monitor)
    {
        this.baseAddress = 0x7100000000L;
        this.aSpace = program.getAddressFactory().getDefaultAddressSpace();
        
        try 
        {
            // Set the base address
            this.program.setImageBase(aSpace.getAddress(this.baseAddress), true);
            this.loadDefaultSegments(monitor);
            this.memBlockHelper = new MemoryBlockHelper(monitor, this.program, this.memoryByteProvider, this.mbu, this.baseAddress);
            this.memoryBinaryReader = new BinaryReader(this.memoryByteProvider, true);
            this.factoryReader = new FactoryBundledWithBinaryReader(RethrowContinuesFactory.INSTANCE, this.memoryByteProvider, true);
            
            // Setup memory blocks
            InputStream textInputStream = this.memoryByteProvider.getInputStream(this.textOffset);
            InputStream rodataInputStream = this.memoryByteProvider.getInputStream(this.rodataOffset);
            InputStream dataInputStream = this.memoryByteProvider.getInputStream(this.dataOffset);
            
            this.memBlockHelper.addDeferredSection(".text", this.textOffset, textInputStream, this.textSize, true, false, true);
            this.memBlockHelper.addDeferredSection(".rodata", this.rodataOffset, rodataInputStream, this.rodataSize, true, false, false);
            this.memBlockHelper.addDeferredSection(".data", this.dataOffset, dataInputStream, this.dataSize, true, true, false);
            
            try
            {
                this.loadMod0();
            }
            catch (InvalidMagicException | IllegalArgumentException e)
            {
                e.printStackTrace();
                
                // We can't create .dynamic, so work with what we've got.
                this.memBlockHelper.finalizeSections();
                return;
            }
            
            this.dummyElfHeader = new DummyElfHeader();
            
            // Create the dynamic table and its memory block
            this.dynamicTable = ElfDynamicTable.createDynamicTable(this.factoryReader, this.dummyElfHeader, this.mod0.getDynamicOffset(), this.mod0.getDynamicOffset());
            this.memBlockHelper.addSection(".dynamic", this.mod0.getDynamicOffset(), this.memoryByteProvider.getInputStream(this.mod0.getDynamicOffset()), this.dynamicTable.getLength(), true, true, false);

            // Create dynamic sections
            this.optionallyCreateDynBlock(".dynstr", ElfDynamicType.DT_STRTAB, ElfDynamicType.DT_STRSZ);
            this.optionallyCreateDynBlock(".init_array", ElfDynamicType.DT_INIT_ARRAY, ElfDynamicType.DT_INIT_ARRAYSZ);
            this.optionallyCreateDynBlock(".fini_array", ElfDynamicType.DT_FINI_ARRAY, ElfDynamicType.DT_FINI_ARRAYSZ);
            this.optionallyCreateDynBlock(".rela.dyn", ElfDynamicType.DT_RELA, ElfDynamicType.DT_RELASZ);
            this.optionallyCreateDynBlock(".rel.dyn", ElfDynamicType.DT_REL, ElfDynamicType.DT_RELSZ);
            this.optionallyCreateDynBlock(".rela.plt", ElfDynamicType.DT_JMPREL, ElfDynamicType.DT_PLTRELSZ);
            
            this.createDynSymBlock();

            this.stringTable = this.setupStringTable();
            this.symbolTable = this.setupSymbolTable();
            this.setupRelocations();
            this.memBlockHelper.finalizeSections();
            this.performRelocations();
            
            // Create BSS
            this.mbu.createUninitializedBlock(false, ".bss", aSpace.getAddress(baseAddress + this.mod0.getBssStartOffset()), this.mod0.getBssSize(), "", null, true, true, false);
        } 
        catch (AddressOverflowException | LockException | IllegalStateException | AddressOutOfBoundsException | IOException | NotFoundException | DataTypeConflictException | SecurityException | IllegalArgumentException | MemoryAccessException | InvalidInputException | NoSuchMethodException | IllegalAccessException | InvocationTargetException | CodeUnitInsertionException e) 
        {
            e.printStackTrace();
        }
        
        // Ensure memory blocks are ordered from first to last.
        // Normally they are ordered by the order they are added.
        UIUtil.sortProgramTree(this.program);
    }
    
    protected abstract void loadDefaultSegments(TaskMonitor monitor) throws IOException, AddressOverflowException, AddressOutOfBoundsException;
    
    protected void loadMod0() throws IOException
    {
        int mod0Offset = this.memoryBinaryReader.readInt(this.textOffset + 4);
        
        if (Integer.toUnsignedLong(mod0Offset) >= this.memoryByteProvider.length())
            throw new IllegalArgumentException("Mod0 offset is outside the binary!");
        
        this.mod0 = new MOD0Header(this.memoryBinaryReader, mod0Offset, mod0Offset);
    }
    
    protected void createDynSymBlock() throws NotFoundException, IOException, AddressOverflowException, AddressOutOfBoundsException
    {
        this.symbolTableOff = this.dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMTAB);
        this.symbolEntrySize = this.dynamicTable.getDynamicValue(ElfDynamicType.DT_SYMENT);
        long dtHashOff = this.dynamicTable.getDynamicValue(ElfDynamicType.DT_HASH);
        long nchain = this.memoryBinaryReader.readUnsignedInt(dtHashOff + 4);
        this.symbolTableSize = nchain * symbolEntrySize;
        this.memBlockHelper.addSection(".dynsym", symbolTableOff, this.memoryByteProvider.getInputStream(symbolTableOff), this.symbolTableSize, true, false, false);
    }
    
    protected ElfStringTable setupStringTable() throws IOException, AddressOverflowException, CodeUnitInsertionException, DataTypeConflictException, NotFoundException
    {
        long dynamicStringTableAddr = -1;
        long dynamicStringTableSize = -1;
        
        dynamicStringTableAddr = dynamicTable.getDynamicValue(ElfDynamicType.DT_STRTAB);
        dynamicStringTableSize = dynamicTable.getDynamicValue(ElfDynamicType.DT_STRSZ);

        long stringTableAddrOffset = this.baseAddress + dynamicStringTableAddr;
        ElfStringTable stringTable = ElfStringTable.createElfStringTable(new FactoryBundledWithBinaryReader(RethrowContinuesFactory.INSTANCE, this.memoryByteProvider, true), this.dummyElfHeader,
                null, dynamicStringTableAddr, stringTableAddrOffset, dynamicStringTableSize);
        
        Address address = this.aSpace.getAddress(stringTableAddrOffset);
        Address end = address.addNoWrap(stringTable.getLength() - 1);
        
        while (address.compareTo(end) < 0) 
        {
            int length = createString(address);
            address = address.addNoWrap(length);
        }
        
        return stringTable;
    }
    
    protected ElfSymbolTable setupSymbolTable() throws InvalidInputException, NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException
    {
        Method m = ElfSymbolTable.class.getDeclaredMethod("createElfSymbolTable", FactoryBundledWithBinaryReader.class, ElfHeader.class, ElfSectionHeader.class, long.class, long.class, 
                long.class, long.class, ElfStringTable.class, boolean.class);
        m.setAccessible(true);
        ElfSymbolTable symbolTable = (ElfSymbolTable)m.invoke(null, this.factoryReader, this.dummyElfHeader, null,
                this.symbolTableOff,
                this.symbolTableOff,
                this.symbolTableSize,
                this.symbolEntrySize,
                this.stringTable, true);
        
        for (ElfSymbol elfSymbol : symbolTable.getSymbols()) 
        {
            Address address = this.aSpace.getAddress(this.baseAddress + elfSymbol.getValue());
            String symName = elfSymbol.getNameAsString();
            this.evaluateElfSymbol(elfSymbol, address, false);
        }
        
        return symbolTable;
    }
    
    protected void setupRelocations() throws NotFoundException, IOException, MemoryAccessException, AddressOverflowException, AddressOutOfBoundsException
    {
        if (this.dynamicTable.containsDynamicValue(ElfDynamicType.DT_REL.value)) 
        {
            Msg.info(this, "Processing DT_REL relocations...");
            processRelocations(program, this.memoryBinaryReader, relocs, this.symbolTable,
                    (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_REL),
                    (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_RELSZ));
        }
        if (this.dynamicTable.containsDynamicValue(ElfDynamicType.DT_RELA)) 
        {
            Msg.info(this, "Processing DT_RELA relocations...");
            processRelocations(program, this.memoryBinaryReader, relocs, this.symbolTable,
                    (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_RELA),
                    (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_RELASZ));
        }
        if (this.dynamicTable.containsDynamicValue(ElfDynamicType.DT_JMPREL)) 
        {
            Msg.info(this, "Processing JMPREL relocations...");
            ArrayList<Relocation> pltRelocs = new ArrayList<>();
            
            this.processRelocations(program, this.memoryBinaryReader, pltRelocs, this.symbolTable,
                    (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_JMPREL),
                    (long)this.dynamicTable.getDynamicValue(ElfDynamicType.DT_PLTRELSZ));
            relocs.addAll(pltRelocs);
            
            pltRelocs.sort(Comparator.comparing(reloc -> reloc.offset));
            long pltGotStart = pltRelocs.get(0).offset;
            long pltGotEnd = pltRelocs.get(pltRelocs.size() - 1).offset + 8;
            
            if (this.dynamicTable.containsDynamicValue(ElfDynamicType.DT_PLTGOT))
            {
                long pltGotOff = this.dynamicTable.getDynamicValue(ElfDynamicType.DT_PLTGOT);
                this.memBlockHelper.addSection(".got.plt", pltGotOff, this.memoryByteProvider.getInputStream(pltGotOff), pltGotEnd - pltGotStart, true, false, false);
            }
            
            int last = 12;
            
            while (true)
            {
                int pos = -1;
                
                for (int i = last; i < this.textSize; i++)
                {
                    if (this.memoryBinaryReader.readInt(i) == 0xD61F0220)
                    {
                        pos = i;
                        break;
                    }
                }
                
                if (pos == -1) break;
                last = pos + 1;
                if ((pos % 4) != 0) continue;
                
                int off = pos - 12;
                long a = Integer.toUnsignedLong(this.memoryBinaryReader.readInt(off));
                long b = Integer.toUnsignedLong(this.memoryBinaryReader.readInt(off + 4));
                long c = Integer.toUnsignedLong(this.memoryBinaryReader.readInt(off + 8));
                long d = Integer.toUnsignedLong(this.memoryBinaryReader.readInt(off + 12));

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
            
            long pltStart = this.pltEntries.get(0).off;
            long pltEnd = this.pltEntries.get(this.pltEntries.size() - 1).off + 0x10;
            this.memBlockHelper.addSection(".plt", pltStart, this.memoryByteProvider.getInputStream(pltStart), pltEnd - pltStart, true, false, false);
            
            boolean good = false;
            long gotEnd = pltGotEnd + 8;
            
            while (!this.dynamicTable.containsDynamicValue(ElfDynamicType.DT_INIT_ARRAY) || gotEnd < this.dynamicTable.getDynamicValue(ElfDynamicType.DT_INIT_ARRAY))
            {
                boolean foundOffset = false;
                
                for (Relocation reloc : this.relocs)
                {
                    if (reloc.offset == gotEnd)
                    {
                        foundOffset = true;
                        break;
                    }
                }
                
                if (!foundOffset)
                    break;
                
                good = true;
                gotEnd += 8;
            }
            
            if (good)
                this.memBlockHelper.addSection(".got", pltGotEnd, this.memoryByteProvider.getInputStream(pltGotEnd), gotEnd - pltGotEnd, true, false, false);
        }
        
        // TODO: Handle imports
    }
    
    protected void performRelocations() throws MemoryAccessException, InvalidInputException, AddressOutOfBoundsException
    {
        Map<Long, String> gotNameLookup = new HashMap<>(); 
        
        // Relocations again
        for (Relocation reloc : relocs) 
        {
            Address target = this.aSpace.getAddress(reloc.offset + this.baseAddress);
            if (reloc.r_type == AARCH64_ElfRelocationConstants.R_AARCH64_GLOB_DAT ||
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
                    program.getMemory().setLong(target, reloc.sym.getValue() + this.baseAddress + reloc.addend);
                    
                    if (reloc.addend == 0)
                        gotNameLookup.put(reloc.offset, reloc.sym.getNameAsString());
                }
            } 
            else if (reloc.r_type == AARCH64_ElfRelocationConstants.R_AARCH64_RELATIVE) 
            {
                long target_val = program.getMemory().getLong(target);
                program.getMemory().setLong(target, target_val + this.baseAddress);
            } 
            else 
            {
                Msg.info(this, String.format("TODO: r_type 0x%x", reloc.r_type));
            }
        }
        
        for (PltEntry entry : this.pltEntries)
        {
            if (gotNameLookup.containsKey(entry.target))
            {
                long addr = this.baseAddress + entry.off;
                String name = gotNameLookup.get(entry.target);
                // TODO: Mark as func
                this.createSymbol(this.aSpace.getAddress(addr), name, false, false, null);
            }
        }
    }
    
    private Set<Long> processRelocations(Program program, BinaryReader provider, List<Relocation> relocs, ElfSymbolTable symtab, long rel, long relsz) throws IOException 
    {
        Set<Long> locations = new HashSet<Long>();
        for (long i = 0; i < relsz / 0x18; i++) 
        {
            long offset = provider.readLong(rel + i * 0x18);
            long info = provider.readLong(rel + i * 0x18 + 8);
            long addend = provider.readLong(rel + i * 0x18 + 0x10);
            
            long r_type = info & 0xffffffffL;
            long r_sym = info >> 32;
        
            ElfSymbol sym;
            if (r_sym != 0) {
                sym = symtab.getSymbolAt(r_sym);
            } else {
                sym = null;
            }
            
            if (r_type != AARCH64_ElfRelocationConstants.R_AARCH64_TLSDESC)
            {
                locations.add(offset);
            }
            relocs.add(new Relocation(offset, r_type, sym, addend));
        }
        return locations;
    }
    
    protected int createString(Address address) throws CodeUnitInsertionException, DataTypeConflictException 
    {
        Data d = this.program.getListing().getDataAt(address);
        
        if (d == null || !TerminatedStringDataType.dataType.isEquivalent(d.getDataType())) 
        {
            d = this.program.getListing().createData(address, TerminatedStringDataType.dataType, -1);
        }
        
        return d.getLength();
    }
    
    private void evaluateElfSymbol(ElfSymbol elfSymbol, Address address, boolean isFakeExternal) throws InvalidInputException 
    {
        if (elfSymbol.isSection()) {
            // Do not add section symbols to program symbol table
            return;
        }

        String name = elfSymbol.getNameAsString();
        if (name == null) {
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

        createSymbol(address, name, isPrimary, elfSymbol.isAbsolute(), null);

        // NOTE: treat weak symbols as global so that other programs may link to them.
        // In the future, we may want additional symbol flags to denote the distinction
        if ((elfSymbol.isGlobal() || elfSymbol.isWeak()) && !isFakeExternal) 
        {
            program.getSymbolTable().addExternalEntryPoint(address);
        }
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
    
    protected void optionallyCreateDynBlock(String name, ElfDynamicType offsetType, ElfDynamicType sizeType) throws NotFoundException, IOException, AddressOverflowException, AddressOutOfBoundsException
    {
        if (this.dynamicTable.containsDynamicValue(offsetType) && this.dynamicTable.containsDynamicValue(sizeType))
        {
            long offset = this.dynamicTable.getDynamicValue(offsetType);
            long size = this.dynamicTable.getDynamicValue(sizeType);
            
            if (size > 0)
            {
                Msg.info(this, String.format("Created dyn block %s at 0x%X of size 0x%X", name, offset, size));
                this.memBlockHelper.addSection(name, offset, this.memoryByteProvider.getInputStream(offset), size, true, false, false);
            }
        }
    }
    
    private static class Relocation 
    {
        public Relocation(long offset, long r_type, ElfSymbol sym, long addend) 
        {
            this.offset = offset;
            this.r_type = r_type;
            this.sym = sym;
            this.addend = addend;
        }
        
        long offset;
        long r_type;
        ElfSymbol sym;
        long addend;
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
    
    // Fake only what is needed for an elf dynamic table
    private static class DummyElfHeader extends ElfHeader
    {
        private HashMap<Integer, ElfDynamicType> dynamicTypeMap;
        
        public DummyElfHeader()
        {
            dynamicTypeMap = new HashMap<>();
            ElfDynamicType.addDefaultTypes(this.dynamicTypeMap);

            ElfLoadAdapter extensionAdapter = ElfExtensionFactory.getLoadAdapter(this);
            if (extensionAdapter != null) 
            {
                extensionAdapter.addDynamicTypes(this.dynamicTypeMap);
            }
        }
        
        @Override
        protected HashMap<Integer, ElfDynamicType> getDynamicTypeMap() 
        {
            return this.dynamicTypeMap;
        }

        @Override
        public ElfDynamicType getDynamicType(int type) 
        {
            if (this.dynamicTypeMap != null) 
            {
                return this.dynamicTypeMap.get(type);
            }
            return null; // not found
        }
        
        @Override
        public boolean is32Bit() 
        {
            return false;
        }
    }
}
