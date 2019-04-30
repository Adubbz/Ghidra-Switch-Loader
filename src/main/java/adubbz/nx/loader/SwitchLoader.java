/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package adubbz.nx.loader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import adubbz.nx.loader.kip1.KIP1Header;
import adubbz.nx.loader.kip1.KIP1ProgramBuilder;
import adubbz.nx.loader.knx.KNXProgramBuilder;
import adubbz.nx.loader.nro0.NRO0Header;
import adubbz.nx.loader.nro0.NRO0ProgramBuilder;
import adubbz.nx.loader.nso0.NSO0Header;
import adubbz.nx.loader.nso0.NSO0ProgramBuilder;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SwitchLoader extends BinaryLoader 
{
    public static final String SWITCH_NAME = "Nintendo Switch Binary";
    public static final LanguageID LANG_ID = new LanguageID("AARCH64:LE:64:v8A");
    private BinaryType binaryType;

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException 
    {
        List<LoadSpec> loadSpecs = new ArrayList<>();
        BinaryReader reader = new BinaryReader(provider, true);
        String magic_0x0 = reader.readAsciiString(0, 4);
        String magic_0x10 = reader.readAsciiString(0x10, 4);
        
        reader.setPointerIndex(0);

        if (magic_0x0.equals("KIP1")) 
        {
            this.binaryType = BinaryType.KIP1;
        }
        else if (magic_0x0.equals("NSO0"))
        {
            this.binaryType = BinaryType.NSO0;
        }
        else if (magic_0x0.equals("\u00DF\u004F\u0003\u00D5"))
        {
            this.binaryType = BinaryType.KERNEL_800;
        }
        else if (magic_0x10.equals("NRO0"))
        {
            this.binaryType = BinaryType.NRO0;
        }
        else if (magic_0x10.equals("KIP1"))
        {
            // Note: This is kinda a bad way of determining this, but for now it gets the job done
            // and I don't believe there are any clashes.
            this.binaryType = BinaryType.SX_KIP1; 
        }
        else
            return loadSpecs;

        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(LANG_ID, new CompilerSpecID("default")), true));

        return loadSpecs;
    }

    @Override
    protected List<Program> loadProgram(ByteProvider provider, String programName,
            DomainFolder programFolder, LoadSpec loadSpec, List<Option> options, MessageLog log,
            Object consumer, TaskMonitor monitor)
                    throws IOException, CancelledException 
    {
        LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
        Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
        CompilerSpec importerCompilerSpec = importerLanguage.getCompilerSpecByID(pair.compilerSpecID);

        Address baseAddr = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(0);
        Program prog = createProgram(provider, programName, baseAddr, getName(), importerLanguage, importerCompilerSpec, consumer);
        boolean success = false;

        try 
        {
            success = this.loadInto(provider, loadSpec, options, log, prog, monitor, MemoryConflictHandler.ALWAYS_OVERWRITE);
        }
        finally 
        {
            if (!success) 
            {
                prog.release(consumer);
                prog = null;
            }
        }

        List<Program> results = new ArrayList<Program>();
        if (prog != null) results.add(prog);
        return results;
    }

    @Override
    protected boolean loadProgramInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            MessageLog messageLog, Program program, TaskMonitor monitor, MemoryConflictHandler memoryConflictHandler) 
                    throws IOException
    {
        if (this.binaryType == BinaryType.SX_KIP1)
        {
            ByteProvider offsetProvider = new ByteProviderWrapper(provider, 0x10, provider.length() - 0x10);
            KIP1ProgramBuilder.loadKIP1(offsetProvider, program, memoryConflictHandler, monitor);
        }
        else
        {
            if (this.binaryType == BinaryType.KIP1)
            {
                KIP1ProgramBuilder.loadKIP1(provider, program, memoryConflictHandler, monitor);
            }

            else if (this.binaryType == BinaryType.NSO0)
            {
                NSO0ProgramBuilder.loadNSO0(provider, program, memoryConflictHandler, monitor);
            }
            else if (this.binaryType == BinaryType.NRO0)
            {
                NRO0ProgramBuilder.loadNRO0(provider, program, memoryConflictHandler, monitor);
            }
            else if (this.binaryType == BinaryType.KERNEL_800)
            {
                KNXProgramBuilder.loadKNX(provider, program, memoryConflictHandler, monitor);
            }
        }
        
        return true;
    }

    @Override
    public LoaderTier getTier() 
    {
        return LoaderTier.SPECIALIZED_TARGET_LOADER;
    }

    @Override
    public int getTierPriority() 
    {
        return 0;
    }

    @Override
    public String getName() 
    {
        return SWITCH_NAME;
    }

    private static enum BinaryType
    {
        KIP1("Kernel Initial Process"), 
        NSO0("Nintendo Shared Object"), 
        NRO0("Nintendo Relocatable Object"),
        SX_KIP1("Gateway Kernel Initial Process"),
        KERNEL_800("Nintendo Switch Kernel 8.0.0+");
        
        public final String name;
        
        private BinaryType(String name)
        {
            this.name = name;
        }
    }
}
