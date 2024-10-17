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
import java.util.function.BiFunction;

import adubbz.nx.loader.common.NXProgramBuilder;
import adubbz.nx.loader.kip1.KIP1Adapter;
import adubbz.nx.loader.knx.KNXAdapter;
import adubbz.nx.loader.nro0.NRO0Adapter;
import adubbz.nx.loader.nso0.NSO0Adapter;
import adubbz.nx.loader.nxo.NXOAdapter;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.Project;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.app.util.opinion.Loaded;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SwitchLoader extends BinaryLoader 
{
    public static final String SWITCH_NAME = "Nintendo Switch Binary";
    public static final LanguageID AARCH64_LANGUAGE_ID = new LanguageID("AARCH64:LE:64:v8A");
    public static final LanguageID AARCH32_LANGUAGE_ID = new LanguageID("ARM:LE:32:v8");
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

        var adapter = this.binaryType.createAdapter(null, provider);
        
        if (adapter.isAarch32())
        {
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(AARCH32_LANGUAGE_ID, new CompilerSpecID("default")), true));
        }
        else
        {
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(AARCH64_LANGUAGE_ID, new CompilerSpecID("default")), true));
        }

        return loadSpecs;
    }

    @Override
    protected List<Loaded<Program>> loadProgram(ByteProvider provider, String programName, Project project, String programFolderPath, LoadSpec loadSpec, List<Option> options, MessageLog log, Object consumer, TaskMonitor monitor) throws IOException, CancelledException
    {
        LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
        Language importerLanguage = getLanguageService().getLanguage(pair.languageID);
        CompilerSpec importerCompilerSpec = importerLanguage.getCompilerSpecByID(pair.compilerSpecID);

        Address baseAddr = importerLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(0);
        Program prog = createProgram(provider, programName, baseAddr, getName(), importerLanguage, importerCompilerSpec, consumer);
        boolean success = false;

        List<Loaded<Program>> results;

        try 
        {
            this.loadInto(provider, loadSpec, options, log, prog, monitor);
            success = true;
            results = List.of(new Loaded<>(prog, programName, programFolderPath));
        }
        finally 
        {
            if (!success) 
            {
                prog.release(consumer);
            }
        }

        return results;
    }

    @Override
    protected void loadProgramInto(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            MessageLog messageLog, Program program, TaskMonitor monitor)
                    throws IOException, CancelledException
    {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        
        if (this.binaryType == BinaryType.SX_KIP1)
        {
            provider = new ByteProviderWrapper(provider, 0x10, provider.length() - 0x10);
        }

        var adapter = this.binaryType.createAdapter(program, provider);
        
        // Set the base address
        try 
        {
            long baseAddress = adapter.isAarch32() ? 0x60000000L : 0x7100000000L;
            
            if (this.binaryType == BinaryType.KERNEL_800)
            {
                baseAddress = 0x80060000L;
            }

            program.setImageBase(space.getAddress(baseAddress), true);
        } 
        catch (AddressOverflowException | LockException | IllegalStateException | AddressOutOfBoundsException e) 
        {
            Msg.error(this, "Failed to set image base", e);
        }

        var loader = new NXProgramBuilder(program, provider, adapter);
        loader.load(monitor);
        
        if (this.binaryType == BinaryType.KIP1)
        {
            // KIP1s always start with a branch instruction at the start of their text
            loader.createEntryFunction("entry", program.getImageBase().getOffset(), monitor);
        }
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

    private enum BinaryType
    {
        KIP1("Kernel Initial Process", KIP1Adapter::new),
        NSO0("Nintendo Shared Object", NSO0Adapter::new), 
        NRO0("Nintendo Relocatable Object", NRO0Adapter::new),
        SX_KIP1("Gateway Kernel Initial Process", KIP1Adapter::new),
        KERNEL_800("Nintendo Switch Kernel 8.0.0+", KNXAdapter::new);
        
        public final String name;
        private final BiFunction<Program, ByteProvider, NXOAdapter> adapterFunc;
        
        BinaryType(String name, BiFunction<Program, ByteProvider, NXOAdapter> adapterFunc)
        {
            this.name = name;
            this.adapterFunc = adapterFunc;
        }
        
        public NXOAdapter createAdapter(Program program, ByteProvider provider)
        {
            return adapterFunc.apply(program, provider);
        }
    }
}
