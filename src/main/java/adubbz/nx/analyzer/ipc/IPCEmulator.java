/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.analyzer.ipc;

import adubbz.nx.util.ByteUtil;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.emulate.BreakTableCallBack;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.CodeManager;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import org.apache.commons.compress.utils.Lists;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;

public class IPCEmulator 
{
    private static final int MAX_BUFFER_ATTRS = 8;
    private static final int BUFFER_ATTR_IN = IPCTrace.BUFFER_ATTR_IN;
    private static final int BUFFER_ATTR_OUT = IPCTrace.BUFFER_ATTR_OUT;
    private static final int BUFFER_ATTR_HIPC_MAP_ALIAS = 4;
    private static final int BUFFER_ATTR_HIPC_POINTER = 8;
    private static final int BUFFER_ATTR_HIPC_AUTO_SELECT = 32;
    private static final int BUFFER_ATTR_HIPC_MAP_TRANSFER_ALLOWS_NON_SECURE = 64;
    private static final int BUFFER_ATTR_HIPC_MAP_TRANSFER_ALLOWS_NON_DEVICE = 128;
    private static final int BUFFER_ATTR_VALID_MASK =
        BUFFER_ATTR_IN |
        BUFFER_ATTR_OUT |
        BUFFER_ATTR_HIPC_MAP_ALIAS |
        BUFFER_ATTR_HIPC_POINTER |
        16 |
        BUFFER_ATTR_HIPC_AUTO_SELECT |
        BUFFER_ATTR_HIPC_MAP_TRANSFER_ALLOWS_NON_SECURE |
        BUFFER_ATTR_HIPC_MAP_TRANSFER_ALLOWS_NON_DEVICE;

    private Program program;
    public boolean hasSetup;
    
    private SleighLanguage sLang;
    private MemoryState state;
    private MemoryBank ramBank;
    private MemoryBank registerBank;
    private BreakTableCallBack bTable;
    private Emulate emu;
    private Disassembler disassembler;
    
    private List<Consumer<Long>> instructionHandlers = Lists.newArrayList();
    
    private long messageSize;
    private long messagePtr;
    
    private long messageStructPtr;
    private long targetObjectPtr;
    private long ipcObjectPtr;
    
    private long retInstructionPtr;
    private long inObjectVtablePtr;
    private long inObjectPtr;
    
    private long bufferSize;
    private long bufferMemory;
    private long outputMemory;
    
    private IPCTrace currentTrace;
    
    public IPCEmulator(Program program)
    {
        this.program = program;
    
        try 
        {
            this.setup();
            this.hasSetup = true;
        }
        catch (MemoryAccessException e) 
        {
            Msg.error(this, "Failed to setup IPC emulator");
        }
    }
    
    public void setup() throws MemoryAccessException
    {
        MemoryFaultHandler faultHandler = new MemoryFaultHandler()
        {

            @Override
            public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset) 
            {
                Emulate emu = IPCEmulator.this.emu;
                long pc = IPCEmulator.this.state.getValue("pc");
                
                if (address.isRegisterAddress())
                {
                    for (Register reg : sLang.getRegisters(address))
                    {
                        Msg.info(this, String.format("Uninitialized read from register %s at 0x%X", reg.getName(), address.getOffset()));
                    }
                }
                
                return false;
            }

            @Override
            public boolean unknownAddress(Address address, boolean write) 
            {
                Msg.info(this, String.format("Unknwon address 0x%X", address.getOffset()));
                return false;
            }
        };
        
        this.sLang = (SleighLanguage)this.program.getLanguage();
        this.state = new DefaultMemoryState(this.sLang);
        
        // Create banks for ram and registers and add them to our state
        this.ramBank = new MemoryPageBank(this.sLang.getAddressFactory().getDefaultAddressSpace(), false, 4096, faultHandler);
        this.registerBank = new MemoryPageBank(this.sLang.getAddressFactory().getRegisterSpace(), false, 4096, faultHandler);
        this.state.setMemoryBank(this.ramBank);
        this.state.setMemoryBank(this.registerBank);
        
        this.bTable = new BreakTableCallBack(this.sLang);
        this.emu = new Emulate(this.sLang, this.state, this.bTable);
        this.disassembler = Disassembler.getDisassembler(this.program, TaskMonitorAdapter.DUMMY, null);
        
        // Copy over our binary to the emulator's memory, typically 7100000000
        Memory programMemory = this.program.getMemory();
        byte[] programBytes = new byte[(int)programMemory.getMaxAddress().getOffset()+1];
        
        // Copy memory blocks manually. The entire thing can't be copied at once because there are gaps between segments
        for (MemoryBlock block : programMemory.getBlocks())
        {
            if (block.isInitialized())
            {
                byte[] blockBytes = new byte[(int)block.getSize()];
                int copiedBytes = programMemory.getBytes(block.getStart(), blockBytes);
                
                if (copiedBytes != blockBytes.length)
                    throw new RuntimeException(String.format("Failed to copy bytes from 0x%X of size 0x%x!", block.getStart().getOffset(), block.getSize()));
                
                // Copy the block bytes to the program bytes
                long blockOff = block.getStart().getOffset() - this.program.getImageBase().getOffset();
                System.arraycopy(blockBytes, 0, programBytes, (int)blockOff, (int)block.getSize());
            }
        }
            
        state.setChunk(programBytes, sLang.getAddressFactory().getDefaultAddressSpace(), this.program.getImageBase().getOffset(), programBytes.length);
        
        // Initialize GPRs
        for (int i = 0; i <= 30; i++)
            state.setValue("x" + i, 0);
        
        // Stack is from 0x100000000-0x100002000
        state.setValue("sp", 0x100002000L);
        
        // Allocate IPC message data.
        // We set it later
        this.messageSize = 0x1010;
        this.messagePtr = this.calloc(messageSize);
        
        this.messageStructPtr = this.calloc(0x10);
        this.setLong(messageStructPtr, messagePtr); // Message ptr
        this.setLong(messageStructPtr + 0x8, messageSize); // Message length
        
        // Create the ipc vtable and object
        long ipcVtableSize = 0x8 * 11;
        long ipcVtablePtr = this.calloc(ipcVtableSize);
        this.setLong(ipcVtablePtr,        this.createFunctionPointer(this::PrepareForProcess));
        this.setLong(ipcVtablePtr + 0x8,  this.createFunctionPointer(this::OverwriteClientProcessId));
        this.setLong(ipcVtablePtr + 0x10, this.createFunctionPointer(this::GetBuffers));
        this.setLong(ipcVtablePtr + 0x18, this.createFunctionPointer(this::GetInNativeHandles));
        this.setLong(ipcVtablePtr + 0x20, this.createFunctionPointer(this::GetInObjects));
        this.setLong(ipcVtablePtr + 0x28, this.createFunctionPointer(this::BeginPreparingForReply));
        this.setLong(ipcVtablePtr + 0x30, this.createFunctionPointer(this::SetBuffers));
        this.setLong(ipcVtablePtr + 0x38, this.createFunctionPointer(this::SetOutObjects));
        this.setLong(ipcVtablePtr + 0x40, this.createFunctionPointer(this::SetOutNativeHandles));
        this.setLong(ipcVtablePtr + 0x48, this.createFunctionPointer(this::BeginPreparingForErrorReply));
        this.setLong(ipcVtablePtr + 0x50, this.createFunctionPointer(this::EndPreparingForReply));
        this.ipcObjectPtr = this.calloc(0x10);
        this.setLong(this.ipcObjectPtr, ipcVtablePtr);
        
        // Create the target function vtable
        long targetFuncVtableSize = 0x8 * 512;
        long targetFuncVtablePtr = this.calloc(targetFuncVtableSize);
        
        // Create 512 function pointers, each with a different offset within the target function vtable.
        // This allows us to figure out the vtable offsets for each command id.
        for (long off = 0; off < targetFuncVtableSize; off += 8)
        {
            final long off2 = off; // Lambdas require this to be final
            long targetFuncPtr = this.createFunctionPointer(() -> this.targetFunction(off2));
            
            long targetFuncVtableOff = targetFuncVtablePtr + off; // Where to put the function pointer within the target func vtable
            this.setLong(targetFuncVtableOff, targetFuncPtr);
        }
        
        this.targetObjectPtr = this.calloc(0x10);
        this.setLong(this.targetObjectPtr, targetFuncVtablePtr);
        
        this.retInstructionPtr = this.calloc(0x4);
        this.setInt(this.retInstructionPtr, 0xd65f03c0);
        this.inObjectVtablePtr = this.calloc(0x8 * 16);
        
        // Set up the in object vtable
        for (int i = 0; i < 16; i++)
        {
            this.setLong(this.inObjectVtablePtr + i * 0x8, this.retInstructionPtr);
        }
        
        this.inObjectPtr = this.calloc(0x8 + 8 * 16);
        this.setLong(this.inObjectPtr, this.inObjectVtablePtr);
        
        this.bufferSize = 0x1000;
        this.bufferMemory = this.calloc(this.bufferSize);
        this.outputMemory = this.calloc(0x1000);
    }
    
    public IPCTrace emulateCommand(Address procFuncAddr, int cmd)
    {
        if (!this.hasSetup)
            return null;
        
        // Some commands have in-dispatcher validation. If we fail this
        // validation we miss some information about vtable offsets and
        // returned objects. This tries to brute-force until we find an
        // input that passes that validation.

        int[] bufferSizes = new int[] { 0x300, 128, 33, 1 };
        ByteBuffer nonZeroBuf = ByteBuffer.allocate(0x8 * 6);
        
        for (int i = 0; i < 6; i++) nonZeroBuf.putLong(1);
        
        // All-zeros, standard buffer size
        IPCTrace trace = this.emulateCommand(procFuncAddr, cmd, null, 0x1000);
        
        if (trace.isCorrect())
            return trace;
            
        // Pass checks for non-zero inline data
        trace = this.emulateCommand(procFuncAddr, cmd, nonZeroBuf.array(), 0x1000);

        if (trace.isCorrect())
            return trace;
        
        // All-zeros, Pass buffer size checks
        for (int bufSize : bufferSizes)
        {
            trace = this.emulateCommand(procFuncAddr, cmd, null, bufSize);
            
            if (trace.isCorrect())
                return trace;
        }
        
        nonZeroBuf = ByteBuffer.allocate(0x8 * 4);
        for (int i = 0; i < 4; i++) nonZeroBuf.putLong(1);

        // Pass checks for buffer size, and non-zero inline data
        for (int bufSize : bufferSizes)
        {
            trace = this.emulateCommand(procFuncAddr, cmd, nonZeroBuf.array(), bufSize);
            
            if (trace.isCorrect())
                return trace;
        }
        
        Msg.warn(this, String.format("Warning: unable to brute-force validation on dispatch_func %X command %d", procFuncAddr.getOffset(), cmd));
        return trace;
    }
    
    public IPCTrace emulateCommand(Address procFuncAddr, int cmd, byte[] data, int bufferSize)
    {
        if (!this.hasSetup)
            return null;

        if (bufferSize < 0 || bufferSize > 0x1000)
            throw new RuntimeException("Invalid buffer size provided");

        this.bufferSize = bufferSize;
        this.instructionHandlers.clear();
        this.currentTrace = new IPCTrace(cmd, procFuncAddr.getOffset());

        byte[] zeros = new byte[(int)this.messageSize];
        this.state.setChunk(zeros, this.sLang.getDefaultSpace(), this.messagePtr, zeros.length);

        this.setLong(messagePtr, 0x49434653);
        this.setLong(messagePtr + 0x8, cmd);

        if (data != null && data.length > 0)
            this.state.setChunk(data, this.sLang.getDefaultSpace(), this.messagePtr + 0x10, data.length);

        this.state.setValue("x0", this.targetObjectPtr);
        this.state.setValue("x1", this.ipcObjectPtr);
        this.state.setValue("x2", this.messageStructPtr);

        emu.setExecuteAddress(procFuncAddr);
        disassembler.disassemble(procFuncAddr, null);

        final int MAX_INSTRUCTIONS_WITH_META = 100_000;
        final int MAX_INSTRUCTIONS_NO_META   = 5_000;
        final int MAX_NO_META_PC_HITS        = 256;
        int instructionCount = 0;
        Map<Long, Integer> noMetaPcHits = new HashMap<>();

        while (true)
        {
            boolean hasMeta = this.currentTrace.bytesIn != -1;
            int limit = hasMeta ? MAX_INSTRUCTIONS_WITH_META : MAX_INSTRUCTIONS_NO_META;
            long pc = state.getValue("pc");

            for (Consumer<Long> instructionHandler : this.instructionHandlers)
                instructionHandler.accept(pc);

            if (emu.getExecuteAddress().getOffset() == 0)
                break;

            if (!hasMeta)
            {
                int pcHits = noMetaPcHits.getOrDefault(pc, 0) + 1;
                noMetaPcHits.put(pc, pcHits);

                if (pcHits > MAX_NO_META_PC_HITS)
                {
                    this.currentTrace.timedOut = true;
                    break;
                }
            }

            if (++instructionCount > limit)
            {
                this.currentTrace.timedOut = true;

                if (!hasMeta)
                {
                    // Silent — this is just a command that doesn't exist in this interface
                }
                else
                {
                    Msg.warn(this, String.format(
                        "Emulation exceeded %d instructions for proc_func 0x%X cmd %d, aborting",
                        limit, procFuncAddr.getOffset(), cmd));
                }
                break;
            }

            try
            {
                emu.executeInstruction(true, TaskMonitor.DUMMY);
            }
            catch (CancelledException | LowlevelError e)
            {
                e.printStackTrace();
                break; // also break on error rather than silently continuing
            }
        }

        return this.currentTrace;
    }
    
    /**
     * Memory utils 
     */
    
    private static final long HEAP_START = 0x200000000L;
    private static final long HEAP_SIZE = 0x100000L;
    private long nextHeapPtr = HEAP_START;
    
    private static final long FUNC_PTR_START = 0x400000000L;
    private long nextFuncPtr = FUNC_PTR_START;
    
    private long allocate(long size)
    {
        long available = (HEAP_START + HEAP_SIZE) - nextHeapPtr;
        // Align to 0x10
        long allocationSize = (size + 0xF) & ~0xF;
        
        if (allocationSize > available)
            throw new RuntimeException(String.format("Could not allocate 0x%X bytes", allocationSize));
        
        long start = nextHeapPtr;
        nextHeapPtr += allocationSize;
        return start;
    }
    
    private long calloc(long size)
    {
        long start = allocate(size);
        byte[] vals = new byte[(int)size];
        this.state.setChunk(vals, this.sLang.getDefaultSpace(), start, vals.length);
        return start;
    }
    
    private long createFunctionPointer(Supplier<Boolean> func)
    {
        long start = nextFuncPtr;
        nextFuncPtr += 0x8;
        
        BreakCallBack callBack = new BreakCallBack()
        {
            @Override
            public boolean addressCallback(Address addr) 
            {
                if (addr.getOffset() == start)
                {
                    if (!func.get())
                    {
                        // Failed, halt execution.
                        IPCEmulator.this.emu.setExecuteAddress(addr.getNewAddress(0));
                        //Msg.info(this, "HLE function returned false, halting further execution...");
                    }
                    
                    // Don't execute the instruction. We've handled it
                    return true;
                }
                
                // Execute the instruction
                return false;
            }
        };
        
        this.bTable.registerAddressCallback(this.sLang.getDefaultSpace().getAddress(start), callBack);
        return start;
    }
    
    private void setLong(long off, long val)
    {
        this.state.setChunk(Utils.longToBytes(val, 0x8, this.sLang.isBigEndian()), this.sLang.getDefaultSpace(), off, 0x8);
    }
    
    private void setInt(long off, long val)
    {
        this.state.setChunk(Utils.longToBytes(val, 0x4, this.sLang.isBigEndian()), this.sLang.getDefaultSpace(), off, 0x4);
    }
    
    private void printMemory(long off, long size)
    {
        Msg.info(this, String.format("0x%X (0x%X bytes):", off, size));
        byte[] out = new byte[(int)size];
        this.state.getChunk(out, this.sLang.getDefaultSpace(), off, out.length, true);
        ByteUtil.logBytes(out);
    }
    
    /**
     * HLE function utils 
     */
    
    private void returnFromFunc(long value)
    {
        this.state.setValue("x0", value);
        // x30 = lr
        this.emu.setExecuteAddress(this.sLang.getDefaultSpace().getAddress(this.state.getValue("x30")));
    }
    
    /**
     * HLE-ed functions.
     * If these return false, the emulation will halt.
     */
    
    private boolean targetFunction(long offset)
    {
        this.currentTrace.vtOffset = offset;
        this.returnFromFunc(0);
        return true;
    }
    
    private boolean PrepareForProcess()
    {
        long metaInfoPtr = this.state.getValue("x1");
        long metaInfoSize = 0x90;
        byte[] metaInfo = new byte[(int)metaInfoSize];

        if (metaInfoSize != this.state.getChunk(metaInfo, this.sLang.getDefaultSpace(), metaInfoPtr, metaInfo.length, true))
            throw new RuntimeException("Failed to read meta info");

        try
        {
            Metadata metadata = decodeMetadata(metaInfo);

            if (metadata != null)
            {
                this.currentTrace.bytesIn       = metadata.bytesIn;
                this.currentTrace.bytesOut      = metadata.bytesOut;
                this.currentTrace.bufferCount   = metadata.bufferCount;
                this.currentTrace.bufferAttrs   = metadata.bufferAttrs;
                this.currentTrace.bufferAttrsSource = metadata.bufferAttrsSource;
                this.currentTrace.bufferAttrsProbe = metadata.bufferAttrsProbe;
                this.currentTrace.inInterfaces  = metadata.inInterfaces;
                this.currentTrace.outInterfaces = metadata.outInterfaces;
                this.currentTrace.inHandles     = metadata.inHandles;
                this.currentTrace.outHandles    = metadata.outHandles;
                this.currentTrace.lr            = this.state.getValue("x30");

                if (this.currentTrace.inInterfaces > 0)
                {
                    this.instructionHandlers.add((off) ->
                    {
                        Address pcAddr = this.sLang.getDefaultSpace().getAddress(off);
                        CodeManager codeManager = ((ProgramDB)this.program).getCodeManager();
                        Instruction currentInstruction = codeManager.getInstructionAt(pcAddr);

                        if (currentInstruction == null)
                        {
                            disassembler.disassemble(pcAddr, null);
                            currentInstruction = codeManager.getInstructionAt(pcAddr);
                        }

                        if (currentInstruction != null)
                        {
                            InstructionPrototype prototype = currentInstruction.getPrototype();
                            String mnemonic = prototype.getMnemonic(currentInstruction.getInstructionContext());

                            if (mnemonic.equals("cmp") &&
                                currentInstruction.getOperandType(0) == OperandType.REGISTER &&
                                currentInstruction.getOperandType(1) == OperandType.REGISTER)
                            {
                                Register r0 = currentInstruction.getRegister(0);
                                Register r1 = currentInstruction.getRegister(1);

                                if (r0.getName().equals("x8") && r1.getName().equals("x9"))
                                {
                                    long x9 = this.state.getValue("x9");
                                    this.state.setValue("x8", x9);
                                    this.state.setValue("NZCV", 0b0100);
                                }
                            }
                        }
                    });
                }

                this.returnFromFunc(0);
                return true;
            }

            Msg.warn(this, String.format(
                "PrepareForProcess: no valid layout found for cmd %d. metaInfo[0..0x30]: %s",
                this.currentTrace.cmdId, bytesToHex(metaInfo, 0x30)));
            return false;
        }
        catch (Exception e)
        {
            Msg.error(this, "PrepareForProcess exception", e);
            return false;
        }
    }

    private static Metadata decodeMetadata(byte[] metaInfo)
    {
        Metadata metadata = decodeRuntimeMetadata(metaInfo);
        if (metadata != null && looksLikeRuntimeMetadata(metaInfo))
            return metadata;

        metadata = decodeLegacyCompactMetadata(metaInfo, 0x00);
        if (metadata != null)
            return metadata;

        int[] wideBases = new int[] { 0x08, 0x10, 0x18, 0x20 };
        for (int base : wideBases)
        {
            metadata = decodeLegacyWideMetadata(metaInfo, base);
            if (metadata != null)
                return metadata;
        }

        return null;
    }

    private static Metadata decodeLegacyCompactMetadata(byte[] metaInfo, int base)
    {
        // Legacy Nintendo SDK-style metadata stores CMIF header-inclusive raw
        // sizes followed by object/buffer/handle counts.
        long rawBytesIn    = readU16LE(metaInfo, base + 0x00);
        long rawBytesOut   = readU16LE(metaInfo, base + 0x02);
        long inInterfaces  = metaInfo[base + 0x04] & 0xFFL;
        long bufferCount   = metaInfo[base + 0x05] & 0xFFL;
        long outInterfaces = metaInfo[base + 0x06] & 0xFFL;
        long inHandles     = metaInfo[base + 0x07] & 0xFFL;
        long outHandles    = metaInfo[base + 0x08] & 0xFFL;

        if (!isValidLegacyMetadata(rawBytesIn, rawBytesOut, bufferCount, inInterfaces, outInterfaces, inHandles, outHandles))
            return null;

        BufferAttrsResult bufferAttrs = decodeCompactBufferAttrs(metaInfo, base, bufferCount);
        String bufferAttrsProbe = bufferAttrs == null ? describeCompactBufferAttrProbes(metaInfo, base, bufferCount) : null;

        return new Metadata(rawBytesIn - 0x10, rawBytesOut - 0x10, bufferCount, inInterfaces,
            outInterfaces, inHandles, outHandles, bufferAttrs, bufferAttrsProbe);
    }

    private static Metadata decodeLegacyWideMetadata(byte[] metaInfo, int base)
    {
        long rawBytesIn    = readU32LE(metaInfo, base + 0x00);
        long rawBytesOut   = readU32LE(metaInfo, base + 0x08);
        long inInterfaces  = readU32LE(metaInfo, base + 0x10);
        long bufferCount   = readU32LE(metaInfo, base + 0x14);
        long outInterfaces = readU32LE(metaInfo, base + 0x18);
        long inHandles     = readU32LE(metaInfo, base + 0x1C);
        long outHandles    = readU32LE(metaInfo, base + 0x20);

        if (!isValidLegacyMetadata(rawBytesIn, rawBytesOut, bufferCount, inInterfaces, outInterfaces, inHandles, outHandles))
            return null;

        BufferAttrsResult bufferAttrs = decodeWideBufferAttrs(metaInfo, base, bufferCount);
        String bufferAttrsProbe = bufferAttrs == null ? describeWideBufferAttrProbes(metaInfo, base, bufferCount) : null;

        return new Metadata(rawBytesIn - 0x10, rawBytesOut - 0x10, bufferCount, inInterfaces,
            outInterfaces, inHandles, outHandles, bufferAttrs, bufferAttrsProbe);
    }

    private static Metadata decodeRuntimeMetadata(byte[] metaInfo)
    {
        // Atmosphere's ServerMessageRuntimeMetadata is an eight-byte POD:
        // in data size, unaligned out data size, in/out header sizes, in/out object counts.
        long bytesIn       = readU16LE(metaInfo, 0x00);
        long bytesOut      = readU16LE(metaInfo, 0x02);
        long inHeadersSize = metaInfo[0x04] & 0xFFL;
        long outHeadersSize= metaInfo[0x05] & 0xFFL;
        long inInterfaces  = metaInfo[0x06] & 0xFFL;
        long outInterfaces = metaInfo[0x07] & 0xFFL;

        if (bytesIn > 0x4000L || bytesOut > 0x4000L)
            return null;
        if (!isValidHeaderSize(inHeadersSize) || !isValidHeaderSize(outHeadersSize))
            return null;
        if (inInterfaces > 20 || outInterfaces > 20)
            return null;

        return new Metadata(bytesIn, bytesOut, 0, inInterfaces, outInterfaces, 0, 0, null, null);
    }

    private static BufferAttrsResult decodeCompactBufferAttrs(byte[] metaInfo, int base, long bufferCount)
    {
        int[] offsets = new int[] { base + 0x0A, base + 0x09, alignUp(base + 0x09, 4), base + 0x10 };

        for (int offset : offsets)
        {
            int[] attrs = readByteBufferAttrs(metaInfo, offset, bufferCount);
            if (attrs != null)
                return new BufferAttrsResult(attrs, String.format("legacy-compact/u8+0x%X", offset - base));
        }

        return null;
    }

    private static String describeCompactBufferAttrProbes(byte[] metaInfo, int base, long bufferCount)
    {
        int[] offsets = new int[] { base + 0x0A, base + 0x09, alignUp(base + 0x09, 4), base + 0x10 };
        StringBuilder out = new StringBuilder();

        for (int offset : offsets)
            appendProbe(out, String.format("u8+0x%X", offset - base), readRawByteAttrs(metaInfo, offset, bufferCount));

        return out.toString();
    }

    private static BufferAttrsResult decodeWideBufferAttrs(byte[] metaInfo, int base, long bufferCount)
    {
        int[] offsets = new int[] { base + 0x24, alignUp(base + 0x24, 8), base + 0x30 };

        for (int offset : offsets)
        {
            int[] attrs = readU32BufferAttrs(metaInfo, offset, bufferCount);
            if (attrs != null)
                return new BufferAttrsResult(attrs, String.format("legacy-wide/u32+0x%X", offset - base));
        }

        for (int offset : offsets)
        {
            int[] attrs = readByteBufferAttrs(metaInfo, offset, bufferCount);
            if (attrs != null)
                return new BufferAttrsResult(attrs, String.format("legacy-wide/u8+0x%X", offset - base));
        }

        return null;
    }

    private static String describeWideBufferAttrProbes(byte[] metaInfo, int base, long bufferCount)
    {
        int[] offsets = new int[] { base + 0x24, alignUp(base + 0x24, 8), base + 0x30 };
        StringBuilder out = new StringBuilder();

        for (int offset : offsets)
            appendProbe(out, String.format("u32+0x%X", offset - base), readRawU32Attrs(metaInfo, offset, bufferCount));

        for (int offset : offsets)
            appendProbe(out, String.format("u8+0x%X", offset - base), readRawByteAttrs(metaInfo, offset, bufferCount));

        return out.toString();
    }

    private static void appendProbe(StringBuilder out, String name, String value)
    {
        if (out.length() > 0)
            out.append("; ");

        out.append(name).append("=").append(value);
    }

    private static int[] readByteBufferAttrs(byte[] metaInfo, int offset, long bufferCount)
    {
        if (!isValidBufferAttrCount(bufferCount) || offset < 0 || offset + bufferCount > metaInfo.length)
            return null;

        int[] attrs = new int[(int)bufferCount];

        for (int i = 0; i < attrs.length; i++)
        {
            attrs[i] = metaInfo[offset + i] & 0xFF;

            if (!isValidBufferAttr(attrs[i]))
                return null;
        }

        return attrs;
    }

    private static String readRawByteAttrs(byte[] metaInfo, int offset, long bufferCount)
    {
        if (!isValidBufferAttrCount(bufferCount) || offset < 0 || offset + bufferCount > metaInfo.length)
            return "<range>";

        StringBuilder out = new StringBuilder("[");

        for (int i = 0; i < bufferCount; i++)
        {
            if (i > 0)
                out.append(",");

            out.append(metaInfo[offset + i] & 0xFF);
        }

        return out.append("]").toString();
    }

    private static int[] readU32BufferAttrs(byte[] metaInfo, int offset, long bufferCount)
    {
        if (!isValidBufferAttrCount(bufferCount) || offset < 0 || offset + bufferCount * 4 > metaInfo.length)
            return null;

        int[] attrs = new int[(int)bufferCount];

        for (int i = 0; i < attrs.length; i++)
        {
            long attr = readU32LE(metaInfo, offset + i * 4);

            if (!isValidBufferAttr(attr))
                return null;

            attrs[i] = (int)attr;
        }

        return attrs;
    }

    private static String readRawU32Attrs(byte[] metaInfo, int offset, long bufferCount)
    {
        if (!isValidBufferAttrCount(bufferCount) || offset < 0 || offset + bufferCount * 4 > metaInfo.length)
            return "<range>";

        StringBuilder out = new StringBuilder("[");

        for (int i = 0; i < bufferCount; i++)
        {
            if (i > 0)
                out.append(",");

            out.append(readU32LE(metaInfo, offset + i * 4));
        }

        return out.append("]").toString();
    }

    private static boolean isValidBufferAttrCount(long bufferCount)
    {
        return bufferCount > 0 && bufferCount <= MAX_BUFFER_ATTRS;
    }

    private static boolean isValidBufferAttr(long attr)
    {
        if (attr <= 0 || (attr & ~BUFFER_ATTR_VALID_MASK) != 0)
            return false;

        if ((attr & (BUFFER_ATTR_IN | BUFFER_ATTR_OUT)) == 0)
            return false;

        int transferModes = 0;

        if ((attr & BUFFER_ATTR_HIPC_MAP_ALIAS) != 0) transferModes++;
        if ((attr & BUFFER_ATTR_HIPC_POINTER) != 0) transferModes++;
        if ((attr & BUFFER_ATTR_HIPC_AUTO_SELECT) != 0) transferModes++;

        if (transferModes != 1)
            return false;

        return (attr & (BUFFER_ATTR_HIPC_MAP_TRANSFER_ALLOWS_NON_SECURE |
            BUFFER_ATTR_HIPC_MAP_TRANSFER_ALLOWS_NON_DEVICE)) !=
            (BUFFER_ATTR_HIPC_MAP_TRANSFER_ALLOWS_NON_SECURE |
                BUFFER_ATTR_HIPC_MAP_TRANSFER_ALLOWS_NON_DEVICE);
    }

    private static int alignUp(int value, int align)
    {
        return (value + align - 1) & -align;
    }

    private static class BufferAttrsResult
    {
        private final int[] attrs;
        private final String source;

        private BufferAttrsResult(int[] attrs, String source)
        {
            this.attrs = attrs;
            this.source = source;
        }
    }

    private static boolean isValidLegacyMetadata(long rawBytesIn, long rawBytesOut, long bufferCount,
                                                 long inInterfaces, long outInterfaces,
                                                 long inHandles, long outHandles)
    {
        if (rawBytesIn  < 0x10 || rawBytesIn  > 0x4010L) return false;
        if (rawBytesOut < 0x10 || rawBytesOut > 0x4010L) return false;
        if (bufferCount  > 20) return false;
        if (inInterfaces > 20) return false;
        if (outInterfaces> 20) return false;
        if (inHandles    > 20) return false;
        return outHandles <= 20;
    }

    private static boolean isValidHeaderSize(long size)
    {
        return size == 0 || size == 0x10 || size == 0x20 || size == 0x30;
    }

    private static boolean looksLikeRuntimeMetadata(byte[] metaInfo)
    {
        return isValidHeaderSize(metaInfo[0x04] & 0xFFL) &&
            isValidHeaderSize(metaInfo[0x05] & 0xFFL) &&
            ((metaInfo[0x04] & 0xFFL) >= 0x10 || (metaInfo[0x05] & 0xFFL) >= 0x10);
    }

    private static class Metadata
    {
        private final long bytesIn;
        private final long bytesOut;
        private final long bufferCount;
        private final int[] bufferAttrs;
        private final String bufferAttrsSource;
        private final String bufferAttrsProbe;
        private final long inInterfaces;
        private final long outInterfaces;
        private final long inHandles;
        private final long outHandles;

        private Metadata(long bytesIn, long bytesOut, long bufferCount, long inInterfaces,
                         long outInterfaces, long inHandles, long outHandles,
                         BufferAttrsResult bufferAttrs, String bufferAttrsProbe)
        {
            this.bytesIn = bytesIn;
            this.bytesOut = bytesOut;
            this.bufferCount = bufferCount;
            this.bufferAttrs = bufferAttrs != null ? bufferAttrs.attrs : null;
            this.bufferAttrsSource = bufferAttrs != null ? bufferAttrs.source : null;
            this.bufferAttrsProbe = bufferAttrsProbe;
            this.inInterfaces = inInterfaces;
            this.outInterfaces = outInterfaces;
            this.inHandles = inHandles;
            this.outHandles = outHandles;
        }
    }

    private static long readU16LE(byte[] buf, int off)
    {
        return ((buf[off] & 0xFFL)) | ((buf[off + 1] & 0xFFL) << 8);
    }

    private static long readU32LE(byte[] buf, int off)
    {
        return ((buf[off]     & 0xFFL))
            | ((buf[off + 1] & 0xFFL) << 8)
            | ((buf[off + 2] & 0xFFL) << 16)
            | ((buf[off + 3] & 0xFFL) << 24);
    }

    private static String bytesToHex(byte[] bytes, int len)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(len, bytes.length); i++)
            sb.append(String.format("%02X ", bytes[i]));
        return sb.toString().trim();
    }
    
    private boolean OverwriteClientProcessId()
    {
        long out = this.state.getValue("x1");
        this.setLong(out, 0);
        this.returnFromFunc(0);
        return true;
    }

    private boolean GetBuffers()
    {
        long out = this.state.getValue("x1");
        long bufferCount = Math.max(this.currentTrace.bufferCount, 0);
        
        for (long i = out; i < out + bufferCount * 0x10; i += 0x10)
        {
            this.setLong(i, this.bufferMemory);
            this.setLong(i + 0x8, this.bufferSize);
        }
        
        this.returnFromFunc(0);
        return true;
    }
    
    private boolean GetInNativeHandles()
    {
        long out = this.state.getValue("x1");
        long handleCount = Math.max(this.currentTrace.inHandles, 0);

        for (long i = 0; i < handleCount; i++)
            this.setInt(out + i * 0x4, 0xCAFE0000L + i);

        this.returnFromFunc(0);
        return true;
    }
    
    private boolean GetInObjects()
    {
        long out = this.state.getValue("x1");
        
        // Set up input object pointers for all in interfaces
        // If there are 0 interfaces, we don't set anything
        // If there are 1+ interfaces, fill them with the mock object
        if (this.currentTrace.inInterfaces > 0)
        {
            for (long i = 0; i < this.currentTrace.inInterfaces; i++)
            {
                this.setLong(out + i * 0x8, this.inObjectPtr);
            }
        }
        
        this.returnFromFunc(0);
        return true;
    }
    
    private boolean BeginPreparingForReply()
    {
        long off = this.state.getValue("x1");
        this.setLong(off, this.outputMemory);
        this.setLong(off + 0x8, 0x1000);
        this.returnFromFunc(0);
        return true;
    }
    
    private boolean SetBuffers()
    {
        this.returnFromFunc(0);
        return true;
    }
    
    private boolean SetOutObjects()
    {
        this.returnFromFunc(0);
        return true;
    }
    
    private boolean SetOutNativeHandles()
    {
        this.returnFromFunc(0);
        return true;
    }
    
    private boolean BeginPreparingForErrorReply()
    {
        long off = this.state.getValue("x1");
        this.setLong(off, this.outputMemory);
        this.setLong(off + 0x8, 0x1000);
        this.returnFromFunc(0);
        return true;
    }
    
    private boolean EndPreparingForReply()
    {
        this.returnFromFunc(0);
        return true;
    }
}
