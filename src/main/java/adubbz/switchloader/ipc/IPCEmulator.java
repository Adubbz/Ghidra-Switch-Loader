/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.switchloader.ipc;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import org.apache.commons.compress.utils.Lists;
import org.python.google.common.collect.Maps;

import adubbz.switchloader.util.ByteUtil;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.emulate.BreakTable;
import ghidra.pcode.emulate.BreakTableCallBack;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.memstate.MemoryBank;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.pcode.memstate.MemoryPageBank;
import ghidra.pcode.memstate.MemoryState;
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
import ghidra.util.task.TaskMonitorAdapter;

public class IPCEmulator 
{
    private Program program;
    private IPCAnalyzer analyzer;
    
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
    
    public IPCEmulator(Program program, IPCAnalyzer analyzer) throws MemoryAccessException
    {
        this.program = program;
        this.analyzer = analyzer;
        
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
        this.state = new MemoryState(this.sLang);
        
        // Create banks for ram and registers and add them to our state
        this.ramBank = new MemoryPageBank(this.sLang.getAddressFactory().getDefaultAddressSpace(), false, 4096, faultHandler);
        this.registerBank = new MemoryPageBank(this.sLang.getAddressFactory().getRegisterSpace(), false, 4096, faultHandler);
        this.state.setMemoryBank(this.ramBank);
        this.state.setMemoryBank(this.registerBank);
        
        this.bTable = new BreakTableCallBack(this.sLang);
        this.emu = new Emulate(this.sLang, this.state, this.bTable);
        this.disassembler = Disassembler.getDisassembler(this.program, TaskMonitorAdapter.DUMMY_MONITOR, null);
        
        // Copy over our binary to the emulator's memory, typically 7100000000
        Memory programMemory = this.program.getMemory();
        byte[] programBytes = new byte[(int)programMemory.getMaxAddress().getOffset()];
        
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
        // Some commands have in-dispatcher validation. If we fail this
        // validation we miss some information about vtable offsets and
        // returned objects. This tries to brute-force until we find an
        // input that passes that validation.

        int[] bufferSizes = new int[] { 128, 33, 1 };
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
        // We allocate a fixed 0x1000 for the buffer. Therefore we only allow adjustments to less than or equal
        // to that.
        if (bufferSize < 0 || bufferSize > 0x1000)
            throw new RuntimeException("Invalid buffer size provided");
        
        this.bufferSize = bufferSize;
        
        this.instructionHandlers.clear(); // Clear any existing instruction handlers
        this.currentTrace = new IPCTrace(cmd, procFuncAddr.getOffset());
        
        // Clear out any existing IPC message data
        byte[] zeros = new byte[(int)this.messageSize];
        this.state.setChunk(zeros, this.sLang.getDefaultSpace(), this.messagePtr, zeros.length);
        
        this.setLong(messagePtr, 0x49434653); // IPC Magic
        this.setLong(messagePtr + 0x8, cmd); // Cmd ID
        
        if (data != null && data.length > 0)
            this.state.setChunk(data, this.sLang.getDefaultSpace(), this.messagePtr + 0x10, data.length);
        
        // Set registers to point to our objects.
        // We need to do this each time to reset the state
        this.state.setValue("x0", this.targetObjectPtr);
        this.state.setValue("x1", this.ipcObjectPtr);
        this.state.setValue("x2", this.messageStructPtr);
        
        // Set to the start of the process function
        emu.setExecuteAddress(procFuncAddr);
        
        // Disassemble the proc function so we can get instructions from it
        disassembler.disassemble(procFuncAddr, null);
        
        while (true)
        {
            long pc = state.getValue("pc");
            Address pcAddr = this.sLang.getDefaultSpace().getAddress(pc);
            
            // Pre-process instructions
            for (Consumer<Long> instructionHandler : this.instructionHandlers)
            {
                instructionHandler.accept(pc);
            }
            
            if (emu.getExecuteAddress().getOffset() == 0)
            {
                break;
            }
                
            emu.executeInstruction(true);
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
        
        BinaryReader reader = new BinaryReader(new ByteArrayProvider(metaInfo), true);
        
        try
        {
            this.currentTrace.bytesIn = reader.readInt(0x8) - 0x10;
            this.currentTrace.bytesOut = reader.readInt(0x10) - 0x10;
            this.currentTrace.bufferCount = reader.readInt(0x18);
            this.currentTrace.inInterfaces = reader.readInt(0x1C);
            this.currentTrace.outInterfaces = reader.readInt(0x20);
            this.currentTrace.inHandles = reader.readInt(0x24);
            this.currentTrace.outHandles = reader.readInt(0x28);
            
            if (this.currentTrace.bytesIn < 0 || this.currentTrace.bytesIn > 0x1000L)
                throw new RuntimeException("Invalid value for bytesIn!");
            
            if (this.currentTrace.bytesOut < 0 || this.currentTrace.bytesOut > 0x1000L)
                throw new RuntimeException("Invalid value for bytesOut!");
            
            if (this.currentTrace.bufferCount > 20)
                throw new RuntimeException("Too many buffers!");
            
            if (this.currentTrace.inInterfaces > 20)
                throw new RuntimeException("Too many in interfaces!");
            
            if (this.currentTrace.outInterfaces > 20)
                throw new RuntimeException("Too many out interfaces!");
            
            if (this.currentTrace.inHandles > 20)
                throw new RuntimeException("Too many in handles!");
            
            if (this.currentTrace.outHandles > 20)
                throw new RuntimeException("Too many out handles!");
            
            this.currentTrace.lr = this.state.getValue("x30");
            
            if (this.currentTrace.inInterfaces > 0)
            {
                // Add a handler to cheat the cmp x8, x9 that usually happens
                this.instructionHandlers.add((off) -> 
                {
                    Address pcAddr = this.sLang.getDefaultSpace().getAddress(off);
                    CodeManager codeManager = ((ProgramDB)this.program).getCodeManager();
                    Instruction currentInstruction = codeManager.getInstructionAt(pcAddr);
                    
                    // Attempt to disassemble the instruction so we can try again
                    if (currentInstruction == null)
                    {
                        disassembler.disassemble(pcAddr, null);
                        currentInstruction = codeManager.getInstructionAt(pcAddr);
                    }
                    
                    if (currentInstruction != null)
                    {
                        InstructionPrototype prototype = currentInstruction.getPrototype();
                        String mnemonic = prototype.getMnemonic(currentInstruction.getInstructionContext());
                        
                        if (mnemonic.equals("cmp") && currentInstruction.getOperandType(0) == OperandType.REGISTER && currentInstruction.getOperandType(1) == OperandType.REGISTER)
                        {
                            Register r0 = currentInstruction.getRegister(0);
                            Register r1 = currentInstruction.getRegister(1);
                            
                            // Cheat time!
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
        }
        catch (Exception e)
        {
            return false;
        }
        
        this.returnFromFunc(0);
        return true;
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
        
        for (long i = out; i < out + this.currentTrace.bufferCount * 0x10; i += 0x10)
        {
            this.setLong(i, this.bufferMemory);
            this.setLong(i + 0x8, this.bufferSize);
        }
        
        this.returnFromFunc(0);
        return true;
    }
    
    private boolean GetInNativeHandles()
    {
        this.returnFromFunc(0);
        return true;
    }
    
    private boolean GetInObjects()
    {
        long out = this.state.getValue("x1");
        
        if (this.currentTrace.inInterfaces != 1)
            throw new RuntimeException("Invalid number of in interfaces!");
            
        this.setLong(out, this.inObjectPtr);
        
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
        // Stubbed
        return false;
    }
    
    private boolean SetOutNativeHandles()
    {
        this.returnFromFunc(0);
        return true;
    }
    
    private boolean BeginPreparingForErrorReply()
    {
        // Stubbed
        return false;
    }
    
    private boolean EndPreparingForReply()
    {
        // Stubbed
        this.returnFromFunc(0);
        return false;
    }
}
