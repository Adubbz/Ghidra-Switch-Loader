/**
 * Copyright 2019 Adubbz
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
package adubbz.nx.analyzer.ipc;

import adubbz.nx.util.ByteUtil;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeEmulationCallbacks;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary.OpOutput;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary.PcodeUserop;
import ghidra.pcode.exec.PcodeExecutionException;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.utils.Utils;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.CodeManager;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitorAdapter;
import org.apache.commons.compress.utils.Lists;

import java.lang.invoke.MethodHandles;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.List;
import java.util.Locale;
import java.util.StringJoiner;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
    private static final long STACK_START = 0x100000000L;
    private static final long STACK_SIZE = 0x2000L;
    private static final long STACK_GUARD_SIZE = 0x1000L;
    private static final long LOW_NULL_PAGE_SIZE = 0x1000L;
    private static final long LOW_SPECULATIVE_ZERO_SIZE = 0x1000000L;
    private static final long HEAP_SPECULATIVE_ZERO_SIZE = 0x400000L;
    private static final long SYNTHETIC_FUNC_PTR_SIZE = 0x100000L;
    private static final long TLS_SIZE = 0x1000L;
    private static final long CLIENT_EXTERNAL_ALLOC_MAX = 0x4000L;
    private static final Pattern AARCH64_MEMORY_OFFSET_PATTERN =
        Pattern.compile("\\[\\s*([xw]\\d+|sp)\\s*(?:,\\s*#?(-?0x[0-9A-Fa-f]+|-?\\d+))?", Pattern.CASE_INSENSITIVE);

    private Program program;
    public boolean hasSetup;

    // --- Emulation state (PcodeEmulator replaces MemoryState/MemoryBank/BreakTableCallBack/Emulate) ---
    private SleighLanguage sLang;
    private PcodeEmulator emulator;
    private PcodeThread<byte[]> emuThread;

    /**
     * Function-pointer table: maps a synthetic address to an HLE handler.
     * Replaces the anonymous BreakCallBack objects registered via BreakTableCallBack.
     * When the emulation PC lands on one of these addresses we invoke the handler
     * directly from the execution loop instead of relying on a callback mechanism.
     */
    private final Map<Long, Supplier<Boolean>> hleHandlers = new HashMap<>();

    private Disassembler disassembler;

    private List<Consumer<Long>> instructionHandlers = Lists.newArrayList();

    private long messageSize;
    private long messagePtr;

    /**
     * Thread-local storage block (pointed to by {@code tpidrro_el0}).  This is the canonical
     * location an nnsdk CMIF client writes its request into, so the client request scan checks
     * it for the SFCI/TFCI signature.  Zeroed at the start of each client run to avoid stale
     * data leaking between stubs that reuse the same emulator instance.
     */
    private long tlsPtr;

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
    private int prepareForProcessHits;
    private long lastPrepareForProcessVtOffset = -1;
    private Set<Long> reportedRegisterOffsets = new HashSet<>();
    private int uninitializedLocalReadsThisRun;
    private String firstUninitializedLocalReadThisRun;

    /**
     * Literal immediate values ({@code mov}/{@code movz}) loaded into registers during the
     * current client-stub run, in execution order.  A CMIF command id is emitted into the
     * dispatch as a constant, so at a send/helper boundary it appears both here and in an
     * argument slot; this list lets {@link #recoverClientCommandIdFromDispatch} distinguish
     * the command-id constant from computed pointers and memory-loaded values.
     */
    private final List<Long> clientImmediateLoadOrder = Lists.newArrayList();

    /** Approach 2: how many times the current run redirected an indirect dispatch into the real
     *  transport (capped to avoid runaway), and a global cap on dispatch-resolution diagnostics. */
    private static final int MAX_CLIENT_DISPATCH_REDIRECTS = 6;
    private static final int CLIENT_DISPATCH_DIAG_LIMIT = 40;
    private int clientRedirectsThisRun;
    private int clientDispatchDiagLogged;

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

    // -------------------------------------------------------------------------
    // Setup
    // -------------------------------------------------------------------------

    public void setup() throws MemoryAccessException
    {
        this.sLang = (SleighLanguage) this.program.getLanguage();

        // PcodeEmulator is the modern replacement for the Emulate/MemoryState stack.
        // It owns the concrete BytesPcodeExecutorState internally; we access it
        // through the thread's getState() when we need raw memory I/O.
        //
        // The readUninitialized callback lets us distinguish uninitialised local
        // (unique/unnamed register) state — which is harmless — from genuinely
        // unmapped address ranges, and lets us zero-initialise our synthetic
        // memory regions (stack, heap, func-ptr range) on first access rather
        // than having the framework treat them as errors.
        PcodeEmulationCallbacks<byte[]> callbacks = new PcodeEmulationCallbacks<byte[]>()
        {
            @Override
            public <A, U> AddressSetView readUninitialized(PcodeThread<byte[]> thread,
                    PcodeExecutorStatePiece<A, U> piece, AddressSetView set, Reason reason)
            {
                return IPCEmulator.this.handleReadUninitialized(thread, set, reason);
            }
        };

        this.emulator = new PcodeEmulator(this.sLang, callbacks)
        {
            @Override
            protected PcodeUseropLibrary<byte[]> createUseropLibrary()
            {
                // Compose in order: base library, then our Switch-specific stubs,
                // then the functional-override library (ExclusiveMonitorPass, etc.).
                // The last library wins for any name collision, so the override
                // library must come last.
                return super.createUseropLibrary()
                    .compose(new SwitchPcodeUseropLibrary())
                    .compose(new SwitchPcodeOverrideUseropLibrary());
            }
        };
        this.emuThread = this.emulator.newThread();

        this.disassembler = Disassembler.getDisassembler(this.program, TaskMonitorAdapter.DUMMY, null);

        // Mirror the process image into the emulator's flat state. Initialized blocks get their
        // program bytes; uninitialized blocks model loader-zeroed memory such as .bss.
        // Ghidra returns zero for uninitialized low/null-page reads, but logs each read. Seed it
        // once so null-ish speculative paths do not flood analysis logs.
        zeroStateRange(0, LOW_NULL_PAGE_SIZE);

        Memory programMemory = this.program.getMemory();
        for (MemoryBlock block : programMemory.getBlocks())
        {
            if (block.isInitialized())
            {
                byte[] blockBytes = new byte[(int) block.getSize()];
                int copiedBytes = programMemory.getBytes(block.getStart(), blockBytes);

                if (copiedBytes != blockBytes.length)
                    throw new RuntimeException(String.format(
                        "Failed to copy bytes from 0x%X of size 0x%x!",
                        block.getStart().getOffset(), block.getSize()));

                stateSetChunk(blockBytes, block.getStart().getOffset(), blockBytes.length);
            }
            else
            {
                zeroStateRange(block.getStart().getOffset(), block.getSize());
            }
        }

        // Initialize GPRs to zero
        for (int i = 0; i <= 30; i++)
            setRegister("x" + i, 0);

        // Initialize SIMD/system context commonly touched by compiler/runtime prologues.
        for (int i = 0; i <= 31; i++)
            setRegisterBytesIfExists("q" + i, 16);
        zeroRegisterStateRange(0x100, 0x300);
        for (String flag : new String[] { "NG", "ZR", "CY", "OV", "shift_carry", "tmpCY", "tmpOV", "tmpNG", "tmpZR" })
            setRegisterIfExists(flag, 0);
        setRegisterIfExists("NZCV", 0);
        setRegisterIfExists("fpcr", 0);
        setRegisterIfExists("fpsr", 0);
        setRegisterIfExists("cntpct_el0", 0);
        setRegisterIfExists("cntvct_el0", 0);
        setRegisterIfExists("cntfrq_el0", 0);

        // Stack: 0x100000000-0x100002000
        zeroStateRange(STACK_START, STACK_SIZE + STACK_GUARD_SIZE);
        setRegister("sp", STACK_START + STACK_SIZE);

        // Switch code frequently reads TLS via tpidrro_el0. Model it as a zeroed TLS block.
        this.tlsPtr = this.calloc(TLS_SIZE);
        setRegisterIfExists("tpidrro_el0", this.tlsPtr);

        // Allocate IPC message data
        this.messageSize   = 0x1010;
        this.messagePtr    = this.calloc(messageSize);
        this.messageStructPtr = this.calloc(0x10);
        this.setLong(messageStructPtr,       messagePtr);   // message ptr
        this.setLong(messageStructPtr + 0x8, messageSize);  // message length

        // Build IPC vtable / object
        long ipcVtableSize = 0x8 * 11;
        long ipcVtablePtr  = this.calloc(ipcVtableSize);
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

        // Build target-function vtable: 512 unique pointers each recording their vtable offset
        long targetFuncVtableSize = 0x8 * 512;
        long targetFuncVtablePtr  = this.calloc(targetFuncVtableSize);

        for (long off = 0; off < targetFuncVtableSize; off += 8)
        {
            final long off2 = off;
            long targetFuncPtr = this.createFunctionPointer(() -> this.targetFunction(off2));
            this.setLong(targetFuncVtablePtr + off, targetFuncPtr);
        }

        this.targetObjectPtr = this.calloc(0x10);
        this.setLong(this.targetObjectPtr, targetFuncVtablePtr);

        // A real ARM64 RET instruction for the in-object stub vtable
        this.retInstructionPtr = this.calloc(0x4);
        this.setInt(this.retInstructionPtr, 0xd65f03c0);
        this.inObjectVtablePtr = this.calloc(0x8 * 16);

        for (int i = 0; i < 16; i++)
            this.setLong(this.inObjectVtablePtr + i * 0x8, this.retInstructionPtr);

        this.inObjectPtr = this.calloc(0x8 + 8 * 16);
        this.setLong(this.inObjectPtr, this.inObjectVtablePtr);

        this.bufferSize   = 0x1000;
        this.bufferMemory = this.calloc(this.bufferSize);
        this.outputMemory = this.calloc(0x1000);
    }

    // -------------------------------------------------------------------------
    // Emulation entry points
    // -------------------------------------------------------------------------

    public IPCTrace emulateCommand(Address procFuncAddr, int cmd)
    {
        if (!this.hasSetup)
            return null;

        int[] bufferSizes = new int[] { 0x300, 128, 33, 1 };
        // Cover even the largest inline inputs (e.g. IContentsServiceManager cmd 1 takes 0x60 bytes); a
        // too-small non-zero buffer leaves the tail of the input zero and can trip a precondition.
        ByteBuffer nonZeroBuf = ByteBuffer.allocate(0x8 * 0x20);
        for (int i = 0; i < 0x20; i++) nonZeroBuf.putLong(1);

        // Try several input primings. A timeout only short-circuits when NO metadata was captured (not
        // a real command): if PrepareForProcess already ran (hasDescription), the command IS real and a
        // zero/garbage input merely wandered into a precondition branch (e.g. `cbz Uid`) before reaching
        // the target-impl call that yields vtOffset -- so keep trying the non-zero primings.
        int attempts = 1;
        IPCTrace trace = this.withValidationAttempt(
            this.emulateCommand(procFuncAddr, cmd, null, 0x1000),
            attempts, "default");
        if (trace.isCorrect()) return trace;
        if (trace.timedOut && !trace.hasDescription()) return trace;

        trace = this.withValidationAttempt(
            this.emulateCommand(procFuncAddr, cmd, nonZeroBuf.array(), 0x1000),
            ++attempts, "nonzero6");
        if (trace.isCorrect()) return trace;
        if (trace.timedOut && !trace.hasDescription()) return trace;

        for (int bufSize : bufferSizes)
        {
            trace = this.withValidationAttempt(
                this.emulateCommand(procFuncAddr, cmd, null, bufSize),
                ++attempts, String.format("buf=0x%X", bufSize));
            if (trace.isCorrect()) return trace;
            if (trace.timedOut && !trace.hasDescription()) return trace;
        }

        nonZeroBuf = ByteBuffer.allocate(0x8 * 0x20);
        for (int i = 0; i < 0x20; i++) nonZeroBuf.putLong(4);

        for (int bufSize : bufferSizes)
        {
            trace = this.withValidationAttempt(
                this.emulateCommand(procFuncAddr, cmd, nonZeroBuf.array(), bufSize),
                ++attempts, String.format("nonzero4+buf=0x%X", bufSize));
            if (trace.isCorrect()) return trace;
            if (trace.timedOut && !trace.hasDescription()) return trace;
        }

        // A real command (metadata captured at PrepareForProcess) whose handler bailed on an input/Uid
        // precondition before the impl call never set vtOffset, so the pipeline would discard it.
        // Recover vtOffset statically from the handler so the (correct) captured metadata is kept.
        if (trace != null && trace.hasDescription() && trace.vtOffset == -1)
        {
            long vt = this.recoverImplVtOffset(trace.lr);
            if (vt != -1)
            {
                trace.vtOffset = vt;
                trace.validationProfile = (trace.validationProfile == null ? "" : trace.validationProfile + "+")
                    + "static-vt";
                return trace;
            }
        }

        Msg.debug(this, String.format(
            "Unable to brute-force validation on dispatch_func %X command %d",
            procFuncAddr.getOffset(), cmd));
        return trace;
    }

    private IPCTrace withValidationAttempt(IPCTrace trace, int attempts, String profile)
    {
        if (trace != null)
        {
            trace.validationAttempts = attempts;
            trace.validationProfile = profile;
        }

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
        this.currentTrace = new IPCTrace((long) cmd, procFuncAddr.getOffset());
        this.uninitializedLocalReadsThisRun = 0;
        this.firstUninitializedLocalReadThisRun = null;
        this.prepareForProcessHits = 0;
        this.lastPrepareForProcessVtOffset = -1;
        this.reportedRegisterOffsets.clear();

        // Zero the message buffer then write the SFCI header and command id
        byte[] zeros = new byte[(int) this.messageSize];
        stateSetChunk(zeros, this.messagePtr, zeros.length);

        this.setLong(messagePtr,       0x49434653);
        this.setLong(messagePtr + 0x8, cmd);

        if (data != null && data.length > 0)
            stateSetChunk(data, this.messagePtr + 0x10, data.length);

        // Set up the initial register context
        setRegister("x0", this.targetObjectPtr);
        setRegister("x1", this.ipcObjectPtr);
        setRegister("x2", this.messageStructPtr);

        // Point the thread at the entry address
        emuThread.overrideCounter(procFuncAddr);
        // Disassemble only the entry instruction (doFollowFlow=false). The emulator decodes
        // from its own state via stepInstruction(), so flow-following here would needlessly
        // disassemble and mutate the program listing across the binary.
        disassembler.disassemble(procFuncAddr, null, false);

        // These limits ONLY bound dead-end (timeout) runs: a valid command always exits earlier via
        // hasCompleteTraceForDiscovery(). Measured across a full run, the largest valid command is
        // 1020 complete instructions (982 core), so 12_000 keeps a ~12x safety margin while cutting
        // the per-timeout cost ~8x (each meta dead end used to grind to 100k instructions, ~4.7s, and
        // proc_funcs that find >=1 command try all candidates -- so trailing dead ends dominated time).
        final int MAX_INSTRUCTIONS_WITH_META = 12_000;
        final int MAX_INSTRUCTIONS_NO_META   = 5_000;
        final int MAX_NO_META_PC_HITS        = 256;
        final int MAX_META_NO_VT_PC_HITS     = 1024;
        final int MAX_INSTRUCTIONS_AFTER_CORE_TRACE = 2_000;
        // Progress cap (the real cost lever): the expensive dead ends have metadata but spin forever
        // without ever resolving a vtOffset, hitting the per-PC limit only after ~10k instructions.
        // A VALID command always resolves its vtOffset and completes within <=1020 instructions
        // (measured max across a full run), so if vtOffset is still unresolved after a 2.5x-margin
        // budget the candidate can never be valid -- bail immediately. Zero recall cost.
        final int MAX_INSTRUCTIONS_META_NO_VT = 2_500;
        int instructionCount = 0;
        Map<Long, Integer> noMetaPcHits = new HashMap<>();
        Map<Long, Integer> metaNoVtPcHits = new HashMap<>();
        int coreTraceInstruction = -1;

        while (true)
        {
            boolean hasMeta = this.currentTrace.bytesIn != -1;
            int limit = hasMeta ? MAX_INSTRUCTIONS_WITH_META : MAX_INSTRUCTIONS_NO_META;
            long pc = getRegisterLong("pc");

            for (Consumer<Long> handler : this.instructionHandlers)
                handler.accept(pc);

            // A PC of zero signals that an HLE handler has requested a halt
            if (pc == 0)
            {
                this.currentTrace.cleanReturn = true;
                break;
            }

            if (this.hasCoreTraceForDiscovery())
            {
                if (coreTraceInstruction == -1)
                {
                    coreTraceInstruction = instructionCount;
                    this.currentTrace.coreTraceInstructionCount = instructionCount;
                }
            }

            if (this.hasCompleteTraceForDiscovery())
            {
                this.currentTrace.completeTraceInstructionCount = instructionCount;
                break;
            }

            if (coreTraceInstruction != -1)
            {
                if (this.currentTrace.completeTraceInstructionCount == -1 &&
                        this.currentTrace.outInterfaces <= 0)
                    this.currentTrace.completeTraceInstructionCount = coreTraceInstruction;

                if (instructionCount - coreTraceInstruction > MAX_INSTRUCTIONS_AFTER_CORE_TRACE)
                    break;
            }

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
            else if (this.currentTrace.vtOffset == -1)
            {
                int pcHits = metaNoVtPcHits.getOrDefault(pc, 0) + 1;
                metaNoVtPcHits.put(pc, pcHits);
                if (pcHits > MAX_META_NO_VT_PC_HITS || instructionCount > MAX_INSTRUCTIONS_META_NO_VT)
                {
                    this.currentTrace.timedOut = true;
                    break;
                }
            }

            if (++instructionCount > limit)
            {
                this.currentTrace.timedOut = true;
                if (hasMeta)
                    Msg.warn(this, String.format(
                        "Emulation exceeded %d instructions for proc_func 0x%X cmd %d, aborting",
                        limit, procFuncAddr.getOffset(), cmd));
                break;
            }

            // Check whether PC has landed on a synthetic HLE function pointer
            Supplier<Boolean> hle = this.hleHandlers.get(pc);
            if (hle != null)
            {
                if (!hle.get())
                {
                    // HLE returned false: halt, mirroring the original BreakCallBack behavior.
                    setRegister("pc", 0);
                }
                // Either way, do not fall through to native execution for this address
                continue;
            }

            try
            {
                // PcodeThread.stepInstruction() is the direct replacement for
                // Emulate.executeInstruction(true, monitor).
                emuThread.stepInstruction();
            }
            catch (PcodeExecutionException | LowlevelError e)
            {
                Msg.warn(this, String.format("Stopping IPC emulation at 0x%X: %s", pc, e.getMessage()));
                break;
            }
        }

        this.currentTrace.instructionsExecuted = instructionCount;
        this.currentTrace.uninitializedLocalReads = this.uninitializedLocalReadsThisRun;
        this.currentTrace.firstUninitializedLocalRead = this.firstUninitializedLocalReadThisRun;
        return this.currentTrace;
    }


    private AddressSetView handleReadUninitialized(PcodeThread<byte[]> thread, AddressSetView set, Reason reason)
    {
        if (reason == Reason.EXECUTE_READ && thread != null && isThreadLocalVolatileState(set))
        {
            this.uninitializedLocalReadsThisRun++;
            if (this.firstUninitializedLocalReadThisRun == null)
                this.firstUninitializedLocalReadThisRun = set.toString();
            return new AddressSet();
        }

        if (this.zeroSyntheticUninitializedState(set))
            return new AddressSet();

        return set;
    }

    private boolean zeroSyntheticUninitializedState(AddressSetView set)
    {
        if (set.isEmpty())
            return false;

        for (AddressRange range : set)
        {
            if (!this.isSyntheticStateRange(range))
                return false;
        }

        for (AddressRange range : set)
            this.zeroStateRange(range.getMinAddress().getOffset(), range.getLength());

        return true;
    }

    private boolean isSyntheticStateRange(AddressRange range)
    {
        AddressSpace space = range.getMinAddress().getAddressSpace();

        if (!space.equals(this.sLang.getAddressFactory().getDefaultAddressSpace()))
            return false;

        long start = range.getMinAddress().getOffset();
        long endExclusive = start + range.getLength();

        if (start < 0)
            return true;

        return isWithinRange(start, endExclusive, 0, LOW_SPECULATIVE_ZERO_SIZE)
            || isWithinRange(start, endExclusive, STACK_START,
                STACK_START + STACK_SIZE + STACK_GUARD_SIZE)
            || isWithinRange(start, endExclusive, HEAP_START, HEAP_START + HEAP_SIZE)
            || isWithinRange(start, endExclusive, HEAP_START,
                HEAP_START + HEAP_SPECULATIVE_ZERO_SIZE)
            || isWithinRange(start, endExclusive,
                this.program.getImageBase().getOffset() + HEAP_START,
                this.program.getImageBase().getOffset() + HEAP_START + HEAP_SPECULATIVE_ZERO_SIZE)
            || isWithinRange(start, endExclusive, FUNC_PTR_START,
                FUNC_PTR_START + SYNTHETIC_FUNC_PTR_SIZE);
    }

    private boolean isWithinRange(long start, long endExclusive, long rangeStart, long rangeEndExclusive)
    {
        return start >= rangeStart && endExclusive <= rangeEndExclusive;
    }

    private boolean isThreadLocalVolatileState(AddressSetView set)
    {
        if (set.isEmpty())
            return false;

        AddressSpace space = set.getMinAddress().getAddressSpace();
        if (space.isUniqueSpace())
            return true;

        return space.isRegisterSpace() && isUnnamedRegisterState(set);
    }

    private boolean isUnnamedRegisterState(AddressSetView set)
    {
        for (AddressRange range : set)
        {
            int length = (int) range.getLength();
            if (sLang.getRegister(range.getMinAddress(), length) != null)
                return false;

            if (sLang.getRegisters(range.getMinAddress()).length != 0)
                return false;
        }

        return true;
    }

    private boolean hasCoreTraceForDiscovery()
    {
        return this.currentTrace.hasDescription() && this.currentTrace.vtOffset != -1;
    }

    private boolean hasCompleteTraceForDiscovery()
    {
        if (!this.hasCoreTraceForDiscovery())
            return false;

        if (this.currentTrace.outInterfaces <= 0)
            return true;

        return this.currentTrace.outInterfaceTargets != null &&
            this.currentTrace.outInterfaceTargets.length > 0 &&
            this.currentTrace.hasOutInterfaceTarget(0);
    }

    // -------------------------------------------------------------------------
    // Heap / function-pointer allocator
    // -------------------------------------------------------------------------

    private static final long HEAP_START  = 0x200000000L;
    private static final long HEAP_SIZE   = 0x100000L;
    private long nextHeapPtr = HEAP_START;

    /**
     * Synthetic function-pointer range.
     * These addresses are never mapped as real instructions; the emulation loop
     * intercepts them via {@link #hleHandlers} before PcodeThread gets a chance
     * to fetch/decode them, so there is no need to write actual code bytes here.
     */
    private static final long FUNC_PTR_START = 0x400000000L;
    private long nextFuncPtr = FUNC_PTR_START;

    private long allocate(long size)
    {
        long available      = (HEAP_START + HEAP_SIZE) - nextHeapPtr;
        long allocationSize = alignHeapAllocation(size);

        if (allocationSize > available)
            throw new RuntimeException(String.format("Could not allocate 0x%X bytes", allocationSize));

        long start = nextHeapPtr;
        nextHeapPtr += allocationSize;
        return start;
    }

    private long calloc(long size)
    {
        long start = allocate(size);
        long allocationSize = alignHeapAllocation(size);
        stateSetChunk(new byte[(int) allocationSize], start, (int) allocationSize);
        return start;
    }

    private static long alignHeapAllocation(long size)
    {
        return (size + 0xF) & ~0xF;
    }

    /**
     * Register an HLE handler and return a synthetic address that acts as its
     * "function pointer".  The emulation loop checks {@link #hleHandlers} every
     * iteration before calling {@code emuThread.stepInstruction()}, so landing
     * on one of these addresses triggers the handler instead of native decode.
     *
     * This replaces the anonymous {@code BreakCallBack} + {@code BreakTableCallBack}
     * pattern from the original code.
     */
    private long createFunctionPointer(Supplier<Boolean> func)
    {
        long start = nextFuncPtr;
        nextFuncPtr += 0x8;
        hleHandlers.put(start, func);
        return start;
    }

    // -------------------------------------------------------------------------
    // Low-level state accessors
    // (PcodeThread exposes registers via writeVar/readVar on named registers;
    //  raw memory goes through the shared BytesPcodeExecutorState.)
    // -------------------------------------------------------------------------

    /** Write a 64-bit value to a named register. */
    private void setRegister(String name, long value)
    {
        Register reg = sLang.getRegister(name);
        if (reg == null)
            throw new IllegalArgumentException("Unknown register: " + name);
        setRegisterBytes(reg, Utils.longToBytes(value, reg.getMinimumByteSize(), sLang.isBigEndian()));
    }

    private boolean setRegisterIfExists(String name, long value)
    {
        Register reg = sLang.getRegister(name);
        if (reg == null)
            return false;
        setRegisterBytes(reg, Utils.longToBytes(value, reg.getMinimumByteSize(), sLang.isBigEndian()));
        return true;
    }

    private boolean setRegisterBytesIfExists(String name, int length)
    {
        Register reg = sLang.getRegister(name);
        if (reg == null)
            return false;
        setRegisterBytes(reg, new byte[Math.max(length, reg.getMinimumByteSize())]);
        return true;
    }

    private void setRegisterBytes(Register reg, byte[] value)
    {
        emuThread.getState().setVar(
            reg.getAddress(),
            reg.getMinimumByteSize(),
            true,
            Arrays.copyOf(value, reg.getMinimumByteSize()));
    }

    /** Read a 64-bit value from a named register. */
    private long getRegisterLong(String name)
    {
        Register reg = sLang.getRegister(name);
        byte[] raw = emuThread.getState().getVar(
            reg.getAddress(),
            reg.getMinimumByteSize(),
            true,
            Reason.INSPECT);
        if (raw == null) return 0L;
        ByteBuffer buf = ByteBuffer.wrap(raw);
        buf.order(sLang.isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        // pad to 8 bytes if the register is narrower (shouldn't happen for AArch64 Xn)
        if (raw.length < 8)
        {
            byte[] padded = new byte[8];
            System.arraycopy(raw, 0, padded, sLang.isBigEndian() ? 8 - raw.length : 0, raw.length);
            buf = ByteBuffer.wrap(padded).order(buf.order());
        }
        return buf.getLong();
    }

    /** Write a byte array into the emulator's default (RAM) address space. */
    private void stateSetChunk(byte[] data, long offset, int length)
    {
        AddressSpace space = sLang.getAddressFactory().getDefaultAddressSpace();
        emuThread.getState().setVar(space.getAddress(offset), length, true, Arrays.copyOf(data, length));
    }

    private void zeroStateRange(long offset, long length)
    {
        final int chunkSize = 0x10000;
        byte[] zeros = new byte[chunkSize];
        long remaining = length;
        long cursor = offset;

        while (remaining > 0)
        {
            int n = (int) Math.min(chunkSize, remaining);
            stateSetChunk(zeros, cursor, n);
            cursor += n;
            remaining -= n;
        }
    }

    private void zeroRegisterStateRange(long offset, int length)
    {
        AddressSpace space = sLang.getAddressFactory().getRegisterSpace();
        emuThread.getState().setVar(space.getAddress(offset), length, true, new byte[length]);
    }

    public static final class SwitchPcodeUseropLibrary extends AnnotatedPcodeUseropLibrary<byte[]>
    {
        @Override
        protected MethodHandles.Lookup getMethodLookup()
        {
            return MethodHandles.lookup();
        }

        @PcodeUserop
        public void CallSupervisor(byte[] imm16)
        {
            // AArch64 SVC lowers to this Sleigh userop. IPC metadata discovery does not need
            // kernel-side behavior here, so treat it as a trap boundary and continue.
        }

        @PcodeUserop
        public void ClearExclusiveLocal()
        {
            // CLREX only clears CPU exclusive-monitor state, which this analyzer does not model.
        }

        @PcodeUserop
        public void LOAcquire()
        {
            // Load-acquire only constrains ordering, which this emulator does not model.
        }

        @PcodeUserop
        public void LORelease()
        {
            // Store-release only constrains ordering, which this emulator does not model.
        }

        @PcodeUserop
        public void DataMemoryBarrier(byte[] domain, byte[] types)
        {
            // DMB enforces memory ordering only; single-threaded IPC metadata emulation can ignore it.
        }

        @PcodeUserop(variadic = true)
        public void Hint_Prefetch(byte[][] inputs)
        {
            // PRFM is a cache hint. It has no architectural data effect for metadata discovery.
        }

        @PcodeUserop
        public void DataSynchronizationBarrier(byte[] domain, byte[] types, byte[] nXS)
        {
            // DSB enforces memory ordering/completion only; this emulator has no concurrent agents.
        }

        @PcodeUserop
        public void InstructionSynchronizationBarrier()
        {
            // ISB affects instruction-fetch visibility, which is irrelevant for static stub emulation.
        }

        @PcodeUserop
        public void SpeculationBarrier()
        {
            // SB affects CPU speculation only; it has no metadata-visible side effect here.
        }

        @PcodeUserop
        public long UndefinedInstructionException(byte[] id, byte[] excaddr)
        {
            // UDF is a trap path. Returning 0 lets the client-stub emulator halt cleanly.
            return 0;
        }

        @PcodeUserop(functional = true, hasSideEffects = false, variadic = true)
        public byte[] NEON_ext(@OpOutput Varnode output, byte[][] inputs)
        {
            byte[] out = zeroOutput(output);

            if (inputs.length < 3 || inputs[0] == null || inputs[1] == null)
                return out;

            int shift = (int) bytesToUnsignedLong(inputs[2]);
            byte[] concatenated = new byte[inputs[0].length + inputs[1].length];
            System.arraycopy(inputs[0], 0, concatenated, 0, inputs[0].length);
            System.arraycopy(inputs[1], 0, concatenated, inputs[0].length, inputs[1].length);

            if (shift >= concatenated.length)
                return out;

            System.arraycopy(concatenated, shift, out, 0, Math.min(out.length, concatenated.length - shift));
            return out;
        }

        @PcodeUserop(functional = true, hasSideEffects = false, variadic = true)
        public byte[] NEON_fmov(@OpOutput Varnode output, byte[][] inputs)
        {
            return zeroOutput(output);
        }

        @PcodeUserop(functional = true, hasSideEffects = false, variadic = true)
        public byte[] NEON_ucvtf(@OpOutput Varnode output, byte[][] inputs)
        {
            return zeroOutput(output);
        }

        private static byte[] zeroOutput(Varnode output)
        {
            return new byte[output != null ? output.getSize() : 0];
        }

        private static long bytesToUnsignedLong(byte[] bytes)
        {
            long value = 0;
            int limit = Math.min(bytes.length, Long.BYTES);

            for (int i = 0; i < limit; i++)
                value |= (long) (bytes[i] & 0xFF) << (i * 8);

            return value;
        }
    }

    public static final class SwitchPcodeOverrideUseropLibrary extends AnnotatedPcodeUseropLibrary<byte[]>
    {
        @Override
        protected MethodHandles.Lookup getMethodLookup()
        {
            return MethodHandles.lookup();
        }

        //@PcodeUserop(functional = true)
        //public int ExclusiveMonitorPass(long addr, int rsize)
        //{
            // Single-threaded metadata emulation: the exclusive monitor is always clear,
            // so the store always succeeds. Return 0 (= pass/success) per ARM semantics.
        //    return 0;
        //}
    }

    /** Read a byte array from the emulator's default (RAM) address space. */
    private byte[] stateGetChunk(long offset, int length)
    {
        AddressSpace space = sLang.getAddressFactory().getDefaultAddressSpace();
        byte[] out = emuThread.getState().getVar(space.getAddress(offset), length, true, Reason.INSPECT);
        return out != null ? out : new byte[length];
    }

    private void setLong(long off, long val)
    {
        stateSetChunk(Utils.longToBytes(val, 0x8, sLang.isBigEndian()), off, 0x8);
    }

    private long getLong(long off)
    {
        byte[] out = stateGetChunk(off, 0x8);
        ByteBuffer buffer = ByteBuffer.wrap(out);
        buffer.order(sLang.isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        return buffer.getLong();
    }

    private void setInt(long off, long val)
    {
        stateSetChunk(Utils.longToBytes(val, 0x4, sLang.isBigEndian()), off, 0x4);
    }

    private void printMemory(long off, long size)
    {
        Msg.info(this, String.format("0x%X (0x%X bytes):", off, size));
        byte[] out = stateGetChunk(off, (int) size);
        ByteUtil.logBytes(out);
    }

    // -------------------------------------------------------------------------
    // HLE function utilities
    // -------------------------------------------------------------------------

    private void returnFromFunc(long value)
    {
        setRegister("x0", value);
        // x30 is the link register; redirect the thread's PC to it
        long lr = getRegisterLong("x30");
        emuThread.overrideCounter(sLang.getDefaultSpace().getAddress(lr));
    }

    // -------------------------------------------------------------------------
    // HLE-ed functions.
    // If these return false, emulation halts (same semantics as before).
    // -------------------------------------------------------------------------

    private boolean targetFunction(long offset)
    {
        this.currentTrace.vtOffset = offset;
        this.returnFromFunc(0);
        return true;
    }

    /**
     * Statically recover a command's impl-call vtable offset for handlers that captured metadata at
     * PrepareForProcess but bailed (on an input/Uid-buffer precondition) before invoking the target
     * impl that normally fires {@link #targetFunction} to set vtOffset. The handler saves the target
     * service object (its {@code x1}) into a callee-saved register, then invokes the command via
     * {@code ldr R,[target]; ldr R,[R,#vt]; blr R}. We find that register (just before the captured lr)
     * and the first such impl-call, returning {@code vt}. Returns -1 if not confidently found.
     */
    private long recoverImplVtOffset(long lr)
    {
        if (lr == 0 || lr == -1)
            return -1;
        try
        {
            Address lrAddr = sLang.getDefaultSpace().getAddress(lr);
            Function f = program.getFunctionManager().getFunctionContaining(lrAddr);
            if (f == null)
                return -1;

            // Walk the whole handler function (the impl call is on a conditional success path, not the
            // linear fall-through from lr). target = the callee-saved register assigned from x1.
            // A virtual impl call is: ldr R,[target]; ... ldr R,[R,#vt]; ... blr R  -- with the target's
            // own object distinguishing it from decoy calls on the request object (x2/x20).
            String targetReg = null;
            Set<String> vtLoaded = new HashSet<>();     // reg currently holds target's vtable pointer
            Map<String, Long> method = new HashMap<>();  // reg currently holds a method ptr (vtable+vt)

            InstructionIterator it = program.getListing().getInstructions(f.getBody(), true);
            while (it.hasNext())
            {
                Instruction insn = it.next();
                String mn = insn.getMnemonicString().toLowerCase();

                if (targetReg == null)
                {
                    if (mn.equals("mov"))
                    {
                        Register d = insn.getRegister(0);
                        Object[] src = insn.getOpObjects(1);
                        if (d != null && src.length == 1 && src[0] instanceof Register
                                && ((Register) src[0]).getName().equals("x1")
                                && d.getName().matches("x(19|2[0-8])"))
                            targetReg = d.getName();
                    }
                    continue;
                }

                if (mn.equals("ldr") && isBaseLoad(insn, targetReg) && insn.getRegister(0) != null)
                {
                    String r = insn.getRegister(0).getName();
                    vtLoaded.add(r);
                    method.remove(r);
                    continue;
                }
                if (mn.equals("ldr"))
                {
                    Register d = insn.getRegister(0);
                    Object[] mem = insn.getOpObjects(1);
                    if (d != null && mem.length == 2 && mem[0] instanceof Register && mem[1] instanceof Scalar
                            && vtLoaded.contains(((Register) mem[0]).getName()))
                    {
                        method.put(d.getName(), ((Scalar) mem[1]).getUnsignedValue());
                        vtLoaded.remove(d.getName());
                        continue;
                    }
                }
                if (mn.equals("blr"))
                {
                    Register d = insn.getRegister(0);
                    if (d != null && method.containsKey(d.getName()))
                        return method.get(d.getName());
                }
                if (writesOperand0(mn) && insn.getRegister(0) != null)
                {
                    String r = insn.getRegister(0).getName();
                    vtLoaded.remove(r);
                    method.remove(r);
                }
            }
        }
        catch (Exception e)
        {
            Msg.debug(this, "recoverImplVtOffset failed: " + e.getMessage());
        }
        return -1;
    }

    /** True if {@code insn} is {@code ldr R,[base]} or {@code ldr R,[base,#0]}. */
    private boolean isBaseLoad(Instruction insn, String base)
    {
        Object[] mem = insn.getOpObjects(1);
        if (mem.length < 1 || !(mem[0] instanceof Register) || !((Register) mem[0]).getName().equals(base))
            return false;
        return mem.length == 1 || (mem.length == 2 && mem[1] instanceof Scalar && ((Scalar) mem[1]).getValue() == 0);
    }

    /** True if the instruction writes its operand-0 register (loads/moves/ALU), false for stores,
     *  branches and compares which read operand 0. */
    private boolean writesOperand0(String mn)
    {
        switch (mn)
        {
            case "str": case "stp": case "strb": case "strh": case "stur": case "sturb": case "sturh":
            case "cbz": case "cbnz": case "tbz": case "tbnz": case "cmp": case "cmn": case "tst":
            case "ccmp": case "ccmn": case "b": case "bl": case "blr": case "br": case "ret":
                return false;
            default:
                return true;
        }
    }

    private boolean PrepareForProcess()
    {
        long metaInfoPtr  = getRegisterLong("x1");
        long metaInfoSize = 0x90;
        byte[] metaInfo   = stateGetChunk(metaInfoPtr, (int) metaInfoSize);

        try
        {
            Metadata metadata = decodeMetadata(metaInfo);

            if (metadata != null)
            {
                long lr = getRegisterLong("x30");

                if (this.prepareForProcessHits > 0)
                {
                    String message = String.format(
                        "PrepareForProcess hit %d for proc_func 0x%X cmd %d; replacing previous IPC metadata. previous={vt=%s, lr=%s, %s} new={vt=%s, lr=%s, %s}",
                        this.prepareForProcessHits + 1,
                        this.currentTrace.procFuncAddr,
                        this.currentTrace.cmdId,
                        formatOptionalHex(this.lastPrepareForProcessVtOffset),
                        formatOptionalHex(this.currentTrace.lr),
                        formatTraceMetadata(this.currentTrace),
                        formatOptionalHex(this.currentTrace.vtOffset),
                        formatOptionalHex(lr),
                        formatMetadata(metadata));

                    if (this.traceMetadataDiffers(this.currentTrace, metadata, lr))
                        Msg.warn(this, message);
                    else
                        Msg.debug(this, message);
                }

                this.prepareForProcessHits++;
                this.lastPrepareForProcessVtOffset  = this.currentTrace.vtOffset;
                this.currentTrace.bytesIn           = metadata.bytesIn;
                this.currentTrace.bytesOut          = metadata.bytesOut;
                this.currentTrace.bufferCount       = metadata.bufferCount;
                this.currentTrace.bufferAttrs       = metadata.bufferAttrs;
                this.currentTrace.bufferAttrsSource = metadata.bufferAttrsSource;
                this.currentTrace.bufferAttrsProbe  = metadata.bufferAttrsProbe;
                this.currentTrace.inInterfaces      = metadata.inInterfaces;
                this.currentTrace.outInterfaces     = metadata.outInterfaces;
                this.currentTrace.initializeOutInterfaceTargets();
                this.currentTrace.inHandles         = metadata.inHandles;
                this.currentTrace.outHandles        = metadata.outHandles;
                this.currentTrace.lr                = lr;

                if (this.currentTrace.inInterfaces > 0)
                {
                    this.instructionHandlers.add((off) ->
                    {
                        Address pcAddr = this.sLang.getDefaultSpace().getAddress(off);
                        CodeManager codeManager = ((ProgramDB) this.program).getCodeManager();
                        Instruction currentInstruction = codeManager.getInstructionAt(pcAddr);

                        if (currentInstruction == null)
                        {
                            disassembler.disassemble(pcAddr, null, false);
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
                                    // Make the operands of the upcoming `cmp x8, x9` equal so the
                                    // real cmp sets the working ZR/NG/CY/OV flags (offset 0x100) that
                                    // AArch64 conditional branches actually read. (A prior
                                    // setRegister("NZCV", ...) here resolved to the architectural
                                    // nzcv system register, which branches do not read, so it had no
                                    // effect and was removed.)
                                    long x9 = getRegisterLong("x9");
                                    setRegister("x8", x9);
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

    private boolean OverwriteClientProcessId()
    {
        long out = getRegisterLong("x1");
        this.currentTrace.pid = true;
        this.setLong(out, 0);
        this.returnFromFunc(0);
        return true;
    }

    private boolean GetBuffers()
    {
        long out         = getRegisterLong("x1");
        long bufferCount = Math.max(this.currentTrace.bufferCount, 0);

        for (long i = out; i < out + bufferCount * 0x10; i += 0x10)
        {
            this.setLong(i,        this.bufferMemory);
            this.setLong(i + 0x8,  this.bufferSize);
        }

        this.returnFromFunc(0);
        return true;
    }

    private boolean GetInNativeHandles()
    {
        long out         = getRegisterLong("x1");
        long handleCount = Math.max(this.currentTrace.inHandles, 0);

        for (long i = 0; i < handleCount; i++)
            this.setInt(out + i * 0x4, 0xCAFE0000L + i);

        this.returnFromFunc(0);
        return true;
    }

    private boolean GetInObjects()
    {
        long out = getRegisterLong("x1");

        if (this.currentTrace.inInterfaces > 0)
        {
            for (long i = 0; i < this.currentTrace.inInterfaces; i++)
                this.setLong(out + i * 0x8, this.inObjectPtr);
        }

        this.returnFromFunc(0);
        return true;
    }

    private boolean BeginPreparingForReply()
    {
        long off = getRegisterLong("x1");
        this.setLong(off,        this.outputMemory);
        this.setLong(off + 0x8,  0x1000);
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
        if (this.currentTrace.outInterfaces > 0)
        {
            long out = getRegisterLong("x1");
            this.currentTrace.setOutInterfaceTarget(0, this.getLong(out + 0x8));
        }

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
        long off = getRegisterLong("x1");
        this.setLong(off,        this.outputMemory);
        this.setLong(off + 0x8,  0x1000);
        this.returnFromFunc(0);
        return true;
    }

    private boolean EndPreparingForReply()
    {
        this.returnFromFunc(0);
        return true;
    }

    // -------------------------------------------------------------------------
    // Metadata decoding (unchanged from original)
    // -------------------------------------------------------------------------

    private static Metadata decodeMetadata(byte[] metaInfo)
    {
        Metadata metadata = decodeRuntimeMetadata(metaInfo);
        if (metadata != null && looksLikeRuntimeMetadata(metaInfo))
            return metadata;

        metadata = decodeModernCompactMetadata(metaInfo, 0x00);
        if (metadata != null) return metadata;

        metadata = decodeLegacyCompactMetadata(metaInfo, 0x00);
        if (metadata != null) return metadata;

        int[] wideBases = new int[] { 0x08, 0x10, 0x18, 0x20 };
        for (int base : wideBases)
        {
            metadata = decodeLegacyWideMetadata(metaInfo, base);
            if (metadata != null) return metadata;
        }

        return null;
    }

    private static Metadata decodeModernCompactMetadata(byte[] metaInfo, int base)
    {
        long rawBytesIn    = readU16LE(metaInfo, base + 0x00);
        long rawBytesOut   = readU16LE(metaInfo, base + 0x02);
        long pid           = metaInfo[base + 0x04] & 0xFFL;
        long bufferCount   = metaInfo[base + 0x05] & 0xFFL;
        long inInterfaces  = metaInfo[base + 0x06] & 0xFFL;
        long outInterfaces = metaInfo[base + 0x07] & 0xFFL;
        long inHandles     = metaInfo[base + 0x08] & 0xFFL;
        long outHandles    = metaInfo[base + 0x09] & 0xFFL;

        if (pid > 1) return null;

        if (!isValidLegacyMetadata(rawBytesIn, rawBytesOut, bufferCount, inInterfaces, outInterfaces, inHandles, outHandles))
            return null;

        BufferAttrsResult bufferAttrs  = null;
        String            bufferAttrsProbe = null;

        if (bufferCount > 0)
        {
            int[] attrs = readByteBufferAttrs(metaInfo, base + 0x0A, bufferCount);
            bufferAttrs      = attrs != null ? new BufferAttrsResult(attrs, "modern-compact/u8+0xA") : null;
            bufferAttrsProbe = bufferAttrs == null ? readRawByteAttrs(metaInfo, base + 0x0A, bufferCount) : null;
        }

        return new Metadata(rawBytesIn - 0x10, rawBytesOut - 0x10, bufferCount, inInterfaces,
            outInterfaces, inHandles, outHandles, bufferAttrs, bufferAttrsProbe);
    }

    private static Metadata decodeLegacyCompactMetadata(byte[] metaInfo, int base)
    {
        long rawBytesIn    = readU16LE(metaInfo, base + 0x00);
        long rawBytesOut   = readU16LE(metaInfo, base + 0x02);
        long inInterfaces  = metaInfo[base + 0x04] & 0xFFL;
        long bufferCount   = metaInfo[base + 0x05] & 0xFFL;
        long outInterfaces = metaInfo[base + 0x06] & 0xFFL;
        long inHandles     = metaInfo[base + 0x07] & 0xFFL;
        long outHandles    = metaInfo[base + 0x08] & 0xFFL;

        if (!isValidLegacyMetadata(rawBytesIn, rawBytesOut, bufferCount, inInterfaces, outInterfaces, inHandles, outHandles))
            return null;

        BufferAttrsResult bufferAttrs  = decodeCompactBufferAttrs(metaInfo, base, bufferCount);
        String            bufferAttrsProbe = bufferAttrs == null ? describeCompactBufferAttrProbes(metaInfo, base, bufferCount) : null;

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

        BufferAttrsResult bufferAttrs  = decodeWideBufferAttrs(metaInfo, base, bufferCount);
        String            bufferAttrsProbe = bufferAttrs == null ? describeWideBufferAttrProbes(metaInfo, base, bufferCount) : null;

        return new Metadata(rawBytesIn - 0x10, rawBytesOut - 0x10, bufferCount, inInterfaces,
            outInterfaces, inHandles, outHandles, bufferAttrs, bufferAttrsProbe);
    }

    private static Metadata decodeRuntimeMetadata(byte[] metaInfo)
    {
        long bytesIn        = readU16LE(metaInfo, 0x00);
        long bytesOut       = readU16LE(metaInfo, 0x02);
        long inHeadersSize  = metaInfo[0x04] & 0xFFL;
        long outHeadersSize = metaInfo[0x05] & 0xFFL;
        long inInterfaces   = metaInfo[0x06] & 0xFFL;
        long outInterfaces  = metaInfo[0x07] & 0xFFL;

        if (bytesIn > 0x4000L || bytesOut > 0x4000L) return null;
        if (!isValidHeaderSize(inHeadersSize) || !isValidHeaderSize(outHeadersSize)) return null;
        if (inInterfaces > 20 || outInterfaces > 20) return null;

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
        int[]         offsets = new int[] { base + 0x0A, base + 0x09, alignUp(base + 0x09, 4), base + 0x10 };
        StringBuilder out     = new StringBuilder();

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
        int[]         offsets = new int[] { base + 0x24, alignUp(base + 0x24, 8), base + 0x30 };
        StringBuilder out     = new StringBuilder();

        for (int offset : offsets)
            appendProbe(out, String.format("u32+0x%X", offset - base), readRawU32Attrs(metaInfo, offset, bufferCount));

        for (int offset : offsets)
            appendProbe(out, String.format("u8+0x%X",  offset - base), readRawByteAttrs(metaInfo, offset, bufferCount));

        return out.toString();
    }

    private static void appendProbe(StringBuilder out, String name, String value)
    {
        if (out.length() > 0) out.append("; ");
        out.append(name).append("=").append(value);
    }

    private static int[] readByteBufferAttrs(byte[] metaInfo, int offset, long bufferCount)
    {
        if (!isValidBufferAttrCount(bufferCount) || offset < 0 || offset + bufferCount > metaInfo.length)
            return null;

        int[] attrs = new int[(int) bufferCount];

        for (int i = 0; i < attrs.length; i++)
        {
            attrs[i] = metaInfo[offset + i] & 0xFF;
            if (!isValidBufferAttr(attrs[i])) return null;
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
            if (i > 0) out.append(",");
            out.append(metaInfo[offset + i] & 0xFF);
        }

        return out.append("]").toString();
    }

    private static int[] readU32BufferAttrs(byte[] metaInfo, int offset, long bufferCount)
    {
        if (!isValidBufferAttrCount(bufferCount) || offset < 0 || offset + bufferCount * 4 > metaInfo.length)
            return null;

        int[] attrs = new int[(int) bufferCount];

        for (int i = 0; i < attrs.length; i++)
        {
            long attr = readU32LE(metaInfo, offset + i * 4);
            if (!isValidBufferAttr(attr)) return null;
            attrs[i] = (int) attr;
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
            if (i > 0) out.append(",");
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
        if (attr <= 0 || (attr & ~BUFFER_ATTR_VALID_MASK) != 0) return false;
        if ((attr & (BUFFER_ATTR_IN | BUFFER_ATTR_OUT)) == 0)   return false;

        int transferModes = 0;
        if ((attr & BUFFER_ATTR_HIPC_MAP_ALIAS)   != 0) transferModes++;
        if ((attr & BUFFER_ATTR_HIPC_POINTER)     != 0) transferModes++;
        if ((attr & BUFFER_ATTR_HIPC_AUTO_SELECT) != 0) transferModes++;
        if (transferModes != 1) return false;

        return (attr & (BUFFER_ATTR_HIPC_MAP_TRANSFER_ALLOWS_NON_SECURE |
            BUFFER_ATTR_HIPC_MAP_TRANSFER_ALLOWS_NON_DEVICE)) !=
            (BUFFER_ATTR_HIPC_MAP_TRANSFER_ALLOWS_NON_SECURE |
                BUFFER_ATTR_HIPC_MAP_TRANSFER_ALLOWS_NON_DEVICE);
    }

    private static int alignUp(int value, int align)
    {
        return (value + align - 1) & -align;
    }

    // -------------------------------------------------------------------------
    // Formatting helpers (unchanged)
    // -------------------------------------------------------------------------

    private static boolean traceMetadataDiffers(IPCTrace trace, Metadata metadata, long lr)
    {
        return trace.lr != lr ||
            trace.bytesIn       != metadata.bytesIn       ||
            trace.bytesOut      != metadata.bytesOut      ||
            trace.bufferCount   != metadata.bufferCount   ||
            !Arrays.equals(trace.bufferAttrs, metadata.bufferAttrs) ||
            !Objects.equals(trace.bufferAttrsSource, metadata.bufferAttrsSource) ||
            !Objects.equals(trace.bufferAttrsProbe,  metadata.bufferAttrsProbe)  ||
            trace.inInterfaces  != metadata.inInterfaces  ||
            trace.outInterfaces != metadata.outInterfaces ||
            trace.inHandles     != metadata.inHandles     ||
            trace.outHandles    != metadata.outHandles;
    }

    private static String formatTraceMetadata(IPCTrace trace)
    {
        return String.format(
            "in=%s, out=%s, buffers=%s, attrs=%s, attrSource=%s, attrProbe=%s, inIfaces=%s, outIfaces=%s, inHandles=%s, outHandles=%s",
            formatOptionalHex(trace.bytesIn),
            formatOptionalHex(trace.bytesOut),
            formatOptionalHex(trace.bufferCount),
            trace.bufferAttrs       != null ? Arrays.toString(trace.bufferAttrs)  : "null",
            trace.bufferAttrsSource != null ? trace.bufferAttrsSource              : "null",
            trace.bufferAttrsProbe  != null ? trace.bufferAttrsProbe               : "null",
            formatOptionalHex(trace.inInterfaces),
            formatOptionalHex(trace.outInterfaces),
            formatOptionalHex(trace.inHandles),
            formatOptionalHex(trace.outHandles));
    }

    private static String formatMetadata(Metadata metadata)
    {
        return String.format(
            "in=%s, out=%s, buffers=%s, attrs=%s, attrSource=%s, attrProbe=%s, inIfaces=%s, outIfaces=%s, inHandles=%s, outHandles=%s",
            formatOptionalHex(metadata.bytesIn),
            formatOptionalHex(metadata.bytesOut),
            formatOptionalHex(metadata.bufferCount),
            metadata.bufferAttrs       != null ? Arrays.toString(metadata.bufferAttrs) : "null",
            metadata.bufferAttrsSource != null ? metadata.bufferAttrsSource             : "null",
            metadata.bufferAttrsProbe  != null ? metadata.bufferAttrsProbe              : "null",
            formatOptionalHex(metadata.inInterfaces),
            formatOptionalHex(metadata.outInterfaces),
            formatOptionalHex(metadata.inHandles),
            formatOptionalHex(metadata.outHandles));
    }

    private static String formatOptionalHex(long value)
    {
        return value == -1 ? "<unset>" : String.format("0x%X", value);
    }

    private static long readU16LE(byte[] buf, int off)
    {
        return ((buf[off] & 0xFFL)) | ((buf[off + 1] & 0xFFL) << 8);
    }

    private static long readU32LE(byte[] buf, int off)
    {
        return  ((buf[off]     & 0xFFL))
            |   ((buf[off + 1] & 0xFFL) << 8)
            |   ((buf[off + 2] & 0xFFL) << 16)
            |   ((buf[off + 3] & 0xFFL) << 24);
    }

    private static String bytesToHex(byte[] bytes, int len)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(len, bytes.length); i++)
            sb.append(String.format("%02X ", bytes[i]));
        return sb.toString().trim();
    }

    // -------------------------------------------------------------------------
    // Inner types (unchanged)
    // -------------------------------------------------------------------------

    private static class BufferAttrsResult
    {
        private final int[]  attrs;
        private final String source;

        private BufferAttrsResult(int[] attrs, String source)
        {
            this.attrs  = attrs;
            this.source = source;
        }
    }

    private static boolean isValidLegacyMetadata(long rawBytesIn, long rawBytesOut, long bufferCount,
                                                  long inInterfaces, long outInterfaces,
                                                  long inHandles, long outHandles)
    {
        if (rawBytesIn   < 0x10 || rawBytesIn   > 0x4010L) return false;
        if (rawBytesOut  < 0x10 || rawBytesOut  > 0x4010L) return false;
        if (bufferCount   > 20)                             return false;
        if (inInterfaces  > 20)                             return false;
        if (outInterfaces > 20)                             return false;
        if (inHandles     > 20)                             return false;
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
        private final long   bytesIn;
        private final long   bytesOut;
        private final long   bufferCount;
        private final int[]  bufferAttrs;
        private final String bufferAttrsSource;
        private final String bufferAttrsProbe;
        private final long   inInterfaces;
        private final long   outInterfaces;
        private final long   inHandles;
        private final long   outHandles;

        private Metadata(long bytesIn, long bytesOut, long bufferCount, long inInterfaces,
                         long outInterfaces, long inHandles, long outHandles,
                         BufferAttrsResult bufferAttrs, String bufferAttrsProbe)
        {
            this.bytesIn           = bytesIn;
            this.bytesOut          = bytesOut;
            this.bufferCount       = bufferCount;
            this.bufferAttrs       = bufferAttrs != null ? bufferAttrs.attrs  : null;
            this.bufferAttrsSource = bufferAttrs != null ? bufferAttrs.source : null;
            this.bufferAttrsProbe  = bufferAttrsProbe;
            this.inInterfaces      = inInterfaces;
            this.outInterfaces     = outInterfaces;
            this.inHandles         = inHandles;
            this.outHandles        = outHandles;
        }
    }
}
