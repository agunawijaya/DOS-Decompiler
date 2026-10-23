/* RecoverFunctions.java -- find the functions Ghidra's auto-analysis missed.
 *
 * Why this is necessary
 * ---------------------
 * Ghidra discovers functions by following control flow from the entry point.
 * That works well on modern binaries and badly on 1980s games, because a game
 * loop dispatches through function-pointer tables held in data structures
 * (Sopwith stores ob_drawf and ob_movef inside every object). Code reached
 * only through such a pointer is never walked, so it is never turned into a
 * function, so the decompiler never sees it. Measured on Sopwith, plain
 * auto-analysis recovered fewer than half of the real function entry points.
 *
 * What it does
 * ------------
 * Scans executable memory for the stack-frame prologue that every C compiler
 * of the era emits, and defines a function wherever one is found that is not
 * already inside a known function body:
 *
 *     55        push bp
 *     8B EC     mov  bp,sp        (Microsoft C, Open Watcom, Lattice, Turbo C)
 *     C8 xx xx 00   enter n,0     (186+ compilers; rarer, but used)
 *
 * Leaf functions that never touch bp are deliberately NOT guessed at from
 * bytes -- that produces false positives in data. They are instead recovered
 * from call targets, which is evidence rather than a guess.
 *
 * The prologue scan is a heuristic and is reported as such: the script prints
 * how many functions it added so the number can be checked against a linker
 * map when one exists.
 *
 * Where each function came from
 * -----------------------------
 * Every function this script creates is a hypothesis resting on weaker
 * evidence than Ghidra's own flow analysis, and later tools should be able to
 * tell. So it records why it made each one, in a string property map keyed by
 * entry address, which ExportDecompiledC.java reports as `origin`:
 *
 *     recovered-call-target    something calls it
 *     recovered-code-pointer   an immediate in the code points at it
 *     recovered-split          a prologue inside another function's body
 *     recovered-prologue       a prologue no function contained
 *
 * A function with no mark is Ghidra's (the MZ loader creates none: measured,
 * an import without analysis holds no functions). The function a split
 * shortens keeps whatever mark it had.
 *
 * Why a property map, and not a bookmark or a plate comment: the split
 * removes a function and creates it again, so nothing attached to the
 * function itself would survive it. A plate comment is printed into
 * decompiled.c and is where ApplyNames.java writes its warnings, and a
 * bookmark is something a person clears from the GUI. A property map is
 * keyed by address, saved with the program, invisible in the listing and the
 * decompiler output, and outlives the function it describes.
 *
 * @category DOS.Decompile
 */

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.StringPropertyMap;

public class RecoverFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        int fromCalls = recoverFromCallTargets();
        int fromPointers = recoverFromCodePointers();
        List<Address> prologues = findPrologues();
        int split = splitOverlongFunctions(prologues);
        int fromPrologues = recoverFromPrologues();

        int total = currentProgram.getFunctionManager().getFunctionCount();
        println("RecoverFunctions: " + prologues.size() + " prologues seen, +"
                + fromCalls + " from call targets, +" + fromPointers + " from code pointers, "
                + split + " over-long functions split, +"
                + fromPrologues + " new from prologues, " + total + " functions total");

        // Leave a mark in the program saying this ran, and which version of
        // this script it was. ExportDecompiledC reports it and the pipeline's
        // profile handshake holds it to what tools/analysis_profile.py expected, so an
        // export from a project where recovery never ran, or ran an older copy
        // of this script, stops the run instead of passing as the real thing.
        currentProgram.getOptions(Program.PROGRAM_INFO)
                .setString(RECOVERY_OPTION, sourceSha256());
    }

    /** Program Information key ExportDecompiledC reads back. */
    static final String RECOVERY_OPTION = "DOS-Decompiler RecoverFunctions SHA-256";

    /** Property map ExportDecompiledC reads `origin` from; the same name. */
    static final String ORIGIN_MAP = "DOS-Decompiler function origin";

    /* Record why this script made the function at `entry`. */
    private void markOrigin(Address entry, String origin) throws Exception {
        StringPropertyMap map = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap(ORIGIN_MAP);
        if (map == null) {
            map = currentProgram.getUsrPropertyManager().createStringPropertyMap(ORIGIN_MAP);
        }
        map.add(entry, origin);
    }

    /* SHA-256 of this script's own source, by the rule analysis_profile.py
     * hashes it with, so the handshake can tell which recovery ran and not
     * merely that one did. */
    private String sourceSha256() {
        try (java.io.InputStream in = getSourceFile().getInputStream()) {
            byte[] raw = in.readAllBytes();
            // CRLF is read as LF, the rule evidence.source_sha256 applies, so a
            // Windows checkout and a Linux checkout of one commit agree.
            java.io.ByteArrayOutputStream text = new java.io.ByteArrayOutputStream(raw.length);
            for (int i = 0; i < raw.length; i++) {
                if (raw[i] == '\r' && i + 1 < raw.length && raw[i + 1] == '\n') {
                    continue;
                }
                text.write(raw[i]);
            }
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            md.update(text.toByteArray());
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest()) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "unreadable: " + e.getMessage();
        }
    }

    /* Any address that something CALLs is a function entry point. This is
     * evidence, not inference, so it runs first and its results are trusted. */
    private int recoverFromCallTargets() throws Exception {
        List<Address> targets = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            for (Reference ref : ins.getReferencesFrom()) {
                RefType t = ref.getReferenceType();
                if (t.isCall() && ref.getToAddress().isMemoryAddress()) {
                    targets.add(ref.getToAddress());
                }
            }
        }

        int added = 0;
        for (Address a : targets) {
            if (monitor.isCancelled()) {
                break;
            }
            if (getFunctionAt(a) != null) {
                continue;
            }
            if (createFunctionAt(a)) {
                markOrigin(a, "recovered-call-target");
                added++;
            }
        }
        return added;
    }

    /* A prologue sitting inside an existing function body, but not at its
     * entry, means Ghidra ran two functions together: it never saw a call to
     * the second one, so the first appeared to fall straight through into it.
     * Splitting them is the single highest-value correction on this class of
     * binary -- on Sopwith it is the difference between one unreadable
     * 900-instruction blob and half a dozen recognisable movement routines. */
    private int splitOverlongFunctions(List<Address> prologues) throws Exception {
        int split = 0;
        for (Address a : prologues) {
            if (monitor.isCancelled()) {
                break;
            }
            Function containing = getFunctionContaining(a);
            if (containing == null || containing.getEntryPoint().equals(a)) {
                continue;
            }
            Address ownerEntry = containing.getEntryPoint();
            try {
                currentProgram.getFunctionManager().removeFunction(ownerEntry);
                boolean a1 = createFunctionAt(ownerEntry);
                boolean a2 = createFunctionAt(a);
                if (a2) {
                    markOrigin(a, "recovered-split");
                    split++;
                } else if (!a1) {
                    // Recreate whatever we can rather than leaving a hole.
                    createFunctionAt(ownerEntry);
                }
            } catch (Exception e) {
                println("  split failed at " + a + ": " + e.getMessage());
            }
        }
        return split;
    }

    /* The technique that actually matters on 1980s game binaries.
     *
     * A game loop dispatches through function pointers held in structures
     * (ob_movef, ob_drawf) and installs interrupt handlers by address. In a
     * small-model real-mode program those pointers are plain 16-bit near
     * offsets, so the code that stores them does it with an immediate:
     *
     *     mov  word ptr [bx+0x3a], 0x1587      ; ob_movef = moveplyr
     *
     * Ghidra's flow analysis never follows an integer, so every routine
     * reachable only this way stays undisassembled. Measured on Sopwith, 48
     * real functions -- movement handlers, drawing handlers, the keyboard and
     * timer interrupt service routines -- were invisible for exactly this
     * reason.
     *
     * So: treat any immediate that lands inside the code segment as a
     * candidate entry point. False positives are filtered by requiring the
     * bytes to disassemble cleanly and not already belong to a function.
     */
    private int recoverFromCodePointers() throws Exception {
        // Ghidra's MZ loader marks every segment executable, data included.
        // Trusting that flag creates functions inside sprite tables. Restrict
        // to blocks that demonstrably hold code: the one containing the entry
        // point, plus any block that already contains defined functions.
        List<MemoryBlock> codeBlocks = new ArrayList<>();
        Address entry = currentProgram.getSymbolTable().getExternalEntryPointIterator().hasNext()
                ? currentProgram.getSymbolTable().getExternalEntryPointIterator().next()
                : currentProgram.getImageBase();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isExecute() || !b.isInitialized()) {
                continue;
            }
            boolean holdsEntry = b.contains(entry);
            boolean holdsCode = false;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (b.contains(f.getEntryPoint())) {
                    holdsCode = true;
                    break;
                }
            }
            if (holdsEntry || holdsCode) {
                codeBlocks.add(b);
            }
        }
        if (codeBlocks.isEmpty()) {
            return 0;
        }

        List<Address> candidates = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            for (int op = 0; op < ins.getNumOperands(); op++) {
                ghidra.program.model.scalar.Scalar s = ins.getScalar(op);
                if (s == null) {
                    continue;
                }
                long v = s.getUnsignedValue();
                // 0 and tiny values are counters, not addresses.
                if (v < 0x10 || v > 0xFFFF) {
                    continue;
                }
                for (MemoryBlock b : codeBlocks) {
                    if (v < b.getSize()) {
                        candidates.add(b.getStart().add(v));
                    }
                }
            }
        }

        int added = 0;
        for (Address a : candidates) {
            if (monitor.isCancelled()) {
                break;
            }
            if (getFunctionAt(a) != null || getFunctionContaining(a) != null) {
                continue;
            }
            if (usesUnframedBp(a)) {
                continue;
            }
            if (createFunctionAt(a)) {
                markOrigin(a, "recovered-code-pointer");
                added++;
            }
        }
        return added;
    }

    /**
     * Do not create a function at a code pointer whose code uses [bp+...]
     * addressing into a stack frame it never set up itself.
     */
    private boolean usesUnframedBp(Address a) throws Exception {
        Instruction existing = getInstructionContaining(a);
        if (existing != null && !existing.getAddress().equals(a)) {
            return true;
        }
        boolean wasDisassembled = (getInstructionAt(a) != null);
        if (!wasDisassembled) {
            if (!disassemble(a)) {
                return false;
            }
        }
        Instruction ins = getInstructionAt(a);
        if (ins == null) {
            return false;
        }

        int count = 0;
        int maxCheck = 32;
        boolean bpSetup = false;
        boolean unframedBp = false;
        Instruction cur = ins;
        Address curMax = ins.getMaxAddress();

        while (cur != null && count < maxCheck) {
            curMax = cur.getMaxAddress();
            String mn = cur.getMnemonicString().toUpperCase();

            if (mn.equals("ENTER")) {
                bpSetup = true;
                break;
            }
            if (mn.equals("MOV") || mn.equals("LEA")) {
                if (cur.getNumOperands() > 0) {
                    String op0 = cur.getDefaultOperandRepresentation(0);
                    if (op0 != null && op0.equalsIgnoreCase("BP")) {
                        bpSetup = true;
                        break;
                    }
                }
            } else if (mn.equals("POP")) {
                if (cur.getNumOperands() > 0) {
                    String op0 = cur.getDefaultOperandRepresentation(0);
                    if (op0 != null && op0.equalsIgnoreCase("BP")) {
                        bpSetup = true;
                        break;
                    }
                }
            }

            for (int op = 0; op < cur.getNumOperands(); op++) {
                String rep = cur.getDefaultOperandRepresentation(op);
                if (rep != null) {
                    int lbr = rep.indexOf('[');
                    int rbr = rep.indexOf(']');
                    if (lbr >= 0 && rbr > lbr) {
                        String inside = rep.substring(lbr + 1, rbr).toUpperCase();
                        if (inside.contains("BP")) {
                            unframedBp = true;
                            break;
                        }
                    }
                }
            }
            if (unframedBp) {
                break;
            }

            if (mn.equals("RET") || mn.equals("RETF") || mn.equals("IRET") || mn.equals("JMP")) {
                break;
            }
            Instruction next = cur.getNext();
            if (next == null || next.getAddress().compareTo(cur.getMaxAddress().add(1)) != 0) {
                break;
            }
            cur = next;
            count++;
        }

        if (unframedBp && !bpSetup) {
            if (!wasDisassembled) {
                clearListing(a, curMax);
            }
            return true;
        }
        return false;
    }

    private List<Address> findPrologues() throws Exception {
        List<Address> found = new ArrayList<>();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) {
                continue;
            }
            byte[] bytes = new byte[(int) Math.min(block.getSize(), Integer.MAX_VALUE)];
            block.getBytes(block.getStart(), bytes);
            for (int i = 0; i + 3 < bytes.length; i++) {
                boolean isPushBp = (bytes[i] == 0x55 && bytes[i + 1] == (byte) 0x8B
                                && bytes[i + 2] == (byte) 0xEC);
                boolean isEnter = (bytes[i] == (byte) 0xC8 && bytes[i + 3] == 0x00);
                if (!isPushBp && !isEnter) {
                    continue;
                }
                Address a = block.getStart().add(i);
                if (isEnter && !isPlausibleEnter(a)) {
                    continue;
                }
                found.add(a);
            }
        }
        return found;
    }

    private int recoverFromPrologues() throws Exception {
        int added = 0;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) {
                continue;
            }
            monitor.setMessage("scanning " + block.getName());

            Address start = block.getStart();
            Address end = block.getEnd();
            long length = block.getSize();
            byte[] bytes = new byte[(int) Math.min(length, Integer.MAX_VALUE)];
            block.getBytes(start, bytes);

            for (int i = 0; i + 3 < bytes.length; i++) {
                if (monitor.isCancelled()) {
                    break;
                }
                boolean isPushBp = (bytes[i] == 0x55 && bytes[i + 1] == (byte) 0x8B
                                && bytes[i + 2] == (byte) 0xEC);
                boolean isEnter = (bytes[i] == (byte) 0xC8 && bytes[i + 3] == 0x00);
                if (!isPushBp && !isEnter) {
                    continue;
                }

                Address a = start.add(i);
                if (a.compareTo(end) > 0) {
                    break;
                }
                // Already accounted for? Then this is the real prologue of a
                // function we know about, which is the common case.
                Function containing = getFunctionContaining(a);
                if (containing != null) {
                    continue;
                }
                if (isEnter && !isPlausibleEnter(a)) {
                    continue;
                }
                if (createFunctionAt(a)) {
                    markOrigin(a, "recovered-prologue");
                    added++;
                }
            }
        }
        return added;
    }

    private static final Set<String> IMPLAUSIBLE_MNEMONICS = new HashSet<>(Arrays.asList(
        "HLT", "ARPL", "BOUND", "INSB", "INSW", "OUTSB", "OUTSW",
        "SALC", "INTO", "XLATB", "LOCK", "CPUID", "CWDE", "POPAW",
        "PUSHAW", "POPAL", "PUSHAL", "MOVSX", "MOVZX", "FISTTP"
    ));

    private boolean isPlausibleEnter(Address a) throws Exception {
        Instruction existing = getInstructionContaining(a);
        if (existing != null && !existing.getAddress().equals(a)) {
            return false;
        }
        boolean wasDisassembled = (getInstructionAt(a) != null);
        if (!wasDisassembled) {
            if (!disassemble(a)) {
                return false;
            }
        }
        Instruction ins = getInstructionAt(a);
        if (ins == null || !ins.getMnemonicString().equalsIgnoreCase("ENTER")) {
            if (!wasDisassembled && ins != null) {
                clearListing(a, ins.getMaxAddress());
            }
            return false;
        }

        int count = 0;
        int maxCheck = 64;
        boolean hasTransfer = false;
        boolean plausible = true;
        Instruction cur = ins.getNext();
        Address endAddr = ins.getMaxAddress();

        while (cur != null && count < maxCheck) {
            endAddr = cur.getMaxAddress();
            String mn = cur.getMnemonicString().toUpperCase();
            if (IMPLAUSIBLE_MNEMONICS.contains(mn) || mn.startsWith("F") || mn.equals("??")) {
                plausible = false;
                break;
            }
            if (mn.equals("RET") || mn.equals("RETF") || mn.equals("IRET") || mn.equals("LEAVE")) {
                hasTransfer = true;
                break;
            }
            cur = cur.getNext();
            count++;
        }

        if (plausible && !hasTransfer && (cur == null || count >= maxCheck)) {
            plausible = false;
        }

        if (!plausible && !wasDisassembled) {
            clearListing(a, endAddr);
        }
        return plausible;
    }

    /** Disassemble if needed, then define a function. Returns true on success. */
    private boolean createFunctionAt(Address a) {
        try {
            if (getInstructionAt(a) == null) {
                if (!disassemble(a)) {
                    return false;
                }
            }
            Function f = createFunction(a, null);
            return f != null;
        } catch (Exception e) {
            // A prologue-shaped byte sequence inside data will fail to
            // disassemble cleanly. That is the expected way for a false
            // positive to be rejected, so it is not an error.
            return false;
        }
    }
}
