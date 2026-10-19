/* ExportDecompiledC.java -- headless export of Ghidra's decompiler output.
 *
 * Usage (headless):
 *   -postScript ExportDecompiledC.java OUTDIR [load_image:STATUS] [load_image:allowed]
 *
 * Writes, into the directory given as the first script argument:
 *   decompiled.c    every function Ghidra could decompile, in address order
 *   functions.json  a machine-readable inventory used by the scoring harness,
 *                   carrying the file it describes (`target`: path, size,
 *                   SHA-256), what Ghidra did on import (`observed_profile`,
 *                   which pipeline.ps1 holds to the profile
 *                   tools/analysis_profile.py wrote before import), and the
 *                   load-image check's verdict when the pipeline passes it
 *                   (`load_image`). Each function carries its `body` as
 *                   address ranges with inclusive ends and its `origin`;
 *                   `body_overlaps` lists the bytes more than one function
 *                   claims, and `tail_calls` the jumps into a called
 *                   function that end a claim
 *   failures.txt    functions the decompiler refused, with the reason
 *
 * Written in Java rather than Python on purpose: a .java GhidraScript is
 * compiled by Ghidra itself at run time and needs no interpreter installed,
 * so the package stays self-contained.
 *
 * @category DOS.Decompile
 */

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import java.util.Set;
import java.util.TreeSet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.util.StringPropertyMap;

public class ExportDecompiledC extends GhidraScript {

    private static final int TIMEOUT_SECONDS = 120;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir = new File(args.length > 0 ? args[0] : "decompiled");
        // pipeline.ps1 passes what the load-image check found, so a run it
        // let through with -AllowLoadMismatch says so in functions.json and
        // not only in a log nobody keeps. Colons, not '=': a headless argument
        // goes through analyzeHeadless.bat on Windows, and cmd.exe splits
        // "a=b" into two arguments (measured: the first form never arrived).
        String loadStatus = null;
        boolean loadAllowed = false;
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("load_image:allowed")) {
                loadAllowed = true;
            } else if (args[i].startsWith("load_image:")) {
                loadStatus = args[i].substring("load_image:".length());
            }
        }
        if (!outDir.exists() && !outDir.mkdirs()) {
            printerr("cannot create output directory: " + outDir);
            return;
        }

        DecompInterface ifc = new DecompInterface();
        // Headless has no tool to inherit options from, so use the defaults
        // explicitly rather than grabbing from a tool that does not exist.
        DecompileOptions opts = new DecompileOptions();
        ifc.setOptions(opts);
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(true);
        if (!ifc.openProgram(currentProgram)) {
            printerr("decompiler failed to open program: " + ifc.getLastMessage());
            return;
        }

        List<String> failures = new ArrayList<>();
        List<String> records = new ArrayList<>();
        List<Function> exported = new ArrayList<>();
        int ok = 0, bad = 0;

        PrintWriter c = new PrintWriter(new File(outDir, "decompiled.c"), StandardCharsets.UTF_8);
        c.println("/* Decompiled by Ghidra " + ghidra.framework.Application.getApplicationVersion());
        c.println(" * program : " + currentProgram.getName());
        c.println(" * language: " + currentProgram.getLanguageID());
        c.println(" * NOTE: machine output. Every line is a hypothesis, not a fact.");
        c.println(" */");
        c.println();

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            monitor.setMessage("decompiling " + f.getName());

            DecompileResults res = ifc.decompileFunction(f, TIMEOUT_SECONDS, monitor);
            String addr = f.getEntryPoint().toString();
            long size = f.getBody().getNumAddresses();

            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                c.println("/* ---- " + f.getName() + " @ " + addr
                        + "  (" + size + " bytes) ---- */");
                c.println(res.getDecompiledFunction().getC());
                c.println();
                ok++;
            } else {
                String why = (res == null) ? "null result" : res.getErrorMessage();
                failures.add(addr + "  " + f.getName() + "  : " + why);
                bad++;
            }

            records.add(functionRecord(f, addr, size,
                    res != null && res.decompileCompleted()));
            exported.add(f);
        }
        c.close();
        ifc.dispose();

        PrintWriter j = new PrintWriter(new File(outDir, "functions.json"), StandardCharsets.UTF_8);
        j.println("{");
        j.println("  \"program\": " + quote(currentProgram.getName()) + ",");
        j.println("  \"language\": " + quote(currentProgram.getLanguageID().toString()) + ",");
        j.println("  \"image_base\": " + quote(currentProgram.getImageBase().toString()) + ",");
        j.println("  \"target\": " + targetRecord() + ",");
        j.println("  \"observed_profile\": " + observedProfile() + ",");
        if (loadStatus != null) {
            // corrections: null when CorrectMzLoad.java never ran, a count
            // (0 for a clean file) when it did, so a reader can tell a clean
            // load from a corrected one.
            String count = currentProgram.getOptions(Program.PROGRAM_INFO)
                    .getString(CORRECTION_COUNT, null);
            j.println("  \"load_image\": {\"status\": " + quote(loadStatus)
                    + ", \"corrections\": " + (count == null ? "null" : count)
                    + ", \"mismatch_allowed\": " + loadAllowed
                    + ", \"record\": \"loadimage.json\"},");
        }
        j.println("  \"decompiled_ok\": " + ok + ",");
        j.println("  \"decompiled_failed\": " + bad + ",");
        j.println("  \"functions\": [");
        for (int i = 0; i < records.size(); i++) {
            j.println("    " + records.get(i) + (i + 1 < records.size() ? "," : ""));
        }
        j.println("  ],");
        List<String> overlaps = bodyOverlaps(exported);
        j.println("  \"body_overlaps\": [");
        for (int i = 0; i < overlaps.size(); i++) {
            j.println("    " + overlaps.get(i) + (i + 1 < overlaps.size() ? "," : ""));
        }
        j.println("  ],");
        // Filled by bodyOverlaps' walks: jumps into the entry of a function
        // something calls, which end a walk instead of extending a claim.
        List<String> tails = new ArrayList<>(tailCalls.values());
        j.println("  \"tail_calls\": [");
        for (int i = 0; i < tails.size(); i++) {
            j.println("    " + tails.get(i) + (i + 1 < tails.size() ? "," : ""));
        }
        j.println("  ]");
        j.println("}");
        j.close();

        if (!failures.isEmpty()) {
            PrintWriter fw = new PrintWriter(new File(outDir, "failures.txt"), StandardCharsets.UTF_8);
            for (String s : failures) {
                fw.println(s);
            }
            fw.close();
        }

        println("ExportDecompiledC: " + ok + " decompiled, " + bad + " failed -> " + outDir);
    }

    /* Which file this export describes. The hash is computed over the
     * program's own copy of the file bytes -- what the analysis actually read
     * -- rather than taken from the import metadata. Tools that read
     * functions.json beside an executable compare it with the executable they
     * were given (tools/evidence.py), so an export of last week's build cannot
     * be read against this week's without anything saying so. */
    private String targetRecord() throws Exception {
        String path = currentProgram.getExecutablePath();
        // Ghidra keeps a Windows path as "/C:/dir/file"; drop the slash so the
        // path opens as written.
        if (path != null && path.matches("^/[A-Za-z]:/.*")) {
            path = path.substring(1);
        }
        long size = -1;
        String sha = currentProgram.getExecutableSHA256();
        List<FileBytes> all = currentProgram.getMemory().getAllFileBytes();
        if (!all.isEmpty()) {
            FileBytes fb = all.get(0);
            size = fb.getSize();
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[65536];
            for (long at = 0; at < size; at += buf.length) {
                int n = (int) Math.min(buf.length, size - at);
                fb.getOriginalBytes(at, buf, 0, n);
                md.update(buf, 0, n);
            }
            StringBuilder hex = new StringBuilder();
            for (byte b : md.digest()) {
                hex.append(String.format("%02x", b));
            }
            sha = hex.toString();
        }
        return "{\"path\": " + quote(path) + ", \"size\": " + size
                + ", \"sha256\": " + quote(sha) + "}";
    }

    /** Written by RecoverFunctions.java when it runs; the same key. */
    private static final String RECOVERY_OPTION = "DOS-Decompiler RecoverFunctions SHA-256";

    /** Written by CorrectMzLoad.java when it runs; the same keys. */
    private static final String CORRECTION_HASH = "DOS-Decompiler CorrectMzLoad SHA-256";
    private static final String CORRECTION_COUNT = "DOS-Decompiler CorrectMzLoad corrections";

    /* What Ghidra actually did with this program, in the terms tools/analysis_profile.py
     * expects. The pipeline compares the two after export and stops on any
     * difference. Nothing here decides what is right; it only reports. */
    private String observedProfile() throws Exception {
        String recovery = currentProgram.getOptions(Program.PROGRAM_INFO)
                .getString(RECOVERY_OPTION, null);
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"loader\": ").append(quote(currentProgram.getExecutableFormat())).append(", ");
        sb.append("\"language\": ")
          .append(quote(currentProgram.getLanguageID().toString())).append(", ");
        sb.append("\"compiler_spec\": ")
          .append(quote(currentProgram.getCompilerSpec().getCompilerSpecID().toString()))
          .append(", ");
        sb.append("\"image_base\": ")
          .append(quote(currentProgram.getImageBase().toString())).append(", ");
        sb.append("\"load_segment\": ").append(quote(observedLoadSegment())).append(", ");
        sb.append("\"address_convention\": ").append(quote(observedConvention())).append(", ");
        sb.append("\"ghidra_version\": ")
          .append(quote(ghidra.framework.Application.getApplicationVersion())).append(", ");
        sb.append("\"recovery\": {\"ran\": ").append(recovery != null)
          .append(", \"script_sha256\": ").append(quote(recovery)).append("}, ");
        // This script's own source and the helper it uses, by the rule the
        // profile hashes them with, so the handshake holds the exporter to
        // the copy in this checkout the way it holds recovery.
        sb.append("\"export\": {\"script_sha256\": ")
          .append(quote(LoadImageMap.sourceSha256(getSourceFile())))
          .append(", \"helper_sha256\": ")
          .append(quote(LoadImageMap.helperSha256(getSourceFile()))).append("}, ");
        // The corrector's mark, as RecoverFunctions' is read above: whether it
        // ran on this program, which copy, and how many corrections it made.
        String correction = currentProgram.getOptions(Program.PROGRAM_INFO)
                .getString(CORRECTION_HASH, null);
        String corrections = currentProgram.getOptions(Program.PROGRAM_INFO)
                .getString(CORRECTION_COUNT, null);
        sb.append("\"load_correction\": {\"ran\": ").append(correction != null)
          .append(", \"script_sha256\": ").append(quote(correction))
          .append(", \"corrections\": ").append(corrections == null ? "null" : corrections)
          .append("}");
        return sb.append("}").toString();
    }

    /* The segment the first byte of the load image was put at, worked out
     * from where the file's bytes landed (LoadImageMap.loadSegment, which
     * DumpLoadImage.java reports too). */
    private String observedLoadSegment() throws Exception {
        return LoadImageMap.loadSegment(currentProgram);
    }

    /* Whether every address this export writes has the form its readers
     * parse -- four lowercase hex digits, a colon, four more -- or the first
     * one that does not. */
    private String observedConvention() {
        String base = currentProgram.getImageBase().toString();
        if (!base.matches("[0-9a-f]{4}:[0-9a-f]{4}")) {
            return "other: " + base;
        }
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            String s = f.getEntryPoint().toString();
            if (!s.matches("[0-9a-f]{4}:[0-9a-f]{4}")) {
                return "other: " + s;
            }
        }
        return "ssss:oooo";
    }

    private String functionRecord(Function f, String addr, long size, boolean okFlag) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"name\": ").append(quote(f.getName())).append(", ");
        sb.append("\"entry\": ").append(quote(addr)).append(", ");
        sb.append("\"size\": ").append(size).append(", ");
        sb.append("\"thunk\": ").append(f.isThunk()).append(", ");
        sb.append("\"external\": ").append(f.isExternal()).append(", ");
        sb.append("\"calling_convention\": ")
          .append(quote(String.valueOf(f.getCallingConventionName()))).append(", ");
        sb.append("\"return_type\": ")
          .append(quote(f.getReturnType().getDisplayName())).append(", ");
        sb.append("\"param_count\": ").append(f.getParameterCount()).append(", ");
        sb.append("\"params\": [");
        Parameter[] ps = f.getParameters();
        for (int i = 0; i < ps.length; i++) {
            sb.append(quote(ps[i].getDataType().getDisplayName() + " " + ps[i].getName()));
            if (i + 1 < ps.length) {
                sb.append(", ");
            }
        }
        sb.append("], ");
        sb.append("\"decompiled\": ").append(okFlag).append(", ");
        appendFingerprint(sb, f);
        sb.append(", \"origin\": ").append(quote(origin(f)));
        sb.append(", \"body\": ").append(bodyRecord(f));
        sb.append("}");
        return sb.toString();
    }

    /** Written by RecoverFunctions.java for each function it creates; the same name. */
    private static final String ORIGIN_MAP = "DOS-Decompiler function origin";

    /* Why this function exists. RecoverFunctions.java marks every function it
     * creates with the evidence it used; a function with no mark is Ghidra's
     * own, because the MZ loader creates none (measured: an import without
     * analysis holds no functions). */
    private String origin(Function f) {
        StringPropertyMap map = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap(ORIGIN_MAP);
        String mark = map == null ? null : map.getString(f.getEntryPoint());
        return mark == null ? "ghidra-analysis" : mark;
    }

    /* The function's body as Ghidra holds it: every address range, ends
     * inclusive, and what follows from them.
     *
     * `size`, kept beside it as it always was, is getBody().getNumAddresses():
     * the count of addresses in the body, the same as total_bytes here. It is
     * not the distance from the lowest address to the highest -- that is
     * span_bytes -- and the two differ for every non-contiguous function, a
     * jump table in the middle of one for instance (measured). */
    private String bodyRecord(Function f) {
        AddressSetView body = f.getBody();
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"available\": ").append(!body.isEmpty()).append(", ");
        sb.append("\"provenance\": \"ghidra-function-body-address-set\", ");
        sb.append("\"ranges\": [");
        long lowest = Long.MAX_VALUE, highest = -1;
        boolean first = true;
        for (AddressRange r : body.getAddressRanges()) {
            long lo = LoadImageMap.linear(r.getMinAddress());
            long hi = LoadImageMap.linear(r.getMaxAddress());
            lowest = Math.min(lowest, lo);
            highest = Math.max(highest, hi);
            if (!first) {
                sb.append(", ");
            }
            sb.append(rangeRecord(r.getMinAddress().toString(), r.getMaxAddress().toString(), lo, hi));
            first = false;
        }
        long total = body.getNumAddresses();
        long span = highest < 0 ? 0 : highest - lowest + 1;
        sb.append("], ");
        sb.append("\"total_bytes\": ").append(total).append(", ");
        sb.append("\"span_bytes\": ").append(span).append(", ");
        sb.append("\"non_contiguous\": ").append(total != span).append(", ");
        sb.append("\"contains_entry\": ").append(body.contains(f.getEntryPoint()));
        return sb.append("}").toString();
    }

    private String rangeRecord(String start, String end, long lo, long hi) {
        return "{\"start\": " + quote(start) + ", \"end\": " + quote(end)
                + ", \"start_linear\": " + quote(String.format("0x%x", lo))
                + ", \"end_linear\": " + quote(String.format("0x%x", hi)) + "}";
    }

    /* Bytes more than one function claims, and which functions -- reported,
     * never resolved.
     *
     * Ghidra 12.1.2 does not let two function bodies overlap: setBody and
     * createFunction both throw OverlappingFunctionException (measured). So
     * the bodies themselves never share a byte, and code two functions both
     * run shows up another way: one function leaves its own body, by a jump
     * or by falling through, into a body Ghidra gave to another. Two
     * functions jumping to one epilogue come out as three functions, the
     * epilogue its own; a jump into the middle of a neighbour lands inside
     * the neighbour's body. A consumer that treats a body as everything a
     * function runs, and only what it runs, is wrong about both.
     *
     * So a function claims its body ("body"), and also the code it reaches
     * from each exit of its body ("jump", "fallthrough"): followed through
     * jumps and fall-throughs, stepping over calls, until it returns, comes
     * back into the function's own body, leaves every function's body, or
     * reaches the entry of a function something calls -- a tail call, listed
     * in `tail_calls` and not claimed (see walk). A byte two or more
     * functions claim is listed. Body against body is
     * checked as well, so a Ghidra that allows overlapping bodies would show
     * it here rather than be assumed not to. */
    private List<String> bodyOverlaps(List<Function> functions) {
        List<Claim> claims = new ArrayList<>();
        for (Function f : functions) {
            for (AddressRange r : f.getBody().getAddressRanges()) {
                claims.add(new Claim(LoadImageMap.linear(r.getMinAddress()),
                        LoadImageMap.linear(r.getMaxAddress()), f, "body", null, false));
            }
            claims.addAll(exitClaims(f));
        }

        // A sweep over every claim's start and end: between two consecutive
        // boundaries the set of claims is constant.
        TreeSet<Long> cuts = new TreeSet<>();
        for (Claim c : claims) {
            cuts.add(c.lo);
            cuts.add(c.hi + 1);
        }
        List<String> out = new ArrayList<>();
        long runLo = -1, runHi = -1;
        String runWho = null;
        Long previous = null;
        for (Long cut : cuts) {
            if (previous != null) {
                long lo = previous, hi = cut - 1;
                String who = claimants(claims, lo, hi);
                if (who != null && who.equals(runWho) && lo == runHi + 1) {
                    runHi = hi;
                } else {
                    if (runWho != null) {
                        out.add(overlapRecord(runLo, runHi, runWho));
                    }
                    runLo = lo;
                    runHi = hi;
                    runWho = who;
                }
            }
            previous = cut;
        }
        if (runWho != null) {
            out.add(overlapRecord(runLo, runHi, runWho));
        }
        return out;
    }

    /** One function's claim on a run of linear addresses, ends inclusive. */
    private static final class Claim {
        final long lo, hi;
        final Function f;
        final String how;
        final Address via;
        final boolean partial;

        Claim(long lo, long hi, Function f, String how, Address via, boolean partial) {
            this.lo = lo;
            this.hi = hi;
            this.f = f;
            this.how = how;
            this.via = via;
            this.partial = partial;
        }
    }

    /* The functions claiming every byte of [lo, hi], as the JSON list the
     * record carries, or null when fewer than two functions do. */
    private String claimants(List<Claim> claims, long lo, long hi) {
        java.util.TreeMap<String, java.util.TreeMap<String, TreeSet<String>>> by =
                new java.util.TreeMap<>();
        java.util.Map<String, Function> fn = new java.util.HashMap<>();
        Set<String> partial = new TreeSet<>();
        for (Claim c : claims) {
            if (c.lo > lo || c.hi < hi) {
                continue;
            }
            String entry = c.f.getEntryPoint().toString();
            fn.put(entry, c.f);
            TreeSet<String> via = by.computeIfAbsent(entry, k -> new java.util.TreeMap<>())
                    .computeIfAbsent(c.how, k -> new TreeSet<>());
            if (c.via != null) {
                via.add(c.via.toString());
            }
            if (c.partial) {
                partial.add(entry + " " + c.how);
            }
        }
        if (by.size() < 2) {
            return null;
        }
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String entry : by.keySet()) {
            for (java.util.Map.Entry<String, TreeSet<String>> how : by.get(entry).entrySet()) {
                if (!first) {
                    sb.append(", ");
                }
                sb.append("{\"entry\": ").append(quote(entry))
                  .append(", \"name\": ").append(quote(fn.get(entry).getName()))
                  .append(", \"claim\": ").append(quote(how.getKey()));
                if (!how.getKey().equals("body")) {
                    sb.append(", \"via\": ").append(strArray(how.getValue()));
                    if (partial.contains(entry + " " + how.getKey())) {
                        sb.append(", \"walk_limit_reached\": true");
                    }
                }
                sb.append("}");
                first = false;
            }
        }
        return sb.append("]").toString();
    }

    private String overlapRecord(long lo, long hi, String who) {
        Address start = LoadImageMap.addressOf(currentProgram, lo);
        Address end = LoadImageMap.addressOf(currentProgram, hi);
        return "{\"start\": " + quote(start == null ? null : start.toString())
                + ", \"end\": " + quote(end == null ? null : end.toString())
                + ", \"start_linear\": " + quote(String.format("0x%x", lo))
                + ", \"end_linear\": " + quote(String.format("0x%x", hi))
                + ", \"bytes\": " + (hi - lo + 1)
                + ", \"functions\": " + who + "}";
    }

    /** Instructions one exit walk may follow before it stops and says so. */
    private static final int WALK_LIMIT = 65536;

    /* What a function reaches outside its own body without calling: from each
     * jump whose target, and each fall-through whose next instruction, lies in
     * another function's body. Jumps are told from calls by the mnemonic
     * rather than the flow type, because Ghidra overrides a jump to another
     * function's entry into a call-return, and that override is exactly the
     * case being looked for. */
    private List<Claim> exitClaims(Function f) {
        List<Claim> out = new ArrayList<>();
        AddressSetView own = f.getBody();
        InstructionIterator ii = currentProgram.getListing().getInstructions(own, true);
        while (ii.hasNext()) {
            Instruction ins = ii.next();
            List<Address> targets = new ArrayList<>();
            List<String> hows = new ArrayList<>();
            if (isJump(ins)) {
                for (Address d : ins.getFlows()) {
                    targets.add(d);
                    hows.add("jump");
                }
            }
            // Not past a call or an interrupt: Ghidra gives both a
            // fall-through, but the one at the end of a body is often the
            // DOS exit or a routine that never returns, and the bytes after it
            // are the next function, not more of this one (measured: the
            // startup's `int 0x21` exit "falling through" into main).
            Address next = ins.getFallThrough();
            if (next != null && !callsOut(ins)) {
                targets.add(next);
                hows.add("fallthrough");
            }
            for (int i = 0; i < targets.size(); i++) {
                Address d = targets.get(i);
                if (own.contains(d)) {
                    continue;
                }
                Function other = currentProgram.getFunctionManager().getFunctionContaining(d);
                if (other == null || other == f) {
                    continue;
                }
                boolean[] limited = {false};
                AddressSet reached = walk(d, ins.getAddress(), hows.get(i), own, limited);
                for (AddressRange r : reached.getAddressRanges()) {
                    out.add(new Claim(LoadImageMap.linear(r.getMinAddress()),
                            LoadImageMap.linear(r.getMaxAddress()), f, hows.get(i),
                            ins.getAddress(), limited[0]));
                }
            }
        }
        return out;
    }

    private static boolean isJump(Instruction ins) {
        String mn = ins.getMnemonicString().toUpperCase();
        return mn.startsWith("J") || mn.startsWith("LOOP");
    }

    private boolean sameBody(Address a, Address b) {
        Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
        return f != null && f.getBody().contains(b);
    }

    private static boolean callsOut(Instruction ins) {
        String mn = ins.getMnemonicString().toUpperCase();
        return mn.startsWith("CALL") || mn.startsWith("INT");
    }

    /* Every instruction reachable from `start` by jumps and fall-throughs,
     * staying inside function bodies and out of `own`. A call or interrupt is
     * stepped over only when it returns into the body it was made from, by
     * the same reasoning as in exitClaims.
     *
     * Reaching the entry of a function something calls is a tail call, not a
     * claim: that function is a real one, and following it would claim all
     * the code it reaches (measured, prompt 03: one range of adventur's
     * claimed by 32 functions, 26,100 bytes claimed by two or more). The walk
     * stops there and the jump is recorded in `tail_calls`. An entry nothing
     * calls -- an epilogue Ghidra split off, a fall-through RecoverFunctions
     * cut at a prologue -- is a fragment of whoever runs into it, and is
     * claimed and walked as before. `via` and `how` are the instruction that
     * led to `start` and the way it did. */
    private AddressSet walk(Address start, Address via, String how, AddressSetView own,
            boolean[] limited) {
        AddressSet seen = new AddressSet();
        java.util.ArrayDeque<Object[]> todo = new java.util.ArrayDeque<>();
        todo.push(new Object[] {start, via, how});
        int steps = 0;
        while (!todo.isEmpty()) {
            Object[] step = todo.pop();
            Address a = (Address) step[0];
            if (own.contains(a) || seen.contains(a)) {
                continue;
            }
            Function g = currentProgram.getFunctionManager().getFunctionContaining(a);
            if (g == null) {
                continue;
            }
            if (g.getEntryPoint().equals(a) && isCalled(g)) {
                recordTailCall((Address) step[1], g, (String) step[2]);
                continue;
            }
            Instruction ins = currentProgram.getListing().getInstructionAt(a);
            if (ins == null) {
                continue;
            }
            if (++steps > WALK_LIMIT) {
                limited[0] = true;
                break;
            }
            seen.add(ins.getMinAddress(), ins.getMaxAddress());
            if (isJump(ins)) {
                for (Address d : ins.getFlows()) {
                    todo.push(new Object[] {d, ins.getAddress(), "jump"});
                }
            }
            Address next = ins.getFallThrough();
            if (next != null && (!callsOut(ins) || sameBody(a, next))) {
                todo.push(new Object[] {next, ins.getAddress(), "fallthrough"});
            }
        }
        return seen;
    }

    private final java.util.Map<Address, Boolean> called = new java.util.HashMap<>();

    /* Does any instruction call this function? Told by the calling
     * instruction's mnemonic, not the reference type: Ghidra overrides a
     * jump to a function's entry into a call-return, and that jump is a tail
     * call, not a call. A pointer to the function in data is not a call
     * either: a routine reached only through a table counts as uncalled. */
    private boolean isCalled(Function g) {
        return called.computeIfAbsent(g.getEntryPoint(), entry -> {
            for (ghidra.program.model.symbol.Reference ref
                    : currentProgram.getReferenceManager().getReferencesTo(entry)) {
                Instruction from = currentProgram.getListing().getInstructionAt(ref.getFromAddress());
                if (from != null && from.getMnemonicString().toUpperCase().startsWith("CALL")) {
                    return true;
                }
            }
            return false;
        });
    }

    private final java.util.TreeMap<String, String> tailCalls = new java.util.TreeMap<>();

    /* A jump (or fall-through) from one function into the entry of a called
     * one. The caller is the function whose body holds the instruction, so a
     * tail call met while walking a fragment is the fragment's, said once. */
    private void recordTailCall(Address via, Function target, String how) {
        Function caller = currentProgram.getFunctionManager().getFunctionContaining(via);
        if (caller == null) {
            return;
        }
        String key = String.format("%010x %010x %s", LoadImageMap.linear(via),
                LoadImageMap.linear(target.getEntryPoint()), how);
        tailCalls.put(key, "{\"caller\": " + quote(caller.getEntryPoint().toString())
                + ", \"caller_name\": " + quote(caller.getName())
                + ", \"target\": " + quote(target.getEntryPoint().toString())
                + ", \"target_name\": " + quote(target.getName())
                + ", \"via\": " + quote(via.toString())
                + ", \"how\": " + quote(how) + "}");
    }

    /* The fingerprint is what makes a function identifiable without symbols:
     * who it calls, which unusual constants it mentions, which interrupts and
     * I/O ports it touches. Names change between builds; these rarely do. */
    private void appendFingerprint(StringBuilder sb, Function f) {
        Set<String> callees = new TreeSet<>();
        try {
            for (Function callee : f.getCalledFunctions(monitor)) {
                callees.add(callee.getEntryPoint().toString());
            }
        } catch (Exception e) {
            // getCalledFunctions can throw on damaged flow; an empty callee
            // set is a truthful answer here, not a silent failure.
        }

        // String literals a function touches are the strongest identifier of
        // all: a routine that references "Sopwith" is the title screen, in any
        // build, under any name.
        Set<String> strings = new TreeSet<>();
        Set<String> dataRefs = new TreeSet<>();
        Set<Long> scalars = new TreeSet<>();
        Set<Long> interrupts = new TreeSet<>();
        Set<Long> ports = new TreeSet<>();
        int instructionCount = 0;
        Set<String> mnemonics = new TreeSet<>();

        InstructionIterator ii = currentProgram.getListing()
                .getInstructions(f.getBody(), true);
        while (ii.hasNext()) {
            Instruction ins = ii.next();
            instructionCount++;
            String mn = ins.getMnemonicString().toUpperCase();
            mnemonics.add(mn);

            for (ghidra.program.model.symbol.Reference ref : ins.getReferencesFrom()) {
                if (!ref.getToAddress().isMemoryAddress()) {
                    continue;
                }
                ghidra.program.model.listing.Data d =
                        currentProgram.getListing().getDataAt(ref.getToAddress());
                if (d != null && d.hasStringValue()) {
                    Object v = d.getValue();
                    if (v != null) {
                        String s = v.toString().trim();
                        if (s.length() >= 3) {
                            strings.add(s);
                        }
                    }
                }
            }

            // Which global variables a function touches reveals which
            // translation unit it came from: file-scope data is shared inside
            // a module and rarely across modules.
            //
            // Ghidra creates almost no data references here -- in real mode a
            // direct access is "mov ax,[0x1234]" with the segment living in DS
            // at run time, so static analysis cannot resolve a target address
            // and emits no reference (measured: 2 of 289 functions had any).
            // The displacement itself is still perfectly usable as an
            // identifier, so take it straight from the operand.
            for (int op = 0; op < ins.getNumOperands(); op++) {
                String rep = ins.getDefaultOperandRepresentation(op);
                if (rep == null || rep.indexOf('[') < 0) {
                    continue;               // not a memory operand
                }
                for (Object o : ins.getOpObjects(op)) {
                    if (o instanceof Scalar) {
                        long v = ((Scalar) o).getUnsignedValue();
                        // Small values are stack-frame offsets relative to BP,
                        // not globals; they say nothing about the module.
                        if (v >= 0x20 && v <= 0xFFFF && rep.indexOf("BP") < 0
                                && rep.indexOf("SP") < 0) {
                            dataRefs.add(String.format("%04x", v));
                        }
                    }
                }
            }

            for (int op = 0; op < ins.getNumOperands(); op++) {
                Scalar s = ins.getScalar(op);
                if (s == null) {
                    continue;
                }
                long v = s.getUnsignedValue();
                if (mn.equals("INT")) {
                    interrupts.add(v);
                } else if (mn.equals("IN") || mn.equals("OUT")) {
                    ports.add(v);
                }
                // Constants below 0x10 appear everywhere and carry no
                // identifying information; skip them to keep the fingerprint
                // discriminating.
                if (v >= 0x10) {
                    scalars.add(v);
                }
            }
        }

        sb.append("\"instruction_count\": ").append(instructionCount).append(", ");
        appendControlFlow(sb, f);
        sb.append("\"calls\": ").append(strArray(callees)).append(", ");
        sb.append("\"scalars\": ").append(longArray(scalars)).append(", ");
        sb.append("\"interrupts\": ").append(longArray(interrupts)).append(", ");
        sb.append("\"io_ports\": ").append(longArray(ports)).append(", ");
        sb.append("\"strings\": ").append(strArray(strings)).append(", ");
        sb.append("\"data_refs\": ").append(strArray(dataRefs)).append(", ");
        sb.append("\"mnemonics\": ").append(strArray(mnemonics));
    }

    /* Shape of the function's control-flow graph.
     *
     * Constants and strings are what a compiler is most free to move around;
     * the decision structure is what it must preserve. An `if` in the source
     * has to become a conditional branch in the binary, a loop has to become a
     * back edge. So cyclomatic complexity and loop count survive compilation
     * far better than any byte-level feature, and can be compared against the
     * same quantities counted in C source.
     */
    private void appendControlFlow(StringBuilder sb, Function f) {
        int blocks = 0, edges = 0, backEdges = 0, returns = 0, indirect = 0;
        try {
            ghidra.program.model.block.BasicBlockModel model =
                    new ghidra.program.model.block.BasicBlockModel(currentProgram);
            ghidra.program.model.block.CodeBlockIterator it =
                    model.getCodeBlocksContaining(f.getBody(), monitor);
            while (it.hasNext()) {
                ghidra.program.model.block.CodeBlock block = it.next();
                blocks++;
                int outgoing = 0;
                ghidra.program.model.block.CodeBlockReferenceIterator dests =
                        block.getDestinations(monitor);
                while (dests.hasNext()) {
                    ghidra.program.model.block.CodeBlockReference ref = dests.next();
                    ghidra.program.model.address.Address to =
                            ref.getDestinationAddress();
                    if (!f.getBody().contains(to)) {
                        continue;         // a call leaving the function
                    }
                    outgoing++;
                    edges++;
                    // An edge going backwards inside the function closes a
                    // loop. Counting these is the cheapest reliable loop count.
                    if (to.compareTo(block.getFirstStartAddress()) <= 0) {
                        backEdges++;
                    }
                }
                if (outgoing == 0) {
                    returns++;
                }
            }
        } catch (Exception e) {
            // A damaged or unusual function yields no graph. Reporting zeros
            // is honest: the matcher treats a zero as "no evidence".
        }

        ghidra.program.model.listing.InstructionIterator ii =
                currentProgram.getListing().getInstructions(f.getBody(), true);
        while (ii.hasNext()) {
            ghidra.program.model.listing.Instruction ins = ii.next();
            String mn = ins.getMnemonicString().toUpperCase();
            if ((mn.equals("JMP") || mn.equals("CALL"))
                    && ins.getNumOperands() > 0
                    && ins.getScalar(0) == null) {
                indirect++;               // jump table or call through pointer
            }
        }

        // McCabe: edges - nodes + 2. Equivalent to counting decision points.
        int cyclomatic = blocks > 0 ? edges - blocks + 2 : 0;

        sb.append("\"blocks\": ").append(blocks).append(", ");
        sb.append("\"edges\": ").append(edges).append(", ");
        sb.append("\"loops\": ").append(backEdges).append(", ");
        sb.append("\"returns\": ").append(returns).append(", ");
        sb.append("\"indirect_jumps\": ").append(indirect).append(", ");
        sb.append("\"cyclomatic\": ").append(Math.max(0, cyclomatic)).append(", ");
    }

    /** True when the address lies in a block that holds defined functions.
     *
     * Ghidra's MZ loader marks every segment executable, so isExecute() cannot
     * distinguish code from data. Presence of a defined function is evidence
     * rather than a flag, so that is what is used.
     */
    private boolean inCodeSegment(ghidra.program.model.address.Address a) {
        ghidra.program.model.mem.MemoryBlock blk = currentProgram.getMemory().getBlock(a);
        if (blk == null) {
            return false;
        }
        if (codeBlockNames == null) {
            codeBlockNames = new TreeSet<>();
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                ghidra.program.model.mem.MemoryBlock b =
                        currentProgram.getMemory().getBlock(f.getEntryPoint());
                if (b != null) {
                    codeBlockNames.add(b.getName());
                }
            }
        }
        return codeBlockNames.contains(blk.getName());
    }

    private Set<String> codeBlockNames = null;

    private String strArray(Set<String> items) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String s : items) {
            if (!first) {
                sb.append(", ");
            }
            sb.append(quote(s));
            first = false;
        }
        return sb.append("]").toString();
    }

    private String longArray(Set<Long> items) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Long v : items) {
            if (!first) {
                sb.append(", ");
            }
            sb.append(v);
            first = false;
        }
        return sb.append("]").toString();
    }

    private String quote(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("\"");
        for (char ch : s.toCharArray()) {
            switch (ch) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (ch < 0x20) {
                        sb.append(String.format("\\u%04x", (int) ch));
                    } else {
                        sb.append(ch);
                    }
            }
        }
        return sb.append('"').toString();
    }
}
