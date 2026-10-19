/* ApplyNames.java -- write recovered names back into the Ghidra database,
 * checked before and after.
 *
 * Takes a mapping of names to function entries -- tools/match.py's --json
 * output or tools/anchors.py's --names output, which share one shape --
 * and renames the functions, so a re-export produces C where the calls read
 * `swmove()` instead of `FUN_1000_02f6()`. That single change is most of the
 * difference between output nobody can follow and output a person can work
 * through. A wrong name is worse than no name -- it is a lie that survives
 * into every later reading of the code -- so the writing is guarded at both
 * ends:
 *
 *   * Before anything is written, every entry is validated: the address is a
 *     function's entry, not a byte inside a body; the name is legal for
 *     Ghidra and for C; no two entries give one name to two functions, and
 *     no entry takes a name another function or label in the program keeps
 *     (tools/annotate.py's clash rule on the .COM route). One failing entry
 *     and nothing is written.
 *   * Every write happens in one transaction, and every name and comment is
 *     read back and compared with what was asked. One difference, or one
 *     exception, and the whole transaction is aborted.
 *
 * And the two old safeguards: a confidence floor below which an entry is
 * skipped, and a "certain" level below which a name is suffixed `__maybe`,
 * so uncertainty stays visible in the decompiled output.
 *
 * Comments, per entry, both optional: `comment` is the plate comment above
 * the function -- what this script has always written -- and
 * `inline_comment` the end-of-line comment at its entry. A string sets one,
 * "" clears it, and a missing field leaves it as it is. This script's own
 * note on the name -- its confidence, LOW CONFIDENCE, LONG ROUTINE -- goes in
 * the PRE comment at the entry, which decompiled.c prints at the top of the
 * function's body (measured: plate and PRE are printed, EOL and repeatable
 * comments are not), so it no longer competes with the plate comment for
 * room.
 *
 * Transactions, measured on Ghidra 12.1.2 (knowledge/04-pitfalls.md): a
 * headless script already runs inside one the framework opened. A
 * transaction this script starts is a sub-transaction; ending it with
 * commit=false marks the framework's aborted, and every change the script
 * made -- before it as well as inside it -- is discarded when the script
 * ends. A script that throws instead has its changes *saved*. So nothing
 * here is allowed to escape: every failure is caught and turned into an
 * abort.
 *
 * Output: <outdir>/applynames-record.json, each entry with what was asked,
 * what was stored and the outcome. tools/applynames.py runs this and turns
 * the record into the evidence envelope applynames-result.json, with an exit
 * status, because a headless run's exit code says nothing about its script
 * (measured: 0 even when the script throws).
 *
 * Usage (headless; arguments after the mapping in any order):
 *   -postScript ApplyNames.java mapping.json [minScore] [certainScore] [dryrun] [out:DIR]
 *
 * DOS_DECOMPILER_APPLYNAMES_FAULT=readback|throw makes the last write's
 * readback differ, or its setter throw. It exists so a test can prove the
 * rollback; it announces itself, and is never for real work.
 *
 * @category DOS.Decompile
 */

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;

public class ApplyNames extends GhidraScript {

    /** Above this, a routine is long enough that evidence from one part of it
     *  says little about the rest. Chosen to sit well above the size of the
     *  small BIOS and DOS wrappers that evidence-based naming identifies
     *  reliably. */
    private static final long LONG_ROUTINE_BYTES = 200;

    static final String FAULT_VARIABLE = "DOS_DECOMPILER_APPLYNAMES_FAULT";

    /* Words a C compiler of the period reserves, the ANSI ones and the
     * extensions Microsoft C and Turbo C added. A function named one of
     * these exports as C that does not compile. */
    private static final Set<String> C_KEYWORDS = new HashSet<>(Arrays.asList(
            "auto", "break", "case", "char", "const", "continue", "default", "do",
            "double", "else", "enum", "extern", "float", "for", "goto", "if", "int",
            "long", "register", "return", "short", "signed", "sizeof", "static",
            "struct", "switch", "typedef", "union", "unsigned", "void", "volatile",
            "while", "inline", "restrict", "far", "near", "huge", "cdecl", "pascal",
            "fortran", "interrupt", "asm"));

    /** One mapping entry and everything that happens to it. */
    private static final class Entry {
        int index;
        String address, source, applied, reason, outcome;
        Double score;
        boolean provisional, longRoutine;
        String comment, inline;              // null: leave alone; "": clear
        boolean hasComment, hasInline;
        Function function;
        String previousName, storedName, expectedQualified;
        String note, storedNote, storedComment, storedInline;
    }

    private final List<Entry> entries = new ArrayList<>();
    private final List<String> problems = new ArrayList<>();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: ApplyNames.java mapping.json [minScore] [certainScore] [dryrun] [out:DIR]");
            return;
        }
        File mappingFile = new File(args[0]);
        double minScore = 0.45, certain = 0.70;
        boolean dryRun = false;
        File outDir = mappingFile.getAbsoluteFile().getParentFile();
        List<Double> numbers = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("dryrun")) {
                dryRun = true;
            } else if (args[i].startsWith("out:")) {
                outDir = new File(args[i].substring(4));
            } else {
                numbers.add(Double.parseDouble(args[i]));
            }
        }
        if (numbers.size() > 0) {
            minScore = numbers.get(0);
        }
        if (numbers.size() > 1) {
            certain = numbers.get(1);
        }
        String fault = System.getenv(FAULT_VARIABLE);
        if (fault != null && !fault.isEmpty()) {
            printerr("ApplyNames: " + FAULT_VARIABLE + "=" + fault
                    + " -- a fault is being injected for a test; nothing this run "
                    + "does is to be kept");
        }

        String phase;
        String transaction = "none";
        if (!read(mappingFile)) {
            phase = "refused";
        } else {
            validate(minScore, certain);
            boolean refused = entries.stream().anyMatch(e -> "refused".equals(e.outcome));
            if (refused || !problems.isEmpty()) {
                for (Entry e : entries) {
                    if (e.outcome == null) {
                        e.outcome = "refused";
                        e.reason = "not written: another entry failed validation, and a "
                                + "batch is written whole or not at all";
                    }
                }
                phase = "refused";
            } else if (dryRun) {
                for (Entry e : entries) {
                    if (e.outcome == null) {
                        e.outcome = "would-apply";
                    }
                }
                phase = "dry-run";
            } else {
                transaction = write(fault);
                phase = transaction.equals("committed") ? "applied" : "rolled-back";
            }
        }
        record(outDir, mappingFile, phase, transaction, dryRun, minScore, certain, fault);

        long applied = entries.stream().filter(e -> "applied".equals(e.outcome)).count();
        println(String.format("ApplyNames: %s -- %d applied, %d below floor %.2f, %d refused, "
                + "%d rolled back -> %s", phase, applied,
                entries.stream().filter(e -> "skipped-below-floor".equals(e.outcome)).count(),
                minScore,
                entries.stream().filter(e -> "refused".equals(e.outcome)).count(),
                entries.stream().filter(e -> "rolled-back".equals(e.outcome)).count(),
                new File(outDir, "applynames-record.json")));
    }

    /* The mapping: {"mapping": [{"source", "binary", "score", ...}]}, the
     * shape match.py --json and anchors.py --names both write. Anything that
     * is not that is a problem with the whole file. */
    private boolean read(File mappingFile) {
        JsonArray list;
        try {
            JsonElement root = JsonParser.parseString(
                    Files.readString(mappingFile.toPath(), StandardCharsets.UTF_8));
            list = root.getAsJsonObject().getAsJsonArray("mapping");
            if (list == null) {
                problems.add("no \"mapping\" list in " + mappingFile);
                return false;
            }
        } catch (Exception e) {
            problems.add("cannot read " + mappingFile + ": " + e.getMessage());
            return false;
        }
        for (int i = 0; i < list.size(); i++) {
            Entry e = new Entry();
            e.index = i;
            entries.add(e);
            if (!list.get(i).isJsonObject()) {
                e.outcome = "refused";
                e.reason = "entry is not an object";
                continue;
            }
            JsonObject o = list.get(i).getAsJsonObject();
            e.source = string(o, "source");
            e.address = string(o, "binary");
            try {
                e.score = o.has("score") && !o.get("score").isJsonNull()
                        ? o.get("score").getAsDouble() : null;
            } catch (Exception x) {
                e.score = null;
            }
            e.hasComment = o.has("comment");
            e.hasInline = o.has("inline_comment");
            if (e.hasComment) {
                e.comment = o.get("comment").isJsonNull() ? null : string(o, "comment");
            }
            if (e.hasInline) {
                e.inline = o.get("inline_comment").isJsonNull() ? null : string(o, "inline_comment");
            }
            if (e.source == null || e.address == null || e.score == null
                    || (e.hasComment && e.comment == null) || (e.hasInline && e.inline == null)) {
                e.outcome = "refused";
                e.reason = "malformed: needs \"source\" and \"binary\" strings and a numeric "
                        + "\"score\"; \"comment\" and \"inline_comment\", when present, strings";
            }
        }
        return true;
    }

    private static String string(JsonObject o, String key) {
        try {
            JsonElement v = o.get(key);
            return v == null || v.isJsonNull() || !v.isJsonPrimitive()
                    || !v.getAsJsonPrimitive().isString() ? null : v.getAsString();
        } catch (Exception x) {
            return null;
        }
    }

    /* Every check, for every entry, before anything is written. */
    private void validate(double minScore, double certain) {
        Map<Function, Entry> byFunction = new HashMap<>();
        for (Entry e : entries) {
            if (e.outcome != null) {
                continue;                          // malformed, already refused
            }
            if (e.score < minScore) {
                e.outcome = "skipped-below-floor";
                e.reason = String.format("score %.3f below the floor %.2f", e.score, minScore);
                continue;
            }
            Address a;
            try {
                a = currentProgram.getAddressFactory().getAddress(e.address);
            } catch (Exception x) {
                a = null;
            }
            if (a == null || !currentProgram.getMemory().contains(a)) {
                refuse(e, "no such address in the program");
                continue;
            }
            Function f = getFunctionAt(a);
            if (f == null) {
                Function inside = getFunctionContaining(a);
                refuse(e, inside != null
                        ? "inside the body of " + inside.getName() + " (entry "
                          + inside.getEntryPoint() + "), not a function entry"
                        : "no function starts here");
                continue;
            }
            e.function = f;
            e.provisional = e.score < certain;
            e.applied = e.provisional ? e.source + "__maybe" : e.source;
            String illegal = illegal(e.applied);
            if (illegal != null) {
                refuse(e, illegal);
                continue;
            }
            Entry other = byFunction.get(f);
            if (other != null && !other.applied.equals(e.applied)) {
                refuse(e, "a second name for " + f.getEntryPoint() + ": entry " + other.index
                        + " names it " + other.applied);
                refuse(other, "a second name for " + f.getEntryPoint() + ": entry " + e.index
                        + " names it " + e.applied);
                continue;
            }
            byFunction.put(f, e);
        }

        // Names, as they would stand once the batch is written: one name may
        // belong to one function. Two entries giving the same name to two
        // functions are both refused; so is an entry taking a name another
        // function keeps, or a label or data item already has.
        Map<String, Function> finalOwner = new HashMap<>();
        Map<String, List<Entry>> batchNames = new HashMap<>();
        for (Entry e : byFunction.values()) {
            if (e.outcome == null) {
                batchNames.computeIfAbsent(e.applied, k -> new ArrayList<>()).add(e);
            }
        }
        for (Function g : currentProgram.getFunctionManager().getFunctions(true)) {
            Entry renamed = byFunction.get(g);
            if (renamed == null || renamed.outcome != null) {
                finalOwner.putIfAbsent(g.getName(), g);
            }
        }
        for (Map.Entry<String, List<Entry>> n : batchNames.entrySet()) {
            List<Entry> same = n.getValue();
            if (same.size() > 1) {
                for (Entry e : same) {
                    refuse(e, "the mapping gives the name " + n.getKey() + " to " + same.size()
                            + " functions");
                }
                continue;
            }
            Entry e = same.get(0);
            Function keeper = finalOwner.get(n.getKey());
            if (keeper != null && keeper != e.function) {
                refuse(e, "the name " + n.getKey() + " already belongs to the function at "
                        + keeper.getEntryPoint());
                continue;
            }
            for (Symbol s : currentProgram.getSymbolTable().getSymbols(n.getKey(),
                    currentProgram.getGlobalNamespace())) {
                if (s.getObject() instanceof Function) {
                    continue;                      // judged by name above
                }
                refuse(e, "the name " + n.getKey() + " already belongs to a "
                        + s.getSymbolType().toString().toLowerCase() + " at " + s.getAddress());
                break;
            }
        }
    }

    /* Why a name cannot be applied, or null. */
    private String illegal(String name) {
        if (!name.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            return "not a C identifier: " + name;
        }
        if (C_KEYWORDS.contains(name)) {
            return "a C keyword: " + name;
        }
        try {
            SymbolUtilities.validateName(name);
        } catch (Exception x) {
            return "Ghidra refuses it: " + x.getMessage();
        }
        if (SymbolUtilities.isReservedDynamicLabelName(name, currentProgram.getAddressFactory())) {
            return "the form of a name Ghidra makes up for an address: " + name;
        }
        return null;
    }

    private static void refuse(Entry e, String why) {
        e.outcome = "refused";
        e.reason = e.reason == null ? why : e.reason + "; " + why;
    }

    /* Write every entry inside one transaction, reading each back. Any
     * difference, or any exception at all, aborts the transaction. */
    private String write(String fault) {
        List<Entry> todo = new ArrayList<>();
        for (Entry e : entries) {
            if (e.outcome == null) {
                todo.add(e);
            }
        }
        Listing listing = currentProgram.getListing();
        int tx = currentProgram.startTransaction("ApplyNames");
        boolean ok = true;
        Entry failed = null;
        String failure = null;
        try {
            for (int i = 0; i < todo.size(); i++) {
                Entry e = todo.get(i);
                Function f = e.function;
                boolean last = i == todo.size() - 1;
                failed = e;
                e.previousName = f.getName(true);
                Namespace ns = f.getParentNamespace();
                e.expectedQualified = ns == null || ns.isGlobal() ? e.applied
                        : ns.getName(true) + Namespace.DELIMITER + e.applied;
                e.note = note(e);
                Address entry = f.getEntryPoint();

                if (last && "throw".equals(fault)) {
                    throw new IllegalStateException("fault injected: the setter threw");
                }
                f.setName(e.applied, SourceType.ANALYSIS);   // namespace untouched
                listing.setComment(entry, CodeUnit.PRE_COMMENT, e.note);
                if (e.hasComment) {
                    f.setComment(e.comment.isEmpty() ? null : e.comment);
                }
                if (e.hasInline) {
                    listing.setComment(entry, CodeUnit.EOL_COMMENT,
                            e.inline.isEmpty() ? null : e.inline);
                }

                // Read back what Ghidra stored, and hold it to what was asked.
                e.storedName = f.getName(true);
                e.storedNote = listing.getComment(CodeUnit.PRE_COMMENT, entry);
                e.storedComment = f.getComment();
                e.storedInline = listing.getComment(CodeUnit.EOL_COMMENT, entry);
                if (last && "readback".equals(fault)) {
                    e.storedName = e.storedName + "_FAULT";
                }
                List<String> differs = new ArrayList<>();
                if (!e.expectedQualified.equals(e.storedName)) {
                    differs.add("name " + e.storedName + ", not " + e.expectedQualified);
                }
                if (!e.note.equals(e.storedNote)) {
                    differs.add("the note on the name");
                }
                if (e.hasComment && !same(e.comment, e.storedComment)) {
                    differs.add("comment " + quoted(e.storedComment));
                }
                if (e.hasInline && !same(e.inline, e.storedInline)) {
                    differs.add("inline comment " + quoted(e.storedInline));
                }
                if (!differs.isEmpty()) {
                    ok = false;
                    failure = "read back differently: " + String.join("; ", differs);
                    break;
                }
                e.outcome = "applied";
            }
        } catch (Throwable t) {
            ok = false;
            failure = "threw " + t;
        } finally {
            // A sub-transaction of the one the framework opened: ending it
            // uncommitted aborts that one too, and with it every change.
            currentProgram.endTransaction(tx, ok);
        }
        if (ok) {
            return "committed";
        }
        for (Entry e : todo) {
            e.outcome = "rolled-back";
            e.reason = e == failed ? failure
                    : "written, then discarded with the rest when entry " + failed.index
                      + " " + failure;
        }
        return "aborted";
    }

    private static boolean same(String asked, String stored) {
        return asked.isEmpty() ? stored == null || stored.isEmpty() : asked.equals(stored);
    }

    private static String quoted(String s) {
        return s == null ? "(none)" : "\"" + s + "\"";
    }

    /* This script's note on the name it applies, as it has always been
     * written, now in the PRE comment at the entry. */
    private String note(Entry e) {
        StringBuilder note = new StringBuilder(String.format(
                "identified as %s (confidence %.3f)", e.source, e.score));
        if (e.provisional) {
            note.append("\nLOW CONFIDENCE -- verify before relying on this name.");
        }
        // A long routine named from evidence found near its start is a
        // documented way to be confidently wrong. A sibling project
        // reconstructing Tapper recorded two such cases side by side:
        // erase_bar_list_a and erase_bar_list_b, both named from their
        // opening lines, both actually doing far more further down --
        // including killing the player. Being a plausible-looking pair made
        // each seem to confirm the other.
        long size = e.function.getBody().getNumAddresses();
        e.longRoutine = size >= LONG_ROUTINE_BYTES;
        if (e.longRoutine) {
            note.append(String.format("\nLONG ROUTINE (%d bytes) -- this name reflects "
                    + "evidence found somewhere inside it, not a reading of the whole. "
                    + "Read through to the RET before trusting it; a routine this size "
                    + "often does several things, and the last one is what kills you.",
                    size));
        }
        return note.toString();
    }

    private void record(File outDir, File mappingFile, String phase, String transaction,
            boolean dryRun, double minScore, double certain, String fault) throws Exception {
        JsonObject r = new JsonObject();
        r.addProperty("schema", "dos-decompiler/applynames-record/1");
        r.addProperty("script_sha256", LoadImageMap.sourceSha256(getSourceFile()));
        r.addProperty("program", currentProgram.getName());
        r.add("target", target());
        r.addProperty("mapping", mappingFile.getAbsolutePath());
        r.addProperty("phase", phase);
        r.addProperty("transaction", transaction);
        r.addProperty("dryrun", dryRun);
        r.addProperty("min_score", minScore);
        r.addProperty("certain_score", certain);
        r.addProperty("fault_injected", fault == null || fault.isEmpty() ? null : fault);
        JsonArray p = new JsonArray();
        problems.forEach(p::add);
        r.add("problems", p);
        JsonArray list = new JsonArray();
        for (Entry e : entries) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("index", e.index);
            m.put("address", e.address);
            m.put("requested_name", e.source);
            m.put("score", e.score);
            m.put("applied_name", e.applied);
            m.put("provisional", e.provisional);
            m.put("previous_name", e.previousName);
            m.put("stored_name", e.storedName);
            m.put("note", e.note);
            m.put("stored_note", e.storedNote);
            m.put("comment", e.hasComment ? e.comment : null);
            m.put("comment_given", e.hasComment);
            m.put("stored_comment", e.storedComment);
            m.put("inline_comment", e.hasInline ? e.inline : null);
            m.put("inline_comment_given", e.hasInline);
            m.put("stored_inline_comment", e.storedInline);
            m.put("long_routine", e.longRoutine);
            m.put("outcome", e.outcome);
            m.put("reason", e.reason);
            JsonObject o = new JsonObject();
            for (Map.Entry<String, Object> kv : m.entrySet()) {
                Object v = kv.getValue();
                if (v == null) {
                    o.add(kv.getKey(), com.google.gson.JsonNull.INSTANCE);
                } else if (v instanceof Number) {
                    o.addProperty(kv.getKey(), (Number) v);
                } else if (v instanceof Boolean) {
                    o.addProperty(kv.getKey(), (Boolean) v);
                } else {
                    o.addProperty(kv.getKey(), v.toString());
                }
            }
            list.add(o);
        }
        r.add("entries", list);
        outDir.mkdirs();
        Files.writeString(new File(outDir, "applynames-record.json").toPath(),
                new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping()
                        .create().toJson(r) + "\n", StandardCharsets.UTF_8);
    }

    /* The file this program was imported from: its path as recorded, and the
     * size and SHA-256 of Ghidra's own copy of its bytes, as
     * ExportDecompiledC.java reports them. */
    private JsonObject target() throws Exception {
        JsonObject t = new JsonObject();
        String path = currentProgram.getExecutablePath();
        if (path != null && path.matches("^/[A-Za-z]:/.*")) {
            path = path.substring(1);
        }
        t.addProperty("path", path);
        List<FileBytes> all = currentProgram.getMemory().getAllFileBytes();
        if (all.isEmpty()) {
            t.add("size", com.google.gson.JsonNull.INSTANCE);
            t.add("sha256", com.google.gson.JsonNull.INSTANCE);
            return t;
        }
        FileBytes fb = all.get(0);
        byte[] bytes = new byte[(int) fb.getSize()];
        fb.getOriginalBytes(0, bytes, 0, bytes.length);
        t.addProperty("size", fb.getSize());
        t.addProperty("sha256", LoadImageMap.hex(MessageDigest.getInstance("SHA-256").digest(bytes)));
        return t;
    }
}
