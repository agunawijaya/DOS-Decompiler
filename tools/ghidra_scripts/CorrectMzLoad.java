/* CorrectMzLoad.java -- put right the two things Ghidra's MZ loader is measured
 * to get wrong, and nothing else.
 *
 * Ghidra 12.1.2's MzLoader differs from DOS in two places (knowledge/04-pitfalls.md,
 * measured with tests/loadimage/fixtures/segments.asm):
 *
 *   * It ends the image at (pages - 1) * 512 + bytes_on_last_page, so a header
 *     that says the last page is full (bytes_on_last_page 0) loses that whole
 *     page. This maps the missing file range at the addresses DOS would load
 *     it at, backed by the file's own bytes, applying any fixup DOS would
 *     apply inside it.
 *   * It writes 0x1000 + the file's word for each relocation entry instead of
 *     adding the load segment to what memory holds, so an entry listed twice
 *     takes effect once. This writes the value DOS produces -- the file word
 *     plus the load segment once per entry -- and leaves the relocation table
 *     as Ghidra recorded it.
 *
 * Anything else that differs is left alone, for tools/loadimage.py verify to
 * report: the verifier compares the result against the file and does not
 * trust this script.
 *
 * Input is `loadimage.py expected`'s envelope for the same file. Output is
 * <outdir>/load-corrections.json: each correction with its kind, where it is,
 * and the values before and after. The script also leaves a mark in Program
 * Information -- its own hash and the number of corrections -- which
 * ExportDecompiledC.java reports, so the handshake can tell a corrected
 * export from one where the corrector never ran. When there is nothing to
 * correct, the mark is the only thing it writes.
 *
 * Usage (headless, not -readOnly: it saves its corrections):
 *   -process GAME.EXE -noanalysis -postScript CorrectMzLoad.java EXPECTED.json OUTDIR
 *
 * @category DOS.Decompile
 */

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class CorrectMzLoad extends GhidraScript {

    /** Read by ExportDecompiledC.java; the same keys. */
    static final String MARK_HASH = "DOS-Decompiler CorrectMzLoad SHA-256";
    static final String MARK_COUNT = "DOS-Decompiler CorrectMzLoad corrections";

    private final List<String> corrections = new ArrayList<>();
    private final List<String> notes = new ArrayList<>();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("usage: CorrectMzLoad.java EXPECTED.json OUTDIR");
            return;
        }
        File expectedFile = new File(args[0]);
        File outDir = new File(args[1]);
        JsonObject env = JsonParser.parseString(
                Files.readString(expectedFile.toPath(), StandardCharsets.UTF_8)).getAsJsonObject();

        String refused = refusal(env);
        if (refused == null) {
            JsonObject result = env.getAsJsonObject("result");
            correctMissingTail(result);
            correctDuplicatedRelocations(result);
        } else {
            notes.add(refused);
        }

        String hash = LoadImageMap.sourceSha256(getSourceFile());
        currentProgram.getOptions(Program.PROGRAM_INFO).setString(MARK_HASH, hash);
        currentProgram.getOptions(Program.PROGRAM_INFO)
                .setString(MARK_COUNT, Integer.toString(corrections.size()));
        if (corrections.isEmpty() && refused == null) {
            notes.add("nothing to correct: the load agrees with DOS on both cases this corrects");
        }
        write(new File(outDir, "load-corrections.json"), expectedFile, env, hash);
        println("CorrectMzLoad: " + corrections.size() + " correction(s)"
                + (notes.isEmpty() ? "" : "; " + String.join("; ", notes))
                + " -> " + new File(outDir, "load-corrections.json"));
    }

    /* Corrections are only made against an expected record of this very
     * file: same size, same SHA-256 as Ghidra's own copy. Anything else would
     * be correcting one program to look like another. */
    private String refusal(JsonObject env) throws Exception {
        if (!"ok".equals(env.get("status").getAsString())) {
            return "expected side is " + env.get("status").getAsString()
                    + ", so nothing is corrected";
        }
        List<FileBytes> all = currentProgram.getMemory().getAllFileBytes();
        if (all.isEmpty()) {
            return "the program keeps no copy of the file, so nothing is corrected";
        }
        FileBytes fb = all.get(0);
        byte[] original = new byte[(int) fb.getSize()];
        fb.getOriginalBytes(0, original, 0, original.length);
        String sha = LoadImageMap.hex(MessageDigest.getInstance("SHA-256").digest(original));
        String want = env.getAsJsonObject("target").get("sha256").getAsString();
        if (!sha.equals(want)) {
            return "the expected record is for another file (" + want.substring(0, 12)
                    + "... not " + sha.substring(0, 12) + "...), so nothing is corrected";
        }
        return null;
    }

    /* The last page when the header says it is full. Corrected only in the
     * exact shape MzLoader produces: bytes_on_last_page 0, and nothing mapped
     * from the file at or past (pages - 1) * 512. */
    private void correctMissingTail(JsonObject result) throws Exception {
        JsonObject header = result.getAsJsonObject("header");
        if (header.get("bytes_on_last_page").getAsInt() != 0) {
            return;
        }
        long headerSize = header.get("size").getAsLong();
        long ghidraEnd = (header.get("pages").getAsLong() - 1) * 512;
        long moduleEnd = result.getAsJsonObject("module").get("file_end_inclusive").getAsLong() + 1;
        int loadSegment = Integer.decode(result.get("load_segment").getAsString());

        long mappedEnd = -1;
        MemoryBlock last = null;
        for (LoadImageMap.Mapping m : LoadImageMap.mappings(currentProgram)) {
            if (m.fileOffset < 0 || !m.segmented()) {
                continue;
            }
            if (m.fileOffset + m.length > mappedEnd) {
                mappedEnd = m.fileOffset + m.length;
                last = m.block;
            }
        }
        if (mappedEnd != ghidraEnd || mappedEnd >= moduleEnd || last == null) {
            if (mappedEnd < moduleEnd) {
                notes.add(String.format("file 0x%x..0x%x is not mapped, but not in the shape "
                        + "this corrects; left for the verifier", mappedEnd, moduleEnd - 1));
            }
            return;
        }

        Memory memory = currentProgram.getMemory();
        FileBytes fb = memory.getAllFileBytes().get(0);
        long length = moduleEnd - mappedEnd;
        long linear = ((long) loadSegment << 4) + (mappedEnd - headerSize);
        SegmentedAddressSpace space =
                (SegmentedAddressSpace) currentProgram.getAddressFactory().getDefaultAddressSpace();

        // Uninitialised blocks where the page belongs -- MzLoader puts its
        // minalloc block straight after the last block it loaded -- come out
        // of the way first, and go back after the restored page.
        List<String> moved = new ArrayList<>();
        long uninitTotal = 0;
        String uninitName = null;
        boolean r = true, w = true, x = false;
        for (MemoryBlock b : memory.getBlocks()) {
            if (b.isInitialized() || !(b.getStart() instanceof SegmentedAddress)) {
                continue;
            }
            long lo = b.getStart().getOffset();
            long hi = lo + b.getSize();
            if (hi <= linear || lo >= linear + length) {
                continue;
            }
            if (lo != linear) {
                notes.add("an uninitialised block " + b.getName() + " overlaps the missing page "
                        + "but does not start where it should; left for the verifier");
                return;
            }
            uninitName = b.getName();
            uninitTotal = b.getSize();
            r = b.isRead();
            w = b.isWrite();
            x = b.isExecute();
            moved.add(b.getName() + " " + b.getStart() + " size " + b.getSize());
            memory.removeBlock(b, monitor);
        }

        SegmentedAddress lastStart = (SegmentedAddress) last.getStart();
        int segment = lastStart.getSegment();
        long offset = linear - ((long) segment << 4);
        Address start = offset + length - 1 <= 0xFFFF
                ? space.getAddress(segment, (int) offset)
                : space.getAddress((int) (linear >> 4), (int) (linear & 0xF));
        MemoryBlock page = memory.createInitializedBlock(last.getName() + "_page", start, fb,
                mappedEnd, length, false);
        page.setRead(last.isRead());
        page.setWrite(last.isWrite());
        page.setExecute(last.isExecute());

        String joined;
        MemoryBlock restored;
        try {
            restored = memory.join(last, page);
            joined = "joined to " + last.getName();
        } catch (Exception e) {
            restored = page;
            joined = "a block of its own (" + page.getName() + "): join refused, " + e.getMessage();
        }

        List<String> fixups = applyFixupsInside(result, mappedEnd, moduleEnd, loadSegment, space);

        String movedTo = null;
        if (uninitName != null) {
            Address after = restored.getEnd().add(1);
            MemoryBlock again = memory.createUninitializedBlock(uninitName, after, uninitTotal, false);
            again.setRead(r);
            again.setWrite(w);
            again.setExecute(x);
            movedTo = uninitName + " " + after + " size " + uninitTotal;
        }

        corrections.add("{\"kind\": \"missing-last-page\""
                + ", \"file_start\": " + mappedEnd
                + ", \"file_end_inclusive\": " + (moduleEnd - 1)
                + ", \"linear_start\": " + linear
                + ", \"linear_end_inclusive\": " + (linear + length - 1)
                + ", \"address\": " + quote(start.toString())
                + ", \"before\": \"not loaded\""
                + ", \"after\": " + quote(String.format("file 0x%x..0x%x mapped at %s, %s",
                        mappedEnd, moduleEnd - 1, start, joined))
                + ", \"uninitialized_moved\": " + (movedTo == null ? "null"
                        : quote(String.join(", ", moved) + " -> " + movedTo))
                + ", \"fixups\": [" + String.join(", ", fixups) + "]}");
    }

    /* Relocations whose word lies in the restored page: MzLoader could not
     * apply them, because there was no memory there. DOS adds the load
     * segment once per entry. The relocation table keeps whatever status
     * Ghidra gave them; correcting that is not something the program allows. */
    private List<String> applyFixupsInside(JsonObject result, long fileStart, long fileEnd,
            int loadSegment, SegmentedAddressSpace space) throws Exception {
        List<String> out = new ArrayList<>();
        List<Long> done = new ArrayList<>();
        Memory memory = currentProgram.getMemory();
        FileBytes fb = memory.getAllFileBytes().get(0);
        for (JsonElement el : result.getAsJsonArray("relocations")) {
            JsonObject r = el.getAsJsonObject();
            long fileOffset = r.get("file_offset").getAsLong();
            long linear = r.get("linear").getAsLong();
            if (fileOffset < fileStart || fileOffset + 1 >= fileEnd || done.contains(linear)) {
                continue;
            }
            done.add(linear);
            int entries = r.get("entries_for_this_word").getAsInt();
            int fileWord = fileWord(fb, fileOffset);
            int value = (fileWord + entries * loadSegment) & 0xFFFF;
            Address a = addressOf(space, linear);
            int before = memory.getShort(a) & 0xFFFF;
            memory.setShort(a, (short) value);
            out.add("{\"address\": " + quote(a.toString()) + ", \"file_offset\": " + fileOffset
                    + ", \"entries\": " + entries
                    + ", \"before\": " + quote(String.format("0x%04x", before))
                    + ", \"after\": " + quote(String.format("0x%04x", value)) + "}");
        }
        return out;
    }

    /* A word that more than one relocation entry names gets the load segment
     * once per entry, as DOS adds it. */
    private void correctDuplicatedRelocations(JsonObject result) throws Exception {
        int loadSegment = Integer.decode(result.get("load_segment").getAsString());
        Memory memory = currentProgram.getMemory();
        FileBytes fb = memory.getAllFileBytes().get(0);
        SegmentedAddressSpace space =
                (SegmentedAddressSpace) currentProgram.getAddressFactory().getDefaultAddressSpace();
        List<Long> done = new ArrayList<>();
        for (JsonElement el : result.getAsJsonArray("relocations")) {
            JsonObject r = el.getAsJsonObject();
            int entries = r.get("entries_for_this_word").getAsInt();
            long linear = r.get("linear").getAsLong();
            if (entries < 2 || done.contains(linear)) {
                continue;
            }
            done.add(linear);
            Address a = addressOf(space, linear);
            MemoryBlock b = memory.getBlock(a);
            if (b == null || !b.isInitialized()) {
                notes.add("the duplicated relocation at " + r.get("address").getAsString()
                        + " is not in loaded memory; left for the verifier");
                continue;
            }
            int recorded = currentProgram.getRelocationTable().getRelocations(a).size();
            long fileOffset = r.get("file_offset").getAsLong();
            int value = (fileWord(fb, fileOffset) + entries * loadSegment) & 0xFFFF;
            int before = memory.getShort(a) & 0xFFFF;
            if (before == value) {
                continue;
            }
            memory.setShort(a, (short) value);
            corrections.add("{\"kind\": \"duplicated-relocation\""
                    + ", \"address\": " + quote(a.toString())
                    + ", \"linear\": " + linear
                    + ", \"file_offset\": " + fileOffset
                    + ", \"entries\": " + entries
                    + ", \"relocation_records\": " + recorded
                    + ", \"before\": " + quote(String.format("0x%04x", before))
                    + ", \"after\": " + quote(String.format("0x%04x", value)) + "}");
        }
    }

    /* The address Ghidra already uses for a linear address, when a block
     * holds it: its segment. Otherwise the paragraph form. */
    private Address addressOf(SegmentedAddressSpace space, long linear) {
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!(b.getStart() instanceof SegmentedAddress)) {
                continue;
            }
            long lo = b.getStart().getOffset();
            if (linear >= lo && linear < lo + b.getSize()) {
                int seg = ((SegmentedAddress) b.getStart()).getSegment();
                return space.getAddress(seg, (int) (linear - ((long) seg << 4)));
            }
        }
        return space.getAddress((int) (linear >> 4), (int) (linear & 0xF));
    }

    private static int fileWord(FileBytes fb, long at) throws Exception {
        return (fb.getOriginalByte(at) & 0xff) | ((fb.getOriginalByte(at + 1) & 0xff) << 8);
    }

    private void write(File out, File expectedFile, JsonObject env, String hash) throws Exception {
        PrintWriter j = new PrintWriter(out, StandardCharsets.UTF_8);
        j.println("{");
        j.println("  \"schema\": \"dos-decompiler/load-corrections/1\",");
        j.println("  \"script_sha256\": " + quote(hash) + ",");
        j.println("  \"helper_sha256\": " + quote(LoadImageMap.helperSha256(getSourceFile())) + ",");
        j.println("  \"program\": " + quote(currentProgram.getName()) + ",");
        j.println("  \"target_sha256\": "
                + quote(env.getAsJsonObject("target").get("sha256").getAsString()) + ",");
        j.println("  \"expected\": " + quote(expectedFile.getAbsolutePath()) + ",");
        j.println("  \"count\": " + corrections.size() + ",");
        JsonArray noteArray = new JsonArray();
        notes.forEach(noteArray::add);
        j.println("  \"notes\": " + noteArray + ",");
        j.println("  \"corrections\": [");
        for (int i = 0; i < corrections.size(); i++) {
            j.println("    " + corrections.get(i) + (i + 1 < corrections.size() ? "," : ""));
        }
        j.println("  ]");
        j.println("}");
        j.close();
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
