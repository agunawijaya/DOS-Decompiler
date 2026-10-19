/* DumpLoadImage.java -- write down what Ghidra actually loaded, so it can be
 * checked against what the file says it should have loaded.
 *
 * Writes, into <outdir>/loadimage-observed/:
 *   observed.json   every memory block with the file ranges it came from, the
 *                   relocation table, the entry points, the stack registers
 *                   at the entry, and the program's own copy of the file
 *   block-NN.bin    the bytes of each initialised block, as Ghidra holds them
 *   file-original.bin, file-modified.bin
 *                   Ghidra's copy of the file before and after the loader's
 *                   fixups
 *
 * It decides nothing. tools/loadimage.py computes from the file alone what a
 * correct load looks like and compares the two; keeping every judgement on
 * that side is what lets the comparison be tested, tampered with and
 * reproduced without Ghidra.
 *
 * Read-only: run it with -readOnly, it changes nothing in the program.
 *
 * Usage (headless):
 *   -process GAME.EXE -noanalysis -readOnly -postScript DumpLoadImage.java OUTDIR
 *
 * @category DOS.Decompile
 */

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;

public class DumpLoadImage extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir = new File(args.length > 0 ? args[0] : "decompiled", "loadimage-observed");
        if (!outDir.exists() && !outDir.mkdirs()) {
            printerr("cannot create output directory: " + outDir);
            return;
        }
        // A dump from an earlier run must not survive beside this one: a
        // block that no longer exists would still have its bytes on disk.
        File[] old = outDir.listFiles();
        if (old != null) {
            for (File f : old) {
                if (f.isFile()) {
                    f.delete();
                }
            }
        }

        List<String> blocks = new ArrayList<>();
        MemoryBlock[] all = currentProgram.getMemory().getBlocks();
        for (int i = 0; i < all.length; i++) {
            blocks.add(blockRecord(outDir, i, all[i]));
        }

        List<String> fileBytes = new ArrayList<>();
        List<FileBytes> fbs = currentProgram.getMemory().getAllFileBytes();
        for (int i = 0; i < fbs.size(); i++) {
            fileBytes.add(fileBytesRecord(outDir, i, fbs.get(i)));
        }

        List<String> relocations = new ArrayList<>();
        Iterator<Relocation> it = currentProgram.getRelocationTable().getRelocations();
        while (it.hasNext()) {
            relocations.add(relocationRecord(it.next()));
        }

        List<String> entries = new ArrayList<>();
        var ei = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        Address firstEntry = null;
        while (ei.hasNext()) {
            Address a = ei.next();
            if (firstEntry == null) {
                firstEntry = a;
            }
            entries.add("{\"address\": " + quote(a.toString()) + ", \"offset\": "
                    + a.getOffset() + "}");
        }

        PrintWriter j = new PrintWriter(new File(outDir, "observed.json"), StandardCharsets.UTF_8);
        j.println("{");
        j.println("  \"schema\": \"dos-decompiler/loadimage-observed/1\",");
        // This script's own source and the helper it shares with the
        // exporter, by the rule tools/analysis_profile.py hashes them with.
        j.println("  \"script_sha256\": " + quote(LoadImageMap.sourceSha256(getSourceFile())) + ",");
        j.println("  \"helper_sha256\": " + quote(LoadImageMap.helperSha256(getSourceFile())) + ",");
        j.println("  \"program\": " + quote(currentProgram.getName()) + ",");
        j.println("  \"executable_path\": " + quote(currentProgram.getExecutablePath()) + ",");
        j.println("  \"executable_sha256\": " + quote(currentProgram.getExecutableSHA256()) + ",");
        j.println("  \"loader\": " + quote(currentProgram.getExecutableFormat()) + ",");
        j.println("  \"language\": " + quote(currentProgram.getLanguageID().toString()) + ",");
        j.println("  \"compiler_spec\": "
                + quote(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + ",");
        j.println("  \"ghidra_version\": "
                + quote(ghidra.framework.Application.getApplicationVersion()) + ",");
        j.println("  \"image_base\": " + quote(currentProgram.getImageBase().toString()) + ",");
        j.println("  \"header_size\": " + LoadImageMap.headerSize(currentProgram) + ",");
        j.println("  \"load_segment\": " + quote(LoadImageMap.loadSegment(currentProgram)) + ",");
        j.println("  \"stack\": " + stackRecord(firstEntry) + ",");
        j.println("  \"entry_points\": [" + String.join(", ", entries) + "],");
        writeList(j, "file_bytes", fileBytes, true);
        writeList(j, "blocks", blocks, true);
        writeList(j, "relocations", relocations, false);
        j.println("}");
        j.close();

        println("DumpLoadImage: " + all.length + " blocks, " + relocations.size()
                + " relocations, " + entries.size() + " entry point(s) -> " + outDir);
    }

    private String blockRecord(File outDir, int index, MemoryBlock b) throws Exception {
        StringBuilder sb = new StringBuilder("{");
        Address start = b.getStart();
        sb.append("\"index\": ").append(index).append(", ");
        sb.append("\"name\": ").append(quote(b.getName())).append(", ");
        sb.append("\"space\": ").append(quote(start.getAddressSpace().getName())).append(", ");
        sb.append("\"segmented\": ").append(start instanceof SegmentedAddress).append(", ");
        sb.append("\"start\": ").append(quote(start.toString())).append(", ");
        sb.append("\"end\": ").append(quote(b.getEnd().toString())).append(", ");
        sb.append("\"start_offset\": ").append(start.getOffset()).append(", ");
        sb.append("\"size\": ").append(b.getSize()).append(", ");
        sb.append("\"initialized\": ").append(b.isInitialized()).append(", ");
        sb.append("\"read\": ").append(b.isRead()).append(", ");
        sb.append("\"write\": ").append(b.isWrite()).append(", ");
        sb.append("\"execute\": ").append(b.isExecute()).append(", ");
        if (b.isInitialized()) {
            byte[] bytes = new byte[(int) b.getSize()];
            b.getBytes(start, bytes);
            String name = String.format("block-%02d.bin", index);
            try (FileOutputStream out = new FileOutputStream(new File(outDir, name))) {
                out.write(bytes);
            }
            sb.append("\"sha256\": ").append(quote(sha256(bytes))).append(", ");
            sb.append("\"dump\": ").append(quote(name)).append(", ");
        }
        sb.append("\"mappings\": [");
        boolean first = true;
        for (LoadImageMap.Mapping m : LoadImageMap.mappings(currentProgram)) {
            if (m.block != b) {
                continue;
            }
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append("{\"min\": ").append(quote(m.min.toString()))
              .append(", \"max\": ").append(quote(m.max.toString()))
              .append(", \"min_offset\": ").append(m.min.getOffset())
              .append(", \"offset_in_block\": ").append(m.min.subtract(start))
              .append(", \"length\": ").append(m.length)
              .append(", \"file_offset\": ").append(m.fileOffset).append("}");
        }
        sb.append("]}");
        return sb.toString();
    }

    private String fileBytesRecord(File outDir, int index, FileBytes fb) throws Exception {
        long size = fb.getSize();
        byte[] original = new byte[(int) size];
        byte[] modified = new byte[(int) size];
        fb.getOriginalBytes(0, original, 0, (int) size);
        fb.getModifiedBytes(0, modified, 0, (int) size);
        String originalName = String.format("file-%02d-original.bin", index);
        String modifiedName = String.format("file-%02d-modified.bin", index);
        try (FileOutputStream out = new FileOutputStream(new File(outDir, originalName))) {
            out.write(original);
        }
        try (FileOutputStream out = new FileOutputStream(new File(outDir, modifiedName))) {
            out.write(modified);
        }
        return "{\"index\": " + index + ", \"filename\": " + quote(fb.getFilename())
                + ", \"file_offset\": " + fb.getFileOffset() + ", \"size\": " + size
                + ", \"original_sha256\": " + quote(sha256(original))
                + ", \"modified_sha256\": " + quote(sha256(modified))
                + ", \"original_dump\": " + quote(originalName)
                + ", \"modified_dump\": " + quote(modifiedName) + "}";
    }

    private String relocationRecord(Relocation r) {
        StringBuilder sb = new StringBuilder("{");
        Address a = r.getAddress();
        sb.append("\"address\": ").append(quote(a.toString())).append(", ");
        sb.append("\"offset\": ").append(a.getOffset()).append(", ");
        sb.append("\"status\": ").append(quote(r.getStatus().name())).append(", ");
        sb.append("\"type\": ").append(r.getType()).append(", ");
        sb.append("\"length\": ").append(r.getLength()).append(", ");
        byte[] bytes = r.getBytes();
        sb.append("\"bytes\": ").append(bytes == null ? "null" : quote(LoadImageMap.hex(bytes)))
          .append(", ");
        sb.append("\"values\": [");
        long[] values = r.getValues();
        for (int i = 0; values != null && i < values.length; i++) {
            sb.append(i > 0 ? ", " : "").append(values[i]);
        }
        sb.append("]}");
        return sb.toString();
    }

    /* SS and SP as the loader set them at the entry point. Ghidra keeps them
     * as register context, not as data, so this is the only place they show. */
    private String stackRecord(Address entry) {
        if (entry == null) {
            return "null";
        }
        ProgramContext context = currentProgram.getProgramContext();
        Register ss = context.getRegister("ss");
        Register sp = context.getRegister("sp");
        BigInteger ssValue = ss == null ? null : context.getValue(ss, entry, false);
        BigInteger spValue = sp == null ? null : context.getValue(sp, entry, false);
        return "{\"ss\": " + (ssValue == null ? "null" : ssValue.toString())
                + ", \"sp\": " + (spValue == null ? "null" : spValue.toString()) + "}";
    }

    private void writeList(PrintWriter j, String name, List<String> items, boolean more) {
        j.println("  \"" + name + "\": [");
        for (int i = 0; i < items.size(); i++) {
            j.println("    " + items.get(i) + (i + 1 < items.size() ? "," : ""));
        }
        j.println("  ]" + (more ? "," : ""));
    }

    private static String sha256(byte[] data) throws Exception {
        return LoadImageMap.hex(MessageDigest.getInstance("SHA-256").digest(data));
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
