/* LoadImageMap.java -- where the file's bytes landed in a program, and which
 * version of a script is running.
 *
 * Not a script: it has no run() and does nothing on its own. It holds what
 * ExportDecompiledC.java, DumpLoadImage.java and CorrectMzLoad.java all need,
 * so each is written once:
 *
 *   * the walk over every memory block's source mappings -- which file offset
 *     each range of addresses came from -- and the load segment worked out
 *     from it;
 *   * linear addresses, segment * 16 + offset, and back to the address
 *     Ghidra uses;
 *   * the hash a script reports of its own source, by the rule
 *     tools/evidence.py's source_sha256 uses (CRLF read as LF).
 *
 * Ghidra compiles every .java file in a script directory as one bundle, so a
 * script can call a plain class beside it. Measured on Ghidra 12.1.2 before
 * relying on it: a script calling a sibling class resolved it and ran.
 *
 * @category DOS.Decompile
 */

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import generic.jar.ResourceFile;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;

public final class LoadImageMap {

    private LoadImageMap() {
    }

    /** One contiguous range of a block and where its bytes came from. */
    public static final class Mapping {
        public final MemoryBlock block;
        public final Address min;
        public final Address max;
        public final long length;
        /** -1 when the range has no file bytes behind it: uninitialised. */
        public final long fileOffset;

        Mapping(MemoryBlock block, MemoryBlockSourceInfo si) {
            this.block = block;
            this.min = si.getMinAddress();
            this.max = si.getMaxAddress();
            this.length = si.getLength();
            this.fileOffset = si.getFileBytes().isPresent() ? si.getFileBytesOffset() : -1;
        }

        public boolean segmented() {
            return min instanceof SegmentedAddress;
        }

        /** segment * 16 + offset; meaningful only for a segmented address. */
        public long linear() {
            return LoadImageMap.linear(min);
        }
    }

    /** segment * 16 + offset for a segmented address -- the one number that
     * names a byte however many segment:offset spellings it has. Anything
     * else, the HEADER space for one, has no linear address: its plain offset. */
    public static long linear(Address address) {
        if (address instanceof SegmentedAddress) {
            SegmentedAddress a = (SegmentedAddress) address;
            return ((long) a.getSegment() << 4) + a.getSegmentOffset();
        }
        return address.getOffset();
    }

    /** The address Ghidra itself uses for a linear address: the segment of
     * the block holding it. Null when no segmented block holds it. */
    public static Address addressOf(Program program, long linear) {
        for (MemoryBlock b : program.getMemory().getBlocks()) {
            if (!(b.getStart() instanceof SegmentedAddress)) {
                continue;
            }
            long lo = linear(b.getStart());
            if (linear < lo || linear > lo + b.getSize() - 1) {
                continue;
            }
            SegmentedAddress start = (SegmentedAddress) b.getStart();
            int segment = start.getSegment();
            long offset = linear - ((long) segment << 4);
            if (offset > 0xFFFF) {
                return null;
            }
            return ((ghidra.program.model.address.SegmentedAddressSpace) start.getAddressSpace())
                    .getAddress(segment, (int) offset);
        }
        return null;
    }

    /** Every source mapping of every block, in block order. */
    public static List<Mapping> mappings(Program program) {
        List<Mapping> out = new ArrayList<>();
        for (MemoryBlock b : program.getMemory().getBlocks()) {
            for (MemoryBlockSourceInfo si : b.getSourceInfos()) {
                out.add(new Mapping(b, si));
            }
        }
        return out;
    }

    /** The MZ header's size in bytes, read from Ghidra's own copy of the file. */
    public static long headerSize(Program program) throws IOException {
        List<FileBytes> all = program.getMemory().getAllFileBytes();
        if (all.isEmpty()) {
            return -1;
        }
        FileBytes fb = all.get(0);
        return ((fb.getOriginalByte(8) & 0xff) | ((fb.getOriginalByte(9) & 0xff) << 8)) * 16L;
    }

    /* The segment the first byte of the load image was put at.
     *
     * Program.getImageBase() does not answer this: measured on Ghidra 12.1.2
     * it returns 0000:0000 for an MZ whose image sits at 1000:0000. So it is
     * worked out from where the file's bytes landed instead -- each block
     * backed by the file says which file offset it starts at, and subtracting
     * the header size gives the image offset. Every such block must agree on
     * one load address; if they do not, that is reported rather than one of
     * them being picked. */
    public static String loadSegment(Program program) throws IOException {
        long headerSize = headerSize(program);
        if (headerSize < 0) {
            return "unknown: no file bytes";
        }
        Set<Long> bases = new TreeSet<>();
        for (Mapping m : mappings(program)) {
            if (m.fileOffset < 0 || !m.segmented()) {
                continue;       // the HEADER block lives in a space of its own
            }
            long imageOffset = m.fileOffset - headerSize;
            if (imageOffset < 0) {
                continue;
            }
            bases.add(m.linear() - imageOffset);
        }
        if (bases.size() != 1) {
            return bases.isEmpty() ? "unknown: no block holds the load image"
                                   : "inconsistent: " + bases;
        }
        long base = bases.iterator().next();
        if (base % 16 != 0) {
            return String.format("unaligned: 0x%x", base);
        }
        return String.format("0x%04x", base >> 4);
    }

    /* SHA-256 of a source file with CRLF read as LF, the rule
     * evidence.source_sha256 applies, so a Windows checkout and a Linux
     * checkout of one commit report the same hash. */
    public static String sourceSha256(File file) {
        try {
            byte[] raw = Files.readAllBytes(file.toPath());
            java.io.ByteArrayOutputStream text = new java.io.ByteArrayOutputStream(raw.length);
            for (int i = 0; i < raw.length; i++) {
                if (raw[i] == '\r' && i + 1 < raw.length && raw[i + 1] == '\n') {
                    continue;
                }
                text.write(raw[i]);
            }
            return hex(MessageDigest.getInstance("SHA-256").digest(text.toByteArray()));
        } catch (Exception e) {
            return "unreadable: " + e.getMessage();
        }
    }

    /** The hash of a running script's own source. */
    public static String sourceSha256(ResourceFile script) {
        return sourceSha256(new File(script.getAbsolutePath()));
    }

    /** The hash of this helper's source, found beside the script using it. */
    public static String helperSha256(ResourceFile script) {
        File here = new File(new File(script.getAbsolutePath()).getParentFile(),
                "LoadImageMap.java");
        return sourceSha256(here);
    }

    public static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
