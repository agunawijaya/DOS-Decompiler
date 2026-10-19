# Draft: an upstream issue for Ghidra's MZ loader

**Status: drafted, not filed.** Whether and when to file it is the user's
decision. Everything below the line is written to be pasted into a new issue at
<https://github.com/NationalSecurityAgency/ghidra/issues> as it stands. The
reproducer was assembled and imported on the version named, and the values
quoted are the ones measured. The suggested changes were not built or tested.

What this toolkit does about it meanwhile is in `04-pitfalls.md` and
`17-evidence.md`: `CorrectMzLoad.java` corrects both after import, and the
load-image check compares the result with the file. The reproducer below is a
smaller cousin of `tests/loadimage/fixtures/segments.asm` assembled with
`-dDUPLICATED -dFULL_LAST_PAGE`, which the test suite runs on every pass.
Through `pipeline.ps1` it reads `load image: verified after 2 corrections`:
the page mapped at `1000:01c0` and joined to `CODE_0`, and `1000:0001`
`0x1000 -> 0x2000`. Without the corrector it fails 5 of 22 checks, the first
`module.coverage`.

---

## MzLoader: a full last page (`e_cblp == 0`) is not loaded, and a relocation listed twice is applied once

**Describe the bug**

The Old-style DOS Executable (MZ) loader builds a different memory image from
the one DOS builds, in two cases. Both produce a program that looks normal;
importing the reproducer below logs nothing but `Import succeeded`. The
disassembly and decompilation built on it are then quietly wrong.

1. **`e_cblp == 0` drops the whole last page.** In the MZ header, `e_cblp`
   (bytes on the last page) is 0 when the last 512-byte page is full, which a
   linker writes whenever header plus image is an exact multiple of 512
   bytes. `MzLoader` ends the image at `pagesToBytes(e_cp - 1) + e_cblp`, so a
   0 there loses the entire last page: up to 512 bytes of code or data are not
   mapped at all. A relocation inside that page cannot be applied and is
   recorded with status `FAILURE`.

2. **A word listed in two relocation entries gets the load segment once.** DOS
   adds the load segment to the word in memory, once per entry, so a word
   listed twice gets it twice. `MzLoader` instead *writes*
   `INITIAL_SEGMENT_VAL + the word read from the file` for each entry. The
   second write repeats the first, and the word ends up `0x1000` short of
   what DOS loads. Both relocation records are kept, so the relocation table
   looks right; only the word is wrong.

**Where in the source** (`Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/MzLoader.java`,
12.1.2, from `Base-src.zip`):

- lines 196–197, in `processMemoryBlocks`:

  ```java
  int endOffset = pagesToBytes(Short.toUnsignedInt(header.e_cp()) - 1) +
      Short.toUnsignedInt(header.e_cblp());
  ```

- lines 474–477, in `getRelocationFixups`, the value is computed from the
  file's word alone:

  ```java
  int value = Short.toUnsignedInt(reader.readShort(relocationFileOffset));
  int relocatedSegment = (INITIAL_SEGMENT_VAL + value) & 0xffff;
  fixups.add(new RelocationFixup(relocation, relocationAddress, relocationFileOffset,
      relocatedSegment, true));
  ```

- line 337, in `processRelocations`, it is written rather than added:

  ```java
  memory.setShort(relocationAddress, (short) relocationFixup.segment());
  ```

  The fixups are collected in a `HashSet` (line 458). `MzRelocation` does not
  override `equals`, so two entries for one word stay two fixups, both carrying
  the same value.

**What DOS does** (read 2026-10-19 from the current sources of two independent
loaders; MS-DOS's own loader was not consulted):

- FreeDOS kernel, `kernel/task.c`: the image size is
  `image_size = (ExeHeader.exPages << 5) - ExeHeader.exHeaderSize;` (line 643,
  in paragraphs: whole pages, whatever `e_cblp` says), and each relocation
  entry does `*spot += start_seg;` (line 803).
- DOSBox Staging, `src/dos/dos_execute.cpp`:
  `imagesize = head.pages*512-headersize;` (line 338), and for each entry
  `mem_writew(address,mem_readw(address)+relocate);` (line 430).

Both load whole pages, so for a partial last page they also load the bytes
after `e_cblp`. The change suggested below goes less far: it keeps `MzLoader`'s
use of `e_cblp` for a partial page, and reads 0 as 512.

**To Reproduce**

A 1,024-byte MZ with both: `e_cp = 2`, `e_cblp = 0`, and the immediate of a
`mov ax, 0` at image offset 1 listed in two relocation entries.

```nasm
; MZREPRO.EXE: both MzLoader divergences in one 1,024-byte MZ.
;   nasm -f bin -o MZREPRO.EXE mzrepro.asm
;
; 1. e_cblp = 0 with e_cp = 2: the last page is full, so the load module is
;    file 0x40..0x3FF (2 * 512 - 64 = 960 bytes).
; 2. The word at image offset 1 -- the immediate of `mov ax, 0` -- is listed
;    in two relocation entries, so DOS adds the load segment to it twice.

BITS 16
ORG 0

    db 'MZ'
    dw 0                    ; e_cblp: bytes on the last page, 0 = all 512
    dw 2                    ; e_cp: pages in the file
    dw 2                    ; e_crlc: relocation entries
    dw 4                    ; e_cparhdr: header paragraphs (64 bytes)
    dw 0x0010               ; e_minalloc
    dw 0xFFFF               ; e_maxalloc
    dw 0x003C               ; e_ss: just past the image
    dw 0x0100               ; e_sp
    dw 0                    ; e_csum
    dw 0                    ; e_ip
    dw 0                    ; e_cs
    dw reloc                ; e_lfarlc
    dw 0                    ; e_ovno
reloc:
    dw 1, 0                 ; segment 0, offset 1
    dw 1, 0                 ; the same word again
    times 64 - ($ - $$) db 0

image:                      ; file 0x40, loaded at <load segment>:0000
    mov ax, 0               ; B8 00 00: the relocated word is image offset 1
    mov ah, 0x4C
    int 0x21
    times 0x200 - ($ - $$) db 0xEE
second_page:                ; file 0x200, image offset 0x1C0
    db 'SECOND PAGE'
    times 0x400 - ($ - $$) db 0xEE
```

1. `nasm -f bin -o MZREPRO.EXE mzrepro.asm`. With NASM 2.16.03 the file is
   1,024 bytes, SHA-256
   `5cf1cc4060f905055bc5da22e011612e959a6d9279ac32293fce1cb0bb8ad8ac`.
2. Import it. The loader chosen is "Old-style DOS Executable (MZ)". Analysis
   is not needed. (Measured with `analyzeHeadless <dir> <project> -import
   MZREPRO.EXE -noanalysis`.)
3. Look at the Memory Map, the relocation table, and the word at `1000:0001`.

Observed on 12.1.2:

- `CODE_0` is `1000:0000..1000:01bf`: 448 bytes, file `0x40..0x1ff`. The
  next block is the uninitialised `DATA` (the `e_minalloc` paragraphs) at
  `1000:01c0..1000:02bf`, exactly where the second page belongs. File
  `0x200..0x3ff`, which begins `SECOND PAGE`, is not mapped anywhere.
- The word at `1000:0001` is `0x1000`. The relocation table holds two entries
  for `1000:0001`, both `APPLIED`, each recording `0x1000`.
- The import log says only `Import succeeded`.

**Expected behavior**

- The whole module, file `0x40..0x3FF`, is mapped: 960 bytes, ending at
  `1000:03bf`, with `SECOND PAGE` at `1000:01c0`, and the `e_minalloc` block
  after it, from `1000:03c0`.
- The word at `1000:0001` is `0x2000`: the file's `0x0000`, plus `0x1000`
  once for each of the two entries.

**Suggested change** (not built or tested):

```java
// processMemoryBlocks: e_cblp == 0 means the last page is full
int lastPage = Short.toUnsignedInt(header.e_cblp());
int endOffset = pagesToBytes(Short.toUnsignedInt(header.e_cp()) - 1) +
    (lastPage == 0 ? 512 : lastPage);

// processRelocations: add the load segment to what memory holds, as DOS does,
// so each entry takes effect
short current = memory.getShort(relocationAddress);
memory.setShort(relocationAddress, (short) (current + INITIAL_SEGMENT_VAL));
```

With the second change the value recorded in the relocation table would also
need to come from memory after the add, not from `relocationFixup.segment()`.
For a word listed once, the result is the same as today: the file's word plus
`0x1000`.

**Environment**

- Ghidra 12.1.2 PUBLIC, build 2026-Jun-05
- OpenJDK 21.0.10
- Windows 11 Pro

**Additional context**

The two cases were found by comparing every imported byte, block and
relocation against an independent reading of the MZ header, across a set of
NASM fixtures and six real DOS games. None of the six games has either
feature, so these are not common. But an exact multiple of 512 bytes is
something any linker can produce, and nothing in the import log reports it.
