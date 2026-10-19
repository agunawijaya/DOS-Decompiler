; An MZ with several segments, built to give a loader something to get wrong.
;
; Four paragraph-aligned segments: a few bytes of data, the startup, a far
; routine, and a data segment. Four relocations, each a different reason a
; loader patches a word:
;
;   1. `mov ax, DATA_SEG` in the startup        -- loading DS, as C startups do
;   2. the segment half of `call far FAR:proc`  -- a far call
;   3. `mov ax, DATA_SEG` in the far routine    -- the same fixup, elsewhere
;   4. the segment half of a far pointer in a data table -- a relocation that
;      is not in code at all
;
; The entry point is not at offset 0: CS = 1 and IP = 4, so the entry is image
; offset 0x14, and the four bytes before it are data.
;
; The header is 64 bytes rather than the 512 the other fixtures use, so the
; image does not start where they all do.
;
; Variants, chosen with -d at assembly time, each a single difference from
; the file above so a failure points at that difference and nothing else:
;
;   APPENDED              bytes after the declared image: an overlay or junk,
;                         which must stay outside the load module
;   DUPLICATED            the data-table relocation listed twice
;   FULL_LAST_PAGE        the image padded so header plus image is exactly two
;                         pages, 1024 bytes, which makes bytes-on-last-page 0
;                         -- "the last page is full" in DOS's reading of the
;                         header
;   TAIL_RELOCATION       FULL_LAST_PAGE with a far pointer inside the second
;                         page, so a relocation patches a word in the page
;                         Ghidra's loader drops
;   RELOC_TABLE_OUTSIDE   malformed: the relocation table starts past the file
;   RELOC_TARGET_PAST     malformed: a relocation patches a word past the image
;   ENTRY_OUTSIDE         malformed: CS:IP points past the image
;
; DUPLICATED and FULL_LAST_PAGE may be given together, for a file with both.

BITS 16
ORG 0

%ifdef TAIL_RELOCATION
  %define FULL_LAST_PAGE
%endif

; `mov bp, sp` has two encodings; 8B EC is the one compilers emit and the
; tools count.
%macro frame 0
    push bp
    db 0x8B, 0xEC
%endmacro

HDR_PARAS   equ 4                       ; 64-byte header
IMAGE_LEN   equ image_end - image_start
TOTAL       equ HDR_PARAS * 16 + IMAGE_LEN

CODE_SEG    equ (code_start - image_start) / 16
FAR_SEG     equ (far_start - image_start) / 16
DATA_SEG    equ (data_start - image_start) / 16

%ifdef DUPLICATED
  %assign DUP_ENTRIES 1
%else
  %assign DUP_ENTRIES 0
%endif
%ifdef TAIL_RELOCATION
  %assign TAIL_ENTRIES 1
%else
  %assign TAIL_ENTRIES 0
%endif
RELOCATIONS equ 4 + DUP_ENTRIES + TAIL_ENTRIES

; ---------------------------------------------------------------- MZ header
    db 'MZ'
    dw TOTAL % 512                      ; bytes used in the last page
    dw (TOTAL + 511) / 512              ; pages
    dw RELOCATIONS
    dw HDR_PARAS
    dw 0x0010                           ; minalloc
    dw 0xFFFF                           ; maxalloc
    dw DATA_SEG                         ; SS
    dw 0x0200                           ; SP
    dw 0                                ; checksum
%ifdef ENTRY_OUTSIDE
    dw 0x7000                           ; IP far past the image
%else
    dw entry - code_start               ; IP = 4
%endif
    dw CODE_SEG                         ; CS = 1
%ifdef RELOC_TABLE_OUTSIDE
    dw 0x7FF0                           ; relocation table past the end of the file
%else
    dw relocations
%endif
    dw 0                                ; overlay number
relocations:
    dw fix_startup - code_start, CODE_SEG
    dw fix_farcall - code_start, CODE_SEG
    dw fix_farproc - far_start, FAR_SEG
%ifdef RELOC_TARGET_PAST
    dw 0x0000, 0x0100                   ; image offset 0x1000: past the image
%else
    dw fix_table - data_start, DATA_SEG
%endif
%ifdef DUPLICATED
    dw fix_table - data_start, DATA_SEG ; the same word again
%endif
%ifdef TAIL_RELOCATION
    dw fix_tail - data_start, DATA_SEG  ; a word in the second page
%endif
    times HDR_PARAS * 16 - ($ - $$) db 0

; ---------------------------------------------------------------- load image
image_start:
    db 'LOADIMG', 0                     ; data before the first code
    dw 0x0102, 0x0304, 0x0506, 0x0708

; ---------- the startup: CS = 1 --------------------------------------------
code_start:
    dw 0x1111, 0x2222                   ; four bytes the entry steps over
entry:
    mov ax, DATA_SEG
fix_startup equ $ - 2
    mov ds, ax
    mov es, ax
    call FAR_SEG:(farproc - far_start)
fix_farcall equ $ - 2
    call near_helper
    call far [table - data_start]       ; through the far pointer in DATA
    mov ax, 0x4C00
    int 0x21

near_helper:
    frame
    xor ax, ax
    pop bp
    ret
    align 16, db 0

; ---------- a far routine in a segment of its own ----------------------------
; Its RETF sits past the first sixteen bytes on purpose: Ghidra's MZ loader
; moves a far return it finds there into the previous block.
far_start:
farproc:
    frame
    mov ax, DATA_SEG
fix_farproc equ $ - 2
    mov ds, ax
    mov ah, 0x09
    mov dx, message - data_start
    int 0x21
    pop bp
    retf
    align 16, db 0

; ---------- data ---------------------------------------------------------
data_start:
message:
    db 'segments fixture', 0x0D, 0x0A, '$'
    align 2, db 0
table:
    dw farproc - far_start              ; offset half of a far pointer
    dw FAR_SEG                          ; segment half: relocation 4
fix_table equ $ - 2
    dw 0xAAAA, 0x5555                   ; more of the table, not relocated
%ifdef FULL_LAST_PAGE
%ifdef TAIL_RELOCATION
    ; Filler to just past file offset 0x200, then a far pointer: a relocation
    ; inside the page Ghidra's loader drops.
    times 0x210 - (HDR_PARAS * 16 + ($ - image_start)) db 0xEE
tail_table:
    dw farproc - far_start
    dw FAR_SEG
fix_tail equ $ - 2
%endif
    ; Two whole pages: everything above, then filler to byte 1024 of the file.
    times 1024 - (HDR_PARAS * 16 + ($ - image_start)) db 0xEE
%endif
image_end:

%ifdef APPENDED
; ---------- past the declared image: never loaded ------------------------
appended:
    db 'APPENDED, NOT LOADED'
    times 300 db 0xA5
%endif
