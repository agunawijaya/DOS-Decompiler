; An MZ that took the .COM route, with CS != 0 in the header.
;
; Some MZ programs -- Alley Cat (1984) is the case that prompted this fixture
; -- carry their code in a segment that starts partway into the image, not at
; the load segment. Alley Cat's header says CS = 0x0723, so the code segment
; lives at load_seg + 0x0723, and the code starts at image offset 0x7230. What
; is DS-relative reads flat like a normal .COM, but what is CS-relative has to
; be taken *relative to that base*.
;
; A `jmp word [cs:bx + disp]` in such a program does NOT dispatch to image
; offset `disp`. It dispatches to image offset `cs_base + disp`, and the
; *words in the table it reads* are themselves CS-relative offsets, so they
; need cs_base added too. Miss this, and comrec looked for Alley Cat's phase
; table at image 0x0250 (zero-fill inside the data segment) instead of at
; image 0x7480 (the real 8-word table); the seven per-phase handlers behind
; that table stayed data. That was 1,500 bytes of missing code and the whole
; game-play surface of the reading -- and the file rebuilt byte-identically
; the whole time.
;
; This fixture reproduces the pattern in miniature: CS = 0x0100 (code lives
; at image 0x1000), a `jmp word [cs:bx + table]` through a two-slot table,
; two handlers reachable *only* through that table. Each handler is preceded
; by a byte the sweep will not decode cleanly, so if the CS-prefix dispatch
; is not followed neither handler is reached and the needles `mov dl, 'M'`
; and `mov dl, 'Z'` never appear in the output.

BITS 16
ORG 0

HDR_PARAS   equ 32                      ; 512-byte header
IMAGE_LEN   equ image_end - image_start
TOTAL       equ HDR_PARAS * 16 + IMAGE_LEN

; ---------------------------------------------------------------- MZ header
    db 'MZ'
    dw TOTAL % 512                      ; bytes used in the last page
    dw (TOTAL + 511) / 512               ; pages
    dw 0                                ; no relocations -- takes the .COM route
    dw HDR_PARAS                        ; header size, in paragraphs
    dw 0x0010                           ; minalloc
    dw 0xFFFF                           ; maxalloc
    dw 0x0200                           ; initial SS, relative to the image
    dw 0x0100                           ; initial SP
    dw 0                                ; checksum
    dw 0x0000                           ; initial IP  -- CS:0000 is the entry
    dw 0x0100                           ; initial CS  -- image offset 0x1000
    dw 0x001C                           ; relocation table offset
    dw 0                                ; overlay number
    times HDR_PARAS * 16 - ($ - $$) db 0

; ---------------------------------------------------------------- load image
image_start:

; ---------- data segment: image 0x0000..0x0FFF -----------------------------
; Zero-fill. This is where the walker would look for the table if it took
; the CS-relative displacement flat.
    times 0x1000 db 0

; ---------- code segment: image 0x1000+, CS = 0x0100 at runtime ------------
code_start:
    mov ax, cs
    mov ds, ax                          ; DS := CS -- reads land in the code seg
    mov ss, ax
    mov sp, 0x100
    sti

    mov ah, 0x09
    mov dx, banner - code_start
    int 0x21

    ; A direct call to a routine sitting past every handler and past the
    ; table. Without this, code_hi (the walker's known reach) would stop at
    ; the jmp below and every dispatch-target sitting past it would be
    ; rejected as "past known reach". A real game always has other code
    ; reachable past the dispatch -- interrupt handlers, sibling routines,
    ; the walker's own iteration -- but a fixture has to arrange it by hand.
    call helper

    mov bx, [index - code_start]        ; runtime 0
    shl bx, 1
    jmp word [cs:bx + table - code_start]   ; the case under test

; A byte the gap sweep will not decode cleanly, so neither handler is
; recoverable by accident.
    db 0x0F, 0xFF, 0xFF

; Reached only through slot 0 of the dispatch table.
; Each handler ends with `ret` so walks_to_return sees a clean terminator
; rather than trying to walk through the banner/table bytes past its end --
; that walk hits an `insw` (0x6D) inside the string "mzdispatchcs" and
; walks_to_return refuses on the IMPLAUSIBLE list. The fixture never runs,
; so it does not matter that the `ret` pops garbage.
one:
    mov ah, 0x02
    mov dl, 'M'                         ; needle: must appear in the output
    int 0x21
    ret

    db 0x0F, 0xFF, 0xFF

; Reached only through slot 1 of the dispatch table.
two:
    mov ah, 0x02
    mov dl, 'Z'                         ; second needle
    int 0x21
    ret

; ---------- data in the code segment ---------------------------------------
banner:
    db 'mzdispatchcs', 0x0D, 0x0A, '$'
index:
    dw 0
table:
    dw one - code_start, two - code_start   ; CS-relative words, per the pattern

; Reached by the direct call above. Its only job is to sit past the table
; and the handlers, so code_hi covers everything the dispatch might name.
helper:
    ret

image_end:
