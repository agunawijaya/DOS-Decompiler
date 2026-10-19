; An MZ that triage can neither clear nor block: every finding is a warning.
;
; Three relocations, none of them near the entry point, over a two-kilobyte
; image -- which is how a program with far pointers looks, so the memory model
; comes back as compact or larger and the small-model assumption of
; emuverify.py is flagged. Two stack frames in that image, too few for
; compiled C and too many to rule it out. Two kilobytes past the declared load
; image, which might be overlays and might be data. And the bytes "PKLITE" out
; in that trailing region, far from the entry point, in a file that is not
; packed: a signature that has to be reported, and reported as incidental.
;
; It exists so that the envelope test covers the findings that carry a
; question rather than an answer -- the ones that become `unknowns`.

BITS 16
ORG 0

; `mov bp, sp` has two encodings. NASM picks 89 E5; Microsoft C emits 8B EC,
; and 8B EC is what triage.py and RecoverFunctions.java count. Spell it out.
%macro frame 0
    push bp
    db 0x8B, 0xEC                       ; mov bp, sp
%endmacro

HDR_PARAS   equ 32
IMAGE_LEN   equ image_end - image_start
TOTAL       equ HDR_PARAS * 16 + IMAGE_LEN

    db 'MZ'
    dw TOTAL % 512
    dw (TOTAL + 511) / 512
    dw 3
    dw HDR_PARAS
    dw 0x0040
    dw 0xFFFF
    dw 0x0080                           ; SS
    dw 0x0100                           ; SP
    dw 0
    dw start - image_start              ; IP
    dw 0                                ; CS
    dw relocations
    dw 0
relocations:
    dw far_a - image_start, 0
    dw far_b - image_start, 0
    dw far_c - image_start, 0
    times HDR_PARAS * 16 - ($ - $$) db 0

image_start:
start:
    call first
    mov ax, 0x4C00
    int 0x21

first:
    frame
    pop bp
    ret

    times 0x300 - ($ - image_start) db 0x90

; Three far references, the shape a medium- or large-model program has all
; over its image. The words patched are the segment halves.
second:
    frame
    mov ax, 0x0010
far_a equ $ - 2
    mov es, ax
    mov ax, 0x0020
far_b equ $ - 2
    mov ds, ax
    mov ax, 0x0030
far_c equ $ - 2
    pop bp
    ret

    times 2048 - ($ - image_start) db 0
image_end:

; Past the declared load image: never loaded, but still in the file.
trailing:
    times 512 db 0x00
    db 'PKLITE'
    times 2048 - ($ - trailing) db 0x00
