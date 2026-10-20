; A load image of just over 64 KB with one long run in it, for the
; arithmetic in bodies.py that only shows past 64 KB: a run, or a body,
; longer than the linear address it starts at is above 0x10000.
;
;   header      64 bytes, no relocations
;   image       0x10200 bytes: a few instructions at 0000; then 90 00 over
;               and over, which is padding byte by byte to bodies.py but no
;               one kind of thing as a whole; at image 0x10100 a line of
;               text; more 90 00; and 32 zero bytes at the end
;
; tests/bodies/regress.py builds exports over it by hand: no Ghidra.

BITS 16
ORG 0

HDR_PARAS   equ 4
IMAGE_LEN   equ 0x10200
TOTAL       equ HDR_PARAS * 16 + IMAGE_LEN

    db 'MZ'
    dw TOTAL % 512                      ; bytes used in the last page
    dw (TOTAL + 511) / 512              ; pages
    dw 0                                ; relocations
    dw HDR_PARAS
    dw 0x0010                           ; minalloc
    dw 0xFFFF                           ; maxalloc
    dw 0x1020                           ; SS: just past the image
    dw 0x0100                           ; SP
    dw 0                                ; checksum
    dw 0                                ; IP
    dw 0                                ; CS
    dw 0x1C                             ; relocation table offset (empty)
    dw 0                                ; overlay number
    times HDR_PARAS * 16 - ($ - $$) db 0

image_start:
    mov ax, 0x4C00                      ; 3 bytes
    int 0x21                            ; 2 bytes
    db 0x90                             ; so the pairs start at an even offset
    times (0x10100 - ($ - image_start)) / 2 db 0x90, 0x00
text:                                   ; image 0x10100
    db 'LONG RUN TEXT'
    db 0x90
    times (0x101E0 - ($ - image_start)) / 2 db 0x90, 0x00
    times IMAGE_LEN - ($ - image_start) db 0
