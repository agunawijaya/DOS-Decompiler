; One segment of just over 64 KB whose header says the last page is full.
;
; Ghidra 12.1.2's MZ loader drops a full last page (knowledge/04-pitfalls.md),
; and CorrectMzLoad.java maps it back at the address DOS loads it at -- in the
; segment of the block before it when it fits there. Here it cannot: the one
; block Ghidra builds starts at 1000:0000 and runs to image offset 0xFFBF, so
; the missing page, image 0xFFC0..0x101BF, would need offsets up to 0x101BF in
; segment 0x1000. This is the file that makes the corrector use the other
; form, the page's own paragraph (1FFC:0000).
;
;   header      64 bytes (4 paragraphs), no relocations
;   image       0x101C0 bytes: a few instructions at 0000, filler, a marker
;               at the start of the last page
;   total       0x10200 bytes = 129 pages of 512, so bytes-on-last-page is 0

BITS 16
ORG 0

HDR_PARAS   equ 4
TOTAL       equ 0x10200
IMAGE_LEN   equ TOTAL - HDR_PARAS * 16

    db 'MZ'
    dw TOTAL % 512                      ; 0: the last page is full
    dw TOTAL / 512                      ; 129 pages
    dw 0                                ; relocations
    dw HDR_PARAS
    dw 0x0010                           ; minalloc
    dw 0xFFFF                           ; maxalloc
    dw 0x101C                           ; SS: just past the image
    dw 0x0100                           ; SP
    dw 0                                ; checksum
    dw 0                                ; IP
    dw 0                                ; CS
    dw 0x1C                             ; relocation table offset (empty)
    dw 0                                ; overlay number
    times HDR_PARAS * 16 - ($ - $$) db 0

image_start:
    mov ax, 0x4C00
    int 0x21
    ; Filler to the start of the last page, file 0x10000 (image 0xFFC0).
    times 0x10000 - ($ - $$) db 0xEE
last_page:
    db 'LAST PAGE, PAST 64K'
    times TOTAL - ($ - $$) db 0xEE
