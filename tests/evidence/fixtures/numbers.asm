; An MZ whose every number triage reads is set from NASM's command line.
;
; Each of triage's rules turns on a number: prologues per kilobyte (2.0 and
; 0.5), how far a packer's signature sits from the entry point (0x400), the
; prologue density that calls a file stripped (0.2), how many relocations it
; has. A rule tested only far from its threshold passes whichever side of it
; the code puts the threshold, so tests/evidence builds this file several
; times with -D values that put one number exactly on one threshold. Built
; with none, it is a 1 KB image with two frames and nothing else.
;
;   -DIMAGE=n        bytes in the load image
;   -DPROLOGUES=n    `push bp / mov bp, sp` frames at the start of the image
;   -DRELOCS=n       relocations, at image offsets 0x400, 0x500, ... -- away
;                    from the entry, as a program with far pointers has them
;   -DENTRY=n        the entry point's offset in the image
;   -DSIG=text -DSIG_AT=n
;                    a packer's signature at that image offset
;
; Nothing here runs: triage reads files, it does not execute them.

BITS 16
ORG 0

%ifndef IMAGE
%define IMAGE 1024
%endif
%ifndef PROLOGUES
%define PROLOGUES 2
%endif
%ifndef RELOCS
%define RELOCS 0
%endif
%ifndef ENTRY
%define ENTRY 0
%endif

HDR_PARAS   equ 4                       ; 64 bytes: room for nine relocations
TOTAL       equ HDR_PARAS * 16 + IMAGE

    db 'MZ'
    dw TOTAL % 512
    dw (TOTAL + 511) / 512
    dw RELOCS
    dw HDR_PARAS
    dw 0x0010                           ; minalloc
    dw 0xFFFF                           ; maxalloc
    dw 0                                ; SS
    dw 0xFFFE                           ; SP
    dw 0                                ; checksum
    dw ENTRY % 16                       ; IP
    dw ENTRY / 16                       ; CS
    dw relocations
    dw 0                                ; overlay number
relocations:
%assign i 0
%rep RELOCS
    dw 0x400 + 0x100 * i, 0
%assign i i + 1
%endrep
    times HDR_PARAS * 16 - ($ - $$) db 0

image_start:
%rep PROLOGUES
    db 0x55, 0x8B, 0xEC                 ; push bp / mov bp, sp
%endrep
%ifdef SIG
    times SIG_AT - ($ - image_start) db 0
    db SIG
%endif
    times IMAGE - ($ - image_start) db 0
image_end:
