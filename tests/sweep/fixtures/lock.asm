; One cdecl routine with LOCK prefixes on instructions that lock nothing, in a
; small-model MZ shaped as sweep.asm is.
;
; int timed(int x) { return x + 1; } -- with the `lock nop` delays Jungle Hunt
; (1983) times its port writes with, and the increment written `lock inc ax`.
; An 8088 runs every one of them. Unicorn refuses all five: `nop` and
; arithmetic into a register, the LOCK first or after one, two or three
; segment overrides, at odd and even addresses. So under --cpu 8088 the sweep
; runs them without it, and under 386 every case ends in the CPU's refusal.
; 11 instructions, each counted once.
;
; tests/sweep/regress.py reads the labels from NASM's listing.

BITS 16
ORG 0

%macro frame 0
    push bp
    db 0x8B, 0xEC
%endmacro

HDR_PARAS   equ 4                       ; 64-byte header
IMAGE_LEN   equ image_end - image_start
TOTAL       equ HDR_PARAS * 16 + IMAGE_LEN
DGROUP      equ (data_start - image_start) / 16

%define C(label) (label - image_start)  ; offset in the code segment (CS = 0)
%define D(label) (label - data_start)   ; offset in DGROUP

; ---------------------------------------------------------------- MZ header
    db 'MZ'
    dw TOTAL % 512                      ; bytes used in the last page
    dw (TOTAL + 511) / 512              ; pages
    dw 2                                ; relocations
    dw HDR_PARAS
    dw 0x0010                           ; minalloc
    dw 0xFFFF                           ; maxalloc
    dw DGROUP                           ; SS
    dw D(stack_top)                     ; SP
    dw 0                                ; checksum
    dw C(start)                         ; IP
    dw 0                                ; CS
    dw relocations
    dw 0                                ; overlay number
relocations:
    dw C(fix_ds), 0                     ; mov ax, DGROUP
    dw C(fix_ss), 0                     ; mov bx, DGROUP
    times HDR_PARAS * 16 - ($ - $$) db 0

; ---------------------------------------------------------------- code
image_start:
start:
    mov ax, DGROUP
fix_ds equ $ - 2
    mov ds, ax
    mov bx, DGROUP
fix_ss equ $ - 2
    mov ss, bx
    mov sp, D(stack_top)
    mov ax, 41
    push ax
    call timed
    add sp, 2
    mov ax, 0x4C00
    int 0x21

timed:
    frame
    mov ax, [bp + 4]
    db 0xF0, 0x90                       ; lock nop
    nop                                 ; so that the next starts at the other parity
    db 0xF0, 0x40                       ; lock inc ax
    db 0x2E, 0xF0, 0x90                 ; cs lock nop
    db 0x2E, 0x26, 0xF0, 0x90           ; cs es lock nop
    db 0x26, 0x2E, 0x36, 0xF0, 0x90     ; es cs ss lock nop
    pop bp
    ret
timed_end:

; ---------------------------------------------------------------- data
    align 16
data_start:
    times 64 db 0
stack_top:
image_end:
