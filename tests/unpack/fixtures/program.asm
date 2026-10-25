; The program tests/unpack packs with an EXEPACK-style stub: an MZ whose
; relocation table matters.
;
; Four segments and eight relocations, two of them past the first 64 KB of
; the image, where EXEPACK's packed table keeps them in a group of their own:
;
;   CODE   the entry, which is not at offset 0; loads DS, prints, and calls
;          three far routines -- directly, through a far pointer in DATA, and
;          through one in HIGH
;   FAR    a far routine that loads DS again
;   DATA   three lines of text and the far pointers
;   HIGH   past 0x10000: a far routine and a far pointer, both relocated
;
; Between DATA and HIGH lie 66,048 zero bytes, which EXEPACK packs as fill
; runs. Each of the five lines is printed only if the relocations it depends
; on were applied -- the far routine prints twice, called directly and
; through the pointer -- so a run of the unpacked file that prints all five
; has every relocation right; one applied to the wrong word sends a far call
; nowhere.

BITS 16
CPU 8086
ORG 0

HDR_PARAS   equ 4
IMAGE_LEN   equ image_end - image_start
TOTAL       equ HDR_PARAS * 16 + IMAGE_LEN

CODE_SEG    equ (code_start - image_start) / 16
FAR_SEG     equ (far_start - image_start) / 16
DATA_SEG    equ (data_start - image_start) / 16
HIGH_SEG    equ (high_start - image_start) / 16
STACK_SEG   equ (stack_start - image_start) / 16

; ---------------------------------------------------------------- MZ header
    db 'MZ'
    dw TOTAL % 512
    dw (TOTAL + 511) / 512
    dw 8                                ; relocations
    dw HDR_PARAS
    dw 0x0010                           ; minalloc
    dw 0xFFFF                           ; maxalloc
    dw STACK_SEG                        ; SS
    dw 0x0100                           ; SP
    dw 0
    dw entry - code_start               ; IP
    dw CODE_SEG                         ; CS
    dw relocations
    dw 0
relocations:
    dw fix_ds - code_start, CODE_SEG
    dw fix_call - code_start, CODE_SEG
    dw fix_far_ds - far_start, FAR_SEG
    dw fix_far_ptr - data_start, DATA_SEG
    dw fix_high_ptr - data_start, DATA_SEG
    dw fix_high_ds - high_start, HIGH_SEG
    dw fix_high_self - high_start, HIGH_SEG
    dw fix_stack - code_start, CODE_SEG
    times HDR_PARAS * 16 - ($ - $$) db 0

; ---------------------------------------------------------------- load image
image_start:
    db 'EXEPACK fixture, before the code', 0

    align 16, db 0
code_start:
    dw 0x5A5A, 0x1234                   ; data the entry steps over
entry:
    mov ax, DATA_SEG
fix_ds equ $ - 2
    mov ds, ax
    mov es, ax
    mov dx, line_entry - data_start
    mov ah, 0x09
    int 0x21
    call FAR_SEG:(far_line - far_start)
fix_call equ $ - 2
    call far [far_ptr - data_start]
    call far [high_ptr - data_start]
    mov bx, STACK_SEG                   ; a relocated word the program only compares
fix_stack equ $ - 2
    mov ax, ss
    cmp ax, bx
    jne .done
    mov dx, line_stack - data_start
    mov ah, 0x09
    int 0x21
.done:
    mov ax, 0x4C00
    int 0x21

    align 16, db 0
far_start:
far_line:
    push ds
    mov ax, DATA_SEG
fix_far_ds equ $ - 2
    mov ds, ax
    mov dx, line_far - data_start
    mov ah, 0x09
    int 0x21
    pop ds
    retf

    align 16, db 0
data_start:
line_entry:
    db 'entry reached, DATA relocated', 0x0D, 0x0A, '$'
line_far:
    db 'far call through a relocated segment', 0x0D, 0x0A, '$'
line_high:
    db 'far call past the first 64 KB', 0x0D, 0x0A, '$'
line_stack:
    db 'SS where the header put it', 0x0D, 0x0A, '$'
    align 2, db 0
far_ptr:
    dw far_line - far_start
    dw FAR_SEG
fix_far_ptr equ $ - 2
high_ptr:
    dw high_line - high_start
    dw HIGH_SEG
fix_high_ptr equ $ - 2

    align 16, db 0
    times 0x10200 db 0                  ; nothing, for fill runs

high_start:
high_line:
    push ds
    mov ax, DATA_SEG
fix_high_ds equ $ - 2
    mov ds, ax
    mov dx, line_high - data_start
    mov ah, 0x09
    int 0x21
    pop ds
    retf
self_ptr:
    dw high_line - high_start
    dw HIGH_SEG                         ; relocated, and never used
fix_high_self equ $ - 2

    align 16, db 0
stack_start:
    times 0x100 db 0x77                 ; the stack, filled so it packs as a run
image_end:
