; A .COM whose far return goes to a segment it computes, so its target is
; not a constant and must not be followed.
;
;     mov ax, cs / add ax, 0x20 / add ax, [extra] / push ax / ...  / retf
;
; The segment is CS + 0x20 plus a word the program reads from memory. That
; word is 0x10 in the file, so the run lands at CS + 0x30, file 0x0200 -- but
; a reading of the file cannot know the word still holds 0x10 by then, and a
; reading that skips the instruction it does not understand lands at
; CS + 0x20, file 0x0100, which is padding. That is what an evaluator that
; assumes "anything else leaves the registers alone" does: it splits the file
; at the wrong place, and the rebuild is still byte-identical.
;
; The right answer is to say where the target is computed and not follow it.

BITS 16

section .stub start=0 vstart=0x100
start:
    mov ax, cs
    add ax, 0x20
    add ax, [extra]             ; computed: whatever the word holds by now
    push ax
    xor ax, ax
    push ax
    retf
extra:
    dw 0x10

section .code start=0x200 vstart=0
main:
    push cs
    pop ds
    mov ah, 0x02
    mov dl, 'C'
    int 0x21
    mov ax, 0x4C00
    int 0x21
