; A .COM that masks the 8087's interrupts: FNDISI, the bytes DB E1.
;
; The twin of fneni.asm, and there for the same reason: comrec cannot rebuild
; it and has to say so from its last check. Capstone names DB E1
; `fdisi8087_nop`, NASM takes that for a label and emits nothing, and the file
; comes out two bytes short.
;
; The difference between the two is the byte the rebuild has where the
; original has DB. Here it is MOV AX (B8), below DB; in fneni.asm it is CLD
; (FC), above it. A comparison that only looked for a larger byte, or only
; for a smaller one, would find the first difference in one file and miss it
; in the other.

BITS 16
ORG 0x100

start:
    mov dx, msg
    mov ah, 0x09
    int 0x21
    fninit
    fndisi                              ; DB E1, the only one in the file
    mov ax, 0x4C00
    int 0x21

msg:
    db 'An 8087 with its interrupts masked.$'
