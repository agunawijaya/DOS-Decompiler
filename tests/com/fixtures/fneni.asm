; A .COM that enables the 8087's interrupts: FNENI, the bytes DB E0.
;
; comrec cannot rebuild this, and it is here to show that it says so. It is
; the one path found to comrec's last check -- the whole-file comparison after
; every instruction has matched its own encoding -- with an honest assembler.
;
; Capstone 5.0.7 names DB E0 `feni8087_nop`. NASM 2.16.03 reads that as a
; label without a colon, which is a warning and not an error, so the line
; assembles to nothing and has no row in the listing. The per-instruction
; check compares listing rows, finds none for this line, and has nothing to
; disagree with; the file comes out two bytes short. Only the whole-file
; comparison sees it, at offset 9, where the rebuild has CLD (FC) and the
; original has DB.
;
; Found by decoding every one-byte opcode, and every second byte after 0F,
; the x87 escapes and the group opcodes -- 2,794 distinct spellings -- and
; assembling each one alone: FNENI and FNDISI (fndisi.asm) were the only ones
; NASM accepted and emitted nothing for.
;
; If comrec learns to spell these, or to count a line with no listing row as
; a mismatch, this file rebuilds, and tests/com/regress.py has to reach the
; last check some other way.

BITS 16
ORG 0x100

start:
    mov dx, msg
    mov ah, 0x09
    int 0x21
    fninit
    fneni                               ; DB E0, the only one in the file
    cld
    mov si, msg
    lodsb
    mov ax, 0x4C00
    int 0x21

msg:
    db 'An 8087 with its interrupts enabled.$'
