; Software interrupts through vectors the program installs: tests/comrun.
;
; Three handlers of the program's own, each reached only by `int`:
;
;   INT 80h  installed through INT 21h AH=25h. Returns AX + 1, and clears the
;            carry flag in the frame it returns through, as a file-read shim
;            reports success; the caller set the flag before the call.
;   INT 60h  written straight into the vector table. Returns BX = 6060h.
;   INT 21h  its own, installed after saving the old one with AH=35h. It
;            counts each call and passes it on to the vector it replaced, so
;            DOS still answers: the lines below are printed through it.
;
; One line is printed for each handler that ran as it should, the last only
; if the INT 21h handler counted the two prints before it. A harness that
; answers every `int` itself runs none of them and prints nothing.

CPU 8086
BITS 16
ORG 0x100

start:
    mov dx, int80
    mov ax, 0x2580
    int 0x21

    xor ax, ax
    mov es, ax
    cli
    mov word [es:0x60 * 4], int60
    mov [es:0x60 * 4 + 2], cs
    sti

    mov ax, 0x3521
    int 0x21
    mov [old21], bx
    mov [old21 + 2], es
    push cs
    pop es
    mov dx, int21
    mov ax, 0x2521
    int 0x21

    mov ax, 0x1233
    stc
    int 0x80
    jc .no80
    cmp ax, 0x1234
    jne .no80
    mov dx, line80
    mov ah, 0x09
    int 0x21
.no80:
    xor bx, bx
    int 0x60
    cmp bx, 0x6060
    jne .no60
    mov dx, line60
    mov ah, 0x09
    int 0x21
.no60:
    cmp word [count21], 2
    jne .exit
    mov dx, line21
    mov ah, 0x09
    int 0x21
.exit:
    mov ax, 0x4C00
    int 0x21

int80:
    inc ax
    push bp
    mov bp, sp
    and word [bp + 6], 0xFFFE           ; the caller's carry, in its FLAGS
    pop bp
    iret

int60:
    mov bx, 0x6060
    iret

int21:
    inc word [cs:count21]
    jmp far [cs:old21]

line80: db 'INT 80h: the program', 0x27, 's handler, AX + 1, carry clear', 0x0D, 0x0A, '$'
line60: db 'INT 60h: the program', 0x27, 's handler, BX = 6060h', 0x0D, 0x0A, '$'
line21: db 'INT 21h: the program', 0x27, 's handler counted two calls and passed them on', 0x0D, 0x0A, '$'
    align 2, db 0
old21:   dw 0, 0
count21: dw 0
