; biostty.asm -- text through the BIOS in eighty-column text: AH=09h writes
; 'A' three times in attribute 0x1E without moving the cursor; the cursor
; goes to the last row, second-last column, and AH=0Eh writes "xyz", which
; wraps onto a new line and scrolls the screen up by one row. AH=03h and
; AH=0Fh are asked where the cursor is and what the mode is, and the answers
; are kept at 0x0200 and 0x0202 for the test to read.

        org 0x100

start:  mov ax, 0x0003              ; 80x25 colour text
        int 0x10
        mov ax, 0x0941              ; 'A'
        mov bx, 0x001E              ; page 0, yellow on blue
        mov cx, 3
        int 0x10
        mov ah, 0x02
        xor bh, bh
        mov dx, 0x184E              ; row 24, column 78
        int 0x10
        mov al, 'x'
        call tty
        mov al, 'y'
        call tty
        mov al, 'z'
        call tty
        mov ah, 0x03
        xor bh, bh
        int 0x10
        mov [0x0200], dx            ; row 24, column 1, after the scroll
        mov ah, 0x0F
        int 0x10
        mov [0x0202], ax            ; 80 columns, mode 3
        mov ax, 0x4C00
        int 0x21

tty:    mov ah, 0x0E
        xor bh, bh
        int 0x10
        ret
