; biostext.asm -- text through the BIOS on a 320-wide graphics screen, the
; way Alley Cat (1984) asks its questions: INT 10h mode 4, the cursor set
; with AH=02h, characters written one at a time with AH=0Eh in the colour BL
; gives, a carriage return and a line feed, and then AH=09h writing one
; character twice with bit 7 of BL set, which the BIOS exclusive-ors onto
; what is already there. Under --bios-text the test draws the expected
; screen from the shipped font and compares every pixel; without it the
; screen stays black and the characters are only counted.

        org 0x100

start:  mov ax, 0x0004              ; 320x200, four colours
        int 0x10
        mov ah, 0x02
        xor bh, bh
        mov dx, 0x0102              ; row 1, column 2
        int 0x10
        mov si, first
        mov bl, 2
        call say
        mov si, second
        mov bl, 3
        call say
        mov ax, 0x0958              ; 'X', twice, from the cursor on
        mov bx, 0x0081              ; colour 1, exclusive-or
        mov cx, 2
        int 0x10
        mov ax, 0x4C00
        int 0x21

say:    lodsb
        or al, al
        jz .done
        mov ah, 0x0E
        int 0x10
        jmp say
.done:  ret

first:  db 'Hi!', 0x0D, 0x0A, 0
second: db 'ok', 0
