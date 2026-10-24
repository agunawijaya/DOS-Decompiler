; biospal.asm -- mode 4 through INT 10h, then the two palette calls a game of
; the period makes after it: AH=0Bh BH=0 BL=12h (background green, and bit 4,
; so the colours are intensified) and AH=0Bh BH=1 BL=0 (palette 0: green,
; red, brown, here light green, light red and yellow). A real CGA shows that,
; not mode 4's default cyan, magenta and white. Every byte is its own
; offset's low byte.

        org 0x100

start:  mov ax, 0x0004
        int 0x10
        mov bx, 0x0012              ; BH=0: background and intensity
        mov ah, 0x0b
        int 0x10
        mov bx, 0x0100              ; BH=1: the palette, 0
        mov ah, 0x0b
        int 0x10

        mov ax, 0xb800
        mov es, ax
        xor di, di
        mov cx, 0x4000
.fill:  mov ax, di
        stosb
        loop .fill
        mov ax, 0x4c00
        int 0x21
