; biospal.asm -- mode 4 through INT 10h, then the two palette calls Rollo
; makes: AH=0Bh BH=1 BL=0 (palette 0: green, red, brown) and AH=0Bh BH=0
; BL=1 (background blue, and bit 4 clear, so the colours are not intensified).
; A real CGA shows that, not mode 4's default cyan, magenta and white.
; Every byte is its own offset's low byte.

        org 0x100

start:  mov ax, 0x0004
        int 0x10
        mov ah, 0x0b
        mov bh, 1
        mov bl, 0
        int 0x10
        mov ah, 0x0b
        mov bh, 0
        mov bl, 1
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
