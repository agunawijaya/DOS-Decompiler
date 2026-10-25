; text40.asm -- forty-column colour text (INT 10h mode 1), every cell
; written straight into the framebuffer: cell n holds character n mod 256 in
; attribute (n * 7 + 0x1E) mod 128, so all 256 characters appear and no cell
; blinks. The test draws the screen from the shipped font's own bitmaps and
; compares every pixel.

        org 0x100

start:  mov ax, 0x0001              ; 40x25 colour text
        int 0x10
        mov ax, 0xB800
        mov es, ax
        xor di, di
        xor bx, bx                  ; n
        mov cx, 40 * 25
cell:   mov al, bl
        mov dl, 7
        mul dl                      ; AX = (n mod 256) * 7
        add al, 0x1E
        and al, 0x7F
        mov ah, al                  ; the attribute
        mov al, bl                  ; the character
        stosw
        inc bx
        loop cell
        mov ax, 0x4C00
        int 0x21
