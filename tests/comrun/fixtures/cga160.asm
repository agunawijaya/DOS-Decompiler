; cga160.asm -- the 160 by 100 sixteen-colour arrangement Moon Bugs plays in,
; set through the ports alone: eighty-column text with blink off (mode control
; 0x09), the CRTC told 100 character rows of two scanlines each, and every
; cell character 0xDE, a right-hand half block. Each cell is then two pixels,
; its attribute's background colour on the left and its foreground on the
; right.
;
; Each cell's attribute is the low byte of the cell's number, so every one of
; the 256 attributes appears and the expected picture is arithmetic.

        org 0x100

start:  mov dx, 0x3d8
        mov al, 0x01                ; 80 columns, video off while programming
        out dx, al
        mov si, crtc
        mov cx, 16
        xor bl, bl
.next:  mov dx, 0x3d4
        mov al, bl
        out dx, al
        inc dx
        lodsb
        out dx, al
        inc bl
        loop .next
        mov dx, 0x3d9
        xor al, al
        out dx, al

        mov ax, 0xb800
        mov es, ax
        xor di, di
        xor bx, bx                  ; the cell number
        mov cx, 0x2000
.fill:  mov al, 0xde
        stosb
        mov al, bl
        stosb
        inc bx
        loop .fill

        mov dx, 0x3d8
        mov al, 0x09                ; 80 columns, video on, blink off
        out dx, al
        mov ax, 0x4c00
        int 0x21

; The BIOS's eighty-column table, with the vertical registers (R4 to R9) of
; its graphics one: 100 rows of 2 scanlines.
crtc:   db 0x71, 0x50, 0x5A, 0x0A, 0x7F, 0x06, 0x64, 0x70
        db 0x02, 0x01, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00
