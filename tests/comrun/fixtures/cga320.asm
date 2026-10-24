; cga320.asm -- 320-wide graphics set through the ports alone, never INT 10h:
; mode control 0x0A, the CRTC loaded from a table, colour select 0x24 (palette
; 1 at low intensity, background red). The CRTC's start address is 20 words,
; so the picture begins 40 bytes into memory -- half a row along.
;
; Every byte of the 16 KB is its own offset's low byte, so the expected
; picture can be computed from the address arithmetic alone.

        org 0x100

start:  mov dx, 0x3d8
        mov al, 0x02                ; graphics, video off while programming
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
        mov al, 0x24
        out dx, al

        mov ax, 0xb800
        mov es, ax
        xor di, di
        mov cx, 0x4000
.fill:  mov ax, di
        stosb
        loop .fill

        mov dx, 0x3d8
        mov al, 0x0a                ; graphics, 320 wide, video on
        out dx, al
        mov ax, 0x4c00
        int 0x21

crtc:   db 0x38, 0x28, 0x2D, 0x0A, 0x7F, 0x06, 0x64, 0x70
        db 0x02, 0x01, 0x06, 0x07, 0x00, 0x14, 0x00, 0x00
