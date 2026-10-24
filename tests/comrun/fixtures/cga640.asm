; cga640.asm -- 640-wide two-colour graphics set through the ports alone:
; mode control 0x1A, the BIOS's graphics CRTC table, colour select 0x0E so
; that a set bit is yellow. Every byte is its own offset's low byte.

        org 0x100

start:  mov dx, 0x3d8
        mov al, 0x12                ; graphics, 640 wide, video off
        out dx, al
        mov si, crtc
        mov cx, 16
        xor bl, bl
.next:  mov dx, 0x3d4
        mov al, bl
        mov ah, [si]                ; index and value in one word, the way
        out dx, ax                  ; `out dx, ax` programs a register
        inc si
        inc bl
        loop .next
        mov dx, 0x3d9
        mov al, 0x0e
        out dx, al

        mov ax, 0xb800
        mov es, ax
        xor di, di
        mov cx, 0x4000
.fill:  mov ax, di
        stosb
        loop .fill

        mov dx, 0x3d8
        mov al, 0x1a                ; graphics, 640 wide, video on
        out dx, al
        mov ax, 0x4c00
        int 0x21

crtc:   db 0x38, 0x28, 0x2D, 0x0A, 0x7F, 0x06, 0x64, 0x70
        db 0x02, 0x01, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00
