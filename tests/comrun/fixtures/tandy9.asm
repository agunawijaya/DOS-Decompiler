; tandy9.asm -- Tandy 1000 mode 9, drawn on a page that is not shown and
; then shown, the way Rampage (1986) double-buffers.
;
; After INT 10h AX=0009h both page registers are 6, the top of the 128 KB the
; video pages are counted in. The program fills that page with colour 4; then
; points the CPU page at 2 (INT 10h AX=0581h), draws the picture there, shows
; page 2 while the window goes back to page 6 (AX=0583h, BH 2, BL 6), and
; fills page 6 with colour 7, which must not be seen.
;
; The picture: line y is at (y mod 4) * 2000h + (y div 4) * 160, and byte b
; of it holds two pixels, the high nibble first: (b + 3y) and (b + 3y + 5),
; each mod 16. The palette: register i is (7i mod 16) from AX=1002h, then
; register 3 is 15 through the video gate array's ports (3DA index 13h, 3DE)
; and register 5 is 0 through AX=1000h.

        org 0x100

start:  mov ax, 0x0009
        int 0x10
        mov ax, 0xb800
        mov es, ax
        mov al, 0x44                ; page 6: colour 4
        call fill

        mov ax, 0x0581              ; the CPU page: 2
        mov bx, 0x0002
        int 0x10

        xor bp, bp                  ; line
.line:  mov ax, bp
        and ax, 3
        mov cl, 13
        shl ax, cl                  ; (y mod 4) * 2000h
        mov di, ax
        mov ax, bp
        shr ax, 1
        shr ax, 1
        mov cx, 160
        mul cx
        add di, ax                  ; + (y div 4) * 160
        mov ax, bp
        mov cx, 3
        mul cx
        mov bl, al                  ; 3y, low byte: only its low nibble matters
        xor si, si                  ; byte
.byte:  mov ax, si
        add al, bl
        and al, 15                  ; (b + 3y) mod 16
        mov ah, al
        add ah, 5
        and ah, 15                  ; (b + 3y + 5) mod 16
        mov cl, 4
        shl al, cl
        or al, ah
        stosb
        inc si
        cmp si, 160
        jb .byte
        inc bp
        cmp bp, 200
        jb .line

        mov ax, 0x1002
        push es
        push cs
        pop es
        mov dx, palette
        int 0x10
        pop es
        mov dx, 0x3da               ; the video gate array: register 13h ...
        mov al, 0x13
        out dx, al
        mov dx, 0x3de               ; ... is palette register 3
        mov al, 0x0f
        out dx, al
        mov ax, 0x1000
        mov bx, 0x0005              ; register 5 to 0
        int 0x10

        mov ax, 0x0583              ; show page 2; the window back to page 6
        mov bx, 0x0206
        int 0x10
        mov al, 0x77                ; never seen
        call fill
        mov ax, 0x4c00
        int 0x21

fill:   xor di, di
        mov cx, 0x8000
        rep stosb
        ret

palette: db 0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9, 0
