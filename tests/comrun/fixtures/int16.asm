; int16.asm -- the ordinary way to read a key: INT 16h, asked whether a key
; is waiting and then read. Two keys, each printed as its character and the
; high digit of its scancode, then a mode-4 screen with a stripe in it, so
; that a run of this checks both what INT 16h hands over and what is drawn.
; Nothing here touches port 0x60 or vector 9, so its output must not change
; whatever the keyboard code does.

        org 0x100

start:  call read_key
        call read_key

        mov ax, 0x0004
        int 0x10
        mov ax, 0xb800
        mov es, ax
        mov di, 80 * 50
        mov cx, 80
        mov al, 0x1b                ; colours 0, 1, 2, 3, left to right
        rep stosb
        mov ax, 0x4c00
        int 0x21

read_key:
        mov ah, 1
        int 0x16
        jz read_key
        mov ah, 0
        int 0x16
        mov bx, ax                  ; keep the key
        mov dl, bl
        mov ah, 2
        int 0x21                    ; its character
        mov al, bh
        mov cl, 4
        shr al, cl                  ; and the high digit of its scancode
        add al, '0'
        mov dl, al
        mov ah, 2
        int 0x21
        ret
