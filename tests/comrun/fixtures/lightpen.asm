; lightpen.asm -- the beam found through the light pen latch, the way Jungle
; Hunt (1983) finds it before starting its own timer: in mode 4, clear the
; latch (3DBh), set it (3DCh), read the address it took from CRTC registers
; 10h and 11h, divide by the 40 bytes of a row, and go round until the row
; is 99, the last one shown. It then prints "99" and the column, in hex.
;
; Answered with whatever a port gives, the address divided by 40 does not
; fit in AL, and the divide error ends the program.

        org 0x100

start:  mov ax, 4
        int 0x10
.again: mov dx, 0x3db
        out dx, al                  ; clear the latch
        inc dx
        out dx, al                  ; set it: it takes the address now
        mov dx, 0x3d4
        mov al, 0x10
        out dx, al
        inc dx
        in al, dx
        mov ah, al                  ; the address, high
        dec dx
        mov al, 0x11
        out dx, al
        inc dx
        in al, dx                   ; and low
        mov dl, 40
        div dl                      ; AL the row, AH the column
        cmp al, 99
        jne .again
        mov [column], ah
        call hex
        mov al, [column]
        call hex
        mov ax, 0x4c00
        int 0x21

hex:    push ax
        shr al, 1
        shr al, 1
        shr al, 1
        shr al, 1
        call nibble
        pop ax
        and al, 15
nibble: add al, '0'
        cmp al, '9'
        jbe .digit
        add al, 'A' - '9' - 1
.digit: mov dl, al
        mov ah, 2
        int 0x21
        ret

column: db 0
