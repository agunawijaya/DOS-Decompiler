; pit.asm -- a program that measures the processor against the 8253, as The
; Ancient Art of War (1987) does before its title: counter 2 loaded with
; 6000h in mode 2, then its gate opened, then latched and read again and
; again, the loops counted in BX until the count is 200 or below. It prints
; the loops in hex.
;
; Read without a latch the counter gives whatever a port gives; a run that
; answers every port read with an alternating value never gets that low.

        org 0x100

start:  mov al, 10110100b           ; counter 2, low then high byte, mode 2
        out 0x43, al
        mov ax, 0x6000
        out 0x42, al
        mov al, ah
        out 0x42, al
        in al, 0x61
        or al, 1                    ; and only now open its gate
        out 0x61, al
        xor bx, bx
.again: inc bx
        mov al, 0x80                ; latch counter 2
        out 0x43, al
        in al, 0x42
        mov cl, al
        in al, 0x42
        mov ch, al
        cmp cx, 200
        ja .again
        mov [loops], bx
        mov al, bh
        call hex
        mov al, bl
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

loops:  dw 0
