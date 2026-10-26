; pit.asm -- the processor measured against the 8253, the way The Ancient Art
; of War (1987) does it before its title: counter 2 loaded with 7950h in mode
; 2, its gate opened, then latched and read again and again, counting loops,
; until the count is below 100. It prints the loops in hex.
;
; Read without a latch the counter gives whatever a port gives; a run that
; answers every port read with an alternating value never gets below 100.

        org 0x100

start:  cli
        in al, 0x61
        or al, 1                    ; open counter 2's gate
        out 0x61, al
        mov al, 0xb4                ; counter 2, low then high byte, mode 2
        out 0x43, al
        mov ax, 0x7950
        out 0x42, al
        xchg al, ah
        out 0x42, al
        xor cx, cx
.again: inc cx
        mov al, 0x80                ; latch counter 2
        out 0x43, al
        in al, 0x42
        mov ah, al
        in al, 0x42
        xchg ah, al
        cmp ax, 100
        ja .again
        sti
        mov [loops], cx
        mov al, ch
        call hex
        mov al, cl
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
