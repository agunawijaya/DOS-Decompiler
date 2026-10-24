; kbdpoll.asm -- reads the keyboard with no interrupt at all: IRQ 1 masked at
; the PIC, port 0x64 polled until bit 0 says a scancode is waiting, the
; scancode read from port 0x60. Two key presses, printed in hex, and the mask
; put back.

        org 0x100

start:  in al, 0x21
        mov [old_mask], al
        or al, 0x02                 ; mask IRQ 1
        out 0x21, al

poll:   in al, 0x64
        test al, 1
        jz poll
        in al, 0x60
        test al, 0x80               ; ignore the key going up
        jnz poll
        mov bl, [count]
        xor bh, bh
        mov [codes+bx], al
        inc byte [count]
        cmp byte [count], 2
        jb poll

        mov al, [old_mask]
        out 0x21, al

        mov al, [codes]
        call print_hex
        mov al, [codes+1]
        call print_hex
        mov ax, 0x4c00
        int 0x21

print_hex:
        push ax
        mov cl, 4
        shr al, cl
        call digit
        pop ax
        and al, 0x0f
digit:  add al, '0'
        cmp al, '9'
        jbe .out
        add al, 'A' - '9' - 1
.out:   mov dl, al
        mov ah, 2
        int 0x21
        ret

count:    db 0
codes:    db 0, 0
old_mask: db 0
