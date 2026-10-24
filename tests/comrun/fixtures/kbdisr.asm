; kbdisr.asm -- reads the keyboard the way Rollo and Moon Bugs (Windmill
; Software, 1983) do: its own INT 09h handler, written straight into the
; vector table rather than set through DOS, reading port 0x60 and
; acknowledging the keyboard and the PIC itself. It waits for two key
; presses, prints their scancodes in hex, puts the vector back and exits.
;
; Under an emulator that hands keys only to INT 16h the handler never runs,
; the count never reaches two, and the wait never ends.

        org 0x100

start:  xor ax, ax
        mov es, ax
        cli
        mov ax, [es:9*4]
        mov [old_vector], ax
        mov ax, [es:9*4+2]
        mov [old_vector+2], ax
        mov word [es:9*4], keyboard
        mov [es:9*4+2], cs
        sti

idle:   cmp byte [count], 2
        jb idle

        cli
        mov ax, [old_vector]
        mov [es:9*4], ax
        mov ax, [old_vector+2]
        mov [es:9*4+2], ax
        sti

        mov al, [codes]
        call print_hex
        mov al, [codes+1]
        call print_hex
        mov ax, 0x4c00
        int 0x21

; AL as two hex digits, through INT 21h AH=02.
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

keyboard:
        push ax
        push bx
        in al, 0x60
        test al, 0x80               ; a break code: the key went up
        jnz .ack
        mov bl, [cs:count]
        cmp bl, 2
        jae .ack
        xor bh, bh
        mov [cs:codes+bx], al
        inc byte [cs:count]
.ack:   in al, 0x61                 ; the XT's acknowledgement: pulse bit 7
        mov ah, al
        or al, 0x80
        out 0x61, al
        mov al, ah
        out 0x61, al
        mov al, 0x20                ; end of interrupt
        out 0x20, al
        pop bx
        pop ax
        iret

count:      db 0
codes:      db 0, 0
old_vector: dw 0, 0
