; atkeys.asm -- three keys, each read a different way, each waited for at an
; image offset a --at can name:
;
;   0x10  through INT 16h, with vector 9 still the BIOS's;
;   0x30  through its own INT 09h handler, which keeps the make code and
;         passes nothing on;
;   0x50  through INT 16h again, while its handler, now passing each key on
;         to the BIOS's, keeps the make code too -- a program reading both.
;
; It prints the first key's character, the second's make code in hex, the
; third's character and the make code its handler saw, then puts vector 9
; back and exits. Given 'a', 'b' and 'c' it prints "a 30 c 2E".

        org 0x100

start:  jmp wait16

        times 0x10 - ($ - $$) nop
wait16: mov ah, 1                   ; image 0x10
        int 0x16
        jz wait16
        mov ah, 0
        int 0x16
        mov [first], al
        jmp install

        times 0x30 - ($ - $$) nop
wait09: cmp byte [made], 0          ; image 0x30
        je wait09
        jmp both

        times 0x50 - ($ - $$) nop
wait_both:
        mov ah, 1                   ; image 0x50
        int 0x16
        jz wait_both
        mov ah, 0
        int 0x16
        mov [third], al
        jmp finish

install:
        xor ax, ax
        mov es, ax
        cli
        mov ax, [es:9*4]
        mov [old_vector], ax
        mov ax, [es:9*4+2]
        mov [old_vector+2], ax
        mov word [es:9*4], keyboard
        mov [es:9*4+2], cs
        sti
        jmp wait09

both:   mov al, [made]
        mov [second], al
        mov byte [made], 0
        mov byte [chain], 1
        jmp wait_both

finish: cli
        mov ax, [old_vector]
        mov [es:9*4], ax
        mov ax, [old_vector+2]
        mov [es:9*4+2], ax
        sti
        mov dl, [first]
        call char
        mov al, [second]
        call hex
        mov dl, [third]
        call char
        mov al, [made]
        call hex
        mov ax, 0x4c00
        int 0x21

hex:    push ax
        mov cl, 4
        shr al, cl
        call nibble
        pop ax
        and al, 0x0f
        call nibble
        mov dl, ' '
        jmp out
nibble: add al, '0'
        cmp al, '9'
        jbe .digit
        add al, 'A' - '9' - 1
.digit: mov dl, al
        jmp out
char:   call out
        mov dl, ' '
out:    mov ah, 2
        int 0x21
        ret

keyboard:
        push ax
        in al, 0x60
        test al, 0x80               ; a break code: the key went up
        jnz .done
        cmp byte [cs:made], 0
        jne .done
        mov [cs:made], al
.done:  cmp byte [cs:chain], 0
        je .ack
        pop ax
        jmp far [cs:old_vector]     ; the BIOS's acknowledges it
.ack:   in al, 0x61
        mov ah, al
        or al, 0x80
        out 0x61, al
        mov al, ah
        out 0x61, al
        mov al, 0x20                ; end of interrupt
        out 0x20, al
        pop ax
        iret

first:      db 0
second:     db 0
third:      db 0
made:       db 0
chain:      db 0
old_vector: dw 0, 0
