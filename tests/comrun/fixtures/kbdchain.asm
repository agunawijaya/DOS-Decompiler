; kbdchain.asm -- a handler that watches the keyboard and passes it on: it
; counts the scancodes it sees in port 0x60, then jumps to the INT 09h
; handler it replaced, which on a real machine is the BIOS's and turns the
; make code into a key for INT 16h. The program reads its two keys from
; INT 16h, prints them, prints how many scancodes its handler saw, and exits.

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

        call read_key
        call read_key

        cli
        mov ax, [old_vector]
        mov [es:9*4], ax
        mov ax, [old_vector+2]
        mov [es:9*4+2], ax
        sti

        mov dl, [seen]
        add dl, '0'
        mov ah, 2
        int 0x21
        mov ax, 0x4c00
        int 0x21

; Wait until INT 16h has a key, read it, print its character.
read_key:
        mov ah, 1
        int 0x16
        jz read_key
        mov ah, 0
        int 0x16
        mov dl, al
        mov ah, 2
        int 0x21
        ret

keyboard:
        push ax
        in al, 0x60
        inc byte [cs:seen]
        pop ax
        jmp far [cs:old_vector]

seen:       db 0
old_vector: dw 0, 0
