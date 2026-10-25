; irq0.asm -- keeps time the way a game with its own clock does: its own
; INT 08h handler, written straight into the vector table, counting ticks,
; and passing every other one on to the handler it replaced -- on a real
; machine the BIOS's, which counts the tick at 0040:006C, raises INT 1Ch and
; acknowledges the PIC. INT 1Ch is hooked here too, and counted.
;
; Before any tick may count, IRQ 0 is masked at the PIC while the program
; spins for a while; nothing may arrive. Then it is unmasked, the program
; waits for six ticks of its own, puts both vectors back and prints, as hex
; bytes: its ticks, the INT 1Ch calls, how far 0040:006C moved, and the
; ticks that arrived while masked. With IRQ 0 delivered as the hardware does
; it that is "06030300".
;
; An emulator that only answers interrupts never runs the handler at all,
; and the wait never ends. One that sends interrupt 8 to it every so often
; whatever the PIC says counts ticks while masked, and the ticks passed on
; reach nothing that counts them or raises INT 1Ch.

        org 0x100

start:  cli
        in al, 0x21
        or al, 0x01                 ; mask IRQ 0
        out 0x21, al
        xor ax, ax
        mov es, ax
        mov ax, [es:8*4]
        mov [old_timer], ax
        mov ax, [es:8*4+2]
        mov [old_timer+2], ax
        mov ax, [es:0x1C*4]
        mov [old_user], ax
        mov ax, [es:0x1C*4+2]
        mov [old_user+2], ax
        mov word [es:8*4], timer
        mov [es:8*4+2], cs
        mov word [es:0x1C*4], user_tick
        mov [es:0x1C*4+2], cs
        sti

        xor cx, cx                  ; 65,536 turns with IRQ 0 masked
masked: loop masked
        mov al, [ticks]
        mov [while_masked], al

        mov bx, [es:0x46C]
        mov [bios_before], bx
        cli
        in al, 0x21
        and al, 0xFE                ; unmask IRQ 0
        out 0x21, al
        sti

idle:   cmp byte [ticks], 6
        jb idle

        cli
        mov ax, [old_timer]
        mov [es:8*4], ax
        mov ax, [old_timer+2]
        mov [es:8*4+2], ax
        mov ax, [old_user]
        mov [es:0x1C*4], ax
        mov ax, [old_user+2]
        mov [es:0x1C*4+2], ax
        sti

        mov al, [ticks]
        call print_hex
        mov al, [calls]
        call print_hex
        mov ax, [es:0x46C]
        sub ax, [bios_before]
        call print_hex
        mov al, [while_masked]
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

; IRQ 0. The odd ticks go on to the replaced handler, which acknowledges the
; PIC itself; the even ones are acknowledged here.
timer:  push ax
        inc byte [cs:ticks]
        test byte [cs:ticks], 1
        jz .own
        pop ax
        jmp far [cs:old_timer]
.own:   mov al, 0x20
        out 0x20, al
        pop ax
        iret

; INT 1Ch, raised by the BIOS's INT 08h.
user_tick:
        inc byte [cs:calls]
        iret

old_timer:      dw 0xFFFF, 0xFFFF   ; written before they are read
old_user:       dw 0xFFFF, 0xFFFF
bios_before:    dw 0xFFFF
ticks:          db 0
calls:          db 0
while_masked:   db 0
