; except.asm -- a program that takes the CPU's exceptions itself, as the
; Microsoft C and Turbo Pascal runtimes and The Dam Busters (1984) put their
; own handler in vector 0. It installs handlers for INT 0 and INT 1 through
; DOS and for INT 3 and INT 4 straight into the table, then:
;
;   divides six ways that raise the divide error -- by zero, a quotient too
;   big for AL, IDIV from a word at a direct address, DIV from [bp+disp8],
;   AAM 0 and DIV from [bx+disp16] -- each a different length, at the image
;   offsets listed below;
;   sets the trap flag for three instructions;
;   executes `int3` (CC) and `into` (CE) with the overflow flag set.
;
; Its INT 0 handler keeps each return address it was given, in `returns`.
; On an 8088 that is the instruction after the divide, so the program goes on
; and prints "6 3 1 1": the divide errors, the traps, INT 3 and INT 4. On a
; 286 or later it is the divide itself, which divides again.

        org 0x100

start:  mov dx, divide
        mov ax, 0x2500
        int 0x21
        mov dx, trap
        mov ax, 0x2501
        int 0x21
        xor ax, ax
        mov es, ax
        mov word [es:3*4], breakpoint
        mov [es:3*4+2], cs
        mov word [es:4*4], overflow
        mov [es:4*4+2], cs

        xor bx, bx
        mov ax, 1234
div1:   div bl                      ; image 0x31: by zero, 2 bytes
        mov ax, 0x1000
        mov bl, 2
div2:   div bl                      ; image 0x38: 0x800 does not fit in AL, 2 bytes
        xor dx, dx
        mov ax, 99
div3:   idiv word [zero]            ; image 0x3F: a direct address, 4 bytes
        mov bp, zero - 2
        mov ax, 7
div4:   div byte [bp+2]             ; image 0x49: [bp+disp8], 3 bytes
        mov al, 9
div5:   db 0xD4, 0x00               ; image 0x4E: aam 0, 2 bytes
        mov bx, zero - 0x300
div6:   div byte [bx+0x300]         ; image 0x53: [bx+disp16], 4 bytes

        pushf
        pop ax
        or ah, 1                    ; the trap flag
        push ax
        popf
        nop
        nop
        nop
        nop

        int3
        mov al, 0x7f
        add al, 1                   ; sets the overflow flag
        into

        mov al, [count0]
        call digit
        mov al, [count1]
        call digit
        mov al, [count3]
        call digit
        mov al, [count4]
        call digit
        mov ax, 0x4c00
        int 0x21

digit:  add al, '0'
        mov dl, al
        mov ah, 2
        int 0x21
        mov dl, ' '
        int 0x21
        ret

divide: push bp
        push bx
        mov bp, sp
        mov bl, [cs:count0]
        xor bh, bh
        shl bx, 1
        mov ax, [bp+4]              ; the return IP the CPU pushed
        mov [cs:returns+bx], ax
        inc byte [cs:count0]
        pop bx
        pop bp
        iret

trap:   push bp
        mov bp, sp
        inc byte [cs:count1]
        cmp byte [cs:count1], 3
        jb .on
        and word [bp+6], ~0x100     ; three is enough: clear TF in the flags it returns to
.on:    pop bp
        iret

breakpoint:
        inc byte [cs:count3]
        iret
overflow:
        inc byte [cs:count4]
        iret

count0:  db 0
count1:  db 0
count3:  db 0
count4:  db 0
zero:    dw 0
returns: dw 0, 0, 0, 0, 0, 0, 0, 0
