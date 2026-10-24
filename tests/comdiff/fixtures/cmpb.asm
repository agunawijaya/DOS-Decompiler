; cmpb.asm -- the sibling of cmpa.asm, the program comdiff.py is reading.
; Everything sits somewhere else: `beep` comes first, so every routine after
; it moves, and the globals are laid out in another order.
;
;   times_ten     the same bytes                       byte-identical
;   accumulate    the same, globals elsewhere          instruction-identical, confirmed
;   find_key      the same, but counts six, not four   instruction-identical, differs
;   halve_twice   one instruction more                 similar
;   beep          only here                            no counterpart
;   one           three bytes                          too small
;   pick          the same switch, its table moved     instruction-identical
;   tick          the same handler, its counter moved  instruction-identical, confirmed

BITS 16
ORG 0x100

start:
    cli
    xor ax, ax
    mov es, ax
    lea ax, [tick]
    mov bx, cs
    xchg word [es:0x70], ax
    xchg word [es:0x72], bx
    sti
    call times_ten
    call accumulate
    call find_key
    call halve_twice
    call beep
    call one
    mov ax, 2
    call pick
    mov ax, 0x4C00
    int 0x21

; Only in B: the speaker on, a moment, the speaker off.
beep:
    push cx
    in al, 0x61
    or al, 3
    out 0x61, al
    mov cx, 0x1000
.hold:
    loop .hold
    and al, 0xFC
    out 0x61, al
    pop cx
    ret

times_ten:
    push bx
    mov bx, ax
    shl ax, 1
    shl ax, 1
    add ax, bx
    shl ax, 1
    pop bx
    ret

accumulate:
    mov ax, [counter]
    add ax, [step]
    mov [counter], ax
    call times_ten
    mov [result], ax
    ret

find_key:
    mov si, keys
    mov cx, 6
.scan:
    cmp al, [si]
    je .found
    add si, 2
    loop .scan
    xor ax, ax
    ret
.found:
    mov al, [si + 1]
    ret

halve_twice:
    push cx
    mov cx, ax
    shr cx, 1
    add ax, cx
    shr cx, 1
    add ax, cx
    inc ax
    pop cx
    ret

one:
    mov al, 1
    ret

pick:
    mov si, ax
    and si, 3
    shl si, 1
    jmp word [cs:si + cases]
cases:
    dw case0, case1, case2, case3
    db 0x0F, 0xFF, 0xFF
case0:
    mov al, 10
    ret
case1:
    mov al, 20
    ret
case2:
    mov al, 30
    ret
case3:
    mov al, 40
    ret
    db 0x0F, 0xFF, 0xFF

tick:
    push ax
    mov ax, [cs:ticks]
    inc ax
    mov [cs:ticks], ax
    pop ax
    iret
    db 0x0F, 0xFF, 0xFF

ticks:   dw 0
keys:    db 1, 10, 2, 20, 3, 30, 4, 40, 5, 50, 6, 60
result:  dw 0
step:    dw 3
counter: dw 0
    db 0x0F, 0xFF, 0xFF         ; the data is not code: keeps the gap sweep out
