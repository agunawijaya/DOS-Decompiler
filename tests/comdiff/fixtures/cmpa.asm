; cmpa.asm -- the program comdiff.py is told it knows. cmpb.asm is its
; sibling, written the way Moon Bugs relates to Rollo: some routines copied
; byte for byte, some moved so that only their addresses differ, one whose
; loop bound differs, one edited, one each that the other lacks.
;
; The routines are reached the three ways a routine starts in comdiff.py:
; called; a handler installed by writing the vector table, which nothing
; branches to; and the program's entry. `pick` is a switch whose four cases
; are reached through a jump table, and they are part of it, not routines.

BITS 16
ORG 0x100

start:
    cli
    xor ax, ax
    mov es, ax
    lea ax, [tick]
    mov bx, cs
    xchg word [es:0x70], ax     ; 0x70 / 4 = vector 0x1C, the user tick
    xchg word [es:0x72], bx
    sti
    call times_ten
    call accumulate
    call find_key
    call halve_twice
    call copy_name
    call one
    mov ax, 2
    call pick
    mov ax, 0x4C00
    int 0x21

; The same bytes in both programs.
times_ten:
    push bx
    mov bx, ax
    shl ax, 1
    shl ax, 1
    add ax, bx
    shl ax, 1
    pop bx
    ret

; The same instructions; B keeps the globals elsewhere.
accumulate:
    mov ax, [counter]
    add ax, [step]
    mov [counter], ax
    call times_ten
    mov [result], ax
    ret

; The same instructions, but B's table is longer, so its count differs --
; and with it what the routine does.
find_key:
    mov si, keys
    mov cx, 4
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

; B adds one instruction: similar, not identical.
halve_twice:
    push cx
    mov cx, ax
    shr cx, 1
    add ax, cx
    shr cx, 1
    add ax, cx
    pop cx
    ret

; Only in A.
copy_name:
    push si
    push di
    mov si, name
    mov di, buffer
    mov cx, 8
    cld
    rep movsb
    pop di
    pop si
    ret

; Too small to compare.
one:
    mov al, 1
    ret

; A switch on AX: the four cases are part of pick.
pick:
    mov si, ax
    and si, 3
    shl si, 1
    jmp word [cs:si + cases]
cases:
    dw case0, case1, case2, case3
    db 0x0F, 0xFF, 0xFF         ; not an instruction: keeps the gap sweep out
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

; The timer handler, installed above and reached by nothing in the program.
tick:
    push ax
    mov ax, [cs:ticks]
    inc ax
    mov [cs:ticks], ax
    pop ax
    iret
    db 0x0F, 0xFF, 0xFF

counter: dw 0
step:    dw 3
result:  dw 0
ticks:   dw 0
keys:    db 1, 10, 2, 20, 3, 30, 4, 40
name:    db "ABCDEFGH"
buffer:  times 8 db 0
    db 0x0F, 0xFF, 0xFF         ; the data is not code: keeps the gap sweep out
