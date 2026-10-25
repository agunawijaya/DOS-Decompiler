; A .COM whose entry stub leaves through `jmp far [mem]`, the way Moon Patrol
; (1983) starts:
;
;     mov ax, cs / add ax, N / mov [ptr+2], ax / xor ax, ax / mov [ptr], ax
;     jmp far [ptr]
;
; The stub writes a far pointer, CS + N : 0, and jumps through it, so the
; program proper begins at file offset N*16 - 0x100 in a segment of its own,
; addressed from 0. It is not packing. A walk that does not read the stub
; misses the split, and one that takes `jmp far` for an instruction control
; falls through decodes the zero fill behind it as code: 279 of Moon Patrol's
; 58,306 bytes came back that way, nearly all of them `add [bx + si], al`.
;
; The layout here:
;
;   file 0x0000  the stub, addressed from 0x100 as usual, and its pointer
;   file 0x0200  the program, addressed from 0, reached through the pointer
;
; The program enters its one routine through `jmp word [state]` with the
; address stored as a constant, so that routine is found only when this
; segment is addressed from 0: from any other base the constant names
; nothing in the file. A byte that cannot begin an instruction stands in
; front of it, so the gap sweep cannot rescue it either.

BITS 16

section .stub start=0 vstart=0x100
start:
    mov ax, cs
    add ax, 0x30                ; (0x30 << 4) - 0x100 = file offset 0x200
    mov [far_ptr + 2], ax       ; the segment half of the pointer
    xor ax, ax
    mov [far_ptr], ax           ; and the offset half
    jmp far [far_ptr]
far_ptr:
    dw 0xFFFF, 0xFFFF           ; written before it is read

section .code start=0x200 vstart=0
main:
    push cs
    pop ds                      ; DS := this segment, so [state] is its own
    mov word [state], shout
    jmp word [state]

    db 0x0F, 0xFF, 0xFF         ; blocks the gap sweep

shout:
    mov ah, 0x02
    mov dl, 'F'
    int 0x21
    mov dl, 'J'
    int 0x21
    mov ax, 0x4C00
    int 0x21

    db 0x0F, 0xFF, 0xFF         ; and here

state:
    dw 0
