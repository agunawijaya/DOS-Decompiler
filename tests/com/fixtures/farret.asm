; A .COM that moves to a segment of its own with a far return,
;
;     mov bx, cs / add bx, N / push bx / mov ax, OFF / push ax / retf
;
; but not in the first instructions of the file. It checks the DOS version
; first, and the far return is on the far side of a conditional jump whose
; other arm prints a message and returns to DOS. A reading that starts at
; offset 0 and walks straight ahead meets that `ret` and stops; the far
; return is reached only by following the branch.
;
; The return lands at offset 8 of the new segment, not at 0, so the region
; starts eight bytes into it, with its own origin: file 0x0208 at 8.
;
; As in farjmp.asm, the program's routine is reached only through a pointer
; stored as a constant, which names it only from the right origin, and a
; byte that cannot begin an instruction keeps the gap sweep away from it.

BITS 16

section .stub start=0 vstart=0x100
start:
    mov ah, 0x30
    int 0x21                    ; the DOS version, in AL
    cmp al, 2
    jae relocate
    mov dx, too_old
    mov ah, 0x09
    int 0x21
    ret                         ; to the PSP's int 20h

too_old:
    db 'This needs DOS 2 or later.', 0x0D, 0x0A, '$'

relocate:
    mov bx, cs
    add bx, 0x30                ; (0x30 << 4) - 0x100 = file offset 0x200
    push bx
    mov ax, main                ; 8, the routine's offset in that segment
    push ax
    retf

section .code start=0x200 vstart=0
    dw 0x5555, 0x5555, 0x5555, 0x5555   ; eight bytes before the entry

main:
    push cs
    pop ds
    mov word [hook], speak
    call word [hook]
    mov ax, 0x4C00
    int 0x21

    db 0x0F, 0xFF, 0xFF         ; blocks the gap sweep

speak:
    mov ah, 0x02
    mov dl, 'R'
    int 0x21
    mov dl, 'T'
    int 0x21
    ret

    db 0x0F, 0xFF, 0xFF         ; and here

hook:
    dw 0
