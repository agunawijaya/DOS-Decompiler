; lock.asm -- LOCK prefixes on instructions that lock nothing, the way Jungle
; Hunt (1983) times its port writes with `lock nop`. The 8088 asserts its
; LOCK pin for the instruction and runs it, whatever it is; a later x86
; refuses LOCK on an instruction that is not a read-modify-write of memory,
; and Unicorn refuses it on `nop` and on arithmetic into a register.
;
; Each line below is at an image offset the test names, so that it can run
; the program from any of them. Under --cpu 8088 the whole program runs and
; prints "6 8 0": BX after `lock inc bx`, the counter after `lock inc word`,
; CX after `lock loop`. Under --cpu 386 it faults at the first refused one.

        org 0x100

start:  mov ax, 5
lock1:  lock nop                    ; image 0x03: refused by Unicorn
lock2:  lock mov bx, ax             ; image 0x05: Unicorn ignores the prefix itself
lock3:  lock inc bx                 ; image 0x08: refused -- arithmetic into a register
lock4:  lock inc word [count]       ; image 0x0A: a locked read-modify-write, run anywhere
lock5:  db 0x2E, 0xF0, 0x90         ; image 0x0F: cs lock nop -- the prefix after another
        mov cx, 3
spin:   lock loop spin              ; Unicorn runs it, ignoring the prefix

        mov al, bl
        call digit
        call space
        mov al, [count]
        call digit
        call space
        mov al, cl
        call digit
        mov ax, 0x4c00
        int 0x21

space:  mov dl, ' '
        jmp out
digit:  add al, '0'
        mov dl, al
out:    mov ah, 2
        int 0x21
        ret

count:  dw 7
