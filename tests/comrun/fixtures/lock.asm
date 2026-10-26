; lock.asm -- LOCK prefixes on instructions that lock nothing, the way Jungle
; Hunt (1983) times its port writes with `lock nop`. The 8088 asserts its
; LOCK pin for the instruction and runs it, whatever it is; a later x86
; refuses LOCK on an instruction that is not a read-modify-write of memory,
; and Unicorn refuses it on `nop` and on arithmetic into a register.
;
; Each line below is at an image offset the test names, so that it can run
; the program from any of them. The refused ones sit at odd and even
; addresses, and three have the LOCK after one, two and three other prefixes.
; Under --cpu 8088 the whole program runs and prints "6 8 0 6": BX after
; `lock inc bx`, the counter after `lock inc word`, CX after `lock loop`, AL
; after the last, an increment behind three prefixes. Under --cpu 386 it
; faults at the first refused one.

        org 0x100

start:  mov ax, 5
lock1:  lock nop                    ; image 0x03, odd: refused by Unicorn
lock2:  lock mov bx, ax             ; image 0x05: Unicorn ignores the prefix itself
lock3:  lock inc bx                 ; image 0x08, even: refused -- arithmetic into a register
lock4:  lock inc word [count]       ; image 0x0A: a locked read-modify-write, run anywhere
lock5:  db 0x2E, 0xF0, 0x90         ; image 0x0F: cs lock nop -- the LOCK second
lock6:  db 0x2E, 0x26, 0xF0, 0x90   ; image 0x12: cs es lock nop -- third
lock7:  db 0x26, 0x2E, 0x36, 0xF0, 0x40  ; image 0x16: es cs ss lock inc ax -- fourth
        mov cx, 3
spin:   lock loop spin              ; Unicorn runs it, ignoring the prefix

        mov dl, bl
        call digit
        mov dl, [count]
        call digit
        mov dl, cl
        call digit
        mov dl, al
        call last
        mov ax, 0x4c00
        int 0x21

; DL as a digit, and a space after it unless it is the last.
digit:  call last
        mov dl, ' '
        jmp out
last:   add dl, '0'
out:    mov ah, 2
        int 0x21
        ret

count:  dw 7
