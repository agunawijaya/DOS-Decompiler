; Function bodies that are not one contiguous run of bytes the function owns.
;
; `functions.json` used to give each function an entry and one `size`. This
; small-model MZ holds the shapes that make that misleading, each named in a
; comment above it:
;
;   left, right       two functions that jump to one shared epilogue
;   jumper, fall      a jump into the middle of a neighbour: `jumper` jumps to
;                     the tail `fall` falls through into
;   chunky            a function whose second chunk sits after another
;                     function, reached by a conditional jump
;   switcher          a jump table in the middle of a function
;   pointed_a/_b      routines reached only through a table of function
;                     pointers main fills with immediates
;   faller            falls through into `fallen`, a prologue nothing calls
;   lonely            a prologue nothing calls, straight after a string
;   tailer            ends by jumping to `middle`, which main also calls: a
;                     tail call, which is not a claim on middle's code
;   orphan            bytes that read as code and that nothing reaches
;
; What Ghidra 12.1.2 makes of each was measured before tests/bodies expected
; anything of it; tests/bodies/regress.py says which shape gives which body.
;
; The header is written by hand so the bytes under test are visible here, and
; the file builds with `nasm -f bin`.

BITS 16
ORG 0

; `mov bp, sp` has two encodings. NASM picks 89 E5; compilers of the period
; emit 8B EC, which is what RecoverFunctions.java looks for.
%macro frame 0
    push bp
    db 0x8B, 0xEC
%endmacro

HDR_PARAS   equ 4                       ; 64-byte header
IMAGE_LEN   equ image_end - image_start
TOTAL       equ HDR_PARAS * 16 + IMAGE_LEN
DGROUP      equ (data_start - image_start) / 16

%define C(label) (label - image_start)  ; offset in the code segment (CS = 0)
%define D(label) (label - data_start)   ; offset in DGROUP

; ---------------------------------------------------------------- MZ header
    db 'MZ'
    dw TOTAL % 512                      ; bytes used in the last page
    dw (TOTAL + 511) / 512              ; pages
    dw 2                                ; relocations
    dw HDR_PARAS
    dw 0x0010                           ; minalloc
    dw 0xFFFF                           ; maxalloc
    dw DGROUP                           ; SS
    dw D(stack_top)                     ; SP
    dw 0                                ; checksum
    dw C(start)                         ; IP
    dw 0                                ; CS
    dw relocations
    dw 0                                ; overlay number
relocations:
    dw C(fix_ds), 0
    dw C(fix_ss), 0
    times HDR_PARAS * 16 - ($ - $$) db 0

; ---------------------------------------------------------------- code
image_start:
start:
    mov ax, DGROUP
fix_ds equ $ - 2
    mov ds, ax
    mov bx, DGROUP
fix_ss equ $ - 2
    mov ss, bx
    mov sp, D(stack_top)
    call main
    mov ax, 0x4C00
    int 0x21

main:
    frame
    call left
    call right
    call jumper
    call fall
    call chunky
    call middle
    mov bx, 1
    call switcher
    call faller
    call tailer
    mov word [D(handlers)], C(pointed_a)
    mov word [D(handlers) + 2], C(pointed_b)
    mov bx, 2
    call word [D(handlers) + bx]
    pop bp
    ret

; ---- two functions, one epilogue ------------------------------------------
left:
    frame
    mov ax, 0x0101
    jmp short shared_tail
right:
    frame
    mov ax, 0x0202
    jmp short shared_tail
shared_tail:
    mov sp, bp
    pop bp
    ret

; ---- a jump into the middle of a neighbour ---------------------------------
jumper:
    frame
    mov ax, 0x1111
    jmp short fall_tail
fall:
    frame
    mov ax, 0x2222
fall_tail:
    mov sp, bp
    pop bp
    ret

; ---- a function in two pieces, another function between them --------------
chunky:
    frame
    cmp ax, 0x0007
    je chunky_rest
    mov ax, 0x0303
    pop bp
    ret
middle:
    frame
    mov ax, 0x0404
    pop bp
    ret
chunky_rest:
    add ax, 0x0011
    pop bp
    ret

; ---- a jump table in the middle of a function -----------------------------
switcher:
    frame
    cmp bx, 2
    ja .out
    shl bx, 1
    jmp word [cs:bx + C(.table)]
.table:
    dw C(.case0), C(.case1), C(.case2)
.case0:
    mov ax, 0x0A0A
    jmp short .out
.case1:
    mov ax, 0x0B0B
    jmp short .out
.case2:
    mov ax, 0x0C0C
.out:
    pop bp
    ret

; ---- reached only through the handler table main fills -------------------
pointed_a:
    mov ax, 0xB800
    mov es, ax
    mov byte [es:0x0002], 0x41
    ret
pointed_b:
    mov dx, 0x03D8
    mov al, 0x09
    out dx, al
    ret

; ---- a fall-through into a prologue nothing calls --------------------------
faller:
    frame
    mov ax, 0x0505
    pop bp
fallen:
    frame
    mov ax, 0x0606
    pop bp
    ret

; ---- a prologue nothing calls, straight after a string --------------------
banner:
    db 'BODIES'
lonely:
    frame
    mov ax, 0x0707
    pop bp
    ret

; ---- a tail call into a function main calls ---------------------------------
tailer:
    frame
    mov ax, 0x0808
    pop bp
    jmp near middle

; ---- code nothing reaches, between two runs of padding ---------------------
    db 0x90, 0x90
orphan:
    mov cx, 0x0010
    mov si, 0x0123
.next:
    lodsb
    cmp al, 0x2E
    je .found
    loop .next
.found:
    ret

    align 16, db 0

; ---------------------------------------------------------------- DGROUP
data_start:
message:
    db 'bodies fixture', 0x0D, 0x0A, '$'
    align 2, db 0
handlers:
    dw 0, 0, 0
    times 64 db 0
stack_top:
image_end:
