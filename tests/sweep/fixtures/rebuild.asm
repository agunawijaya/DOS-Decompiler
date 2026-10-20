; sweep.asm's four routines again, written differently: a stand-in for a
; rebuild from reconstructed source, the binary candidate of a sweep.
;
; Nothing here is at the address it has in sweep.asm. The routines are in
; another order, use other registers and other instructions, and the globals
; sit two bytes further into DGROUP, behind a word sweep.asm does not have.
; What each routine computes is the same, so a sweep of each against the
; original agrees on every input.
;
; Assembled with -DWRONG, clamp_store compares with JG where it should use
; JGE: x equal to g_limit goes to the wrong side, and only that input. That is
; the boundary error tests/sweep/regress.py plants and expects the sweep to
; find, at exactly that input.

BITS 16
ORG 0

%macro frame 0
    push bp
    db 0x8B, 0xEC
%endmacro

HDR_PARAS   equ 4
IMAGE_LEN   equ image_end - image_start
TOTAL       equ HDR_PARAS * 16 + IMAGE_LEN
DGROUP      equ (data_start - image_start) / 16

%define C(label) (label - image_start)
%define D(label) (label - data_start)

    db 'MZ'
    dw TOTAL % 512
    dw (TOTAL + 511) / 512
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
    dw 0
relocations:
    dw C(fix_ds), 0
    dw C(fix_ss), 0
    times HDR_PARAS * 16 - ($ - $$) db 0

image_start:
start:
    mov dx, DGROUP
fix_ds equ $ - 2
    mov ds, dx
    mov ss, dx
    mov sp, D(stack_top)
    mov ax, 0x4C00
    int 0x21
    mov dx, DGROUP                      ; never reached: a second relocated
fix_ss equ $ - 2                        ; DGROUP word, as a compiler's startup
                                        ; often has

; int helper(int x, int y) { return x - y; }   -- first here, last there
helper:
    frame
    mov ax, [bp + 4]
    sub ax, [bp + 6]
    pop bp
    ret

; int rare(int x)
rare:
    frame
    mov ax, [bp + 4]
    cmp ax, 0x1234
    je .seven
    xor ah, ah
    pop bp
    ret
.seven:
    mov ax, 7
    pop bp
    ret

; int muldiv(int a, int b, int c) -- the operands of IMUL the other way round
muldiv:
    frame
    mov ax, [bp + 6]
    imul word [bp + 4]
    mov cx, [bp + 8]
    cwd
    idiv cx
    pop bp
    ret

; int caller(int a, int b) -- DI where the original keeps SI
caller:
    frame
    push di
    mov ax, [bp + 6]
    push ax
    push word [bp + 4]
    call helper
    pop cx
    pop cx
    mov di, ax
    mov ax, [bp + 6]
    cmp [bp + 4], ax
    jge .done
    mov cx, 1
    push cx
    push ax
    call helper
    add sp, 4
    add di, ax
.done:
    xchg ax, di
    pop di
    pop bp
    ret

; void clamp_store(int x) -- the comparison turned round: g_limit against x
clamp_store:
    frame
    mov ax, [bp + 4]
    mov dx, [D(g_limit)]
    cmp dx, ax
%ifdef WRONG
    jg .under                           ; x == g_limit lands above the limit
%else
    jge .under
%endif
    sub ax, dx
    mov [D(g_over)], ax
    add word [D(g_hits)], 1
    pop bp
    ret
.under:
    shr ax, 1
    shr ax, 1
    mov [D(g_under)], ax
    pop bp
    ret

    align 16, db 0

data_start:
g_spare:    dw 0x5A5A                   ; pushes every global two bytes along
g_limit:    dw 10
g_over:     dw 0
g_hits:     dw 0
g_under:    dw 0
    times 64 db 0
stack_top:
image_end:
