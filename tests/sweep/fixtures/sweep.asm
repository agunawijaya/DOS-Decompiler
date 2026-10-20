; Four small cdecl routines to sweep, in a small-model MZ.
;
; `emuverify.py sweep` runs one routine of an original program on every input
; of a domain and compares it with a candidate. These are the shapes where a
; port's arithmetic goes wrong, each named in a comment above it:
;
;   muldiv        IMUL then IDIV on 16-bit ints: the product wraps, and IDIV
;                 faults on a zero divisor and on -32768 / -1
;   clamp_store   writes two globals on one side of a signed comparison and a
;                 third, shifted right unsigned, on the other
;   rare          a branch only one input in 65,536 takes
;   caller        calls `helper` once, and a second time only when a < b
;
; tests/sweep/regress.py works out every expected value from this file: the
; labels from NASM's listing, and the instruction counts by hand, written out
; beside each routine. tests/sweep/fixtures/rebuild.asm is the same four
; routines written differently, to stand in for a rebuild from reconstructed
; source.
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
    dw C(fix_ds), 0                     ; mov ax, DGROUP
    dw C(fix_ss), 0                     ; mov bx, DGROUP
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
    mov ax, 3
    push ax
    mov ax, 2
    push ax
    mov ax, 1
    push ax
    call muldiv
    add sp, 6
    mov ax, 0x4C00
    int 0x21

; int muldiv(int a, int b, int c) { return (a * b) / c; }
;
; C keeps the low word of the product (AX) and sign-extends it again (CWD)
; before dividing, so the product wraps at 16 bits. IDIV faults when c is 0,
; and when the wrapped product is -32768 and c is -1, because +32768 does not
; fit. 8 instructions, every one run by any input that does not fault.
muldiv:
    frame
    mov ax, [bp + 4]
    imul word [bp + 6]
    cwd
    idiv word [bp + 8]
    pop bp
    ret
muldiv_end:

; void clamp_store(int x)
; {
;     if (x > g_limit) { g_over = x - g_limit; g_hits++; }
;     else             g_under = (unsigned)x >> 2;
; }
;
; The comparison is signed (JLE); the shift is unsigned (SHR), so a negative
; x arrives in g_under as a large positive number. 14 instructions: 7 run on
; both sides, 4 only above the limit, 3 only at or below it.
clamp_store:
    frame
    mov ax, [bp + 4]
    cmp ax, [D(g_limit)]
    jle .under
    sub ax, [D(g_limit)]
    mov [D(g_over)], ax
    inc word [D(g_hits)]
    jmp .done
.under:
    mov cl, 2
    shr ax, cl
    mov [D(g_under)], ax
.done:
    pop bp
    ret
clamp_store_end:

; int rare(int x) { return x == 0x1234 ? 7 : x & 0xFF; }
;
; 10 instructions. `mov ax, 7` and the `jmp` after it run only for 0x1234, so
; a domain without that value exercises 8 of the 10.
rare:
    frame
    mov ax, [bp + 4]
    cmp ax, 0x1234
    jne .common
    mov ax, 7
    jmp .out
.common:
    and ax, 0x00FF
.out:
    pop bp
    ret
rare_end:

; int caller(int a, int b)
; {
;     int r = helper(a, b);
;     if (a < b) r += helper(b, 1);
;     return r;
; }
;
; The comparison is signed (JGE). Under a sweep `helper` never runs: each call
; is skipped and answers with its stub, and the sweep compares the calls made
; -- target and arguments -- as well as what comes back. 21 instructions; the
; 6 from `mov ax, 1` to `add si, ax` run only when a < b.
caller:
    frame
    push si
    push word [bp + 6]
    push word [bp + 4]
    call helper
    add sp, 4
    mov si, ax
    mov ax, [bp + 4]
    cmp ax, [bp + 6]
    jge .done
    mov ax, 1
    push ax
    push word [bp + 6]
    call helper
    add sp, 4
    add si, ax
.done:
    mov ax, si
    pop si
    pop bp
    ret
caller_end:

; int helper(int x, int y) { return x - y; }
helper:
    frame
    mov ax, [bp + 4]
    sub ax, [bp + 6]
    pop bp
    ret
helper_end:

    align 16, db 0

; ---------------------------------------------------------------- data
data_start:
g_limit:    dw 10
g_over:     dw 0
g_hits:     dw 0
g_under:    dw 0
    times 64 db 0
stack_top:
image_end:
