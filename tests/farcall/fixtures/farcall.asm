; A far function in a second code segment, reached by a relocated far call.
;
; libsig.py and emuverify.py used to find a function's bytes from the offset
; half of its entry alone, which is right only for code in the segment the
; image starts in. Here `farfunc` is at offset 0 of its own segment, so
; reading "offset 0" finds the startup instead.
;
;   segment 0 (CS = 0)   the startup, which calls `nearfunc` and then
;                        `farfunc` through a far call whose segment word is
;                        relocated; and `nearfunc`, an ordinary near routine
;   FARSEG               `farfunc`: a far routine that takes one argument,
;                        writes a global and returns a value
;   DGROUP               the globals, and the stack
;
; The header is written by hand so the bytes under test are visible here.

BITS 16
ORG 0

%macro frame 0
    push bp
    db 0x8B, 0xEC                       ; mov bp, sp, as compilers encode it
%endmacro

HDR_PARAS   equ 4                       ; 64-byte header
IMAGE_LEN   equ image_end - image_start
TOTAL       equ HDR_PARAS * 16 + IMAGE_LEN
FARSEG      equ (far_start - image_start) / 16
DGROUP      equ (data_start - image_start) / 16

%define C(label) (label - image_start)  ; offset in segment 0
%define F(label) (label - far_start)    ; offset in FARSEG
%define D(label) (label - data_start)   ; offset in DGROUP

    db 'MZ'
    dw TOTAL % 512
    dw (TOTAL + 511) / 512
    dw 3                                ; relocations
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
    dw C(fix_ds), 0                     ; mov ax, DGROUP
    dw C(fix_ss), 0                     ; mov bx, DGROUP
    dw C(fix_far), 0                    ; the segment half of the far call
    times HDR_PARAS * 16 - ($ - $$) db 0

image_start:
start:
    mov ax, DGROUP
fix_ds equ $ - 2
    mov ds, ax
    mov bx, DGROUP
fix_ss equ $ - 2
    mov ss, bx
    mov sp, D(stack_top)
    call nearfunc
    mov ax, 0x0005
    push ax
    call FARSEG:F(farfunc)
fix_far equ $ - 2
    add sp, 2
    mov ax, 0x4C00
    int 0x21

; ---- an ordinary near routine in segment 0 ---------------------------------
nearfunc:
    frame
    mov word [D(near_result)], 0x1357
    mov ax, 0x2468
    pop bp
    ret

    align 16, db 0

; ---- a far routine in a segment of its own ---------------------------------
; Reads its argument from [bp + 6] -- past a far return address, CS and IP --
; adds 0x1111, stores the sum in far_result and returns it with 0x00FA in DX.
far_start:
farfunc:
    frame
    mov ax, [bp + 6]
    add ax, 0x1111
    mov [D(far_result)], ax
    mov dx, 0x00FA
    pop bp
    retf
far_end:

    align 16, db 0

data_start:
near_result:
    dw 0
far_result:
    dw 0
    times 64 db 0
stack_top:
image_end:
