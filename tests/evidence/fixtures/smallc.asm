; A small-model C program in miniature: the case the MZ pipeline was built for.
;
; Everything triage looks for in a good candidate is here on purpose. Two
; relocations, both inside the startup and both patching the segment of the
; data group -- what Sopwith's 2 relocations for 60 KB turned out to be. Four
; `push bp / mov bp, sp` frames in well under a kilobyte, which is what a
; period C compiler emits. One DOS print, one far store into CGA memory, one
; read of the keyboard port, so the fingerprint has something in it.
;
; It is also the fixture tests/handshake imports through Ghidra. `draw` is
; reached only through a function pointer `main` stores as an immediate, and
; `tick` by nothing at all -- the shapes RecoverFunctions exists for. Measured
; on Ghidra 12.1.2, though, auto-analysis finds all five routines by itself
; (its function-start patterns know 55 8B EC) and RecoverFunctions adds none,
; so this fixture tests the handshake, not recovery.
;
; The header is written by hand, like the .COM fixtures', so the bytes under
; test are visible in the source and the file builds with `nasm -f bin`.

BITS 16
ORG 0

; `mov bp, sp` has two encodings. NASM picks 89 E5; Microsoft C emits 8B EC,
; and 8B EC is what triage.py and RecoverFunctions.java count. Spell it out.
%macro frame 0
    push bp
    db 0x8B, 0xEC                       ; mov bp, sp
%endmacro

HDR_PARAS   equ 32                      ; 512-byte header
IMAGE_LEN   equ image_end - image_start
TOTAL       equ HDR_PARAS * 16 + IMAGE_LEN
DGROUP      equ (data_start - image_start) / 16

; ---------------------------------------------------------------- MZ header
    db 'MZ'
    dw TOTAL % 512                      ; bytes used in the last page
    dw (TOTAL + 511) / 512              ; pages
    dw 2                                ; relocations
    dw HDR_PARAS                        ; header size, in paragraphs
    dw 0x0040                           ; minalloc
    dw 0xFFFF                           ; maxalloc
    dw DGROUP                           ; SS = DGROUP, as small model has it
    dw stack_top - data_start           ; SP
    dw 0                                ; checksum
    dw start - image_start              ; IP
    dw 0                                ; CS
    dw relocations                      ; relocation table offset
    dw 0                                ; overlay number
relocations:
    dw fix_ds - image_start, 0          ; the word inside `mov ax, DGROUP`
    dw fix_ss - image_start, 0          ; the word inside `mov bx, DGROUP`
    times HDR_PARAS * 16 - ($ - $$) db 0

; ---------------------------------------------------------------- load image
image_start:

; The startup: load DGROUP into DS and SS. The loader adds the load segment to
; both immediates, which is all a small-model program ever needs fixed up.
start:
    mov ax, DGROUP
fix_ds equ $ - 2
    mov ds, ax
    mov bx, DGROUP
fix_ss equ $ - 2
    mov ss, bx
    mov sp, stack_top - data_start
    call main
    mov ax, 0x4C00
    int 0x21

main:
    frame
    call print
    mov word [handler - data_start], draw - image_start
    call word [handler - data_start]
    pop bp
    ret

print:
    frame
    mov ah, 0x09
    mov dx, message - data_start
    int 0x21
    pop bp
    ret

; Reached only through the pointer `main` stores.
draw:
    frame
    mov ax, 0xB800
    mov es, ax
    mov byte [es:0x0000], 0x41
    pop bp
    ret

; Reached by nothing at all; only a prologue scan finds it.
tick:
    frame
    in al, 0x60
    pop bp
    ret

    align 16, db 0

; ---------------------------------------------------------------- DGROUP
data_start:
message:
    db 'evidence fixture', 0x0D, 0x0A, '$'
handler:
    dw 0
    times 64 db 0
stack_top:

image_end:
