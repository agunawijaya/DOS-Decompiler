; An MZ overlay module: header field 0x1A says overlay 1, not a main program.
;
; triage.py blocks it, because nothing in the toolkit handles code that is
; swapped into a shared region at run time. survey.py lists it separately from
; the executables for the same reason. Both have to say so in their evidence.

BITS 16
ORG 0

; `mov bp, sp` has two encodings. NASM picks 89 E5; Microsoft C emits 8B EC,
; and 8B EC is what triage.py and RecoverFunctions.java count. Spell it out.
%macro frame 0
    push bp
    db 0x8B, 0xEC                       ; mov bp, sp
%endmacro

HDR_PARAS   equ 32
IMAGE_LEN   equ image_end - image_start
TOTAL       equ HDR_PARAS * 16 + IMAGE_LEN

    db 'MZ'
    dw TOTAL % 512
    dw (TOTAL + 511) / 512
    dw 0
    dw HDR_PARAS
    dw 0
    dw 0
    dw 0
    dw 0
    dw 0
    dw 0                                ; IP
    dw 0                                ; CS
    dw 0x001C
    dw 1                                ; overlay number
    times HDR_PARAS * 16 - ($ - $$) db 0

image_start:
    frame
    mov ax, 1
    pop bp
    retf
image_end:
