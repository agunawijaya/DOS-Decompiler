; An MZ that names an interpreter's resource files.
;
; Sierra's SCI interpreter opens RESOURCE.MAP and RESOURCE.000; the game is in
; those files and the executable is a virtual machine. Decompiling it succeeds
; and tells you nothing you wanted, which is why triage.py blocks on the name
; alone. The fixture carries the names and nothing else.

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
    dw 0x0040
    dw 0xFFFF
    dw 0x0020                           ; SS
    dw 0x0100                           ; SP
    dw 0
    dw 0                                ; IP
    dw 0                                ; CS
    dw 0x001C
    dw 0
    times HDR_PARAS * 16 - ($ - $$) db 0

image_start:
    frame
    mov ax, 0x4C00
    int 0x21
map_name:
    db 'RESOURCE.MAP', 0
volume_name:
    db 'RESOURCE.000', 0
image_end:
