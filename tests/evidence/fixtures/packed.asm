; An MZ that looks packed with Microsoft EXEPACK, found two independent ways.
;
; EXEPACK's packed header ends with the ASCII bytes "RB" immediately before the
; entry point, and its stub carries the message "Packed file is corrupt".
; triage.py checks each, and each produces a finding with the same title. The
; prose report prints that title once; the evidence envelope keeps both,
; because two checks agreeing is corroboration and the reader is entitled to
; see it.
;
; Nothing here decompresses anything. The "payload" is filler and the stub
; just exits: the fixture is for the tools that look at a file, not for
; unpack.py, which runs one.

BITS 16
ORG 0

HDR_PARAS   equ 32
IMAGE_LEN   equ image_end - image_start
TOTAL       equ HDR_PARAS * 16 + IMAGE_LEN

    db 'MZ'
    dw TOTAL % 512
    dw (TOTAL + 511) / 512
    dw 0                                ; no relocations: the payload has none yet
    dw HDR_PARAS
    dw 0x0100
    dw 0xFFFF
    dw 0x0040                           ; SS
    dw 0x0100                           ; SP
    dw 0
    dw entry - image_start              ; IP
    dw 0                                ; CS
    dw 0x001C
    dw 0
    times HDR_PARAS * 16 - ($ - $$) db 0

image_start:
payload:
    times 256 db 0x5A                   ; stands in for the compressed program
    db 'RB'                             ; where EXEPACK's packed header ends
entry:
    mov ax, cs
    mov ds, ax
    mov ah, 0x09
    mov dx, corrupt - image_start
    int 0x21
    mov ax, 0x4CFF
    int 0x21
corrupt:
    db 'Packed file is corrupt', 0x0D, 0x0A, '$'
image_end:
