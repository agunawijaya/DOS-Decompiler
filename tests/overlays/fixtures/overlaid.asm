; An MZ with two overlays in Microsoft LINK's format: tests/overlays' fixture.
;
; The file is the root -- an MZ with an overlay area in its image -- and two
; overlay modules after it, each an MZ of its own with its overlay number at
; 0x1A of its header, the first on the page after the root's last and the
; second on the page after that. Every module loads at the overlay area, so
; their code shares addresses. Module 2 has two segments, as LINK lays out a
; module built from two code segments.
;
; A call into an overlay is `int 3Fh` followed by a byte and a word: which
; module, and the offset in it. The root installs its own INT 3Fh handler, a
; small overlay manager written for this fixture: it opens OVERLAID.EXE --
; the file's own name, so the file must be called that -- and finds module N
; the way LINK's manager does, reading headers from the start of the file and
; stepping each one's page count times 512; reads the module's image to the
; area, adds the load segment to each word its relocation table names, and
; jumps in. Overlay routines return with `iret`, through the frame `int 3Fh`
; pushed. The root calls module 1, module 2, module 1 again, and prints a
; last line only if all three returned and each module saw the root's data
; through a relocation of its own.
;
; A run that prints all five lines therefore needs the program's INT 3Fh to
; reach the program's handler, not the emulator's; the views written from
; this file need nothing but the file.

BITS 16
CPU 8086
ORG 0

ROOT_HDR    equ 3                       ; paragraphs
AREA_PARAS  equ 0x20                    ; 512 bytes, more than either module

CODE_SEG    equ (code_start - root_image) / 16
AREA_SEG    equ (area_start - root_image) / 16
DATA_SEG    equ (data_start - root_image) / 16
STACK_SEG   equ (stack_start - root_image) / 16
ROOT_TOTAL  equ root_image_end - root
ROOT_PAGES  equ (ROOT_TOTAL + 511) / 512

; ================================================================ the root
root:
    db 'MZ'
    dw ROOT_TOTAL % 512
    dw ROOT_PAGES
    dw 2                                ; relocations
    dw ROOT_HDR
    dw 0x0010                           ; minalloc
    dw 0xFFFF                           ; maxalloc
    dw STACK_SEG                        ; SS
    dw 0x0100                           ; SP
    dw 0
    dw entry - code_start               ; IP
    dw CODE_SEG                         ; CS
    dw root_relocs - root
    dw 0                                ; overlay number: the root
root_relocs:
    dw fix_entry_data - code_start, CODE_SEG
    dw fix_handler_data - code_start, CODE_SEG
    times ROOT_HDR * 16 - ($ - root) db 0

root_image:
code_start:
entry:
    mov ax, DATA_SEG
fix_entry_data equ $ - 2
    mov ds, ax
    mov [psp - data_start], es          ; DOS leaves the PSP in ES
    push ds
    push cs
    pop ds
    mov dx, handler - code_start
    mov ax, 0x253F                      ; INT 3Fh: the overlay manager
    int 0x21
    pop ds
    mov dx, line_root - data_start
    mov ah, 0x09
    int 0x21
    int 0x3F
    db 1
    dw ov1_hello - ov1_image
    int 0x3F
    db 2
    dw ov2_hello - ov2_image
    int 0x3F
    db 1
    dw ov1_again - ov1_image
    cmp byte [calls - data_start], 3
    jne .exit
    mov dx, line_done - data_start
    mov ah, 0x09
    int 0x21
.exit:
    mov ax, 0x4C00
    int 0x21

; INT 3Fh: [bp+2] the caller's IP, pointing at the module and offset bytes;
; [bp+4] its CS. Returns into the module with the caller's frame in place.
handler:
    push bp
    mov bp, sp
    push ds
    push ax
    push si
    push es
    push bx
    push di
    push dx
    push cx
    mov ds, [bp + 4]
    mov si, [bp + 2]
    lodsb
    mov bl, al                          ; the module
    lodsw
    mov [cs:target_off - code_start], ax
    mov [bp + 2], si                    ; the caller resumes past the three bytes
    mov ax, DATA_SEG
fix_handler_data equ $ - 2
    mov ds, ax
    cmp bl, [resident - data_start]
    je .go
    call load_module
.go:
    mov ax, [psp - data_start]
    add ax, 0x10 + AREA_SEG
    mov [cs:target_seg - code_start], ax
    pop cx
    pop dx
    pop di
    pop bx
    pop es
    pop si
    pop ax
    pop ds
    pop bp
    jmp far [cs:target_off - code_start]

target_off: dw 0
target_seg: dw 0

; Module BL into the overlay area. DS: the root's data.
load_module:
    mov [resident - data_start], bl
    mov ax, [psp - data_start]
    add ax, 0x10
    mov [load - data_start], ax
    mov dx, file_name - data_start
    mov ax, 0x3D00
    int 0x21
    jc .failed
    mov [handle - data_start], ax
    xor ax, ax
    mov [pos_lo - data_start], ax
    mov [pos_hi - data_start], ax
    mov byte [steps - data_start], 8    ; no more headers than this
.walk:
    xor dx, dx
    call seek_to
    mov dx, header - data_start
    mov cx, 0x1C
    call read
    jc .failed
    mov al, [header + 0x1A - data_start]
    cmp al, [resident - data_start]
    je .found
    dec byte [steps - data_start]
    jz .failed
    mov ax, [header + 4 - data_start]   ; pages
    mov dx, 512
    mul dx
    add [pos_lo - data_start], ax
    adc [pos_hi - data_start], dx
    jmp .walk
.found:
    mov dx, [header + 8 - data_start]   ; the image, after the header's paragraphs
    mov cl, 4
    shl dx, cl
    call seek_to
    mov ax, [header + 4 - data_start]   ; its length: pages, last, less the header
    dec ax
    mov dx, 512
    mul dx
    add ax, [header + 2 - data_start]
    mov cx, [header + 8 - data_start]
    shl cx, 1
    shl cx, 1
    shl cx, 1
    shl cx, 1
    sub ax, cx
    mov cx, ax
    mov bx, [handle - data_start]
    mov ax, [load - data_start]
    add ax, AREA_SEG
    push ds
    mov ds, ax
    xor dx, dx
    mov ah, 0x3F
    int 0x21
    pop ds
    jc .failed
    mov dx, [header + 0x18 - data_start] ; the relocation table
    call seek_to
    mov cx, [header + 6 - data_start]
    shl cx, 1
    shl cx, 1
    mov dx, fixups - data_start
    call read
    jc .failed
    mov cx, [header + 6 - data_start]
    mov si, fixups - data_start
    jcxz .close
.fixup:
    mov di, [si]                        ; offset
    mov ax, [si + 2]                    ; segment, from the program's start
    add ax, [load - data_start]
    mov es, ax
    mov ax, [load - data_start]
    add [es:di], ax
    add si, 4
    loop .fixup
.close:
    mov bx, [handle - data_start]
    mov ah, 0x3E
    int 0x21
    ret
.failed:
    mov dx, line_failed - data_start
    mov ah, 0x09
    int 0x21
    mov ax, 0x4C01
    int 0x21

; Seek to the current module's position plus DX.
seek_to:
    mov cx, [pos_hi - data_start]
    add dx, [pos_lo - data_start]
    adc cx, 0
    mov bx, [handle - data_start]
    mov ax, 0x4200
    int 0x21
    ret

; CX bytes to DS:DX; carry set unless all arrived.
read:
    push cx
    mov bx, [handle - data_start]
    mov ah, 0x3F
    int 0x21
    pop cx
    jc .short
    cmp ax, cx
    je .done
.short:
    stc
.done:
    ret

    align 16, db 0
area_start:
    times AREA_PARAS * 16 db 0          ; the overlay area: empty in the file

data_start:
line_root:   db 'root: calling overlays', 0x0D, 0x0A, '$'
line_done:   db 'root: 3 overlay calls back', 0x0D, 0x0A, '$'
line_failed: db 'root: overlay load failed', 0x0D, 0x0A, '$'
file_name:   db 'OVERLAID.EXE', 0
calls:       db 0
resident:    db 0
steps:       db 0
    align 2, db 0
psp:         dw 0
load:        dw 0
handle:      dw 0
pos_lo:      dw 0
pos_hi:      dw 0
header:      times 0x1C db 0
fixups:      times 16 dw 0

    align 16, db 0
stack_start:
    times 0x100 db 0
root_image_end:
    times ROOT_PAGES * 512 - ($ - root) db 0

; ================================================================ overlay 1
OV1_TOTAL   equ ov1_end - ov1
ov1:
    db 'MZ'
    dw OV1_TOTAL % 512
    dw (OV1_TOTAL + 511) / 512
    dw 1                                ; relocations
    dw 2                                ; header paragraphs
    dw 0, 0
    dw STACK_SEG, 0x0100
    dw 0
    dw entry - code_start, CODE_SEG
    dw ov1_relocs - ov1
    dw 1                                ; overlay number
ov1_relocs:
    dw ov1_fix_data - ov1_image, AREA_SEG
    times 32 - ($ - ov1) db 0
ov1_image:
ov1_hello:
    push ds
    push cs
    pop ds
    mov dx, ov1_text - ov1_image
    jmp ov1_say
ov1_again:
    push ds
    push cs
    pop ds
    mov dx, ov1_text_again - ov1_image
ov1_say:
    mov ah, 0x09
    int 0x21
    mov ax, DATA_SEG                    ; the root's data, through this module's table
ov1_fix_data equ $ - 2
    mov ds, ax
    inc byte [calls - data_start]
    pop ds
    iret
ov1_text:       db 'overlay 1: called', 0x0D, 0x0A, '$'
ov1_text_again: db 'overlay 1: called again, reloaded', 0x0D, 0x0A, '$'
ov1_end:
    times (OV1_TOTAL + 511) / 512 * 512 - ($ - ov1) db 0

; ================================================================ overlay 2
OV2_TOTAL   equ ov2_end - ov2
OV2_SEG2    equ AREA_SEG + (ov2_second - ov2_image) / 16
ov2:
    db 'MZ'
    dw OV2_TOTAL % 512
    dw (OV2_TOTAL + 511) / 512
    dw 2                                ; relocations
    dw 3                                ; header paragraphs
    dw 0, 0
    dw STACK_SEG, 0x0100
    dw 0
    dw entry - code_start, CODE_SEG
    dw ov2_relocs - ov2
    dw 2                                ; overlay number
ov2_relocs:
    dw ov2_fix_far - ov2_image, AREA_SEG
    dw ov2_fix_data - ov2_second, OV2_SEG2
    times 48 - ($ - ov2) db 0
ov2_image:
ov2_hello:
    push ds
    push cs
    pop ds
    mov dx, ov2_text - ov2_image
    mov ah, 0x09
    int 0x21
    pop ds
    call OV2_SEG2:(ov2_count - ov2_second)
ov2_fix_far equ $ - 2
    iret
ov2_text: db 'overlay 2: called, segment 2 next', 0x0D, 0x0A, '$'
    align 16, db 0
ov2_second:
ov2_count:
    push ds
    mov ax, DATA_SEG
ov2_fix_data equ $ - 2
    mov ds, ax
    inc byte [calls - data_start]
    pop ds
    retf
ov2_end:
    times (OV2_TOTAL + 511) / 512 * 512 - ($ - ov2) db 0
