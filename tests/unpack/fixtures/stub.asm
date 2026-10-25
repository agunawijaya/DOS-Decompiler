; An EXEPACK-style decompressor, written for tests/unpack's packed fixtures.
;
; Its header is EXEPACK's, in either layout: 16 bytes, or 18 with a skip_len
; word before "RB" (assemble with -DHEADER=16 or -DHEADER=18). The packer in
; tests/unpack/regress.py fills the fields in and appends the relocation table
; at `table`. The format is EXEPACK's: the compressed image read from its end
; backwards, B0/B1 a fill and B2/B3 a copy with a 16-bit count, bit 0 on the
; last command, 0xFF padding before it; then sixteen groups of relocations, a
; count and that many offsets each, one group per 64 KB.
;
; The code is not Microsoft's. It reads each header field the way an EXEPACK
; stub does -- the destination's length added to the load segment, the block
; length loaded into CX for the copy, skip_len subtracted from both ends, SS
; and SP loaded from the header, CS relocated and jumped through -- but in
; its own registers and order, so unpack.py has to find the fields by what
; the instructions do with them rather than by matching bytes.
;
; Each pointer is moved, before every command, to the same address with an
; offset of at least 0x8000, so a run of up to 0x7FF0 bytes can go down from
; it without wrapping; the packer keeps runs that short.

BITS 16
CPU 8086
ORG 0

%ifndef HEADER
  %define HEADER 18
%endif

f_ip:       dw 0
f_cs:       dw 0
f_start:    dw 0                        ; written: the segment the image loads at
f_size:     dw 0                        ; this block: header, code and table
f_sp:       dw 0
f_ss:       dw 0
f_dest:     dw 0                        ; the image, in paragraphs
%if HEADER == 18
f_skip:     dw 0
%endif
            db 'RB'

start:
    push cs
    pop ds
    mov bp, es
    add bp, 0x10                        ; BP: the image's segment
    mov [f_start], bp
    mov dx, bp
    add dx, [f_dest]                    ; DX: just past the image
    mov es, dx
    mov cx, [f_size]
    mov si, cx
    dec si
    mov di, si
    std
    rep movsb                           ; this block, out of the way, to DX:0
%if HEADER == 18
    mov bx, [f_skip]
%else
    mov bx, 1                           ; the 16-byte layout: skip_len is 1
%endif
    push es
    mov ax, decompress
    push ax
    retf

decompress:                             ; CS: the copy; DS: where it came from
    mov ax, ds
    sub ax, bx
    mov ds, ax
    mov si, 0x000F                      ; the last byte of the packed data
    mov cx, 16
.padding:
    cmp byte [si], 0xFF
    jne .padded
    dec si
    loop .padding
.padded:
    mov ax, cs
    sub ax, bx
    mov es, ax
    mov di, 0x000F                      ; the last byte of the image
    std
.command:
    call low_si
    call low_di
    mov dl, [si]                        ; the command
    mov ch, [si - 1]                    ; its count, high byte first going down
    mov cl, [si - 2]
    sub si, 3
    mov al, dl
    and al, 0xFE
    cmp al, 0xB0
    je .fill
    cmp al, 0xB2
    jne corrupt
    rep movsb
    jmp .next
.fill:
    mov al, [si]
    dec si
    rep stosb
.next:
    test dl, 1
    jz .command

    push cs                             ; the relocations, as DOS applies them
    pop ds
    mov si, table
    mov bp, [f_start]
    xor dx, dx
    cld
.group:
    lodsw
    mov cx, ax
    jcxz .group_done
.fixup:
    lodsw
    mov bx, ax
    mov ax, dx
    add ax, bp
    mov es, ax
    add [es:bx], bp
    loop .fixup
.group_done:
    add dx, 0x1000
    jnz .group

    mov ax, [f_ss]                      ; the program's stack and entry
    add ax, bp
    mov cx, [f_sp]
    add [f_cs], bp
    mov bx, bp
    sub bx, 0x10                        ; the PSP, as DOS leaves DS and ES
    cli
    mov ss, ax
    mov sp, cx
    sti
    mov ds, bx
    mov es, bx
    jmp far [cs:f_ip]

corrupt:
    push cs
    pop ds
    mov dx, damaged
    mov ah, 0x09
    int 0x21
    mov ax, 0x4CFF
    int 0x21

; DS:SI, then ES:DI, moved to the same address with the offset in
; 0x8000..0x800F.
low_si:
    push ax
    push cx
    mov ax, si
    mov cl, 4
    shr ax, cl
    sub ax, 0x0800
    mov cx, ds
    add cx, ax
    mov ds, cx
    and si, 0x000F
    or si, 0x8000
    pop cx
    pop ax
    ret

low_di:
    push ax
    push cx
    mov ax, di
    mov cl, 4
    shr ax, cl
    sub ax, 0x0800
    mov cx, es
    add cx, ax
    mov es, cx
    and di, 0x000F
    or di, 0x8000
    pop cx
    pop ax
    ret

damaged:
    db 'the packed image is damaged', 0x0D, 0x0A, '$'
table:
