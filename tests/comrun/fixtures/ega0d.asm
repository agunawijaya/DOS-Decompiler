; ega0d.asm -- EGA mode 0Dh drawn through the registers, in ten bands of
; twenty lines, each through a different part of the graphics controller.
; Every pixel's colour follows from the arithmetic below, so the test can
; work the picture out without an EGA model of its own.
;
; The picture is on page 1, from byte 0x2000 of each plane; page 0 is filled
; with colour 4 first, and the CRTC's start address moves the display to
; page 1 at the end. Line y, byte column c (0-39), is at 0x2000 + y*40 + c,
; and in each byte the leftmost pixel is bit 7.
;
;   A   0-19  map mask one plane at a time, write mode 0: plane 0 = 55h,
;             plane 1 = 33h, plane 2 = 0Fh, plane 3 = (c*8 + y) & FFh
;   B  20-39  set/reset c & 15, enable set/reset 0Fh: every pixel c & 15
;   C  40-59  colour 1 everywhere, then a read to load the latches and a
;             write with bit mask 0Fh and set/reset 12: left half 1, right 12
;   D  60-79  colour 5, then latches loaded and 81h written with data rotate
;             19h -- xor, rotated right by one, so C0h: the two left pixels
;             5 xor 15 = 10, the others 5
;   E  80-89  colour 15, then 0Fh written with function and (08h): left half
;             0, right half 15
;      90-99  colour 0, then F0h written with function or (10h): left 15,
;             right 0
;   F 100-119 band A copied in write mode 1, rep movsb from A to F: the
;             latches, all four planes at once
;   G 120-139 colour 3, then write mode 2 with bit mask 55h, the byte c & 15:
;             odd pixels c & 15, even ones 3
;   H 140-159 read mode 1 against band A's same line: colour compare 5,
;             colour don't care 7, so a pixel matches when its planes 0-2
;             are 1, 0, 1; the result written as it is: 15 where it matched
;   I 160-179 read mode 0 with read map select 3 from band A: plane 3 written
;             into plane 0 alone, the others cleared: colour 1 or 0
;   J 180-199 every pixel c & 15, as band B
;
; The palette: INT 10h AX=1002h loads register i with the colour 15 - i;
; then register 14 is set to 04h (red) through AX=1000h, and register 15 to
; 39h through the attribute controller at 3C0: light blue, blue in bit 0 and
; the intensity in bit 4, as a 200-line mode reads it -- bits 3 and 5 are
; the 350-line monitor's and change nothing here.

        org 0x100

%macro gc 2                         ; graphics controller register %1 = %2
        mov ax, ((%2) << 8) | (%1)
        mov dx, 0x3ce
        out dx, ax
%endmacro

%macro maps 1                       ; the sequencer's map mask
        mov dx, 0x3c4
        mov ax, ((%1) << 8) | 2
        out dx, ax
%endmacro

; Run %3 for every byte of lines %1 to %2-1: DI the byte, BX its column,
; BP its line. The routine may use AX, CX, DX and SI.
%macro band 3
        mov bp, %1
%%line: xor bx, bx
%%col:  mov ax, bp
        mov cx, 40
        mul cx
        add ax, bx
        add ax, 0x2000
        mov di, ax
        call %3
        inc bx
        cmp bx, 40
        jb %%col
        inc bp
        cmp bp, %2
        jb %%line
%endmacro

start:  mov ax, 0x000d
        int 0x10
        mov ax, 0x1002              ; ES:DX, the program's own segment
        mov dx, palette
        int 0x10
        mov ax, 0xa000
        mov es, ax

        ; page 0: colour 4 through set/reset
        maps 0x0f
        gc 1, 0x0f
        gc 0, 4
        xor di, di
        mov cx, 0x2000
        rep stosb
        gc 1, 0

        band 0, 20, band_a
        band 20, 40, band_b
        band 40, 60, band_c
        band 60, 80, band_d
        band 80, 90, band_e_and
        band 90, 100, band_e_or

        ; F: band A copied by the latches, all planes at once
        gc 5, 1
        mov si, 0x2000
        mov di, 0x2000 + 100 * 40
        mov cx, 20 * 40
        push ds
        mov ax, 0xa000
        mov ds, ax
        rep movsb
        pop ds
        gc 5, 0

        band 120, 140, band_g
        band 140, 160, band_h
        band 160, 180, band_i
        band 180, 200, band_b

        ; the palette's last two registers, one through the BIOS, one through
        ; the attribute controller -- whose flip-flop a read of 3DA resets
        mov ax, 0x1000
        mov bx, 0x040e
        int 0x10
        mov dx, 0x3da
        in al, dx
        mov dx, 0x3c0
        mov al, 0x0f
        out dx, al
        mov al, 0x39
        out dx, al
        mov al, 0x20                ; palette address source: the screen on
        out dx, al

        ; show page 1
        mov dx, 0x3d4
        mov ax, 0x200c
        out dx, ax
        mov ax, 0x000d
        out dx, ax
        mov ax, 0x4c00
        int 0x21

band_a: maps 1
        mov byte [es:di], 0x55
        maps 2
        mov byte [es:di], 0x33
        maps 4
        mov byte [es:di], 0x0f
        maps 8
        mov ax, bx
        mov cl, 3
        shl ax, cl
        add ax, bp
        mov [es:di], al
        maps 0x0f
        ret

band_b: gc 1, 0x0f
        mov dx, 0x3ce
        mov al, 0
        mov ah, bl
        and ah, 15
        out dx, ax
        mov byte [es:di], 0
        gc 1, 0
        ret

band_c: gc 1, 0x0f
        gc 0, 1
        mov byte [es:di], 0
        mov al, [es:di]             ; the latches
        gc 8, 0x0f
        gc 0, 12
        mov byte [es:di], 0
        gc 8, 0xff
        gc 1, 0
        ret

band_d: gc 1, 0x0f
        gc 0, 5
        mov byte [es:di], 0
        gc 1, 0
        mov al, [es:di]
        gc 3, 0x19                  ; xor, rotated right by one
        mov byte [es:di], 0x81
        gc 3, 0
        ret

band_e_and:
        gc 1, 0x0f
        gc 0, 15
        mov byte [es:di], 0
        gc 1, 0
        mov al, [es:di]
        gc 3, 0x08                  ; and
        mov byte [es:di], 0x0f
        gc 3, 0
        ret

band_e_or:
        gc 1, 0x0f
        gc 0, 0
        mov byte [es:di], 0
        gc 1, 0
        mov al, [es:di]
        gc 3, 0x10                  ; or
        mov byte [es:di], 0xf0
        gc 3, 0
        ret

band_g: gc 1, 0x0f
        gc 0, 3
        mov byte [es:di], 0
        gc 1, 0
        mov al, [es:di]
        gc 5, 2
        gc 8, 0x55
        mov al, bl
        and al, 15
        mov [es:di], al
        gc 8, 0xff
        gc 5, 0
        ret

band_h: mov si, di
        sub si, 140 * 40            ; band A's same line
        gc 5, 0x08                  ; read mode 1
        gc 2, 5
        gc 7, 7
        mov al, [es:si]
        mov cl, al
        gc 5, 0
        mov [es:di], cl
        ret

band_i: mov si, di
        sub si, 160 * 40
        gc 4, 3                     ; read map select: plane 3
        mov al, [es:si]
        mov cl, al
        gc 4, 0
        maps 0x0e
        mov byte [es:di], 0
        maps 1
        mov [es:di], cl
        maps 0x0f
        ret

; The EGA colour for each RGBI colour 15 - i: blue, green and red in bits 0-2,
; the intensity in bit 4. The seventeenth byte is the border.
palette: db 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10
         db 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00
