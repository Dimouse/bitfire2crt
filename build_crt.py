"""Build an EasyFlash CRT for a Bitfire trackmo from harvested files.
Usage: build_crt.py out.crt
Inputs: dec_mem.pkl (decrunched booter image), harvest_{a,b,c}.pkl
"""
import sys, pickle, struct
sys.path.insert(0, '/home/claude/work')
from asm import assemble

SIDES = ['a', 'b', 'c']
TAB = 0xA000          # file tables in bank 0 ROMH ($A000-$ABFF)
DFIMG = 0xB000        # image of $DF00 code in bank 0 ROMH
STUBIMG = 0xBE00      # (ultimax view: $FE00) stub copied to $0110
RESET = 0xBF00        # (ultimax view: $FF00)

RES_SRC = r"""
* = $0231
; ---- replaces bitfire_send_byte ($020c). A = command
SEND:   cmp #$f0
        bcc sfile
        cmp #$ff
        beq sdone            ; drive reset -> ignore
        and #$0f             ; $f0+n : disk side n, file numbering restarts
        sta side
        lda #0
        sta cur
        sta pending
sdone:  rts
sfile:  cmp #$ef
        beq snext            ; $ef : next file
        sta cur              ; else: file number A
snext:  lda #1
        sta pending
        rts
; ---- replaces bitfire block poll/receive ($022e)
; returns N=1 (A=$c0) = "file complete / drive idle"
POLL:   lda pending
        bne doload
        lda #$c0
        rts
doload: txa
        pha
        tya
        pha
        lda #0
        sta pending
        sta nmif
        php
        pla
        and #$04
        beq ien
        lda #$ea             ; caller had I=1 -> keep it (NOP)
        .byte $2c
ien:    lda #$58             ; CLI
        sta cli0
        ldy $01              ; Y = caller's $01 for the whole load
        lda $0318
        sta sv18
        lda $0319
        sta sv19
        jmp FETCH
resend:
"""

DF_SRC = r"""
* = $df00
; NMI arriving inside the ROM window ($01=$37): KERNAL does SEI/JMP ($0318) -> here
NMIT:   sty $01              ; back to caller's memory config
        pha
        lda #$80
        sta nmif
        pla
        jmp ($fffa)          ; demo's own NMI handler (RAM vector)
; read one byte from cartridge ROM at (rdp+1/2); Y = caller $01; keeps X
RD:     lda #$37
        sei
        sta $01
rdp:    lda !$8000
        sty $01
cli0:   cli
        bit nmif
        bmi rdr
        rts
rdr:    lsr nmif
        bne RD
FETCH:  lda #<NMIT
        sta $0318
        lda #>NMIT
        sta $0319
        lda #$07             ; EasyFlash 16K mode (ROM visible only while $01=$37)
        sta $de02
        lda #0
        sta $de00
        lda cur
        sta rdp+1
        lda side
        asl a
        asl a
        adc #>TAB
        sta rdp+2
        ldx #0
fl:     jsr RD
        sta ent,x
        lda rdp+1
        eor #$80
        sta rdp+1
        bmi f2
        inc rdp+2
f2:     inx
        cpx #7
        bne fl
        lda ent+5
        sta $f0
        sta dp+1
        lda ent+6
        sta $f1
        sta dp+2
        lda ent+1
        sta rdp+1
        lda ent+2
        sta rdp+2
        lda ent
        sta $de00
cl:     jsr RD
dp:     sta !$1000
        inc rdp+1
        bne s1
        inc rdp+2
        bit rdp+2
        bvc s1
        lda #$80
        sta rdp+2
        inc ent
        lda ent
        sta $de00
s1:     inc dp+1
        bne s2
        inc dp+2
s2:     inc ent+3            ; length stored negated
        bne cl
        inc ent+4
        bne cl
        lda #$04             ; cartridge off
        sta $de02
        lda sv18
        sta $0318
        lda sv19
        sta $0319
        inc cur
        pla
        tay
        pla
        tax
        lda #$c0
        rts
side:    .byte 0
cur:     .byte 0
pending: .byte 0
nmif:    .byte 0
sv18:    .byte 0
sv19:    .byte 0
ent:     .byte 0,0,0,0,0,0,0
dfend:
"""

STUB_SRC = r"""
* = $0110
stub:   lda #$04             ; cartridge off: normal memory map, KERNAL on
        sta $de02
        jsr $ff84            ; IOINIT
        jsr $ff87            ; RAMTAS
        jsr $ff8a            ; RESTOR
        jsr $ff81            ; CINT
        sei
        lda #$00
        sta $de00
        lda #$07             ; 16K mode, bank 0
        sta $de02
        ldx #0
cp:     lda $8000,x          ; booter image ROML -> RAM below
cps:    sta $8000,x
        inx
        bne cp
        inc cp+2
        inc cps+2
        lda cp+2
        cmp #>(IMGEND+255)
        bne cp
        ldx #0
cd:     lda DFIMG,x           ; loader -> EasyFlash RAM $df00
        sta $df00,x
        inx
        bne cd
        lda #$04
        sta $de02            ; cartridge off
        lda #$37
        sta $01
        lda #$08
        sta $ba
        jmp $8a00
stubend:
"""

RESET_SRC = r"""
* = $ff00
reset:  sei
        ldx #$ff
        txs
        cld
        lda #$08
        sta $d016
        ldx #0
rc:     lda STUBV,x
        sta $0110,x
        inx
        cpx #STUBLEN
        bne rc
        jmp $0110
nmi:    rti
* = $fffa
        .word nmi, reset, nmi
"""

def build(out_fn):
    img = pickle.load(open('/home/claude/work/dec_mem.pkl', 'rb'))
    img = bytearray(img)
    IMGEND = 0x8c2b
    # --- patch installer: skip drive detection / drive code upload
    def put(a, bs):
        for i, b in enumerate(bs): img[a + i] = b
    put(0x800c, [0x4c, 0x2f, 0x80])      # jmp $802f  (skip LISTEN loop & upload cmds)
    put(0x803a, [0x4c, 0x76, 0x80])      # jmp $8076  (skip drive code transfer)
    assert img[0x818c] == 0x10
    put(0x818c, [0x10, 0x00])            # don't wait for drive
    # --- patch resident (image byte = resident addr + $80b1)
    df, dsyms = assemble(DF_SRC, {'TAB': TAB})
    for _ in range(2):
        rs, rsy = assemble(RES_SRC, dsyms)
        df, dsyms = assemble(DF_SRC, dict(rsy, TAB=TAB))
    rs, rsy = assemble(RES_SRC, dsyms)
    assert dsyms['dfend'] <= 0xe000, hex(dsyms['dfend'])
    assert rsy['resend'] <= 0x028f, hex(rsy['resend'])
    dsyms.update({k: v for k, v in rsy.items() if k in ('SEND', 'POLL', 'resend')})
    R = lambda a: a + 0x80b1
    assert img[R(0x020c)] == 0x38 and img[R(0x022e)] == 0xad and img[R(0x036b)] == 0x50
    put(R(0x020c), [0x4c, dsyms['SEND'] & 255, dsyms['SEND'] >> 8])
    put(R(0x022e), [0x4c, dsyms['POLL'] & 255, dsyms['POLL'] >> 8])
    put(R(0x036c), [0x00])               # bvc *+2 : never poll drive while depacking
    for a in range(0x0231, rsy['resend']):
        img[R(a)] = rs[a]
    assert img[0x8150:0x8154] == bytes([0xc9, 0x20, 0xb0, 0x30])
    put(0x8150, [0x4c, 0x84, 0x81])      # skip NTSC patching of (now unused) receive code

    stub, ssyms = assemble(STUB_SRC, {'DFIMG': DFIMG, 'IMGEND': IMGEND})
    stub_bytes = bytes(stub[a] for a in range(0x110, ssyms['stubend']))
    STUBV = STUBIMG - 0xA000 + 0xE000
    rst, rsyms = assemble(RESET_SRC, {'STUBV': STUBV, 'STUBLEN': len(stub_bytes)})

    # --- ROM space: 64 banks x 16K
    rom = bytearray(b'\xff' * (64 * 16384))
    def romput(bank, addr, bs):           # addr in $8000-$bfff
        o = bank * 16384 + (addr - 0x8000)
        rom[o:o + len(bs)] = bs
    romput(0, 0x8000, img[0x8000:IMGEND + 1])
    romput(0, DFIMG, bytes(df.get(0xdf00 + i, 0) for i in range(256)))
    romput(0, STUBIMG, stub_bytes)
    romput(0, RESET, bytes(rst.get(0xff00 + i, 0xff) for i in range(256)))

    # --- file data
    pos = 16384   # start of bank 1
    tables = bytearray(b'\x00' * 0x0c00)
    summary = []
    for si, s in enumerate(SIDES):
        files = pickle.load(open('/home/claude/work/harvest_%s.pkl' % s, 'rb'))
        assert len(files) <= 128
        for i in range(len(files)):
            lo, data, n, h = files[i]
            data = data[:n]
            bank = pos // 16384; off = 0x8000 + pos % 16384
            rom[pos:pos + n] = data
            base = si * 0x400
            neg = (0x10000 - n) & 0xffff
            vals = [bank, off & 255, off >> 8, neg & 255, neg >> 8, lo & 255, lo >> 8]
            for f, v in enumerate(vals):
                tables[base + f * 0x80 + i] = v
            pos += n
        summary.append((s, len(files)))
    romput(0, TAB, tables)
    nbanks = (pos + 16383) // 16384
    assert nbanks <= 64, nbanks

    # --- write CRT
    hdr = bytearray(64)
    hdr[0:16] = b'C64 CARTRIDGE   '
    hdr[16:20] = struct.pack('>I', 64)
    hdr[20:22] = struct.pack('>H', 0x0100)
    hdr[22:24] = struct.pack('>H', 32)       # EasyFlash
    hdr[24] = 1; hdr[25] = 0                 # EXROM=1 (inactive), GAME=0
    name = b'FAIRLIGHT 1337 (EF)'
    hdr[32:32 + len(name)] = name
    out = bytearray(hdr)
    for b in range(nbanks):
        for chip, la in ((0, 0x8000), (1, 0xA000)):
            o = b * 16384 + chip * 8192
            chunk = rom[o:o + 8192]
            if b > 0 and chunk == b'\xff' * 8192: continue
            out += b'CHIP' + struct.pack('>IHHHH', 0x2010, 2, b, la, 0x2000) + chunk
    open(out_fn, 'wb').write(out)
    return dict(rom=rom, nbanks=nbanks, pos=pos, dsyms=dsyms, df=df, summary=summary,
                dfsize=dsyms['dfend'] - 0xdf00, ressize=rsy['resend']-0x231, stublen=len(stub_bytes))

if __name__ == '__main__':
    r = build(sys.argv[1])
    print('banks used', r['nbanks'], 'bytes', r['pos'], 'df code', r['dfsize'], 'res code', r['ressize'], 'stub', r['stublen'], r['summary'])
