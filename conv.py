"""Generic Bitfire -> EasyFlash CRT builder + self-test (profile driven)."""
import sys, os, struct, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from asm import assemble
import build_crt as B
import re
from ef64 import EF64
from c64 import C64
from bitfire import depack_range

TAB = 0xA000        # 4 sides x $400 : $A000-$AFFF
DFIMG = 0xB000
STUBIMG = 0xBE00
RESET = 0xBF00

STUB_SRC = r"""
* = $0110
stub:   lda #$04
        sta $de02
        jsr $ff84
        jsr $ff87
        jsr $ff8a
        jsr $ff81
        sei
        lda #$00
        sta $de00
        lda #$07
        sta $de02
        ldy #0
pg:     lda ptab,y
        sta cps+2
        tya
        clc
        adc #$80
        sta cp+2
        ldx #0
cp:     lda $8000,x
cps:    sta !$0000,x
        inx
        bne cp
        iny
        cpy #NPAGES
        bne pg
cd:     lda DFIMG,x
        sta $df00,x
        inx
        bne cd
        lda #$04
        sta $de02
        lda #$37
        sta $01
        lda #$08
        sta $ba
        jmp ENTRY
ptab:
"""

RES_SRC = r"""
* = RESORG
SEND:
PLUGCHK
        cmp #$f0
        bcc sfile
        cmp #$ff
        beq sdone            ; drive reset -> ignore
        and #$0f             ; $f0+n : disk side n, file numbering restarts
sside:  sta side
        lda #0
        sta cur
        sta pending
        jmp APPLY            ; neutralise busy-waits for a drive that isn't there
sdone:  rts
PLUGSIDE
sfile:  cmp #$ef
        beq snext            ; $ef : next file
        cmp #$80
        bcs sdone            ; no such file -> ignore
        sta cur
snext:  lda #1
        sta pending
        rts
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
        jmp FETCH
resend:
"""

RES2_SRC = r"""
* = RES2ORG
; NMI inside the ROM window ($01=$37): KERNAL does SEI/JMP ($0318) -> here
NMIT:   sty $01
        pha
        lda #$80
        sta nmif
        pla
        jmp ($fffa)
res2end:
"""

DF_SRC = r"""
* = $df00
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
FETCH:  lda $0318
        sta sv18
        lda $0319
        sta sv19
        lda #<NMIT
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
        sta SRC0
        sta dp+1
        lda ent+6
        sta SRC1
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
APPLY:
SITES
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

def sources(prof, logic):
    plug = logic.get('plug') if logic else None
    rs = RES_SRC.replace('PLUGCHK', ('        cmp #$%02x\n        beq snxs' % plug) if plug is not None else '')
    rs = rs.replace('PLUGSIDE', ('snxs:   lda side             ; drive plugin = "wait for next disk"\n'
                                 '        adc #0               ; C=1 here -> side+1\n        bne sside') if plug is not None else '')
    sites = ''
    for i, a in enumerate(logic.get('sites', []) if logic else []):
        sites += ('        lda $%04x\n        cmp #$30\n        bne ns%d\n        lda $%04x\n        cmp #$fb\n'
                  '        bne ns%d\n        lda #0\n        sta $%04x\nns%d:\n') % (a - 1, i, a, i, a, i)
    df = DF_SRC.replace('SITES', sites)
    return df, rs, RES2_SRC

def build(out_fn, a, files_by_side, name, logic=None):
    """a: analyse_bitfire() result; files_by_side: [(sid, [(addr, data)])] in side order"""
    prof = a['prof']
    img = bytearray(a['snap'])
    def put(x, bs):
        for i, b in enumerate(bs): img[x + i] = b
    J = lambda t: [0x4c, t & 255, t >> 8]
    put(a['p_detect'], J(a['p_after_detect']))
    put(a['p_wait'], J(a['copyloop']))
    put(a['p_end'] + 9, [0x00])
    put(a['p_ntsc'], J(a['p_end']))
    DFS, RSS, R2S = sources(prof, logic)
    syms = {'TAB': TAB, 'SRC0': prof['src'], 'SRC1': prof['src'] + 1,
            'RESORG': prof['free'][0], 'RES2ORG': prof['free2'][0]}
    allsyms = dict(syms)
    for k in ('NMIT', 'nmif', 'side', 'cur', 'pending', 'cli0', 'FETCH', 'APPLY', 'SEND', 'POLL'):
        allsyms[k] = 0xdfff
    for _ in range(3):
        df, dsyms = assemble(DFS, allsyms); allsyms.update(dsyms)
        rs, rsy = assemble(RSS, allsyms); allsyms.update(rsy)
        r2, r2y = assemble(R2S, allsyms); allsyms.update(r2y)
    if dsyms['dfend'] > 0xe000:
        raise ValueError('код для $DF00 не помещается (%d байт; ожиданий для патча: %d)' % (
            dsyms['dfend'] - 0xdf00, len(logic.get('sites', [])) if logic else 0))
    if rsy['resend'] > prof['free'][1]: raise ValueError('код не помещается в свободное место резидента')
    if r2y['res2end'] > prof['free2'][1]: raise ValueError('трамплин NMI не помещается')
    R = lambda x: x + a['res_off']
    put(R(prof['send']), J(rsy['SEND'])); put(R(prof['poll']), J(rsy['POLL']))
    put(R(prof['bvc']), [0x00])
    for x in range(prof['free'][0], rsy['resend']): img[R(x)] = rs[x]
    for x in range(prof['free2'][0], r2y['res2end']): img[R(x)] = r2[x]
    pages = a['pages']
    stub, ssyms = assemble(STUB_SRC, {'DFIMG': DFIMG, 'NPAGES': len(pages), 'ENTRY': a['entry']})
    stub_bytes = bytes(stub[x] for x in range(0x110, ssyms['ptab'])) + bytes(pages)
    rst, _ = assemble(B.RESET_SRC, {'STUBV': STUBIMG - 0xA000 + 0xE000, 'STUBLEN': len(stub_bytes)})
    rom = bytearray(b'\xff' * (64 * 16384))
    def romput(bank, addr, bs):
        o = bank * 16384 + (addr - 0x8000); rom[o:o + len(bs)] = bs
    romput(0, 0x8000, b''.join(bytes(img[p*256:p*256+256]) for p in pages))
    romput(0, DFIMG, bytes(df.get(0xdf00 + i, 0) for i in range(256)))
    romput(0, STUBIMG, stub_bytes)
    romput(0, RESET, bytes(rst.get(0xff00 + i, 0xff) for i in range(256)))
    pos = 16384; tables = bytearray(0x1000)
    if len(files_by_side) > 4: raise ValueError('больше 4 сторон')
    for si, (sid, files) in enumerate(files_by_side):
        if (sid & 0x0f) != si: raise ValueError('стороны не по порядку ($F0, $F1, ...)')
        if len(files) > 128: raise ValueError('больше 128 файлов на стороне')
        for i, (la, data) in enumerate(files):
            n = len(data); bank = pos // 16384; off = 0x8000 + pos % 16384
            if pos + n > len(rom): raise ValueError('не помещается в 1 МБ EasyFlash')
            rom[pos:pos + n] = data
            neg = (0x10000 - n) & 0xffff
            for f, v in enumerate([bank, off & 255, off >> 8, neg & 255, neg >> 8, la & 255, la >> 8]):
                tables[si * 0x400 + f * 0x80 + i] = v
            pos += n
    romput(0, TAB, tables)
    nbanks = (pos + 16383) // 16384
    hdr = bytearray(64)
    hdr[0:16] = b'C64 CARTRIDGE   '; hdr[16:20] = struct.pack('>I', 64)
    hdr[20:22] = struct.pack('>H', 0x0100); hdr[22:24] = struct.pack('>H', 32)
    hdr[24] = 1; hdr[25] = 0
    nm = name.encode('ascii', 'replace')[:31]; hdr[32:32 + len(nm)] = nm
    out = bytearray(hdr)
    for b in range(nbanks):
        for chip, la in ((0, 0x8000), (1, 0xA000)):
            o = b * 16384 + chip * 8192; chunk = rom[o:o + 8192]
            if b > 0 and chunk == b'\xff' * 8192: continue
            out += b'CHIP' + struct.pack('>IHHHH', 0x2010, 2, b, la, 0x2000) + chunk
    open(out_fn, 'wb').write(out)
    return rom, pos

def verify(rom, a, boot, files_by_side, log=print, seed=1, prob=0.002, logic=None):
    """Boot the cart; then for every file in demo order: raw load must give exactly the
    disk data; packed files are also loaded+depacked on the fly and compared to the
    original resident. Random NMI/IRQ are injected inside the loader."""
    prof = a['prof']
    random.seed(seed)
    res_orig = bytes(boot.boot_ram[0x200:0x400])
    m = EF64(rom)
    def rts(mm):
        cp = mm.cpu; cp.pc = ((cp.pull() | cp.pull() << 8) + 1) & 0xffff
    for x in (0xff84, 0xff87, 0xff8a, 0xff81): m.traps[x] = rts
    m.cpu.pc = 0xff00
    first_pc = boot.final_pc
    r = m.run(stop=lambda mm: mm.cpu.pc == first_pc, maxsteps=60_000_000)
    if r[0] != 'stop': return False, 'картридж не дошёл до старта демки ($%04X)' % first_pc
    ref = boot.boot_ram; snap = a['snap']
    bad = [x for x in range(0x0400, 0x10000) if ref[x] != snap[x] and m.ram[x] != ref[x]
           and not 0xd000 <= x < 0xe000 and (x >> 8) not in a['pages']]
    if bad: return False, 'после старта с картриджа память отличается (%d байт, с $%04X)' % (len(bad), bad[0])
    H1 = bytes([0xee, 0x40, 0x01, 0x40]); H2 = bytes([0xee, 0x41, 0x01, 0x40])
    active = [False]; stats = {'nmi_win': 0, 'bad_irq': 0}
    lo_r, hi_r = prof['free']
    def hook(mm):
        cp = mm.cpu
        if not active[0]: return
        if mm.ram[0xfffa:0xfffc] != b'\x20\x01' or mm.ram[0xfffe:0x10000] != b'\x28\x01': return
        if mm.ram[0x120:0x124] != H1 or mm.ram[0x128:0x12c] != H2: return
        if not (0xdf00 <= cp.pc < 0xe000 or lo_r <= cp.pc < hi_r): return
        if random.random() < prob:
            if mm.p01 == 0x37: stats['nmi_win'] += 1
            cp.irq(0xfffa)
        elif cp.i == 0 and random.random() < prob:
            if mm.p01 & 2: stats['bad_irq'] += 1
            cp.irq(0xfffe)
    m.nmi_hook = hook
    def call(pc, av=0, p01=0x35):
        cp = m.cpu; cp.s = 0xf0; cp.push(0xff); cp.push(0xf7); cp.pc = pc; cp.a = av; cp.i = 0
        m.p01 = p01
        return m.run(stop=lambda mm: mm.cpu.pc == 0xfff8, maxsteps=60_000_000)
    def prep():
        m.ram[0xfffa:0xfffc] = b'\x20\x01'; m.ram[0xfffe:0x10000] = b'\x28\x01'
        m.ram[0x120:0x124] = H1; m.ram[0x128:0x12c] = H2
    def cmp(exp):
        return [q for q in range(0x200, 0x10000) if exp[q] != m.ram[q]
                and not 0xd000 <= q < 0xe000 and not 0x100 <= q < 0x200 and not 0x200 <= q < 0x400]
    nraw = ncomp = 0
    for si, (sid, files) in enumerate(files_by_side):
        if si > 0:
            cmd = (logic or {}).get('trans', {}).get(si) or sid
            call(prof['raw'] + 2, cmd)          # like the demo: JSR send + wait
            for st in (logic or {}).get('sites', []):
                if m.ram[st-1] == 0x30 and m.ram[st] == 0xfb:
                    return False, 'ожидание дисковода на $%04X не обезврежено' % st
        for i, (la, data) in enumerate(files):
            if si == 0 and i == 0: continue
            # 1) raw load by number: memory must equal before + file
            prep(); before = bytearray(m.ram); active[0] = True
            call(prof['send'], i); call(prof['raw_loop'])
            active[0] = False
            exp = bytearray(before); exp[la:la+len(data)] = data
            d = cmp(exp)
            if d: return False, 'файл %d стороны $%02X (raw): %d байт отличается' % (i, sid, len(d))
            if m.ram[prof['src']] | m.ram[prof['src']+1] << 8 != la:
                return False, 'файл %d стороны $%02X: неверный указатель распаковщика' % (i, sid)
            nraw += 1
            # 2) packed: reload with load_comp and compare to original depacker
            rg = depack_range(res_orig, la, data, prof)
            if rg is None or (rg[0] <= 0xdfff and rg[1] >= 0xd000): continue
            m.ram[:] = before; prep()
            call(prof['send'], i)             # re-select file i, then load_comp of "next" = i
            m.ram[:] = before; prep()
            x = C64(); x.p01 = 0x35; x.ram[:] = before; x.ram[0x200:0x400] = res_orig
            x.ram[la:la+len(data)] = data; x.ram[prof['src']] = la & 255; x.ram[prof['src']+1] = la >> 8
            cp = x.cpu; cp.s = 0xf0; cp.push(0xff); cp.push(0xf7); cp.pc = prof['decomp']; cp.i = 1
            x.run(stop=lambda mm: mm.cpu.pc == 0xfff8, maxsteps=60_000_000)
            active[0] = True
            call(prof['comp'])
            active[0] = False
            d = cmp(x.ram)
            if d: return False, 'файл %d стороны $%02X (распаковка): %d байт отличается' % (i, sid, len(d))
            ncomp += 1
    if stats['bad_irq']: return False, 'IRQ при включённом KERNAL'
    return True, '%d загрузок, из них %d с распаковкой; NMI внутри окна ROM: %d' % (nraw, ncomp, stats['nmi_win'])
