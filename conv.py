"""Generic Bitfire -> EasyFlash CRT builder + self-test."""
import sys, struct, random
sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from asm import assemble
import build_crt as B
from ef64 import EF64
from c64 import C64
from bitfire import depack_range

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
        ldx #0
cp:     lda SRCBASE,x
cps:    sta DSTBASE,x
        inx
        bne cp
        inc cp+2
        inc cps+2
        dec npg
        bne cp
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
npg:    .byte NPAGES
stubend:
"""

def build(out_fn, a, files_by_side, name):
    """a: analyse_bitfire() result; files_by_side: [(sid, [(addr, data)])]"""
    img = bytearray(a['snap'])
    def put(x, bs):
        for i, b in enumerate(bs): img[x + i] = b
    J = lambda t: [0x4c, t & 255, t >> 8]
    put(a['p_detect'], J(a['p_after_detect']))
    put(a['p_wait'], J(a['copyloop']))
    put(a['p_end'] + 9, [0x00])
    put(a['p_ntsc'], J(a['p_end']))
    df, dsyms = assemble(B.DF_SRC, {'TAB': B.TAB})
    for _ in range(2):
        rs, rsy = assemble(B.RES_SRC, dsyms)
        df, dsyms = assemble(B.DF_SRC, dict(rsy, TAB=B.TAB))
    rs, rsy = assemble(B.RES_SRC, dsyms)
    assert dsyms['dfend'] <= 0xe000 and rsy['resend'] <= 0x028f
    R = lambda x: x + a['res_off']
    put(R(0x020c), J(rsy['SEND'])); put(R(0x022e), J(rsy['POLL'])); put(R(0x036c), [0x00])
    for x in range(0x0231, rsy['resend']): img[R(x)] = rs[x]
    lo = a['img_lo'] & 0xff00; hi = (a['img_hi'] + 0xff) & 0xff00
    npages = (hi - lo) >> 8
    assert 0 < npages <= 0x20
    stub, ssyms = assemble(STUB_SRC, {'DFIMG': B.DFIMG, 'SRCBASE': 0x8000, 'DSTBASE': lo,
                                      'NPAGES': npages, 'ENTRY': a['entry']})
    stub_bytes = bytes(stub[x] for x in range(0x110, ssyms['stubend']))
    rst, _ = assemble(B.RESET_SRC, {'STUBV': B.STUBIMG - 0xA000 + 0xE000, 'STUBLEN': len(stub_bytes)})
    rom = bytearray(b'\xff' * (64 * 16384))
    def romput(bank, addr, bs):
        o = bank * 16384 + (addr - 0x8000); rom[o:o + len(bs)] = bs
    romput(0, 0x8000, img[lo:hi])
    romput(0, B.DFIMG, bytes(df.get(0xdf00 + i, 0) for i in range(256)))
    romput(0, B.STUBIMG, stub_bytes)
    romput(0, B.RESET, bytes(rst.get(0xff00 + i, 0xff) for i in range(256)))
    pos = 16384; tables = bytearray(0x0c00)
    if len(files_by_side) > 3: raise ValueError('больше 3 сторон — нужна другая раскладка таблиц')
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
    romput(0, B.TAB, tables)
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

def verify(rom, a, boot, files_by_side, log=print, seed=1, prob=0.002):
    """Boot the cart, then load+depack every file in demo order with random NMI/IRQ,
    comparing each result against the original resident's depack."""
    random.seed(seed)
    res_orig = bytes(boot.boot_ram[0x200:0x400])
    m = EF64(rom)
    def rts(mm):
        cp = mm.cpu; cp.pc = ((cp.pull() | cp.pull() << 8) + 1) & 0xffff
    for x in (0xff84, 0xff87, 0xff8a, 0xff81): m.traps[x] = rts
    m.cpu.pc = 0xff00
    first_pc = boot.final_pc
    r = m.run(stop=lambda mm: mm.cpu.pc == first_pc, maxsteps=40_000_000)
    if r[0] != 'stop': return False, 'картридж не дошёл до старта демки (%04x)' % first_pc
    la0, d0 = files_by_side[0][1][0]
    rng = depack_range(res_orig, la0, d0)
    ref = boot.boot_ram
    if rng and bytes(m.ram[rng[0]:rng[1]+1]) != bytes(ref[rng[0]:rng[1]+1]):
        return False, 'первый файл после старта с картриджа отличается'
    m.ram[0x0120:0x0124] = bytes([0xee, 0x40, 0x01, 0x40])
    m.ram[0x0128:0x012c] = bytes([0xee, 0x41, 0x01, 0x40])
    active = [False]; stats = {'nmi_win': 0, 'bad_irq': 0}
    def hook(mm):
        cp = mm.cpu
        if not active[0]: return
        if mm.ram[0xfffa:0xfffc] != b'\x20\x01' or mm.ram[0xfffe:0x10000] != b'\x28\x01': return
        if not (0xdf00 <= cp.pc < 0xe000 or 0x231 <= cp.pc < 0x290): return
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
    nfiles = 0
    for si, (sid, files) in enumerate(files_by_side):
        if si > 0: call(0x020c, sid)
        for i, (la, data) in enumerate(files):
            if si == 0 and i == 0: continue
            rg = depack_range(res_orig, la, data)
            if rg is None: return False, 'файл %d стороны $%02X не распаковывается' % (i, sid)
            io = rg[0] <= 0xdfff and rg[1] >= 0xd000
            m.ram[0xfffa:0xfffc] = b'\x20\x01'; m.ram[0xfffe:0x10000] = b'\x28\x01'
            before = bytes(m.ram)
            active[0] = True
            if io:
                call(0x0224); active[0] = False; call(0x02cc, p01=0x34)
            else:
                call(0x02d2)
            active[0] = False
            x = C64(); x.p01 = 0x34 if io else 0x35; x.ram[:] = before; x.ram[0x200:0x400] = res_orig
            x.ram[la:la+len(data)] = data; x.ram[0xf0] = la & 255; x.ram[0xf1] = la >> 8
            cp = x.cpu; cp.s = 0xf0; cp.push(0xff); cp.push(0xf7); cp.pc = 0x02cc; cp.i = 1
            x.run(stop=lambda mm: mm.cpu.pc == 0xfff8, maxsteps=60_000_000)
            bad = [q for q in range(0x400, 0x10000) if x.ram[q] != m.ram[q]
                   and not 0xd000 <= q < 0xe000 and not 0x120 <= q < 0x150]
            if bad:
                return False, 'файл %d стороны $%02X: %d байт отличается' % (i, sid, len(bad))
            nfiles += 1
    if stats['bad_irq']: return False, 'IRQ при включённом KERNAL'
    return True, 'проверено %d загрузок, NMI внутри окна ROM: %d' % (nfiles, stats['nmi_win'])
