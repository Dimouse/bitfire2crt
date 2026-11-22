"""Generic Bitfire-trackmo analysis / harvesting / EasyFlash conversion."""
import sys, os, re, hashlib, random
sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from d64 import D64, SPT
from machine import Machine
from c64 import C64
from cpu import disasm

# ---------------------------------------------------------------- disk helpers
def bitfire_dir(d):
    """Return (side_id, [(load, len)]) if 18/18 looks like a Bitfire dir, else None."""
    b = d.sec(18, 18)
    if not (0xf0 <= b[3] <= 0xfe): return None
    ents = []
    for s in (18, 17):
        bb = d.sec(18, s)
        for i in range(63):
            e = (bb[4+i] | bb[0x43+i] << 8, bb[0x82+i] | bb[0xc1+i] << 8)
            if e == (0, 0): continue
            ents.append(((e[0] + 0x100) & 0xffff, e[1] + 1))
    if not ents: return None
    tot = sum(n for a, n in ents)
    cap = (sum(SPT[:min(40, len(d.d)//256 and 40)]) - 19) * 256
    if tot > cap + 256: return None
    return b[3], ents

def first_prg(d):
    for e in d.dir():
        if (e[0] & 7) == 2:
            data, _ = d.file(e[1], e[2])
            return e[3], data
    return None, None

def basic_sys(data):
    """SYS address from a BASIC stub at $0801, if any."""
    la = data[0] | data[1] << 8
    if la != 0x0801: return None
    body = data[2:200]
    i = body.find(b'\x9e')
    if i < 0: return None
    m = re.match(rb'\s*\(?\s*(\d+)', body[i+1:i+12])
    return int(m.group(1)) if m else None

# ---------------------------------------------------------------- boot emulation
class BootResult: pass

def emulate_boot(d64_path, maxc=40_000_000):
    """Run the first program of a disk on C64+1541 emulation.
    Records drive code uploads, first-exec snapshots, and stops when freshly
    fast-loaded code starts executing (the demo's first part)."""
    r = BootResult()
    d = D64(d64_path)
    name, prg = first_prg(d)
    r.boot_name = name; r.notes = []
    if prg is None:
        r.error = 'нет PRG-файлов в каталоге'; return r
    M = Machine(d64_path)
    orig = M.do_job
    def job(dd, slot, v):
        orig(dd, slot, v); M.job_hook = None
    M.job_hook = job
    la, end = M.c.load_prg(prg)
    start = basic_sys(prg)
    if start is None:
        if la <= 0x0302 < end and la <= 0x0303 < end:
            start = M.c.ram[0x302] | M.c.ram[0x303] << 8; r.notes.append('автостарт через вектор $0302')
        elif la <= 0x0326 < end:
            start = M.c.ram[0x326] | M.c.ram[0x327] << 8; r.notes.append('автостарт через вектор $0326')
        else:
            start = la; r.notes.append('нет SYS, старт с адреса загрузки (догадка)')
    r.load = la; r.start = start
    c = M.c; c.ram[0xba] = 8; c.cpu.s = 0xf6; c.cpu.pc = start
    # extra KERNAL traps: file loading and harmless calls
    def rts(m):
        cp = m.cpu; cp.pc = ((cp.pull() | cp.pull() << 8) + 1) & 0xffff
    st = {'name': b'', 'sa': 0, 'loads': []}
    def SETNAM(m):
        n = m.cpu.a; a = m.cpu.x | m.cpu.y << 8
        st['name'] = bytes(m.ram[a:a+n]); rts(m)
    def SETLFS(m):
        st['sa'] = m.cpu.y; rts(m)
    def LOAD(m):
        nm = st['name']; f = None
        for e in d.dir():
            en = e[3]
            if (e[0] & 7) == 2 and (en == nm or (nm.endswith(b'*') and en.startswith(nm[:-1])) or nm in (b'*', b'')):
                f = d.file(e[1], e[2])[0]; break
        cp = m.cpu
        if f is None:
            st['loads'].append((nm, None)); cp.c = 1; cp.a = 4; rts(m); return
        a = (f[0] | f[1] << 8) if st['sa'] else (cp.x | cp.y << 8)
        m.ram[a:a+len(f)-2] = f[2:]
        e2 = a + len(f) - 2
        cp.x = e2 & 255; cp.y = e2 >> 8; cp.c = 0
        st['loads'].append((nm, a)); rts(m)
    for a in (0xff81, 0xff84, 0xff8a, 0xffd2, 0xffcc, 0xffe7, 0xffc3, 0xffc0, 0xff90, 0xffe1):
        c.traps[a] = lambda m: (setattr(m.cpu, 'c', 0), rts(m))
    c.traps[0xffbd] = SETNAM; c.traps[0xffba] = SETLFS; c.traps[0xffd5] = LOAD
    c.traps[0xffe4] = lambda m: (setattr(m.cpu, 'a', 0), rts(m))
    # tracking
    lastw = {}; wcount = [0]
    ow = c.write
    def w(a, v):
        lastw[a & 0xffff] = c.cpu.cycles; ow(a, v)
    c.write = w; c.cpu.write = w
    seen_pages = set(); snaps = {}
    me_cycle = [None]
    def stop(m):
        pc = m.c.cpu.pc; pg = pc >> 8
        if pg not in seen_pages:
            seen_pages.add(pg)
            if lastw.get(pc, -1) >= 0:
                snaps[pg] = (pc, bytes(m.c.ram), m.c.cpu.s, m.c.cpu.cycles)
        if m.drive_on and me_cycle[0] is None: me_cycle[0] = m.c.cpu.cycles
        if me_cycle[0] is not None and pc >= 0x400 and lastw.get(pc, -1) > me_cycle[0] and not (0xdf00 <= pc < 0xe000):
            return True
        return False
    try:
        res = M.run(maxc=maxc, stop=stop)
    except Exception as ex:
        res = ('error', str(ex))
    r.result = res
    r.M = M; r.snaps = snaps; r.loads = st['loads']; r.lastw = lastw
    r.drive_cmds = list(M.mw_log)
    # drive code fingerprint: all M-W payloads of the main drive
    mw = bytearray()
    up = M.d.ram
    r.drive_used = M.drive_on
    r.final_pc = c.cpu.pc
    r.boot_ram = bytes(c.ram)
    r.demo_started = res[0] == 'stop'
    return r

def drive_fingerprint(r):
    """Hash of the drive memory that the host uploaded (M-W + bit-banged)."""
    dram = bytes(r.M.d.ram)
    return hashlib.sha1(dram[0x0000:0x0800]).hexdigest()[:12]

# ---------------------------------------------------------------- bitfire recognition
REF = None
def ref_resident():
    global REF
    if REF is None:
        REF = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'res_orig.bin'), 'rb').read()  # $0200-$03FF of 1337
    return REF

# resident ranges the converter relies on (send, poll/receive, depack glue, poll loop)
KEY_RANGES = [(0x020c, 0x0224), (0x0224, 0x0235), (0x02cc, 0x02e4), (0x0368, 0x036d), (0x03e1, 0x03f9)]

def find(pat, mem, lo=0, hi=0x10000):
    rx = re.compile(b''.join(b'.' if x is None else re.escape(bytes([x])) for x in pat), re.S)
    return [m.start() for m in rx.finditer(mem, lo, hi)]

def analyse_bitfire(r):
    """Locate installer, entry, patch sites. Returns dict or raises ValueError(reason)."""
    M = r.M; mem = bytes(M.c.ram)
    res = mem[0x200:0x400]
    diff_key = sum(1 for a, b in KEY_RANGES for x in range(a, b) if res[x-0x200] != ref_resident()[x-0x200])
    diff_all = sum(1 for x in range(0x200, 0x3fc) if res[x-0x200] != ref_resident()[x-0x200])
    out = {'res_diff_key': diff_key, 'res_diff_all': diff_all}
    if diff_key:
        raise ValueError('резидент Bitfire другой сборки (%d байт отличается в ключевых местах)' % diff_key, out)
    # installer copy loop
    cl = find([0xa2, 0x00, 0xbd, None, None, 0x9d, 0x00, 0x02, 0xbd, None, None, 0x9d, 0xfc, 0x02], mem, 0x400)
    cl = [x for x in cl if r.lastw.get(x, -1) >= 0]   # produced by the decruncher, not the packed PRG
    if len(cl) != 1: raise ValueError('не найден цикл копирования резидента', out)
    cl = cl[0]
    s1 = mem[cl+3] | mem[cl+4] << 8; s2 = mem[cl+9] | mem[cl+10] << 8
    if s2 - s1 != 0xfc: raise ValueError('неожиданная раскладка резидента', out)
    out['res_off'] = s1 - 0x200; out['copyloop'] = cl
    # entry: earliest first-executed page snapshot inside the installer's image block
    # image block = nonzero region around installer (gaps <= 64 zero bytes)
    snapmem = None
    lo = cl;
    while lo > 0 and any(mem[lo-64:lo]): lo -= 1
    hi = cl
    while hi < 0xffff and any(mem[hi:hi+64]): hi += 1
    p1 = find([0xa5, 0xba, 0x85, 0xfb, 0xa2, 0x08, 0x86, 0xba, 0x20, None, None, 0x30], mem, lo, hi)
    p1b = find([0x78, 0xa9, 0xc3, 0x8d, 0x00, 0xdd, 0xa9, 0x3f, 0x8d, 0x02, 0xdd, 0x2c, 0x00, 0xdd, 0x30, 0xfb], mem, lo, hi)
    p4 = find([0xa9, 0x3f, 0x8d, 0x02, 0xdd, 0xad, 0x00, 0xdd, 0x10, 0xfb, 0x60], mem, lo, hi)
    p3 = find([0xc9, 0x20, 0xb0, None], mem, lo, hi)
    if len(p1) != 1 or len(p1b) != 1 or len(p4) != 1:
        raise ValueError('инсталлятор не совпадает с известной сборкой (точки патча не найдены)', out)
    p3 = [a for a in p3 if a + 4 + mem[a+3] == p4[0]]
    if len(p3) != 1: raise ValueError('не найдена проверка PAL/NTSC инсталлятора', out)
    out.update(p_detect=p1[0], p_after_detect=p1b[0], p_wait=p1b[0] + 11, p_ntsc=p3[0], p_end=p4[0])
    cands = [(v[3], v) for pg, v in r.snaps.items() if lo <= v[0] < hi]
    if not cands: raise ValueError('не найдена точка входа бутера', out)
    cyc, (epc, smem, ssp, _) = min(cands)
    # image bounds in the snapshot
    lo2 = lo; hi2 = hi
    out.update(entry=epc, img_lo=lo2, img_hi=hi2, snap=smem)
    if not (0x0400 <= lo2 and hi2 <= 0xd000 and hi2 - lo2 <= 0x2000):
        raise ValueError('образ бутера %04x-%04x не помещается в 8K банка 0' % (lo2, hi2), out)
    if mem[0x3fa:0x3fc] is None: pass
    return out

# ---------------------------------------------------------------- harvesting
def harvest(disks, first_side_boot, log=print):
    """disks: list of (side_id, path) ordered. Uses a booted Machine (first side).
    Returns {side_id: [(addr, bytes)]}."""
    M = first_side_boot.M
    c = M.c
    def call(pc, a=0, maxc=300_000_000):
        cp = c.cpu; cp.s = 0xf0
        cp.push(0xff); cp.push(0xf7); cp.pc = pc; cp.a = a; cp.i = 1
        blocks = []
        def stop(m):
            p = m.c.cpu.pc
            if p == 0x0271:
                blocks.append((((c.ram[0x272] | c.ram[0x273] << 8) + cp.y) & 0xffff, cp.a))
            return p == 0xfff8
        rr = M.run(maxc=maxc, stop=stop)
        return rr, blocks
    c.p01 = 0x35
    out = {}
    for k, (sid, path, ents) in enumerate(disks):
        if k > 0:
            M.d.setdisk(path)
            call(0x020c, sid); call(0x0229)
        files = []
        for i, (la, ln) in enumerate(ents):
            call(0x020c, i)
            rr, b = call(0x0229)
            mem = {}
            for a, v in b:
                if a >= 0x100: mem[a] = v
            if not mem or rr[0] != 'stop':
                raise ValueError('сбой чтения файла %d стороны $%02X' % (i, sid))
            lo = min(mem); hi = max(mem)
            if hi - lo + 1 != len(mem) or (lo, len(mem)) != (la, ln):
                raise ValueError('файл %d стороны $%02X не совпал с каталогом' % (i, sid))
            files.append((lo, bytes(mem[x] for x in range(lo, hi + 1))))
        out[sid] = files
        log('  сторона $%02X: снято %d файлов' % (sid, len(files)))
    return out

# ---------------------------------------------------------------- reference depack
def depack_range(res, addr, data):
    m = C64(); m.p01 = 0x34
    m.ram[0x200:0x400] = res
    m.ram[addr:addr+len(data)] = data
    m.ram[0xf0] = addr & 255; m.ram[0xf1] = addr >> 8
    before = bytes(m.ram)
    cp = m.cpu; cp.s = 0xf0; cp.push(0xff); cp.push(0xf7); cp.pc = 0x02cc; cp.i = 1
    try:
        rr = m.run(stop=lambda mm: mm.cpu.pc == 0xfff8, maxsteps=8_000_000)
    except Exception:
        return None
    if rr[0] != 'stop': return None
    ch = [a for a in range(0x400, 0x10000) if m.ram[a] != before[a]]
    return (min(ch), max(ch)) if ch else (addr, addr)
