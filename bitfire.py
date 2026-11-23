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
        if s == 17 and len(ents) < 63: break
        bb = d.sec(18, s)
        for i in range(63):
            e = (bb[4+i] | bb[0x43+i] << 8, bb[0x82+i] | bb[0xc1+i] << 8)
            if e == (0, 0): continue
            ents.append(((e[0] + 0x100) & 0xffff, e[1] + 1))
    if not ents and any(b[4:]): return None
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

def emulate_boot(d64_path, maxc=40_000_000, pcs=None):
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
    la, end = M.c.load_prg(prg)
    start = basic_sys(prg)
    if start is None:
        if la <= 0x0302 < end and la <= 0x0303 < end:
            start = M.c.ram[0x302] | M.c.ram[0x303] << 8; r.notes.append('автостарт через вектор $0302')
        elif la <= 0x0326 < end:
            start = M.c.ram[0x326] | M.c.ram[0x327] << 8; r.notes.append('автостарт через вектор $0326')
        else:
            start = la; r.notes.append('нет SYS, старт с адреса загрузки (догадка)')
    r.load = la; r.load_end = end; r.start = start
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
    lastw = {}; firstw = {}
    ow = c.write
    def w(a, v):
        a &= 0xffff; cy = c.cpu.cycles
        lastw[a] = cy
        if a not in firstw: firstw[a] = cy
        ow(a, v)
    c.write = w; c.cpu.write = w
    seen_pages = set(); snaps = {}
    me_cycle = [None]
    def stop(m):
        pc = m.c.cpu.pc; pg = pc >> 8
        if pcs is not None and 0x100 <= pc < 0x400: pcs.add(pc)
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
    r.M = M; r.snaps = snaps; r.loads = st['loads']; r.lastw = lastw; r.firstw = firstw
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
def find(pat, mem, lo=0, hi=0x10000):
    rx = re.compile(b''.join(b'.' if x is None else re.escape(bytes([x])) for x in pat), re.S)
    return [m.start() for m in rx.finditer(mem, lo, hi)]

def one(lst, what):
    if len(lst) != 1: raise ValueError('%s: %s' % (what, 'не найдено' if not lst else 'несколько вариантов'))
    return lst[0]

def find_profile(mem):
    """Locate the Bitfire resident API by byte patterns in $0200-$03FF of `mem`."""
    L, H = 0x200, 0x400
    p = {}
    raw = one(find([0xa9, 0xef, 0x20, None, None, 0x20, None, None, 0x10, 0xfb], mem, L, H), 'load_next_raw')
    p['raw'] = raw; p['send'] = mem[raw+3] | mem[raw+4] << 8
    p['poll'] = mem[raw+6] | mem[raw+7] << 8; p['raw_loop'] = raw + 5
    p['comp'] = one(find([0xa9, 0xef, 0x20, p['send'] & 255, p['send'] >> 8, 0xa9, 0x91, 0xa2, 0x08], mem, L, H), 'load_next_comp')
    p['decomp'] = one(find([0xa9, 0x96, 0xa2, 0x60, 0xd0], mem, L, H), 'decomp')
    q = p['poll']
    pp = find([0xad, 0x00, 0xdd, 0x29, 0xc0, 0xd0, None, 0xa0, 0x05, 0xa2, None, 0x20, None, None,
               0xa6, None, 0xa5, None, None, None, 0x30, 0x04, 0x86, None, 0x85, None], mem, q, q + 26)
    if not pp: raise ValueError('опрос дисковода не похож на Bitfire')
    p['src'] = mem[q+23]
    if mem[q+25] != p['src'] + 1: raise ValueError('указатель распаковщика не подряд')
    recv = mem[q+12] | mem[q+13] << 8
    if not (mem[recv] == 0x8e and mem[recv+3] == 0x8d and mem[recv+4] == mem[recv+1] + 1):
        raise ValueError('процедура приёма блока не распознана')
    p['store'] = (mem[recv+1] | mem[recv+2] << 8) - 1
    if mem[p['store']] != 0x99: raise ValueError('запись принятого байта не распознана')
    p['bvc'] = one(find([0x2c, 0x00, 0xdd, 0x50, 0xf6], mem, L, H), 'проверка $DD00 в распаковщике') + 4
    ends = [x for x in find([0xa2, 0x60, 0xd0], mem, q, H) if x > recv]
    if not ends: raise ValueError('конец процедуры приёма не найден')
    p['free'] = (q + 3, ends[0] + 4)
    snd = p['send']; e = snd
    while e < raw and mem[e] != 0x60: e += 1
    p['free2'] = (snd + 3, e + 1)
    if p['free2'][1] - p['free2'][0] < 12: raise ValueError('мало места в процедуре отправки')
    if not (L <= p['store'] < p['free'][1]): raise ValueError('странная раскладка резидента')
    return p

def analyse_bitfire(r):
    """Locate resident API, installer patch sites, booter entry and image pages."""
    M = r.M; mem = bytes(r.boot_ram)
    out = {}
    try:
        out['prof'] = find_profile(mem)
    except ValueError as ex:
        raise ValueError('резидент Bitfire неизвестной сборки (' + ex.args[0] + ')', out)
    w = lambda a: r.lastw.get(a, -1) >= 0
    cl = [x for x in find([0xa2, 0x00, 0xbd, None, None, 0x9d, 0x00, 0x02, 0xbd, None, None, 0x9d, None, 0x02], mem, 0x400) if w(x)]
    cl = one(cl, 'цикл копирования резидента')
    s1 = mem[cl+3] | mem[cl+4] << 8; s2 = mem[cl+9] | mem[cl+10] << 8; d2 = 0x200 | mem[cl+12]
    if s1 - 0x200 != s2 - d2: raise ValueError('неожиданная раскладка копии резидента', out)
    out['res_off'] = s1 - 0x200; out['copyloop'] = cl
    W = lambda pat, what: one([x for x in find(pat, mem, 0x400, 0xd000) if w(x)], what)
    try:
        out['p_detect'] = W([0xa2, 0x08, 0x86, 0xba, 0x20, None, None, 0x30], 'поиск дисководов')
        out['p_after_detect'] = W([0x78, 0xa9, 0xc3, 0x8d, 0x00, 0xdd, 0xa9, 0x3f, 0x8d, 0x02, 0xdd, 0x2c, 0x00, 0xdd, 0x30, 0xfb], 'заливка кода')
        out['p_wait'] = out['p_after_detect'] + 11
        out['p_end'] = W([0xa9, 0x3f, 0x8d, 0x02, 0xdd, 0xad, 0x00, 0xdd, 0x10, 0xfb, 0x60], 'ожидание дисковода')
        p3 = [x for x in find([0xc9, 0x20, 0xb0, None], mem, 0x400, 0xd000) if w(x) and x + 4 + mem[x+3] == out['p_end']]
        out['p_ntsc'] = one(p3, 'проверка PAL/NTSC')
    except ValueError as ex:
        raise ValueError('инсталлятор другой сборки (' + ex.args[0] + ')', out)
    cands = [(v[3], v) for pg, v in r.snaps.items() if 0x0400 <= v[0] < 0xd000]
    if not cands: raise ValueError('не найдена точка входа бутера', out)
    cyc, (epc, smem, ssp, _) = min(cands)
    pages = [pg for pg in range(0x04, 0xd0) if any(smem[pg*256:pg*256+256])]
    for x in (cl, out['p_detect'], out['p_end'], epc):
        if (x >> 8) not in pages: raise ValueError('код бутера вне образа', out)
    if len(pages) > 32: raise ValueError('образ бутера (%d страниц) больше 8 КБ' % len(pages), out)
    out.update(entry=epc, pages=pages, snap=smem)
    return out

# ---------------------------------------------------------------- harvesting
def harvest(r, prof, sides, log=print):
    """sides: [(sid, path, ents)] unique disks; sides[0] must be the booted disk.
    Returns {path: [(addr, data)]} read through the real Bitfire drive code."""
    M = r.M; c = M.c
    ST = prof['store']; SEND = prof['send']; LOOP = prof['raw_loop']
    def call(pc, a=0, maxc=300_000_000):
        cp = c.cpu; cp.s = 0xf0
        cp.push(0xff); cp.push(0xf7); cp.pc = pc; cp.a = a; cp.i = 1
        blocks = []
        def stop(m):
            p = m.c.cpu.pc
            if p == ST:
                blocks.append((((c.ram[ST+1] | c.ram[ST+2] << 8) + cp.y) & 0xffff, cp.a))
            return p == 0xfff8
        rr = M.run(maxc=maxc, stop=stop)
        return rr, blocks
    c.p01 = 0x35
    out = {}; cur = sides[0][0]; boot = sides[0]
    for k, (sid, path, ents) in enumerate(sides):
        if k > 0:
            if sid == cur:      # alternative disk for the same side: make the drive re-read its dir
                hop = boot if sid != boot[0] else next(x for x in sides if x[0] != sid)
                M.d.setdisk(hop[1]); call(SEND, hop[0]); call(LOOP)
            M.d.setdisk(path); call(SEND, sid); call(LOOP)
        cur = sid
        files = []
        for i, (la, ln) in enumerate(ents):
            call(SEND, i)
            rr, b = call(LOOP)
            mem = {}
            for a, v in b:
                if a >= 0x100 or la < 0x100: mem[a] = v
            mem = {a: v for a, v in mem.items() if la <= a < la + ln}
            if rr[0] != 'stop' or len(mem) != ln:
                raise ValueError('файл %d стороны $%02X не совпал с каталогом' % (i, sid))
            files.append((la, bytes(mem[x] for x in range(la, la + ln))))
        out[path] = files
        log('  сторона $%02X (%s): снято %d файлов' % (sid, re.sub(r'^\d+_', '', os.path.basename(path)), len(files)))
    return out

# ---------------------------------------------------------------- reference depack
def depack_range(res, addr, data, prof):
    """Depack a file standalone with the original resident ($01=$34); return changed range."""
    m = C64(); m.p01 = 0x34
    m.ram[0x200:0x400] = res
    m.ram[addr:addr+len(data)] = data
    m.ram[prof['src']] = addr & 255; m.ram[prof['src']+1] = addr >> 8
    before = bytes(m.ram)
    cp = m.cpu; cp.s = 0xf0; cp.push(0xff); cp.push(0xf7); cp.pc = prof['decomp']; cp.i = 1
    try:
        rr = m.run(stop=lambda mm: mm.cpu.pc == 0xfff8, maxsteps=8_000_000)
    except Exception:
        return None
    if rr[0] != 'stop': return None
    ch = [a for a in range(0x400, 0x10000) if m.ram[a] != before[a]]
    return (min(ch), max(ch)) if ch else (addr, addr)

# ---------------------------------------------------------------- demo-side disk logic
def find_disk_logic(files_by_side, res, prof, log=print):
    """Scan (depacked) demo code for side requests and drive busy-waits.
    files_by_side: [(sid, [(addr, data)])]. Returns dict."""
    from c64 import C64
    send_targets = {prof['send'], prof['raw'] + 2}
    nfiles = {sid: len(f) for sid, f in files_by_side}
    found = []      # (side_index_of_file, cmd)
    sites = set()
    for si, (sid, files) in enumerate(files_by_side):
        for i, (la, data) in enumerate(files):
            m = C64(); m.p01 = 0x34; m.ram[0x200:0x400] = res
            m.ram[la:la+len(data)] = data
            m.ram[prof['src']] = la & 255; m.ram[prof['src']+1] = la >> 8
            cp = m.cpu; cp.s = 0xf0; cp.push(0xff); cp.push(0xf7); cp.pc = prof['decomp']; cp.i = 1
            ok = False
            try: ok = m.run(stop=lambda mm: mm.cpu.pc == 0xfff8, maxsteps=1_500_000)[0] == 'stop'
            except Exception: pass
            mems = [bytes(bytearray(la)) + data]
            if ok: mems.append(bytes(m.ram))
            for mem in mems:
                for mm in re.finditer(rb'\xa9([\x00-\xff])\x20([\x00-\xff])([\x02\x03])', mem):
                    if mm.start() < 0x400: continue
                    tgt = mem[mm.start()+3] | mem[mm.start()+4] << 8
                    if tgt in send_targets:
                        c = mem[mm.start()+1]
                        if c >= 0xf0 and c != 0xff or (c < 0xef and c >= nfiles[sid]):
                            found.append((si, c))
                for mm in re.finditer(rb'[\x2c\xad]\x00\xdd\x30\xfb', mem):
                    a = mm.start() + 4
                    if 0x400 <= a < 0xd000: sites.add(a)
    plugs = sorted({c for si, c in found if c < 0xef})
    out = {'plug': plugs[0] if plugs else None, 'plugs': plugs, 'sites': sorted(sites), 'trans': {}}
    for k in range(1, len(files_by_side)):
        sid = files_by_side[k][0]
        prev = [c for si, c in found if si == k - 1]
        if sid in prev: out['trans'][k] = sid
        elif out['plug'] is not None and out['plug'] in prev: out['trans'][k] = out['plug']
        else: out['trans'][k] = None
    return out
