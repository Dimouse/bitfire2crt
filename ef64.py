import sys
sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from c64 import C64
from cpu import CPU

def fake_kernal():
    k = bytearray(b'\xea' * 8192)
    def put(a, bs): k[a - 0xe000:a - 0xe000 + len(bs)] = bytes(bs)
    put(0xfe43, [0x78, 0x6c, 0x18, 0x03])                     # NMI: SEI; JMP ($0318)
    put(0xff48, [0x48, 0x8a, 0x48, 0x98, 0x48, 0xba, 0xbd, 0x04, 0x01, 0x29, 0x10,
                 0xf0, 0x03, 0x6c, 0x16, 0x03, 0x6c, 0x14, 0x03])
    put(0xfffa, [0x43, 0xfe, 0xe2, 0xfc, 0x48, 0xff])
    return k

class EF64(C64):
    def __init__(self, rom):
        super().__init__()
        self.rom = rom              # 64*16K
        self.bank = 0; self.efctl = 0   # boot: ultimax (GAME low via boot jumper)
        self.dfram = bytearray(256)
        self.kernal = fake_kernal()
        self.p00 = 0x2f
        self.cpu = CPU(self.read, self.write)
        self.traps = {}
        self.nmi_hook = None
    def mode(self):
        c = self.efctl
        idx = (c & 2) | (((c >> 2) & 1) & (~c & 1))
        return ('ultimax', 'off', '16k', '8k')[idx]
    def kernal_in(self):
        m = self.mode()
        if m == 'ultimax': return False
        return (self.p01 & 2) != 0
    def io_in(self):
        m = self.mode()
        if m == 'ultimax': return True
        p = self.p01 & 7
        if p & 3 == 0: return False
        return (p & 4) != 0
    def read(self, a):
        a &= 0xffff
        if a == 0: return self.p00
        if a == 1: return self.p01
        m = self.mode(); p = self.p01
        lo = p & 1; hi = (p >> 1) & 1
        if m == 'ultimax':
            if 0x8000 <= a < 0xa000: return self.rom[self.bank*16384 + a - 0x8000]
            if a >= 0xe000: return self.rom[self.bank*16384 + 0x2000 + a - 0xe000]
            if 0xd000 <= a < 0xe000: return self.io_read(a)
            if a < 0x1000: return self.ram[a]
            return 0xff
        if 0x8000 <= a < 0xa000 and m in ('8k', '16k') and lo and hi:
            return self.rom[self.bank*16384 + a - 0x8000]
        if 0xa000 <= a < 0xc000:
            if m == '16k' and hi: return self.rom[self.bank*16384 + 0x2000 + a - 0xa000]
            if m in ('8k', 'off') and lo and hi: return 0x60   # BASIC ROM (dummy)
        if 0xd000 <= a < 0xe000:
            if self.io_in(): return self.io_read(a)
            if (p & 3) and not (p & 4): return 0    # char rom
        if a >= 0xe000 and hi: return self.kernal[a - 0xe000]
        return self.ram[a]
    def io_read(self, a):
        if 0xdf00 <= a < 0xe000: return self.dfram[a & 0xff]
        if self.io_read_hook:
            r = self.io_read_hook(a)
            if r is not None: return r
        if a == 0xd012: return ((self.cpu.cycles // 63) % 312) & 0xff
        if a == 0xd011: return (self.io[0x11] & 0x7f) | (0x80 if ((self.cpu.cycles//63) % 312) > 255 else 0)
        if a == 0xdd00: return 0xc7 | (self.io[0xd00] & 0x3f & self.io[0xd02])
        return self.io[a - 0xd000]
    def write(self, a, v):
        a &= 0xffff; v &= 0xff
        if a == 0: self.p00 = v; return
        if a == 1: self.p01 = v; return
        if 0xd000 <= a < 0xe000 and self.io_in():
            if a == 0xde00: self.bank = v & 0x3f
            elif a == 0xde02: self.efctl = v
            elif a >= 0xdf00: self.dfram[a & 0xff] = v
            self.io[a - 0xd000] = v
            return
        if self.mode() == 'ultimax' and not (a < 0x1000 or 0xd000 <= a < 0xe000):
            return
        self.ram[a] = v
    def run(self, pc=None, maxsteps=50_000_000, stop=None):
        c = self.cpu
        if pc is not None: c.pc = pc
        n = 0
        while n < maxsteps:
            if c.pc >= 0xe000 and self.kernal_in():
                t = self.traps.get(c.pc)
                if t is not None:
                    r = t(self)
                    if r: return r
                    continue
            if stop and stop(self): return ('stop', c.pc)
            if self.nmi_hook: self.nmi_hook(self)
            c.step(); n += 1
        return ('maxsteps', c.pc)
