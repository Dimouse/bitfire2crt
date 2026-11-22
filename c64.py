import sys
sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from cpu import CPU, disasm

class C64:
    """RAM-only C64 with trapped KERNAL and logged I/O."""
    def __init__(self):
        self.ram = bytearray(65536)
        self.io = bytearray(4096)
        self.p01 = 0x37
        self.iolog = []
        self.cpu = CPU(self.read, self.write)
        self.traps = {}
        self.log_io = False
        self.io_read_hook = None
    def kernal_in(self): return (self.p01 & 2) != 0
    def io_in(self): return (self.p01 & 3) != 0 and (self.p01 & 4) != 0
    def read(self, a):
        a &= 0xffff
        if a == 1: return self.p01
        if 0xd000 <= a < 0xe000 and self.io_in():
            if self.io_read_hook:
                r = self.io_read_hook(a)
                if r is not None: return r
            if a == 0xd012: return ((self.cpu.cycles // 63) % 312) & 0xff
            if a == 0xd011: return (self.io[0x11] & 0x7f) | (0x80 if ((self.cpu.cycles//63) % 312) > 255 else 0)
            return self.io[a - 0xd000]
        return self.ram[a]
    def write(self, a, v):
        a &= 0xffff; v &= 0xff
        if a == 1: self.p01 = v; return
        if 0xd000 <= a < 0xe000 and self.io_in():
            self.io[a - 0xd000] = v
            if self.log_io: self.iolog.append((self.cpu.pc, a, v))
            return
        self.ram[a] = v
    def load_prg(self, data):
        la = data[0] | data[1] << 8
        self.ram[la:la+len(data)-2] = data[2:]
        return la, la+len(data)-2
    def run(self, pc=None, maxsteps=50_000_000, stop=None):
        c = self.cpu
        if pc is not None: c.pc = pc
        n = 0
        while n < maxsteps:
            if c.pc >= 0xe000 and self.kernal_in():
                t = self.traps.get(c.pc)
                if t is None:
                    return ('kernal', c.pc)
                r = t(self)
                if r: return r
                continue
            if stop and stop(self): return ('stop', c.pc)
            c.step(); n += 1
        return ('maxsteps', c.pc)
