import sys
sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from c64 import C64
from drive import Drive
from cpu import disasm

C64HZ = 985248.0
DRVHZ = 1000000.0

class Machine:
    def __init__(self, d64):
        self.c = C64()
        self.d = Drive(d64)
        self.d.bus = self
        self.d.pb = 0x4e
        self.c.io_read_hook = self.c64_io_read
        self.c.write = self.c64_write_wrap(self.c.write)
        self.c.cpu.write = self.c.write
        self.pra = 0xc7; self.ddra = 0x3f
        self.drive_on = False
        self.catching = False
        self.job_hook = self.do_job
        self.mw_log = []
        self.dev = 8
        self.trace_bus = False
        self.buslog = []
        self.install_kernal_traps()
    # ---------------- bus -----------------
    def c64_pull(self):
        # returns (atn, clk, data) pulled-low flags from C64
        def pulled(bit):
            m = 1 << bit
            return (not (self.ddra & m)) or bool(self.pra & m)
        return pulled(3), pulled(4), pulled(5)
    def drive_pull(self):
        d = self.d
        out = d.via1_pb & d.via1_ddrb
        atn, _, _ = self.c64_pull()
        clk = bool(out & 0x08)
        data = bool(out & 0x02) or (bool(atn) != bool(out & 0x10))
        return clk, data
    def lines(self):
        atn, cclk, cdata = self.c64_pull()
        dclk, ddata = self.drive_pull() if True else (False, False)
        return atn, cclk or dclk, cdata or ddata
    def drive_read_pb(self):
        self.catch_up_c64()
        atn, clk, data = self.lines()
        d = self.d
        inp = (1 if data else 0) | (4 if clk else 0) | (0x80 if atn else 0)
        return (d.via1_pb & d.via1_ddrb) | (inp & ~d.via1_ddrb & 0xff)
    def drive_changed(self):
        self.job_hook = None      # custom drive code talks to the bus: DOS jobs are over
        if self.trace_bus: self.buslog.append(('D', self.t_drive(), self.d.via1_pb, self.d.via1_ddrb))
    def c64_io_read(self, a):
        if a == 0xdd00:
            self.catch_up_drive()
            atn, clk, data = self.lines()
            v = (self.pra & self.ddra) | (0x3f & ~self.ddra)
            v &= 0x3f
            v |= (0x40 if not clk else 0) | (0x80 if not data else 0)
            return v
        if a == 0xdd02: return self.ddra
        return None
    def c64_write_wrap(self, orig):
        def w(a, v):
            a &= 0xffff
            if a in (0xdd00, 0xdd02) and self.c.io_in():
                if a == 0xdd00: self.pra = v & 0xff
                else: self.ddra = v & 0xff
                if self.trace_bus: self.buslog.append(('C', self.t_c64(), self.pra, self.ddra))
            orig(a, v)
        return w
    # --------------- timing ----------------
    def t_c64(self): return self.c.cpu.cycles / C64HZ
    def t_drive(self): return self.d.cpu.cycles / DRVHZ
    def catch_up_drive(self):
        if self.catching or not self.drive_on: return
        T = (self.c.cpu.cycles - 1) / C64HZ
        self.catching = True
        d = self.d
        while d.cpu.cycles / DRVHZ < T:
            self.dstep()
        self.catching = False
    def catch_up_c64(self):
        if self.catching: return
        T = (self.d.cpu.cycles - 1) / DRVHZ
        self.catching = True
        c = self.c
        while c.cpu.cycles / C64HZ < T:
            if self.cstep(): break
        self.catching = False
    def dstep(self):
        d = self.d
        d.update_byte_ready()
        d.cpu.step()
    def cstep(self):
        c = self.c
        if c.cpu.pc >= 0xe000 and c.kernal_in():
            t = c.traps.get(c.cpu.pc)
            if t is None:
                self.stopped = ('kernal', c.cpu.pc); return True
            t(c); return False
        if self.c64_stop and self.c64_stop(self):
            self.stopped = ('stop', c.cpu.pc); return True
        c.cpu.step()
        return False
    def run(self, maxc=10**9, stop=None):
        self.c64_stop = stop
        self.stopped = None
        c = self.c; d = self.d
        lim = c.cpu.cycles + maxc
        while c.cpu.cycles < lim:
            if self.drive_on and d.cpu.cycles / DRVHZ < c.cpu.cycles / C64HZ:
                self.dstep()
            else:
                if self.cstep(): return self.stopped
                if not self.drive_on:
                    d.cpu.cycles = int(c.cpu.cycles / C64HZ * DRVHZ)
        return ('maxc', c.cpu.pc)
    # --------------- job emulation ----------
    def do_job(self, d, slot, v):
        # job for buffer `slot` at track/sector ($06+2*slot,$07+2*slot)
        t = d.ram[6 + 2*slot]; s = d.ram[7 + 2*slot]
        if v in (0x80, 0xb0):
            d.halftrack = (t - 1) * 2
            d.pb = (d.pb & ~3) | (d.halftrack & 3)
        if v == 0x80:
            d.ram[0x300 + slot*0x100: 0x400 + slot*0x100] = d.d64.sec(t, s)
            d.halftrack = (t - 1) * 2
            d.pb = (d.pb & ~3) | (d.halftrack & 3)
        d.ram[slot] = 0x01
    # --------------- kernal traps -----------
    def install_kernal_traps(self):
        c = self.c
        def rts(m):
            cp = m.cpu; cp.pc = ((cp.pull() | cp.pull() << 8) + 1) & 0xffff
        self.cmd = bytearray()
        def LISTEN(m):
            self.dev = m.cpu.a; self.cmd = bytearray(); m.cpu.c = 0; rts(m)
        def SECOND(m):
            if self.dev != 8:
                m.ram[0x90] = 0x80; m.cpu.n = 1
            else:
                m.cpu.n = 0
            rts(m)
        def CIOUT(m):
            if self.dev == 8: self.cmd.append(m.cpu.a)
            m.cpu.c = 0; rts(m)
        def UNLSN(m):
            if self.dev == 8: self.drive_cmd(bytes(self.cmd))
            self.cmd = bytearray(); rts(m)
        for a, f in ((0xffb1, LISTEN), (0xff93, SECOND), (0xffa8, CIOUT), (0xffae, UNLSN)):
            c.traps[a] = f
    def drive_cmd(self, cmd):
        d = self.d
        if cmd[:3] == b'M-W':
            a = cmd[3] | cmd[4] << 8; n = cmd[5]
            for i in range(n): d.ram[(a + i) & 0x7ff] = cmd[6 + i]
        elif cmd[:3] == b'M-E':
            a = cmd[3] | cmd[4] << 8
            d.cpu.pc = a; d.cpu.s = 0xfd; d.cpu.i = 1
            d.cpu.cycles = int(self.c.cpu.cycles / C64HZ * DRVHZ)
            self.drive_on = True
            # ROM idle state: buffers / jobs
        elif cmd[:1] == b'I':
            pass
        self.mw_log.append(cmd[:6])
