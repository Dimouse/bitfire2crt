import sys
sys.path.insert(0, '/home/claude/work')
from cpu import CPU
from d64 import D64, SPT

GCR = [0x0a,0x0b,0x12,0x13,0x0e,0x0f,0x16,0x17,0x09,0x19,0x1a,0x1b,0x0d,0x1d,0x1e,0x15]

def gcr_encode(raw):
    out = bytearray()
    for i in range(0, len(raw), 4):
        q = raw[i:i+4]
        bits = 0
        for b in q:
            bits = (bits << 10) | (GCR[b >> 4] << 5) | GCR[b & 15]
        out += bits.to_bytes(5, 'big')
    return out

ZONE_BYTES = {3: 7692, 2: 7142, 1: 6666, 0: 6250}
def zone_of(t):
    return 3 if t <= 17 else 2 if t <= 24 else 1 if t <= 30 else 0
SPEED_CYC = {3: 26, 2: 28, 1: 30, 0: 32}   # drive cycles per byte, by density setting

def build_track(d64, t, id1, id2):
    data = bytearray(); sync = bytearray()
    ns = SPT[t-1]
    for s in range(ns):
        hdr = bytes([0x08, s ^ t ^ id1 ^ id2, s, t, id2, id1, 0x0f, 0x0f])
        data += b'\xff'*5; sync += b'\x01'*5
        g = gcr_encode(hdr); data += g; sync += b'\x00'*len(g)
        data += b'\x55'*9; sync += b'\x00'*9
        data += b'\xff'*5; sync += b'\x01'*5
        sec = d64.sec(t, s)
        ck = 0
        for b in sec: ck ^= b
        g = gcr_encode(bytes([0x07]) + sec + bytes([ck, 0, 0])); data += g; sync += b'\x00'*len(g)
        data += b'\x55'*8; sync += b'\x00'*8
    L = ZONE_BYTES[zone_of(t)]
    data += b'\x55'*(L-len(data)); sync += b'\x00'*(L-len(sync))
    return bytes(data), bytes(sync)

class Drive:
    def __init__(self, d64file):
        self.ram = bytearray(2048)
        self.cpu = CPU(self.read, self.write)
        self.setdisk(d64file)
        self.halftrack = 34   # track 18
        self.pb = 0x00; self.ddrb2 = 0x6f
        self.pcr2 = 0xee; self.acr2 = 0
        self.via1_pb = 0; self.via1_ddrb = 0x1a
        self.t1c = 0xffff; self.t1l = 0xffff; self.ifr2 = 0; self.ifr1 = 0
        self.last_byte_pos = -1
        self.bus = None          # set by machine
        self.cur_byte = 0
        self.running = False
        self.t1_base = 0
    def setdisk(self, fn):
        self.d64 = D64(fn)
        bam = self.d64.sec(18, 0)
        self.id1, self.id2 = bam[0xa2], bam[0xa3]
        self.tracks = {}
    def track(self):
        t = self.halftrack // 2 + 1
        if self.halftrack & 1 or t > 40: return None
        if t not in self.tracks:
            self.tracks[t] = build_track(self.d64, t, self.id1, self.id2)
        return self.tracks[t]
    # disk position based on time
    def disk_pos(self):
        tr = self.track()
        if tr is None: return None, 0
        dens = (self.pb >> 5) & 3
        cyc = SPEED_CYC[dens]
        L = len(tr[0])
        return tr, (self.cpu.cycles // cyc)
    def update_byte_ready(self):
        tr, p = self.disk_pos()
        if tr is None: return
        if p != self.last_byte_pos:
            self.last_byte_pos = p
            i = p % len(tr[0])
            self.cur_byte = tr[0][i]
            if not tr[1][i]:
                if (self.pcr2 & 0x0e) == 0x0e:
                    self.cpu.v = 1
                self.ifr2 |= 0x02
    def in_sync(self):
        tr, p = self.disk_pos()
        if tr is None: return False
        i = p % len(tr[0])
        return tr[1][i] == 1 and tr[1][(i+1) % len(tr[0])] == 1 or (tr[1][i] == 1)
    def read(self, a):
        a &= 0xffff
        if a < 0x0800: return self.ram[a]
        if 0x1800 <= a < 0x1c00:
            r = a & 15
            if r == 0: return self.bus.drive_read_pb()
            if r == 2: return self.via1_ddrb
            if r == 0x0d: return self.ifr1
            return 0
        if 0x1c00 <= a < 0x2000:
            r = a & 15
            if r == 0:
                v = self.pb & 0x6f
                v |= 0x10  # write protect off? (1 = not protected)
                if not self.in_sync(): v |= 0x80
                return v
            if r == 1 or r == 0x0f:
                self.update_byte_ready()
                self.ifr2 &= ~0x02
                return self.cur_byte
            if r == 2: return self.ddrb2
            if r == 3: return 0
            if r in (4, 5):
                el = (self.cpu.cycles - self.t1_base)
                cnt = (self.t1l - el) % (self.t1l + 2) if self.t1l else 0
                if r == 4:
                    self.ifr2 &= ~0x40
                    return cnt & 0xff
                return (cnt >> 8) & 0xff
            if r == 6: return self.t1l & 0xff
            if r == 7: return self.t1l >> 8
            if r == 0x0b: return self.acr2
            if r == 0x0c: return self.pcr2
            if r == 0x0d:
                el = (self.cpu.cycles - self.t1_base)
                if el > self.t1l: self.ifr2 |= 0x40
                return self.ifr2 | (0x80 if self.ifr2 & 0x7f else 0)
            return 0
        if a >= 0xc000:
            # no ROM: vectors -> stub
            return 0x00
        return 0
    def write(self, a, v):
        a &= 0xffff; v &= 0xff
        if a < 0x0800:
            self.ram[a] = v
            if a <= 5 and v & 0x80 and self.bus and self.bus.job_hook:
                self.bus.job_hook(self, a, v)
            return
        if 0x1800 <= a < 0x1c00:
            r = a & 15
            if r == 0: self.via1_pb = v; self.bus.drive_changed()
            elif r == 2: self.via1_ddrb = v; self.bus.drive_changed()
            elif r == 0x0d: self.ifr1 &= ~v
            return
        if 0x1c00 <= a < 0x2000:
            r = a & 15
            if r == 0:
                old = self.pb
                self.pb = v
                # stepper
                o = old & 3; n = v & 3
                if n == ((o + 1) & 3): self.halftrack = min(self.halftrack + 1, 83)
                elif n == ((o - 1) & 3): self.halftrack = max(self.halftrack - 1, 0)
            elif r == 2: self.ddrb2 = v
            elif r == 4 or r == 6: self.t1l = (self.t1l & 0xff00) | v
            elif r == 5:
                self.t1l = (self.t1l & 0xff) | v << 8; self.t1_base = self.cpu.cycles; self.ifr2 &= ~0x40
            elif r == 7: self.t1l = (self.t1l & 0xff) | v << 8
            elif r == 0x0b: self.acr2 = v
            elif r == 0x0c: self.pcr2 = v
            elif r == 0x0d: self.ifr2 &= ~v
            return
