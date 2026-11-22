# Minimal 6502 (NMOS, incl. common illegal opcodes) emulator + disassembler
MODES = {}
OPS = {}
def op(code, name, mode, cyc=2):
    OPS[code] = (name, mode, cyc)

_tab = """
00 BRK imp 7|01 ORA izx 6|05 ORA zp 3|06 ASL zp 5|08 PHP imp 3|09 ORA imm 2|0A ASL acc 2|0D ORA abs 4|0E ASL abs 6
10 BPL rel 2|11 ORA izy 5|15 ORA zpx 4|16 ASL zpx 6|18 CLC imp 2|19 ORA aby 4|1D ORA abx 4|1E ASL abx 7
20 JSR abs 6|21 AND izx 6|24 BIT zp 3|25 AND zp 3|26 ROL zp 5|28 PLP imp 4|29 AND imm 2|2A ROL acc 2|2C BIT abs 4|2D AND abs 4|2E ROL abs 6
30 BMI rel 2|31 AND izy 5|35 AND zpx 4|36 ROL zpx 6|38 SEC imp 2|39 AND aby 4|3D AND abx 4|3E ROL abx 7
40 RTI imp 6|41 EOR izx 6|45 EOR zp 3|46 LSR zp 5|48 PHA imp 3|49 EOR imm 2|4A LSR acc 2|4C JMP abs 3|4D EOR abs 4|4E LSR abs 6
50 BVC rel 2|51 EOR izy 5|55 EOR zpx 4|56 LSR zpx 6|58 CLI imp 2|59 EOR aby 4|5D EOR abx 4|5E LSR abx 7
60 RTS imp 6|61 ADC izx 6|65 ADC zp 3|66 ROR zp 5|68 PLA imp 4|69 ADC imm 2|6A ROR acc 2|6C JMP ind 5|6D ADC abs 4|6E ROR abs 6
70 BVS rel 2|71 ADC izy 5|75 ADC zpx 4|76 ROR zpx 6|78 SEI imp 2|79 ADC aby 4|7D ADC abx 4|7E ROR abx 7
81 STA izx 6|84 STY zp 3|85 STA zp 3|86 STX zp 3|88 DEY imp 2|8A TXA imp 2|8C STY abs 4|8D STA abs 4|8E STX abs 4
90 BCC rel 2|91 STA izy 6|94 STY zpx 4|95 STA zpx 4|96 STX zpy 4|98 TYA imp 2|99 STA aby 5|9A TXS imp 2|9D STA abx 5
A0 LDY imm 2|A1 LDA izx 6|A2 LDX imm 2|A4 LDY zp 3|A5 LDA zp 3|A6 LDX zp 3|A8 TAY imp 2|A9 LDA imm 2|AA TAX imp 2|AC LDY abs 4|AD LDA abs 4|AE LDX abs 4
B0 BCS rel 2|B1 LDA izy 5|B4 LDY zpx 4|B5 LDA zpx 4|B6 LDX zpy 4|B8 CLV imp 2|B9 LDA aby 4|BA TSX imp 2|BC LDY abx 4|BD LDA abx 4|BE LDX aby 4
C0 CPY imm 2|C1 CMP izx 6|C4 CPY zp 3|C5 CMP zp 3|C6 DEC zp 5|C8 INY imp 2|C9 CMP imm 2|CA DEX imp 2|CC CPY abs 4|CD CMP abs 4|CE DEC abs 6
D0 BNE rel 2|D1 CMP izy 5|D5 CMP zpx 4|D6 DEC zpx 6|D8 CLD imp 2|D9 CMP aby 4|DD CMP abx 4|DE DEC abx 7
E0 CPX imm 2|E1 SBC izx 6|E4 CPX zp 3|E5 SBC zp 3|E6 INC zp 5|E8 INX imp 2|E9 SBC imm 2|EA NOP imp 2|EC CPX abs 4|ED SBC abs 4|EE INC abs 6
F0 BEQ rel 2|F1 SBC izy 5|F5 SBC zpx 4|F6 INC zpx 6|F8 SED imp 2|F9 SBC aby 4|FD SBC abx 4|FE INC abx 7
"""
for part in _tab.replace('\n', '|').split('|'):
    part = part.strip()
    if not part: continue
    c, n, m, cy = part.split()
    op(int(c, 16), n, m, int(cy))
# illegal opcodes
for base, n in ((0x03,'SLO'),(0x23,'RLA'),(0x43,'SRE'),(0x63,'RRA'),(0xC3,'DCP'),(0xE3,'ISC')):
    for d, m, cy in ((0,'izx',8),(4,'zp',5),(0xc,'abs',6),(0x10,'izy',8),(0x14,'zpx',6),(0x18,'aby',7),(0x1c,'abx',7)):
        op(base+d, n, m, cy)
for c, m, cy in ((0xA3,'izx',6),(0xA7,'zp',3),(0xAF,'abs',4),(0xB3,'izy',5),(0xB7,'zpy',4),(0xBF,'aby',4),(0xAB,'imm',2)):
    op(c, 'LAX', m, cy)
for c, m, cy in ((0x83,'izx',6),(0x87,'zp',3),(0x8F,'abs',4),(0x97,'zpy',4)):
    op(c, 'SAX', m, cy)
op(0x0B,'ANC','imm');op(0x2B,'ANC','imm');op(0x4B,'ALR','imm');op(0x6B,'ARR','imm');op(0xCB,'SBX','imm');op(0xEB,'SBC','imm')
for c in (0x1A,0x3A,0x5A,0x7A,0xDA,0xFA): op(c,'NOP','imp')
for c in (0x80,0x82,0x89,0xC2,0xE2): op(c,'NOP','imm')
for c in (0x04,0x44,0x64): op(c,'NOP','zp',3)
for c in (0x14,0x34,0x54,0x74,0xD4,0xF4): op(c,'NOP','zpx',4)
op(0x0C,'NOP','abs',4)
for c in (0x1C,0x3C,0x5C,0x7C,0xDC,0xFC): op(c,'NOP','abx',4)
op(0x9F,'SHA','aby',5);op(0x93,'SHA','izy',6);op(0x9E,'SHX','aby',5);op(0x9C,'SHY','abx',5);op(0x9B,'TAS','aby',5);op(0xBB,'LAS','aby',4)
for c in (0x02,0x12,0x22,0x32,0x42,0x52,0x62,0x72,0x92,0xB2,0xD2,0xF2): op(c,'JAM','imp')

LEN = {'imp':1,'acc':1,'imm':2,'zp':2,'zpx':2,'zpy':2,'izx':2,'izy':2,'rel':2,'abs':3,'abx':3,'aby':3,'ind':3}

def disasm(mem, pc, n=20, rd=None):
    rd = rd or (lambda a: mem[a & 0xffff])
    out = []
    for _ in range(n):
        o = rd(pc); name, m, _c = OPS.get(o, ('???','imp',2)); l = LEN[m]
        b = [rd(pc+i) for i in range(l)]
        a8 = b[1] if l > 1 else 0; a16 = (b[1] | b[2] << 8) if l > 2 else 0
        s = {'imp':'','acc':'A','imm':'#$%02X'%a8,'zp':'$%02X'%a8,'zpx':'$%02X,X'%a8,'zpy':'$%02X,Y'%a8,
             'izx':'($%02X,X)'%a8,'izy':'($%02X),Y'%a8,'rel':'$%04X'%((pc+2+(a8-256 if a8>127 else a8))&0xffff),
             'abs':'$%04X'%a16,'abx':'$%04X,X'%a16,'aby':'$%04X,Y'%a16,'ind':'($%04X)'%a16}[m]
        out.append('%04X  %-9s %s %s' % (pc, ' '.join('%02X'%x for x in b), name, s))
        pc = (pc + l) & 0xffff
    return '\n'.join(out)

class CPU:
    def __init__(self, read, write):
        self.read = read; self.write = write
        self.a = self.x = self.y = 0; self.s = 0xff; self.pc = 0
        self.c = self.z = self.i = self.d = self.v = self.n = 0
        self.cycles = 0
    def p(self):
        return self.c | self.z<<1 | self.i<<2 | self.d<<3 | 0x20 | self.v<<6 | self.n<<7
    def setp(self, v):
        self.c=v&1; self.z=(v>>1)&1; self.i=(v>>2)&1; self.d=(v>>3)&1; self.v=(v>>6)&1; self.n=(v>>7)&1
    def push(self, v): self.write(0x100+self.s, v & 0xff); self.s = (self.s-1) & 0xff
    def pull(self): self.s = (self.s+1) & 0xff; return self.read(0x100+self.s)
    def nz(self, v): v &= 0xff; self.z = int(v == 0); self.n = v >> 7; return v
    def irq(self, vec=0xfffe, brk=False):
        self.push(self.pc>>8); self.push(self.pc); self.push(self.p() | (0x10 if brk else 0))
        self.i = 1; self.pc = self.read(vec) | self.read(vec+1) << 8
    def adc(self, v):
        if self.d:
            lo = (self.a & 15) + (v & 15) + self.c
            hi = (self.a >> 4) + (v >> 4)
            if lo > 9: lo += 6; hi += 1
            self.z = int(((self.a + v + self.c) & 0xff) == 0)
            self.n = (hi >> 3) & 1
            self.v = int(((~(self.a ^ v)) & (self.a ^ (hi << 4)) & 0x80) != 0)
            if hi > 9: hi += 6
            self.c = int(hi > 15); self.a = ((hi << 4) | (lo & 15)) & 0xff
        else:
            r = self.a + v + self.c
            self.v = int(((self.a ^ r) & (v ^ r) & 0x80) != 0)
            self.c = int(r > 0xff); self.a = self.nz(r)
    def sbc(self, v):
        if self.d:
            r = self.a - v - (1 - self.c)
            lo = (self.a & 15) - (v & 15) - (1 - self.c)
            hi = (self.a >> 4) - (v >> 4)
            if lo < 0: lo -= 6; hi -= 1
            if hi < 0: hi -= 6
            self.v = int(((self.a ^ v) & (self.a ^ r) & 0x80) != 0)
            self.c = int(r >= 0); self.nz(r)
            self.a = ((hi << 4) | (lo & 15)) & 0xff
        else:
            r = self.a - v - (1 - self.c)
            self.v = int(((self.a ^ v) & (self.a ^ r) & 0x80) != 0)
            self.c = int(r >= 0); self.a = self.nz(r)
    def cmp(self, r, v):
        t = r - v; self.c = int(t >= 0); self.nz(t)
    def step(self):
        rd = self.read; pc = self.pc
        o = rd(pc); name, m, cyc = OPS.get(o, ('JAM','imp',2))
        self.cycles += cyc
        if m == 'imp' or m == 'acc': ad = None; pc += 1
        elif m == 'imm': ad = pc+1; pc += 2
        elif m == 'zp': ad = rd(pc+1); pc += 2
        elif m == 'zpx': ad = (rd(pc+1)+self.x) & 0xff; pc += 2
        elif m == 'zpy': ad = (rd(pc+1)+self.y) & 0xff; pc += 2
        elif m == 'izx':
            z = (rd(pc+1)+self.x) & 0xff; ad = rd(z) | rd((z+1)&0xff) << 8; pc += 2
        elif m == 'izy':
            z = rd(pc+1); b = rd(z) | rd((z+1)&0xff) << 8; ad = (b+self.y) & 0xffff; pc += 2
            if (b ^ ad) & 0xff00 and name not in ('STA',): self.cycles += 1
        elif m == 'rel':
            ofs = rd(pc+1); ad = (pc+2+(ofs-256 if ofs > 127 else ofs)) & 0xffff; pc += 2
        elif m == 'abs': ad = rd(pc+1) | rd(pc+2) << 8; pc += 3
        elif m == 'abx':
            b = rd(pc+1) | rd(pc+2) << 8; ad = (b+self.x) & 0xffff; pc += 3
            if (b ^ ad) & 0xff00 and cyc == 4: self.cycles += 1
        elif m == 'aby':
            b = rd(pc+1) | rd(pc+2) << 8; ad = (b+self.y) & 0xffff; pc += 3
            if (b ^ ad) & 0xff00 and cyc == 4: self.cycles += 1
        elif m == 'ind':
            b = rd(pc+1) | rd(pc+2) << 8
            ad = rd(b) | rd((b & 0xff00) | ((b+1) & 0xff)) << 8; pc += 3
        self.pc = pc & 0xffff
        f = getattr(self, 'o_'+name)
        f(ad, m)
    # ops
    def _rmw(self, ad, m, fn):
        if m == 'acc': self.a = fn(self.a)
        else:
            v = self.read(ad); self.write(ad, v); self.write(ad, fn(v))
    def o_LDA(s,a,m): s.a = s.nz(s.read(a))
    def o_LDX(s,a,m): s.x = s.nz(s.read(a))
    def o_LDY(s,a,m): s.y = s.nz(s.read(a))
    def o_LAX(s,a,m): s.a = s.x = s.nz(s.read(a))
    def o_STA(s,a,m): s.write(a, s.a)
    def o_STX(s,a,m): s.write(a, s.x)
    def o_STY(s,a,m): s.write(a, s.y)
    def o_SAX(s,a,m): s.write(a, s.a & s.x)
    def o_SHA(s,a,m): s.write(a, s.a & s.x & ((a>>8)+1))
    def o_SHX(s,a,m): s.write(a, s.x & ((a>>8)+1))
    def o_SHY(s,a,m): s.write(a, s.y & ((a>>8)+1))
    def o_TAS(s,a,m): s.s = s.a & s.x; s.write(a, s.s & ((a>>8)+1))
    def o_LAS(s,a,m): s.a = s.x = s.s = s.nz(s.read(a) & s.s)
    def o_TAX(s,a,m): s.x = s.nz(s.a)
    def o_TAY(s,a,m): s.y = s.nz(s.a)
    def o_TXA(s,a,m): s.a = s.nz(s.x)
    def o_TYA(s,a,m): s.a = s.nz(s.y)
    def o_TSX(s,a,m): s.x = s.nz(s.s)
    def o_TXS(s,a,m): s.s = s.x
    def o_INX(s,a,m): s.x = s.nz(s.x+1)
    def o_INY(s,a,m): s.y = s.nz(s.y+1)
    def o_DEX(s,a,m): s.x = s.nz(s.x-1)
    def o_DEY(s,a,m): s.y = s.nz(s.y-1)
    def o_ORA(s,a,m): s.a = s.nz(s.a | s.read(a))
    def o_AND(s,a,m): s.a = s.nz(s.a & s.read(a))
    def o_EOR(s,a,m): s.a = s.nz(s.a ^ s.read(a))
    def o_ADC(s,a,m): s.adc(s.read(a))
    def o_SBC(s,a,m): s.sbc(s.read(a))
    def o_CMP(s,a,m): s.cmp(s.a, s.read(a))
    def o_CPX(s,a,m): s.cmp(s.x, s.read(a))
    def o_CPY(s,a,m): s.cmp(s.y, s.read(a))
    def o_BIT(s,a,m):
        v = s.read(a); s.z = int((v & s.a) == 0); s.n = v >> 7; s.v = (v >> 6) & 1
    def _asl(s,v): s.c = v >> 7; return s.nz(v << 1)
    def _lsr(s,v): s.c = v & 1; return s.nz(v >> 1)
    def _rol(s,v): r = (v << 1) | s.c; s.c = v >> 7; return s.nz(r)
    def _ror(s,v): r = (v >> 1) | (s.c << 7); s.c = v & 1; return s.nz(r)
    def o_ASL(s,a,m): s._rmw(a,m,s._asl)
    def o_LSR(s,a,m): s._rmw(a,m,s._lsr)
    def o_ROL(s,a,m): s._rmw(a,m,s._rol)
    def o_ROR(s,a,m): s._rmw(a,m,s._ror)
    def o_INC(s,a,m): s._rmw(a,m,lambda v: s.nz(v+1))
    def o_DEC(s,a,m): s._rmw(a,m,lambda v: s.nz(v-1))
    def o_SLO(s,a,m):
        def f(v): r = s._asl(v); s.a = s.nz(s.a | r); return r
        s._rmw(a,m,f)
    def o_RLA(s,a,m):
        def f(v): r = s._rol(v); s.a = s.nz(s.a & r); return r
        s._rmw(a,m,f)
    def o_SRE(s,a,m):
        def f(v): r = s._lsr(v); s.a = s.nz(s.a ^ r); return r
        s._rmw(a,m,f)
    def o_RRA(s,a,m):
        def f(v): r = s._ror(v); s.adc(r); return r
        s._rmw(a,m,f)
    def o_DCP(s,a,m):
        def f(v): r = (v-1) & 0xff; s.cmp(s.a, r); return r
        s._rmw(a,m,f)
    def o_ISC(s,a,m):
        def f(v): r = (v+1) & 0xff; s.sbc(r); return r
        s._rmw(a,m,f)
    def o_ANC(s,a,m): s.a = s.nz(s.a & s.read(a)); s.c = s.n
    def o_ALR(s,a,m): s.a = s._lsr(s.a & s.read(a))
    def o_ARR(s,a,m):
        t = s.a & s.read(a); s.a = s.nz((t >> 1) | (s.c << 7))
        s.c = (s.a >> 6) & 1; s.v = ((s.a >> 6) ^ (s.a >> 5)) & 1
    def o_SBX(s,a,m):
        t = (s.a & s.x) - s.read(a); s.c = int(t >= 0); s.x = s.nz(t)
    def o_NOP(s,a,m): pass
    def o_JAM(s,a,m): s.pc = (s.pc-1) & 0xffff; raise RuntimeError('JAM at %04X' % s.pc)
    def _br(s,cond,a):
        if cond:
            s.cycles += 1 + (((s.pc ^ a) & 0xff00) != 0); s.pc = a
    def o_BPL(s,a,m): s._br(not s.n,a)
    def o_BMI(s,a,m): s._br(s.n,a)
    def o_BVC(s,a,m): s._br(not s.v,a)
    def o_BVS(s,a,m): s._br(s.v,a)
    def o_BCC(s,a,m): s._br(not s.c,a)
    def o_BCS(s,a,m): s._br(s.c,a)
    def o_BNE(s,a,m): s._br(not s.z,a)
    def o_BEQ(s,a,m): s._br(s.z,a)
    def o_CLC(s,a,m): s.c = 0
    def o_SEC(s,a,m): s.c = 1
    def o_CLI(s,a,m): s.i = 0
    def o_SEI(s,a,m): s.i = 1
    def o_CLV(s,a,m): s.v = 0
    def o_CLD(s,a,m): s.d = 0
    def o_SED(s,a,m): s.d = 1
    def o_PHA(s,a,m): s.push(s.a)
    def o_PHP(s,a,m): s.push(s.p() | 0x10)
    def o_PLA(s,a,m): s.a = s.nz(s.pull())
    def o_PLP(s,a,m): s.setp(s.pull())
    def o_JMP(s,a,m): s.pc = a
    def o_JSR(s,a,m):
        r = (s.pc-1) & 0xffff; s.push(r >> 8); s.push(r); s.pc = a
    def o_RTS(s,a,m): s.pc = ((s.pull() | s.pull() << 8) + 1) & 0xffff
    def o_RTI(s,a,m): s.setp(s.pull()); s.pc = s.pull() | s.pull() << 8
    def o_BRK(s,a,m): s.pc = (s.pc+1) & 0xffff; s.irq(0xfffe, True)
