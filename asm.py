"""Tiny two-pass 6502 assembler.
Syntax: one statement per line; ';' comments; 'label:' ; '* = $addr' or '.org $addr';
.byte / .word ; 'name = expr' constants. Operands: #imm, zp/abs, ,x ,y, (zp,x), (zp),y, (abs).
Expressions: python-evaluated with $hex, %bin, <expr, >expr, labels; '*' = current pc.
Use '!zp' suffix not needed: zero page chosen when value < $100 and mode exists.
"""
import re, sys
sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
from cpu import OPS

CODE = {}
for c, (n, m, _) in OPS.items():
    key = (n, m)
    # prefer official opcodes (first defined); avoid illegal dup like SBC $EB
    if key not in CODE or c in (0xE9,):
        CODE[key] = c
CODE[('SBC', 'imm')] = 0xE9
CODE[('NOP', 'imp')] = 0xEA

BRANCH = {'BPL','BMI','BVC','BVS','BCC','BCS','BNE','BEQ'}

class Asm:
    def __init__(self):
        self.syms = {}
    def ev(self, e, pc, final):
        e = e.strip()
        def conv(t):
            t = re.sub(r'\$([0-9A-Fa-f]+)', lambda m: str(int(m.group(1), 16)), t)
            t = re.sub(r'%([01]+)', lambda m: str(int(m.group(1), 2)), t)
            return t
        lo = hi = False
        if e.startswith('<'): lo = True; e = e[1:]
        elif e.startswith('>'): hi = True; e = e[1:]
        e2 = conv(e)
        e2 = re.sub(r'(?<![\w])\*(?![\w*])', str(pc), e2)
        env = dict(self.syms)
        try:
            v = eval(e2, {'__builtins__': {}}, env)
        except NameError:
            if final: raise
            v = 0x1234
        v = int(v)
        if lo: v &= 0xff
        if hi: v = (v >> 8) & 0xff
        return v
    def assemble(self, src):
        for final in (False, True, True):
            self.out = {}
            pc = 0
            for ln, line in enumerate(src.split('\n')):
                line = line.split(';')[0].rstrip()
                if not line.strip(): continue
                m = re.match(r'^\s*([A-Za-z_][\w]*):(.*)$', line)
                if m:
                    lab = m.group(1); line = m.group(2)
                    if final and self.syms.get(lab) != pc and self._pass > 1:
                        raise Exception('phase error %s' % lab)
                    self.syms[lab] = pc
                    if not line.strip(): continue
                s = line.strip()
                m = re.match(r'^([A-Za-z_]\w*)\s*=\s*(.+)$', s)
                if m:
                    self.syms[m.group(1)] = self.ev(m.group(2), pc, final); continue
                m = re.match(r'^(\*\s*=|\.org)\s*(.+)$', s)
                if m:
                    pc = self.ev(m.group(2), pc, final); continue
                parts = s.split(None, 1)
                mn = parts[0].upper(); arg = parts[1].strip() if len(parts) > 1 else ''
                try:
                    pc = self.stmt(mn, arg, pc, final)
                except Exception as ex:
                    raise Exception('line %d: %s: %s' % (ln+1, line, ex))
            self._pass = getattr(self, '_pass', 0) + 1
        return self.out
    def emit(self, pc, bs):
        for b in bs:
            self.out[pc] = b & 0xff; pc += 1
        return pc
    def stmt(self, mn, arg, pc, final):
        if mn == '.BYTE':
            vals = []
            for a in split_args(arg):
                if a.startswith('"'):
                    vals += [ord(ch) for ch in a.strip('"')]
                else:
                    vals.append(self.ev(a, pc, final))
            return self.emit(pc, vals)
        if mn == '.WORD':
            vals = []
            for a in split_args(arg):
                v = self.ev(a, pc, final); vals += [v & 0xff, v >> 8 & 0xff]
            return self.emit(pc, vals)
        if mn == '.FILL':
            n, v = [self.ev(a, pc, final) for a in split_args(arg)]
            return self.emit(pc, [v]*n)
        if mn in BRANCH:
            t = self.ev(arg, pc, final); off = t - (pc + 2)
            if final and not -128 <= off <= 127: raise Exception('branch out of range')
            return self.emit(pc, [CODE[(mn, 'rel')], off & 0xff])
        if arg == '' :
            mode = 'imp' if (mn, 'imp') in CODE else 'acc'
            return self.emit(pc, [CODE[(mn, mode)]])
        if arg.upper() == 'A':
            return self.emit(pc, [CODE[(mn, 'acc')]])
        if arg.startswith('#'):
            return self.emit(pc, [CODE[(mn, 'imm')], self.ev(arg[1:], pc, final)])
        m = re.match(r'^\((.+),\s*[xX]\)$', arg)
        if m:
            return self.emit(pc, [CODE[(mn, 'izx')], self.ev(m.group(1), pc, final)])
        m = re.match(r'^\((.+)\),\s*[yY]$', arg)
        if m:
            return self.emit(pc, [CODE[(mn, 'izy')], self.ev(m.group(1), pc, final)])
        m = re.match(r'^\((.+)\)$', arg)
        if m:
            v = self.ev(m.group(1), pc, final)
            return self.emit(pc, [CODE[(mn, 'ind')], v & 0xff, v >> 8])
        idx = None
        m = re.match(r'^(.+),\s*([xXyY])$', arg)
        if m: arg = m.group(1); idx = m.group(2).lower()
        forceabs = arg.startswith('!')
        if forceabs: arg = arg[1:]
        v = self.ev(arg, pc, final)
        zm = {None: 'zp', 'x': 'zpx', 'y': 'zpy'}[idx]
        am = {None: 'abs', 'x': 'abx', 'y': 'aby'}[idx]
        if not forceabs and v < 0x100 and (mn, zm) in CODE:
            return self.emit(pc, [CODE[(mn, zm)], v])
        return self.emit(pc, [CODE[(mn, am)], v & 0xff, v >> 8 & 0xff])

def split_args(s):
    out = []; cur = ''; q = False
    for ch in s:
        if ch == '"': q = not q
        if ch == ',' and not q: out.append(cur.strip()); cur = ''
        else: cur += ch
    if cur.strip(): out.append(cur.strip())
    return out

def assemble(src, syms=None):
    a = Asm()
    if syms: a.syms.update(syms)
    out = a.assemble(src)
    return out, a.syms
