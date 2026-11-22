import sys, pickle; sys.path.insert(0,'/home/claude/work')
from c64 import C64
from cpu import disasm
m=C64(); m.load_prg(open('boot_a.prg','rb').read()); m.ram[0xba]=8
init=bytes(m.ram)
m.cpu.s=0xf6
writes=set()
ow=m.write
def w(a,v):
    writes.add(a&0xffff); ow(a,v)
m.write=w; m.cpu.write=w
r=m.run(0x80d, stop=lambda m: m.cpu.pc==0x8a00)
print(r, m.cpu.s, hex(m.p01), m.cpu.i)
ws=sorted(writes)
# ranges
rs=[]; s=ws[0]; p=s
for a in ws[1:]:
    if a!=p+1: rs.append((s,p)); s=a
    p=a
rs.append((s,p))
print([('%04x-%04x'%r) for r in rs if r[1]-r[0]>4 or r[0]<0x400])
pickle.dump(bytes(m.ram),open('dec_mem.pkl','wb'))
print(disasm(m.ram,0x8b73,40))
