import sys, pickle; sys.path.insert(0,'/home/claude/work')
from c64 import C64
from cpu import disasm
c0,_=pickle.load(open('after_boot_mem.pkl','rb'))
res=c0[0x200:0x400]
out={}
for side in 'abc':
    o=pickle.load(open('harvest_%s.pkl'%side,'rb'))
    for i,(lo,data,n,h) in o.items():
        m=C64(); m.p01=0x34
        m.ram[0x200:0x400]=res
        m.ram[lo:lo+n]=data
        m.ram[0xf0]=lo&255; m.ram[0xf1]=lo>>8
        before=bytes(m.ram)
        cp=m.cpu; cp.s=0xf0; cp.push(0xff); cp.push(0xf7); cp.pc=0x02cc; cp.i=1
        try:
            r=m.run(stop=lambda m: m.cpu.pc==0xfff8, maxsteps=5_000_000)
        except Exception as e:
            r=('err',str(e))
        ch=[a for a in range(0x400,0x10000) if m.ram[a]!=before[a]]
        if ch: rng=(min(ch),max(ch))
        else: rng=None
        ok = r[0]=='stop'
        out[(side,i)]=(ok, rng, bytes(m.ram[rng[0]:rng[1]+1]) if rng and ok else None)
        print(side,i,'%04x+%04x'%(lo,n), r, ('%04x-%04x'%rng) if rng else None)
pickle.dump(out,open('depacked.pkl','wb'))
