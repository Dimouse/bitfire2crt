import sys, time, pickle; sys.path.insert(0,'/home/claude/work')
from machine import Machine
from cpu import disasm
side=sys.argv[1]; nfiles=int(sys.argv[2])
M=Machine('/home/claude/in/demo/fairlight-1337-58679b69-a.d64')
orig=M.do_job
def job(d,slot,v):
    orig(d,slot,v); M.job_hook=None
M.job_hook=job
M.c.load_prg(open('boot_a.prg','rb').read()); M.c.cpu.s=0xf6; M.c.cpu.pc=0x80d; M.c.ram[0xba]=8
r=M.run(maxc=60_000_000, stop=lambda m: m.c.cpu.pc==0x0e00)
print('booted',r, M.d.ram[0x18])
c=M.c
def call(pc,a=0,maxc=200_000_000):
    cp=c.cpu; cp.s=0xf0
    cp.push(0xff); cp.push(0xf7); cp.pc=pc; cp.a=a; cp.i=1
    blocks=[]; hdrs=[]
    def stop(m):
        p=m.c.cpu.pc
        if p==0x0271:
            ad=(c.ram[0x272]|c.ram[0x273]<<8)+cp.y
            blocks.append((ad&0xffff,cp.a))
        elif p==0x023c:
            hdrs.append(bytes(c.ram[0xf6:0xfb]))
        return p==0xfff8
    r=M.run(maxc=maxc, stop=stop)
    return r,blocks,hdrs
c.p01=0x35
out={}
if side!='a':
    M.d.setdisk('/home/claude/in/demo/fairlight-1337-58679b69-%s.d64'%side)
    r,b,h=call(0x020c, 0xf0+'abc'.index(side))
    # wait for drive to become idle
    r,b,h=call(0x0229)
    print('disk change',r,len(b), M.d.ram[0x18])
else:
    # file 0 was already loaded by boot; re-request file 0 explicitly
    pass
t=time.time()
for i in range(nfiles):
    r,b,h=call(0x020c, i)   # load file i by number
    r,b,h=call(0x0229)
    addrs=sorted(set(a for a,v in b))
    mem={}
    for a,v in b:
        if a>=0x100: mem[a]=v
    lo=min(mem); hi=max(mem)
    data=bytes(mem.get(x,0) for x in range(lo,hi+1))
    out[i]=(lo,data,len(mem),h); assert len(mem)==hi-lo+1
    print(i, r, '%04x-%04x n=%d blocks=%d'%(lo,hi,len(mem),len(h)), ' '.join(x.hex() for x in h[:3]), round(time.time()-t,1)); sys.stdout.flush()
pickle.dump(out,open('/home/claude/work/harvest_%s.pkl'%side,'wb'))
