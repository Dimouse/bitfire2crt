import sys, pickle, random; sys.path.insert(0,'/home/claude/work')
import build_crt
from ef64 import EF64
from c64 import C64
from cpu import disasm
random.seed(int(sys.argv[1]) if len(sys.argv)>1 else 1)
r=build_crt.build('/home/claude/work/test.crt'); rom=r['rom']
m=EF64(rom)
def rts(mm):
    cp=mm.cpu; cp.pc=((cp.pull()|cp.pull()<<8)+1)&0xffff
for a in (0xff84,0xff87,0xff8a,0xff81): m.traps[a]=rts
m.cpu.pc=0xff00
m.run(stop=lambda mm: mm.cpu.pc==0x0e00, maxsteps=30_000_000)
c_ref,_=pickle.load(open('after_boot_mem.pkl','rb'))
res_orig=bytes(c_ref[0x200:0x400])
H={s:pickle.load(open('harvest_%s.pkl'%s,'rb')) for s in 'abc'}
# test interrupt handlers in page 1
m.ram[0x0120:0x0126]=bytes([0xee,0x40,0x01,0x40, 0,0])   # NMI: INC $0140; RTI
m.ram[0x0128:0x012e]=bytes([0xee,0x41,0x01,0x40, 0,0])   # IRQ: INC $0141; RTI
stats={'nmi':0,'nmi_in_window':0,'irq':0,'bad_irq':0}
def hook(mm):
    cp=mm.cpu
    if not active[0]: return
    if mm.ram[0xfffa:0xfffc]!=b'\x20\x01' or mm.ram[0xfffe:0x10000]!=b'\x28\x01': return
    if not (0xdf00<=cp.pc<0xe000 or 0x231<=cp.pc<0x290): return
    if random.random()<0.004:
        if mm.p01==0x37: stats['nmi_in_window']+=1
        stats['nmi']+=1; cp.irq(0xfffa)
    elif cp.i==0 and random.random()<0.004:
        if mm.p01 & 2: stats['bad_irq']+=1
        stats['irq']+=1; cp.irq(0xfffe)
m.nmi_hook=hook
active=[False]
def call(pc,a=0,p01=0x35):
    cp=m.cpu; cp.s=0xf0; cp.push(0xff); cp.push(0xf7); cp.pc=pc; cp.a=a; cp.i=0
    m.p01=p01
    m.ram[0xfffa]=0x20; m.ram[0xfffb]=0x01; m.ram[0xfffe]=0x28; m.ram[0xffff]=0x01
    return m.run(stop=lambda mm: mm.cpu.pc==0xfff8, maxsteps=40_000_000)
def ref_depack(before, side, i):
    lo,data,n,h=H[side][i]
    x=C64(); x.p01=0x34 if (side,i) in IOF else 0x35; x.ram[:]=before; x.ram[0x200:0x400]=res_orig
    x.ram[lo:lo+n]=data[:n]; x.ram[0xf0]=lo&255; x.ram[0xf1]=lo>>8
    cp=x.cpu; cp.s=0xf0; cp.push(0xff); cp.push(0xf7); cp.pc=0x02cc; cp.i=1
    x.run(stop=lambda mm: mm.cpu.pc==0xfff8, maxsteps=40_000_000)
    return x.ram
IOF={('a',6),('a',15),('a',49),('a',60),('a',71),('b',20),('b',41),('b',46),('b',51),('c',3),('c',9),('c',15),('c',24),('c',29),('c',31),('c',36)}
seq=[('a',i) for i in range(1,73)]+[('F',0xf1)]+[('b',i) for i in range(56)]+[('F',0xf2)]+[('c',i) for i in range(54)]
bad=0; mode=sys.argv[2] if len(sys.argv)>2 else 'comp'
for k,(side,i) in enumerate(seq):
    if side=='F':
        call(0x020c,i); continue
    before=bytes(m.ram)
    active[0]=True
    if mode=='raw' or (mode=='mix' and k%3==0) or (side,i) in IOF:
        call(0x0224)                    # load_next_raw
        active[0]=False
        call(0x02cc, p01=0x34 if (side,i) in IOF else 0x35)   # decomp
    else:
        try:
            call(0x02d2)                    # load_next_comp
        except Exception as e:
            cp=m.cpu
            print('EXC',side,i,e,hex(cp.pc),hex(m.p01),m.mode(),'S=%02x'%cp.s, m.ram[0x100+cp.s+1:0x100+cp.s+12].hex(), 'H', '%04x+%04x'%(H[side][i][0],H[side][i][2]), stats)
            raise
    active[0]=False
    exp=ref_depack(before, side, i)
    d=[a for a in range(0x0400,0x10000) if exp[a]!=m.ram[a] and not 0xd000<=a<0xe000 and not 0x120<=a<0x150 and a<0xfffa]
    if d: bad+=1; print('MISMATCH',side,i,len(d),hex(d[0]))
print('done bad=',bad, stats, 'nmi count ram', m.ram[0x140], 'irq', m.ram[0x141], 'cycles', m.cpu.cycles)
print('resident intact:', bytes(m.ram[0x300:0x320])==res_orig[0x100:0x120], 'efctl', hex(m.efctl))
