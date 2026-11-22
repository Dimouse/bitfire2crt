import sys
SPT=[21]*17+[19]*7+[18]*6+[17]*10
def off(t,s): return (sum(SPT[:t-1])+s)*256
class D64:
    def __init__(s,fn): s.d=open(fn,'rb').read()
    def sec(s,t,sc): o=off(t,sc); return s.d[o:o+256]
    def dir(s):
        t,sc=18,1; out=[]
        while t:
            b=s.sec(t,sc)
            for i in range(8):
                e=b[i*32:i*32+32]
                if e[2]: out.append((e[2],e[3],e[4],e[5:21].rstrip(b'\xa0'),e[30]|e[31]<<8))
            t,sc=b[0],b[1]
        return out
    def file(s,t,sc):
        r=b''; ch=[]
        while t:
            b=s.sec(t,sc); ch.append((t,sc))
            if b[0]: r+=b[2:]
            else: r+=b[2:b[1]+1]
            t,sc=b[0],b[1]
        return r,ch
if __name__=='__main__':
    for fn in sys.argv[1:]:
        d=D64(fn); bam=d.sec(18,0)
        print(fn, bam[0x90:0xa0], bam[0xa2:0xa4])
        for e in d.dir():
            data,ch=d.file(e[1],e[2])
            print(' %02x %-16s blk=%3d start=%2d/%2d len=%d load=%04x'%(e[0],e[3],e[4],e[1],e[2],len(data),data[0]|data[1]<<8 if len(data)>1 else 0))
