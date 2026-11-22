import struct
def load_crt(fn):
    d=open(fn,'rb').read()
    assert d[:16]==b'C64 CARTRIDGE   '
    hl=struct.unpack('>I',d[16:20])[0]; hw=struct.unpack('>H',d[22:24])[0]
    exrom,game=d[24],d[25]
    rom=bytearray(b'\xff'*(64*16384)); p=hl; chips=0
    while p<len(d):
        assert d[p:p+4]==b'CHIP', p
        plen,ctype,bank,la,sz=struct.unpack('>IHHHH',d[p+4:p+16])
        assert la in (0x8000,0xa000) and sz==0x2000 and plen==0x2010
        o=bank*16384+(la-0x8000); rom[o:o+sz]=d[p+16:p+16+sz]; p+=plen; chips+=1
    return rom, dict(hw=hw,exrom=exrom,game=game,chips=chips,name=d[32:64].rstrip(b'\0'))
if __name__=='__main__':
    import sys; r,i=load_crt(sys.argv[1]); print(i)
