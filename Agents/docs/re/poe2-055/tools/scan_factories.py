import struct, bisect, re
EXE='PathOfExile.exe'
data=open(EXE,'rb').read()
pe=struct.unpack_from('<I',data,0x3c)[0]
nsec=struct.unpack_from('<H',data,pe+6)[0]
opt=struct.unpack_from('<H',data,pe+20)[0]
base=struct.unpack_from('<Q',data,pe+24+24)[0]
soff=pe+24+opt
secs={}
for i in range(nsec):
    o=soff+i*40
    name=data[o:o+8].rstrip(b'\0').decode()
    vs,va,rs,ra=struct.unpack_from('<IIII',data,o+8)
    secs[name]=(base+va,ra,rs)
tva,tra,tsz=secs['.text']
pva,pra,psz=secs['.pdata']
funcs=[]
for o in range(pra,pra+psz,12):
    b,e,_=struct.unpack_from('<III',data,o)
    if b and e and b<e: funcs.append((base+b,base+e))
funcs.sort(); starts=[f[0] for f in funcs]
def fo(va):
    i=bisect.bisect_right(starts,va)-1
    return funcs[i] if i>=0 and funcs[i][0]<=va<funcs[i][1] else None
blob=data[tra:tra+tsz]
# mov word ptr [rax+8], imm16  == 66 C7 40 08 xx xx ; also [rax+0x8] variants with other regs: 66 C7 4x 08
pat=re.compile(rb'\x66\xc7[\x40-\x47]\x08(..)',re.S)
from collections import defaultdict
byfunc=defaultdict(list)
for m in pat.finditer(blob):
    va=tva+m.start()
    f=fo(va)
    if f: byfunc[f].append((va,struct.unpack('<H',m.group(1))[0]))
for f,cases in sorted(byfunc.items(), key=lambda kv:-len(kv[1])):
    if len(cases)>=8:
        print(f'factory? func {f[0]:#x}..{f[1]:#x} cases={len(cases)}')
        for va,imm in sorted(cases, key=lambda x:x[1]):
            print(f'   id {imm:#06x} at {va:#x}')
