import json,sys,pefile
pe=pefile.PE(__import__('os').environ.get('HOTD_EXE','../THOTD.EXE')); img=pe.get_memory_mapped_image(); B=0x400000
d=json.load(open('build/analysis/export.json'))
import capstone; md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
cov=bytearray(0x187000)
for h in d['code_heads']:
    ins=next(md.disasm(img[h-B:h-B+16],h)); 
    for i in range(ins.size): cov[h-0x410000+i]=1
gaps=[];s=None
for i in range(len(cov)+1):
    c=cov[i] if i<len(cov) else 1
    if not c and s is None: s=i
    if c and s is not None: gaps.append((s,i)); s=None
nz=lambda a,b: sum(1 for x in img[0x10000+a:0x10000+b] if x)
tot=sum(nz(a,b) for a,b in gaps); print('uncovered nonzero bytes',tot)
big=sorted(gaps,key=lambda g:-nz(*g))[:15]
for a,b in big: print(hex(0x410000+a),b-a,nz(a,b), img[0x10000+a:0x10000+a+16].hex())
