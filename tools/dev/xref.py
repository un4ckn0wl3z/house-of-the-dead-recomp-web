import sys,struct,pefile
pe=pefile.PE(__import__('os').environ.get('HOTD_EXE','../THOTD.EXE')); img=pe.get_memory_mapped_image(); B=0x400000
T0,T1=0x410000,0x597000
for t in [int(x,16) for x in sys.argv[1:]]:
    hits=[]
    for o in range(T0-B,T1-B-5):
        if img[o] in (0xE8,0xE9) and (o+B+5+struct.unpack_from('<i',img,o+1)[0])&0xffffffff==t: hits.append(('rel',hex(o+B)))
    v=struct.pack('<I',t); i=img.find(v)
    while i>=0: hits.append(('abs',hex(i+B))); i=img.find(v,i+1)
    print(hex(t),hits[:10])
