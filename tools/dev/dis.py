import sys,pefile,capstone
pe=pefile.PE(__import__('os').environ.get('HOTD_EXE','../THOTD.EXE')); img=pe.get_memory_mapped_image(); B=0x400000
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
a=int(sys.argv[1],16); n=int(sys.argv[2]) if len(sys.argv)>2 else 20
for i in md.disasm(bytes(img[a-B:a-B+n*8]),a):
    print('%x  %-20s %s %s'%(i.address,i.bytes.hex(),i.mnemonic,i.op_str)); n-=1
    if n<=0: break
