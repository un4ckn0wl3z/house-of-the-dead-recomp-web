# dis.py <pe> <hexaddr> [count]  -- disassemble at a (preferred-base) address
import sys, pefile, capstone
pe = pefile.PE(sys.argv[1]); img = pe.get_memory_mapped_image(); base = pe.OPTIONAL_HEADER.ImageBase
a = int(sys.argv[2], 16); n = int(sys.argv[3]) if len(sys.argv) > 3 else 30
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
for i, ins in enumerate(md.disasm(img[a - base:a - base + n * 16], a)):
    if i >= n: break
    print("%08x  %-24s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
