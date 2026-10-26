import json, sys, collections, pefile, capstone
pe = pefile.PE(sys.argv[1])
img = pe.get_memory_mapped_image()
base = pe.OPTIONAL_HEADER.ImageBase
d = json.load(open(sys.argv[2]))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail = True
h = collections.Counter(); ex = {}
for ea in d['code_heads']:
    off = ea - base
    ins = next(md.disasm(img[off:off+16], ea), None)
    if ins is None: h['<bad>'] += 1; continue
    key = ins.mnemonic
    h[key] += 1; ex.setdefault(key, "%x %s %s" % (ea, ins.mnemonic, ins.op_str))
for k, v in sorted(h.items(), key=lambda x: -x[1]): print("%-12s %7d   %s" % (k, v, ex[k]))
