# List instructions that reference an absolute address (memory operand or immediate), with their functions.
# Usage: python tools/dev/refs.py c64cdc [more addresses]   (HOTD_EXE = path of THOTD.EXE)
import json, os, sys, bisect, pefile, capstone
pe = pefile.PE(os.environ.get('HOTD_EXE', '../THOTD.EXE'))
img = pe.get_memory_mapped_image(); B = pe.OPTIONAL_HEADER.ImageBase
d = json.load(open('build/analysis/export.json'))
starts = sorted(f['start'] for f in d['funcs'])
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail = True
want = set(int(a, 16) for a in sys.argv[1:])
for h in d['code_heads']:
    o = h - B
    ins = next(md.disasm(bytes(img[o:o + 16]), h), None)
    if not ins: continue
    hit = False
    for op in ins.operands:
        if op.type == capstone.x86_const.X86_OP_MEM and (op.mem.disp & 0xffffffff) in want: hit = True
        if op.type == capstone.x86_const.X86_OP_IMM and (op.imm & 0xffffffff) in want: hit = True
    if hit:
        f = starts[bisect.bisect_right(starts, h) - 1]
        print('%x  [f %x]  %s %s' % (h, f, ins.mnemonic, ins.op_str))
