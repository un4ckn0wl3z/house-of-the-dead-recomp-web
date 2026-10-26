# Instruction histogram over several modules, flagging mnemonics recomp.py has no semantic for.
# Usage: python histo_all.py <bin_dir> <export_dir> mod1 mod2 ...
import json, sys, collections, re, os, pefile, capstone
bdir, edir, mods = sys.argv[1], sys.argv[2], sys.argv[3:]
src = open(os.path.join(os.path.dirname(__file__), 'recomp.py')).read()
known = set(re.findall(r'def i_(\w+)\(', src))
known |= set(re.findall(r"'i_' \+ (\w+)", src))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
tot = collections.Counter(); per = collections.defaultdict(collections.Counter); ex = {}
for m in mods:
    pe = pefile.PE(os.path.join(bdir, m))
    img = pe.get_memory_mapped_image(); base = pe.OPTIONAL_HEADER.ImageBase
    d = json.load(open(os.path.join(edir, os.path.splitext(m)[0] + '.export.json')))
    for ea in d['code_heads']:
        ins = next(md.disasm(img[ea - base:ea - base + 16], ea), None)
        k = ins.mnemonic if ins else '<bad>'
        tot[k] += 1; per[k][m] += 1
        ex.setdefault(k, "%s:%x %s %s" % (m, ea, k, ins.op_str if ins else ''))
print("total instructions:", sum(tot.values()))
for k, v in sorted(tot.items(), key=lambda x: -x[1]):
    flag = '' if k in known else '  <-- no i_%s' % k
    print("%-12s %8d  %-40s %s%s" % (k, v, ex[k][:40], dict(per[k].most_common(3)), flag))
