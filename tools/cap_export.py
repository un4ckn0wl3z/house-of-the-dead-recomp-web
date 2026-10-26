# Capstone-based replacement for ida_export.py (IDA Free has no IDAPython).
# Recursive descent from the entry point, the export table and every relocated pointer into code, with
# Watcom-style jump tables (jmp [reg*4+table], tables inside the code segment) resolved from .reloc.
# Usage: python cap_export.py THOTD.EXE ida_export.json
import json, sys, struct, bisect
import pefile, capstone
from capstone import x86_const as X

EXE, OUT = sys.argv[1], sys.argv[2]
pe = pefile.PE(EXE)
IMG = pe.get_memory_mapped_image()
BASE = pe.OPTIONAL_HEADER.ImageBase
CODE_SECT = [s for s in pe.sections if s.Characteristics & 0x20000000][0]
TLO = BASE + CODE_SECT.VirtualAddress
THI = TLO + max(CODE_SECT.Misc_VirtualSize, CODE_SECT.SizeOfRawData)

def rd32(a): return struct.unpack_from('<I', IMG, a - BASE)[0]
def in_text(a): return TLO <= a < THI

RELOCS = {}
for blk in pe.DIRECTORY_ENTRY_BASERELOC:
    for e in blk.entries:
        if e.type == 3: RELOCS[BASE + e.rva] = rd32(BASE + e.rva)

IMPORTS = {}
for d in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in d.imports:
        IMPORTS[imp.address] = [d.dll.decode(), imp.name.decode() if imp.name else '#%d' % imp.ordinal]
NAMES = {}
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if e.name: NAMES[BASE + e.address] = e.name.decode()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
_dc = {}
def decode(a):
    if a in _dc: return _dc[a]
    o = a - BASE
    ins = next(md.disasm(bytes(IMG[o:o + 16]), a), None) if in_text(a) else None
    _dc[a] = ins
    return ins

DATA_IN_TEXT = set()       # byte addresses of jump tables
HEADS = {}                 # head -> size
SWITCHES = {}
FUNCS = set()
problems = []

def bad(ins):
    if ins is None: return True
    b = bytes(ins.bytes)
    if ins.mnemonic in ('int3', 'hlt', 'in', 'out', 'insb', 'insd', 'outsb', 'outsd', 'arpl', 'bound', 'into',
                        'les', 'lds', 'retf', 'iretd', 'sti', 'cli'): return True
    if b[:2] == b'\x00\x00': return True
    return any(a in DATA_IN_TEXT for a in range(ins.address, ins.address + ins.size))

def read_table(ins, op):
    """jmp [idx*4 + table]: entries are consecutive relocated dwords pointing into code."""
    t = op.mem.disp & 0xffffffff
    if not in_text(t) and not (BASE <= t < BASE + len(IMG)): return None
    out, a = [], t
    while a in RELOCS and in_text(RELOCS[a]) and (a == t or a not in HEADS) and len(out) < 4096:
        out.append(RELOCS[a]); a += 4
    if not out: return None
    if in_text(t):
        DATA_IN_TEXT.update(range(t, a))
    return out

def explore(start, newfuncs):
    st = [start]
    while st:
        a = st.pop()
        while True:
            if a in HEADS or not in_text(a): break
            ins = decode(a)
            if bad(ins):
                if a != start: problems.append('flow into bad code at %x (from func %x)' % (a, start))
                break
            HEADS[a] = ins.size
            m = ins.mnemonic
            nxt = a + ins.size
            # relocated immediates/displacements pointing into code: function pointers
            for s in range(a + 1, nxt - 3):
                if s in RELOCS and in_text(RELOCS[s]) and m not in ('jmp',):
                    newfuncs.add(('imm', RELOCS[s]))
            if m in ('ret', 'retf'): break
            if m == 'call':
                op = ins.operands[0]
                if op.type == X.X86_OP_IMM: newfuncs.add(op.imm & 0xffffffff)
                a = nxt; continue
            if m == 'jmp':
                op = ins.operands[0]
                if op.type == X.X86_OP_IMM:
                    a = op.imm & 0xffffffff; continue
                if op.type == X.X86_OP_MEM and in_text(op.mem.disp & 0xffffffff) and \
                        ((op.mem.index and op.mem.scale == 4 and op.mem.base == 0) or
                         (op.mem.base and not op.mem.index)):
                    tg = read_table(ins, op)
                    if tg:
                        SWITCHES[a] = {'targets': sorted(set(tg)), 'jumps': op.mem.disp & 0xffffffff,
                                       'ncases': len(tg), 'elbase': 0}
                        st.extend(tg)
                    else:
                        problems.append('unresolved table jump at %x' % a)
                elif not (op.type == X.X86_OP_MEM and (op.mem.disp & 0xffffffff) in IMPORTS):
                    problems.append('indirect jmp at %x: %s %s' % (a, m, ins.op_str))
                break
            if m.startswith('j') or m.startswith('loop') or m == 'jecxz':
                op = ins.operands[0]
                if op.type == X.X86_OP_IMM: st.append(op.imm & 0xffffffff)
            a = nxt

def plausible(t):
    """Data pointer into code: accept if the first few instructions decode cleanly."""
    a = t
    for _ in range(64):
        ins = decode(a)
        if bad(ins) or ins.mnemonic in ('les', 'lds') or (ins.mnemonic == 'add' and ins.bytes[0] in (0, 2)):
            return False
        if ins.mnemonic in ('ret', 'jmp'): return True
        a += ins.size
    return True

seeds = {BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint} | set(NAMES)
# pass 1: jump tables can only be identified while exploring, so exploring code first keeps table entries
# (case labels) out of the function seeds. Data pointers from outside the code segment come next.
pending = set(seeds)
data_ptrs = sorted(v for s, v in RELOCS.items() if not in_text(s) and in_text(v))
rounds = 0
while True:
    rounds += 1
    while pending:
        f = pending.pop()
        if f in FUNCS or not in_text(f): continue
        if f in HEADS and f not in FUNCS:
            FUNCS.add(f); continue          # already reached as code inside another function: still an entry
        FUNCS.add(f)
        nf = set()
        explore(f, nf)
        for x in nf:
            if isinstance(x, tuple):
                if x[1] not in FUNCS and x[1] not in DATA_IN_TEXT and plausible(x[1]): pending.add(x[1])
            elif x not in FUNCS: pending.add(x)
    if data_ptrs:
        for v in data_ptrs:
            if v not in FUNCS and v not in DATA_IN_TEXT and plausible(v): pending.add(v)
        data_ptrs = []
        continue
    # leftover relocated code-segment words not inside any table or instruction: callback tables in code
    extra = set()
    covered = set()
    for h, sz in HEADS.items(): covered.update(range(h, h + sz))
    for s, v in RELOCS.items():
        if in_text(s) and in_text(v) and s not in covered and s not in DATA_IN_TEXT and v not in FUNCS \
                and v not in DATA_IN_TEXT and plausible(v):
            extra.add(v)
    if not extra or rounds > 6: break
    pending |= extra

# switch targets that were seeded as functions from immediates (case labels) stay as entries; harmless.
# function bodies -> chunks
fs = sorted(FUNCS)
heads_sorted = sorted(HEADS)
funcs_out = []
for f in fs:
    body, st = set(), [f]
    while st:
        a = st.pop()
        while a in HEADS and a not in body:
            if a != f and a in FUNCS: break
            body.add(a)
            ins = decode(a); m = ins.mnemonic; nxt = a + ins.size
            if m in ('ret', 'retf'): break
            if m == 'jmp':
                op = ins.operands[0]
                if op.type == X.X86_OP_IMM:
                    t = op.imm & 0xffffffff
                    if t in FUNCS: break
                    a = t; continue
                if a in SWITCHES: st.extend(SWITCHES[a]['targets'])
                break
            if m.startswith('j') or m.startswith('loop') or m == 'jecxz':
                op = ins.operands[0]
                if op.type == X.X86_OP_IMM: st.append(op.imm & 0xffffffff)
            a = nxt
    chunks = []
    for h in sorted(body):
        e = h + HEADS[h]
        if chunks and chunks[-1][1] == h: chunks[-1][1] = e
        else: chunks.append([h, e])
    if not chunks: chunks = [[f, f + HEADS.get(f, 1)]]
    funcs_out.append({'start': f, 'end': max(c[1] for c in chunks), 'name': NAMES.get(f, 'sub_%X' % f),
                      'flags': 0, 'chunks': chunks, 'frsize': 0, 'argsize': 0})

segs = []
for s in pe.sections:
    nm = s.Name.rstrip(b'\0').decode()
    lo = BASE + s.VirtualAddress
    hi = lo + max(s.Misc_VirtualSize, s.SizeOfRawData)
    if s is CODE_SECT: nm = '.text'
    elif nm == 'DGROUP': nm = 'DGROUP'  # recomp.py would scan .data for code-like words; relocs already did that
    segs.append({'start': lo, 'end': hi, 'name': nm, 'perm': 5 if s is CODE_SECT else 6})
segs.sort(key=lambda x: x['start'])
out = {'funcs': funcs_out, 'switches': SWITCHES, 'names': NAMES, 'imports': IMPORTS,
       'segments': segs, 'code_heads': heads_sorted}
json.dump(out, open(OUT, 'w'))
with open(OUT + '.problems.txt', 'w') as fp:
    fp.write('\n'.join(problems) + '\n')
cov = sum(HEADS.values())
print('funcs %d heads %d switches %d code bytes %d / %d (%.1f%%) problems %d' % (
    len(FUNCS), len(HEADS), len(SWITCHES), cov, THI - TLO, 100.0 * cov / (THI - TLO), len(problems)))
