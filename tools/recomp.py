# Static recompiler: x86 (MSVC6 PE32) -> C
# Usage: python recomp.py <exe> <ida_export.json> <outdir> [--config recomp_config.json]
#
# recomp_config.json (all keys optional):
#   {"hooks": {"0x405003": ["host_frame_loop", "0x405012"]},   # replace insn, resume address
#    "hle":   {"_memcpy": "hle_memcpy", "0x46b9ac": "hle_ftol"}, # IDA name or address -> host fn
#    "entries": ["0x412345"],                                   # extra function entry points
#    "wraps":  {"0x444a80": "host_find_target"}}                # direct calls go to a host function, which can
#                                                               # still call the original as f_444a80()
#
# Multi-module games (one exe + many DLLs, e.g. Unreal Engine 2): run once per module with --tag and --base.
# The image is rebased to --base with its .reloc table (the IDA database must be rebased to the same base, see
# tools/ida_rebase_export.py), all output symbols get the module tag, and --modules lets direct calls through the
# import table go straight to the recompiled export in another module. recomp_config.json then has an "all"
# section plus one section per tag:
#   {"all": {"import_hle": {"MSVCR70!_ftol": "hle_ftol"}}, "core": {"hooks": {...}, "hle": {...}}}
# EH: "unwind_jumps" lists indirect jmps that resume at a catch continuation (MSVC _JumpToContinuation). Every
# call site checks g_unwind afterwards; frames that own the continuation (found from the FuncInfo tables of
# __CxxFrameHandler) resume there, all others return (runtime.c: guest_unwind_jump).
import json, sys, os, struct, collections, argparse
import pefile, capstone
from capstone import x86_const as X

_ap = argparse.ArgumentParser()
_ap.add_argument('exe'); _ap.add_argument('export'); _ap.add_argument('out')
_ap.add_argument('--config', default=None)
_ap.add_argument('--tag', default='')
_ap.add_argument('--base', default=None)
_ap.add_argument('--modules', default=None, help='modules.json (layout.py) for cross-module direct calls')
_args = _ap.parse_args()
EXE, EXPORT, OUT = _args.exe, _args.export, _args.out
TAG = _args.tag
SFX = ('_' + TAG) if TAG else ''
_CFG = json.load(open(_args.config)) if _args.config else {}
if TAG or 'all' in _CFG:
    CFG = {}
    for sect in (_CFG.get('all', {}), _CFG.get(TAG, {})):
        for k, v in sect.items():
            if isinstance(v, dict): CFG.setdefault(k, {}).update(v)
            elif isinstance(v, list): CFG.setdefault(k, []).extend(v)
            else: CFG[k] = v
else:
    CFG = _CFG
pe = pefile.PE(EXE)
if _args.base is not None and int(_args.base, 0) != pe.OPTIONAL_HEADER.ImageBase:
    pe.relocate_image(int(_args.base, 0))
    pe.OPTIONAL_HEADER.ImageBase = int(_args.base, 0)
IMG = pe.get_memory_mapped_image()
BASE = pe.OPTIONAL_HEADER.ImageBase
D = json.load(open(EXPORT))
if D['segments'] and not (BASE <= D['segments'][0]['start'] < BASE + len(IMG)):
    sys.exit('export %s does not match image base %x (rebase the IDA database)' % (EXPORT, BASE))
CODE_HEADS = set(D['code_heads'])
# IDA folds 'wait' (9B) into the following x87 instruction; capstone splits them
for _h in list(CODE_HEADS):
    if IMG[_h - BASE] == 0x9B and 0xD8 <= IMG[_h - BASE + 1] <= 0xDF:
        CODE_HEADS.add(_h + 1)
NAMES = {int(k): v for k, v in D['names'].items()}
IMPORTS = {int(k): v for k, v in D['imports'].items()}
SWITCHES = {int(k): v for k, v in D['switches'].items()}
TEXT_START = min(s['start'] for s in D['segments'] if s['name'] == '.text')
TEXT_END = max(s['end'] for s in D['segments'] if s['name'] == '.text')

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def rd32(a):
    return struct.unpack_from('<I', IMG, a - BASE)[0]

# IDA sometimes leaves a few instructions inside a function undefined (e.g. after an indirect call). When control
# flow inside .text reaches such an address, decode it ourselves.
GAP_HEADS = set()
def flow_code(a):
    if a in CODE_HEADS: return True
    if not (TEXT_START <= a < TEXT_END): return False
    ins = decode(a)
    if ins is None or ins.mnemonic in ('int3', 'hlt') or (ins.bytes[0] == 0 and ins.bytes[1] == 0): return False
    CODE_HEADS.add(a); GAP_HEADS.add(a)
    return True

_dcache = {}
def decode(ea):
    if ea in _dcache: return _dcache[ea]
    off = ea - BASE
    ins = next(md.disasm(bytes(IMG[off:off + 16]), ea), None)
    _dcache[ea] = ins
    return ins

# --------------------------------------------------------------------------
# HLE overrides: guest address -> host function (cdecl helpers, see hle.c)
HLE_BY_NAME = {
    '__ftol': 'hle_ftol', '_floor': 'hle_floor', '_ceil': 'hle_ceil', '_pow': 'hle_pow',
    '__CIpow': 'hle_CIpow', '_acos': 'hle_acos', '__CIacos': 'hle_CIacos',
    '_ldexp': 'hle_ldexp', '_frexp': 'hle_frexp',
    '_memcpy': 'hle_memcpy', '_memcpy_0': 'hle_memcpy', '_memmove': 'hle_memcpy', '_memset': 'hle_memset', '_strlen': 'hle_strlen',
    '__setjmp3': 'hle_setjmp3', '_longjmp': 'hle_longjmp',
    '_asin': 'hle_asin', '__CIasin': 'hle_CIasin', '_sin': 'hle_sin', '__CIsin': 'hle_CIsin',
    '_cos': 'hle_cos', '__CIcos': 'hle_CIcos', '_tan': 'hle_tan', '__CItan': 'hle_CItan',
    '_exp': 'hle_exp', '__CIexp': 'hle_CIexp', '_sqrt': 'hle_sqrt', '__CIsqrt': 'hle_CIsqrt', '_modf': 'hle_modf',
}
# HOOKS: guest instruction address -> (host function, resume address)
HOOKS = {int(k, 0): (v[0], int(v[1], 0)) for k, v in CFG.get('hooks', {}).items()}
# WRAPS: guest function -> host function that direct calls (and tail calls) go to instead. The original body is
# still emitted as f_<address> and stays the target of indirect calls (use host_override() for those), so the host
# function can run it, e.g. several times with different state.
WRAPS = {int(k, 0): v for k, v in CFG.get('wraps', {}).items()}
for k, v in CFG.get('hle', {}).items():
    if k.startswith('0x'):
        pass
    else:
        HLE_BY_NAME[k] = v
HLE = {}
for f in D['funcs']:
    if f['name'] in HLE_BY_NAME:
        HLE[f['start']] = HLE_BY_NAME[f['name']]
for k, v in CFG.get('hle', {}).items():
    if k.startswith('0x'):
        HLE[int(k, 16)] = v

# --------------------------------------------------------------------------
# Imports: calls through the IAT go to a host function (import_hle, "DLL!name" with or without ".dll"), or straight
# to the recompiled export of another module (--modules), or through call_ind as a last resort.
def imp_key(mod, nm):
    m = mod.lower()
    if m.endswith('.dll'): m = m[:-4]
    if nm.startswith('__imp_'): nm = nm[6:]
    return m + '!' + nm
IMPORT_HLE = {}
for k, v in CFG.get('import_hle', {}).items():
    mod, nm = k.split('!', 1)
    IMPORT_HLE[imp_key(mod, nm)] = v
XEXP = {}        # imp_key -> guest address of the export (function exports in .text only)
if _args.modules:
    _sysdir = os.path.dirname(os.path.abspath(EXE))
    for m in json.load(open(_args.modules))['modules']:
        p2 = pefile.PE(os.path.join(_sysdir, m['file']), fast_load=True)
        p2.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        if not hasattr(p2, 'DIRECTORY_ENTRY_EXPORT'): continue
        texts = [(s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize) for s in p2.sections
                 if s.Characteristics & 0x20000000]
        mt = os.path.splitext(m['file'])[0]
        for e in p2.DIRECTORY_ENTRY_EXPORT.symbols:
            if e.forwarder or not any(lo <= e.address < hi for lo, hi in texts): continue
            a = m['base'] + e.address
            if e.name: XEXP[imp_key(mt, e.name.decode())] = a
            XEXP[imp_key(mt, '#%d' % e.ordinal)] = a
XFUNCS = set()   # other modules' functions called directly
def import_target(iat):
    mod, nm = IMPORTS[iat]
    k = imp_key(mod, nm)
    if k in IMPORT_HLE: return 'hle', IMPORT_HLE[k]
    if k in XEXP: return 'func', XEXP[k]
    return None, None

# --------------------------------------------------------------------------
# MSVC C++ EH: find FuncInfo tables (mov eax, FuncInfo; jmp __CxxFrameHandler), their catch and unwind funclets
# (which become entries, they are called through __CallSettingFrame) and the continuation addresses the catch
# funclets return. Each continuation belongs to the function that contains it.
UNWIND_JUMPS = set(int(x, 0) for x in CFG.get('unwind_jumps', []))
# call sites check g_unwind (the runtime must define it) in multi-module builds, or when the config asks for it
EH_UNWIND = bool(TAG) or bool(UNWIND_JUMPS) or bool(CFG.get('eh_unwind'))
EH_FUNCLETS = set()
EH_CONTS = set()
def _scan_eh():
    md0 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md0.detail = True
    def dec(a):
        o = a - BASE
        if not (0 <= o < len(IMG)): return None
        return next(md0.disasm(bytes(IMG[o:o + 16]), a), None)
    cxx_iat = set(a for a, (m, n) in IMPORTS.items() if n.lstrip('_') == 'CxxFrameHandler')
    cxx_fn = set(f['start'] for f in D['funcs'] if f['name'].lstrip('_') == 'CxxFrameHandler')
    heads = sorted(CODE_HEADS)
    for h in heads:
        ins = dec(h)
        if ins and ins.mnemonic == 'jmp' and ins.operands[0].type == X.X86_OP_MEM and \
                (ins.operands[0].mem.disp & 0xffffffff) in cxx_iat and ins.operands[0].mem.base == 0:
            cxx_fn.add(h)
    def is_cxx_jmp(ins):
        if ins is None or ins.mnemonic != 'jmp': return False
        op = ins.operands[0]
        if op.type == X.X86_OP_IMM: return (op.imm & 0xffffffff) in cxx_fn
        if op.type == X.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
            return (op.mem.disp & 0xffffffff) in cxx_iat
        return False
    infos = set()
    for h in heads:
        ins = dec(h)
        if ins is None or ins.mnemonic != 'mov' or len(ins.operands) != 2: continue
        if ins.operands[1].type != X.X86_OP_IMM or ins.reg_name(ins.operands[0].reg) != 'eax': continue
        if is_cxx_jmp(dec(h + ins.size)):
            infos.add(ins.operands[1].imm & 0xffffffff)
            EH_FUNCLETS.add(h)          # the frame's handler thunk, called by the SEH dispatcher
    def ok(a): return BASE <= a < BASE + len(IMG) - 4
    for fi in infos:
        if not ok(fi) or (rd32(fi) & 0xfffffff0) != 0x19930520: continue
        nstate, punw, ntry, ptry = rd32(fi + 4), rd32(fi + 8), rd32(fi + 12), rd32(fi + 16)
        for i in range(nstate if ok(punw) else 0):
            act = rd32(punw + 8 * i + 4)
            if TEXT_START <= act < TEXT_END: EH_FUNCLETS.add(act)
        for t in range(ntry if ok(ptry) else 0):
            e = ptry + 20 * t
            nc, ph = rd32(e + 12), rd32(e + 16)
            for c in range(nc if ok(ph) else 0):
                fa = rd32(ph + 16 * c + 12)
                if not (TEXT_START <= fa < TEXT_END): continue
                EH_FUNCLETS.add(fa)
                # follow the funclet to its ret(s), collecting 'mov eax, <code address>'
                st, vis = [fa], set()
                while st and len(vis) < 400:
                    a = st.pop()
                    if a in vis: continue
                    vis.add(a)
                    i2 = dec(a)
                    if i2 is None: continue
                    m = i2.mnemonic
                    if m == 'mov' and len(i2.operands) == 2 and i2.operands[1].type == X.X86_OP_IMM and \
                            i2.operands[0].type == X.X86_OP_REG and i2.reg_name(i2.operands[0].reg) == 'eax':
                        v = i2.operands[1].imm & 0xffffffff
                        if TEXT_START <= v < TEXT_END: EH_CONTS.add(v)
                    if m in ('ret', 'retf'): continue
                    if m == 'jmp':
                        t2 = i2.operands[0].imm & 0xffffffff if i2.operands[0].type == X.X86_OP_IMM else None
                        if t2 is not None: st.append(t2)
                        continue
                    if m.startswith('j'):
                        if i2.operands[0].type == X.X86_OP_IMM: st.append(i2.operands[0].imm & 0xffffffff)
                    st.append(a + i2.size)
    print('EH: %d FuncInfo tables, %d funclets, %d continuations' % (len(infos), len(EH_FUNCLETS), len(EH_CONTS)), file=sys.stderr)
_scan_eh()
CODE_HEADS |= EH_CONTS | EH_FUNCLETS
HLE_USED = set()
# import thunks (jmp [iat]) of host-implemented imports are host functions too, so calls to them get the same
# special treatment (_setjmp3 needs the host setjmp in the caller's frame)
for f in D['funcs']:
    o = f['start'] - BASE
    if bytes(IMG[o:o + 2]) == b'\xff\x25':
        iat = struct.unpack_from('<I', IMG, o + 2)[0]
        if iat in IMPORTS and import_target(iat)[0] == 'hle' and f['start'] not in HLE:
            HLE[f['start']] = import_target(iat)[1]

# --------------------------------------------------------------------------
# Entry points
entries = set(f['start'] for f in D['funcs'])
entries |= set(int(x, 0) for x in CFG.get('entries', []))
entries |= EH_FUNCLETS
soft = set()
# orphan code groups (code heads not inside any IDA function)
import bisect
_ivo = sorted((a, b, f['start']) for f in D['funcs'] for a, b in f['chunks'])
iv = [(a, b) for a, b, _ in _ivo]
iv_owner = [s for _, _, s in _ivo]
ivs = [a for a, b in iv]
def in_func(h):
    i = bisect.bisect_right(ivs, h) - 1
    return i >= 0 and iv[i][0] <= h < iv[i][1]
prev = None
for h in sorted(CODE_HEADS):
    if not in_func(h):
        pins = decode(prev) if prev is not None else None
        if prev is None or h - prev >= 16 or not (prev in CODE_HEADS) or                 (pins is not None and pins.mnemonic in ('jmp', 'ret', 'retf', 'int3')):
            soft.add(h)
        prev = h
    else:
        prev = None
# data words pointing to code heads that start functions (vtables etc.) are already entries.
switch_targets = set()
for s in SWITCHES.values():
    switch_targets.update(s['targets'])
extra_ptrs = set()
for seg in D['segments']:
    if seg['name'] in ('.rdata', '.data'):
        a = seg['start']
        while a + 4 <= min(seg['end'], BASE + len(IMG)):
            v = rd32(a)
            if v in CODE_HEADS and v not in entries and v not in switch_targets:
                extra_ptrs.add(v)
            a += 4
# these are possibly function pointers to code not recognized as functions
soft |= extra_ptrs
soft -= entries

# iterate: discover call targets
REGS32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

def is_import_mem(op):
    return (op.type == X.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0
            and (op.mem.segment == 0 or op.mem.segment in (X.X86_REG_CS, X.X86_REG_DS)) and (op.mem.disp & 0xffffffff) in IMPORTS)

def branch_target(ins):
    op = ins.operands[0]
    if op.type == X.X86_OP_IMM:
        return op.imm & 0xffffffff
    return None

work = list(entries | soft)
seen_calls = set()
while work:
    ea = work.pop()
    # linear scan of function body done later; here just find call targets
    stack = [ea]; vis = set()
    while stack:
        a = stack.pop()
        if a in vis or not flow_code(a): continue
        vis.add(a)
        ins = decode(a)
        if ins is None: continue
        m = ins.mnemonic
        nxt = a + ins.size
        if m == 'call':
            t = branch_target(ins)
            if t is not None and t in CODE_HEADS and t not in entries:
                entries.add(t); work.append(t)
            stack.append(nxt)
        elif m == 'ret' or m == 'retf':
            pass
        elif m == 'jmp':
            t = branch_target(ins)
            if t is not None:
                if t not in entries: stack.append(t)
            elif a in SWITCHES:
                stack.extend(SWITCHES[a]['targets'])
        elif m.startswith('j') or m in ('loop', 'jecxz'):
            t = branch_target(ins)
            stack.append(nxt)
            if t is not None and t not in entries: stack.append(t)
        else:
            if nxt not in entries: stack.append(nxt)

soft -= entries
ENTRY_SET = set(entries)          # hard entries: function boundaries
ENTRIES = sorted(entries | soft)  # everything gets a host function
# continuation address -> the function (IDA function start) whose body resumes there
CONTS_BY_OWNER = collections.defaultdict(set)
for _c in sorted(EH_CONTS):
    _i = bisect.bisect_right(ivs, _c) - 1
    _owner = None
    if _i >= 0 and iv[_i][0] <= _c < iv[_i][1]:
        _owner = iv_owner[_i]
    if _owner is None or _owner not in ENTRY_SET:
        print('EH: continuation %x has no owning function' % _c, file=sys.stderr)
        continue
    CONTS_BY_OWNER[_owner].add(_c)
print("entries:", len(ENTRIES), "extra data ptrs:", len(extra_ptrs), "gap instructions decoded:", len(GAP_HEADS), file=sys.stderr)

# --------------------------------------------------------------------------
# Register helpers
REG_INFO = {}
for i, r in enumerate(REGS32):
    REG_INFO[r] = (r, 0, 32)
for r16, r32 in zip(['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di'], REGS32):
    REG_INFO[r16] = (r32, 0, 16)
for r8, r32 in zip(['al', 'cl', 'dl', 'bl'], REGS32[:4]):
    REG_INFO[r8] = (r32, 0, 8)
for r8, r32 in zip(['ah', 'ch', 'dh', 'bh'], REGS32[:4]):
    REG_INFO[r8] = (r32, 8, 8)

MASK = {8: '0xffu', 16: '0xffffu', 32: '0xffffffffu'}
SIGN = {8: 7, 16: 15, 32: 31}
UT = {8: 'uint8_t', 16: 'uint16_t', 32: 'uint32_t'}
ST = {8: 'int8_t', 16: 'int16_t', 32: 'int32_t'}
RD = {8: 'R8', 16: 'R16', 32: 'R32', 64: 'R64'}
WR = {8: 'W8', 16: 'W16', 32: 'W32', 64: 'W64'}

class Unsupported(Exception):
    pass

SEG_VAL = {'cs': 0x1b, 'ds': 0x23, 'es': 0x23, 'ss': 0x23, 'fs': 0x3b, 'gs': 0}
def reg_read(name):
    if name in SEG_VAL: return '0x%xu' % SEG_VAL[name]
    if name not in REG_INFO: raise Unsupported('reg ' + name)
    base, sh, bits = REG_INFO[name]
    if bits == 32: return base
    if sh: return '((%s >> %d) & 0xffu)' % (base, sh)
    return '(%s & %s)' % (base, MASK[bits])

def reg_write(name, val):
    if name in SEG_VAL: return '(void)(%s); /* segment load ignored (flat model) */' % val
    if name not in REG_INFO: raise Unsupported('reg ' + name)
    base, sh, bits = REG_INFO[name]
    if bits == 32: return '%s = %s;' % (base, val)
    if sh: return '%s = (%s & 0xffff00ffu) | (((uint32_t)(%s) & 0xffu) << 8);' % (base, base, val)
    if bits == 16: return '%s = (%s & 0xffff0000u) | ((uint32_t)(%s) & 0xffffu);' % (base, base, val)
    return '%s = (%s & 0xffffff00u) | ((uint32_t)(%s) & 0xffu);' % (base, base, val)

class Ctx:
    pass

def addr_expr(ins, op):
    m = op.mem
    parts = []
    if m.base:
        parts.append(REG_INFO[ins.reg_name(m.base)][0])
    if m.index:
        idx = REG_INFO[ins.reg_name(m.index)][0]
        parts.append(idx if m.scale == 1 else '%s*%d' % (idx, m.scale))
    disp = m.disp & 0xffffffff
    if disp or not parts:
        parts.append('0x%xu' % disp)
    e = ' + '.join(parts)
    if m.segment and ins.reg_name(m.segment) == 'fs':
        e = 'FS_BASE + ' + e
    return '(uint32_t)(%s)' % e

def op_bits(op):
    return op.size * 8

def rd(ins, op, bits=None):
    if op.type == X.X86_OP_REG:
        return reg_read(ins.reg_name(op.reg))
    if op.type == X.X86_OP_IMM:
        b = bits or op_bits(op) or 32
        return '0x%xu' % (op.imm & ((1 << b) - 1) if b < 64 else op.imm & 0xffffffff)
    if op.type == X.X86_OP_MEM:
        b = bits or op_bits(op)
        return '%s(%s)' % (RD[b], addr_expr(ins, op))
    raise Exception('bad op')

def wr(ins, op, val, bits=None):
    if op.type == X.X86_OP_REG:
        return reg_write(ins.reg_name(op.reg), val)
    if op.type == X.X86_OP_MEM:
        b = bits or op_bits(op)
        return '%s(%s, %s);' % (WR[b], addr_expr(ins, op), val)
    raise Exception('bad op')

# Flags: c p z s o  (a ignored)
ALLF = frozenset('cpzso')

def parity(r):
    return '(uint32_t)!__builtin_parity((uint32_t)(%s) & 0xffu)' % r

# --------------------------------------------------------------------------
# Instruction semantics: returns (code_lines, defs, uses) where code depends on live set
# We return a function emit(live_out) -> list of lines, plus static defs/uses sets.

COND = {
    'o': 'of', 'no': '!of', 'b': 'cf', 'c': 'cf', 'nae': 'cf', 'ae': '!cf', 'nb': '!cf', 'nc': '!cf',
    'e': 'zf', 'z': 'zf', 'ne': '!zf', 'nz': '!zf', 'be': '(cf | zf)', 'na': '(cf | zf)',
    'a': '(!cf && !zf)', 'nbe': '(!cf && !zf)', 's': 'sf', 'ns': '!sf', 'p': 'pf', 'pe': 'pf',
    'np': '!pf', 'po': '!pf', 'l': '(sf != of)', 'nge': '(sf != of)', 'ge': '(sf == of)',
    'nl': '(sf == of)', 'le': '(zf || sf != of)', 'ng': '(zf || sf != of)',
    'g': '(!zf && sf == of)', 'nle': '(!zf && sf == of)',
}
COND_USES = {}
for k, v in COND.items():
    COND_USES[k] = frozenset(c for c in 'cpzso' if (c + 'f') in v)

def flag_lines(kind, bits, live, r='r', a='a', b='b', cin='cin'):
    """Generate flag computation lines for result r (already masked to bits) of operation kind."""
    L = []
    sb = SIGN[bits]
    if 'z' in live: L.append('zf = (%s) == 0;' % r)
    if 's' in live: L.append('sf = ((%s) >> %d) & 1;' % (r, sb))
    if 'p' in live: L.append('pf = %s;' % parity(r))
    if kind == 'add':
        if 'c' in live: L.append('cf = (%s) < (%s);' % (r, a))
        if 'o' in live: L.append('of = ((((%s) ^ (%s)) & ((%s) ^ (%s))) >> %d) & 1;' % (a, r, b, r, sb))
    elif kind == 'adc':
        if 'c' in live: L.append('cf = %s ? ((%s) <= (%s)) : ((%s) < (%s));' % (cin, r, a, r, a))
        if 'o' in live: L.append('of = ((((%s) ^ (%s)) & ((%s) ^ (%s))) >> %d) & 1;' % (a, r, b, r, sb))
    elif kind == 'sub':
        if 'c' in live: L.append('cf = (%s) < (%s);' % (a, b))
        if 'o' in live: L.append('of = ((((%s) ^ (%s)) & ((%s) ^ (%s))) >> %d) & 1;' % (a, b, a, r, sb))
    elif kind == 'sbb':
        if 'c' in live: L.append('cf = %s ? ((%s) <= (%s)) : ((%s) < (%s));' % (cin, a, b, a, b))
        if 'o' in live: L.append('of = ((((%s) ^ (%s)) & ((%s) ^ (%s))) >> %d) & 1;' % (a, b, a, r, sb))
    elif kind == 'logic':
        if 'c' in live: L.append('cf = 0;')
        if 'o' in live: L.append('of = 0;')
    elif kind == 'inc':
        if 'o' in live: L.append('of = (%s) == 0x%xu;' % (r, 1 << sb))
    elif kind == 'dec':
        if 'o' in live: L.append('of = (%s) == 0x%xu;' % (r, (1 << sb) - 1))
    elif kind == 'neg':
        if 'c' in live: L.append('cf = (%s) != 0;' % a)
        if 'o' in live: L.append('of = (%s) == 0x%xu;' % (r, 1 << sb))
    return L

def tmpdecl(bits, name, expr):
    return '%s %s = (%s)(%s)' % (UT[bits], name, UT[bits], expr)

FPU_MEM_RD = {32: 'F32', 64: 'F64', 80: 'F80'}

class Gen:
    def __init__(self, fstart):
        self.fstart = fstart
        self.calls = set()
        self.problems = []
        self.uses_mmx = False

    # returns (lines_fn, defs, uses, kind)  kind: 'normal','jcc','jmp','call','ret','switch','tail','end'
    def sem(self, ins):
        m = ins.mnemonic
        prefix = ''
        if m.startswith('rep ') or m.startswith('repe ') or m.startswith('repne ') or m.startswith('repz ') or m.startswith('repnz '):
            prefix, m = m.split(' ', 1)
        ops = ins.operands
        b0 = ins.bytes[0]
        # ---- x87 (raw opcode decode)
        bb = bytes(ins.bytes)
        i = 0
        while bb[i] in (0x66, 0x67, 0xf2, 0xf3, 0x64, 0x26, 0x2e, 0x36, 0x3e, 0x65):
            i += 1
        # capstone prints "F2 A5" (repne movsd) as plain "movsd" (the SSE2 name), losing the prefix: take REP from
        # the raw bytes of string instructions (A4-A7 movs/cmps, AA-AF stos/lods/scas)
        if not prefix and 0xa4 <= bb[i] <= 0xaf and any(x in (0xf2, 0xf3) for x in bb[:i]):
            last = [x for x in bb[:i] if x in (0xf2, 0xf3)][-1]
            if bb[i] in (0xa6, 0xa7, 0xae, 0xaf):
                prefix = 'repne' if last == 0xf2 else 'repe'
            else:
                prefix = 'rep'
        if 0xd8 <= bb[i] <= 0xdf:
            return self.x87(ins, bb[i], bb[i + 1])
        fn = getattr(self, 'i_' + m.replace(' ', '_'), None)
        if fn is None:
            raise Unsupported(m)
        return fn(ins, ops, prefix)

    # ---------------- integer
    def binop(self, ins, ops, kind, cexpr, store=True):
        bits = op_bits(ops[0])
        a = rd(ins, ops[0])
        bsrc = rd(ins, ops[1], bits)
        def emit(live):
            L = ['{ %s; %s;' % (tmpdecl(bits, 'a', a), tmpdecl(bits, 'b', bsrc))]
            if kind in ('adc', 'sbb'):
                L.append('uint32_t cin = cf;')
            L.append(tmpdecl(bits, 'r', cexpr) + ';')
            L += flag_lines(kind, bits, live)
            if store: L.append(wr(ins, ops[0], 'r'))
            L.append('}')
            return L
        defs = frozenset('cpzso')
        uses = frozenset('c') if kind in ('adc', 'sbb') else frozenset()
        return emit, defs, uses, 'normal'

    def i_add(self, ins, ops, p): return self.binop(ins, ops, 'add', 'a + b')
    def i_adc(self, ins, ops, p): return self.binop(ins, ops, 'adc', 'a + b + cin')
    def i_sub(self, ins, ops, p):
        if ops[0].type == X.X86_OP_REG and ops[1].type == X.X86_OP_REG and ops[0].reg == ops[1].reg:
            return self.zero_idiom(ins, ops)
        return self.binop(ins, ops, 'sub', 'a - b')
    def i_sbb(self, ins, ops, p): return self.binop(ins, ops, 'sbb', 'a - b - cin')
    def i_cmp(self, ins, ops, p): return self.binop(ins, ops, 'sub', 'a - b', store=False)
    def i_and(self, ins, ops, p): return self.binop(ins, ops, 'logic', 'a & b')
    def i_or(self, ins, ops, p): return self.binop(ins, ops, 'logic', 'a | b')
    def i_test(self, ins, ops, p): return self.binop(ins, ops, 'logic', 'a & b', store=False)
    def i_xor(self, ins, ops, p):
        if ops[0].type == X.X86_OP_REG and ops[1].type == X.X86_OP_REG and ops[0].reg == ops[1].reg:
            return self.zero_idiom(ins, ops)
        return self.binop(ins, ops, 'logic', 'a ^ b')

    def zero_idiom(self, ins, ops):
        def emit(live):
            L = [wr(ins, ops[0], '0')]
            for f, v in (('z', 1), ('s', 0), ('p', 1), ('c', 0), ('o', 0)):
                if f in live: L.append('%sf = %d;' % (f, v))
            return L
        return emit, frozenset('cpzso'), frozenset(), 'normal'

    def unop(self, ins, ops, kind, cexpr, defs):
        bits = op_bits(ops[0])
        a = rd(ins, ops[0])
        def emit(live):
            L = ['{ %s;' % tmpdecl(bits, 'a', a), tmpdecl(bits, 'r', cexpr) + ';']
            L += flag_lines(kind, bits, live)
            L.append(wr(ins, ops[0], 'r'))
            L.append('}')
            return L
        return emit, defs, frozenset(), 'normal'

    def i_inc(self, ins, ops, p): return self.unop(ins, ops, 'inc', 'a + 1', frozenset('pzso'))
    def i_dec(self, ins, ops, p): return self.unop(ins, ops, 'dec', 'a - 1', frozenset('pzso'))
    def i_neg(self, ins, ops, p): return self.unop(ins, ops, 'neg', '0 - a', frozenset('cpzso'))
    def i_not(self, ins, ops, p):
        bits = op_bits(ops[0])
        return (lambda live: [wr(ins, ops[0], '~%s' % rd(ins, ops[0]))]), frozenset(), frozenset(), 'normal'

    def i_mov(self, ins, ops, p):
        bits = op_bits(ops[0])
        v = rd(ins, ops[1], bits)
        return (lambda live: [wr(ins, ops[0], v)]), frozenset(), frozenset(), 'normal'

    def i_movzx(self, ins, ops, p):
        v = rd(ins, ops[1])
        return (lambda live: [wr(ins, ops[0], '(uint32_t)(%s)' % v)]), frozenset(), frozenset(), 'normal'

    def i_movsx(self, ins, ops, p):
        sb = op_bits(ops[1])
        v = rd(ins, ops[1])
        return (lambda live: [wr(ins, ops[0], '(uint32_t)(int32_t)(%s)(%s)' % (ST[sb], v))]), frozenset(), frozenset(), 'normal'

    def i_lea(self, ins, ops, p):
        e = addr_expr(ins, ops[1])
        return (lambda live: [wr(ins, ops[0], e)]), frozenset(), frozenset(), 'normal'

    def i_xchg(self, ins, ops, p):
        bits = op_bits(ops[0])
        a, b = rd(ins, ops[0]), rd(ins, ops[1])
        def emit(live):
            return ['{ %s; %s;' % (tmpdecl(bits, 'a', a), tmpdecl(bits, 'b', b)), wr(ins, ops[0], 'b'), wr(ins, ops[1], 'a'), '}']
        return emit, frozenset(), frozenset(), 'normal'

    def i_push(self, ins, ops, p):
        op = ops[0]
        if op.type == X.X86_OP_REG and ins.reg_name(op.reg) in SEG_VAL:
            return (lambda live: ['esp -= 4; W32(esp, %s);' % reg_read(ins.reg_name(op.reg))]), frozenset(), frozenset(), 'normal'
        if op.type == X.X86_OP_IMM:
            v = '0x%xu' % (op.imm & 0xffffffff)
        else:
            if op_bits(op) == 16 and op.type == X.X86_OP_REG and ins.reg_name(op.reg) in REG_INFO:
                v16 = rd(ins, op)
                return (lambda live: ['{ uint32_t v = %s; esp -= 2; W16(esp, v); }' % v16]), frozenset(), frozenset(), 'normal'
            if op_bits(op) != 32: raise Unsupported('push16')
            v = rd(ins, op)
        return (lambda live: ['{ uint32_t v = %s; esp -= 4; W32(esp, v); }' % v]), frozenset(), frozenset(), 'normal'

    def i_pop(self, ins, ops, p):
        op = ops[0]
        if op.type == X.X86_OP_REG and ins.reg_name(op.reg) in SEG_VAL:
            return (lambda live: ['esp += 4;']), frozenset(), frozenset(), 'normal'
        if op_bits(op) == 16 and op.type == X.X86_OP_REG and ins.reg_name(op.reg) in REG_INFO:
            return (lambda live: ['{ uint32_t v = R16(esp); esp += 2;', wr(ins, op, 'v'), '}']), frozenset(), frozenset(), 'normal'
        if op_bits(op) != 32: raise Unsupported('pop16')
        if op.type == X.X86_OP_REG and ins.reg_name(op.reg) == 'esp':
            return (lambda live: ['esp = R32(esp);']), frozenset(), frozenset(), 'normal'
        # pop [esp+x] uses esp after increment
        def emit(live):
            return ['{ uint32_t v = R32(esp); esp += 4;', wr(ins, op, 'v'), '}']
        return emit, frozenset(), frozenset(), 'normal'

    def i_les(self, ins, ops, p):
        v = rd(ins, ops[1], 32)
        return (lambda live: [wr(ins, ops[0], v)]), frozenset(), frozenset(), 'normal'
    i_lds = i_les
    i_lfs = i_les
    i_lgs = i_les

    def i_enter(self, ins, ops, p):
        n, lvl = ops[0].imm & 0xffff, ops[1].imm & 0x1f
        if lvl: raise Unsupported('enter level')
        return (lambda live: ['esp -= 4; W32(esp, ebp); ebp = esp; esp -= %du;' % n]), frozenset(), frozenset(), 'normal'

    def i_verr(self, ins, ops, p):
        return (lambda live: ['zf = 1;'] if 'z' in live else []), frozenset('z'), frozenset(), 'normal'
    i_verw = i_verr

    def i_leave(self, ins, ops, p):
        return (lambda live: ['esp = ebp; ebp = R32(esp); esp += 4;']), frozenset(), frozenset(), 'normal'

    def i_cdq(self, ins, ops, p):
        return (lambda live: ['edx = (uint32_t)((int32_t)eax >> 31);']), frozenset(), frozenset(), 'normal'
    def i_cwde(self, ins, ops, p):
        return (lambda live: ['eax = (uint32_t)(int32_t)(int16_t)eax;']), frozenset(), frozenset(), 'normal'
    def i_cbw(self, ins, ops, p):
        return (lambda live: [reg_write('ax', '(uint16_t)(int16_t)(int8_t)eax')]), frozenset(), frozenset(), 'normal'
    def i_cwd(self, ins, ops, p):
        return (lambda live: [reg_write('dx', '((int16_t)eax < 0) ? 0xffff : 0')]), frozenset(), frozenset(), 'normal'

    def i_nop(self, ins, ops, p): return (lambda live: []), frozenset(), frozenset(), 'normal'
    def i_wait(self, ins, ops, p): return (lambda live: []), frozenset(), frozenset(), 'normal'
    def i_cld(self, ins, ops, p): return (lambda live: ['DF = 0;']), frozenset(), frozenset(), 'normal'
    def i_std(self, ins, ops, p): return (lambda live: ['DF = 1;']), frozenset(), frozenset(), 'normal'
    def i_int(self, ins, ops, p):
        n = ops[0].imm
        return (lambda live: ['guest_int(%d, 0x%x);' % (n, ins.address)]), frozenset(), frozenset(), 'normal'
    def i_int3(self, ins, ops, p):
        return (lambda live: ['guest_int(3, 0x%x);' % ins.address]), frozenset(), frozenset(), 'normal'
    def i_hlt(self, ins, ops, p):
        return (lambda live: ['guest_int(-1, 0x%x);' % ins.address]), frozenset(), frozenset(), 'normal'

    def i_sahf(self, ins, ops, p):
        def emit(live):
            L = []
            if 'c' in live: L.append('cf = (eax >> 8) & 1;')
            if 'p' in live: L.append('pf = (eax >> 10) & 1;')
            if 'z' in live: L.append('zf = (eax >> 14) & 1;')
            if 's' in live: L.append('sf = (eax >> 15) & 1;')
            return L
        return emit, frozenset('cpzs'), frozenset(), 'normal'

    def i_lahf(self, ins, ops, p):
        return (lambda live: [reg_write('ah', '(sf<<7)|(zf<<6)|(pf<<2)|2|cf')]), frozenset(), frozenset('cpzs'), 'normal'

    def i_xlatb(self, ins, ops, p):
        return (lambda live: [reg_write('al', 'R8(ebx + (eax & 0xff))')]), frozenset(), frozenset(), 'normal'

    def i_bt(self, ins, ops, p): return self.btx(ins, ops, None)
    def i_bts(self, ins, ops, p): return self.btx(ins, ops, '|')
    def i_btr(self, ins, ops, p): return self.btx(ins, ops, '&~')
    def i_btc(self, ins, ops, p): return self.btx(ins, ops, '^')
    def btx(self, ins, ops, opr):
        bits = op_bits(ops[0])
        if ops[0].type == X.X86_OP_MEM and ops[1].type == X.X86_OP_REG:
            # bit string addressing: memory base + (signed bitoffset >> 3)
            base = addr_expr(ins, ops[0])
            off = rd(ins, ops[1])
            def emit(live):
                L = ['{ int32_t bo = (int32_t)%s; uint32_t ad = %s + (uint32_t)(bo >> 3); uint32_t bi = bo & 7; uint32_t v = R8(ad);' % (off, base)]
                L.append('cf = (v >> bi) & 1;')
                if opr: L.append('W8(ad, v %s (1u << bi));' % opr if opr != '&~' else 'W8(ad, v & ~(1u << bi));')
                L.append('}')
                return L
            return emit, frozenset('c'), frozenset(), 'normal'
        a = rd(ins, ops[0])
        bi = rd(ins, ops[1])
        def emit(live):
            L = ['{ uint32_t v = %s; uint32_t bi = (%s) & %d;' % (a, bi, bits - 1), 'cf = (v >> bi) & 1;']
            if opr == '|': L.append(wr(ins, ops[0], 'v | (1u << bi)'))
            elif opr == '&~': L.append(wr(ins, ops[0], 'v & ~(1u << bi)'))
            elif opr == '^': L.append(wr(ins, ops[0], 'v ^ (1u << bi)'))
            L.append('}')
            return L
        return emit, frozenset('c'), frozenset(), 'normal'

    def shift(self, ins, ops, kind):
        bits = op_bits(ops[0])
        a = rd(ins, ops[0])
        if len(ops) == 1:
            cnt, const = '1', 1
        elif ops[1].type == X.X86_OP_IMM:
            const = ops[1].imm & 31
            cnt = str(const)
        else:
            cnt, const = '(ecx & 31)', None
        sb = SIGN[bits]
        U = UT[bits]
        def emit(live):
            if const == 0:
                return []
            L = ['{ %s; uint32_t c = %s;' % (tmpdecl(bits, 'a', a), cnt)]
            body = []
            if kind == 'shl':
                body.append('%s r = (%s)((uint32_t)a << c);' % (U, U))
                if 'c' in live: body.append('cf = (c <= %d) ? (((uint32_t)a >> (%d - c)) & 1) : 0;' % (bits, bits))
                if 'o' in live: body.append('of = ((r >> %d) & 1) ^ (((uint32_t)a >> (%d - c)) & 1);' % (sb, bits))
            elif kind == 'shr':
                body.append('%s r = (%s)((uint32_t)a >> c);' % (U, U))
                if 'c' in live: body.append('cf = ((uint32_t)a >> (c - 1)) & 1;')
                if 'o' in live: body.append('of = (a >> %d) & 1;' % sb)
            elif kind == 'sar':
                body.append('%s r = (%s)((int32_t)(%s)a >> c);' % (U, U, ST[bits]))
                if 'c' in live: body.append('cf = ((int32_t)(%s)a >> (c - 1)) & 1;' % ST[bits])
                if 'o' in live: body.append('of = 0;')
            elif kind == 'rol':
                body.append('uint32_t cc = c %% %d;' % bits)
                body.append('%s r = (%s)(cc ? (((uint32_t)a << cc) | ((uint32_t)a >> (%d - cc))) : a);' % (U, U, bits))
                if 'c' in live: body.append('cf = r & 1;')
                if 'o' in live: body.append('of = ((r >> %d) ^ r) & 1;' % sb)
            elif kind == 'ror':
                body.append('uint32_t cc = c %% %d;' % bits)
                body.append('%s r = (%s)(cc ? (((uint32_t)a >> cc) | ((uint32_t)a << (%d - cc))) : a);' % (U, U, bits))
                if 'c' in live: body.append('cf = (r >> %d) & 1;' % sb)
                if 'o' in live: body.append('of = ((r >> %d) ^ (r >> %d)) & 1;' % (sb, sb - 1))
            elif kind in ('rcr', 'rcl'):
                if const != 1: raise Unsupported(kind + ' count')
                if kind == 'rcr':
                    body.append('%s r = (%s)(((uint32_t)a >> 1) | ((uint32_t)cf << %d));' % (U, U, sb))
                    body.append('of = ((r >> %d) ^ (r >> %d)) & 1;' % (sb, sb - 1))
                    body.append('cf = a & 1;')
                else:
                    body.append('%s r = (%s)(((uint32_t)a << 1) | cf);' % (U, U))
                    body.append('cf = (a >> %d) & 1;' % sb)
                    body.append('of = ((r >> %d) & 1) ^ cf;' % sb)
            if kind in ('shl', 'shr', 'sar'):
                if 'z' in live: body.append('zf = r == 0;')
                if 's' in live: body.append('sf = (r >> %d) & 1;' % sb)
                if 'p' in live: body.append('pf = %s;' % parity('r'))
            body.append(wr(ins, ops[0], 'r'))
            if const is None:
                L.append('if (c) {'); L += body; L.append('}')
            else:
                L += body
            L.append('}')
            return L
        if kind in ('rcr', 'rcl'):
            return emit, frozenset('co'), frozenset('c'), 'normal'
        if kind in ('rol', 'ror'):
            d = frozenset('co')
        else:
            d = frozenset('cpzso')
        u = d if const is None else frozenset()   # variable count may leave flags unchanged
        return emit, d, u, 'normal'

    def i_shl(self, ins, ops, p): return self.shift(ins, ops, 'shl')
    def i_sal(self, ins, ops, p): return self.shift(ins, ops, 'shl')
    def i_shr(self, ins, ops, p): return self.shift(ins, ops, 'shr')
    def i_sar(self, ins, ops, p): return self.shift(ins, ops, 'sar')
    def i_rol(self, ins, ops, p): return self.shift(ins, ops, 'rol')
    def i_ror(self, ins, ops, p): return self.shift(ins, ops, 'ror')
    def i_rcr(self, ins, ops, p): return self.shift(ins, ops, 'rcr')
    def i_rcl(self, ins, ops, p): return self.shift(ins, ops, 'rcl')

    def i_shld(self, ins, ops, p): return self.shxd(ins, ops, True)
    def i_shrd(self, ins, ops, p): return self.shxd(ins, ops, False)
    def shxd(self, ins, ops, left):
        a = rd(ins, ops[0]); b = rd(ins, ops[1])
        cnt = rd(ins, ops[2]) if ops[2].type == X.X86_OP_IMM else '(ecx & 31)'
        def emit(live):
            L = ['{ uint32_t a = %s, b = %s, c = (%s) & 31;' % (a, b, cnt), 'if (c) {']
            if left:
                L.append('uint32_t r = (a << c) | (b >> (32 - c)); cf = (a >> (32 - c)) & 1;')
            else:
                L.append('uint32_t r = (a >> c) | (b << (32 - c)); cf = (a >> (c - 1)) & 1;')
            L.append('zf = r == 0; sf = r >> 31; pf = %s; of = 0;' % parity('r'))
            L.append(wr(ins, ops[0], 'r'))
            L.append('} }')
            return L
        return emit, frozenset('cpzso'), frozenset('cpzso'), 'normal'

    def i_imul(self, ins, ops, p):
        if len(ops) == 1:
            bits = op_bits(ops[0])
            s = rd(ins, ops[0])
            if bits == 32:
                def emit(live):
                    return ['{ int64_t r = (int64_t)(int32_t)eax * (int64_t)(int32_t)(%s); eax = (uint32_t)r; edx = (uint32_t)((uint64_t)r >> 32);' % s,
                            'cf = of = (r != (int64_t)(int32_t)r); }']
            elif bits == 8:
                def emit(live):
                    return ['{ int32_t r = (int32_t)(int8_t)eax * (int32_t)(int8_t)(%s);' % s, reg_write('ax', 'r'), 'cf = of = (r != (int8_t)r); }']
            else:
                def emit(live):
                    return ['{ int32_t r = (int32_t)(int16_t)eax * (int32_t)(int16_t)(%s);' % s, reg_write('ax', 'r'), reg_write('dx', 'r >> 16'), 'cf = of = (r != (int16_t)r); }']
            return emit, frozenset('cpzso'), frozenset(), 'normal'
        bits = op_bits(ops[0])
        if bits == 16:
            if len(ops) == 2:
                a, b = rd(ins, ops[0]), rd(ins, ops[1])
            else:
                a, b = rd(ins, ops[1]), rd(ins, ops[2], 16)
            def emit16(live):
                L = ['{ int32_t r = (int32_t)(int16_t)(%s) * (int32_t)(int16_t)(%s);' % (a, b), wr(ins, ops[0], '(uint32_t)r')]
                if 'c' in live or 'o' in live: L.append('cf = of = (r != (int32_t)(int16_t)r);')
                if 'z' in live: L.append('zf = (uint16_t)r == 0;')
                if 's' in live: L.append('sf = ((uint32_t)r >> 15) & 1;')
                if 'p' in live: L.append('pf = %s;' % parity('(uint32_t)r'))
                L.append('}')
                return L
            return emit16, frozenset('cpzso'), frozenset(), 'normal'
        if bits != 32: raise Unsupported('imul%d' % bits)
        if len(ops) == 2:
            a, b = rd(ins, ops[0]), rd(ins, ops[1])
        else:
            a, b = rd(ins, ops[1]), rd(ins, ops[2], 32)
        def emit(live):
            L = ['{ int64_t r = (int64_t)(int32_t)(%s) * (int64_t)(int32_t)(%s);' % (a, b), wr(ins, ops[0], '(uint32_t)r')]
            if 'c' in live or 'o' in live: L.append('cf = of = (r != (int64_t)(int32_t)r);')
            if 'z' in live: L.append('zf = (uint32_t)r == 0;')
            if 's' in live: L.append('sf = ((uint32_t)r) >> 31;')
            if 'p' in live: L.append('pf = %s;' % parity('(uint32_t)r'))
            L.append('}')
            return L
        return emit, frozenset('cpzso'), frozenset(), 'normal'

    def i_mul(self, ins, ops, p):
        bits = op_bits(ops[0])
        s = rd(ins, ops[0])
        if bits == 32:
            def emit(live):
                return ['{ uint64_t r = (uint64_t)eax * (uint64_t)(%s); eax = (uint32_t)r; edx = (uint32_t)(r >> 32); cf = of = (edx != 0); }' % s]
        elif bits == 8:
            def emit(live):
                return ['{ uint32_t r = (eax & 0xff) * (%s);' % s, reg_write('ax', 'r'), 'cf = of = (r > 0xff); }']
        else:
            def emit(live):
                return ['{ uint32_t r = (eax & 0xffff) * (%s);' % s, reg_write('ax', 'r'), reg_write('dx', 'r >> 16'), 'cf = of = (r > 0xffff); }']
        return emit, frozenset('cpzso'), frozenset(), 'normal'

    def i_div(self, ins, ops, p):
        bits = op_bits(ops[0])
        s = rd(ins, ops[0])
        if bits == 32:
            def emit(live):
                return ['{ uint32_t d = %s; if (!d) d = guest_divzero(0x%x);' % (s, ins.address),
                        'uint64_t n = ((uint64_t)edx << 32) | eax; eax = (uint32_t)(n / d); edx = (uint32_t)(n % d); }']
        elif bits == 8:
            def emit(live):
                return ['{ uint32_t d = %s; if (!d) d = guest_divzero(0x%x);' % (s, ins.address),
                        'uint32_t n = eax & 0xffff;', reg_write('al', 'n / d'), reg_write('ah', 'n % d'), '}']
        else:
            def emit(live):
                return ['{ uint32_t d = %s; if (!d) d = guest_divzero(0x%x);' % (s, ins.address),
                        'uint32_t n = ((edx & 0xffff) << 16) | (eax & 0xffff);', reg_write('ax', 'n / d'), reg_write('dx', 'n % d'), '}']
        return emit, frozenset('cpzso'), frozenset(), 'normal'

    def i_idiv(self, ins, ops, p):
        bits = op_bits(ops[0])
        s = rd(ins, ops[0])
        if bits == 32:
            def emit(live):
                return ['{ int32_t d = (int32_t)%s; if (!d) d = (int32_t)guest_divzero(0x%x);' % (s, ins.address),
                        'int64_t n = (int64_t)(((uint64_t)edx << 32) | eax);',
                        'if (d == -1) { eax = (uint32_t)(0 - (uint64_t)n); edx = 0; } else { eax = (uint32_t)(int32_t)(n / d); edx = (uint32_t)(int32_t)(n % d); } }']
        elif bits == 8:
            def emit(live):
                return ['{ int32_t d = (int8_t)%s; if (!d) d = (int32_t)guest_divzero(0x%x);' % (s, ins.address),
                        'int32_t n = (int16_t)eax;', reg_write('al', 'n / d'), reg_write('ah', 'n % d'), '}']
        else:
            def emit(live):
                return ['{ int32_t d = (int16_t)%s; if (!d) d = (int32_t)guest_divzero(0x%x);' % (s, ins.address),
                        'int32_t n = (int32_t)(((edx & 0xffff) << 16) | (eax & 0xffff));', reg_write('ax', 'n / d'), reg_write('dx', 'n % d'), '}']
        return emit, frozenset('cpzso'), frozenset(), 'normal'

    def setcc(self, ins, ops, cc):
        c = COND[cc]
        return (lambda live: [wr(ins, ops[0], '(%s) ? 1 : 0' % c)]), frozenset(), COND_USES[cc], 'normal'

    # string ops
    def strop(self, ins, ops, prefix, op, bits):
        n = bits // 8
        step = '(DF ? -%d : %d)' % (n, n)
        U = UT[bits]
        # F2/F3 on movs/stos/lods both mean a plain REP (Watcom emits "repne movsb")
        if op in ('movs', 'stos', 'lods') and prefix in ('repne', 'repnz', 'repe', 'repz'):
            prefix = 'rep'
        if op == 'lods' and prefix == 'rep':
            one = reg_write({8: 'al', 16: 'ax', 32: 'eax'}[bits], '%s(esi)' % RD[bits]) + ' esi += %s;' % step
            return (lambda live: ['while (ecx) { %s ecx--; }' % one]), frozenset(), frozenset(), 'normal'
        if op == 'movs':
            one = '%s(edi, %s(esi)); esi += %s; edi += %s;' % (WR[bits], RD[bits], step, step)
            if prefix == 'rep':
                if bits == 32 or bits == 8:
                    return (lambda live: ['if (!DF) { guest_movs(edi, esi, ecx, %d); esi += ecx * %d; edi += ecx * %d; ecx = 0; } else { while (ecx) { %s ecx--; } }' % (n, n, n, one)]), frozenset(), frozenset(), 'normal'
                return (lambda live: ['while (ecx) { %s ecx--; }' % one]), frozenset(), frozenset(), 'normal'
            return (lambda live: [one]), frozenset(), frozenset(), 'normal'
        if op == 'stos':
            val = {8: '(uint8_t)eax', 16: '(uint16_t)eax', 32: 'eax'}[bits]
            one = '%s(edi, %s); edi += %s;' % (WR[bits], val, step)
            if prefix == 'rep':
                return (lambda live: ['if (!DF) { guest_stos%d(edi, %s, ecx); edi += ecx * %d; ecx = 0; } else { while (ecx) { %s ecx--; } }' % (bits, val, n, one)]), frozenset(), frozenset(), 'normal'
            return (lambda live: [one]), frozenset(), frozenset(), 'normal'
        if op == 'scas':
            val = {8: '(uint8_t)eax', 16: '(uint16_t)eax', 32: 'eax'}[bits]
            if prefix in ('repne', 'repnz', 'repe', 'repz'):
                ne = prefix in ('repne', 'repnz')
                def emit(live):
                    L = ['{ %s a = %s, b = 0, r = 0; int any = 0;' % (U, val),
                         'while (ecx) { b = %s(edi); edi += %s; ecx--; any = 1; r = (%s)(a - b); if (%s) break; }' % (RD[bits], step, U, 'r == 0' if ne else 'r != 0'),
                         'if (any) {']
                    L += flag_lines('sub', bits, live)
                    L.append('} }')
                    return L
                return emit, frozenset('cpzso'), frozenset('cpzso'), 'normal'
            def emit(live):
                L = ['{ %s a = %s, b = %s(edi); %s r = (%s)(a - b); edi += %s;' % (U, val, RD[bits], U, U, step)]
                L += flag_lines('sub', bits, live)
                L.append('}')
                return L
            return emit, frozenset('cpzso'), frozenset(), 'normal'
        if op == 'cmps':
            if prefix in ('repe', 'repz', 'repne', 'repnz'):
                ne = prefix in ('repne', 'repnz')
                def emit(live):
                    L = ['{ %s a = 0, b = 0, r = 0; int any = 0;' % U,
                         'while (ecx) { a = %s(esi); b = %s(edi); esi += %s; edi += %s; ecx--; any = 1; r = (%s)(a - b); if (%s) break; }' % (RD[bits], RD[bits], step, step, U, 'r == 0' if ne else 'r != 0'),
                         'if (any) {']
                    L += flag_lines('sub', bits, live)
                    L.append('} }')
                    return L
                return emit, frozenset('cpzso'), frozenset('cpzso'), 'normal'
            def emit(live):
                L = ['{ %s a = %s(esi), b = %s(edi); %s r = (%s)(a - b); esi += %s; edi += %s;' % (U, RD[bits], RD[bits], U, U, step, step)]
                L += flag_lines('sub', bits, live)
                L.append('}')
                return L
            return emit, frozenset('cpzso'), frozenset(), 'normal'
        if op == 'lods':
            one = reg_write({8: 'al', 16: 'ax', 32: 'eax'}[bits], '%s(esi)' % RD[bits]) + ' esi += %s;' % step
            return (lambda live: [one]), frozenset(), frozenset(), 'normal'
        raise Unsupported(op)

    # ---- control flow (handled specially by function generator)
    def i_jmp(self, ins, ops, p): return None, frozenset(), frozenset(), 'jmp'
    def i_call(self, ins, ops, p): return None, frozenset('cpzso'), frozenset(), 'call'
    def i_ret(self, ins, ops, p): return None, frozenset(), frozenset(), 'ret'
    def i_jecxz(self, ins, ops, p): return None, frozenset(), frozenset(), 'jcc'

    # MMX (only paddusb/movq/emms used)
    def i_movq(self, ins, ops, p):
        if any(o.type == X.X86_OP_REG and ins.reg_name(o.reg).startswith('xmm') for o in ops): raise Unsupported('movq xmm')
        self.uses_mmx = True
        d, s = ops
        def get(op):
            if op.type == X.X86_OP_REG: return 'MMX[%d]' % (int(ins.reg_name(op.reg)[2:]))
            return 'R64(%s)' % addr_expr(ins, op)
        def emit(live):
            if d.type == X.X86_OP_REG: return ['%s = %s;' % (get(d), get(s))]
            return ['W64(%s, %s);' % (addr_expr(ins, d), get(s))]
        return emit, frozenset(), frozenset(), 'normal'
    def i_paddusb(self, ins, ops, p):
        self.uses_mmx = True
        dn = int(ins.reg_name(ops[0].reg)[2:])
        src = 'MMX[%d]' % int(ins.reg_name(ops[1].reg)[2:]) if ops[1].type == X.X86_OP_REG else 'R64(%s)' % addr_expr(ins, ops[1])
        return (lambda live: ['MMX[%d] = mmx_paddusb(MMX[%d], %s);' % (dn, dn, src)]), frozenset(), frozenset(), 'normal'
    def i_emms(self, ins, ops, p): return (lambda live: []), frozenset(), frozenset(), 'normal'

    # CPU identification: the host decides which features the game sees (src/runtime.c: host_cpuid), so engines
    # and libraries that dispatch on CPUID (D3DX, the CRT) take their plain x87/integer paths.
    def i_rdtsc(self, ins, ops, p):
        return (lambda live: ['{ uint64_t t = host_rdtsc(); eax = (uint32_t)t; edx = (uint32_t)(t >> 32); }']), frozenset(), frozenset(), 'normal'
    def i_cpuid(self, ins, ops, p):
        return (lambda live: ['{ uint32_t q[4]; host_cpuid(eax, ecx, q); eax = q[0]; ebx = q[1]; ecx = q[2]; edx = q[3]; }']), frozenset(), frozenset(), 'normal'
    def i_pushal(self, ins, ops, p):
        return (lambda live: ['{ uint32_t s = esp; esp -= 32; W32(esp + 28, eax); W32(esp + 24, ecx); W32(esp + 20, edx); W32(esp + 16, ebx);',
                              '  W32(esp + 12, s); W32(esp + 8, ebp); W32(esp + 4, esi); W32(esp, edi); }']), frozenset(), frozenset(), 'normal'
    def i_popal(self, ins, ops, p):
        return (lambda live: ['edi = R32(esp); esi = R32(esp + 4); ebp = R32(esp + 8); ebx = R32(esp + 16); edx = R32(esp + 20);',
                              'ecx = R32(esp + 24); eax = R32(esp + 28); esp += 32;']), frozenset(), frozenset(), 'normal'
    def i_pushf(self, ins, ops, p):
        return (lambda live: ['{ uint32_t v = (of << 11) | (DF << 10) | (sf << 7) | (zf << 6) | (pf << 2) | 2 | cf; esp -= 2; W16(esp, v); }']), frozenset(), frozenset('cpzso'), 'normal'
    def i_popf(self, ins, ops, p):
        return (lambda live: ['{ uint32_t v = R16(esp); esp += 2; cf = v & 1; pf = (v >> 2) & 1; zf = (v >> 6) & 1; sf = (v >> 7) & 1; DF = (v >> 10) & 1; of = (v >> 11) & 1; }']), frozenset('cpzso'), frozenset(), 'normal'
    def i_cmc(self, ins, ops, p):
        return (lambda live: ['cf = !cf;']), frozenset('c'), frozenset('c'), 'normal'
    def i_aam(self, ins, ops, p):
        n = ops[0].imm & 0xff if ops else 10
        def emit(live):
            L = ['{ uint32_t al = eax & 0xffu; eax = (eax & 0xffff0000u) | ((al / %du) << 8) | (al %% %du);' % (n, n)]
            if 'z' in live: L.append('zf = (eax & 0xffu) == 0;')
            if 's' in live: L.append('sf = (eax >> 7) & 1;')
            if 'p' in live: L.append('pf = %s;' % parity('eax'))
            L.append('}')
            return L
        return emit, frozenset('pzs'), frozenset(), 'normal'
    def i_pushfd(self, ins, ops, p):
        return (lambda live: ['{ uint32_t v = (of << 11) | (DF << 10) | (sf << 7) | (zf << 6) | (pf << 2) | 2 | cf; esp -= 4; W32(esp, v); }']), frozenset(), frozenset('cpzso'), 'normal'
    def i_popfd(self, ins, ops, p):
        return (lambda live: ['{ uint32_t v = R32(esp); esp += 4; cf = v & 1; pf = (v >> 2) & 1; zf = (v >> 6) & 1; sf = (v >> 7) & 1; DF = (v >> 10) & 1; of = (v >> 11) & 1; }']), frozenset('cpzso'), frozenset(), 'normal'
    def cmov(self, ins, ops, cc):
        v = rd(ins, ops[1])
        return (lambda live: ['if (%s) { %s }' % (COND[cc], wr(ins, ops[0], v))]), frozenset(), COND_USES[cc], 'normal'

    # ---------------- x87
    def x87(self, ins, op, modrm):
        mod = modrm >> 6; reg = (modrm >> 3) & 7; rm = modrm & 7
        memop = None
        for o in ins.operands:
            if o.type == X.X86_OP_MEM: memop = o
        A = addr_expr(ins, memop) if memop is not None else None
        N = lambda L: ((lambda live: L), frozenset(), frozenset(), 'normal')
        arith = ['+', '*', 'com', 'comp', '-', 'r-', '/', 'r/']
        def ar(dst, src, k, pop=False):
            if k == '+': s = '%s = %s + %s;' % (dst, dst, src)
            elif k == '*': s = '%s = %s * %s;' % (dst, dst, src)
            elif k == '-': s = '%s = %s - %s;' % (dst, dst, src)
            elif k == 'r-': s = '%s = %s - %s;' % (dst, src, dst)
            elif k == '/': s = '%s = %s / %s;' % (dst, dst, src)
            elif k == 'r/': s = '%s = %s / %s;' % (dst, src, dst)
            return s
        if mod != 3:
            if op in (0xd8, 0xdc, 0xda, 0xde):
                src = {0xd8: 'F32(%s)', 0xdc: 'F64(%s)', 0xda: '(double)(int32_t)R32(%s)', 0xde: '(double)(int16_t)R16(%s)'}[op] % A
                k = arith[reg]
                if k in ('com', 'comp'):
                    return N(['fpu_com(ST0, %s);' % src] + (['FPOP();'] if k == 'comp' else []))
                return N([ar('ST0', '(%s)' % src, k)])
            if op == 0xd9:
                if reg == 0: return N(['{ double v = F32(%s); FPUSH(v); }' % A])
                if reg == 2: return N(['WF32(%s, ST0);' % A])
                if reg == 3: return N(['WF32(%s, ST0); FPOP();' % A])
                if reg == 4: return N(['fpu_ldenv(%s);' % A])
                if reg == 5: return N(['FCW = R16(%s);' % A])
                if reg == 6: return N(['fpu_stenv(%s);' % A])
                if reg == 7: return N(['W16(%s, FCW);' % A])
            if op == 0xdb:
                if reg == 0: return N(['{ double v = (double)(int32_t)R32(%s); FPUSH(v); }' % A])
                if reg == 2: return N(['W32(%s, (uint32_t)fpu_toint32(ST0));' % A])
                if reg == 3: return N(['W32(%s, (uint32_t)fpu_toint32(ST0)); FPOP();' % A])
                if reg == 5: return N(['{ double v = F80(%s); FPUSH(v); }' % A])
                if reg == 7: return N(['WF80(%s, ST0); FPOP();' % A])
            if op == 0xdd:
                if reg == 0: return N(['{ double v = F64(%s); FPUSH(v); }' % A])
                if reg == 2: return N(['WF64(%s, ST0);' % A])
                if reg == 3: return N(['WF64(%s, ST0); FPOP();' % A])
                if reg == 4: return N(['fpu_rstor(%s);' % A])
                if reg == 6: return N(['fpu_save(%s);' % A])
                if reg == 7: return N(['W16(%s, fpu_sw());' % A])
            if op == 0xdf:
                if reg == 0: return N(['{ double v = (double)(int16_t)R16(%s); FPUSH(v); }' % A])
                if reg == 2: return N(['W16(%s, (uint16_t)fpu_toint16(ST0));' % A])
                if reg == 3: return N(['W16(%s, (uint16_t)fpu_toint16(ST0)); FPOP();' % A])
                if reg == 5: return N(['{ double v = (double)(int64_t)R64(%s); FPUSH(v); }' % A])
                if reg == 7: return N(['W64(%s, (uint64_t)fpu_toint64(ST0)); FPOP();' % A])
            raise Unsupported('x87 mem %02x /%d' % (op, reg))
        i = rm
        STi = 'STI(%d)' % i
        if op == 0xd8:
            k = arith[reg]
            if k in ('com', 'comp'):
                return N(['fpu_com(ST0, %s);' % STi] + (['FPOP();'] if k == 'comp' else []))
            return N([ar('ST0', STi, k)])
        if op == 0xdc:
            # dst = st(i): C0 add, C8 mul, E0 fsubr (sti = st0 - sti), E8 fsub (sti = sti - st0), F0 fdivr, F8 fdiv
            k = {0: '+', 1: '*', 4: 'r-', 5: '-', 6: 'r/', 7: '/'}.get(reg)
            if k is None:
                k2 = arith[reg]
                return N(['fpu_com(ST0, %s);' % STi] + (['FPOP();'] if k2 == 'comp' else []))
            return N([ar(STi, 'ST0', k)])
        if op == 0xde:
            if reg == 3 and i == 1:
                return N(['fpu_com(ST0, STI(1)); FPOP(); FPOP();'])
            k = {0: '+', 1: '*', 4: 'r-', 5: '-', 6: 'r/', 7: '/'}.get(reg)
            if k is None: raise Unsupported('de %x' % modrm)
            return N([ar(STi, 'ST0', k), 'FPOP();'])
        if op == 0xd9:
            if reg == 0: return N(['{ double v = %s; FPUSH(v); }' % STi])
            if reg == 1: return N(['{ double t = ST0; ST0 = %s; %s = t; }' % (STi, STi)])
            if modrm == 0xd0: return N([])
            tbl = {0xe0: ['ST0 = -ST0;'], 0xe1: ['ST0 = fabs(ST0);'], 0xe4: ['fpu_com(ST0, 0.0);'],
                   0xe5: ['fpu_xam();'], 0xe8: ['FPUSH(1.0);'], 0xe9: ['FPUSH(3.321928094887362347870);'],
                   0xea: ['FPUSH(1.442695040888963407360);'], 0xeb: ['FPUSH(3.141592653589793238463);'],
                   0xec: ['FPUSH(0.301029995663981195214);'], 0xed: ['FPUSH(0.693147180559945309417);'],
                   0xee: ['FPUSH(0.0);'], 0xf0: ['ST0 = exp2(ST0) - 1.0;'],
                   0xf1: ['STI(1) = STI(1) * log2(ST0); FPOP();'],
                   0xf2: ['ST0 = tan(ST0); FPUSH(1.0); FSW_CC &= ~0x400;'],
                   0xf3: ['STI(1) = atan2(STI(1), ST0); FPOP();'],
                   0xf4: ['fpu_xtract();'],
                   0xf5: ['fpu_prem(1);'], 0xf6: ['FTOP = (FTOP - 1) & 7;'], 0xf7: ['FTOP = (FTOP + 1) & 7;'],
                   0xf8: ['fpu_prem(0);'], 0xf9: ['STI(1) = STI(1) * log2(ST0 + 1.0); FPOP();'],
                   0xfa: ['ST0 = sqrt(ST0);'], 0xfb: ['{ double v = ST0; ST0 = sin(v); FPUSH(cos(v)); FSW_CC &= ~0x400; }'],
                   0xfc: ['ST0 = fpu_round(ST0);'], 0xfd: ['ST0 = ldexp(ST0, (int)trunc(STI(1)));'],
                   0xfe: ['ST0 = sin(ST0); FSW_CC &= ~0x400;'], 0xff: ['ST0 = cos(ST0); FSW_CC &= ~0x400;']}
            if modrm in tbl: return N(tbl[modrm])
            raise Unsupported('d9 %x' % modrm)
        if op == 0xda:
            if modrm == 0xe9: return N(['fpu_com(ST0, STI(1)); FPOP(); FPOP();'])
            raise Unsupported('da %x' % modrm)
        if op == 0xdb:
            if modrm == 0xe2: return N(['FSW_CC = 0;'])
            if modrm == 0xe3: return N(['fpu_init();'])
            raise Unsupported('db %x' % modrm)
        if op == 0xdd:
            if reg == 0: return N([])  # ffree
            if reg == 2: return N(['%s = ST0;' % STi])
            if reg == 3: return N(['%s = ST0; FPOP();' % STi])
            if reg == 4: return N(['fpu_com(ST0, %s);' % STi])
            if reg == 5: return N(['fpu_com(ST0, %s); FPOP();' % STi])
            raise Unsupported('dd %x' % modrm)
        if op == 0xdf:
            if modrm == 0xe0: return N([reg_write('ax', 'fpu_sw()')])
            raise Unsupported('df %x' % modrm)
        raise Unsupported('x87 %02x %02x' % (op, modrm))


for cc in COND:
    setattr(Gen, 'i_set' + cc, (lambda c: lambda self, ins, ops, p: self.setcc(ins, ops, c))(cc))
    setattr(Gen, 'i_cmov' + cc, (lambda c: lambda self, ins, ops, p: self.cmov(ins, ops, c))(cc))
    setattr(Gen, 'i_j' + cc, lambda self, ins, ops, p: (None, frozenset(), frozenset(), 'jcc'))
for op in ('movs', 'stos', 'scas', 'cmps', 'lods'):
    for suf, bits in (('b', 8), ('w', 16), ('d', 32)):
        setattr(Gen, 'i_' + op + suf, (lambda o, b: lambda self, ins, ops, p: self.strop(ins, ops, p, o, b))(op, bits))

# --------------------------------------------------------------------------
def fname(a):
    return 'f_%06x' % a

SPILL = 'SPILL();'
RELOAD = 'RELOAD();'

def jcc_cond(ins):
    m = ins.mnemonic
    if m == 'jecxz': return 'ecx == 0', frozenset()
    cc = m[1:]
    return COND[cc], COND_USES[cc]

def gen_function(entry, problems):
    g = Gen(entry)
    conts = sorted(CONTS_BY_OWNER.get(entry, ()))
    # discover body
    body = {}
    order = []
    stack = [entry] + conts
    while stack:
        a = stack.pop()
        if a in body: continue
        if not flow_code(a):
            body[a] = None
            continue
        ins = decode(a)
        body[a] = ins
        m = ins.mnemonic
        nxt = a + ins.size
        if m in ('ret', 'retf'):
            continue
        if m == 'jmp':
            t = branch_target(ins)
            if t is not None:
                if t not in ENTRY_SET:
                    stack.append(t)
            elif a in SWITCHES:
                for t in SWITCHES[a]['targets']:
                    stack.append(t)
            continue
        if m.startswith('j') or m == 'jecxz':
            t = branch_target(ins)
            if t not in ENTRY_SET: stack.append(t)
            if nxt not in ENTRY_SET: stack.append(nxt)
            continue
        if nxt not in ENTRY_SET:
            stack.append(nxt)
    addrs = sorted(a for a in body)
    def internal(x):
        return x in body and (x not in ENTRY_SET or x == entry)
    # semantics
    sems = {}
    for a in addrs:
        ins = body[a]
        if ins is None: continue
        try:
            sems[a] = g.sem(ins)
        except (Unsupported, KeyError) as e:
            problems.append('%x: unsupported %s (%s %s)' % (a, e, ins.mnemonic, ins.op_str))
            sems[a] = ((lambda live, a=a, ins=ins: ['guest_unsupported(0x%x); /* %s %s */' % (a, ins.mnemonic, ins.op_str)]), frozenset(), frozenset(), 'normal')
    # successors within function
    def succs(a):
        ins = body[a]
        k = sems[a][3]
        nxt = a + ins.size
        res = []
        if k == 'normal' or k == 'call':
            if nxt in body and nxt not in ENTRY_SET: res.append(nxt)
        elif k == 'jcc':
            t = branch_target(ins)
            if internal(t): res.append(t)
            if nxt in body and nxt not in ENTRY_SET: res.append(nxt)
        elif k == 'jmp':
            t = branch_target(ins)
            if t is not None:
                if internal(t): res.append(t)
            elif a in SWITCHES:
                res += [x for x in SWITCHES[a]['targets'] if internal(x)]
        return res
    # flag liveness (backward dataflow)
    live_in = {a: frozenset() for a in sems}
    live_out = {a: frozenset() for a in sems}
    changed = True
    rev = list(reversed([a for a in addrs if a in sems]))
    succ_cache = {a: succs(a) for a in sems}
    jcc_uses = {}
    for a in sems:
        ins = body[a]
        if sems[a][3] == 'jcc':
            jcc_uses[a] = jcc_cond(ins)[1]
    while changed:
        changed = False
        for a in rev:
            lo = frozenset()
            for s in succ_cache[a]:
                if s in live_in: lo |= live_in[s]
            _, defs, uses, kind = sems[a]
            if kind == 'jcc': uses = jcc_uses[a]
            if kind in ('call', 'ret'):
                li = frozenset()
                if kind == 'call': lo = frozenset()
            else:
                li = (lo - defs) | uses
            if lo != live_out[a] or li != live_in[a]:
                live_out[a] = lo; live_in[a] = li; changed = True
    if entry in live_in and live_in[entry]:
        problems.append('%x: flags live at entry %s' % (entry, ''.join(sorted(live_in[entry]))))
    # labels: branch targets and fall-throughs that are not emitted sequentially
    order_next = {}
    for i, a in enumerate(addrs):
        order_next[a] = addrs[i + 1] if i + 1 < len(addrs) else None
    labels = set([entry])
    for a in sems:
        ins = body[a]
        nxt = a + ins.size
        branchy = sems[a][3] in ('jcc', 'jmp')
        for s in succ_cache[a]:
            if branchy or s != nxt or order_next[a] != nxt:
                labels.add(s)
    for h, (_, res) in HOOKS.items():
        if h in sems and res in body:
            labels.add(res)
    conts = [c for c in conts if c in sems]
    labels |= set(conts)
    # after a call returns with an exception unwind in progress: resume at our continuation or keep returning
    if conts:
        UNW = ' if (g_unwind) { if (g_unwind_ebp == ebp) switch (g_unwind_target) { %s } return; }' % ' '.join(
            'case 0x%xu: guest_unwind_done(); RELOAD(); goto L_%x;' % (c, c) for c in conts)
    else:
        UNW = ' if (g_unwind) return;'
    if not EH_UNWIND: UNW = ''
    # emit
    out = []
    out.append('void %s(void) {' % fname(entry))
    out.append('  LOAD_REGS(); FTRACE(0x%xu);' % entry)
    if g.uses_mmx: out.append('  uint64_t MMX[8];')
    if addrs and addrs[0] != entry:
        out.append('  goto L_%x;' % entry)
    prev_fall = None
    emitted_any = False
    for a in addrs:
        ins = body[a]
        if prev_fall is not None and prev_fall != a:
            out.append('  goto L_%x;' % prev_fall)
        prev_fall = None
        if ins is None:
            out.append('L_%x: guest_badaddr(0x%x); return;' % (a, a))
            continue
        lab = 'L_%x: ' % a if a in labels else ''
        out.append('%s/* %x: %s %s */' % (lab, a, ins.mnemonic, ins.op_str))
        emit, defs, uses, kind = sems[a]
        nxt = a + ins.size
        lo = live_out[a]
        if a in HOOKS:
            fn, res = HOOKS[a]
            out.append('  SPILL(); %s();%s RELOAD(); goto L_%x;' % (fn, UNW, res))
            continue
        if kind == 'normal':
            out += ['  ' + l for l in emit(lo)]
            if nxt in ENTRY_SET:
                out.append('  ' + tail_call(nxt))
            elif nxt in body:
                prev_fall = nxt
            else:
                out.append('  guest_badaddr(0x%x); return;' % nxt)
        elif kind == 'call':
            op = ins.operands[0]
            pre = '  esp -= 4; W32(esp, 0x%xu); ' % nxt
            t = branch_target(ins)
            if t is not None:
                if t in HLE and HLE[t] in ('hle_setjmp3', 'hle_setjmp_wc'):
                    # setjmp in this function's own C frame, so a guest longjmp can come back here (runtime.c).
                    # hle_setjmp_wc: Watcom register convention (jmp_buf in eax).
                    out.append(pre + SPILL + ' { GJmp *j = %s_slot(); if (setjmp(j->env)) R = j->r; else { R.esp += 4; R.eax = 0; j->r = R; } } ' % HLE[t] + RELOAD)
                elif t in HLE:
                    out.append(pre + SPILL + ' %s(); ' % HLE[t] + RELOAD)
                elif t in WRAPS:
                    out.append(pre + SPILL + ' %s();%s ' % (WRAPS[t], UNW) + RELOAD)
                elif t in ENTRY_SET:
                    out.append(pre + SPILL + ' %s();%s ' % (fname(t), UNW) + RELOAD)
                else:
                    problems.append('%x: call to non-entry %x' % (a, t))
                    out.append(pre + SPILL + ' call_ind(0x%xu);%s ' % (t, UNW) + RELOAD)
            elif is_import_mem(op):
                iat = op.mem.disp & 0xffffffff
                mod, nm = IMPORTS[iat]
                kind2, tgt = import_target(iat)
                if kind2 == 'hle':
                    out.append(pre + SPILL + ' %s();%s /* %s!%s */ ' % (tgt, UNW, mod, nm) + RELOAD)
                    HLE_USED.add(tgt)
                elif kind2 == 'func':
                    XFUNCS.add(tgt)
                    out.append(pre + SPILL + ' %s();%s /* %s!%s */ ' % (fname(tgt), UNW, mod, nm) + RELOAD)
                else:
                    out.append(pre + SPILL + ' call_ind(R32(0x%xu));%s /* %s!%s */ ' % (iat, UNW, mod, nm) + RELOAD)
            else:
                v = rd(ins, op)
                out.append('  { uint32_t t = %s; esp -= 4; W32(esp, 0x%xu); %s call_ind(t);%s %s }' % (v, nxt, SPILL, UNW, RELOAD))
            if nxt in ENTRY_SET:
                out.append('  ' + tail_call(nxt))
            elif nxt in body:
                prev_fall = nxt
            else:
                out.append('  guest_noreturn(0x%x); return;' % a)
        elif kind == 'ret':
            n = ins.operands[0].imm if ins.operands else 0
            out.append('  esp += %d; SPILL(); return;' % (4 + n))
        elif kind == 'jcc':
            cond, _ = jcc_cond(ins)
            t = branch_target(ins)
            if internal(t):
                out.append('  if (%s) goto L_%x;' % (cond, t))
            else:
                out.append('  if (%s) { %s }' % (cond, tail_call(t)))
            if nxt in ENTRY_SET:
                out.append('  ' + tail_call(nxt))
            elif nxt in body:
                prev_fall = nxt
            else:
                out.append('  guest_badaddr(0x%x); return;' % nxt)
        elif kind == 'jmp':
            t = branch_target(ins)
            op = ins.operands[0]
            if t is not None:
                if internal(t):
                    out.append('  goto L_%x;' % t)
                else:
                    out.append('  ' + tail_call(t))
            elif a in SWITCHES:
                v = rd(ins, op)
                out.append('  switch (%s) {' % v)
                for x in SWITCHES[a]['targets']:
                    if internal(x):
                        out.append('    case 0x%xu: goto L_%x;' % (x, x))
                    else:
                        out.append('    case 0x%xu: %s' % (x, tail_call(x)))
                out.append('    default: guest_badjump(0x%x, %s); return;' % (a, v))
                out.append('  }')
            elif is_import_mem(op):
                iat = op.mem.disp & 0xffffffff
                mod, nm = IMPORTS[iat]
                kind2, tgt = import_target(iat)
                if kind2 == 'hle':
                    HLE_USED.add(tgt)
                    out.append('  SPILL(); %s(); return; /* %s!%s */' % (tgt, mod, nm))
                elif kind2 == 'func':
                    XFUNCS.add(tgt)
                    out.append('  SPILL(); %s(); return; /* %s!%s */' % (fname(tgt), mod, nm))
                else:
                    out.append('  SPILL(); call_ind(R32(0x%xu)); return; /* %s!%s */' % (iat, mod, nm))
            elif a in UNWIND_JUMPS:
                v = rd(ins, op)
                out.append('  { uint32_t t = %s; SPILL(); guest_unwind_jump(t); return; }' % v)
            else:
                v = rd(ins, op)
                out.append('  { uint32_t t = %s; SPILL(); call_ind(t); return; }' % v)
                problems.append('%x: indirect jmp %s' % (a, ins.op_str))
    if prev_fall is not None:
        out.append('  goto L_%x;' % prev_fall)
    out.append('}')
    # remove unused labels (labels not in set) -- we only printed labels in set; ensure targets exist
    return out, len(sems)

def tail_call(t):
    if t in HLE:
        return 'SPILL(); %s(); return;' % HLE[t]
    if t in WRAPS:
        return 'SPILL(); %s(); return;' % WRAPS[t]
    if t in ENTRY_SET:
        return 'SPILL(); %s(); return;' % fname(t)
    return 'SPILL(); call_ind(0x%xu); return;' % t

# --------------------------------------------------------------------------
os.makedirs(OUT, exist_ok=True)
problems = []
files = []
cur = []; cur_n = 0; fidx = 0
PER_FILE = 6000
total = 0
for e in ENTRIES:
    if e in HLE:
        lines = ['void %s(void) { %s(); }' % (fname(e), HLE[e])]
        n = 1
    else:
        lines, n = gen_function(e, problems)
    cur.append('\n'.join(lines)); cur_n += n; total += n
    if cur_n >= PER_FILE:
        files.append(cur); cur = []; cur_n = 0
if cur: files.append(cur)
hl = sorted(set(HLE.values()) | HLE_USED | set(h[0] for h in HOOKS.values()) | set(WRAPS.values()))
if not TAG:
    # single-module layout (assets/template): rec_funcs.h, rec_config.h, rec_table.c with global names
    for i, fl in enumerate(files):
        with open(os.path.join(OUT, 'rec_%03d.c' % i), 'w') as fp:
            fp.write('#include "recomp.h"\n\n')
            fp.write('\n\n'.join(fl))
            fp.write('\n')
    with open(os.path.join(OUT, 'rec_funcs.h'), 'w') as fp:
        for e in sorted(set(ENTRIES) | XFUNCS):
            fp.write('void %s(void);\n' % fname(e))
    with open(os.path.join(OUT, 'rec_table.c'), 'w') as fp:
        fp.write('#include "recomp.h"\n\nconst FuncEntry rec_func_table[] = {\n')
        for e in ENTRIES:
            fp.write('  {0x%xu, %s},\n' % (e, fname(e)))
        fp.write('};\nconst int rec_func_count = %d;\n' % len(ENTRIES))
        fp.write('\nconst ImportEntry rec_imports[] = {\n')
        for a, (mod, nm) in sorted(IMPORTS.items()):
            fp.write('  {0x%xu, "%s", "%s"},\n' % (a, mod, nm))
        fp.write('};\nconst int rec_import_count = %d;\n' % len(IMPORTS))
    with open(os.path.join(OUT, 'rec_config.h'), 'w') as fp:
        fp.write('// generated by recomp.py\n#pragma once\n')
        fp.write('#define REC_IMAGE_BASE 0x%xu\n' % BASE)
        fp.write('#define REC_ENTRY 0x%xu\n' % (BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        fp.write('#define REC_TEXT_LO 0x%xu\n' % TEXT_START)
        fp.write('#define REC_TEXT_HI 0x%xu\n' % ((TEXT_END + 0xfff) & ~0xfff))
        for h in hl:
            fp.write('void %s(void);\n' % h)
    with open(os.path.join(OUT, 'problems.txt'), 'w') as fp:
        fp.write('\n'.join(problems))
    print('files', len(files), 'instructions emitted', total, 'problems', len(problems), file=sys.stderr)
    sys.exit(0)
for i, fl in enumerate(files):
    with open(os.path.join(OUT, 'rec_%03d.c' % i), 'w') as fp:
        fp.write('#include "recomp.h"\n#include "rec_mod.h"\n\n')
        fp.write('\n\n'.join(fl))
        fp.write('\n')
with open(os.path.join(OUT, 'rec_mod.h'), 'w') as fp:
    fp.write('// generated by recomp.py: %s\n#pragma once\n' % os.path.basename(EXE))
    for e in sorted(set(ENTRIES) | XFUNCS):
        fp.write('void %s(void);\n' % fname(e))
    for h in hl:
        fp.write('void %s(void);\n' % h)
with open(os.path.join(OUT, 'rec_table.c'), 'w') as fp:
    fp.write('#include "recomp.h"\n#include "rec_mod.h"\n\nstatic const FuncEntry funcs[] = {\n')
    for e in ENTRIES:
        fp.write('  {0x%xu, %s},\n' % (e, fname(e)))
    fp.write('};\n\nstatic const ImportEntry imports[] = {\n')
    for a, (mod, nm) in sorted(IMPORTS.items()):
        fp.write('  {0x%xu, "%s", "%s"},\n' % (a, mod, nm))
    fp.write('  {0, 0, 0}\n};\n\n')
    fp.write('const RecModule rec_module%s = {"%s", 0x%xu, 0x%xu, 0x%xu, 0x%xu, 0x%xu, funcs, %d, imports, %d};\n' % (
        SFX, os.path.basename(EXE), BASE, pe.OPTIONAL_HEADER.SizeOfImage,
        BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint if pe.OPTIONAL_HEADER.AddressOfEntryPoint else 0,
        TEXT_START, (TEXT_END + 0xfff) & ~0xfff, len(ENTRIES), len(IMPORTS)))
with open(os.path.join(OUT, 'problems.txt'), 'w') as fp:
    fp.write('\n'.join(problems))
print('files', len(files), 'instructions emitted', total, 'problems', len(problems), file=sys.stderr)
