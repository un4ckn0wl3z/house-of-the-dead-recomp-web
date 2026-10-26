# IDA headless export: functions, code heads, switch tables, names, imports
import json, idaapi, idautils, idc, ida_funcs, ida_nalt, ida_auto, ida_bytes, ida_segment, ida_name, ida_pro, ida_xref, ida_ua
ida_auto.auto_wait()

# Functions reached only through data (vtables, callback tables) or immediates that IDA left unexplored: create
# them when the address follows the end of other code (ret/jmp/int3/nop padding or a function end).
def text_range():
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        if seg.perm & ida_segment.SEGPERM_EXEC: return seg.start_ea, seg.end_ea
    return 0, 0
TLO, THI = text_range()
def plausible_start(t):
    if not (TLO <= t < THI): return False
    fl = ida_bytes.get_flags(t)
    if ida_bytes.is_code(fl) or ida_funcs.get_func(t): return False
    p = idc.prev_head(t, TLO)
    if p == idc.BADADDR: return False
    if ida_bytes.get_byte(t - 1) in (0xCC, 0x90): return True
    if ida_bytes.is_code(ida_bytes.get_flags(p)) and p + idc.get_item_size(p) == t:
        m = idc.print_insn_mnem(p)
        return m in ("ret", "retn", "jmp", "int3")
    f = ida_funcs.get_func(p)
    return f is not None and f.end_ea == t
added = 0
for rnd in range(4):
    cands = set()
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        if seg.perm & ida_segment.SEGPERM_EXEC: continue
        a = seg.start_ea
        while a + 4 <= seg.end_ea:
            v = ida_bytes.get_dword(a)
            if TLO <= v < THI: cands.add(v)
            a += 4
    for h in idautils.Heads(TLO, THI):
        if not ida_bytes.is_code(ida_bytes.get_flags(h)): continue
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, h): continue
        for op in insn.ops:
            if op.type == ida_ua.o_imm and TLO <= op.value < THI: cands.add(op.value)
    n = 0
    for t in sorted(cands):
        if plausible_start(t):
            if ida_ua.create_insn(t) and ida_funcs.add_func(t): n += 1
    ida_auto.auto_wait()
    print("export: created %d functions referenced from data (round %d)" % (n, rnd))
    added += n
    if not n: break
out = {"funcs": [], "switches": {}, "names": {}, "imports": {}, "segments": [], "code_heads": []}
for s in idautils.Segments():
    seg = ida_segment.getseg(s)
    out["segments"].append({"start": seg.start_ea, "end": seg.end_ea, "name": ida_segment.get_segm_name(seg), "perm": seg.perm})
for fea in idautils.Functions():
    f = ida_funcs.get_func(fea)
    chunks = [(a, b) for a, b in idautils.Chunks(fea)]
    out["funcs"].append({"start": fea, "end": f.end_ea, "name": idc.get_func_name(fea), "flags": f.flags,
                         "chunks": chunks, "frsize": f.frsize, "argsize": f.argsize})
for ea in idautils.Heads():
    if ida_bytes.is_code(ida_bytes.get_flags(ea)):
        out["code_heads"].append(ea)
        si = ida_nalt.get_switch_info(ea)
        if si:
            res = idaapi.calc_switch_cases(ea, si)
            targets = sorted(set(res.targets)) if res else []
            out["switches"][ea] = {"targets": targets, "jumps": si.jumps, "ncases": si.ncases, "elbase": si.elbase}
for ea, n in idautils.Names():
    out["names"][ea] = n
def imp_cb(ea, name, ordinal):
    out["imports"][ea] = [cur_mod, name if name else "#%d" % ordinal]
    return True
for i in range(ida_nalt.get_import_module_qty()):
    cur_mod = ida_nalt.get_import_module_name(i)
    ida_nalt.enum_import_names(i, imp_cb)
with open(idc.ARGV[1], "w") as fp:
    json.dump(out, fp)
ida_pro.qexit(0)
