// Core runtime: guest memory, PE loading, dispatch, x87 helpers, HLE math.
#include "recomp.h"
#include "host.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#if defined(__GNUC__)
__attribute__((aligned(4096)))
#endif
uint8_t G[GUEST_SIZE];
Regs R;
uint32_t DF;
double FPR[8];
uint32_t FTOP, FSW_CC, FCW = 0x27f;

// ---------------------------------------------------------------- logging
static FILE *g_log;
void host_log(const char *fmt, ...) {
    va_list ap;
    if (!g_log) g_log = fopen("port.log", "w");
    va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    if (g_log) { va_start(ap, fmt); vfprintf(g_log, fmt, ap); va_end(ap); fflush(g_log); }
}

void host_backtrace(void) {
    // walk guest ebp chain for diagnostics
    uint32_t bp = R.ebp;
    host_log("  esp=%08x ebp=%08x eax=%08x ecx=%08x edx=%08x ebx=%08x esi=%08x edi=%08x\n",
             R.esp, R.ebp, R.eax, R.ecx, R.edx, R.ebx, R.esi, R.edi);
    for (int i = 0; i < 24 && bp > 0x10000 && bp < 0x380000; i++) {
        host_log("  frame %08x ret %08x\n", bp, R32(bp + 4));
        bp = R32(bp);
    }
    // also scan stack for code addresses
    host_log("  stack scan:");
    for (uint32_t p = R.esp, n = 0; p < 0x370000 && n < 24; p += 4) {
        uint32_t v = R32(p);
        if (v >= REC_TEXT_LO && v < REC_TEXT_HI) { host_log(" %08x", v); n++; }
    }
    host_log("\n");
}

#ifdef FUNC_TRACE
// entry counts per frame window: PORT_TRACE=file writes "first_frame count address" for every function that ran
static uint32_t *tr_count, *tr_first;
void ftrace_hit(uint32_t a) {
    if (!tr_count) { tr_count = calloc(REC_TEXT_HI - REC_TEXT_LO, 4); tr_first = calloc(REC_TEXT_HI - REC_TEXT_LO, 4); }
    if (a < REC_TEXT_LO || a >= REC_TEXT_HI) return;
    uint32_t i = a - REC_TEXT_LO;
    if (!tr_count[i]++) tr_first[i] = host_frame_count() + 1;
}
void ftrace_dump(void) {
    const char *fn = getenv("PORT_TRACE");
    if (!fn || !tr_count) return;
    FILE *f = fopen(fn, "w");
    if (!f) return;
    for (uint32_t i = 0; i < REC_TEXT_HI - REC_TEXT_LO; i++)
        if (tr_count[i]) fprintf(f, "%u %u %x\n", tr_first[i], tr_count[i], REC_TEXT_LO + i);
    fclose(f);
}
#endif

void host_fatal(const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    host_log("FATAL: %s\n", buf);
    host_backtrace();
    host_shutdown();
    exit(1);
}

// ---------------------------------------------------------------- traps
uint32_t guest_divzero(uint32_t addr) { host_log("divide by zero at %08x\n", addr); return 1; }
void guest_int(int n, uint32_t addr) { host_fatal("int %d at %08x", n, addr); }
void guest_unsupported(uint32_t addr) { host_fatal("unsupported instruction at %08x", addr); }
void guest_badaddr(uint32_t addr) { host_fatal("execution reached non-code address %08x", addr); }
void guest_badjump(uint32_t addr, uint32_t t) { host_fatal("bad switch jump at %08x -> %08x", addr, t); }
void guest_noreturn(uint32_t addr) { host_fatal("returned from noreturn call at %08x", addr); }
#ifdef MEMCHECK
void guest_memfault(uint32_t a, int n) { host_fatal("memory access out of range %08x (%d)", a, n); }
#endif

void guest_movs(uint32_t dst, uint32_t src, uint32_t count, uint32_t el) {
    uint32_t n = count * el;
    if (!n) return;
    if (dst > src && dst - src < n) {
        // forward overlapping copy: element-wise semantics
        for (uint32_t i = 0; i < n; i += el) (COW(dst + i, (uint32_t)(el)), memcpy(G + dst + i, G + src + i, el));
    } else {
        (COW(dst, (uint32_t)(n)), memmove(G + dst, G + src, n));
    }
}
void guest_stos8(uint32_t dst, uint32_t v, uint32_t count) { (COW(dst, (uint32_t)(count)), memset(G + dst, (int)(v & 0xff), count)); }
void guest_stos16(uint32_t dst, uint32_t v, uint32_t count) { for (uint32_t i = 0; i < count; i++) W16(dst + i * 2, v); }
void guest_stos32(uint32_t dst, uint32_t v, uint32_t count) {
    if (v == 0) { (COW(dst, (uint32_t)((size_t)count * 4)), memset(G + dst, 0, (size_t)count * 4)); return; }
    for (uint32_t i = 0; i < count; i++) W32(dst + i * 4, v);
}

// ---------------------------------------------------------------- x87
double F80(uint32_t a) {
    uint64_t m = R64(a);
    uint32_t se = R16(a + 8);
    int s = se >> 15, e = se & 0x7fff;
    double v;
    if (e == 0 && m == 0) v = 0.0;
    else if (e == 0x7fff) v = (m << 1) ? NAN : INFINITY;
    else v = ldexp((double)m, e - 16383 - 63);
    return s ? -v : v;
}
void WF80(uint32_t a, double v) {
    uint64_t m = 0; uint32_t se = 0;
    if (signbit(v)) { se = 0x8000; v = -v; }
    if (v == 0.0) { m = 0; }
    else if (isinf(v)) { se |= 0x7fff; m = 0x8000000000000000ull; }
    else if (isnan(v)) { se |= 0x7fff; m = 0xC000000000000000ull; }
    else {
        int e; double f = frexp(v, &e);    // v = f * 2^e, f in [0.5,1)
        m = (uint64_t)ldexp(f, 64);
        se |= (uint32_t)(e - 1 + 16383);
    }
    W64(a, m); W16(a + 8, se);
}
void fpu_com(double a, double b) {
    FSW_CC &= ~0x4500u;
    if (isnan(a) || isnan(b)) FSW_CC |= 0x4500;
    else if (a < b) FSW_CC |= 0x100;
    else if (a == b) FSW_CC |= 0x4000;
}
uint32_t fpu_sw(void) { return (FSW_CC & 0x4700u) | ((FTOP & 7) << 11); }
static double fpu_rnd(double v) {
    switch ((FCW >> 10) & 3) {
    case 0: return nearbyint(v);
    case 1: return floor(v);
    case 2: return ceil(v);
    default: return trunc(v);
    }
}
double fpu_round(double v) { return fpu_rnd(v); }
int32_t fpu_toint32(double v) {
    v = fpu_rnd(v);
    if (!(v >= -2147483648.0 && v <= 2147483647.0)) return INT32_MIN;
    return (int32_t)v;
}
int16_t fpu_toint16(double v) {
    v = fpu_rnd(v);
    if (!(v >= -32768.0 && v <= 32767.0)) return INT16_MIN;
    return (int16_t)v;
}
int64_t fpu_toint64(double v) {
    v = fpu_rnd(v);
    if (!(v >= -9223372036854775808.0 && v < 9223372036854775808.0)) return INT64_MIN;
    return (int64_t)v;
}
void fpu_xam(void) {
    double v = ST0;
    FSW_CC &= ~0x4700u;
    if (signbit(v)) FSW_CC |= 0x200;
    if (isnan(v)) FSW_CC |= 0x100;
    else if (isinf(v)) FSW_CC |= 0x500;
    else if (v == 0.0) FSW_CC |= 0x4000;
    else FSW_CC |= 0x400;
}
void fpu_prem(int ieee) {
    double a = ST0, b = STI(1);
    ST0 = ieee ? remainder(a, b) : fmod(a, b);
    FSW_CC &= ~0x4700u;
}
void fpu_xtract(void) {
    double v = ST0; int e;
    double f = frexp(v, &e);
    ST0 = (double)(e - 1);
    FPUSH(f * 2.0);
}
void fpu_ldenv(uint32_t a) { FCW = R16(a); FSW_CC = R16(a + 4) & 0x4700; FTOP = (R16(a + 4) >> 11) & 7; }
void fpu_stenv(uint32_t a) { (COW(a, (uint32_t)(28)), memset(G + a, 0, 28)); W16(a, FCW); W16(a + 4, fpu_sw()); W16(a + 8, 0xffff); }
void fpu_save(uint32_t a) {
    fpu_stenv(a);
    for (int i = 0; i < 8; i++) WF80(a + 28 + i * 10, STI(i));
    fpu_init();
}
void fpu_rstor(uint32_t a) {
    fpu_ldenv(a);
    for (int i = 0; i < 8; i++) STI(i) = F80(a + 28 + i * 10);
}
void fpu_init(void) { FCW = 0x37f; FSW_CC = 0; FTOP = 0; }
uint64_t mmx_paddusb(uint64_t a, uint64_t b) {
    uint64_t r = 0;
    for (int i = 0; i < 64; i += 8) {
        uint32_t s = (uint32_t)((a >> i) & 0xff) + (uint32_t)((b >> i) & 0xff);
        if (s > 255) s = 255;
        r |= (uint64_t)s << i;
    }
    return r;
}

// ---------------------------------------------------------------- HLE runtime functions
#define HRET() (R.esp += 4)
void hle_ftol(void) {
    double v = ST0; FPOP();
    int64_t r;
    v = trunc(v);
    if (!(v >= -9223372036854775808.0 && v < 9223372036854775808.0)) r = INT64_MIN; else r = (int64_t)v;
    R.eax = (uint32_t)r; R.edx = (uint32_t)((uint64_t)r >> 32);
    HRET();
}
void hle_floor(void) { FPUSH(floor(F64(R.esp + 4))); HRET(); }
void hle_ceil(void) { FPUSH(ceil(F64(R.esp + 4))); HRET(); }
void hle_pow(void) { FPUSH(pow(F64(R.esp + 4), F64(R.esp + 12))); HRET(); }
void hle_CIpow(void) { double y = ST0; FPOP(); double x = ST0; ST0 = pow(x, y); HRET(); }
void hle_acos(void) { FPUSH(acos(F64(R.esp + 4))); HRET(); }
void hle_CIacos(void) { ST0 = acos(ST0); HRET(); }
void hle_ldexp(void) { FPUSH(ldexp(F64(R.esp + 4), (int32_t)R32(R.esp + 12))); HRET(); }
void hle_frexp(void) {
    int e; double f = frexp(F64(R.esp + 4), &e);
    W32(R32(R.esp + 12), (uint32_t)e);
    FPUSH(f); HRET();
}
void hle_memcpy(void) {
    uint32_t d = R32(R.esp + 4), s = R32(R.esp + 8), n = R32(R.esp + 12);
    if (n > GUEST_SIZE || d > GUEST_SIZE - n || s > GUEST_SIZE - n)
        host_fatal("memcpy(%08x, %08x, %u) out of range, caller %08x", d, s, n, R32(R.esp));
    if (n) (COW(d, (uint32_t)(n)), memmove(G + d, G + s, n));
    R.eax = d; HRET();
}
void hle_memset(void) {
    uint32_t d = R32(R.esp + 4), c = R32(R.esp + 8), n = R32(R.esp + 12);
    if (n) (COW(d, (uint32_t)(n)), memset(G + d, (int)(c & 0xff), n));
    R.eax = d; HRET();
}
void hle_strlen(void) { R.eax = (uint32_t)strlen((char *)G + R32(R.esp + 4)); HRET(); }
// setjmp/longjmp (libjpeg/libpng inside D3DX, error recovery): recomp.py calls setjmp in the C frame of the
// function that calls _setjmp3; that frame stays alive for as long as the guest jump point does.
#define MAXJMP 256
static GJmp jmps[MAXJMP];
static uint32_t jsp[MAXJMP];      // guest esp after the setjmp returned: identifies the frame that owns the slot
static GJmp *setjmp_slot(uint32_t gbuf);
GJmp *hle_setjmp3_slot(void) { return setjmp_slot(R32(R.esp + 4)); }
GJmp *hle_setjmp_wc_slot(void) { return setjmp_slot(R.eax); }
// A slot belongs to one (buffer, frame) pair. Games copy jmp_buf contents around (a nested runner saves and later
// restores the outer jump point), so the slot number lives in the buffer's first word and longjmp reads it from
// there. Slots of frames deeper than the current one are dead and get reused.
static GJmp *setjmp_slot(uint32_t gbuf) {
    uint32_t sp = R.esp + 4;
    int free_i = -1;
    for (int i = 0; i < MAXJMP; i++) {
        if (jmps[i].gbuf && jsp[i] < sp) jmps[i].gbuf = 0;
        if (jmps[i].gbuf == gbuf && jsp[i] == sp) { free_i = i; break; }
    }
    if (free_i < 0) for (int i = 0; i < MAXJMP; i++) if (!jmps[i].gbuf) { free_i = i; break; }
    if (free_i < 0) { host_log("setjmp: too many jump points, reusing slot 0\n"); free_i = 0; }
    GJmp *j = &jmps[free_i];
    j->gbuf = gbuf; jsp[free_i] = sp;
    j->seh = R32(FS_BASE);
    // Watcom layout: ebx ecx edx esi edi ebp ret esp (the slot marker replaces ebx, which only longjmp restores)
    W32(gbuf, 0x5E7D0000u | (uint32_t)free_i);
    W32(gbuf + 4, R.ecx); W32(gbuf + 8, R.edx); W32(gbuf + 12, R.esi); W32(gbuf + 16, R.edi);
    W32(gbuf + 20, R.ebp); W32(gbuf + 24, R32(R.esp)); W32(gbuf + 28, sp);
    return j;
}
static void do_longjmp(uint32_t gbuf, uint32_t val) {
    uint32_t m = R32(gbuf);
    int i = (int)(m & 0xffff);
    if ((m >> 16) != 0x5E7D || i >= MAXJMP || !jmps[i].gbuf)
        host_fatal("longjmp to an unknown jump buffer %08x (word %08x)", gbuf, m);
    jmps[i].r.eax = val ? val : 1;
    W32(FS_BASE, jmps[i].seh);
    longjmp(jmps[i].env, 1);
}
void hle_setjmp3(void) { R.eax = 0; HRET(); }
void hle_setjmp_wc(void) { host_fatal("Watcom setjmp reached through an indirect call"); }
void hle_longjmp_wc(void) { do_longjmp(R.eax, R.edx); }   // Watcom: eax = jmp_buf, edx = value
void hle_longjmp(void) { do_longjmp(R32(R.esp + 4), R32(R.esp + 8)); }
// A Pentium Pro class CPU with FPU, TSC, CX8 and CMOV but no MMX/SSE/3DNow!, so the CRT, D3DX and engines take
// their x87 paths (SIMD is not lifted). rdtsc counts nanoseconds of the host clock (main.c: host_time_ns).
void host_cpuid(uint32_t leaf, uint32_t sub, uint32_t out[4]) {
    (void)sub;
    out[0] = out[1] = out[2] = out[3] = 0;
    if (leaf == 0) { out[0] = 1; memcpy(&out[1], "Genu", 4); memcpy(&out[3], "ineI", 4); memcpy(&out[2], "ntel", 4); }
    else if (leaf == 1) { out[0] = 0x0633; out[3] = (1u << 0) | (1u << 4) | (1u << 8) | (1u << 15); }
}
uint64_t host_rdtsc(void) { extern uint64_t host_time_ns(void); return host_time_ns(); }

// ---------------------------------------------------------------- dispatch
#define TEXT_LO REC_TEXT_LO
#define TEXT_HI REC_TEXT_HI
static GFunc *disp;
#define MAX_THUNKS 4096
static struct { GFunc fn; const char *name; } thunks[MAX_THUNKS];
static int n_thunks;

uint32_t host_thunk(GFunc fn, const char *name) {
    for (int i = 0; i < n_thunks; i++)
        if (thunks[i].fn == fn && fn != NULL) return MAGIC_BASE + i * 4;
    if (n_thunks >= MAX_THUNKS) host_fatal("too many thunks");
    thunks[n_thunks].fn = fn; thunks[n_thunks].name = name;
    return MAGIC_BASE + (n_thunks++) * 4;
}

void call_ind(uint32_t a) {
    if (a >= TEXT_LO && a < TEXT_HI) {
        GFunc f = disp[a - TEXT_LO];
        if (f) { f(); return; }
    } else if (a >= MAGIC_BASE && a < MAGIC_BASE + (uint32_t)n_thunks * 4) {
        int i = (a - MAGIC_BASE) >> 2;
        if (thunks[i].fn) { thunks[i].fn(); return; }
        host_fatal("unimplemented import %s", thunks[i].name);
    }
    host_fatal("indirect call to unknown address %08x", a);
}

// replace the code at a function address for every indirect call (vtables, function pointers); returns the
// original, which the replacement may call. Direct calls in the recompiled code are not affected (use "wraps").
GFunc host_override(uint32_t addr, GFunc fn) {
    if (addr < TEXT_LO || addr >= TEXT_HI) return NULL;
    GFunc old = disp[addr - TEXT_LO];
    disp[addr - TEXT_LO] = fn;
    return old;
}

// call a guest __thiscall method (this in ecx, args on stack); returns eax
uint32_t guest_call_this(uint32_t fn, uint32_t self, int nargs, ...) {
    uint32_t args[16];
    va_list ap; va_start(ap, nargs);
    for (int i = 0; i < nargs; i++) args[i] = va_arg(ap, uint32_t);
    va_end(ap);
    Regs save = R;
    for (int i = nargs - 1; i >= 0; i--) { R.esp -= 4; W32(R.esp, args[i]); }
    R.esp -= 4; W32(R.esp, RET_MAGIC);
    R.ecx = self;
    call_ind(fn);
    uint32_t ret = R.eax;
    R.esp = save.esp; R.ebx = save.ebx; R.esi = save.esi; R.edi = save.edi; R.ebp = save.ebp;
    return ret;
}

// call guest function (stdcall or cdecl) from host; returns eax
uint32_t guest_call(uint32_t fn, int nargs, ...) {
    uint32_t args[16];
    va_list ap; va_start(ap, nargs);
    for (int i = 0; i < nargs; i++) args[i] = va_arg(ap, uint32_t);
    va_end(ap);
    Regs save = R;
    for (int i = nargs - 1; i >= 0; i--) { R.esp -= 4; W32(R.esp, args[i]); }
    R.esp -= 4; W32(R.esp, RET_MAGIC);
    call_ind(fn);
    uint32_t ret = R.eax;
    R.esp = save.esp; R.ebx = save.ebx; R.esi = save.esi; R.edi = save.edi; R.ebp = save.ebp;
    return ret;
}

// ---------------------------------------------------------------- guest heap
// Boundary-tag allocator inside guest memory.  Block header (8 bytes) precedes
// payload: [size|inuse][prevsize].  Payload is 16-byte aligned.
#define HEAP_START IMAGE_END
#define HDR 8u
#define NBINS 128
static uint32_t heap_top;      // address of next unallocated block header
static uint32_t bins[NBINS];   // free list heads (block addresses)
static uint32_t heap_used, heap_peak;

// small sizes (<2048) use exact 16-byte classes; large sizes use log2/4 classes
static uint32_t lbins[64];
static uint32_t *binp(uint32_t sz) {
    if (sz < 2048) return &bins[sz >> 4];
    int lg = 31 - __builtin_clz(sz);
    int b = (lg - 11) * 4 + ((sz >> (lg - 2)) & 3);
    if (b > 63) b = 63;
    return &lbins[b];
}
#define BSIZE(b) (R32(b) & ~15u)
#define BUSED(b) (R32(b) & 1u)
#define BPREV(b) R32((b) + 4)
#define FNEXT(b) R32((b) + 8)
#define FPREV(b) R32((b) + 12)

static void fl_insert(uint32_t b) {
    uint32_t *h = binp(BSIZE(b));
    W32(b + 8, *h); W32(b + 12, 0);
    if (*h) W32(*h + 12, b);
    *h = b;
}
static void fl_remove(uint32_t b) {
    uint32_t n = FNEXT(b), p = FPREV(b);
    if (p) W32(p + 8, n); else *binp(BSIZE(b)) = n;
    if (n) W32(n + 12, p);
}

// the allocator's host-side state, saved and restored around an undoable pass (netplay.c)
typedef struct { uint32_t top, used, peak, bins[NBINS], lbins[64]; } HeapState;
static HeapState heap_saved;
void heap_state_save(void) {
    heap_saved.top = heap_top; heap_saved.used = heap_used; heap_saved.peak = heap_peak;
    memcpy(heap_saved.bins, bins, sizeof bins); memcpy(heap_saved.lbins, lbins, sizeof lbins);
}
void heap_state_restore(void) {
    heap_top = heap_saved.top; heap_used = heap_saved.used; heap_peak = heap_saved.peak;
    memcpy(bins, heap_saved.bins, sizeof bins); memcpy(lbins, heap_saved.lbins, sizeof lbins);
}

void heap_init(void) {
    heap_top = HEAP_START - HDR;   // so payload of first block = HEAP_START (16 aligned)
    memset(bins, 0, sizeof bins); memset(lbins, 0, sizeof lbins);
    W32(heap_top + 4, 0);
}

static uint32_t take_block(uint32_t b, uint32_t need) {
    uint32_t bs = BSIZE(b);
    if (bs - need >= 64) {
        uint32_t r = b + need;
        W32(r, bs - need); W32(r + 4, need);
        uint32_t nx = b + bs;
        W32(nx + 4, bs - need);
        fl_insert(r);
        bs = need;
    }
    W32(b, bs | 1);
    heap_used += bs; if (heap_used > heap_peak) heap_peak = heap_used;
    return b + HDR;
}

uint32_t heap_alloc(uint32_t n) {
    uint32_t need = (n + HDR + 15) & ~15u;
    if (need < 32) need = 32;
    if (need < 2048) {
        for (uint32_t s = need; s < 2048; s += 16) {
            uint32_t b = bins[s >> 4];
            if (b) { fl_remove(b); return take_block(b, need); }
        }
    }
    int lg = 31 - __builtin_clz(need < 2048 ? 2048 : need);
    int start = need < 2048 ? 0 : (lg - 11) * 4 + (int)((need >> (lg - 2)) & 3);
    if (start > 63) start = 63;
    for (int i = start; i < 64; i++) {
        for (uint32_t b = lbins[i]; b; b = FNEXT(b)) {
            if (BSIZE(b) >= need) { fl_remove(b); return take_block(b, need); }
        }
    }
    if ((uint64_t)heap_top + need + 2 * HDR > GUEST_SIZE) {
        host_log("guest heap exhausted (request %u, used %u peak %u)\n", n, heap_used, heap_peak);
        return 0;
    }
    uint32_t b = heap_top;
    W32(b, need | 1);
    heap_top += need;
    W32(heap_top + 4, need);
    heap_used += need; if (heap_used > heap_peak) heap_peak = heap_used;
    return b + HDR;
}

void heap_free(uint32_t p) {
    if (!p) return;
    uint32_t b = p - HDR;
    if (b < HEAP_START - HDR || b >= heap_top || !BUSED(b)) { host_log("heap_free: bad pointer %08x\n", p); return; }
    uint32_t sz = BSIZE(b);
    heap_used -= sz;
    // coalesce with next
    uint32_t nx = b + sz;
    if (nx < heap_top && !BUSED(nx)) { fl_remove(nx); sz += BSIZE(nx); }
    // coalesce with previous
    uint32_t ps = BPREV(b);
    if (ps && b - ps >= HEAP_START - HDR) {
        uint32_t pb = b - ps;
        if (!BUSED(pb)) { fl_remove(pb); sz += BSIZE(pb); b = pb; }
    }
    if (b + sz == heap_top) {
        // merge into top
        heap_top = b;
        return;
    }
    W32(b, sz);
    W32(b + sz + 4, sz);
    fl_insert(b);
}

uint32_t heap_size(uint32_t p) {
    if (!p) return 0;
    return BSIZE(p - HDR) - HDR;
}

uint32_t heap_realloc(uint32_t p, uint32_t n) {
    if (!p) return heap_alloc(n);
    uint32_t old = heap_size(p);
    if (n <= old) return p;
    uint32_t q = heap_alloc(n);
    if (!q) return 0;
    (COW(q, (uint32_t)(old)), memcpy(G + q, G + p, old));
    heap_free(p);
    return q;
}

uint32_t heap_peak_bytes(void) { return heap_peak; }
uint32_t heap_used_bytes(void) { return heap_used; }

// simple bump region for host-made guest structures (COM objects, strings) that live forever
static uint32_t static_top = 0x00381000u;
uint32_t guest_static_alloc(uint32_t n) {
    n = (n + 15) & ~15u;
    if (static_top + n > 0x00400000u) return heap_alloc(n);
    uint32_t r = static_top; static_top += n;
    (COW(r, (uint32_t)(n)), memset(G + r, 0, n));
    return r;
}
uint32_t guest_strdup(const char *s) {
    uint32_t n = (uint32_t)strlen(s) + 1;
    uint32_t a = heap_alloc(n);
    (COW(a, (uint32_t)(n)), memcpy(G + a, s, n));
    return a;
}

// ---------------------------------------------------------------- PE loader
static int load_pe(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(sz);
    if (fread(buf, 1, sz, f) != (size_t)sz) { fclose(f); free(buf); return 0; }
    fclose(f);
    uint32_t pe = *(uint32_t *)(buf + 0x3c);
    if (sz < 0x400 || pe > (uint32_t)sz - 0x100 || buf[pe] != 'P' || buf[pe + 1] != 'E' || *(uint16_t *)(buf + pe + 4) != 0x14c) {
        host_log("%s is not a 32-bit x86 PE image\n", path);
        free(buf);
        return 0;
    }
    uint16_t nsec = *(uint16_t *)(buf + pe + 6);
    uint16_t optsz = *(uint16_t *)(buf + pe + 20);
    uint32_t base = *(uint32_t *)(buf + pe + 24 + 28);
    uint32_t hdrsz = *(uint32_t *)(buf + pe + 24 + 60);
    (COW(base, (uint32_t)(hdrsz)), memcpy(G + base, buf, hdrsz));
    uint8_t *sec = buf + pe + 24 + optsz;
    for (int i = 0; i < nsec; i++, sec += 40) {
        uint32_t vsz = *(uint32_t *)(sec + 8), va = *(uint32_t *)(sec + 12);
        uint32_t rsz = *(uint32_t *)(sec + 16), rofs = *(uint32_t *)(sec + 20);
        uint32_t n = rsz < vsz ? rsz : vsz;
        if (vsz == 0) n = rsz;
        // uninitialised data (Watcom's .bss has a raw size but no file data): leave it zeroed
        if ((*(uint32_t *)(sec + 36) & 0x80) || rofs == 0 || rofs >= (uint32_t)sz) continue;
        if (rofs + n > (uint32_t)sz) n = (uint32_t)sz - rofs;
        (COW(base + va, (uint32_t)(n)), memcpy(G + base + va, buf + rofs, n));
    }
    free(buf);
    return 1;
}

extern GFunc shim_lookup(const char *dll, const char *name);

uint32_t host_resolve_import(const char *dll, const char *name) {
    GFunc fn = shim_lookup(dll, name);
    char *full = malloc(strlen(dll) + strlen(name) + 2);
    sprintf(full, "%s!%s", dll, name);
    if (!fn) host_log("note: import %s not implemented\n", full);
    if (fn) {
        for (int i = 0; i < n_thunks; i++) if (thunks[i].fn == fn) { free(full); return MAGIC_BASE + i * 4; }
    }
    if (n_thunks >= MAX_THUNKS) host_fatal("too many thunks");
    thunks[n_thunks].fn = fn; thunks[n_thunks].name = full;
    return MAGIC_BASE + (n_thunks++) * 4;
}

int runtime_init(const char *exe_path) {
    memset(G, 0, IMAGE_END);
    if (!load_pe(exe_path)) { host_log("cannot load %s\n", exe_path); return 0; }
    disp = calloc(TEXT_HI - TEXT_LO, sizeof(GFunc));
    for (int i = 0; i < rec_func_count; i++) {
        uint32_t a = rec_func_table[i].addr;
        if (a >= TEXT_LO && a < TEXT_HI) disp[a - TEXT_LO] = rec_func_table[i].fn;
    }
    for (int i = 0; i < rec_import_count; i++) {
        const char *nm = rec_imports[i].name;
        if (!strncmp(nm, "__imp_", 6)) nm += 6;
        W32(rec_imports[i].addr, host_resolve_import(rec_imports[i].dll, nm));
    }
    heap_init();
    // TEB
    W32(FS_BASE + 0, 0xffffffffu);
    W32(FS_BASE + 4, 0x00370000u);
    W32(FS_BASE + 8, 0x00010000u);
    W32(FS_BASE + 0x18, FS_BASE);
    fpu_init(); FCW = 0x27f;
    R.esp = 0x0036fff0u;
    return 1;
}

void runtime_run_entry(uint32_t entry) {
    R.esp -= 4; W32(R.esp, RET_MAGIC);
    call_ind(entry);
}
