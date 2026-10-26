// Runtime interface for recompiled x86 code.
#pragma once
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <setjmp.h>
#include "port_config.h"
#include "rec_config.h"

#define GUEST_SIZE   ((uint32_t)GUEST_SIZE_MB << 20)
#define FS_BASE      0x00380000u      // fake TEB
#define MAGIC_BASE   0xFF000000u      // host thunk addresses
#define RET_MAGIC    0xFFFFFFF0u      // return address for host->guest calls

extern uint8_t G[];

typedef struct { uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi; } Regs;
extern Regs R;
extern uint32_t DF;

// x87 state
extern double FPR[8];
extern uint32_t FTOP, FSW_CC, FCW;
#define ST0 FPR[FTOP]
#define STI(i) FPR[(FTOP + (i)) & 7]
#define FPUSH(v) do { double _v = (v); FTOP = (FTOP - 1) & 7; FPR[FTOP] = _v; } while (0)
#define FPOP() (FTOP = (FTOP + 1) & 7)

#define LOAD_REGS() \
    uint32_t eax = R.eax, ecx = R.ecx, edx = R.edx, ebx = R.ebx, esp = R.esp, ebp = R.ebp, esi = R.esi, edi = R.edi; \
    uint32_t cf = 0, pf = 0, zf = 0, sf = 0, of = 0
// -DFUNC_TRACE: count entries of every recompiled function (runtime.c dumps them at exit, PORT_TRACE=file)
#ifdef FUNC_TRACE
void ftrace_hit(uint32_t a);
#define FTRACE(a) ftrace_hit(a)
#else
#define FTRACE(a) ((void)0)
#endif
#define SPILL()(R.eax = eax, R.ecx = ecx, R.edx = edx, R.ebx = ebx, R.esp = esp, R.ebp = ebp, R.esi = esi, R.edi = edi)
#define RELOAD() (eax = R.eax, ecx = R.ecx, edx = R.edx, ebx = R.ebx, esp = R.esp, ebp = R.ebp, esi = R.esi, edi = R.edi)

#ifdef MEMCHECK
void guest_memfault(uint32_t a, int n);
#define CHK(a, n) do { if ((uint32_t)(a) > GUEST_SIZE - (n)) guest_memfault(a, n); } while (0)
#else
#define CHK(a, n) ((void)0)
#endif

// Undoable passes (netplay.c: a client drawing its own view in an online game): while g_cow is set, the first
// write to each 4 KB page of guest memory saves the page, and net_cow_end() copies the pages back. Every write
// below and every host-side write into G (memcpy/memset/fread into guest memory) must go through COW().
extern int g_cow;
void cow_range(uint32_t a, uint32_t n);
#define COW(a, n) (g_cow ? cow_range((a), (n)) : (void)0)

static inline uint32_t R8(uint32_t a) { CHK(a, 1); return G[a]; }
static inline uint32_t R16(uint32_t a) { CHK(a, 2); uint16_t v; memcpy(&v, G + a, 2); return v; }
static inline uint32_t R32(uint32_t a) { CHK(a, 4); uint32_t v; memcpy(&v, G + a, 4); return v; }
static inline uint64_t R64(uint32_t a) { CHK(a, 8); uint64_t v; memcpy(&v, G + a, 8); return v; }
static inline void W8(uint32_t a, uint32_t v) { CHK(a, 1); COW(a, 1); G[a] = (uint8_t)v; }
static inline void W16(uint32_t a, uint32_t v) { CHK(a, 2); COW(a, 2); uint16_t x = (uint16_t)v; memcpy(G + a, &x, 2); }
static inline void W32(uint32_t a, uint32_t v) { CHK(a, 4); COW(a, 4); memcpy(G + a, &v, 4); }
static inline void W64(uint32_t a, uint64_t v) { CHK(a, 8); COW(a, 8); memcpy(G + a, &v, 8); }
// x87 precision control (FCW bits 8-9): with 00 (24-bit) the FPU rounds every arithmetic result to single
// precision. Games switch to it for speed around their rasterisers (House of the Dead: span setup), and their edge
// and texture-gradient maths is tuned to it; computing those in double draws different pixels. 53/64-bit -> double.
static inline double PREC(double x) { return (FCW & 0x300u) ? x : (double)(float)x; }
static inline double F32(uint32_t a) { CHK(a, 4); float f; memcpy(&f, G + a, 4); return f; }
static inline double F64(uint32_t a) { CHK(a, 8); double d; memcpy(&d, G + a, 8); return d; }
static inline void WF32(uint32_t a, double v) { CHK(a, 4); COW(a, 4); float f = (float)v; memcpy(G + a, &f, 4); }
static inline void WF64(uint32_t a, double v) { CHK(a, 8); COW(a, 8); memcpy(G + a, &v, 8); }
double F80(uint32_t a);
void WF80(uint32_t a, double v);

// x87 helpers
void fpu_com(double a, double b);
uint32_t fpu_sw(void);
int32_t fpu_toint32(double v);
int16_t fpu_toint16(double v);
int64_t fpu_toint64(double v);
double fpu_round(double v);
void fpu_xam(void);
void fpu_prem(int ieee);
void fpu_xtract(void);
void fpu_ldenv(uint32_t a);
void fpu_stenv(uint32_t a);
void fpu_rstor(uint32_t a);
void fpu_save(uint32_t a);
void fpu_init(void);
uint64_t mmx_paddusb(uint64_t a, uint64_t b);

// misc
void guest_movs(uint32_t dst, uint32_t src, uint32_t count, uint32_t elsize);
void guest_stos8(uint32_t dst, uint32_t v, uint32_t count);
void guest_stos16(uint32_t dst, uint32_t v, uint32_t count);
void guest_stos32(uint32_t dst, uint32_t v, uint32_t count);
uint32_t guest_divzero(uint32_t addr);
void guest_int(int n, uint32_t addr);
void guest_unsupported(uint32_t addr);
// what the game sees from cpuid / rdtsc (recomp.py emits calls to these)
void host_cpuid(uint32_t leaf, uint32_t sub, uint32_t out[4]);
uint64_t host_rdtsc(void);
// guest setjmp/longjmp: the C frame of the function that called _setjmp3 holds the host jmp_buf
typedef struct { jmp_buf env; uint32_t gbuf, seh; Regs r; } GJmp;
GJmp *hle_setjmp3_slot(void);
GJmp *hle_setjmp_wc_slot(void);   // Watcom: jmp_buf in eax
void guest_badaddr(uint32_t addr);
void guest_badjump(uint32_t addr, uint32_t target);
void guest_noreturn(uint32_t addr);
void call_ind(uint32_t addr);

typedef void (*GFunc)(void);
typedef struct { uint32_t addr; GFunc fn; } FuncEntry;
typedef struct { uint32_t addr; const char *dll; const char *name; } ImportEntry;
extern const FuncEntry rec_func_table[];
extern const int rec_func_count;
extern const ImportEntry rec_imports[];
extern const int rec_import_count;

// HLE replacements and hook targets are declared in rec_config.h (generated).

#include "rec_funcs.h"
