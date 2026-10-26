// Host-side declarations shared by the Win32 / DirectX shim layer.
#pragma once
#include <stdint.h>
#include "recomp.h"

void host_log(const char *fmt, ...);
void host_fatal(const char *fmt, ...);
void host_backtrace(void);
void host_shutdown(void);

uint32_t guest_call(uint32_t fn, int nargs, ...);
uint32_t guest_call_this(uint32_t fn, uint32_t self, int nargs, ...);
int port_frame_once(void);      // game.c
void port_after_loop(void);     // game.c
uint32_t host_frame_count(void);
uint32_t host_thunk(GFunc fn, const char *name);
GFunc host_override(uint32_t addr, GFunc fn);   // runtime.c: replace a function for indirect calls
uint32_t host_resolve_import(const char *dll, const char *name);

uint32_t heap_alloc(uint32_t n);
void heap_free(uint32_t p);
uint32_t heap_size(uint32_t p);
uint32_t heap_realloc(uint32_t p, uint32_t n);
uint32_t heap_peak_bytes(void);
uint32_t heap_used_bytes(void);
// the game's registry values as the shim stores them (keypath like "HKCU\SOFTWARE\Company\Game"), misc.c
int reg_get_value(const char *keypath, const char *name, char *out, int outsz);
void reg_set_value(const char *keypath, const char *name, const char *value);
uint32_t guest_static_alloc(uint32_t n);
uint32_t guest_strdup(const char *s);

int runtime_init(const char *exe_path);
void runtime_run_entry(uint32_t entry);

// stdcall shim helpers: args start at esp+4
#define ARG(n) R32(R.esp + 4 + 4 * (n))
#define SRET(v, nargs) do { R.eax = (uint32_t)(v); R.esp += 4 + 4 * (nargs); return; } while (0)
#define GSTR(a) ((char *)G + (a))
#define GPTR(a) ((void *)(G + (a)))

typedef struct { const char *dll; const char *name; GFunc fn; } ShimDef;
extern const ShimDef shims_kernel32[], shims_user32[], shims_gdi32[], shims_misc[];

// file system helpers (case-insensitive path mapping)
int fs_resolve(const char *guest_path, char *out, int outsz, int for_write);
extern char g_game_dir[512];

// window / input (user32.c)
extern uint32_t g_hwnd, g_wndproc;
extern int g_win_w, g_win_h;
void user32_pump_events(void);
void host_present_frame(void);
uint32_t host_ticks(void);
void host_yield(void);

// COM helpers
uint32_t com_vtable(int n, const GFunc *methods, const char *prefix);
uint32_t com_new(uint32_t vtbl, uint32_t size);

// d3d / dsound
void d3d8_create(void);
void dsound_create(void);
void audio_init(void);
void audio_shutdown(void);
void gfx_shutdown(void);
