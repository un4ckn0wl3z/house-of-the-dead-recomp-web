// Imports the template does not cover, for The House of the Dead: kernel32 threads/events/atoms/TLS/console,
// more user32 and GDI, WINMM (also reached through the _INMM.dll renames of CD-audio patched installs:
// _ci = mci, _ime = time, _mio = mmio, _ux = aux, _oy = joy), DirectX entry points and gamebios.dll (light guns).
#include "host.h"
#include "netplay.h"
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <ctype.h>

extern int g_mouse_x, g_mouse_y, g_mouse_buttons;
extern int g_mode_w, g_mode_h;
void post(uint32_t msg, uint32_t wp, uint32_t lp);
int user32_queue_empty(void);
void host_sleep(uint32_t ms);

// ---------------------------------------------------------------- game clock
// Natively and in single player the clock is real time. Online, every client derives it from the frame number
// (net_clock), so timers and the game advance identically everywhere.
uint32_t game_ticks(void) { return net_mode != NET_OFF ? net_clock() : host_ticks(); }

// ---------------------------------------------------------------- multimedia timers (timeSetEvent)
// The callbacks run on the main guest thread whenever the game waits, polls the clock or presents a frame.
typedef struct { int used, periodic; uint32_t delay, fn, user, id, next; } MMTimer;
static MMTimer timers[16];
static int in_timers;
void host_run_timers(void) {
    if (in_timers) return;
    in_timers = 1;
    uint32_t now = game_ticks();
    for (int i = 0; i < 16; i++) {
        MMTimer *t = &timers[i];
        if (!t->used) continue;
        int guard = 0;
        while (t->used && (int32_t)(now - t->next) >= 0 && guard++ < 8) {
            uint32_t fl = 0x10;                   // TIME_CALLBACK_FUNCTION
            (void)fl;
            Regs save = R;
            guest_call(t->fn, 5, t->id, 0, t->user, 0, 0);
            R.eax = save.eax; R.ecx = save.ecx; R.edx = save.edx;
            if (!t->periodic) { t->used = 0; break; }
            t->next += t->delay ? t->delay : 1;
        }
        if (guard >= 8) t->next = now + t->delay;  // fell far behind: skip ahead
    }
    in_timers = 0;
}
static void w_timeSetEvent(void) {
    uint32_t delay = ARG(0), fn = ARG(2), user = ARG(3), fl = ARG(4);
    for (int i = 0; i < 16; i++) if (!timers[i].used) {
        MMTimer *t = &timers[i];
        t->used = 1; t->periodic = fl & 1; t->delay = delay; t->fn = fn; t->user = user; t->id = 0x100 + i;
        t->next = game_ticks() + delay;
        host_log("timeSetEvent(%u ms, fn %08x, %s)\n", delay, fn, t->periodic ? "periodic" : "once");
        SRET(t->id, 5);
    }
    SRET(0, 5);
}
static void w_timeKillEvent(void) { uint32_t id = ARG(0); if (id >= 0x100 && id < 0x110) timers[id - 0x100].used = 0; SRET(0, 1); }
static void w_timeGetDevCaps(void) { W32(ARG(0), 1); W32(ARG(0) + 4, 1000000); SRET(0, 2); }
static void w_timeGetTime(void) { host_run_timers(); SRET(game_ticks(), 0); }
static void w_ret0_1(void) { SRET(0, 1); }
static void w_ret0_2(void) { SRET(0, 2); }
static void w_ret0_4(void) { SRET(0, 4); }
static void w_auxGetVolume(void) { if (ARG(1)) W32(ARG(1), 0xffffffffu); SRET(0, 2); }
static void w_auxGetDevCapsA(void) {
    uint32_t p = ARG(1), n = ARG(2);
    (COW(p, n), memset(G + p, 0, n));
    if (n >= 48) { strcpy(GSTR(p + 8), "CD Audio"); W16(p + 40, 1); W32(p + 44, 1); }   // AUXCAPS_CDAUDIO, VOLUME
    SRET(0, 3);
}
static void w_auxGetNumDevs(void) { SRET(1, 0); }
static void w_joyGetNumDevs(void) { SRET(0, 0); }
static void w_joyFail2(void) { SRET(167, 2); }   // JOYERR_UNPLUGGED
static void w_joyFail3(void) { SRET(167, 3); }

// mmio: plain file reads (used for WAV files)
static FILE **mmio_tab(void) { static FILE *mf[64]; return mf; }
static FILE *mmio_f(uint32_t h) { return h > 0x4D00 && h < 0x4D40 ? mmio_tab()[h - 0x4D00] : NULL; }
static void w_mmioOpenA2(void) {
    char path[1024];
    const char *name = ARG(0) ? GSTR(ARG(0)) : "";
    if (!fs_resolve(name, path, sizeof path, 0)) { host_log("mmioOpen %s: not found\n", name); SRET(0, 3); }
    FILE *f = fopen(path, "rb");
    if (!f) SRET(0, 3);
    for (int i = 1; i < 64; i++) if (!mmio_tab()[i]) { mmio_tab()[i] = f; SRET(0x4D00 + i, 3); }
    fclose(f);
    SRET(0, 3);
}
static void w_mmioClose(void) { FILE *f = mmio_f(ARG(0)); if (f) { fclose(f); mmio_tab()[ARG(0) - 0x4D00] = NULL; } SRET(0, 2); }
static void w_mmioRead(void) {
    FILE *f = mmio_f(ARG(0)); uint32_t p = ARG(1); int32_t n = (int32_t)ARG(2);
    if (!f || n < 0) SRET(0xffffffffu, 3);
    COW(p, (uint32_t)n);
    SRET((uint32_t)fread(G + p, 1, (size_t)n, f), 3);
}
static void w_mmioSeek(void) {
    FILE *f = mmio_f(ARG(0)); int32_t off = (int32_t)ARG(1); int org = (int)ARG(2);
    if (!f) SRET(0xffffffffu, 3);
    fseek(f, off, org == 0 ? SEEK_SET : org == 1 ? SEEK_CUR : SEEK_END);
    SRET((uint32_t)ftell(f), 3);
}

// MCI CD audio: "play cdaudio from N to M" etc. The music module plays MUSIC/trackNN.* (cdmusic.c).
void cdmusic_play(int from_track, int to_track);
void cdmusic_stop(void);
int cdmusic_playing(void);
int cdmusic_current_track(void);
int cdmusic_num_tracks(void);
static int mci_time_tmsf = 0;
static void w_mciSendStringA(void) {
    char cmd[512]; snprintf(cmd, sizeof cmd, "%s", ARG(0) ? GSTR(ARG(0)) : "");
    uint32_t ret = ARG(1), retn = ARG(2);
    char out[128] = "";
    for (char *c = cmd; *c; c++) *c = (char)tolower((unsigned char)*c);
    static uint32_t n; if (n++ < 200) host_log("mci: %s\n", cmd);
    if (strstr(cmd, "set") && strstr(cmd, "tmsf")) mci_time_tmsf = 1;
    if (!strncmp(cmd, "play", 4)) {
        int from = 2, to = 99;
        char *f = strstr(cmd, "from"), *t = strstr(cmd, " to ");
        if (f) from = atoi(f + 5);
        if (t) to = atoi(t + 4);
        cdmusic_play(from, to);
    } else if (!strncmp(cmd, "stop", 4) || !strncmp(cmd, "pause", 5)) {
        cdmusic_stop();
    } else if (!strncmp(cmd, "status", 6)) {
        if (strstr(cmd, "mode")) snprintf(out, sizeof out, "%s", cdmusic_playing() ? "playing" : "stopped");
        else if (strstr(cmd, "number of tracks")) snprintf(out, sizeof out, "%d", cdmusic_num_tracks());
        else if (strstr(cmd, "current track")) snprintf(out, sizeof out, "%d", cdmusic_current_track());
        else if (strstr(cmd, "media present")) snprintf(out, sizeof out, "true");
        else if (strstr(cmd, "ready")) snprintf(out, sizeof out, "true");
        else if (strstr(cmd, "type track")) snprintf(out, sizeof out, "audio");
        else if (strstr(cmd, "position")) snprintf(out, sizeof out, "%02d:00:00:00", cdmusic_current_track());
        else if (strstr(cmd, "length")) snprintf(out, sizeof out, "03:00:00");
    } else if (!strncmp(cmd, "info", 4)) {
        snprintf(out, sizeof out, "CD Audio");
    }
    if (ret && retn) { COW(ret, retn); snprintf(GSTR(ret), retn, "%s", out); }
    SRET(0, 4);
}

// ---------------------------------------------------------------- kernel32: events, threads, sync, atoms, TLS
#define MAXH 64
typedef struct { int used, kind, signaled, manual; uint32_t fn, param; int started, done; } KObj;   // kind 1 event 2 thread 3 mutex
static KObj K[MAXH];
#define KH(i) (0x2000u + (uint32_t)(i) * 4)
static KObj *kobj(uint32_t h) { if (h < 0x2000 || h >= KH(MAXH)) return NULL; KObj *k = &K[(h - 0x2000) / 4]; return k->used ? k : NULL; }
static int knew(int kind) { for (int i = 0; i < MAXH; i++) if (!K[i].used) { memset(&K[i], 0, sizeof K[i]); K[i].used = 1; K[i].kind = kind; return i; } host_fatal("too many kernel objects"); return 0; }

static void k_CreateEventA(void) {
    int i = knew(1); K[i].manual = ARG(1) != 0; K[i].signaled = ARG(2) != 0;
    SRET(KH(i), 4);
}
static void k_SetEvent(void) { KObj *k = kobj(ARG(0)); if (k) k->signaled = 1; SRET(1, 1); }
static void k_ResetEvent(void) { KObj *k = kobj(ARG(0)); if (k) k->signaled = 0; SRET(1, 1); }
static void k_CreateMutexA(void) { int i = knew(3); K[i].signaled = 1; SRET(KH(i), 3); }
static void k_ReleaseMutex(void) { KObj *k = kobj(ARG(0)); if (k) k->signaled = 1; SRET(1, 1); }

// Guest threads. The engine's threads are small service loops; each runs cooperatively on its own guest stack
// slice when the main thread waits (see host_idle). A thread that has not been scheduled yet starts there too.
// Recompiled code is not reentrant across real threads, so this keeps everything on one host thread.
void host_run_threads(void);
static void k_CreateThread(void) {
    uint32_t fn = ARG(2), param = ARG(3), flags = ARG(4), pid = ARG(5);
    int i = knew(2); K[i].fn = fn; K[i].param = param;
    host_log("CreateThread fn=%08x param=%08x flags=%x -> %08x\n", fn, param, flags, KH(i));
    if (pid) W32(pid, 0x200 + i);
    SRET(KH(i), 6);
}
static void k_TerminateThread(void) { KObj *k = kobj(ARG(0)); if (k) { k->done = 1; k->signaled = 1; } SRET(1, 2); }
static void k_ExitThread(void) { host_fatal("ExitThread from the main thread"); }
static void k_SetThreadPriority(void) { SRET(1, 2); }
static void k_GetCurrentThread(void) { SRET(0xfffffffeu, 0); }
static void k_GetCurrentThreadId(void) { SRET(0x100, 0); }
static void k_GetCurrentProcessId(void) { SRET(0x10, 0); }

void host_idle(void) {
    host_run_timers();
    host_run_threads();
    host_sleep(1);
}
static void k_WaitForSingleObject(void) {
    uint32_t h = ARG(0), ms = ARG(1);
    KObj *k = kobj(h);
    uint32_t t0 = host_ticks();
    for (;;) {
        if (!k) SRET(0xffffffffu, 2);
        if (k->signaled) { if (k->kind != 2 && !k->manual) k->signaled = 0; SRET(0, 2); }
        if (ms == 0) SRET(0x102, 2);
        host_idle();
        if (ms != 0xffffffffu && host_ticks() - t0 >= ms) SRET(0x102, 2);
        static uint32_t warned; if (ms == 0xffffffffu && host_ticks() - t0 > 5000 && !warned++) host_log("WaitForSingleObject(%08x, INFINITE) still waiting\n", h);
    }
}
static void k_Sleep(void) {
    uint32_t ms = ARG(0);
    host_run_timers();
    host_run_threads();
    host_sleep(ms);
    SRET(0, 1);
}
static void k_GetTickCount(void) { host_run_timers(); SRET(game_ticks(), 0); }

static char atoms[64][64];
static void k_GlobalAddAtomA(void) {
    const char *s = GSTR(ARG(0));
    for (int i = 0; i < 64; i++) if (atoms[i][0] && !strcasecmp(atoms[i], s)) SRET(0xC000 + i, 1);
    for (int i = 0; i < 64; i++) if (!atoms[i][0]) { snprintf(atoms[i], 64, "%s", s); SRET(0xC000 + i, 1); }
    SRET(0, 1);
}
static void k_GlobalFindAtomA(void) {
    const char *s = GSTR(ARG(0));
    for (int i = 0; i < 64; i++) if (atoms[i][0] && !strcasecmp(atoms[i], s)) SRET(0xC000 + i, 1);
    SRET(0, 1);
}
static void k_GlobalDeleteAtom(void) { uint32_t a = ARG(0); if (a >= 0xC000 && a < 0xC040) atoms[a - 0xC000][0] = 0; SRET(0, 1); }
// Global memory: handles are the pointers
static void k_GlobalAlloc(void) {
    uint32_t fl = ARG(0), n = ARG(1);
    uint32_t p = heap_alloc(n ? n : 1);
    if (p && (fl & 0x40)) (COW(p, n), memset(G + p, 0, n));
    SRET(p, 2);
}
static void k_GlobalFree(void) { heap_free(ARG(0)); SRET(0, 1); }
static void k_GlobalLock(void) { SRET(ARG(0), 1); }
static void k_GlobalUnlock(void) { SRET(1, 1); }
static void k_GlobalHandle(void) { SRET(ARG(0), 1); }
static void k_GetDriveTypeA(void) {
    // the CD check: the game folder doubles as the CD (DISK1.ID lives there)
    host_log("GetDriveType(%s)\n", ARG(0) ? GSTR(ARG(0)) : "");
    SRET(5, 1);   // DRIVE_CDROM
}
static uint32_t tls[64]; static int ntls;
static void k_TlsAlloc(void) { SRET(ntls < 64 ? (uint32_t)ntls++ : 0xffffffffu, 0); }
static void k_TlsFree(void) { SRET(1, 1); }
static void k_TlsGetValue(void) { SRET(ARG(0) < 64 ? tls[ARG(0)] : 0, 1); }
static void k_TlsSetValue(void) { if (ARG(0) < 64) tls[ARG(0)] = ARG(1); SRET(1, 2); }
static void k_GetConsoleMode(void) { SRET(0, 2); }
static void k_SetConsoleMode(void) { SRET(1, 2); }
static void k_SetConsoleCtrlHandler(void) { SRET(1, 2); }
static void k_ReadConsoleInputA(void) { if (ARG(3)) W32(ARG(3), 0); SRET(0, 4); }
static void k_WriteConsoleA(void) { host_log("%.*s", (int)ARG(2), GSTR(ARG(1))); if (ARG(3)) W32(ARG(3), ARG(2)); SRET(1, 5); }

// ---------------------------------------------------------------- user32 extras
static uint32_t wnd_long[64];
static void u_AdjustWindowRect(void) { SRET(1, 3); }
static void u_BeginPaint(void) { uint32_t ps = ARG(1); (COW(ps, 64), memset(G + ps, 0, 64)); W32(ps, 0x00050003); SRET(0x00050003, 2); }
static void u_EndPaint(void) { SRET(1, 2); }
static void u_ok1(void) { SRET(1, 1); }
static void u_ok2(void) { SRET(1, 2); }
static void u_ok3(void) { SRET(1, 3); }
static void u_ret0_1(void) { SRET(0, 1); }
static void u_ret0_2(void) { SRET(0, 2); }
static void u_ret0_3(void) { SRET(0, 3); }
static void u_ClipCursor(void) { SRET(1, 1); }
static void u_GetClipCursor(void) { uint32_t r = ARG(0); W32(r, 0); W32(r + 4, 0); W32(r + 8, g_mode_w); W32(r + 12, g_mode_h); SRET(1, 1); }
// the pointer and buttons as this frame's input record has them (gun_input.c: the same on every client online)
int net_pointer(int *x, int *y);
int input_mouse_buttons(void);
static void u_GetCursorPos(void) { int x, y; net_pointer(&x, &y); W32(ARG(0), (uint32_t)x); W32(ARG(0) + 4, (uint32_t)y); SRET(1, 1); }
static void u_DestroyWindow(void) { host_log("DestroyWindow\n"); post(0x02, 0, 0); SRET(1, 1); }
static void u_FindWindowA(void) { SRET(0, 2); }       // no other instance running
static void u_GetAsyncKeyState(void) {
    uint32_t vk = ARG(0);
    int down = 0, b = input_mouse_buttons();
    if (vk == 1) down = b & 1; else if (vk == 2) down = b & 2; else if (vk == 4) down = b & 4;
    else if (net_mode == NET_OFF) { extern uint8_t vk_state[256]; down = vk < 256 && vk_state[vk]; }
    SRET(down ? 0x8001 : 0, 1);
}
static void u_GetKeyboardState(void) {
    extern uint8_t vk_state[256];
    uint32_t p = ARG(0);
    for (int i = 0; i < 256; i++) W8(p + i, net_mode == NET_OFF && vk_state[i] ? 0x80 : 0);
    SRET(1, 1);
}
static void u_GetKeyboardType(void) { int32_t t = (int32_t)ARG(0); SRET(t == 0 ? 4 : t == 2 ? 12 : 0, 1); }
static void u_GetMenu(void) { SRET(0, 1); }
static void u_GetParent(void) { SRET(0, 1); }
static void u_GetSysColor(void) { SRET(0xC0C0C0, 1); }
static void u_GetWindowLongA(void) { int32_t i = (int32_t)ARG(1); SRET(i == -4 ? g_wndproc : (i >= 0 && i < 256) ? wnd_long[i / 4] : 0, 2); }
static void u_SetWindowLongA(void) {
    int32_t i = (int32_t)ARG(1); uint32_t v = ARG(2), old = 0;
    if (i == -4) { old = g_wndproc; g_wndproc = v; }
    else if (i >= 0 && i < 256) { old = wnd_long[i / 4]; wnd_long[i / 4] = v; }
    SRET(old, 3);
}
static void u_GetWindowTextA(void) { if (ARG(2)) W8(ARG(1), 0); SRET(0, 3); }
static void u_IsDlgButtonChecked(void) { SRET(0, 2); }
static void u_IsMenu(void) { SRET(0, 1); }
// window timers: WM_TIMER is posted from the message pump when due (wndtimers_poll, user32.c)
typedef struct { uint32_t id, ms, next, proc; int used; } WTimer;
static WTimer wt[16];
void wndtimers_poll(void) {
    uint32_t now = game_ticks();
    for (int i = 0; i < 16; i++) if (wt[i].used && (int32_t)(now - wt[i].next) >= 0) {
        wt[i].next = now + (wt[i].ms ? wt[i].ms : 1);
        post(0x113, wt[i].id, wt[i].proc);
    }
}
static void u_SetTimer(void) {
    uint32_t id = ARG(1) ? ARG(1) : 1, ms = ARG(2), proc = ARG(3);
    int f = -1;
    for (int i = 0; i < 16; i++) if (wt[i].used && wt[i].id == id) f = i;
    for (int i = 0; i < 16 && f < 0; i++) if (!wt[i].used) f = i;
    if (f < 0) SRET(0, 4);
    wt[f].used = 1; wt[f].id = id; wt[f].ms = ms; wt[f].proc = proc; wt[f].next = game_ticks() + ms;
    host_log("SetTimer id %u, %u ms, proc %08x\n", id, ms, proc);
    SRET(id, 4);
}
static void u_KillTimer(void) {
    for (int i = 0; i < 16; i++) if (wt[i].used && wt[i].id == ARG(1)) wt[i].used = 0;
    SRET(1, 2);
}
static void u_LoadImageA(void) { SRET(0x000B0001, 6); }
static void u_LoadMenuA(void) { SRET(0, 2); }
static void u_LoadStringA(void) { if (ARG(3)) W8(ARG(2), 0); SRET(0, 4); }
static void u_MapWindowPoints(void) { SRET(0, 4); }
static void u_MoveWindow(void) { SRET(1, 6); }
static void u_SetFocus(void) { SRET(g_hwnd, 1); }
static void u_SetRect(void) { uint32_t r = ARG(0); W32(r, ARG(1)); W32(r + 4, ARG(2)); W32(r + 8, ARG(3)); W32(r + 12, ARG(4)); SRET(1, 5); }
static void u_GetActiveWindow(void) { SRET(g_hwnd, 0); }
static void u_SendMessageA(void) {
    uint32_t r = 0;
    if (ARG(0) == g_hwnd && g_wndproc) r = guest_call(g_wndproc, 4, ARG(0), ARG(1), ARG(2), ARG(3));
    SRET(r, 4);
}
// wsprintfA is cdecl with varargs: (buf, fmt, ...)
static void u_wsprintfA(void) {
    uint32_t buf = ARG(0), fmt = ARG(1), ap = R.esp + 12;
    char out[1025]; int o = 0;
    for (const char *f = GSTR(fmt); *f && o < 1024; f++) {
        if (*f != '%') { out[o++] = *f; continue; }
        char spec[32]; int sl = 0; spec[sl++] = '%'; f++;
        while (*f && strchr("-+ #0123456789.lh", *f) && sl < 28) spec[sl++] = *f++;
        if (!*f) break;
        char conv = *f; spec[sl++] = conv; spec[sl] = 0;
        char tmp[512];
        if (conv == 's') snprintf(tmp, sizeof tmp, spec, R32(ap) ? GSTR(R32(ap)) : "(null)");
        else if (conv == 'c') snprintf(tmp, sizeof tmp, "%c", (char)R32(ap));
        else if (conv == '%') { out[o++] = '%'; continue; }
        else {
            // drop size prefixes: guest ints are 32-bit
            char s2[32]; int k = 0; for (int i = 0; i < sl; i++) if (spec[i] != 'l' && spec[i] != 'h') s2[k++] = spec[i]; s2[k] = 0;
            snprintf(tmp, sizeof tmp, s2, R32(ap));
        }
        ap += 4;
        for (const char *t = tmp; *t && o < 1024; t++) out[o++] = *t;
    }
    out[o] = 0;
    COW(buf, (uint32_t)o + 1); memcpy(G + buf, out, (size_t)o + 1);
    R.eax = (uint32_t)o; R.esp += 4;
}

// ---------------------------------------------------------------- gdi extras
static void g_BitBlt(void) { SRET(1, 9); }
static void g_CreateSolidBrush(void) { SRET(0x000C0001, 1); }
static void g_GetSystemPaletteEntries(void) {
    uint32_t start = ARG(1), n = ARG(2), p = ARG(3);
    for (uint32_t i = 0; i < n; i++) W32(p + i * 4, ((start + i) & 0xff) * 0x010101u);
    SRET(n, 4);
}
static void g_GetTextMetricsA(void) { uint32_t p = ARG(1); (COW(p, 56), memset(G + p, 0, 56)); W32(p, 16); W32(p + 4, 13); W32(p + 20, 8); W32(p + 24, 16); SRET(1, 2); }

// ---------------------------------------------------------------- gamebios.dll: arcade light guns (cdecl)
// Two guns. Each client's mouse drives its own gun (gun_input.c fills g_gun[] for the frame, locally or from the
// online relay). Position 0x3FF,0x3FF means "pointing off screen" (reload).
typedef struct { int x, y; uint32_t buttons; } Gun;
Gun g_gun[2];
void gun_update_local(void);
static void gb_InitDeviceDriver(void) { host_log("gbInitDeviceDriver: two emulated light guns\n"); R.eax = 1; R.esp += 4; }
static void gb_SetScreenMode(void) { host_log("gblSetScreenMode(%u)\n", ARG(0)); R.eax = 1; R.esp += 4; }
static void gb_GetButtonStatus(void) {
    uint32_t n = ARG(0);
    if (n == 0) gun_update_local();
    R.eax = n < 2 ? g_gun[n].buttons : 0; R.esp += 4;
}
static void gb_GetCursorPosition(void) {
    uint32_t n = ARG(0), px = ARG(1), py = ARG(2);
    Gun *g = &g_gun[n < 2 ? n : 0];
    if (px) W32(px, (uint32_t)g->x);
    if (py) W32(py, (uint32_t)g->y);
    R.eax = 1; R.esp += 4;
}

// ---------------------------------------------------------------- DirectX entry points
void shim_DirectDrawCreate(void);
void shim_DirectDrawEnumerateA(void);
void shim_DirectInputCreateA(void);
void shim_DirectSoundCreate8(void);

const ShimDef shims_hotd[] = {
    {"KERNEL32", "CreateEventA", k_CreateEventA}, {"KERNEL32", "SetEvent", k_SetEvent},
    {"KERNEL32", "ResetEvent", k_ResetEvent}, {"KERNEL32", "CreateMutexA", k_CreateMutexA},
    {"KERNEL32", "ReleaseMutex", k_ReleaseMutex}, {"KERNEL32", "CreateThread", k_CreateThread},
    {"KERNEL32", "TerminateThread", k_TerminateThread}, {"KERNEL32", "ExitThread", k_ExitThread},
    {"KERNEL32", "SetThreadPriority", k_SetThreadPriority}, {"KERNEL32", "GetCurrentThread", k_GetCurrentThread},
    {"KERNEL32", "GetCurrentThreadId", k_GetCurrentThreadId}, {"KERNEL32", "GetCurrentProcessId", k_GetCurrentProcessId},
    {"KERNEL32", "WaitForSingleObject", k_WaitForSingleObject}, {"KERNEL32", "Sleep", k_Sleep},
    {"KERNEL32", "GetTickCount", k_GetTickCount},
    {"KERNEL32", "GlobalAddAtomA", k_GlobalAddAtomA}, {"KERNEL32", "GlobalFindAtomA", k_GlobalFindAtomA},
    {"KERNEL32", "GlobalDeleteAtom", k_GlobalDeleteAtom}, {"KERNEL32", "GlobalAlloc", k_GlobalAlloc},
    {"KERNEL32", "GlobalFree", k_GlobalFree}, {"KERNEL32", "GlobalLock", k_GlobalLock},
    {"KERNEL32", "GlobalUnlock", k_GlobalUnlock}, {"KERNEL32", "GlobalHandle", k_GlobalHandle},
    {"KERNEL32", "GetDriveTypeA", k_GetDriveTypeA},
    {"KERNEL32", "TlsAlloc", k_TlsAlloc}, {"KERNEL32", "TlsFree", k_TlsFree},
    {"KERNEL32", "TlsGetValue", k_TlsGetValue}, {"KERNEL32", "TlsSetValue", k_TlsSetValue},
    {"KERNEL32", "GetConsoleMode", k_GetConsoleMode}, {"KERNEL32", "SetConsoleMode", k_SetConsoleMode},
    {"KERNEL32", "SetConsoleCtrlHandler", k_SetConsoleCtrlHandler}, {"KERNEL32", "ReadConsoleInputA", k_ReadConsoleInputA},
    {"KERNEL32", "WriteConsoleA", k_WriteConsoleA},
    {"USER32", "AdjustWindowRect", u_AdjustWindowRect}, {"USER32", "BeginPaint", u_BeginPaint},
    {"USER32", "EndPaint", u_EndPaint}, {"USER32", "CheckDlgButton", u_ok3}, {"USER32", "CheckMenuItem", u_ret0_3},
    {"USER32", "ClipCursor", u_ClipCursor}, {"USER32", "GetClipCursor", u_GetClipCursor},
    {"USER32", "GetCursorPos", u_GetCursorPos}, {"USER32", "DestroyWindow", u_DestroyWindow},
    {"USER32", "FindWindowA", u_FindWindowA}, {"USER32", "GetAsyncKeyState", u_GetAsyncKeyState},
    {"USER32", "GetKeyboardState", u_GetKeyboardState}, {"USER32", "GetKeyboardType", u_GetKeyboardType},
    {"USER32", "GetMenu", u_GetMenu}, {"USER32", "GetParent", u_GetParent}, {"USER32", "GetSysColor", u_GetSysColor},
    {"USER32", "GetWindowLongA", u_GetWindowLongA}, {"USER32", "SetWindowLongA", u_SetWindowLongA},
    {"USER32", "GetWindowTextA", u_GetWindowTextA}, {"USER32", "InvalidateRect", u_ok3},
    {"USER32", "IsDlgButtonChecked", u_IsDlgButtonChecked}, {"USER32", "IsMenu", u_IsMenu},
    {"USER32", "KillTimer", u_KillTimer}, {"USER32", "SetTimer", u_SetTimer}, {"USER32", "LoadImageA", u_LoadImageA},
    {"USER32", "LoadMenuA", u_LoadMenuA}, {"USER32", "LoadStringA", u_LoadStringA},
    {"USER32", "MapWindowPoints", u_MapWindowPoints}, {"USER32", "MoveWindow", u_MoveWindow},
    {"USER32", "SetFocus", u_SetFocus}, {"USER32", "SetMenu", u_ok2}, {"USER32", "SetRect", u_SetRect},
    {"USER32", "GetActiveWindow", u_GetActiveWindow}, {"USER32", "SendMessageA", u_SendMessageA},
    {"USER32", "wsprintfA", u_wsprintfA}, {"USER32", "GetDlgItem", u_ret0_2}, {"USER32", "ok1", u_ok1},
    {"USER32", "nop", u_ret0_1},
    {"GDI32", "BitBlt", g_BitBlt}, {"GDI32", "CreateSolidBrush", g_CreateSolidBrush},
    {"GDI32", "GetSystemPaletteEntries", g_GetSystemPaletteEntries}, {"GDI32", "GetTextMetricsA", g_GetTextMetricsA},
    {"WINMM", "timeGetTime", w_timeGetTime}, {"WINMM", "timeBeginPeriod", w_ret0_1}, {"WINMM", "timeEndPeriod", w_ret0_1},
    {"WINMM", "timeGetDevCaps", w_timeGetDevCaps}, {"WINMM", "timeSetEvent", w_timeSetEvent},
    {"WINMM", "timeKillEvent", w_timeKillEvent}, {"WINMM", "mciSendStringA", w_mciSendStringA},
    {"WINMM", "auxGetDevCapsA", w_auxGetDevCapsA}, {"WINMM", "auxGetNumDevs", w_auxGetNumDevs},
    {"WINMM", "auxGetVolume", w_auxGetVolume}, {"WINMM", "auxSetVolume", w_ret0_2},
    {"WINMM", "joyGetDevCapsA", w_joyFail3}, {"WINMM", "joyGetNumDevs", w_joyGetNumDevs},
    {"WINMM", "joyGetPos", w_joyFail2}, {"WINMM", "joyGetPosEx", w_joyFail2},
    {"WINMM", "mmioOpenA", w_mmioOpenA2}, {"WINMM", "mmioClose", w_mmioClose}, {"WINMM", "mmioRead", w_mmioRead},
    {"WINMM", "mmioSeek", w_mmioSeek}, {"WINMM", "mmioSetBuffer", w_ret0_4},
    {"gamebios", "gbInitDeviceDriver", gb_InitDeviceDriver}, {"gamebios", "gblSetScreenMode", gb_SetScreenMode},
    {"gamebios", "gblGetButtonStatus", gb_GetButtonStatus}, {"gamebios", "gblGetCursorPosition", gb_GetCursorPosition},
    {"DDRAW", "DirectDrawCreate", shim_DirectDrawCreate}, {"DDRAW", "DirectDrawEnumerateA", shim_DirectDrawEnumerateA},
    {"DINPUT", "DirectInputCreateA", shim_DirectInputCreateA},
    {"DSOUND", "DirectSoundCreate", shim_DirectSoundCreate8},
    {0, 0, 0}
};
