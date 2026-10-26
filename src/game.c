// Game-specific glue for The House of the Dead.
//
// Natively the game runs its own main loop. On the web the recompiler replaces that loop with a call to
// host_frame_loop() (a hook in recomp_config.json) so the browser drives frames: port_frame_once() then does
// exactly one pass of the original loop body and returns nonzero when the game wants to quit.
#include "host.h"
#include "netplay.h"
#include <stdlib.h>

void host_run_timers(void);
void cdmusic_poll(void);

// The game's debug logger, debug_log(level, fmt, ...), is an empty function in the release build
// (recomp_config.json "hle"): print its messages, at most a few times each.
void hle_game_log(void) {
    uint32_t fmt = R32(R.esp + 8);
    static uint32_t seen[256]; static int nseen;
    int i;
    for (i = 0; i < nseen && seen[i] != fmt; i++) {}
    if (i == nseen && nseen < 256) seen[nseen++] = fmt;
    static int count[256];
    if (i < 256 && count[i]++ < 3)
        host_log("game: [%u] %s (%08x %08x)\n", R32(R.esp + 4), fmt ? GSTR(fmt) : "", R32(R.esp + 12), R32(R.esp + 16));
    R.esp += 4;
}

// Control devices: P1 at 0xd5b200, P2 at 0xd5b204 (0 mouse, 1-2 keyboard, 3-4 joystick, 5-6 light gun 1-2).
// Both players use the emulated light guns (gamebios.dll, gun_input.c): absolute aim at the pointer as on the
// cabinet, and the same input path for local and online players. PORT_CONTROLS=original keeps the game's choice.
#define GUNS_PRESENT 0x005CD354u
#define DEV_P1       0x00D5B200u
#define DEV_P2       0x00D5B204u
static void force_light_guns(void) {
    static int keep = -1;
    if (keep < 0) { const char *e = getenv("PORT_CONTROLS"); keep = e && !strcmp(e, "original"); }
    if (keep || !R32(GUNS_PRESENT)) return;
    if (R32(DEV_P1) != 5) W32(DEV_P1, 5);
    if (R32(DEV_P2) != 6) W32(DEV_P2, 6);
}

// The game turns DirectInput mouse motion into two cursors: the input layer's (0x12fdb90/94, clamped sum) and
// the menus' hand (0xd5a97c/80, scaled motion). Put both under the pointer and report no motion, so the hand
// follows the pointer exactly (dinput.c calls this when the game reads the mouse).
#define MOUSE_SUM_X   0x012FDB90u
#define MOUSE_SUM_Y   0x012FDB94u
#define MENU_HAND_X   0x00D5A97Cu
#define MENU_HAND_Y   0x00D5A980u
void port_mouse_motion(int *dx, int *dy) {
    extern int g_mouse_x, g_mouse_y;
    int x = g_mouse_x, y = g_mouse_y;
    extern int net_pointer(int *x, int *y);   // this frame's pointer (gun_input.c; online: the host's)
    net_pointer(&x, &y);
    W32(MOUSE_SUM_X, (uint32_t)x); W32(MOUSE_SUM_Y, (uint32_t)y);
    W32(MENU_HAND_X, (uint32_t)x); W32(MENU_HAND_Y, (uint32_t)y);
    *dx = *dy = 0;
}

// after every presented frame (ddraw.c)
void host_frame_presented(void) {
#ifndef __EMSCRIPTEN__
    cdmusic_poll();
#endif
    force_light_guns();
    host_run_timers();
}

// guest threads created with CreateThread (hotd_shims.c); scheduled while the main thread waits
void host_run_threads(void) {
}

// WinMain (0x563440) ends in
//     while (app_flags & 1) tick(3);          // 0x563614: test byte [0xc64b14], 1 / mov eax, 3 / call 0x562e30
// tick() pumps messages, runs the game's update / render / present events and waits for the frame time.
#define APP_FLAGS   0x00C64B14u
#define TICK_FN     0x00562E30u
int port_frame_once(void) {
    if (!(R8(APP_FLAGS) & 1)) { host_log("game loop ended (app flags %02x)\n", R8(APP_FLAGS)); return 1; }
    extern void input_frame_begin(void);
    net_frame_begin();
    input_frame_begin();                // this frame's input record (gun_input.c), from the bundle when online
    // A tick that finds a window message only dispatches it and draws nothing: tick until a frame was presented
    // (at most a few times), so the browser gets a picture on every animation frame.
    uint32_t before = host_frame_count();
    for (int i = 0; i < 8 && host_frame_count() == before && (R8(APP_FLAGS) & 1); i++) {
        Regs save = R;
        R.eax = 3;
        guest_call(TICK_FN, 0);
        R = save;
    }
    return 0;
}

void port_after_loop(void) {
}

// ---------------------------------------------------------------- online play
// Two players share one screen, as on the arcade cabinet: only the guns travel (netplay.c / gun_input.c).
// Online desync check: the image's data and bss (0x5a0000-0x138d400) hold the whole simulation
// (objects, enemies, players, the random seed); heap blocks are reached from there.
#define STATE_LO 0x005A0000u
#define STATE_HI 0x0138D400u
uint32_t port_state_crc(uint32_t h) {
    uint64_t x = h;
    for (uint32_t a = STATE_LO; a < STATE_HI; a += 8) { uint64_t v; memcpy(&v, G + a, 8); x = (x ^ v) * 0x100000001b3ull; }
    return (uint32_t)(x ^ (x >> 32));
}
void port_view_camera(int slot, float *x, float *y) { (void)slot; *x = *y = 0; }
