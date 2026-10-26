// Host entry point: init SDL, load the game image, run the recompiled CRT entry.
#include "host.h"
#include "netplay.h"
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif


extern char g_save_dir[512];
int g_fs_dirty;

uint32_t host_ticks(void) { return SDL_GetTicks(); }
uint64_t host_time_ns(void) {
    static uint64_t f;
    if (!f) f = SDL_GetPerformanceFrequency();
    return (uint64_t)((double)SDL_GetPerformanceCounter() * (1e9 / (double)f));
}
void host_yield(void) {
#ifndef __EMSCRIPTEN__
    SDL_Delay(1);
#endif
}
void host_sleep(uint32_t ms) {
#ifndef __EMSCRIPTEN__
    if (ms > 200) ms = 200;
    SDL_Delay(ms);
#else
    (void)ms;
#endif
}

void host_shutdown(void) {
    static int done;
    if (done) return;
    done = 1;
#ifdef FUNC_TRACE
    { void ftrace_dump(void); ftrace_dump(); }
#endif
    host_log("shutdown: guest heap used %u KB, peak %u KB\n", heap_used_bytes() >> 10, heap_peak_bytes() >> 10);
    audio_shutdown();
    SDL_Quit();
}

void host_sync_fs(void) {
#ifdef __EMSCRIPTEN__
    if (!g_fs_dirty || net_mode == NET_GUEST) return;   // an online guest's saves live in memory only
    g_fs_dirty = 0;
    EM_ASM(FS.syncfs(false, function (err) { if (err) console.log('save sync failed', err); }););
#endif
}

// one iteration of the game's main loop, timed
static int tact_once(void) {
    uint64_t t0 = SDL_GetPerformanceCounter();
    int r = port_frame_once();
    static double acc, worst; static uint32_t n;
    double ms = (double)(SDL_GetPerformanceCounter() - t0) * 1000.0 / SDL_GetPerformanceFrequency();
    acc += ms; if (ms > worst) worst = ms;
#ifdef __EMSCRIPTEN__
    EM_ASM({ Module.tacts = (Module.tacts || 0) + 1; Module.lastTactMs = $0; }, ms);
#endif
    if (++n == 600) {
        host_log("perf: frame avg %.2f ms, worst %.1f ms, guest heap %u KB (peak %u KB)\n",
                 acc / n, worst, heap_used_bytes() >> 10, heap_peak_bytes() >> 10);
        acc = worst = 0; n = 0;
    }
    return r;
}

#ifdef __EMSCRIPTEN__
static int exited;
static void game_exit(void) {
    if (exited++) return;
    host_log("game requested exit\n");
    host_sync_fs();
    emscripten_cancel_main_loop();
    EM_ASM(if (Module.onGameExit) Module.onGameExit(););
}
// Online play: the host runs the game at a fixed 60 frames per second of real time (each frame's input goes out
// as one bundle). A guest runs a frame for each bundle received: when more than a few are waiting (joining
// late, or after a hiccup) it simulates them without drawing, within a time budget per animation frame.
static int background;      // called from the page's worker timer: ticks may be far apart, so catch up more
static int net_frames(void) {
    if (net_mode == NET_HOST) {
        static double last, acc;
        double now = emscripten_get_now();
        if (!last) last = now;
        acc += now - last; last = now;
        if (acc > (background ? 1000 : 250)) acc = background ? 1000 : 250;
        int n = 0;
        while (acc >= 1000.0 / 60 && n < (background ? 60 : 4)) { acc -= 1000.0 / 60; n++; }
        for (int i = 0; i < n; i++) if (tact_once()) return 1;
        return 0;
    }
    double t0 = emscripten_get_now();
    while (net_pending() > 3 && emscripten_get_now() - t0 < 25) {
        net_skip_render = 1;
        if (tact_once()) return 1;
    }
    net_skip_render = net_pending() > 3;
    for (int i = 0; i < 2 && net_pending() > 0; i++) {
        if (tact_once()) return 1;
        if (net_pending() < 2) break;
    }
    net_skip_render = 0;
    EM_ASM({ if (Module.onNetStatus) Module.onNetStatus($0, $1); }, net_pending(), net_tact());
    return 0;
}
static void em_frame(void);
// Browsers stop animation frames in background tabs; an online game keeps running from the page's worker timer
// (web/shell.html) so a host in the background doesn't freeze everyone else's game.
EMSCRIPTEN_KEEPALIVE void port_background_tick(void) {
    if (exited || (net_mode != NET_HOST && net_mode != NET_GUEST)) return;
    background = 1;
    em_frame();
    background = 0;
}
static void em_frame(void) {
    if (net_mode == NET_HOST || net_mode == NET_GUEST) {
        if (net_frames()) { game_exit(); return; }
    } else if (tact_once()) {
        game_exit();
        return;
    }
    static uint32_t last_sync;
    uint32_t now = SDL_GetTicks();
    if (now - last_sync > 2000) { last_sync = now; host_sync_fs(); }
}
#endif

// recompiler hook target: replaces the game's main loop (see src/game.c and recomp_config.json)
void host_frame_loop(void) {
    host_log("entering main loop\n");
#ifdef __EMSCRIPTEN__
    emscripten_set_main_loop(em_frame, 0, 1);
#else
    while (!tact_once()) {
        if (net_mode == NET_GUEST && !net_pending()) {     // native replay test: the recorded bundles ran out
            uint32_t net_checks_ok(void);
            host_log("netplay: replay finished at frame %u, %u checksums matched\n", net_tact(), net_checks_ok());
            host_shutdown();
            exit(0);
        }
    }
    port_after_loop();
#endif
}

static int file_exists(const char *p) { struct stat st; return stat(p, &st) == 0; }

int main(int argc, char **argv) {
#ifdef __EMSCRIPTEN__
    snprintf(g_game_dir, sizeof g_game_dir, "/game");
    snprintf(g_save_dir, sizeof g_save_dir, "/save");
#else
    const char *cands[] = { argc > 1 ? argv[1] : NULL, getenv(GAME_DIR_ENV), ".", "..", "../..", "../../.." };
    for (size_t i = 0; i < sizeof cands / sizeof *cands; i++) {
        if (!cands[i]) continue;
        char p[1024]; snprintf(p, sizeof p, "%s/" GAME_EXE, cands[i]);
        if (file_exists(p)) { snprintf(g_game_dir, sizeof g_game_dir, "%s", cands[i]); break; }
    }
    if (argc > 2) snprintf(g_save_dir, sizeof g_save_dir, "%s", argv[2]);
#endif
    host_log("game dir: %s, save dir: %s\n", g_game_dir, g_save_dir);
    SDL_SetMainReady();
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_TIMER) != 0) {
        host_log("SDL_Init failed: %s\n", SDL_GetError());
        return 1;
    }
    char exe[1024];
    snprintf(exe, sizeof exe, "%s/" GAME_EXE, g_game_dir);
    if (!runtime_init(exe)) {
        host_log("Cannot load %s. Pass the game directory as the first argument.\n", exe);
        return 1;
    }
    net_init();
    runtime_run_entry(REC_ENTRY);
    host_shutdown();
    return 0;
}
