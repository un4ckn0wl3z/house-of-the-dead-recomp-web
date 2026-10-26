// USER32 shims: window, message queue, input translation (SDL2).
#include "host.h"
#include "netplay.h"
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

uint32_t g_hwnd = 0x00010010u, g_wndproc;
int g_win_w = 640, g_win_h = 480;
SDL_Window *g_window;
static int cursor_count = 0;
static int quit_requested;

// gfx.c
void gfx_map_mouse(int wx, int wy, int *gx, int *gy);
void gfx_window_created(SDL_Window *w);
void cursor_crosshair(void);

// ---------------------------------------------------------------- message queue
typedef struct { uint32_t hwnd, msg, wp, lp, time, x, y; } Msg;
#define QN 1024
static Msg q[QN];
static int qh, qt;
int g_mouse_x, g_mouse_y, g_mouse_buttons;
uint8_t vk_state[256];
extern int g_mouse_dx, g_mouse_dy;
extern uint8_t g_keys[256], g_keys_latch[256];
extern int g_buttons_latch, g_gun_latch;
uint8_t sdl_to_dik(int sc);

void post(uint32_t msg, uint32_t wp, uint32_t lp);
void post(uint32_t msg, uint32_t wp, uint32_t lp) {
    // online every client must see the same input: mouse and keyboard reach the game only through the frame's
    // input record (gun_input.c), never as window messages
    if (net_mode != NET_OFF && ((msg >= 0x100 && msg <= 0x109) || (msg >= 0x200 && msg <= 0x20E) || msg == 0x84)) return;
    int n = (qt + 1) % QN;
    // The game's loop handles one message per tick and skips that tick's frame, so a stream of mouse moves would
    // eat frames: keep only the newest pending move (and hit test).
    if (msg == 0x200 || msg == 0x84)
        for (int i = qh; i != qt; i = (i + 1) % QN)
            if (q[i].msg == msg) { q[i].wp = wp; q[i].lp = lp; q[i].x = g_mouse_x; q[i].y = g_mouse_y; return; }
    if (n == qh) return;   // drop on overflow
    q[qt].hwnd = g_hwnd; q[qt].msg = msg; q[qt].wp = wp; q[qt].lp = lp;
    q[qt].time = host_ticks(); q[qt].x = g_mouse_x; q[qt].y = g_mouse_y;
    qt = n;
}

static uint32_t sdl_to_vk(SDL_Keycode k, SDL_Scancode sc) {
    if (k >= 'a' && k <= 'z') return (uint32_t)(k - 'a' + 'A');
    if (k >= '0' && k <= '9') return (uint32_t)k;
    if (k >= SDLK_F1 && k <= SDLK_F12) return 0x70 + (k - SDLK_F1);
    switch (k) {
    case SDLK_LEFT: return 0x25; case SDLK_UP: return 0x26; case SDLK_RIGHT: return 0x27; case SDLK_DOWN: return 0x28;
    case SDLK_ESCAPE: return 0x1B; case SDLK_RETURN: case SDLK_KP_ENTER: return 0x0D; case SDLK_SPACE: return 0x20;
    case SDLK_TAB: return 0x09; case SDLK_BACKSPACE: return 0x08;
    case SDLK_LSHIFT: case SDLK_RSHIFT: return 0x10;
    case SDLK_LCTRL: case SDLK_RCTRL: return 0x11;
    case SDLK_LALT: case SDLK_RALT: return 0x12;
    case SDLK_PAUSE: return 0x13; case SDLK_CAPSLOCK: return 0x14;
    case SDLK_PAGEUP: return 0x21; case SDLK_PAGEDOWN: return 0x22; case SDLK_END: return 0x23; case SDLK_HOME: return 0x24;
    case SDLK_INSERT: return 0x2D; case SDLK_DELETE: return 0x2E; case SDLK_PRINTSCREEN: return 0x2C;
    case SDLK_KP_0: return 0x60; case SDLK_KP_1: return 0x61; case SDLK_KP_2: return 0x62; case SDLK_KP_3: return 0x63;
    case SDLK_KP_4: return 0x64; case SDLK_KP_5: return 0x65; case SDLK_KP_6: return 0x66; case SDLK_KP_7: return 0x67;
    case SDLK_KP_8: return 0x68; case SDLK_KP_9: return 0x69; case SDLK_KP_MULTIPLY: return 0x6A; case SDLK_KP_PLUS: return 0x6B;
    case SDLK_KP_MINUS: return 0x6D; case SDLK_KP_PERIOD: return 0x6E; case SDLK_KP_DIVIDE: return 0x6F;
    case SDLK_SEMICOLON: return 0xBA; case SDLK_EQUALS: return 0xBB; case SDLK_COMMA: return 0xBC; case SDLK_MINUS: return 0xBD;
    case SDLK_PERIOD: return 0xBE; case SDLK_SLASH: return 0xBF; case SDLK_BACKQUOTE: return 0xC0;
    case SDLK_LEFTBRACKET: return 0xDB; case SDLK_BACKSLASH: return 0xDC; case SDLK_RIGHTBRACKET: return 0xDD; case SDLK_QUOTE: return 0xDE;
    }
    (void)sc;
    return 0;
}

static void mouse_moved(int wx, int wy) {
    int ox = g_mouse_x, oy = g_mouse_y;
    gfx_map_mouse(wx, wy, &g_mouse_x, &g_mouse_y);
    g_mouse_dx += g_mouse_x - ox; g_mouse_dy += g_mouse_y - oy;
    uint32_t lp = ((uint32_t)(g_mouse_y & 0xffff) << 16) | (uint32_t)(g_mouse_x & 0xffff);
    post(0x84, 0, lp);              // WM_NCHITTEST (game reads mouse position from this)
    post(0x200, g_mouse_buttons, lp); // WM_MOUSEMOVE
}

// Scripted input for testing: PORT_INPUT="frame:key:VK;frame:click:x,y;frame:rclick:x,y;frame:move:x,y;
// frame:down:VK;frame:up:VK;frame:ldown:x,y;frame:lup:x,y;frame:char:c"
uint32_t host_frame_count(void);
static uint8_t key_release_dik, key_release_vk;
static uint32_t key_release_at, trig_release_at, trig2_release_at;
static void mouse_x_override(int x, int y) {
    uint32_t lp = ((uint32_t)(y & 0xffff) << 16) | (uint32_t)(x & 0xffff);
    g_mouse_dx += x - g_mouse_x; g_mouse_dy += y - g_mouse_y;
    g_mouse_x = x; g_mouse_y = y;
    post(0x84, 0, lp); post(0x200, g_mouse_buttons, lp);
}
static void scripted_input(void) {
    static char *spec; static int init; static uint32_t last = 0xffffffffu;
    if (!init) { init = 1; const char *e = getenv("PORT_INPUT"); if (e) spec = strdup(e); }
    if (!spec) return;
    uint32_t fr = net_mode == NET_OFF ? host_frame_count() : net_tact();   // game frames (online: the lockstep frame)
    if (fr == last) return;
    last = fr;
    if (key_release_at && fr >= key_release_at) { g_keys[key_release_dik] = 0; vk_state[key_release_vk] = 0; key_release_at = 0; }
    if (trig_release_at && fr >= trig_release_at) { g_mouse_buttons &= ~3; trig_release_at = 0; }
    if (trig2_release_at && fr >= trig2_release_at) { extern void gun2_scripted(int x, int y, int trig); gun2_scripted(0x3FF, 0x3FF, 0); trig2_release_at = 0; }
    char *copy = strdup(spec);
    for (char *tok = strtok(copy, ";"); tok; tok = strtok(NULL, ";")) {
        unsigned f; char act[16]; char arg[64] = "";
        if (sscanf(tok, "%u:%15[^:]:%63s", &f, act, arg) < 2 || f != fr) continue;
        int x = 0, y = 0; sscanf(arg, "%d,%d", &x, &y);
        uint32_t lp = ((uint32_t)(y & 0xffff) << 16) | (uint32_t)(x & 0xffff);
        if (!strcmp(act, "sclick")) {   // real SDL events in window coordinates (exercises handle_event)
            SDL_Event ev; memset(&ev, 0, sizeof ev);
            ev.type = SDL_MOUSEBUTTONDOWN; ev.button.button = SDL_BUTTON_LEFT; ev.button.x = x; ev.button.y = y; ev.button.state = SDL_PRESSED;
            SDL_PushEvent(&ev);
            ev.type = SDL_MOUSEBUTTONUP; ev.button.state = SDL_RELEASED;
            SDL_PushEvent(&ev);
        } else if (!strcmp(act, "key")) { uint32_t vk = (uint32_t)strtol(arg, NULL, 0); post(0x100, vk, 1); if (vk == 13 || vk == 27 || vk == 8) post(0x102, vk, 1); post(0x101, vk, 0xC0000001u);
            // DirectInput sees the key held for a few frames
            SDL_Scancode sc = vk == 0x20 ? SDL_SCANCODE_SPACE : vk == 0x0D ? SDL_SCANCODE_RETURN : vk == 0x1B ? SDL_SCANCODE_ESCAPE :
                              (vk >= 'A' && vk <= 'Z') ? SDL_GetScancodeFromKey(vk + 32) : (vk >= '0' && vk <= '9') ? SDL_GetScancodeFromKey(vk) : SDL_SCANCODE_UNKNOWN;
            uint8_t dk = sdl_to_dik(sc);
            if (dk) { g_keys[dk] = 0x80; key_release_dik = dk; key_release_at = fr + 4; }
            vk_state[vk & 0xff] = 1; key_release_vk = vk & 0xff; }
        else if (!strcmp(act, "fire2") || !strcmp(act, "aim2") || !strcmp(act, "reload2")) {   // player 2's gun (tests)
            extern void gun2_scripted(int x, int y, int trig);
            if (act[0] == 'r') gun2_scripted(0x3FF, 0x3FF, 1); else gun2_scripted(x, y, act[0] == 'f');
            if (act[0] != 'a') trig2_release_at = fr + 3; }
        else if (!strcmp(act, "fire") || !strcmp(act, "reload")) {   // light gun: aim at x,y and pull the trigger for 3 frames
            mouse_x_override(x, y);
            g_mouse_buttons |= act[0] == 'f' ? 1 : 2; trig_release_at = fr + 3; }
        else if (!strcmp(act, "down")) post(0x100, (uint32_t)strtol(arg, NULL, 0), 1);
        else if (!strcmp(act, "up")) post(0x101, (uint32_t)strtol(arg, NULL, 0), 0xC0000001u);
        else if (!strcmp(act, "char")) post(0x102, (uint32_t)(unsigned char)arg[0], 1);
        else if (!strcmp(act, "move")) { (void)lp; mouse_x_override(x, y); }
        else if (!strcmp(act, "click") || !strcmp(act, "rclick") || !strcmp(act, "ldown") || !strcmp(act, "lup")) {
            g_mouse_x = x; g_mouse_y = y; post(0x84, 0, lp); post(0x200, g_mouse_buttons, lp);
            int right = act[0] == 'r';
            uint32_t m = right ? 0x204 : 0x201;
            if (strcmp(act, "lup")) { g_mouse_buttons |= right ? 2 : 1; post(m, g_mouse_buttons, lp); }
            if (strcmp(act, "ldown")) { g_mouse_buttons &= ~(right ? 2u : 1u); post(m + 1, g_mouse_buttons, lp); }
        }
        host_log("input @%u: %s %s\n", fr, act, arg);
    }
    free(copy);
}

static SDL_Event pending[16];
static int npending;
static uint32_t pending_frame;

static int replaying;
static void handle_event(SDL_Event e);

void user32_pump_events(void) {
    SDL_Event e;
    extern void wndtimers_poll(void);
    wndtimers_poll();
    scripted_input();
    if (npending && host_frame_count() != pending_frame) {
        SDL_Event tmp[16]; int n = npending;
        memcpy(tmp, pending, sizeof(SDL_Event) * n);
        npending = 0;
        replaying = 1;
        for (int i = 0; i < n; i++) handle_event(tmp[i]);
        replaying = 0;
    }
    while (SDL_PollEvent(&e)) handle_event(e);
}

static void handle_event(SDL_Event e) {
        // the determinism test compares runs, so only scripted input may reach the game
        if (net_mode == NET_TEST && e.type != SDL_QUIT && e.type != SDL_WINDOWEVENT) return;
        switch (e.type) {
        case SDL_QUIT:
            quit_requested = 1;
#ifndef __EMSCRIPTEN__
            host_log("window closed\n");
            host_shutdown();
            exit(0);
#endif
            break;
        case SDL_KEYDOWN: case SDL_KEYUP: {
            { uint8_t dk = sdl_to_dik(e.key.keysym.scancode); if (dk) { g_keys[dk] = e.type == SDL_KEYDOWN ? 0x80 : 0; if (e.type == SDL_KEYDOWN) g_keys_latch[dk] = 0x80; } }
            uint32_t vk = sdl_to_vk(e.key.keysym.sym, e.key.keysym.scancode);
            if (!vk) break;
            vk_state[vk & 0xff] = e.type == SDL_KEYDOWN;
            uint32_t lp = 1 | ((uint32_t)(e.key.keysym.scancode & 0xff) << 16);
            if (e.type == SDL_KEYDOWN) {
#ifndef __EMSCRIPTEN__
                if (vk == 0x0D && (e.key.keysym.mod & KMOD_ALT)) {
                    uint32_t fl = SDL_GetWindowFlags(g_window);
                    SDL_SetWindowFullscreen(g_window, (fl & SDL_WINDOW_FULLSCREEN_DESKTOP) ? 0 : SDL_WINDOW_FULLSCREEN_DESKTOP);
                    break;
                }
#endif
                if (e.key.repeat) lp |= 1u << 30;
                post(vk == 0x12 ? 0x104 : 0x100, vk, lp);
                if (vk == 0x0D || vk == 0x08 || vk == 0x1B || vk == 0x09) post(0x102, vk, lp);
            } else {
                post(vk == 0x12 ? 0x105 : 0x101, vk, lp | 0xC0000000u);
            }
            break;
        }
        case SDL_TEXTINPUT: {
            const unsigned char *t = (const unsigned char *)e.text.text;
            for (; *t; t++) if (*t >= 32 && *t < 128) post(0x102, *t, 1);
            break;
        }
        case SDL_MOUSEMOTION:
            mouse_moved(e.motion.x, e.motion.y);
            break;
        case SDL_MOUSEBUTTONDOWN: case SDL_MOUSEBUTTONUP: {
            // The game selects menu items on mouse-move during a frame and acts on the click later,
            // so a click that arrives together with a jump of the cursor is delayed by one frame.
            int gx, gy; gfx_map_mouse(e.button.x, e.button.y, &gx, &gy);
            if (!replaying && (npending || gx != g_mouse_x || gy != g_mouse_y)) {
                mouse_moved(e.button.x, e.button.y);
                if (npending < 16) { pending[npending++] = e; pending_frame = host_frame_count(); }
                break;
            }
            mouse_moved(e.button.x, e.button.y);
            int down = e.type == SDL_MOUSEBUTTONDOWN;
            uint32_t bit = e.button.button == SDL_BUTTON_LEFT ? 1 : e.button.button == SDL_BUTTON_RIGHT ? 2 : 0x10;
            if (down) { g_mouse_buttons |= bit; g_buttons_latch |= bit; g_gun_latch |= bit; } else g_mouse_buttons &= ~bit;
            uint32_t lp = ((uint32_t)(g_mouse_y & 0xffff) << 16) | (uint32_t)(g_mouse_x & 0xffff);
            uint32_t msg = e.button.button == SDL_BUTTON_LEFT ? 0x201 : e.button.button == SDL_BUTTON_RIGHT ? 0x204 : 0x207;
            post(down ? msg : msg + 1, g_mouse_buttons, lp);
            break;
        }
        case SDL_MOUSEWHEEL: {
            int d = e.wheel.y * 120;
            post(0x20A, ((uint32_t)(d & 0xffff) << 16) | g_mouse_buttons, ((uint32_t)(g_mouse_y & 0xffff) << 16) | (uint32_t)(g_mouse_x & 0xffff));
            break;
        }
        case SDL_WINDOWEVENT:
            // Many engines pause while inactive (WM_ACTIVATEAPP 0), which players read as "the game stops when the
            // mouse leaves it"; online, one client must never pause on its own. So the window stays active (it is
            // activated once at creation). Mouse buttons held as focus or the pointer leaves are released, so
            // nothing keeps firing; SDL releases held keys itself.
            if (e.window.event == SDL_WINDOWEVENT_FOCUS_LOST || e.window.event == SDL_WINDOWEVENT_LEAVE) {
                uint32_t lp = ((uint32_t)(g_mouse_y & 0xffff) << 16) | (uint32_t)(g_mouse_x & 0xffff);
                if (g_mouse_buttons & 1) { g_mouse_buttons &= ~1u; post(0x202, g_mouse_buttons, lp); }
                if (g_mouse_buttons & 2) { g_mouse_buttons &= ~2u; post(0x205, g_mouse_buttons, lp); }
            }
            break;
        }
}

// ---------------------------------------------------------------- shims
static void u_RegisterClassA(void) {
    uint32_t wc = ARG(0);
    g_wndproc = R32(wc + 4);
    host_log("RegisterClassA wndproc=%08x\n", g_wndproc);
    SRET(0xC001, 1);
}

static void u_CreateWindowExA(void) {
    int w = (int32_t)ARG(6), h = (int32_t)ARG(7);
    if (w <= 0 || w > 4096) w = 640;
    if (h <= 0 || h > 4096) h = 480;
    g_win_w = w; g_win_h = h;
    host_log("CreateWindowExA '%s' %dx%d style=%08x\n", ARG(2) ? GSTR(ARG(2)) : "", w, h, ARG(3));
    if (!g_window) {
        SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_ES);
        SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 2);
        SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
        SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
        int sw = w, sh = h;
#ifndef __EMSCRIPTEN__
        if (sw < 1024) { sw = w * 2; sh = h * 2; }   // comfortable default size on desktop
        SDL_DisplayMode dm;
        if (!SDL_GetDesktopDisplayMode(0, &dm) && (sw > dm.w - 80 || sh > dm.h - 80)) { sw = w; sh = h; }
#endif
#ifdef __EMSCRIPTEN__
        g_window = SDL_CreateWindow(GAME_TITLE, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, sw, sh, SDL_WINDOW_OPENGL);
#else
        g_window = SDL_CreateWindow(GAME_TITLE, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, sw, sh,
                                    SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
#endif
        if (!g_window) {
            SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, 0);
            g_window = SDL_CreateWindow(GAME_TITLE, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, sw, sh,
                                        SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE);
        }
        if (!g_window) host_fatal("SDL_CreateWindow: %s", SDL_GetError());
        gfx_window_created(g_window);
        cursor_crosshair();
        SDL_StartTextInput();
    }
    post(0x1C, 1, 0);
    SRET(g_hwnd, 12);
}

static void u_ShowWindow(void) { SRET(1, 2); }
static void u_UpdateWindow(void) { SRET(1, 1); }
static void u_DrawMenuBar(void) { SRET(1, 1); }
static void u_RedrawWindow(void) { SRET(1, 4); }
static void u_EnableWindow(void) { SRET(0, 2); }
static void u_SetWindowTextA(void) { SRET(1, 2); }
static void u_GetClientRect(void) {
    uint32_t r = ARG(1);
    W32(r, 0); W32(r + 4, 0); W32(r + 8, g_win_w); W32(r + 12, g_win_h);
    SRET(1, 2);
}
static void u_GetWindowRect(void) {
    uint32_t r = ARG(1);
    W32(r, 0); W32(r + 4, 0); W32(r + 8, g_win_w); W32(r + 12, g_win_h);
    SRET(1, 2);
}
static void u_ClientToScreen(void) { SRET(1, 2); }

static void u_PeekMessageA(void) {
    uint32_t pmsg = ARG(0), remove = ARG(4);
    user32_pump_events();
    if (qh == qt) SRET(0, 5);
    Msg *m = &q[qh];
    W32(pmsg, m->hwnd); W32(pmsg + 4, m->msg); W32(pmsg + 8, m->wp); W32(pmsg + 12, m->lp);
    W32(pmsg + 16, m->time); W32(pmsg + 20, m->x); W32(pmsg + 24, m->y);
    if (remove & 1) qh = (qh + 1) % QN;
    SRET(1, 5);
}
// GetMessage blocks until a message arrives: pump events and let timers/threads run meanwhile
static void u_GetMessageA(void) {
    uint32_t pmsg = ARG(0);
    extern void host_idle(void);
    while (qh == qt) { user32_pump_events(); if (qh != qt) break; host_idle(); }
    Msg *m = &q[qh];
    W32(pmsg, m->hwnd); W32(pmsg + 4, m->msg); W32(pmsg + 8, m->wp); W32(pmsg + 12, m->lp);
    W32(pmsg + 16, m->time); W32(pmsg + 20, m->x); W32(pmsg + 24, m->y);
    qh = (qh + 1) % QN;
    SRET(m->msg != 0x12, 4);
}
int user32_queue_empty(void) { return qh == qt; }
static void u_TranslateMessage(void) { SRET(0, 1); }
static void u_DispatchMessageA(void) {
    uint32_t pmsg = ARG(0);
    uint32_t hwnd = R32(pmsg), msg = R32(pmsg + 4), wp = R32(pmsg + 8), lp = R32(pmsg + 12);
    uint32_t r = 0;
    if (msg == 0x113 && lp) r = guest_call(lp, 4, hwnd, msg, wp, host_ticks());   // WM_TIMER with a TIMERPROC
    else if (g_wndproc) r = guest_call(g_wndproc, 4, hwnd, msg, wp, lp);
    SRET(r, 1);
}
static void u_TranslateAcceleratorA(void) { SRET(0, 3); }
static void u_LoadAcceleratorsA(void) { SRET(0x00020001, 2); }
static void u_DefWindowProcA(void) { SRET(0, 4); }
static void u_PostMessageA(void) { post(ARG(1), ARG(2), ARG(3)); SRET(1, 4); }
static void u_PostQuitMessage(void) { post(0x12, ARG(0), 0); SRET(0, 1); }
static void u_WaitMessage(void) { extern void host_idle(void); user32_pump_events(); if (qh == qt) host_idle(); SRET(1, 0); }
static void u_GetSystemMetrics(void) {
    int32_t i = (int32_t)ARG(0), v = 0;
    switch (i) {
    case 0: v = 1024; break; case 1: v = 768; break; case 4: v = 19; break;
    case 5: case 6: v = 1; break; case 7: case 8: v = 3; break; case 32: case 33: v = 4; break;
    case 11: case 12: v = 32; break; case 13: case 14: v = 32; break;
    }
    SRET(v, 1);
}
static void u_SetCursorPos(void) { SRET(1, 2); }
// The game hides the Windows cursor; the port shows a crosshair cursor instead: it is the player's aim, drawn by
// the system (or the browser) at the pointer without the game's frame of lag.
static void u_ShowCursor(void) {
    cursor_count += ARG(0) ? 1 : -1;
    SRET((uint32_t)cursor_count, 1);
}
void cursor_crosshair(void) {
#ifdef __EMSCRIPTEN__
    return;            // web/shell.html styles the canvas pointer
#endif
    static SDL_Cursor *c;
    if (!c) c = SDL_CreateSystemCursor(SDL_SYSTEM_CURSOR_CROSSHAIR);
    if (c) SDL_SetCursor(c);
    SDL_ShowCursor(SDL_ENABLE);
}
static void u_SetCursor(void) { SRET(0, 1); }
static void u_LoadCursorA(void) { SRET(0x00030001, 2); }
static void u_LoadCursorFromFileA(void) { SRET(0x00030002, 1); }
static void u_DestroyCursor(void) { SRET(1, 1); }
static void u_SetCapture(void) { SRET(0, 1); }
static void u_ReleaseCapture(void) { SRET(1, 0); }
static void u_GetForegroundWindow(void) { SRET(g_hwnd, 0); }
static void u_MessageBoxA(void) {
    host_log("MessageBox: [%s] %s\n", ARG(2) ? GSTR(ARG(2)) : "", ARG(1) ? GSTR(ARG(1)) : "");
    SRET(1, 4);
}
static void u_LoadIconA(void) { SRET(0x00040001, 2); }
static void u_GetDC(void) { SRET(0x00050001, 1); }
static void u_ReleaseDC(void) { SRET(1, 2); }
static void u_DialogBoxParamA(void) {
    host_log("DialogBoxParamA template=%08x proc=%08x (auto-OK)\n", ARG(1), ARG(3));
    SRET(1, 5);
}
static void u_EndDialog(void) { SRET(1, 2); }
static void u_GetDlgItem(void) { SRET(0x00060000 | (ARG(1) & 0xffff), 2); }
static void u_GetDlgItemTextA(void) { if (ARG(3)) W8(ARG(2), 0); SRET(0, 4); }
static void u_SetDlgItemTextA(void) { SRET(1, 3); }
static void u_SendDlgItemMessageA(void) { SRET(0, 5); }

const ShimDef shims_user32[] = {
    {"USER32", "RegisterClassA", u_RegisterClassA}, {"USER32", "CreateWindowExA", u_CreateWindowExA},
    {"USER32", "ShowWindow", u_ShowWindow}, {"USER32", "UpdateWindow", u_UpdateWindow},
    {"USER32", "DrawMenuBar", u_DrawMenuBar}, {"USER32", "RedrawWindow", u_RedrawWindow},
    {"USER32", "EnableWindow", u_EnableWindow}, {"USER32", "SetWindowTextA", u_SetWindowTextA},
    {"USER32", "GetClientRect", u_GetClientRect}, {"USER32", "GetWindowRect", u_GetWindowRect},
    {"USER32", "ClientToScreen", u_ClientToScreen}, {"USER32", "PeekMessageA", u_PeekMessageA},
    {"USER32", "GetMessageA", u_GetMessageA}, {"USER32", "TranslateMessage", u_TranslateMessage}, {"USER32", "DispatchMessageA", u_DispatchMessageA},
    {"USER32", "TranslateAcceleratorA", u_TranslateAcceleratorA}, {"USER32", "LoadAcceleratorsA", u_LoadAcceleratorsA},
    {"USER32", "DefWindowProcA", u_DefWindowProcA}, {"USER32", "PostMessageA", u_PostMessageA},
    {"USER32", "PostQuitMessage", u_PostQuitMessage}, {"USER32", "WaitMessage", u_WaitMessage},
    {"USER32", "GetSystemMetrics", u_GetSystemMetrics}, {"USER32", "SetCursorPos", u_SetCursorPos},
    {"USER32", "ShowCursor", u_ShowCursor}, {"USER32", "SetCursor", u_SetCursor},
    {"USER32", "LoadCursorA", u_LoadCursorA}, {"USER32", "LoadCursorFromFileA", u_LoadCursorFromFileA},
    {"USER32", "DestroyCursor", u_DestroyCursor}, {"USER32", "SetCapture", u_SetCapture},
    {"USER32", "ReleaseCapture", u_ReleaseCapture}, {"USER32", "GetForegroundWindow", u_GetForegroundWindow},
    {"USER32", "MessageBoxA", u_MessageBoxA}, {"USER32", "LoadIconA", u_LoadIconA},
    {"USER32", "GetDC", u_GetDC}, {"USER32", "ReleaseDC", u_ReleaseDC},
    {"USER32", "DialogBoxParamA", u_DialogBoxParamA}, {"USER32", "EndDialog", u_EndDialog},
    {"USER32", "GetDlgItem", u_GetDlgItem}, {"USER32", "GetDlgItemTextA", u_GetDlgItemTextA},
    {"USER32", "SetDlgItemTextA", u_SetDlgItemTextA}, {"USER32", "SendDlgItemMessageA", u_SendDlgItemMessageA},
    {0, 0, 0}
};
