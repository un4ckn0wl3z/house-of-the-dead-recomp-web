// Per-frame input for The House of the Dead: two light guns (gamebios.dll), the menu pointer and mouse buttons
// (DirectInput mouse) and held keys (DirectInput keyboard). Everything the game reads comes from one record,
// FrameInput, built once per frame before the game's tick (game.c: port_frame_once):
//  - offline: from this machine's mouse and keyboard; the mouse is light gun 1 (left fires, right reloads);
//  - online (lockstep, netplay.c): the host's part travels in each frame's bundle as the "input block", player
//    2's gun arrives as the guest's NetInput; every client builds the same record, so both run the same game.
#include "host.h"
#include "netplay.h"
#include <SDL.h>

typedef struct { int x, y; uint32_t buttons; } Gun;
extern Gun g_gun[2];
extern int g_mouse_x, g_mouse_y, g_mouse_buttons;
extern uint8_t g_keys[256], g_keys_latch[256];
extern int g_buttons_latch;
int g_gun_latch;

#define GUN_OFFSCREEN 0x3FF
#define GUN_TRIGGER   1u
#define MAXKEYS       12

#pragma pack(push, 1)
typedef struct {
    int16_t gx[2], gy[2];        // guns: position in screen pixels (0x3FF = off screen, i.e. reload)
    uint8_t gtrig[2];            // trigger held
    uint8_t gaim[2];             // the player's pointer is over the screen (for the crosshair)
    int16_t px, py;              // host's menu pointer
    uint8_t mbtn;                // host's mouse buttons (1 left, 2 right, 4 middle) incl. clicks within the frame
    uint8_t nkeys;
    uint8_t keys[MAXKEYS];       // host's held DirectInput keys (DIK codes) incl. taps within the frame
} FrameInput;
#pragma pack(pop)

static FrameInput fin;              // this frame's input, identical on every client
static uint32_t block_addr;         // guest memory the netplay layer copies into / out of the bundle
static int g2_on;                   // player 2's gun is in use (online: a guest is aiming; tests: PORT_INPUT)
static int16_t g2x = GUN_OFFSCREEN, g2y = GUN_OFFSCREEN;
static uint8_t g2t;

// this machine's gun: the pointer, left fires, right fires off screen (reload); clicks within a frame count once
static void local_gun(int16_t *x, int16_t *y, uint8_t *trig) {
    int b = g_mouse_buttons | g_gun_latch;
    g_gun_latch = 0;
    int reload = (b & 2) != 0;
    *x = (int16_t)(reload ? GUN_OFFSCREEN : g_mouse_x);
    *y = (int16_t)(reload ? GUN_OFFSCREEN : g_mouse_y);
    *trig = (b & 3) ? 1 : 0;
}

// the host's (or offline player's) part of the record
static void local_part(FrameInput *f) {
    user32_pump_events();
    local_gun(&f->gx[0], &f->gy[0], &f->gtrig[0]);
    f->gaim[0] = 1;
    f->px = (int16_t)g_mouse_x; f->py = (int16_t)g_mouse_y;
    int b = g_mouse_buttons | g_buttons_latch;
    g_buttons_latch = 0;
    f->mbtn = (uint8_t)((b & 1) | (b & 2) | ((b & 0x10) ? 4 : 0));
    f->nkeys = 0;
    for (int k = 1; k < 256 && f->nkeys < MAXKEYS; k++)
        if ((g_keys[k] | g_keys_latch[k]) & 0x80) f->keys[f->nkeys++] = (uint8_t)k;
    memset(g_keys_latch, 0, 256);
}

static void set_gun2(void) {
    fin.gx[1] = g2x; fin.gy[1] = g2y; fin.gtrig[1] = g2t; fin.gaim[1] = (uint8_t)g2_on;
}

// game.c calls this at the start of every frame, after net_frame_begin and before the game's tick
void input_frame_begin(void) {
    if (!block_addr) block_addr = guest_static_alloc(sizeof(FrameInput));
    if (net_mode == NET_OFF) {
        local_part(&fin);
        set_gun2();
        return;
    }
    if (net_mode != NET_GUEST) {
        FrameInput f;
        memset(&f, 0, sizeof f);
        local_part(&f);
        memcpy(G + block_addr, &f, sizeof f);
    }
    // netplay.c: the host packs the block and the guests' latest input into this frame's bundle; a guest takes
    // them out of the bundle. Either way port_net_input() then delivers player 2's gun.
    net_after_pump();
    memcpy(&fin, G + block_addr, sizeof fin);
    set_gun2();
}

uint32_t port_input_block(uint32_t *size) { *size = sizeof(FrameInput); return block_addr; }

// player 2's gun for this frame (from the bundle). flags: bit 0 trigger, bit 1 reload, bit 2 pointer on screen.
void port_net_input(int slot, const NetInput *in) {
    if (slot != 1) return;
    int reload = (in->flags & 2) != 0;
    g2x = (int16_t)(reload ? GUN_OFFSCREEN : (int)in->wx);
    g2y = (int16_t)(reload ? GUN_OFFSCREEN : (int)in->wy);
    g2t = (in->flags & 3) ? 1 : 0;
    g2_on = (in->flags & 4) != 0;
}
void port_net_join(int slot, const char *name, const uint8_t data[44]) {
    (void)data;
    host_log("netplay: player %d (%s) joined\n", slot + 1, name);
}
void port_net_leave(int slot) {
    host_log("netplay: player %d left\n", slot + 1);
    if (slot == 1) { g2x = g2y = GUN_OFFSCREEN; g2t = 0; g2_on = 0; }
}

// native tests: player 2 from PORT_INPUT ("<frame>:fire2:x,y"), offline or as the NET_TEST host's bot
static int bot_x = GUN_OFFSCREEN, bot_y = GUN_OFFSCREEN, bot_t, bot_on;
void gun2_scripted(int x, int y, int trig) {
    bot_x = x; bot_y = y; bot_t = trig; bot_on = 1;
    if (net_mode == NET_OFF) { g2x = (int16_t)x; g2y = (int16_t)y; g2t = (uint8_t)trig; g2_on = 1; }
}
int port_bot_input(int slot, NetInput *in) {
    if (slot != 1 || !bot_on) return 0;
    in->flags = (bot_t ? 1u : 0u) | 4u;
    in->wx = (float)bot_x; in->wy = (float)bot_y;
    return 1;
}

// ---------------------------------------------------------------- what the shims read
// gamebios.dll (hotd_shims.c): both guns come from the record
void gun_update_local(void) {
    for (int i = 0; i < 2; i++) {
        g_gun[i].x = fin.gx[i]; g_gun[i].y = fin.gy[i];
        g_gun[i].buttons = fin.gtrig[i] ? GUN_TRIGGER : 0;
    }
}
// DirectInput mouse (dinput.c): the host's pointer (game.c) and buttons
int input_mouse_buttons(void) { return fin.mbtn; }
int net_pointer(int *x, int *y) { *x = fin.px; *y = fin.py; return 1; }
// DirectInput keyboard: the host's held keys
void input_keys(uint8_t *out, uint32_t n) {
    memset(out, 0, n);
    for (int i = 0; i < fin.nkeys && i < MAXKEYS; i++) if (fin.keys[i] < n) out[fin.keys[i]] = 0x80;
}
// crosshairs (ddraw.c): this machine's player at its own pointer (no lag), the partner from the bundle
int gun_crosshair(int slot, int *x, int *y) {
    // this machine's own aim is the real pointer (a crosshair cursor: no frame of lag), only the partner's is drawn
    int mine = net_mode == NET_GUEST ? net_local : 0;
    if (slot == mine) return 0;
    if (!fin.gaim[slot] || fin.gx[slot] == GUN_OFFSCREEN) return 0;
    *x = fin.gx[slot]; *y = fin.gy[slot];
    return 1;
}
