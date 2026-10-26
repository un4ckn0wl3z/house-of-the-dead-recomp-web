// DirectInput (DX5, IDirectInputA / IDirectInputDeviceA) for the system mouse and keyboard, fed from SDL.
#include "host.h"
#include <SDL.h>
#include <stdio.h>

// user32.c keeps the cursor in game pixels and the buttons; relative motion accumulates here between reads
extern int g_mouse_x, g_mouse_y, g_mouse_buttons;
int g_mouse_dx, g_mouse_dy;
uint8_t g_keys[256];          // DIK_* scancode -> 0x80 when held (user32.c fills it)
// presses since the game last looked: a tap shorter than a frame still reads as held once
uint8_t g_keys_latch[256];
int g_buttons_latch;

// SDL scancode -> DirectInput DIK code (PC set 1)
uint8_t sdl_to_dik(int sc) {
    static uint8_t t[SDL_NUM_SCANCODES];
    static int init;
    if (!init) {
        init = 1;
        const char *row1 = "1234567890";
        for (int i = 0; i < 10; i++) t[SDL_SCANCODE_1 + i] = (uint8_t)(0x02 + i);
        (void)row1;
        static const struct { int sc, dik; } m[] = {
            {SDL_SCANCODE_ESCAPE, 0x01}, {SDL_SCANCODE_MINUS, 0x0C}, {SDL_SCANCODE_EQUALS, 0x0D}, {SDL_SCANCODE_BACKSPACE, 0x0E},
            {SDL_SCANCODE_TAB, 0x0F}, {SDL_SCANCODE_Q, 0x10}, {SDL_SCANCODE_W, 0x11}, {SDL_SCANCODE_E, 0x12}, {SDL_SCANCODE_R, 0x13},
            {SDL_SCANCODE_T, 0x14}, {SDL_SCANCODE_Y, 0x15}, {SDL_SCANCODE_U, 0x16}, {SDL_SCANCODE_I, 0x17}, {SDL_SCANCODE_O, 0x18},
            {SDL_SCANCODE_P, 0x19}, {SDL_SCANCODE_LEFTBRACKET, 0x1A}, {SDL_SCANCODE_RIGHTBRACKET, 0x1B}, {SDL_SCANCODE_RETURN, 0x1C},
            {SDL_SCANCODE_LCTRL, 0x1D}, {SDL_SCANCODE_A, 0x1E}, {SDL_SCANCODE_S, 0x1F}, {SDL_SCANCODE_D, 0x20}, {SDL_SCANCODE_F, 0x21},
            {SDL_SCANCODE_G, 0x22}, {SDL_SCANCODE_H, 0x23}, {SDL_SCANCODE_J, 0x24}, {SDL_SCANCODE_K, 0x25}, {SDL_SCANCODE_L, 0x26},
            {SDL_SCANCODE_SEMICOLON, 0x27}, {SDL_SCANCODE_APOSTROPHE, 0x28}, {SDL_SCANCODE_GRAVE, 0x29}, {SDL_SCANCODE_LSHIFT, 0x2A},
            {SDL_SCANCODE_BACKSLASH, 0x2B}, {SDL_SCANCODE_Z, 0x2C}, {SDL_SCANCODE_X, 0x2D}, {SDL_SCANCODE_C, 0x2E}, {SDL_SCANCODE_V, 0x2F},
            {SDL_SCANCODE_B, 0x30}, {SDL_SCANCODE_N, 0x31}, {SDL_SCANCODE_M, 0x32}, {SDL_SCANCODE_COMMA, 0x33}, {SDL_SCANCODE_PERIOD, 0x34},
            {SDL_SCANCODE_SLASH, 0x35}, {SDL_SCANCODE_RSHIFT, 0x36}, {SDL_SCANCODE_KP_MULTIPLY, 0x37}, {SDL_SCANCODE_LALT, 0x38},
            {SDL_SCANCODE_SPACE, 0x39}, {SDL_SCANCODE_CAPSLOCK, 0x3A}, {SDL_SCANCODE_F1, 0x3B}, {SDL_SCANCODE_F2, 0x3C},
            {SDL_SCANCODE_F3, 0x3D}, {SDL_SCANCODE_F4, 0x3E}, {SDL_SCANCODE_F5, 0x3F}, {SDL_SCANCODE_F6, 0x40}, {SDL_SCANCODE_F7, 0x41},
            {SDL_SCANCODE_F8, 0x42}, {SDL_SCANCODE_F9, 0x43}, {SDL_SCANCODE_F10, 0x44}, {SDL_SCANCODE_NUMLOCKCLEAR, 0x45},
            {SDL_SCANCODE_SCROLLLOCK, 0x46}, {SDL_SCANCODE_KP_7, 0x47}, {SDL_SCANCODE_KP_8, 0x48}, {SDL_SCANCODE_KP_9, 0x49},
            {SDL_SCANCODE_KP_MINUS, 0x4A}, {SDL_SCANCODE_KP_4, 0x4B}, {SDL_SCANCODE_KP_5, 0x4C}, {SDL_SCANCODE_KP_6, 0x4D},
            {SDL_SCANCODE_KP_PLUS, 0x4E}, {SDL_SCANCODE_KP_1, 0x4F}, {SDL_SCANCODE_KP_2, 0x50}, {SDL_SCANCODE_KP_3, 0x51},
            {SDL_SCANCODE_KP_0, 0x52}, {SDL_SCANCODE_KP_PERIOD, 0x53}, {SDL_SCANCODE_F11, 0x57}, {SDL_SCANCODE_F12, 0x58},
            {SDL_SCANCODE_KP_ENTER, 0x9C}, {SDL_SCANCODE_RCTRL, 0x9D}, {SDL_SCANCODE_KP_DIVIDE, 0xB5}, {SDL_SCANCODE_RALT, 0xB8},
            {SDL_SCANCODE_HOME, 0xC7}, {SDL_SCANCODE_UP, 0xC8}, {SDL_SCANCODE_PAGEUP, 0xC9}, {SDL_SCANCODE_LEFT, 0xCB},
            {SDL_SCANCODE_RIGHT, 0xCD}, {SDL_SCANCODE_END, 0xCF}, {SDL_SCANCODE_DOWN, 0xD0}, {SDL_SCANCODE_PAGEDOWN, 0xD1},
            {SDL_SCANCODE_INSERT, 0xD2}, {SDL_SCANCODE_DELETE, 0xD3}, {SDL_SCANCODE_PAUSE, 0xC5},
        };
        for (unsigned i = 0; i < sizeof m / sizeof *m; i++) t[m[i].sc] = (uint8_t)m[i].dik;
    }
    return sc >= 0 && sc < SDL_NUM_SCANCODES ? t[sc] : 0;
}

static uint32_t vt_di, vt_dev, di_obj;
enum { DEV_MOUSE = 1, DEV_KEYBOARD = 2 };

static void di_QueryInterface(void) { if (ARG(2)) W32(ARG(2), ARG(0)); SRET(0, 3); }
static void di_AddRef(void) { SRET(1, 1); }
static void di_Release(void) { SRET(0, 1); }
static void di_CreateDevice(void) {
    uint32_t guid = ARG(1), out = ARG(2);
    uint32_t d1 = guid ? R32(guid) : 0;
    int kind = d1 == 0x6F1D2B60u ? DEV_MOUSE : d1 == 0x6F1D2B61u ? DEV_KEYBOARD : 0;
    host_log("DirectInput::CreateDevice %08x -> %s\n", d1, kind == DEV_MOUSE ? "mouse" : kind == DEV_KEYBOARD ? "keyboard" : "none");
    if (!kind) { W32(out, 0); SRET(0x80040154u, 4); }
    uint32_t o = com_new(vt_dev, 32);
    W32(o + 4, (uint32_t)kind);
    W32(out, o);
    SRET(0, 4);
}
static void di_EnumDevices(void) { SRET(0, 5); }
static void di_GetDeviceStatus(void) { SRET(0, 2); }
static void di_ok3(void) { SRET(0, 3); }

static void dev_GetCapabilities(void) {
    uint32_t c = ARG(1), kind = R32(ARG(0) + 4);
    uint32_t sz = R32(c); if (sz < 8 || sz > 64) sz = 44;
    (COW(c + 4, sz - 4), memset(G + c + 4, 0, sz - 4));
    W32(c + 4, 1);                                  // DIDC_ATTACHED
    W32(c + 8, kind == DEV_MOUSE ? 18 : 19);        // DIDEVTYPE_MOUSE / KEYBOARD
    W32(c + 12, kind == DEV_MOUSE ? 3 : 0);         // axes
    W32(c + 16, kind == DEV_MOUSE ? 3 : 128);       // buttons
    SRET(0, 2);
}
static void dev_ok1(void) { SRET(0, 1); }
static void dev_ok2(void) { SRET(0, 2); }
static void dev_ok3(void) { SRET(0, 3); }
static void dev_ok4(void) { SRET(0, 4); }
static void dev_GetProperty(void) { SRET(0x80004001u, 3); }
static void dev_GetDeviceState(void) {
    uint32_t kind = R32(ARG(0) + 4), n = ARG(1), p = ARG(2);
    COW(p, n); memset(G + p, 0, n);
    if (kind == DEV_MOUSE) {
        if (n >= 16) {
            // the game integrates relative motion into its own cursor: report the motion that puts that cursor
            // under the pointer (game.c knows where the cursor lives)
            extern void port_mouse_motion(int *dx, int *dy);
            port_mouse_motion(&g_mouse_dx, &g_mouse_dy);
            W32(p, (uint32_t)g_mouse_dx); W32(p + 4, (uint32_t)g_mouse_dy); W32(p + 8, 0);
            extern int input_mouse_buttons(void);   // this frame's buttons (gun_input.c: same on every client)
            int b = input_mouse_buttons(); b = (b & 3) | ((b & 4) ? 0x10 : 0);
            W8(p + 12, (b & 1) ? 0x80 : 0); W8(p + 13, (b & 2) ? 0x80 : 0);
            W8(p + 14, (b & 0x10) ? 0x80 : 0);
        }
        g_mouse_dx = g_mouse_dy = 0;
    } else {
        extern void input_keys(uint8_t *out, uint32_t n);   // this frame's held keys (gun_input.c)
        input_keys(G + p, n < 256 ? n : 256);
    }
    SRET(0, 3);
}
static void dev_GetDeviceData(void) {
    // buffered data is not used by the game as far as known: report no events
    if (ARG(3)) W32(ARG(3), 0);
    SRET(0, 5);
}
static void dev_GetDeviceInfo(void) { SRET(0x80004001u, 2); }

static void build(void) {
    if (vt_di) return;
    GFunc di[] = { di_QueryInterface, di_AddRef, di_Release, di_CreateDevice, di_EnumDevices, di_GetDeviceStatus,
                   di_ok3 /*RunControlPanel*/, di_ok3 /*Initialize*/ };
    vt_di = com_vtable(8, di, "IDirectInput");
    GFunc dv[] = { di_QueryInterface, di_AddRef, di_Release, dev_GetCapabilities, dev_ok4 /*EnumObjects*/,
                   dev_GetProperty, dev_ok3 /*SetProperty*/, dev_ok1 /*Acquire*/, dev_ok1 /*Unacquire*/,
                   dev_GetDeviceState, dev_GetDeviceData, dev_ok2 /*SetDataFormat*/, dev_ok2 /*SetEventNotification*/,
                   dev_ok3 /*SetCooperativeLevel*/, dev_ok4 /*GetObjectInfo*/, dev_GetDeviceInfo,
                   dev_ok3 /*RunControlPanel*/, dev_ok4 /*Initialize*/ };
    vt_dev = com_vtable(18, dv, "IDirectInputDevice");
    di_obj = com_new(vt_di, 16);
}

void shim_DirectInputCreateA(void) {
    build();
    host_log("DirectInputCreateA version %x\n", ARG(1));
    W32(ARG(2), di_obj);
    SRET(0, 4);
}
