// DirectDraw (IDirectDraw / IDirectDraw2) on SDL2: surfaces live in guest memory, the primary surface is shown
// with an SDL_Renderer streaming texture (WebGL on the web). 16-bit RGB565 and 8-bit palettized surfaces.
#include "host.h"
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>

// ---------------------------------------------------------------- presentation
static SDL_Renderer *ren;
static SDL_Texture *tex;
static int tex_w, tex_h;
static uint32_t frames;
static uint16_t *conv;           // 8-bit -> 565 conversion buffer
int g_mode_w = 640, g_mode_h = 480, g_mode_bpp = 16;

void gfx_window_created(SDL_Window *w) {
    SDL_SetHint(SDL_HINT_RENDER_SCALE_QUALITY, "linear");
    ren = SDL_CreateRenderer(w, -1, SDL_RENDERER_ACCELERATED);
    if (!ren) ren = SDL_CreateRenderer(w, -1, 0);
    if (!ren) host_fatal("SDL_CreateRenderer: %s", SDL_GetError());
    SDL_RenderSetLogicalSize(ren, g_mode_w, g_mode_h);
}
void gfx_shutdown(void) {}
uint32_t host_frame_count(void) { return frames; }

// window pixels -> game pixels (letterboxed logical size)
void gfx_map_mouse(int wx, int wy, int *gx, int *gy) {
    extern SDL_Window *g_window;
    int ww = g_mode_w, wh = g_mode_h;
    if (g_window) SDL_GetWindowSize(g_window, &ww, &wh);
    double s = (double)ww / g_mode_w < (double)wh / g_mode_h ? (double)ww / g_mode_w : (double)wh / g_mode_h;
    double ox = (ww - g_mode_w * s) / 2, oy = (wh - g_mode_h * s) / 2;
    int x = (int)((wx - ox) / s), y = (int)((wy - oy) / s);
    *gx = x < 0 ? 0 : x >= g_mode_w ? g_mode_w - 1 : x;
    *gy = y < 0 ? 0 : y >= g_mode_h ? g_mode_h - 1 : y;
}

// ---------------------------------------------------------------- objects
typedef struct {
    int used, ref, w, h, bpp, pitch;
    uint32_t caps, bits, obj, attached, palette, clipper;
    uint32_t ck_lo, ck_hi; int has_ck;
    int primary, locked;
} Surf;
#define MAXS 1024
static Surf S[MAXS];
static uint32_t pal_rgb[64][256];    // palettes, as 0x00RRGGBB
static int npal;
static uint32_t vt_dd, vt_dd2, vt_surf, vt_pal, vt_clip;
static uint32_t dd_obj, dd2_obj;
static int primary_id = -1;
static int locked_since_present;   // the back buffer was locked since the last presented frame

static int ddlog = -1;
#define DDLOG(...) do { if (ddlog < 0) ddlog = getenv("PORT_DDLOG") != NULL; if (ddlog) host_log(__VA_ARGS__); } while (0)
static int sid(uint32_t obj) {
    if (!obj) return -1;
    uint32_t i = R32(obj + 4);
    return i < MAXS && S[i].used ? (int)i : -1;
}
#define THIS_S(nargs) int si = sid(ARG(0)); if (si < 0) SRET(0x88760000u + 572, nargs); Surf *s = &S[si]

static void write_pf(uint32_t pf, int bpp) {
    (COW(pf, 32), memset(G + pf, 0, 32));
    W32(pf, 32);
    if (bpp == 8) { W32(pf + 4, 0x20 | 0x40); W32(pf + 12, 8); }      // DDPF_PALETTEINDEXED8 | DDPF_RGB
    else { W32(pf + 4, 0x40); W32(pf + 12, 16); W32(pf + 16, 0xF800); W32(pf + 20, 0x07E0); W32(pf + 24, 0x001F); }
}
static void write_desc(uint32_t d, Surf *s) {
    uint32_t sz = R32(d); if (sz < 108) sz = 108;
    (COW(d, sz), memset(G + d, 0, sz));
    W32(d, sz);
    W32(d + 4, 1 | 2 | 4 | 8 | 0x1000);
    W32(d + 8, s->h); W32(d + 12, s->w); W32(d + 16, s->pitch);
    W32(d + 36, s->bits);
    write_pf(d + 72, s->bpp);
    W32(d + 104, s->caps);
}

static int new_surf(int w, int h, int bpp, uint32_t caps) {
    for (int i = 0; i < MAXS; i++) if (!S[i].used) {
        Surf *s = &S[i];
        memset(s, 0, sizeof *s);
        s->used = 1; s->ref = 1; s->w = w; s->h = h; s->bpp = bpp; s->caps = caps;
        s->pitch = ((w * bpp / 8) + 3) & ~3;
        s->bits = heap_alloc((uint32_t)(s->pitch * h) + 16);
        if (!s->bits) host_fatal("out of guest memory for a %dx%dx%d surface", w, h, bpp);
        (COW(s->bits, (uint32_t)(s->pitch * h)), memset(G + s->bits, 0, (size_t)s->pitch * h));
        s->obj = com_new(vt_surf, 16);
        W32(s->obj + 4, (uint32_t)i);
        return i;
    }
    host_fatal("too many DirectDraw surfaces");
    return -1;
}
static void free_surf(int i) {
    Surf *s = &S[i];
    if (!s->used) return;
    int a = sid(s->attached);
    s->used = 0;                 // first, so a circular flip chain ends here
    heap_free(s->bits); heap_free(s->obj);
    if (i == primary_id) primary_id = -1;
    if (a >= 0 && a != i && (S[a].caps & 4)) free_surf(a);   // back buffers die with their primary
}

static void present(void) {
    if (!ren || primary_id < 0) return;
    Surf *p = &S[primary_id];
    // the visible buffer is the primary; flips swap the primary's and back buffer's bits
    if (!tex || tex_w != p->w || tex_h != p->h) {
        if (tex) SDL_DestroyTexture(tex);
        tex = SDL_CreateTexture(ren, SDL_PIXELFORMAT_RGB565, SDL_TEXTUREACCESS_STREAMING, p->w, p->h);
        tex_w = p->w; tex_h = p->h;
        SDL_RenderSetLogicalSize(ren, p->w, p->h);
    }
    if (p->bpp == 16) {
        SDL_UpdateTexture(tex, NULL, G + p->bits, p->pitch);
    } else {
        conv = realloc(conv, (size_t)p->w * p->h * 2);
        uint32_t *pal = pal_rgb[p->palette ? R32(p->palette + 4) & 63 : 0];
        uint16_t lut[256];
        for (int i = 0; i < 256; i++) { uint32_t c = pal[i]; lut[i] = (uint16_t)(((c >> 8) & 0xF800) | ((c >> 5) & 0x07E0) | ((c >> 3) & 0x1F)); }
        for (int y = 0; y < p->h; y++) {
            const uint8_t *src = G + p->bits + (size_t)y * p->pitch;
            uint16_t *dst = conv + (size_t)y * p->w;
            for (int x = 0; x < p->w; x++) dst[x] = lut[src[x]];
        }
        SDL_UpdateTexture(tex, NULL, conv, p->w * 2);
    }
    SDL_SetRenderDrawColor(ren, 0, 0, 0, 255);
    SDL_RenderClear(ren);
    SDL_RenderCopy(ren, tex, NULL, NULL);
    // crosshairs: the game draws none for light guns (gun_input.c says where each player aims)
    {
        extern int gun_crosshair(int slot, int *x, int *y);
        // the HUD's player colours: 1P red, 2P blue; a black outline keeps them visible on any background
        static const uint8_t col[2][3] = {{255, 50, 40}, {40, 190, 255}};
        // 3x5 glyphs for the "1P" / "2P" tag
        static const uint8_t glyph[3][5] = {{2, 6, 2, 2, 7}, {6, 1, 2, 4, 7}, {6, 5, 6, 4, 4}};   // 1, 2, P
        for (int s = 0; s < 2; s++) {
            int x, y;
            if (!gun_crosshair(s, &x, &y)) continue;
            x = x * p->w / g_mode_w; y = y * p->h / g_mode_h;
            for (int pass = 0; pass < 2; pass++) {
                int o = pass == 0 ? 1 : 0;          // outline pass draws everything 1 px bigger in black
                if (pass == 0) SDL_SetRenderDrawColor(ren, 0, 0, 0, 255);
                else SDL_SetRenderDrawColor(ren, col[s][0], col[s][1], col[s][2], 255);
                SDL_Rect arms[4] = {{x - 14 - o, y - 1 - o, 9 + 2 * o, 2 + 2 * o}, {x + 5 - o, y - 1 - o, 9 + 2 * o, 2 + 2 * o},
                                    {x - 1 - o, y - 14 - o, 2 + 2 * o, 9 + 2 * o}, {x - 1 - o, y + 5 - o, 2 + 2 * o, 9 + 2 * o}};
                SDL_RenderFillRects(ren, arms, 4);
                for (int a = 0; a < 48; a++) {      // ring, radius 9
                    double t = a * 6.2831853 / 48;
                    int rx = x + (int)lround(9 * cos(t)), ry = y + (int)lround(9 * sin(t));
                    SDL_Rect d = {rx - o, ry - o, 1 + 2 * o, 1 + 2 * o};
                    SDL_RenderFillRect(ren, &d);
                }
                // tag at the lower right: "1P" / "2P"
                const uint8_t *g[2] = {glyph[s], glyph[2]};
                for (int c = 0; c < 2; c++)
                    for (int r = 0; r < 5; r++)
                        for (int b = 0; b < 3; b++)
                            if (g[c][r] & (4 >> b)) {
                                SDL_Rect d = {x + 12 + c * 5 + b - o, y + 10 + r - o, 1 + 2 * o, 1 + 2 * o};
                                SDL_RenderFillRect(ren, &d);
                            }
            }
        }
    }
    SDL_RenderPresent(ren);
    frames++;
    locked_since_present = 0;
#ifndef __EMSCRIPTEN__
    // A DDFLIP_WAIT flip waits for the vertical blank: the game caps itself at 1024 fps and relies on that for
    // pacing (its texture cache treats frames with the same millisecond timestamp as one frame). 60 Hz here;
    // on the web requestAnimationFrame paces the frames.
    {
        static uint64_t next;
        uint64_t f = SDL_GetPerformanceFrequency(), now = SDL_GetPerformanceCounter(), step = f / 60;
        if (!next || now > next + step * 4) next = now;
        next += step;
        while ((now = SDL_GetPerformanceCounter()) < next) {
            uint64_t ms = (next - now) * 1000 / f;
            if (ms > 1) SDL_Delay((uint32_t)(ms - 1));
        }
    }
#endif
    // PORT_SHOT=100,500: dump the visible frame as a BMP
    static const char *shots; static int init;
    if (!init) { init = 1; shots = getenv("PORT_SHOT"); }
    if (shots) {
        char key[16]; snprintf(key, sizeof key, "%u", frames);
        for (const char *q = shots; (q = strstr(q, key)); q++)
            if ((q == shots || q[-1] == ',') && (q[strlen(key)] == ',' || !q[strlen(key)])) {
                SDL_Surface *sf = SDL_CreateRGBSurfaceWithFormat(0, p->w, p->h, 16, SDL_PIXELFORMAT_RGB565);
                if (p->bpp == 16) for (int y = 0; y < p->h; y++) memcpy((uint8_t *)sf->pixels + y * sf->pitch, G + p->bits + y * p->pitch, p->w * 2);
                else for (int y = 0; y < p->h; y++) memcpy((uint8_t *)sf->pixels + y * sf->pitch, conv + y * p->w, p->w * 2);
                char fn[64]; snprintf(fn, sizeof fn, "shot_%05u.bmp", frames);
                SDL_SaveBMP(sf, fn); SDL_FreeSurface(sf);
                { int nz = 0, pz = 0; uint32_t *pl = pal_rgb[p->palette ? R32(p->palette + 4) & 63 : 0];
                  for (int k = 0; k < p->h * p->pitch; k++) nz += G[p->bits + k] != 0;
                  for (int k = 0; k < 256; k++) pz += pl[k] != 0;
                  host_log("screenshot %s: %d nonzero bytes, %d nonzero palette entries\n", fn, nz, pz); }
                break;
            }
    }
    // PORT_EXIT=N: quit cleanly after N presented frames (tests, debugger runs)
    static int exit_at = -1;
    if (exit_at < 0) { const char *e = getenv("PORT_EXIT"); exit_at = e ? atoi(e) : 0; }
    if (exit_at && frames >= (uint32_t)exit_at) { host_log("PORT_EXIT after %u frames\n", frames); host_shutdown(); exit(0); }
    extern void host_frame_presented(void);
    host_frame_presented();
}

// ---------------------------------------------------------------- IDirectDraw / IDirectDraw2
static int is_iid(uint32_t p, uint32_t d1) { return p && R32(p) == d1; }
static void dd_QueryInterface(void) {
    uint32_t riid = ARG(1), out = ARG(2);
    if (is_iid(riid, 0xB3A6F3E0u)) { W32(out, dd2_obj); SRET(0, 3); }           // IDirectDraw2
    if (is_iid(riid, 0x6C14DB80u)) { W32(out, dd_obj); SRET(0, 3); }            // IDirectDraw
    host_log("DirectDraw::QueryInterface %08x: no\n", riid ? R32(riid) : 0);
    if (out) W32(out, 0);
    SRET(0x80004002u, 3);
}
static void dd_AddRef(void) { SRET(1, 1); }
static void dd_Release(void) { SRET(0, 1); }
static void dd_ok1(void) { SRET(0, 1); }
static void dd_ok2(void) { SRET(0, 2); }
static void dd_ok3(void) { SRET(0, 3); }
static void dd_CreateClipper(void) { W32(ARG(2), com_new(vt_clip, 16)); SRET(0, 4); }
static void dd_CreatePalette(void) {
    uint32_t entries = ARG(2), out = ARG(3);
    if (npal >= 64) host_fatal("too many palettes");
    int i = npal++;
    for (int k = 0; k < 256; k++) { uint32_t e = entries ? R32(entries + k * 4) : 0; pal_rgb[i][k] = ((e & 0xff) << 16) | (e & 0xff00) | ((e >> 16) & 0xff); }
    uint32_t o = com_new(vt_pal, 16); W32(o + 4, (uint32_t)i);
    W32(out, o);
    SRET(0, 5);
}
static void dd_CreateSurface(void) {
    uint32_t d = ARG(1), out = ARG(2);
    uint32_t fl = R32(d + 4), caps = (fl & 1) ? R32(d + 104) : 0x40;
    int w = (fl & 4) ? (int)R32(d + 12) : g_mode_w, h = (fl & 2) ? (int)R32(d + 8) : g_mode_h;
    int bpp = g_mode_bpp;
    if (fl & 0x1000) { uint32_t pf = d + 72; bpp = (R32(pf + 4) & 0x20) ? 8 : (int)R32(pf + 12); }
    if (caps & 0x200) { w = g_mode_w; h = g_mode_h; bpp = g_mode_bpp; }
    if (bpp != 8 && bpp != 16) { host_log("CreateSurface: %d bpp not supported\n", bpp); SRET(0x88760000u + 90, 4); }
    if (caps & 0x20000) bpp = 16;   // z buffer
    int i = new_surf(w, h, bpp, caps | ((caps & 0x200) ? 0x20 | 0x4000 : 0));
    if (caps & 0x200) {
        primary_id = i;
        int nback = (fl & 0x20) ? (int)R32(d + 20) : 0;
        int prev = i;
        for (int k = 0; k < nback; k++) {
            int b = new_surf(w, h, bpp, (caps & ~0x200u & ~0x20u) | 4 | 0x4000);
            S[prev].attached = S[b].obj;
            prev = b;
        }
        if (nback) S[prev].attached = S[i].obj;   // flip chain
    }
    host_log("CreateSurface %dx%dx%d caps=%08x -> #%d\n", w, h, bpp, caps, i);
    W32(out, S[i].obj);
    SRET(0, 4);
}
static void dd_EnumDisplayModes(void) {
    uint32_t ctx = ARG(3), cb = ARG(4);
    static const int modes[][3] = {{640, 480, 16}, {640, 480, 8}, {320, 240, 16}, {320, 200, 8}, {512, 384, 16}, {800, 600, 16}};
    uint32_t d = heap_alloc(108);
    for (unsigned k = 0; k < sizeof modes / sizeof *modes; k++) {
        Surf t = {0}; t.w = modes[k][0]; t.h = modes[k][1]; t.bpp = modes[k][2]; t.pitch = t.w * t.bpp / 8;
        W32(d, 108); write_desc(d, &t); W32(d + 36, 0); W32(d + 24, 60);
        if (!guest_call(cb, 2, d, ctx)) break;
    }
    heap_free(d);
    SRET(0, 5);
}
static void dd_GetCaps(void) {
    for (int k = 1; k <= 2; k++) {
        uint32_t c = ARG(k);
        if (!c) continue;
        uint32_t sz = R32(c); if (sz < 4 || sz > 400) sz = 316;
        (COW(c + 4, sz - 4), memset(G + c + 4, 0, sz - 4));
        W32(c + 4, 0x40 | 0x200);       // DDCAPS_BLT | DDCAPS_COLORKEY ... minimal
        W32(c + 12, 0x200);             // dwCKeyCaps: SRCBLT
        W32(c + 60, 8 * 1024 * 1024);   // dwVidMemTotal
        W32(c + 64, 8 * 1024 * 1024);   // dwVidMemFree
    }
    SRET(0, 3);
}
static void dd_GetDisplayMode(void) {
    Surf t = {0}; t.w = g_mode_w; t.h = g_mode_h; t.bpp = g_mode_bpp; t.pitch = t.w * t.bpp / 8;
    write_desc(ARG(1), &t); W32(ARG(1) + 36, 0);
    SRET(0, 2);
}
static void set_mode(int w, int h, int bpp) {
    host_log("SetDisplayMode %dx%dx%d\n", w, h, bpp);
    g_mode_w = w; g_mode_h = h; g_mode_bpp = bpp;
    extern SDL_Window *g_window;
    if (ren) SDL_RenderSetLogicalSize(ren, w, h);
    (void)g_window;
}
static void dd_SetDisplayMode(void) { set_mode((int)ARG(1), (int)ARG(2), (int)ARG(3)); SRET(0, 4); }
static void dd2_SetDisplayMode(void) { set_mode((int)ARG(1), (int)ARG(2), (int)ARG(3)); SRET(0, 6); }
static void dd_GetMonitorFrequency(void) { W32(ARG(1), 60); SRET(0, 2); }
static void dd_GetFourCCCodes(void) { W32(ARG(1), 0); SRET(0, 3); }
static void dd_GetScanLine(void) { W32(ARG(1), 0); SRET(0, 2); }
static void dd_GetVerticalBlankStatus(void) { W32(ARG(1), 1); SRET(0, 2); }
static void dd_GetAvailableVidMem(void) {
    if (ARG(2)) W32(ARG(2), 8 << 20);
    if (ARG(3)) W32(ARG(3), 8 << 20);
    SRET(0, 4);
}
static void dd_unimpl(void) { host_fatal("IDirectDraw method not implemented (ret %08x)", R32(R.esp)); }

// ---------------------------------------------------------------- IDirectDrawSurface
static void s_QueryInterface(void) {
    uint32_t riid = ARG(1), out = ARG(2);
    // IDirectDrawSurface / 2 / 3 share the vtable layout up to the methods the game uses
    if (is_iid(riid, 0x6C14DB81u) || is_iid(riid, 0x57805885u) || is_iid(riid, 0xDA044E00u)) { W32(out, ARG(0)); SRET(0, 3); }
    host_log("Surface::QueryInterface %08x: no\n", riid ? R32(riid) : 0);
    if (out) W32(out, 0);
    SRET(0x80004002u, 3);
}
static void s_AddRef(void) { THIS_S(1); SRET(++s->ref, 1); }
static void s_Release(void) {
    THIS_S(1);
    if (--s->ref <= 0) { free_surf(si); SRET(0, 1); }
    SRET(s->ref, 1);
}
static void rect_of(uint32_t r, Surf *s, int *x0, int *y0, int *x1, int *y1) {
    if (r) { *x0 = (int32_t)R32(r); *y0 = (int32_t)R32(r + 4); *x1 = (int32_t)R32(r + 8); *y1 = (int32_t)R32(r + 12); }
    else { *x0 = 0; *y0 = 0; *x1 = s->w; *y1 = s->h; }
}
static void fill(Surf *d, int x0, int y0, int x1, int y1, uint32_t c) {
    if (x0 < 0) x0 = 0; if (y0 < 0) y0 = 0; if (x1 > d->w) x1 = d->w; if (y1 > d->h) y1 = d->h;
    for (int y = y0; y < y1; y++) {
        uint8_t *row = G + d->bits + (size_t)y * d->pitch;
        if (d->bpp == 8) memset(row + x0, (int)c, x1 - x0);
        else for (int x = x0; x < x1; x++) ((uint16_t *)row)[x] = (uint16_t)c;
    }
}
// copy (with optional source colour key, and nearest-neighbour stretch)
static void blit(Surf *d, int dx0, int dy0, int dx1, int dy1, Surf *s, int sx0, int sy0, int sx1, int sy1, int key) {
    int dw = dx1 - dx0, dh = dy1 - dy0, sw = sx1 - sx0, sh = sy1 - sy0;
    if (dw <= 0 || dh <= 0 || sw <= 0 || sh <= 0) return;
    int bpp = d->bpp / 8;
    if (s->bpp != d->bpp) { host_log("blit between %d and %d bpp ignored\n", s->bpp, d->bpp); return; }
    for (int y = 0; y < dh; y++) {
        int ty = dy0 + y; if (ty < 0 || ty >= d->h) continue;
        int fy = sy0 + (int)((int64_t)y * sh / dh); if (fy < 0 || fy >= s->h) continue;
        uint8_t *drow = G + d->bits + (size_t)ty * d->pitch;
        const uint8_t *srow = G + s->bits + (size_t)fy * s->pitch;
        if (!key && dw == sw && dx0 >= 0 && dx1 <= d->w && sx0 >= 0 && sx1 <= s->w) {
            memmove(drow + dx0 * bpp, srow + sx0 * bpp, (size_t)dw * bpp);
            continue;
        }
        for (int x = 0; x < dw; x++) {
            int tx = dx0 + x; if (tx < 0 || tx >= d->w) continue;
            int fx = sx0 + (int)((int64_t)x * sw / dw); if (fx < 0 || fx >= s->w) continue;
            if (bpp == 1) { uint8_t c = srow[fx]; if (key && c >= s->ck_lo && c <= s->ck_hi) continue; drow[tx] = c; }
            else { uint16_t c = ((const uint16_t *)srow)[fx]; if (key && c >= s->ck_lo && c <= s->ck_hi) continue; ((uint16_t *)drow)[tx] = c; }
        }
    }
}
static void s_Blt(void) {
    THIS_S(6);
    DDLOG("Blt #%d <- #%d flags %08x\n", si, sid(ARG(2)), ARG(4));
    uint32_t drect = ARG(1), src = ARG(2), srect = ARG(3), fl = ARG(4), fx = ARG(5);
    int x0, y0, x1, y1; rect_of(drect, s, &x0, &y0, &x1, &y1);
    if (fl & 0x400) fill(s, x0, y0, x1, y1, R32(fx + 80));              // DDBLT_COLORFILL
    else {
        int ti = sid(src);
        if (ti >= 0) {
            Surf *t = &S[ti];
            int a0, b0, a1, b1; rect_of(srect, t, &a0, &b0, &a1, &b1);
            int key = 0;
            if ((fl & 0x8000) && t->has_ck) key = 1;                    // DDBLT_KEYSRC
            if (fl & 0x10000) { key = 1; t->ck_lo = R32(fx + 92); t->ck_hi = R32(fx + 96); }   // KEYSRCOVERRIDE
            blit(s, x0, y0, x1, y1, t, a0, b0, a1, b1, key);
        }
    }
    if (si == primary_id) present();
    SRET(0, 6);
}
static void s_BltFast(void) {
    THIS_S(6);
    DDLOG("BltFast #%d <- #%d\n", si, sid(ARG(3)));
    int x = (int)ARG(1), y = (int)ARG(2); uint32_t src = ARG(3), srect = ARG(4), tr = ARG(5);
    int ti = sid(src);
    if (ti >= 0) {
        Surf *t = &S[ti];
        int a0, b0, a1, b1; rect_of(srect, t, &a0, &b0, &a1, &b1);
        blit(s, x, y, x + (a1 - a0), y + (b1 - b0), t, a0, b0, a1, b1, (tr & 1) && t->has_ck);
    }
    if (si == primary_id) present();
    SRET(0, 6);
}
static void s_Flip(void) {
    THIS_S(3);
    DDLOG("Flip #%d\n", si);
    int b = sid(s->attached);
    if (b >= 0 && si == primary_id) {
        // rotate the bits through the chain so the object the game draws into keeps being the back buffer
        uint32_t t = s->bits; s->bits = S[b].bits; S[b].bits = t;
        present();
    }
    SRET(0, 3);
}
static void s_GetAttachedSurface(void) {
    THIS_S(3);
    if (!s->attached) { W32(ARG(2), 0); SRET(0x88760000u + 255, 3); }
    int a = sid(s->attached); if (a >= 0) S[a].ref++;
    W32(ARG(2), s->attached);
    SRET(0, 3);
}
static void s_AddAttachedSurface(void) { THIS_S(2); if (!s->attached) s->attached = ARG(1); SRET(0, 2); }
static void s_GetCaps(void) { THIS_S(2); W32(ARG(1), s->caps); SRET(0, 2); }
static void s_GetPixelFormat(void) { THIS_S(2); write_pf(ARG(1), s->bpp); SRET(0, 2); }
static void s_GetSurfaceDesc(void) { THIS_S(2); write_desc(ARG(1), s); SRET(0, 2); }
static void s_Lock(void) {
    THIS_S(5);
    uint32_t r = ARG(1), d = ARG(2);
    write_desc(d, s);
    DDLOG("Lock #%d rect %08x\n", si, r);
    // Software 3D scenes are never cleared: the world covers the screen, but polygons dropped at the near plane
    // (the camera inside a dying character) leave holes that keep older frames, a smear. game.c names the lock
    // that starts a frame's drawing; the back buffer is cleared to the darkest palette colour first.
    {
        extern int port_clear_on_lock(uint32_t ret_addr);
        if (!locked_since_present && s->bpp == 8 && !r && !(s->caps & 0x200) && port_clear_on_lock(R32(R.esp))) {
            uint32_t *pal = pal_rgb[s->palette ? R32(s->palette + 4) & 63 : 0];
            int best = 0, bv = 1 << 30;
            for (int k = 0; k < 256; k++) { int v = (pal[k] >> 16) + ((pal[k] >> 8) & 255) + (pal[k] & 255); if (v < bv) { bv = v; best = k; } }
            COW(s->bits, (uint32_t)(s->pitch * s->h));
            memset(G + s->bits, best, (size_t)s->pitch * s->h);
        }
        locked_since_present = 1;
    }
    if (r) W32(d + 36, s->bits + R32(r + 4) * s->pitch + R32(r) * (s->bpp / 8));
    s->locked = 1;
    SRET(0, 5);
}
static void s_Unlock(void) {
    THIS_S(2);
    s->locked = 0;
    if (si == primary_id && !s->attached) present();
    SRET(0, 2);
}
static void s_SetColorKey(void) {
    THIS_S(3);
    if (ARG(1) & 8) { s->has_ck = ARG(2) != 0; if (ARG(2)) { s->ck_lo = R32(ARG(2)); s->ck_hi = R32(ARG(2) + 4); } }
    SRET(0, 3);
}
static void s_GetColorKey(void) { THIS_S(3); W32(ARG(2), s->ck_lo); W32(ARG(2) + 4, s->ck_hi); SRET(s->has_ck ? 0 : 0x88760000u + 75, 3); }
static void s_SetPalette(void) { THIS_S(2); DDLOG("SetPalette #%d %08x\n", si, ARG(1)); s->palette = ARG(1); if (si == primary_id) for (int i = 0; i < MAXS; i++) if (S[i].used) S[i].palette = ARG(1); SRET(0, 2); }
static void s_GetPalette(void) { THIS_S(2); W32(ARG(1), s->palette); SRET(s->palette ? 0 : 0x88760000u + 83, 2); }
static void s_SetClipper(void) { THIS_S(2); s->clipper = ARG(1); SRET(0, 2); }
static void s_GetDC(void) { W32(ARG(1), 0x00050002); SRET(0, 2); }
static void s_ok1(void) { SRET(0, 1); }
static void s_ok2(void) { SRET(0, 2); }
static void s_ok3(void) { SRET(0, 3); }
static void s_GetBltStatus(void) { SRET(0, 2); }
static void s_GetFlipStatus(void) { SRET(0, 2); }
static void s_GetDDInterface(void) { W32(ARG(1), dd_obj); SRET(0, 2); }
static void s_unimpl(void) { host_fatal("IDirectDrawSurface method not implemented (ret %08x)", R32(R.esp)); }

// ---------------------------------------------------------------- palette / clipper
static void p_SetEntries(void) {
    uint32_t o = ARG(0), base = ARG(2), n = ARG(3), e = ARG(4);
    int i = (int)(R32(o + 4) & 63);
    DDLOG("Palette %d SetEntries %u..%u\n", i, base, base + n);
    for (uint32_t k = 0; k < n && base + k < 256; k++) {
        uint32_t v = R32(e + k * 4);
        pal_rgb[i][base + k] = ((v & 0xff) << 16) | (v & 0xff00) | ((v >> 16) & 0xff);
    }
    if (primary_id >= 0 && S[primary_id].bpp == 8 && S[primary_id].palette == o) present();
    SRET(0, 5);
}
static void p_GetEntries(void) {
    uint32_t o = ARG(0), base = ARG(2), n = ARG(3), e = ARG(4);
    int i = (int)(R32(o + 4) & 63);
    for (uint32_t k = 0; k < n && base + k < 256; k++) {
        uint32_t c = pal_rgb[i][base + k];
        W32(e + k * 4, ((c >> 16) & 0xff) | (c & 0xff00) | ((c & 0xff) << 16));
    }
    SRET(0, 5);
}
static void p_GetCaps(void) { W32(ARG(1), 4 | 0x40); SRET(0, 2); }
static void c_GetClipList(void) { if (ARG(3)) W32(ARG(3), 0); SRET(0, 4); }
static void c_GetHWnd(void) { W32(ARG(1), g_hwnd); SRET(0, 2); }
static void c_IsClipListChanged(void) { W32(ARG(1), 0); SRET(0, 2); }
static void c_ok4(void) { SRET(0, 4); }

// ---------------------------------------------------------------- entry points
static void build_vtables(void) {
    if (vt_dd) return;
    GFunc dd[] = { dd_QueryInterface, dd_AddRef, dd_Release, dd_ok1 /*Compact*/, dd_CreateClipper, dd_CreatePalette,
        dd_CreateSurface, dd_unimpl /*DuplicateSurface*/, dd_EnumDisplayModes, dd_unimpl /*EnumSurfaces*/,
        dd_ok1 /*FlipToGDISurface*/, dd_GetCaps, dd_GetDisplayMode, dd_GetFourCCCodes, dd_unimpl /*GetGDISurface*/,
        dd_GetMonitorFrequency, dd_GetScanLine, dd_GetVerticalBlankStatus, dd_ok2 /*Initialize*/,
        dd_ok1 /*RestoreDisplayMode*/, dd_ok3 /*SetCooperativeLevel*/, dd_SetDisplayMode, dd_ok3 /*WaitForVerticalBlank*/ };
    vt_dd = com_vtable(23, dd, "IDirectDraw");
    GFunc dd2[24];
    memcpy(dd2, dd, sizeof dd);
    dd2[21] = dd2_SetDisplayMode;
    dd2[23] = dd_GetAvailableVidMem;
    vt_dd2 = com_vtable(24, dd2, "IDirectDraw2");
    GFunc sf[] = { s_QueryInterface, s_AddRef, s_Release, s_AddAttachedSurface, s_ok2 /*AddOverlayDirtyRect*/,
        s_Blt, s_unimpl /*BltBatch*/, s_BltFast, s_ok3 /*DeleteAttachedSurface*/, s_unimpl /*EnumAttachedSurfaces*/,
        s_unimpl /*EnumOverlayZOrders*/, s_Flip, s_GetAttachedSurface, s_GetBltStatus, s_GetCaps,
        s_unimpl /*GetClipper*/, s_GetColorKey, s_GetDC, s_GetFlipStatus, s_unimpl /*GetOverlayPosition*/,
        s_GetPalette, s_GetPixelFormat, s_GetSurfaceDesc, s_ok3 /*Initialize*/, s_ok1 /*IsLost*/, s_Lock,
        s_ok2 /*ReleaseDC*/, s_ok1 /*Restore*/, s_SetClipper, s_SetColorKey, s_unimpl /*SetOverlayPosition*/,
        s_SetPalette, s_Unlock, s_unimpl /*UpdateOverlay*/, s_unimpl, s_unimpl,
        s_GetDDInterface, s_ok2 /*PageLock*/, s_ok2 /*PageUnlock*/, s_ok3 /*SetSurfaceDesc*/ };
    vt_surf = com_vtable(40, sf, "IDirectDrawSurface");
    GFunc pl[] = { s_ok3 /*QI*/, dd_AddRef, dd_Release, p_GetCaps, p_GetEntries, c_ok4 /*Initialize*/, p_SetEntries };
    vt_pal = com_vtable(7, pl, "IDirectDrawPalette");
    GFunc cl[] = { s_ok3, dd_AddRef, dd_Release, c_GetClipList, c_GetHWnd, dd_ok3 /*Initialize*/, c_IsClipListChanged,
        dd_ok3 /*SetClipList*/, dd_ok3 /*SetHWnd*/ };
    vt_clip = com_vtable(9, cl, "IDirectDrawClipper");
    dd_obj = com_new(vt_dd, 16);
    dd2_obj = com_new(vt_dd2, 16);
}

void shim_DirectDrawCreate(void) {
    build_vtables();
    host_log("DirectDrawCreate\n");
    W32(ARG(1), dd_obj);
    SRET(0, 3);
}
void shim_DirectDrawEnumerateA(void) {
    uint32_t cb = ARG(0), ctx = ARG(1);
    uint32_t desc = guest_strdup("Primary Display Driver"), name = guest_strdup("display");
    guest_call(cb, 4, 0, desc, name, ctx);
    SRET(0, 2);
}
