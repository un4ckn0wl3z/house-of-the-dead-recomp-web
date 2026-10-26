// Online play (lockstep): every player runs the whole game; only input travels. Proven on a recompiled MSVC6
// shooter (references/multiplayer.md has the full story and the pitfalls).
//
// The host plays normally. After each frame's message pump (net_after_pump, called from the game's frame hook)
// it packs that frame's input into a bundle: the engine's own input block (it drives the menus, the scripts and
// player 1), each guest's latest input and any join/leave events. The page sends the bundle to the lobby server,
// which relays it to the guests and keeps a log. A guest simulates frame N only once it has bundle N, overwriting
// its own input block with the host's, so every client computes the same game; a late joiner boots from the
// host's starting save files and replays the log without drawing. Every 60th frame the host puts a state checksum
// into the bundle and a guest that computes another one reports a desync.
//
// Determinism also needs (done in the shims): timeGetTime/calendar time from the frame number (net_clock),
// DirectSound positions advancing with that clock, no WM_ACTIVATEAPP 0, and each client's own view drawn in an
// undoable pass (net_cow_begin/end) after the host's view went through the engine with drawing switched off.
//
// Native tests: PORT_NET_TEST=1 runs as a host with the virtual clock and logs checksums (PORT_NET_RECORD=file
// also writes the bundles, PORT_NET_VIEW=slot draws that player's view, PORT_NET_SKIP=n skips drawing every n-th
// frame); PORT_NET_REPLAY=file PORT_NET_VIEW=slot runs as that guest from recorded bundles and reports desyncs.
#include "host.h"
#include "netplay.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define NET_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define NET_EXPORT
#endif

#define CRC_EVERY 60
#define INPUT_MAX 64

int net_mode, net_local, net_skip_render;
static uint32_t tact;
static int view_slot, skip_every;
static FILE *record;
static uint32_t checks_ok;

#pragma pack(push, 1)
typedef struct {
    uint32_t frame;
    uint32_t crc;                       // state checksum at this frame (every CRC_EVERY frames), else 0
    uint8_t input[INPUT_MAX];           // the host's input block (port_input_block)
    NetInput guest[NET_MAX_PLAYERS - 1];
    uint8_t nev;
    NetEvent ev[4];
} Bundle;
#pragma pack(pop)
#define BUNDLE_HEAD offsetof(Bundle, ev)

uint32_t net_tact(void) { return tact; }
int net_view_slot(void) { return net_mode == NET_TEST ? view_slot : net_local; }
int net_test_skip_frame(void) { return skip_every > 0 && tact % (uint32_t)skip_every == 0; }

// ---------------------------------------------------------------- clock
// 60 frames per second of game clock. Code that waits for the clock inside one frame would never finish, so a
// value read very many times in one frame creeps forward (by the same amount on every client).
static uint32_t clock_reads, clock_bump, clock_tact;
uint32_t net_clock(void) {
    if (clock_tact != tact) { clock_tact = tact; clock_reads = 0; }
    if (++clock_reads > 1000000) { clock_reads = 0; clock_bump++; }
    return 100000u + (uint32_t)((uint64_t)tact * 1000 / 60) + clock_bump;
}

uint32_t crc_mix(uint32_t h, uint32_t v) {
    for (int i = 0; i < 4; i++) { h ^= (v >> (8 * i)) & 0xff; h *= 16777619u; }
    return h;
}
static uint32_t state_crc(void) { uint32_t h = port_state_crc(2166136261u); return h ? h : 1; }

// ---------------------------------------------------------------- guest stack and undoable passes
#define STACK_SAVE (512 * 1024)
static uint8_t stack_copy[4][STACK_SAVE];
static uint32_t stack_at[4];
static int stack_depth;
void net_stack_save(void) {
    if (net_mode == NET_OFF || stack_depth >= 4 || R.esp < STACK_SAVE) { stack_depth++; return; }
    stack_at[stack_depth] = R.esp - STACK_SAVE;
    memcpy(stack_copy[stack_depth], G + stack_at[stack_depth], STACK_SAVE);
    stack_depth++;
}
void net_stack_restore(void) {
    if (--stack_depth < 0) { stack_depth = 0; return; }
    if (net_mode == NET_OFF || stack_depth >= 4 || !stack_at[stack_depth]) return;
    memcpy(G + stack_at[stack_depth], stack_copy[stack_depth], STACK_SAVE);
}

int g_cow;
static uint8_t cow_seen[GUEST_SIZE >> 12];
static uint32_t *cow_pages;
static uint8_t *cow_data;
static size_t cow_n, cow_cap;
void heap_state_save(void);
void heap_state_restore(void);
static void cow_page(uint32_t page) {
    if (cow_n == cow_cap) {
        cow_cap = cow_cap ? cow_cap * 2 : 2048;
        cow_pages = realloc(cow_pages, cow_cap * sizeof *cow_pages);
        cow_data = realloc(cow_data, cow_cap * 4096);
    }
    cow_seen[page] = 1;
    cow_pages[cow_n] = page;
    memcpy(cow_data + cow_n * 4096, G + ((size_t)page << 12), 4096);
    cow_n++;
}
void cow_range(uint32_t a, uint32_t n) {
    if (!n) return;
    for (uint32_t p = a >> 12, q = (a + n - 1) >> 12; p <= q && p < (GUEST_SIZE >> 12); p++) if (!cow_seen[p]) cow_page(p);
}
void net_cow_begin(void) { cow_n = 0; heap_state_save(); g_cow = 1; }
void net_cow_end(void) {
    g_cow = 0;
    for (size_t i = cow_n; i-- > 0; ) {
        memcpy(G + ((size_t)cow_pages[i] << 12), cow_data + i * 4096, 4096);
        cow_seen[cow_pages[i]] = 0;
    }
    cow_n = 0;
    heap_state_restore();
}

// ---------------------------------------------------------------- host side
static NetInput latest[NET_MAX_PLAYERS];   // each guest's latest input; chr/key stay until sent once
// Several guest messages can arrive between two host frames: a quick click (press, then release) would be
// overwritten by the release and lost. Button bits (NET_LATCH: trigger and reload in gun_input.c) are kept,
// with the aim at the press, until a bundle has carried them.
#define NET_LATCH 3u
static uint32_t latched[NET_MAX_PLAYERS];
static float latched_x[NET_MAX_PLAYERS], latched_y[NET_MAX_PLAYERS];
static NetEvent pending_ev[16];
static int npending_ev;
static NetEvent *queue_event(int type, int slot, const char *name) {
    static NetEvent spare;
    if (npending_ev >= 16) return &spare;
    NetEvent *e = &pending_ev[npending_ev++];
    memset(e, 0, sizeof *e);
    e->type = (uint8_t)type; e->slot = (uint8_t)slot;
    if (name) snprintf(e->name, sizeof e->name, "%s", name);
    return e;
}

// ---------------------------------------------------------------- guest side: received bundles
static uint8_t *queue; static size_t qlen, qcap, qpos;
static int nqueued;
int net_pending(void) { return nqueued; }

static void apply_bundle(const Bundle *b) {
    for (int i = 0; i < b->nev && i < 4; i++) {
        const NetEvent *e = &b->ev[i];
        char name[31]; memcpy(name, e->name, 30); name[30] = 0;
        if (e->type == 1) port_net_join(e->slot, name, e->data);
        else if (e->type == 2) port_net_leave(e->slot);
    }
    for (int s = 1; s < NET_MAX_PLAYERS; s++) port_net_input(s, &b->guest[s - 1]);
}

static void desync(uint32_t frame, uint32_t want, uint32_t have) {
    static int reported;
    host_log("netplay: DESYNC at frame %u: host %08x, here %08x\n", frame, want, have);
    if (reported++) return;
#ifdef __EMSCRIPTEN__
    EM_ASM({ if (Module.onNetDesync) Module.onNetDesync($0); }, frame);
#endif
}

void net_frame_begin(void) { tact++; }

void net_after_pump(void) {
    if (net_mode == NET_OFF) return;
    uint32_t size = 0, block = port_input_block(&size);
    if (size > INPUT_MAX) size = INPUT_MAX;
    Bundle b;
    memset(&b, 0, sizeof b);
    if (net_mode == NET_GUEST) {
        if (qpos + BUNDLE_HEAD > qlen) { host_log("netplay: no input for frame %u\n", tact); return; }
        memcpy(&b, queue + qpos, BUNDLE_HEAD);
        size_t len = BUNDLE_HEAD + (size_t)b.nev * sizeof(NetEvent);
        memcpy(&b, queue + qpos, len);
        qpos += len; nqueued--;
        if (qpos == qlen) qpos = qlen = 0;
        if (b.frame != tact) host_log("netplay: bundle for frame %u arrived at frame %u\n", b.frame, tact);
        if (b.crc) { uint32_t mine = state_crc(); if (mine != b.crc) desync(tact, b.crc, mine); else checks_ok++; }
        if (block) memcpy(G + block, b.input, size);
    } else {
        b.frame = tact;
        if (tact % CRC_EVERY == 0) {
            b.crc = state_crc();
            if (net_mode == NET_TEST) host_log("crc @%u %08x heap %u\n", tact, b.crc, heap_used_bytes());
        }
        if (block) memcpy(b.input, G + block, size);
        for (int s = 1; s < NET_MAX_PLAYERS; s++) {
            net_stack_save();
            NetInput bot;
            if (port_bot_input(s, &bot)) { latest[s].flags = bot.flags; latest[s].wx = bot.wx; latest[s].wy = bot.wy; }
            net_stack_restore();
            b.guest[s - 1] = latest[s];
            if (latched[s]) {           // a press since the last bundle: this frame shows it, where it happened
                b.guest[s - 1].flags |= latched[s];
                if (!(latest[s].flags & latched[s])) { b.guest[s - 1].wx = latched_x[s]; b.guest[s - 1].wy = latched_y[s]; }
                latched[s] = 0;
            }
            latest[s].chr = latest[s].key = 0;
        }
        while (npending_ev > 0 && b.nev < 4) {
            b.ev[b.nev++] = pending_ev[0];
            memmove(pending_ev, pending_ev + 1, sizeof pending_ev[0] * (size_t)--npending_ev);
        }
        int len = (int)(BUNDLE_HEAD + b.nev * sizeof(NetEvent));
#ifdef __EMSCRIPTEN__
        if (net_mode == NET_HOST) EM_ASM({ if (Module.netOnBundle) Module.netOnBundle(HEAPU8.slice($0, $0 + $1)); }, &b, len);
#endif
        if (record) { fwrite(&b, 1, (size_t)len, record); fflush(record); }
    }
    apply_bundle(&b);
}

// ---------------------------------------------------------------- calls from the web page
// mode 1 = host, 2 = guest; called before the game starts
NET_EXPORT void net_configure(int mode, int slot) {
    net_mode = mode == 1 ? NET_HOST : mode == 2 ? NET_GUEST : NET_OFF;
    net_local = slot;
    host_log("netplay: %s, player %d\n", net_mode == NET_HOST ? "hosting" : net_mode == NET_GUEST ? "guest" : "off", slot + 1);
}
// host: a guest joined (applied at the next frame on every client); data: up to 44 game-defined bytes as hex
NET_EXPORT void net_host_join(int slot, const char *name, const char *data_hex) {
    if (slot <= 0 || slot >= NET_MAX_PLAYERS) return;
    memset(&latest[slot], 0, sizeof latest[slot]);
    NetEvent *e = queue_event(1, slot, name);
    for (int i = 0; data_hex && data_hex[2 * i] && data_hex[2 * i + 1] && i < 44; i++) {
        unsigned v; if (sscanf(data_hex + 2 * i, "%2x", &v) == 1) e->data[i] = (uint8_t)v;
    }
}
NET_EXPORT void net_host_leave(int slot) { if (slot > 0 && slot < NET_MAX_PLAYERS) queue_event(2, slot, NULL); }
NET_EXPORT void net_host_input(int slot, int flags, float wx, float wy, int chr, int key) {
    if (slot <= 0 || slot >= NET_MAX_PLAYERS) return;
    NetInput *g = &latest[slot];
    uint32_t pressed = (uint32_t)flags & NET_LATCH & ~latched[slot];
    if (pressed) { latched[slot] |= pressed; latched_x[slot] = wx; latched_y[slot] = wy; }
    g->flags = (uint32_t)flags; g->wx = wx; g->wy = wy;
    if (key) { g->key = (uint8_t)key; g->chr = (uint8_t)chr; }
}
// guest: bundles from the host, in order (a message may hold several back to back)
NET_EXPORT void net_push_bundles(const uint8_t *data, int len) {
    if (len <= 0) return;
    if (qlen + (size_t)len > qcap) {
        if (qpos) { memmove(queue, queue + qpos, qlen - qpos); qlen -= qpos; qpos = 0; }
        if (qlen + (size_t)len > qcap) { qcap = (qlen + (size_t)len) * 2 + 65536; queue = realloc(queue, qcap); }
    }
    memcpy(queue + qlen, data, (size_t)len);
    qlen += (size_t)len;
    for (int off = 0; off + (int)BUNDLE_HEAD <= len; ) {
        off += (int)BUNDLE_HEAD + data[off + BUNDLE_HEAD - 1] * (int)sizeof(NetEvent);
        nqueued++;
    }
}
NET_EXPORT int net_queued(void) { return nqueued; }
NET_EXPORT int net_frame(void) { return (int)tact; }
// guest: this player's input; the cursor goes from screen to world coordinates with this client's own camera
NET_EXPORT void net_guest_input(int flags, int sx, int sy, int chr, int key) {
    float camx = 0, camy = 0;
    port_view_camera(net_local, &camx, &camy);
#ifdef __EMSCRIPTEN__
    EM_ASM({ if (Module.netSendInput) Module.netSendInput($0, $1, $2, $3, $4); }, flags, (double)(sx + camx), (double)(sy + camy), chr, key);
#else
    (void)flags; (void)chr; (void)key; (void)sx; (void)sy;
#endif
}

void net_init(void) {
    const char *t = getenv("PORT_NET_TEST"), *replay = getenv("PORT_NET_REPLAY");
    if (getenv("PORT_NET_VIEW")) view_slot = atoi(getenv("PORT_NET_VIEW"));
    if (getenv("PORT_NET_SKIP")) skip_every = atoi(getenv("PORT_NET_SKIP"));
    if (replay && *replay) {
        FILE *f = fopen(replay, "rb");
        if (!f) { host_log("netplay: cannot read %s\n", replay); return; }
        fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
        uint8_t *data = malloc((size_t)n + 1);
        if (fread(data, 1, (size_t)n, f) != (size_t)n) n = 0;
        fclose(f);
        net_push_bundles(data, (int)n);
        free(data);
        net_mode = NET_GUEST;
        net_local = view_slot;
        host_log("netplay: replaying %d bundles from %s as player %d\n", nqueued, replay, net_local + 1);
        return;
    }
    if (t && *t && *t != '0') {
        net_mode = NET_TEST;
        if (getenv("PORT_NET_RECORD")) record = fopen(getenv("PORT_NET_RECORD"), "wb");
        host_log("netplay: determinism test (virtual clock, checksums every %d frames)\n", CRC_EVERY);
    }
}
uint32_t net_checks_ok(void) { return checks_ok; }
