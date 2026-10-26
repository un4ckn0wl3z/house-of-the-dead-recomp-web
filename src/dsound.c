// DirectSound 8 emulation: software mixer on SDL audio.
#include "host.h"
#include "netplay.h"
#include <math.h>
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define MIX_RATE 44100
#define MAXBUF 512

typedef struct {
    int used, ref, primary;
    uint32_t g;
    uint32_t data;           // guest buffer
    uint32_t size;
    int *shared;             // refcount of data shared by duplicates
    int channels, bits, rate, freq;
    int playing, looping;
    double pos;              // in frames
    double vpos;             // online: the position the game sees, advanced by the game clock
    int vplaying;            // online: the status the game sees
    uint32_t vclock;
    float vol, panl, panr;
    int32_t vol_db, pan_db;
} SBuf;

static SBuf bufs[MAXBUF];
static uint32_t vt_ds, vt_buf, g_ds;
static SDL_AudioDeviceID dev;

static void lock_audio(void) { if (dev) SDL_LockAudioDevice(dev); }
static void unlock_audio(void) { if (dev) SDL_UnlockAudioDevice(dev); }

// Online play: the game must read the same buffer positions and status on every client, so it sees them
// advance with the game clock instead of the audio device; playback is pulled back to that position whenever
// the two drift apart by more than 150 ms.
static uint32_t frame_bytes(const SBuf *b) { return (uint32_t)(b->channels * b->bits / 8); }
static void net_advance(SBuf *b) {
    if (net_mode == NET_OFF) return;
    uint32_t now = net_clock();
    if (b->vplaying && b->size) {
        double frames = (double)(b->size / frame_bytes(b));
        b->vpos += (double)(now - b->vclock) * b->freq / 1000.0;
        if (b->vpos >= frames) {
            if (b->looping) b->vpos = fmod(b->vpos, frames);
            else { b->vplaying = 0; b->vpos = 0; }
        }
    }
    b->vclock = now;
}
static void net_follow(SBuf *b) {
    if (net_mode == NET_OFF || !b->vplaying) return;
    double d = b->pos - b->vpos;
    if (d > b->freq * 0.15 || d < -b->freq * 0.15) { lock_audio(); b->pos = b->vpos; b->playing = 1; unlock_audio(); }
}

static SBuf *getb(uint32_t g) {
    uint32_t i = R32(g + 4);
    if (i >= MAXBUF || !bufs[i].used) return NULL;
    return &bufs[i];
}

static inline float sample_at(SBuf *b, uint32_t frame, int ch) {
    if (b->bits == 16) {
        int16_t v; memcpy(&v, G + b->data + (frame * b->channels + (b->channels > 1 ? ch : 0)) * 2, 2);
        return v / 32768.0f;
    }
    return (G[b->data + frame * b->channels + (b->channels > 1 ? ch : 0)] - 128) / 128.0f;
}

static void SDLCALL audio_cb(void *ud, Uint8 *stream, int len) {
    (void)ud;
    int n = len / 4;
    static float acc[8192 * 2];
    if (n > 8192) n = 8192;
    memset(acc, 0, n * 2 * sizeof(float));
    for (int i = 0; i < MAXBUF; i++) {
        SBuf *b = &bufs[i];
        if (!b->used || !b->playing || b->primary || !b->size) continue;
        uint32_t frames = b->size / (b->channels * b->bits / 8);
        if (!frames) continue;
        double step = (double)b->freq / MIX_RATE;
        float mute = net_skip_render ? 0.0f : 1.0f;   // silent while an online guest catches up
        float gl = b->vol * b->panl * mute, gr = b->vol * b->panr * mute;
        double pos = b->pos;
        for (int s = 0; s < n; s++) {
            uint32_t f0 = (uint32_t)pos;
            if (f0 >= frames) {
                if (b->looping) { pos -= frames; f0 = (uint32_t)pos; if (f0 >= frames) { pos = 0; f0 = 0; } }
                else { b->playing = 0; pos = 0; break; }
            }
            uint32_t f1 = f0 + 1;
            if (f1 >= frames) f1 = b->looping ? 0 : f0;
            float t = (float)(pos - f0);
            float l = sample_at(b, f0, 0) * (1 - t) + sample_at(b, f1, 0) * t;
            float r = sample_at(b, f0, 1) * (1 - t) + sample_at(b, f1, 1) * t;
            acc[s * 2] += l * gl;
            acc[s * 2 + 1] += r * gr;
            pos += step;
        }
        b->pos = pos;
    }
    { extern void cdmusic_mix(float *acc, int n); cdmusic_mix(acc, n); }
    int16_t *out = (int16_t *)stream;
    for (int s = 0; s < n * 2; s++) {
        float v = acc[s];
        if (v > 1) v = 1; else if (v < -1) v = -1;
        out[s] = (int16_t)(v * 32767);
    }
}

void audio_init(void) {
    if (dev) return;
    SDL_AudioSpec want, have;
    memset(&want, 0, sizeof want);
    want.freq = MIX_RATE; want.format = AUDIO_S16SYS; want.channels = 2;
#ifdef __EMSCRIPTEN__
    want.samples = 4096;   // the mixer runs on the main thread: a long frame or a GC pause must not underrun it
#else
    want.samples = 1024;
#endif
    want.callback = audio_cb;
    dev = SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);
    if (!dev) { host_log("audio: cannot open device: %s\n", SDL_GetError()); return; }
    host_log("audio: %d Hz, %d ch, %d samples\n", have.freq, have.channels, have.samples);
    SDL_PauseAudioDevice(dev, 0);
}
void audio_shutdown(void) { if (dev) { SDL_CloseAudioDevice(dev); dev = 0; } }

static void apply_volpan(SBuf *b) {
    b->vol = b->vol_db <= -10000 ? 0.0f : powf(10.0f, b->vol_db / 2000.0f);
    float l = 1, r = 1;
    if (b->pan_db > 0) l = powf(10.0f, -b->pan_db / 2000.0f);
    else if (b->pan_db < 0) r = powf(10.0f, b->pan_db / 2000.0f);
    b->panl = l; b->panr = r;
}

// Each buffer slot keeps one guest COM object for good, pre-allocated outside the game's heap: engines
// duplicate and release a buffer per sound played, and online what a client plays can differ, so allocating
// these from the game's heap would make the heap (and so the game) differ between clients.
static uint32_t buf_obj[MAXBUF];
static uint32_t new_buf(void) {
    for (int i = 0; i < MAXBUF; i++) if (!bufs[i].used) {
        memset(&bufs[i], 0, sizeof bufs[i]);
        bufs[i].used = 1; bufs[i].ref = 1;
        bufs[i].vol = bufs[i].panl = bufs[i].panr = 1;
        uint32_t g = buf_obj[i];
        (COW(g, 16), memset(G + g, 0, 16));
        W32(g, vt_buf);
        W32(g + 4, (uint32_t)i);
        bufs[i].g = g;
        return (uint32_t)i;
    }
    host_log("dsound: out of buffers\n");
    return 0xffffffffu;
}

// ---------------------------------------------------------------- IDirectSound8
static void ds_QI(void) { if (ARG(2)) W32(ARG(2), 0); SRET(0x80004002u, 3); }
static void ds_AddRef(void) { SRET(1, 1); }
static void ds_Release(void) { SRET(0, 1); }
static void ds_CreateSoundBuffer(void) {
    uint32_t desc = ARG(1), out = ARG(2);
    uint32_t flags = R32(desc + 4), bytes = R32(desc + 8), wfx = R32(desc + 16);
    uint32_t i = new_buf();
    if (i == 0xffffffffu) SRET(0x8007000eu, 4);
    SBuf *b = &bufs[i];
    lock_audio();
    if (flags & 1) { b->primary = 1; }
    else {
        b->size = bytes;
        b->data = heap_alloc(bytes ? bytes : 16);
        (COW(b->data, (uint32_t)(bytes)), memset(G + b->data, 0, bytes));
        b->shared = calloc(1, sizeof(int)); *b->shared = 1;
        if (wfx) {
            b->channels = R16(wfx + 2); b->rate = R32(wfx + 4); b->bits = R16(wfx + 14);
        } else { b->channels = 2; b->rate = 22050; b->bits = 16; }
        if (b->channels < 1) b->channels = 1;
        if (b->bits != 8 && b->bits != 16) b->bits = 16;
        b->freq = b->rate;
    }
    unlock_audio();
    W32(out, b->g);
    SRET(0, 4);
}
static void ds_GetCaps(void) { (COW(ARG(1) + 4, (uint32_t)(R32(ARG(1)) > 4 ? R32(ARG(1)) - 4 : 0)), memset(G + ARG(1) + 4, 0, R32(ARG(1)) > 4 ? R32(ARG(1)) - 4 : 0)); SRET(0, 2); }
static void ds_DuplicateSoundBuffer(void) {
    SBuf *o = getb(ARG(1));
    if (!o) SRET(0x80070057u, 3);
    uint32_t i = new_buf();
    if (i == 0xffffffffu) SRET(0x8007000eu, 3);
    lock_audio();
    SBuf *b = &bufs[i];
    uint32_t g = b->g;
    *b = *o;
    b->g = g; b->ref = 1; b->playing = 0; b->pos = 0; b->vplaying = 0; b->vpos = 0;
    if (b->shared) (*b->shared)++;
    unlock_audio();
    W32(ARG(2), g);
    SRET(0, 3);
}
static void ds_ok2(void) { SRET(0, 2); }
static void ds_ok3(void) { SRET(0, 3); }
static void ds_ok1(void) { SRET(0, 1); }
static void ds_GetSpeakerConfig(void) { W32(ARG(1), 4); SRET(0, 2); }

// ---------------------------------------------------------------- IDirectSoundBuffer8
static void sb_AddRef(void) { SBuf *b = getb(ARG(0)); SRET(b ? ++b->ref : 0, 1); }
static void sb_Release(void) {
    SBuf *b = getb(ARG(0));
    if (!b) SRET(0, 1);
    int r = --b->ref;
    if (r <= 0) {
        lock_audio();
        b->playing = 0;
        if (b->shared && --(*b->shared) == 0) { heap_free(b->data); free(b->shared); }
        b->used = 0;
        unlock_audio();
        r = 0;
    }
    SRET(r, 1);
}
static void sb_GetCaps(void) {
    SBuf *b = getb(ARG(0)); uint32_t p = ARG(1);
    W32(p + 4, 0xe0); W32(p + 8, b ? b->size : 0); W32(p + 12, 0); W32(p + 16, 0);
    SRET(0, 2);
}
static void sb_GetCurrentPosition(void) {
    SBuf *b = getb(ARG(0));
    uint32_t pp = ARG(1), pw = ARG(2);
    uint32_t play = 0, write = 0;
    if (b && b->size) {
        uint32_t fb = b->channels * b->bits / 8;
        if (net_mode != NET_OFF) {
            net_advance(b);
            net_follow(b);
            play = ((uint32_t)b->vpos * fb) % b->size;
        } else {
            lock_audio();
            play = ((uint32_t)b->pos * fb) % b->size;
            unlock_audio();
        }
        uint32_t lat = (uint32_t)(b->freq * 0.03) * fb;
        write = (play + lat) % b->size;
    }
    if (pp) W32(pp, play);
    if (pw) W32(pw, write);
    SRET(0, 3);
}
static void sb_GetFormat(void) {
    SBuf *b = getb(ARG(0)); uint32_t p = ARG(1);
    if (p && b) {
        W16(p, 1); W16(p + 2, b->channels); W32(p + 4, b->rate); W32(p + 8, b->rate * b->channels * b->bits / 8);
        W16(p + 12, b->channels * b->bits / 8); W16(p + 14, b->bits); W16(p + 16, 0);
    }
    if (ARG(3)) W32(ARG(3), 18);
    SRET(0, 4);
}
static void sb_GetVolume(void) { SBuf *b = getb(ARG(0)); W32(ARG(1), b ? (uint32_t)b->vol_db : 0); SRET(0, 2); }
static void sb_GetPan(void) { SBuf *b = getb(ARG(0)); W32(ARG(1), b ? (uint32_t)b->pan_db : 0); SRET(0, 2); }
static void sb_GetFrequency(void) { SBuf *b = getb(ARG(0)); W32(ARG(1), b ? b->freq : 0); SRET(0, 2); }
static void sb_GetStatus(void) {
    SBuf *b = getb(ARG(0));
    uint32_t st = 0;
    if (b && net_mode != NET_OFF) net_advance(b);
    if (b && (net_mode != NET_OFF ? b->vplaying : b->playing)) st = 1 | (b->looping ? 4 : 0);
    W32(ARG(1), st);
    SRET(0, 2);
}
static void sb_Lock(void) {
    SBuf *b = getb(ARG(0));
    uint32_t off = ARG(1), n = ARG(2), pp1 = ARG(3), pb1 = ARG(4), pp2 = ARG(5), pb2 = ARG(6), flags = ARG(7);
    if (!b || !b->size) SRET(0x80070057u, 8);
    if (flags & 2) { off = 0; n = b->size; }
    if (flags & 1) {
        uint32_t fb = b->channels * b->bits / 8;
        net_advance(b);
        double at = net_mode != NET_OFF ? b->vpos : b->pos;
        off = (((uint32_t)at * fb) + (uint32_t)(b->freq * 0.03) * fb) % b->size;
    }
    off %= b->size;
    if (n > b->size) n = b->size;
    uint32_t n1 = n, n2 = 0;
    if (off + n > b->size) { n1 = b->size - off; n2 = n - n1; }
    W32(pp1, b->data + off); W32(pb1, n1);
    if (pp2) W32(pp2, n2 ? b->data : 0);
    if (pb2) W32(pb2, n2);
    SRET(0, 8);
}
static void sb_Play(void) {
    SBuf *b = getb(ARG(0));
    if (b) {
        net_advance(b);
        lock_audio(); b->playing = 1; b->looping = (ARG(3) & 1) != 0; unlock_audio();
        b->vplaying = 1;
        if (net_mode != NET_OFF) { lock_audio(); b->pos = b->vpos; unlock_audio(); }
    }
    SRET(0, 4);
}
static void sb_SetCurrentPosition(void) {
    SBuf *b = getb(ARG(0));
    if (b && b->size) {
        net_advance(b);
        lock_audio(); b->pos = (double)(ARG(1) % b->size) / (b->channels * b->bits / 8); unlock_audio();
        b->vpos = (double)(ARG(1) % b->size) / (b->channels * b->bits / 8);
    }
    SRET(0, 2);
}
static void sb_SetVolume(void) { SBuf *b = getb(ARG(0)); if (b) { b->vol_db = (int32_t)ARG(1); apply_volpan(b); } SRET(0, 2); }
static void sb_SetPan(void) { SBuf *b = getb(ARG(0)); if (b) { b->pan_db = (int32_t)ARG(1); apply_volpan(b); } SRET(0, 2); }
static void sb_SetFrequency(void) {
    SBuf *b = getb(ARG(0));
    if (b) b->freq = ARG(1) ? (int)ARG(1) : b->rate;
    SRET(0, 2);
}
static void sb_Stop(void) { SBuf *b = getb(ARG(0)); if (b) { net_advance(b); lock_audio(); b->playing = 0; unlock_audio(); b->vplaying = 0; } SRET(0, 1); }
static void sb_Unlock(void) { SRET(0, 5); }
static void sb_ok1(void) { SRET(0, 1); }
static void sb_ok2(void) { SRET(0, 2); }
static void sb_ok3(void) { SRET(0, 3); }
static void sb_ok4(void) { SRET(0, 4); }
static void sb_ok5(void) { SRET(0x80004001u, 5); }

void shim_DirectSoundCreate8(void) {
    if (!vt_ds) {
        GFunc ds[12] = { ds_QI, ds_AddRef, ds_Release, ds_CreateSoundBuffer, ds_GetCaps, ds_DuplicateSoundBuffer,
                         ds_ok3, ds_ok1, ds_GetSpeakerConfig, ds_ok2, ds_ok2, ds_ok2 };
        vt_ds = com_vtable(12, ds, "IDirectSound8");
        GFunc sb[24] = { ds_QI, sb_AddRef, sb_Release, sb_GetCaps, sb_GetCurrentPosition, sb_GetFormat, sb_GetVolume,
                         sb_GetPan, sb_GetFrequency, sb_GetStatus, sb_ok3, sb_Lock, sb_Play, sb_SetCurrentPosition,
                         sb_ok2, sb_SetVolume, sb_SetPan, sb_SetFrequency, sb_Stop, sb_Unlock, sb_ok1, sb_ok4, sb_ok4, sb_ok5 };
        vt_buf = com_vtable(24, sb, "IDirectSoundBuffer8");
        g_ds = com_new(vt_ds, 16);
        for (int i = 0; i < MAXBUF; i++) buf_obj[i] = guest_static_alloc(16);   // all at once, in order
    }
    audio_init();
    W32(ARG(1), g_ds);
    host_log("DirectSoundCreate8\n");
    SRET(0, 3);
}
