// CD audio for MCI "play cdaudio": the tracks come from the game folder's MUSIC/trackNN.wav (ripped CD tracks,
// as CD-audio patched installs have them). Native builds mix them into the DirectSound mixer; the web build
// streams music/trackNN.ogg (made by port.py) or .wav next to the page with an <audio> element.
#include "host.h"
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

static int cur, first, last, playing;
static volatile int mixing;     // native: the audio callback is playing a track
static float music_vol = 0.8f;

#include "netplay.h"
int cdmusic_playing(void) {
    // online the game must see the same CD status everywhere: "playing" from play until stop, whatever the
    // audio element does (it loops the range locally)
    if (net_mode != NET_OFF) return playing;
#ifdef __EMSCRIPTEN__
    return EM_ASM_INT({ return Module.cdAudio && !Module.cdAudio.paused && !Module.cdAudio.ended ? 1 : 0; }) || (playing && cur < last);
#else
    return mixing || (playing && cur < last);
#endif
}
int cdmusic_current_track(void) { return cur ? cur : 1; }
int cdmusic_num_tracks(void) { return 12; }

#ifdef __EMSCRIPTEN__
static void start_track(int t) {
    cur = t; playing = 1;
    EM_ASM({
        var t = ('0' + $0).slice(-2);
        var vol = $1;
        if (!Module.cdAudio) {
            Module.cdAudio = new Audio();
            Module.cdAudio.addEventListener('ended', function () { Module.ccall('cdmusic_track_ended', null, [], []); });
        }
        var a = Module.cdAudio;
        a.onerror = function () { if (a.src.endsWith('.ogg')) { a.src = 'music/track' + t + '.wav'; a.play().catch(function () {}); } };
        a.src = 'music/track' + t + '.ogg';
        a.volume = vol;
        a.play().catch(function () {});
    }, t, music_vol);
}
void cdmusic_stop(void) { playing = 0; EM_ASM({ if (Module.cdAudio) Module.cdAudio.pause(); }); }
EMSCRIPTEN_KEEPALIVE void cdmusic_track_ended(void) {
    if (playing && cur < last) start_track(cur + 1);
    else if (net_mode != NET_OFF && playing) start_track(first);
    else playing = 0;
}
void cdmusic_mix(float *acc, int n) { (void)acc; (void)n; }
#else
static int16_t *pcm;         // 44.1 kHz stereo of the current track
static uint32_t pcm_frames, pcm_pos;
static SDL_mutex *mu;

static int load_track(int t) {
    char gp[64], path[1024];
    snprintf(gp, sizeof gp, "MUSIC\\track%02d.wav", t);
    if (!fs_resolve(gp, path, sizeof path, 0)) return 0;
    SDL_AudioSpec spec; Uint8 *buf; Uint32 len;
    if (!SDL_LoadWAV(path, &spec, &buf, &len)) { host_log("music: %s: %s\n", path, SDL_GetError()); return 0; }
    SDL_AudioCVT cvt;
    SDL_BuildAudioCVT(&cvt, spec.format, spec.channels, spec.freq, AUDIO_S16SYS, 2, 44100);
    cvt.len = (int)len;
    cvt.buf = malloc((size_t)len * (cvt.len_mult > 0 ? cvt.len_mult : 1) + 16);
    memcpy(cvt.buf, buf, len);
    SDL_FreeWAV(buf);
    if (cvt.needed) SDL_ConvertAudio(&cvt);
    SDL_LockMutex(mu);
    free(pcm);
    pcm = (int16_t *)cvt.buf; pcm_frames = (uint32_t)cvt.len_cvt / 4; pcm_pos = 0;
    SDL_UnlockMutex(mu);
    return 1;
}
static void start_track(int t) {
    if (!mu) mu = SDL_CreateMutex();
    cur = t;
    playing = load_track(t);
    mixing = playing;
    if (!playing) host_log("music: track %d not found (MUSIC/track%02d.wav)\n", t, t);
}
void cdmusic_stop(void) {
    if (!mu) return;
    SDL_LockMutex(mu); playing = 0; mixing = 0; SDL_UnlockMutex(mu);
}
// called from the audio callback (dsound.c)
void cdmusic_mix(float *acc, int n) {
    if (!mu || !mixing) return;
    SDL_LockMutex(mu);
    for (int s = 0; s < n && pcm; s++) {
        if (pcm_pos >= pcm_frames) { mixing = 0; break; }
        acc[s * 2] += pcm[pcm_pos * 2] / 32768.0f * music_vol;
        acc[s * 2 + 1] += pcm[pcm_pos * 2 + 1] / 32768.0f * music_vol;
        pcm_pos++;
    }
    SDL_UnlockMutex(mu);
}
// next track of a "from N to M" range, checked from the main thread
void cdmusic_poll(void) {
    if (!mixing && playing && cur) {
        if (cur < last) start_track(cur + 1);
        else if (net_mode != NET_OFF) start_track(first);   // online: loop the range, the status stays "playing"
        else playing = 0;
    }
}
#endif

void cdmusic_play(int from, int to) {
    if (from < 1) from = 2;
    first = from;
    last = to > from ? to - 1 : from;     // MCI "to" is exclusive in TMSF track units
    if (to <= from) last = from;
    start_track(from);
}
