// GDI32, WINMM, ADVAPI32 (registry), OLE32, SHELL32, COMDLG32 shims + COM helpers + shim lookup.
#include "host.h"
#include "netplay.h"
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>

extern char g_save_dir[512];
extern int g_fs_dirty;

// ---------------------------------------------------------------- GDI (mostly inert)
static void g_CreateCompatibleDC(void) { SRET(0x00070001, 1); }
static void g_CreateDIBSection(void) {
    // (hdc, pbmi, usage, ppvBits, hSection, offset)
    uint32_t bmi = ARG(1), ppv = ARG(3);
    int32_t w = (int32_t)R32(bmi + 4), h = (int32_t)R32(bmi + 8);
    uint32_t bpp = R16(bmi + 14);
    if (h < 0) h = -h;
    uint32_t stride = ((w * bpp + 31) / 32) * 4;
    uint32_t bits = heap_alloc(stride * h + 16);
    (COW(bits, (uint32_t)(stride * h)), memset(G + bits, 0, stride * h));
    if (ppv) W32(ppv, bits);
    SRET(0x00080000 | (bits >> 8 & 0xffff), 6);
}
static void g_CreateFontA(void) { SRET(0x00090001, 14); }
static void g_DeleteDC(void) { SRET(1, 1); }
static void g_DeleteObject(void) { SRET(1, 1); }
static void g_ExtTextOutA(void) { SRET(1, 8); }
static void g_GetDeviceCaps(void) {
    int32_t i = (int32_t)ARG(1);
    SRET(i == 12 ? 32 : i == 8 ? 1024 : i == 10 ? 768 : i == 88 || i == 90 ? 96 : 0, 2);
}
static void g_GetPixel(void) { SRET(0, 3); }
static void g_SetPixel(void) { SRET(0, 4); }
static void g_GetStockObject(void) { SRET(0x000A0000 | ARG(0), 1); }
static void g_GetTextExtentPoint32A(void) {
    uint32_t n = ARG(2), sz = ARG(3);
    W32(sz, n * 7); W32(sz + 4, 12);
    SRET(1, 4);
}
static void g_SelectObject(void) { SRET(0x000A0000, 2); }
static void g_ret0_2(void) { SRET(0, 2); }

const ShimDef shims_gdi32[] = {
    {"GDI32", "CreateCompatibleDC", g_CreateCompatibleDC}, {"GDI32", "CreateDIBSection", g_CreateDIBSection},
    {"GDI32", "CreateFontA", g_CreateFontA}, {"GDI32", "DeleteDC", g_DeleteDC},
    {"GDI32", "DeleteObject", g_DeleteObject}, {"GDI32", "ExtTextOutA", g_ExtTextOutA},
    {"GDI32", "GetDeviceCaps", g_GetDeviceCaps}, {"GDI32", "GetPixel", g_GetPixel},
    {"GDI32", "SetPixel", g_SetPixel}, {"GDI32", "GetStockObject", g_GetStockObject},
    {"GDI32", "GetTextExtentPoint32A", g_GetTextExtentPoint32A}, {"GDI32", "SelectObject", g_SelectObject},
    {"GDI32", "SetBkColor", g_ret0_2}, {"GDI32", "SetMapMode", g_ret0_2},
    {"GDI32", "SetTextAlign", g_ret0_2}, {"GDI32", "SetTextColor", g_ret0_2},
    {0, 0, 0}
};

// ---------------------------------------------------------------- WINMM
// online play runs on a clock derived from the frame number, so every client computes the same game
static void w_timeGetTime(void) { SRET(net_mode != NET_OFF ? net_clock() : host_ticks(), 0); }
static void w_ret0_1(void) { SRET(0, 1); }
static void w_ret0_2(void) { SRET(0, 2); }
static void w_mciSendStringA(void) {
    host_log("mciSendString: %s\n", GSTR(ARG(0)));
    SRET(0, 4);
}

// ---------------------------------------------------------------- registry
#define MAXK 64
#define MAXV 256
static char keys[MAXK][256]; static int nkeys;
static struct { int key; char name[64]; uint32_t type; uint8_t data[512]; uint32_t len; } vals[MAXV];
static int nvals, reg_loaded;

static void reg_save(void) {
    char path[1024]; snprintf(path, sizeof path, "%s/registry.dat", g_save_dir);
    FILE *f = fopen(path, "wb");
    if (!f) return;
    for (int i = 0; i < nvals; i++) {
        fprintf(f, "%s\t%s\t%u\t%u\t", keys[vals[i].key], vals[i].name, vals[i].type, vals[i].len);
        for (uint32_t j = 0; j < vals[i].len; j++) fprintf(f, "%02x", vals[i].data[j]);
        fprintf(f, "\n");
    }
    fclose(f);
    g_fs_dirty = 1;
}
static int key_index(const char *path, int create) {
    for (int i = 0; i < nkeys; i++) if (!strcasecmp(keys[i], path)) return i;
    if (!create || nkeys >= MAXK) return -1;
    snprintf(keys[nkeys], 256, "%s", path);
    return nkeys++;
}
static void reg_load(void) {
    if (reg_loaded) return;
    reg_loaded = 1;
    char path[1024]; snprintf(path, sizeof path, "%s/registry.dat", g_save_dir);
    FILE *f = fopen(path, "rb");
    if (!f) return;
    char line[2048];
    while (fgets(line, sizeof line, f) && nvals < MAXV) {
        char *k = strtok(line, "\t"), *n = strtok(NULL, "\t"), *t = strtok(NULL, "\t"), *l = strtok(NULL, "\t"), *d = strtok(NULL, "\t\r\n");
        if (!k || !n || !t || !l) continue;
        int ki = key_index(k, 1);
        vals[nvals].key = ki; snprintf(vals[nvals].name, 64, "%s", n);
        vals[nvals].type = (uint32_t)atoi(t); vals[nvals].len = (uint32_t)atoi(l);
        if (vals[nvals].len > 512) vals[nvals].len = 512;
        for (uint32_t j = 0; d && j < vals[nvals].len; j++) { unsigned v; sscanf(d + j * 2, "%2x", &v); vals[nvals].data[j] = (uint8_t)v; }
        nvals++;
    }
    fclose(f);
}
static void key_path(uint32_t hkey, const char *sub, char *out) {
    const char *root = "HKCU";
    if (hkey == 0x80000002u) root = "HKLM";
    else if (hkey >= 0x100 && hkey < 0x100 + MAXK) root = keys[hkey - 0x100];
    if (sub && *sub) snprintf(out, 256, "%s\\%s", root, sub); else snprintf(out, 256, "%s", root);
}
static void a_RegOpenKeyExA(void) {
    reg_load();
    char p[256]; key_path(ARG(0), ARG(1) ? GSTR(ARG(1)) : "", p);
    int k = key_index(p, 0);
    if (k < 0) SRET(2, 5);
    W32(ARG(4), 0x100 + k);
    SRET(0, 5);
}
static void a_RegCreateKeyExA(void) {
    reg_load();
    char p[256]; key_path(ARG(0), ARG(1) ? GSTR(ARG(1)) : "", p);
    int ex = key_index(p, 0);
    int k = key_index(p, 1);
    if (k < 0) SRET(8, 9);
    W32(ARG(7), 0x100 + k);
    if (ARG(8)) W32(ARG(8), ex < 0 ? 1 : 2);
    SRET(0, 9);
}
static void a_RegCloseKey(void) { SRET(0, 1); }
// Read / set one of the game's own registry values (a string) from host code, e.g. a hidden option the game has
// no menu for, or a setting chosen on the web page. keypath as the shim stores it ("HKCU\\SOFTWARE\\...").
int reg_get_value(const char *keypath, const char *name, char *out, int outsz) {
    reg_load();
    int k = key_index(keypath, 0);
    for (int i = 0; k >= 0 && i < nvals; i++) if (vals[i].key == k && !strcasecmp(vals[i].name, name)) {
        snprintf(out, (size_t)outsz, "%.*s", (int)vals[i].len, (const char *)vals[i].data);
        return 1;
    }
    return 0;
}
void reg_set_value(const char *keypath, const char *name, const char *value) {
    reg_load();
    int k = key_index(keypath, 1);
    if (k < 0) return;
    int i;
    for (i = 0; i < nvals; i++) if (vals[i].key == k && !strcasecmp(vals[i].name, name)) break;
    if (i == nvals) { if (nvals >= MAXV) return; nvals++; }
    vals[i].key = k; snprintf(vals[i].name, 64, "%s", name); vals[i].type = 1;
    vals[i].len = (uint32_t)strlen(value) + 1;
    memcpy(vals[i].data, value, vals[i].len);
    reg_save();
}
static void a_RegQueryValueExA(void) {
    reg_load();
    int k = (int)ARG(0) - 0x100;
    const char *name = ARG(1) ? GSTR(ARG(1)) : "";
    uint32_t ptype = ARG(3), pdata = ARG(4), plen = ARG(5);
    for (int i = 0; i < nvals; i++) {
        if (vals[i].key == k && !strcasecmp(vals[i].name, name)) {
            if (ptype) W32(ptype, vals[i].type);
            if (plen) {
                uint32_t cap = R32(plen);
                W32(plen, vals[i].len);
                if (pdata) {
                    if (cap < vals[i].len) SRET(234, 6);
                    (COW(pdata, (uint32_t)(vals[i].len)), memcpy(G + pdata, vals[i].data, vals[i].len));
                }
            }
            SRET(0, 6);
        }
    }
    SRET(2, 6);
}
static void a_RegSetValueExA(void) {
    reg_load();
    int k = (int)ARG(0) - 0x100;
    const char *name = ARG(1) ? GSTR(ARG(1)) : "";
    uint32_t type = ARG(3), data = ARG(4), len = ARG(5);
    if (len > 512) len = 512;
    int i;
    for (i = 0; i < nvals; i++) if (vals[i].key == k && !strcasecmp(vals[i].name, name)) break;
    if (i == nvals) { if (nvals >= MAXV) SRET(8, 6); nvals++; }
    vals[i].key = k; snprintf(vals[i].name, 64, "%s", name); vals[i].type = type; vals[i].len = len;
    memcpy(vals[i].data, G + data, len);
    reg_save();
    SRET(0, 6);
}
static void a_RegDeleteValueA(void) {
    reg_load();
    int k = (int)ARG(0) - 0x100;
    const char *name = ARG(1) ? GSTR(ARG(1)) : "";
    for (int i = 0; i < nvals; i++) if (vals[i].key == k && !strcasecmp(vals[i].name, name)) {
        vals[i] = vals[--nvals]; reg_save(); SRET(0, 2);
    }
    SRET(2, 2);
}

// ---------------------------------------------------------------- OLE32 / SHELL32 / COMDLG32
static void o_CoInitialize(void) { SRET(0, 1); }
static void o_CoUninitialize(void) { SRET(0, 0); }
static void o_CoCreateInstance(void) {
    host_log("CoCreateInstance (not supported)\n");
    if (ARG(4)) W32(ARG(4), 0);
    SRET(0x80040154u, 5);
}
static void s_ShellExecuteA(void) {
    host_log("ShellExecute: %s\n", ARG(2) ? GSTR(ARG(2)) : "");
    SRET(42, 6);
}
static void c_GetFileName(void) { SRET(0, 1); }

// DirectX entry points (implemented in d3d8.c / dsound.c)
void shim_DirectSoundCreate8(void);

const ShimDef shims_misc[] = {
    {"WINMM", "timeGetTime", w_timeGetTime}, {"WINMM", "timeBeginPeriod", w_ret0_1},
    {"WINMM", "timeEndPeriod", w_ret0_1}, {"WINMM", "waveOutSetVolume", w_ret0_2},
    {"WINMM", "auxSetVolume", w_ret0_2}, {"WINMM", "mciSendStringA", w_mciSendStringA},
    {"ADVAPI32", "RegOpenKeyExA", a_RegOpenKeyExA}, {"ADVAPI32", "RegCreateKeyExA", a_RegCreateKeyExA},
    {"ADVAPI32", "RegCloseKey", a_RegCloseKey}, {"ADVAPI32", "RegQueryValueExA", a_RegQueryValueExA},
    {"ADVAPI32", "RegSetValueExA", a_RegSetValueExA}, {"ADVAPI32", "RegDeleteValueA", a_RegDeleteValueA},
    {"ole32", "CoInitialize", o_CoInitialize}, {"ole32", "CoUninitialize", o_CoUninitialize},
    {"ole32", "CoCreateInstance", o_CoCreateInstance},
    {"SHELL32", "ShellExecuteA", s_ShellExecuteA},
    {"comdlg32", "GetOpenFileNameA", c_GetFileName}, {"comdlg32", "GetSaveFileNameA", c_GetFileName},
    {"DSOUND", "DirectSoundCreate8", shim_DirectSoundCreate8},
    {0, 0, 0}
};

extern const ShimDef shims_hotd[];
GFunc shim_lookup(const char *dll, const char *name) {
    // CD-audio patched installs rename WINMM.dll to _INMM.dll and each import's first letter to '_'
    char nm[128];
    if (!strncasecmp(dll, "_INMM", 5) && name[0] == '_') {
        static const char *pre[][2] = {{"_ci", "mci"}, {"_ime", "time"}, {"_mio", "mmio"}, {"_ux", "aux"}, {"_oy", "joy"}};
        for (int i = 0; i < 5; i++) if (!strncmp(name, pre[i][0], strlen(pre[i][0]))) {
            snprintf(nm, sizeof nm, "%s%s", pre[i][1], name + strlen(pre[i][0]));
            name = nm; dll = "WINMM"; break;
        }
    }
    const ShimDef *tabs[] = {shims_hotd, shims_kernel32, shims_user32, shims_gdi32, shims_misc};
    for (int t = 0; t < 5; t++)
        for (const ShimDef *s = tabs[t]; s->name; s++)
            if (!strcmp(s->name, name)) {
                // dll match is case-insensitive and ignores ".dll"
                size_t l = strlen(s->dll);
                if (!strncasecmp(s->dll, dll, l) || !strcmp(dll, "?")) return s->fn;
            }
    return NULL;
}

// ---------------------------------------------------------------- COM helpers
uint32_t com_vtable(int n, const GFunc *methods, const char *prefix) {
    uint32_t vt = guest_static_alloc(n * 4);
    for (int i = 0; i < n; i++) {
        char *nm = malloc(64);
        snprintf(nm, 64, "%s::method%d", prefix, i);
        W32(vt + i * 4, host_thunk(methods[i], nm));
    }
    return vt;
}
uint32_t com_new(uint32_t vtbl, uint32_t size) {
    uint32_t o = heap_alloc(size < 16 ? 16 : size);
    (COW(o, (uint32_t)(size < 16 ? 16 : size)), memset(G + o, 0, size < 16 ? 16 : size));
    W32(o, vtbl);
    return o;
}
