#!/usr/bin/env python3
"""The House of the Dead (PC, 1998) web port: one command from your own game folder to a playable browser build.

    python port.py --game "C:/Games/THOTD"            # analyse, recompile, build for the web, serve on :8080
    python port.py --game ... web                      # build only
    python port.py --game ... native                   # native SDL2 build (gcc/clang + SDL2)
    python port.py serve                               # serve the last web build (and the co-op relay)

Nothing from the game is stored in this repository. Every step reads the files from --game (or the GAME_DIR
environment variable) and writes derived files only into ignored folders: build/, gen/, build_web/.
"""
import argparse, concurrent.futures, hashlib, json, os, platform, shutil, subprocess, sys, zipfile, urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
EXE_NAME = 'THOTD.EXE'
# Builds of THOTD.EXE this port knows (sha256). Others may work: the analysis is automatic, but
# the hooks in recomp_config.json use addresses of these builds.
KNOWN_EXES = {
    'f7097d6a781da46c30d24bf189dba4d4559148d02b728e1d36ce5b6e84aaef3b': 'tested: WINMM imports renamed to _INMM (CD-audio emulator install, MUSIC/*.wav)',
    '63b57767005e37a21c6955c0f8d58798daff899c28f3b113e9898e36849f42ed': 'seen, not tested yet: original WINMM imports',
}
# What the game reads at run time (case-insensitive). Installers, DirectX redistributables, wrappers are skipped.
DATA_DIRS = ['ART', 'CAM', 'EVT', 'SOUND', 'SPRITE']
DATA_GLOBS = ('.PAL', '.TBL', '.CFG', '.BMP', '.ID')
SDL2_MINGW = 'https://github.com/libsdl-org/SDL/releases/download/release-2.32.10/SDL2-devel-2.32.10-mingw.zip'


def log(*a):
    print('[port]', *a, flush=True)


def run(cmd, **kw):
    log(' '.join(str(c) for c in cmd) if len(cmd) < 12 else '%s ... (%d args)' % (cmd[0], len(cmd)))
    subprocess.check_call(cmd, **kw)


def find_ci(d, name):
    """Case-insensitive lookup of one path component."""
    if not os.path.isdir(d): return None
    for n in os.listdir(d):
        if n.lower() == name.lower(): return os.path.join(d, n)
    return None


def sha256(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
    return h.hexdigest()


def game_dir(args):
    cands = [args.game, os.environ.get('GAME_DIR'), os.path.join(ROOT, 'game'), os.path.dirname(ROOT)]
    for c in cands:
        if c and find_ci(c, EXE_NAME): return os.path.abspath(c)
    sys.exit('Cannot find %s. Pass your installed game folder: python port.py --game "<folder with THOTD.EXE>"' % EXE_NAME)


def ensure_pydeps():
    try:
        import capstone, pefile  # noqa: F401
    except ImportError:
        run([sys.executable, '-m', 'pip', 'install', '--user', 'capstone>=5', 'pefile'])


def stamp_ok(path, key):
    try: return open(path).read() == key
    except OSError: return False


# ------------------------------------------------------------------ analysis + generation
def generate(gdir, force=False):
    ensure_pydeps()
    exe = find_ci(gdir, EXE_NAME)
    digest = sha256(exe)
    log('game: %s' % exe)
    log('sha256 %s: %s' % (digest[:16], KNOWN_EXES.get(digest, 'UNKNOWN build - trying anyway')))
    tools = os.path.join(ROOT, 'tools')
    key = digest + ':' + sha256(os.path.join(tools, 'recomp.py')) + ':' + sha256(os.path.join(tools, 'cap_export.py')) \
        + ':' + sha256(os.path.join(ROOT, 'recomp_config.json'))
    stamp = os.path.join(ROOT, 'gen', '.stamp')
    if not force and stamp_ok(stamp, key):
        log('gen/ is up to date')
        return
    os.makedirs(os.path.join(ROOT, 'build', 'analysis'), exist_ok=True)
    export = os.path.join(ROOT, 'build', 'analysis', 'export.json')
    run([sys.executable, '-I', os.path.join(tools, 'cap_export.py'), exe, export])
    shutil.rmtree(os.path.join(ROOT, 'gen'), ignore_errors=True)
    run([sys.executable, '-I', os.path.join(tools, 'recomp.py'), exe, export, os.path.join(ROOT, 'gen'),
         '--config', os.path.join(ROOT, 'recomp_config.json')])
    open(stamp, 'w').write(key)


def sources():
    gen = sorted(os.path.join('gen', f) for f in os.listdir(os.path.join(ROOT, 'gen')) if f.endswith('.c'))
    src = sorted(os.path.join('src', f) for f in os.listdir(os.path.join(ROOT, 'src')) if f.endswith('.c'))
    return gen, src


def compile_all(jobs, out_dir, cc_for):
    """jobs: list of (source, flags). Rebuilds objects older than their source or any header."""
    hdr_time = max(os.path.getmtime(os.path.join(ROOT, d, f)) for d in ('src', 'gen')
                   for f in os.listdir(os.path.join(ROOT, d)) if f.endswith('.h'))
    objs, todo = [], []
    for s, flags in jobs:
        o = os.path.join(out_dir, s.replace(os.sep, '_').replace('/', '_')[:-2] + '.o')
        objs.append(o)
        sp = os.path.join(ROOT, s)
        if not os.path.exists(o) or os.path.getmtime(o) < max(os.path.getmtime(sp), hdr_time):
            todo.append(cc_for(sp, o, flags))
    os.makedirs(out_dir, exist_ok=True)
    if todo:
        log('compiling %d files' % len(todo))
        with concurrent.futures.ThreadPoolExecutor(os.cpu_count() or 4) as ex:
            for r in ex.map(lambda c: subprocess.run(c, cwd=ROOT, capture_output=True, text=True), todo):
                if r.returncode:
                    sys.stderr.write(r.stdout + r.stderr)
                    sys.exit('compile failed: %s' % r.args[-3])
    return objs


# ------------------------------------------------------------------ web
def find_emsdk(auto_install=True):
    for d in (os.environ.get('EMSDK'), os.path.join(ROOT, '.emsdk'), os.path.expanduser('~/emsdk')):
        if d and os.path.exists(os.path.join(d, 'upstream', 'emscripten', 'emcc.py')): return d
    if not auto_install: return None
    d = os.path.join(ROOT, '.emsdk')
    log('Emscripten not found: installing it into %s (about 1 GB, once)' % d)
    if not os.path.isdir(d):
        run(['git', 'clone', '--depth', '1', 'https://github.com/emscripten-core/emsdk.git', d])
    tool = os.path.join(d, 'emsdk.bat' if os.name == 'nt' else 'emsdk')
    run([tool, 'install', 'latest'], cwd=d)
    run([tool, 'activate', 'latest'], cwd=d)
    return d


def emcc_cmd(emsdk):
    env = dict(os.environ, EMSDK=emsdk, EM_CONFIG=os.path.join(emsdk, '.emscripten'))
    node = [os.path.join(emsdk, 'node', n) for n in os.listdir(os.path.join(emsdk, 'node'))] if os.path.isdir(os.path.join(emsdk, 'node')) else []
    if node:
        env['PATH'] = os.path.join(node[0], 'bin') + os.pathsep + env['PATH']
    return [sys.executable, os.path.join(emsdk, 'upstream', 'emscripten', 'emcc.py')], env


def stage_web_data(gdir, out):
    """Copy what the game reads into build_web/data (preloaded), and the CD music into out/music (streamed)."""
    data = os.path.join(ROOT, 'build_web', 'data')
    os.makedirs(data, exist_ok=True)
    def copy(src, dst):
        if os.path.isdir(src):
            for n in os.listdir(src): copy(os.path.join(src, n), os.path.join(dst, n.upper()))
        elif not os.path.exists(dst) or os.path.getmtime(dst) < os.path.getmtime(src) or os.path.getsize(dst) != os.path.getsize(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    copy(find_ci(gdir, EXE_NAME), os.path.join(data, EXE_NAME))
    for d in DATA_DIRS:
        p = find_ci(gdir, d)
        if p: copy(p, os.path.join(data, d))
        else: log('warning: %s/ missing from the game folder' % d)
    for n in os.listdir(gdir):
        if n.upper().endswith(DATA_GLOBS) and os.path.isfile(os.path.join(gdir, n)) and not n.upper().startswith('DGVOODOO'):
            copy(os.path.join(gdir, n), os.path.join(data, n.upper()))
    # CD audio: MUSIC/trackNN.wav (ripped tracks, as _inmm-style installs have them). Browsers stream it next to the
    # page; with ffmpeg it is converted to Ogg Vorbis (a tenth of the size).
    music = find_ci(gdir, 'MUSIC')
    mout = os.path.join(out, 'music')
    os.makedirs(mout, exist_ok=True)
    ff = shutil.which('ffmpeg')
    if music:
        for n in sorted(os.listdir(music)):
            base, ext = os.path.splitext(n)
            if ext.lower() not in ('.wav', '.ogg', '.mp3'): continue
            src = os.path.join(music, n)
            if ff and ext.lower() == '.wav':
                dst = os.path.join(mout, base.lower() + '.ogg')
                if not os.path.exists(dst):
                    run([ff, '-loglevel', 'error', '-y', '-i', src, '-c:a', 'libvorbis', '-q:a', '5', dst])
            else:
                copy(src, os.path.join(mout, base.lower() + ext.lower()))
    else:
        log('no MUSIC/ folder: the game runs without CD music (rip the CD audio tracks to MUSIC/track02.wav ...)')
    return data


def build_web(gdir):
    generate(gdir)
    emsdk = find_emsdk()
    emcc, env = emcc_cmd(emsdk)
    out = os.path.join(ROOT, 'build_web', 'out')
    os.makedirs(out, exist_ok=True)
    data = stage_web_data(gdir, out)
    gen, src = sources()
    mem = ['-DGUEST_SIZE_MB=64']        # image ends at 20 MB, the guest heap peaks near 12 MB
    gflags = ['-O2', '-fno-strict-aliasing', '-w', '-Isrc', '-Igen'] + mem
    sflags = ['-O2', '-fno-strict-aliasing', '-sUSE_SDL=2', '-Isrc', '-Igen', '-Wno-unused-function'] + mem
    def cc(s, o, flags): return emcc + flags + ['-c', s, '-o', o]
    # emcc subprocesses need the emsdk environment
    os.environ.update(env)
    objs = compile_all([(s, gflags) for s in gen] + [(s, sflags) for s in src], os.path.join(ROOT, 'build_web', 'obj'), cc)
    link = emcc + ['-o', os.path.join(out, 'index.html')] + objs + [
        '-O2', '-sUSE_SDL=2', '-sINITIAL_MEMORY=256MB', '-sALLOW_MEMORY_GROWTH=1', '-sMAXIMUM_MEMORY=1GB',
        '-sSTACK_SIZE=8MB', '-sINVOKE_RUN=0', '-sEXIT_RUNTIME=0', '-sENVIRONMENT=web',
        '-sEXPORTED_RUNTIME_METHODS=callMain,ccall,cwrap', '-lidbfs.js',
        '--pre-js', 'web/prejs.js', '--shell-file', 'web/shell.html',
        '--preload-file', data + '@/game']
    run(link, cwd=ROOT, env=env)
    # every build gets its own URLs (index.js?v=..., Module.locateFile adds it to the wasm and the data): a
    # browser never mixes a cached old build with a new page, and co-op players always run the same build
    build_id = hashlib.sha256(open(os.path.join(out, 'index.wasm'), 'rb').read()).hexdigest()[:12]
    page = os.path.join(out, 'index.html')
    html = open(page, encoding='utf-8').read()
    html = html.replace('__BUILD_ID__', build_id)
    html = html.replace('src="index.js"', 'src="index.js?v=%s"' % build_id).replace('src=index.js', 'src="index.js?v=%s"' % build_id)
    open(page, 'w', encoding='utf-8').write(html)
    log('build id %s' % build_id)
    log('web build ready: %s' % out)


# ------------------------------------------------------------------ native
def find_sdl2():
    if os.name != 'nt':
        try:
            cf = subprocess.check_output(['sdl2-config', '--cflags']).decode().split()
            lf = subprocess.check_output(['sdl2-config', '--libs']).decode().split()
            return cf, lf, None
        except (OSError, subprocess.CalledProcessError):
            sys.exit('SDL2 development files not found (install libsdl2-dev / sdl2 from your package manager)')
    tp = os.path.join(ROOT, 'thirdparty')
    root = next((os.path.join(tp, d, 'x86_64-w64-mingw32') for d in (os.listdir(tp) if os.path.isdir(tp) else [])
                 if d.startswith('SDL2-')), None)
    if not root:
        os.makedirs(tp, exist_ok=True)
        z = os.path.join(tp, 'sdl2.zip')
        log('downloading SDL2 (MinGW development package)')
        urllib.request.urlretrieve(SDL2_MINGW, z)
        zipfile.ZipFile(z).extractall(tp)
        return find_sdl2()
    return (['-I' + os.path.join(root, 'include', 'SDL2'), '-DSDL_MAIN_HANDLED'],
            ['-L' + os.path.join(root, 'lib'), '-lSDL2', '-lm'], os.path.join(root, 'bin', 'SDL2.dll'))


def build_native(gdir, trace=False):
    generate(gdir)
    cflags, lflags, dll = find_sdl2()
    cc = os.environ.get('CC') or shutil.which('gcc') or shutil.which('clang') or sys.exit('no C compiler (gcc/clang)')
    gen, src = sources()
    extra = ['-DFUNC_TRACE'] if trace else []
    gflags = ['-O1', '-g', '-fno-strict-aliasing', '-w', '-Isrc', '-Igen'] + extra
    sflags = ['-O2', '-g', '-fno-strict-aliasing', '-Wall', '-Wno-unused-function', '-Isrc', '-Igen'] + cflags + extra
    def ccf(s, o, flags): return [cc] + flags + ['-c', s, '-o', o]
    out = os.path.join(ROOT, 'build')
    objs = compile_all([(s, gflags) for s in gen] + [(s, sflags) for s in src], os.path.join(out, 'obj_trace' if trace else 'obj'), ccf)
    exe = os.path.join(out, ('hotd_port_trace' if trace else 'hotd_port') + ('.exe' if os.name == 'nt' else ''))
    run([cc, '-o', exe] + objs + lflags, cwd=ROOT)
    if dll: shutil.copy2(dll, out)
    log('native build ready: %s  (run: %s "%s")' % (exe, exe, gdir))


# ------------------------------------------------------------------ serve
def serve(port, password=None):
    out = os.path.join(ROOT, 'build_web', 'out')
    if not os.path.exists(os.path.join(out, 'index.html')): sys.exit('no web build yet: run python port.py --game <dir>')
    node = shutil.which('node')
    if node:
        cmd = [node, os.path.join(ROOT, 'server', 'server.js'), '--port', str(port), '--root', out]
        if password: cmd += ['--password', password]
        log('serving http://localhost:%d (solo and online co-op)' % port)
        run(cmd)
    else:
        log('Node.js not found: serving http://localhost:%d for solo play only (install Node 18+ for co-op)' % port)
        run([sys.executable, '-m', 'http.server', str(port), '--directory', out])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('command', nargs='?', default='all', choices=['all', 'gen', 'web', 'native', 'serve'])
    ap.add_argument('--game', help='your installed game folder (contains THOTD.EXE)')
    ap.add_argument('--port', type=int, default=8080)
    ap.add_argument('--password', help='serve: require this password (HTTP basic auth); use it whenever others can reach the server')
    ap.add_argument('--force', action='store_true', help='redo the analysis and code generation')
    ap.add_argument('--trace', action='store_true', help='native: count guest function entries (PORT_TRACE=file)')
    a = ap.parse_args()
    if a.command == 'serve': return serve(a.port, a.password)
    g = game_dir(a)
    if a.command == 'gen': return generate(g, a.force)
    if a.force: generate(g, True)
    if a.command == 'native': return build_native(g, a.trace)
    build_web(g)
    if a.command == 'all': serve(a.port, a.password)


if __name__ == '__main__':
    main()
