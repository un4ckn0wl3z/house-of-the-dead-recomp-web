# Write a gdb script that prints the first hit of each recompiled function, then run it.
# Usage: python tools/dev/gdbhits.py <frames> 412420 415c40 ...   (run from build/run)
import subprocess, sys
secs = sys.argv[1]
lines = []
for i, f in enumerate(sys.argv[2:], 1):
    lines += ['break f_%s' % f, 'commands', 'silent', 'printf "hit %s\\n"' % f, 'disable %d' % i, 'continue', 'end']
lines.append('run')
open('hits.gdb', 'w').write('\n'.join(lines) + '\n')
r = subprocess.run(['gdb', '-batch', '-x', 'hits.gdb', '--args', '../hotd_port.exe',
                    __import__('os').environ.get('GAME_DIR', '../../..'), 'save'], capture_output=True, text=True, env=dict(__import__('os').environ, PORT_EXIT=secs))
print('\n'.join(l for l in r.stdout.splitlines() if l.startswith('hit')))
