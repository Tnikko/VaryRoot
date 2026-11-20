#!/usr/local/bin/python3
"""Test-only adapter for the locked Clang ELF and pinned GNU gold."""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path('/work/project')
CLANG = ROOT / 'toolchains/namespace-v1/agent-a-step04/usr/bin/clang-18'
GOLD = ROOT / 'runs/interface3c-complete/out/ld.gold'
LOADER = Path('/opt/clang/lib/ld-linux-x86-64.so.2')


def main(argv):
    if '-shared' not in argv:
        flags = ['-fintegrated-cc1'] if '-c' in argv else []
        return subprocess.run([str(CLANG), *flags, *argv]).returncode
    if argv.count('-o') != 1:
        raise ValueError('native test adapter requires one output')
    output = Path(argv[argv.index('-o') + 1])
    compile_args = []
    skip = False
    for arg in argv:
        if skip:
            skip = False
        elif arg == '-o':
            skip = True
        elif arg not in ('-shared', '-nostdlib') and not arg.startswith('-Wl,'):
            compile_args.append(arg)
    source = sys.stdin.buffer.read()
    with tempfile.TemporaryDirectory(prefix='varyroot-native-') as tmp:
        obj = str(Path(tmp) / 'source.o')
        cc = subprocess.run([str(CLANG), '-fintegrated-cc1', *compile_args, '-c', '-o', obj], input=source)
        if cc.returncode:
            return cc.returncode
        ld = subprocess.run([str(LOADER), '--library-path', '/opt/clang/lib', str(GOLD),
                             '-shared', '--build-id=none', obj, '-o', str(output)])
        return ld.returncode


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
