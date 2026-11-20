"""Run legacy tests with a test-only adapter; production tool lock stays unchanged."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

project = Path('/dev_sdb/tq/VaryRoot')
run = project/'runs/step3-model-intake'
rootfs = project/'toolchains/namespace-v1/agent-a-step04'
shim = run/'src/clang_shim.py'
lock = project/'tools/frontend/clang18.lock.json'
test_lock = run/'out/clang18-test.lock.json'
sysdir = run/'out/test-sys'

if sys.argv[1:2] == ['--inside']:
    subprocess.run(['mount','--make-rprivate','/'],check=True)
    sysdir.mkdir(exist_ok=True)
    subprocess.run(['mount','-t','sysfs','-o','ro','sysfs',str(sysdir)],check=True)
    command = ['bwrap','--unshare-user','--uid','1009','--gid','1009',
               '--unshare-pid','--unshare-ipc','--unshare-uts','--cap-drop','ALL',
               '--die-with-parent','--ro-bind',str(rootfs),'/',
               '--proc','/proc','--dev','/dev','--ro-bind',str(sysdir),'/sys',
               '--tmpfs','/tmp','--tmpfs','/work',
               '--bind',str(project),'/work/project',
               '--ro-bind',str(shim),'/usr/bin/clang-18',
               '--ro-bind',str(test_lock),'/work/project/tools/frontend/clang18.lock.json',
               '--setenv','PATH','/usr/local/bin:/usr/bin:/bin',
               '--setenv','HOME','/work','--setenv','TMPDIR','/tmp',
               '--setenv','PYTHONPATH','/work/project',
               '--chdir','/work/project','--',*sys.argv[2:]]
    os.execvpe('bwrap',command,{'PATH':'/usr/bin:/bin'})

assert hashlib.sha256((rootfs/'opt/clang/bin/clang').read_bytes()).hexdigest() == json.loads(lock.read_bytes())['files']['bin/clang']
assert shim.is_file() and (project/'runs/interface3c-complete/out/ld.gold').is_file()
test = json.loads(lock.read_bytes())
test['files']['bin/clang'] = hashlib.sha256(shim.read_bytes()).hexdigest()
test_lock.write_text(json.dumps(test,indent=2,sort_keys=True)+'\n')
command = ['unshare','-rnm','--',sys.executable,str(Path(__file__).resolve()),'--inside',*sys.argv[1:]]
raise SystemExit(subprocess.call(command))
