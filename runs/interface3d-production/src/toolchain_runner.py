"""Run legacy tests in the locked Clang 18 rootfs without modifying host /usr."""
import os
import subprocess
import sys
from pathlib import Path

project=Path("/dev_sdb/tq/VaryRoot")
rootfs=project/"toolchains/namespace-v1/agent-a-step04"
sysdir=project/"runs/interface3d-production/out/test-sys"
sysdir.mkdir(exist_ok=True)
if sys.argv[1:2] == ["--inside"]:
    subprocess.run(["mount","--make-rprivate","/"],check=True)
    subprocess.run(["mount","-t","sysfs","-o","ro","sysfs",str(sysdir)],check=True)
    cmd=["bwrap","--unshare-user","--uid","1009","--gid","1009",
         "--unshare-pid","--unshare-ipc","--unshare-uts","--cap-drop","ALL",
         "--die-with-parent","--ro-bind",str(rootfs),"/",
         "--proc","/proc","--dev","/dev","--ro-bind",str(sysdir),"/sys",
         "--tmpfs","/tmp","--tmpfs","/work",
         "--bind",str(project),"/work/project",
         "--ro-bind",str(project/"runs/interface3d-production/out/clang18-test-launcher.lock.json"),
         "/work/project/tools/frontend/clang18.lock.json",
         "--setenv","PATH","/usr/local/bin:/usr/bin:/bin",
         "--setenv","HOME","/work","--setenv","TMPDIR","/tmp",
         "--setenv","PYTHONPATH","/work/project",
         "--chdir","/work/project","--",*sys.argv[2:]]
    os.execvpe("bwrap",cmd,{"PATH":"/usr/bin:/bin"})
cmd=["unshare","-rnm","--",sys.executable,str(Path(__file__).resolve()),"--inside",*sys.argv[1:]]
raise SystemExit(subprocess.call(cmd))
