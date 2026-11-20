"""Enter a private network/mount namespace, then exec a role in bubblewrap."""
import os
import subprocess
import sys


def main():
    sysdir, rootfs, view, out, uid, gid, *argv = sys.argv[1:]
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "sysfs", "-o", "ro", "sysfs", sysdir], check=True)
    args = [
        "bwrap", "--unshare-user", "--uid", uid, "--gid", gid,
        "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--cap-drop", "ALL",
        "--die-with-parent", "--ro-bind", rootfs, "/", "--proc", "/proc",
        "--dev", "/dev", "--ro-bind", sysdir, "/sys", "--tmpfs", "/work",
        "--tmpfs", "/tmp", "--ro-bind", view, "/input", "--bind", out, "/output",
        "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
        "--setenv", "HOME", "/work", "--setenv", "TMPDIR", "/tmp",
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
        "--setenv", "PYTHONPATH", "/opt/role", "--chdir", "/input", "--", *argv,
    ]
    os.execvpe("bwrap", args, {"PATH": "/usr/bin:/bin"})


if __name__ == "__main__":
    main()
