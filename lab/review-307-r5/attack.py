#!/usr/bin/env python3
"""Live hunts against the built fcl-launch at 747cda4f.

Does not edit lab/fail-closed-linux. Needs FCL_SRC (the #307 detached
worktree) and that tree's fcl-launch.
"""

from __future__ import annotations

import json
import os
import pty
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
FCL_SRC = Path(os.environ.get("FCL_SRC", "/tmp/wt-307-r5/candidate/lab/fail-closed-linux"))
LAUNCHER = Path(
    os.environ.get(
        "FCL_LAUNCH",
        str(FCL_SRC / "target" / "debug" / "fcl-launch"),
    )
)
BIN = HERE / "standins" / "bin"
EVIDENCE = HERE / "evidence"
HEAD = "747cda4f0f2dfb5953baad1c62c44be1a0d84e71"


def sh(args, **kw):
    return subprocess.run(args, check=True, **kw)


def build_standins():
    BIN.mkdir(parents=True, exist_ok=True)
    for name in ("hunter", "payload"):
        src = HERE / "standins" / f"{name}.c"
        out = BIN / name
        cmd = ["gcc", "-static", "-O1", "-s", str(src), "-o", str(out)]
        if name == "hunter":
            cmd[1:1] = []
            cmd.extend(["-lrt"])
        sh(cmd)
    return {"hunter": str(BIN / "hunter"), "payload": str(BIN / "payload")}


def start_launch(exe, args, storage, stdin=None, stdout=None):
    cmd = [
        str(LAUNCHER),
        "--provider",
        "did-provider",
        "--storage-root",
        str(storage),
        "--",
        str(exe),
        *args,
    ]
    return subprocess.Popen(
        cmd,
        stdin=stdin if stdin is not None else subprocess.PIPE,
        stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )


def drain_stdout(proc, lines, timeout=0.2):
    import select

    if proc.stdout is None:
        return b""
    deadline = time.time() + timeout
    buf = b""
    while time.time() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], 0.05)
        if not ready:
            if proc.poll() is not None:
                break
            continue
        chunk = os.read(proc.stdout.fileno(), 4096)
        if not chunk:
            break
        buf += chunk
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            line = raw.decode("utf-8", "replace").strip()
            if line:
                lines.append(line)
    return buf


def started_pid_from(lines, proc):
    for line in lines:
        if line.startswith("started "):
            return int(line.rsplit("=", 1)[1])
    kids = children_of(proc.pid)
    return kids[0] if kids else None


def read_started(proc, timeout=8.0):
    deadline = time.time() + timeout
    lines = []
    while time.time() < deadline:
        drain_stdout(proc, lines, timeout=0.15)
        pid = started_pid_from(lines, proc)
        if pid is not None:
            return pid, lines, ""
        if proc.poll() is not None:
            drain_stdout(proc, lines, timeout=0.05)
            break
    err = b""
    if proc.stderr:
        try:
            import select

            if select.select([proc.stderr], [], [], 0.05)[0]:
                err = os.read(proc.stderr.fileno(), 8000)
        except OSError:
            err = b""
    return None, lines, err.decode("utf-8", "replace")


def children_of(pid):
    path = Path(f"/proc/{pid}/task/{pid}/children")
    try:
        text = path.read_text()
    except FileNotFoundError:
        return []
    out = []
    for word in text.split():
        try:
            child = int(word)
        except ValueError:
            continue
        try:
            stat_text = Path(f"/proc/{child}/stat").read_text()
        except FileNotFoundError:
            continue
        close = stat_text.rfind(")")
        parts = stat_text[close + 1 :].split()
        if len(parts) >= 2 and parts[1] == str(pid):
            out.append(child)
    return out


def innermost(pid):
    kids = children_of(pid)
    return kids[0] if kids else None


def exe_of(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError as err:
        return f"errno={err.errno}"


def wait_line(proc, prefix, already, timeout=4.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for line in already:
            if line.startswith(prefix) or line == prefix:
                return line, already
        drain_stdout(proc, already, timeout=0.15)
        if proc.poll() is not None:
            drain_stdout(proc, already, timeout=0.05)
            break
    for line in already:
        if line.startswith(prefix) or line == prefix:
            return line, already
    return None, already


def stop(proc):
    if proc.poll() is None:
        proc.send_signal(signal.SIGKILL)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


def hunt_reexec_foreign(bins, tmp):
    storage = tmp / "reexec-foreign-store"
    storage.mkdir()
    proc = start_launch(bins["hunter"], ["reexec", bins["payload"]], storage)
    init, lines, err = read_started(proc)
    if init is None:
        stop(proc)
        return {
            "id": "reexec-foreign",
            "started": False,
            "lines": lines,
            "stderr": err[-400:],
            "verdict": "launch refused",
        }
    first, lines = wait_line(proc, "first", lines)
    if proc.stdin:
        proc.stdin.write(b"x")
        proc.stdin.flush()
    later, lines = wait_line(proc, "exec errno=", lines, timeout=3)
    second, lines = wait_line(proc, "payload", lines, timeout=1)
    exe = exe_of(innermost(init)) if init else None
    stop(proc)
    return {
        "id": "reexec-foreign",
        "started": True,
        "init": init,
        "first": first,
        "exec_line": later,
        "payload_line": second,
        "exe_after": exe,
        "lines": lines,
        "verdict": "second exec denied" if later and second is None else "second image ran",
    }


def hunt_reexec_storage(bins, tmp):
    storage = tmp / "reexec-store"
    storage.mkdir()
    payload = storage / "payload"
    shutil.copy2(bins["payload"], payload)
    os.chmod(payload, 0o755)
    proc = start_launch(bins["hunter"], ["reexec", str(payload)], storage)
    init, lines, err = read_started(proc)
    if init is None:
        stop(proc)
        return {"id": "reexec-storage", "started": False, "stderr": err[-400:]}
    first, lines = wait_line(proc, "first", lines)
    if proc.stdin:
        proc.stdin.write(b"x")
        proc.stdin.flush()
    later, lines = wait_line(proc, "exec errno=", lines, timeout=3)
    second, lines = wait_line(proc, "payload", lines, timeout=1)
    stop(proc)
    return {
        "id": "reexec-storage",
        "started": True,
        "init": init,
        "first": first,
        "exec_line": later,
        "payload_line": second,
        "lines": lines,
        "verdict": "storage exec denied" if later and second is None else "storage payload ran",
    }


def hunt_swap_same_path(bins, tmp):
    storage = tmp / "swap-store"
    storage.mkdir()
    expected = tmp / "swap-exe"
    shutil.copy2(bins["hunter"], expected)
    os.chmod(expected, 0o755)
    before = expected.stat()
    proc = start_launch(expected, ["reexec", str(expected)], storage)
    init, lines, err = read_started(proc)
    if init is None:
        stop(proc)
        return {"id": "swap-same-path", "started": False, "stderr": err[-400:]}
    first, lines = wait_line(proc, "first", lines)
    replacement = tmp / "swap-exe.new"
    shutil.copy2(bins["payload"], replacement)
    os.chmod(replacement, 0o755)
    os.rename(replacement, expected)
    after = expected.stat()
    if proc.stdin:
        proc.stdin.write(b"x")
        proc.stdin.flush()
    later, lines = wait_line(proc, "exec errno=", lines, timeout=3)
    second, lines = wait_line(proc, "payload", lines, timeout=1)
    provider = innermost(init)
    exe = exe_of(provider) if provider else None
    stop(proc)
    return {
        "id": "swap-same-path",
        "started": True,
        "init": init,
        "ino_before": before.st_ino,
        "ino_after": after.st_ino,
        "dev_before": before.st_dev,
        "dev_after": after.st_dev,
        "first": first,
        "exec_line": later,
        "payload_line": second,
        "exe_after": exe,
        "lines": lines,
        "verdict": "swapped inode exec denied"
        if later and second is None
        else "swapped inode ran",
    }


def hunt_bind_mount(bins, tmp):
    storage = tmp / "bind-store"
    storage.mkdir()
    expected = tmp / "bind-exe"
    shutil.copy2(bins["hunter"], expected)
    os.chmod(expected, 0o755)
    target = tmp / "bind-target"
    shutil.copy2(bins["payload"], target)
    os.chmod(target, 0o755)
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    ms_bind = getattr(os, "MS_BIND", 4096)
    mounted = libc.mount(str(target).encode(), str(expected).encode(), None, ms_bind, None) == 0
    mount_err = 0 if mounted else ctypes.get_errno()
    result = {
        "id": "bind-mount",
        "mounted": mounted,
        "mount_errno": mount_err,
    }
    if not mounted:
        result["verdict"] = "host cannot bind-mount (no CAP_SYS_ADMIN)"
        return result
    try:
        proc = start_launch(expected, ["wait"], storage)
        init, lines, err = read_started(proc)
        result.update(
            {
                "started": init is not None,
                "init": init,
                "lines": lines,
                "stderr": err[-400:] if err else "",
                "exe": exe_of(innermost(init)) if init else None,
            }
        )
        stop(proc)
        result["verdict"] = "bind-mounted path launched" if init else "bind-mounted path refused"
    finally:
        libc.umount(str(expected).encode())
    return result


def hunt_identity_fd(bins, tmp):
    storage = tmp / "fds-store"
    storage.mkdir()
    proc = start_launch(bins["hunter"], ["listfds"], storage)
    init, lines, err = read_started(proc)
    if init is None:
        stop(proc)
        return {"id": "identity-fd", "started": False, "stderr": err[-400:]}
    deadline = time.time() + 3
    while time.time() < deadline:
        line, lines = wait_line(proc, "fd ", lines, timeout=0.4)
        if line is None:
            break
    extra = [
        line
        for line in lines
        if line.startswith("fd ")
        and not line.startswith("fd 0 ")
        and not line.startswith("fd 1 ")
        and not line.startswith("fd 2 ")
    ]
    pipes = [line for line in extra if "kind=pipe" in line]
    stop(proc)
    return {
        "id": "identity-fd",
        "started": True,
        "init": init,
        "fds": [line for line in lines if line.startswith("fd ")],
        "extra": extra,
        "pipes": pipes,
        "verdict": "only fds 0-2"
        if not extra
        else ("identity pipe left open" if pipes else "extra fds remain"),
    }


def hunt_stdin_pty(bins, tmp):
    storage = tmp / "pty-store"
    storage.mkdir()
    master, slave = pty.openpty()
    try:
        proc = start_launch(bins["hunter"], ["stdin-ioctl"], storage, stdin=slave)
        os.close(slave)
        init, lines, err = read_started(proc)
        if init is None:
            os.close(master)
            stop(proc)
            return {"id": "stdin-pty", "started": False, "stderr": err[-400:]}
        deadline = time.time() + 3
        while time.time() < deadline:
            line, lines = wait_line(proc, "ioctl_fd_", lines, timeout=0.4)
            if line is None:
                break
        stop(proc)
        os.close(master)
        ioctl0 = next((line for line in lines if line.startswith("ioctl_fd_0 ")), None)
        tiocsti0 = next((line for line in lines if line.startswith("tiocsti_fd_0 ")), None)
        return {
            "id": "stdin-pty",
            "started": True,
            "init": init,
            "ioctl_lines": [line for line in lines if "ioctl" in line or "tiocsti" in line],
            "ioctl0": ioctl0,
            "tiocsti0": tiocsti0,
            "verdict": "stdin pty ioctl works"
            if ioctl0 == "ioctl_fd_0 ok"
            else "stdin pty ioctl denied",
        }
    except Exception as err:
        try:
            os.close(master)
        except OSError:
            pass
        return {"id": "stdin-pty", "error": str(err)}


def hunt_memfd(bins, tmp):
    storage = tmp / "memfd-store"
    storage.mkdir()
    payload = storage / "payload"
    shutil.copy2(bins["payload"], payload)
    os.chmod(payload, 0o755)
    proc = start_launch(bins["hunter"], ["memfd-exec", str(payload)], storage)
    init, lines, err = read_started(proc)
    if init is None:
        stop(proc)
        return {"id": "memfd-exec", "started": False, "stderr": err[-400:]}
    later, lines = wait_line(proc, "memfd_", lines, timeout=3)
    second, lines = wait_line(proc, "payload", lines, timeout=1)
    stop(proc)
    return {
        "id": "memfd-exec",
        "started": True,
        "init": init,
        "memfd_line": later or next((line for line in lines if line.startswith("memfd")), None),
        "payload_line": second,
        "lines": lines,
        "verdict": "memfd exec denied" if second is None else "memfd payload ran",
    }


def hunt_memfd_exec_flag(bins, tmp):
    storage = tmp / "memfd-flag-store"
    storage.mkdir()
    payload = storage / "payload"
    shutil.copy2(bins["payload"], payload)
    os.chmod(payload, 0o755)
    proc = start_launch(bins["hunter"], ["memfd-exec-flag", str(payload)], storage)
    init, lines, err = read_started(proc)
    if init is None:
        stop(proc)
        return {"id": "memfd-exec-flag", "started": False, "stderr": err[-400:]}
    later, lines = wait_line(proc, "memfd_exec_", lines, timeout=3)
    second, lines = wait_line(proc, "payload", lines, timeout=1)
    stop(proc)
    return {
        "id": "memfd-exec-flag",
        "started": True,
        "init": init,
        "memfd_line": later,
        "payload_line": second,
        "lines": lines,
        "verdict": "MFD_EXEC denied" if second is None else "MFD_EXEC payload ran",
    }


def hunt_reexec_self(bins, tmp):
    storage = tmp / "reexec-self-store"
    storage.mkdir()
    payload = storage / "payload"
    shutil.copy2(bins["payload"], payload)
    os.chmod(payload, 0o755)
    hunter = tmp / "self-hunter"
    shutil.copy2(bins["hunter"], hunter)
    os.chmod(hunter, 0o755)
    proc = start_launch(str(hunter), ["reexec-self", str(payload)], storage)
    init, lines, err = read_started(proc)
    if init is None:
        stop(proc)
        return {"id": "reexec-self", "started": False, "stderr": err[-400:], "lines": lines}
    first, lines = wait_line(proc, "first", lines)
    if proc.stdin:
        proc.stdin.write(b"x")
        proc.stdin.flush()
    after, lines = wait_line(proc, "after_reexec", lines, timeout=3)
    persist, lines = wait_line(proc, "persist_mfd_", lines, timeout=2)
    persist2, lines = wait_line(proc, "persist_noexec_", lines, timeout=2)
    payload_line, lines = wait_line(proc, "payload", lines, timeout=1)
    provider = innermost(init)
    exe = exe_of(provider) if provider else None
    stop(proc)
    persisted = bool(
        persist
        and "errno=1" in persist
        or persist2
        and "errno=1" in (persist2 or "")
    )
    if persist and persist.endswith("errno=1"):
        persisted = True
    if persist2 and persist2.endswith("errno=1"):
        persisted = True
    return {
        "id": "reexec-self",
        "started": True,
        "init": init,
        "first": first,
        "after": after,
        "persist_mfd": persist,
        "persist_noexec": persist2,
        "payload_line": payload_line,
        "exe_after": exe,
        "lines": lines,
        "verdict": (
            "granted-path re-exec ran; second filter persisted"
            if after and payload_line is None and persisted
            else (
                "granted-path re-exec ran; filter lost"
                if after and not persisted
                else "granted-path re-exec denied or unclear"
            )
        ),
    }


def hunt_memfd_procfd(bins, tmp):
    storage = tmp / "procfd-store"
    storage.mkdir()
    payload = storage / "payload"
    shutil.copy2(bins["payload"], payload)
    os.chmod(payload, 0o755)
    proc = start_launch(bins["hunter"], ["memfd-procfd", str(payload)], storage)
    init, lines, err = read_started(proc)
    if init is None:
        stop(proc)
        return {"id": "memfd-procfd", "started": False, "stderr": err[-400:]}
    later, lines = wait_line(proc, "procfd_", lines, timeout=3)
    second, lines = wait_line(proc, "payload", lines, timeout=1)
    stop(proc)
    return {
        "id": "memfd-procfd",
        "started": True,
        "init": init,
        "procfd_line": later or next((line for line in lines if line.startswith("procfd")), None),
        "payload_line": second,
        "lines": lines,
        "verdict": "procfd exec denied" if second is None else "procfd payload ran",
    }


def hunt_shm_exec(bins, tmp):
    storage = tmp / "shm-store"
    storage.mkdir()
    payload = storage / "payload"
    shutil.copy2(bins["payload"], payload)
    os.chmod(payload, 0o755)
    proc = start_launch(bins["hunter"], ["shm-exec", str(payload)], storage)
    init, lines, err = read_started(proc)
    if init is None:
        stop(proc)
        return {"id": "shm-exec", "started": False, "stderr": err[-400:]}
    later, lines = wait_line(proc, "shm_", lines, timeout=3)
    second, lines = wait_line(proc, "payload", lines, timeout=1)
    stop(proc)
    return {
        "id": "shm-exec",
        "started": True,
        "init": init,
        "shm_line": later or next((line for line in lines if line.startswith("shm")), None),
        "payload_line": second,
        "lines": lines,
        "verdict": "shm exec denied" if second is None else "shm payload ran",
    }


def hunt_denied_syscalls(bins, tmp):
    storage = tmp / "denied-store"
    storage.mkdir()
    proc = start_launch(bins["hunter"], ["denied"], storage)
    init, lines, err = read_started(proc)
    if init is None:
        stop(proc)
        return {"id": "denied-syscalls", "started": False, "stderr": err[-400:]}
    wait_line(proc, "io_uring_setup", lines, timeout=3)
    stop(proc)
    interesting = [
        line
        for line in lines
        if line.startswith(("ptrace ", "process_vm_writev ", "io_uring_setup "))
    ]
    all_eperm = all("errno=1" in line for line in interesting) and len(interesting) == 3
    return {
        "id": "denied-syscalls",
        "started": True,
        "init": init,
        "lines": interesting,
        "verdict": "ptrace/process_vm_writev/io_uring EPERM" if all_eperm else "a denied syscall leaked",
    }


def hunt_stdin_socket_rights(bins, tmp):
    storage = tmp / "sock-store"
    storage.mkdir()
    secret = tmp / "host-secret.txt"
    secret.write_text("host-secret\n")
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    proc = start_launch(bins["hunter"], ["recv-rights"], storage, stdin=b.fileno())
    b.close()
    init, lines, err = read_started(proc)
    if init is None:
        a.close()
        stop(proc)
        return {"id": "stdin-socket-rights", "started": False, "stderr": err[-400:], "lines": lines}
    secret_fd = os.open(secret, os.O_RDONLY)
    try:
        send_fd(a, secret_fd, b"x")
    except OSError as send_err:
        os.close(secret_fd)
        a.close()
        stop(proc)
        return {
            "id": "stdin-socket-rights",
            "started": True,
            "send_errno": send_err.errno,
            "verdict": "could not send SCM_RIGHTS",
        }
    os.close(secret_fd)
    later, lines = wait_line(proc, "scm_", lines, timeout=3)
    recv, lines = wait_line(proc, "recvmsg", lines, timeout=1)
    read_line, lines = wait_line(proc, "scm_read", lines, timeout=1)
    a.close()
    stop(proc)
    received = any(line.startswith("scm_rights fd=") for line in lines)
    read_ok = any(line.startswith("scm_read n=") for line in lines)
    return {
        "id": "stdin-socket-rights",
        "started": True,
        "init": init,
        "recv": recv,
        "rights": later,
        "read": read_line,
        "lines": [line for line in lines if line.startswith(("hunter", "recvmsg", "scm_"))],
        "verdict": (
            "SCM_RIGHTS delivered a host fd"
            if received and read_ok
            else ("socket stayed; no extra fd" if recv else "socket stdin unclear")
        ),
    }


def send_fd(sock, fd, payload=b"x"):
    import array

    sock.sendmsg(
        [payload],
        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))],
    )


def hunt_stdin_pipe(bins, tmp):
    storage = tmp / "pipe-store"
    storage.mkdir()
    r, w = os.pipe()
    proc = start_launch(bins["hunter"], ["listfds"], storage, stdin=r)
    os.close(r)
    init, lines, err = read_started(proc)
    if init is None:
        os.close(w)
        stop(proc)
        return {"id": "stdin-pipe", "started": False, "stderr": err[-400:]}
    wait_line(proc, "fd 0 ", lines, timeout=2)
    fd0 = next((line for line in lines if line.startswith("fd 0 ")), None)
    os.close(w)
    stop(proc)
    return {
        "id": "stdin-pipe",
        "started": True,
        "init": init,
        "fd0": fd0,
        "fds": [line for line in lines if line.startswith("fd ")],
        "verdict": "stdin stays a pipe to the host" if fd0 and "kind=pipe" in fd0 else "stdin pipe replaced",
    }


def hunt_ioctl_devnull(bins, tmp):
    storage = tmp / "null-store"
    storage.mkdir()
    null = os.open("/dev/null", os.O_RDWR)
    try:
        proc = start_launch(bins["hunter"], ["stdin-ioctl"], storage, stdin=null)
        init, lines, err = read_started(proc)
        if init is None:
            stop(proc)
            return {"id": "ioctl-devnull", "started": False, "stderr": err[-400:]}
        wait_line(proc, "ioctl_fd_0", lines, timeout=3)
        stop(proc)
        ioctl0 = next((line for line in lines if line.startswith("ioctl_fd_0 ")), None)
        tiocsti0 = next((line for line in lines if line.startswith("tiocsti_fd_0 ")), None)
        return {
            "id": "ioctl-devnull",
            "started": True,
            "init": init,
            "ioctl0": ioctl0,
            "tiocsti0": tiocsti0,
            "lines": [line for line in lines if "ioctl" in line or "tiocsti" in line],
            "verdict": "ioctl on /dev/null works"
            if ioctl0 == "ioctl_fd_0 ok"
            else "ioctl on /dev/null denied",
        }
    finally:
        try:
            os.close(null)
        except OSError:
            pass


def hunt_selftest_strace(bins, tmp):
    storage = tmp / "strace-store"
    storage.mkdir()
    log = tmp / "strace.log"
    cmd = [
        "strace",
        "-f",
        "-o",
        str(log),
        "-e",
        "trace=openat,truncate,ioctl,wait4,waitpid,execve,execveat,memfd_create,close_range,seccomp,rename,mknod,symlink",
        str(LAUNCHER),
        "--provider",
        "did-provider",
        "--storage-root",
        str(storage),
        "--",
        bins["hunter"],
        "wait",
    ]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0
    )
    init, lines, err = read_started(proc)
    stop(proc)
    text = log.read_text() if log.exists() else ""
    opens = [
        line
        for line in text.splitlines()
        if "openat(" in line and ("/dev/pts/" in line or "fcl-enf-" in line)
    ]
    truncates = [line for line in text.splitlines() if "truncate(" in line]
    ioctls = [line for line in text.splitlines() if "ioctl(" in line and "TIOCGWINSZ" in line]
    execveat = [line for line in text.splitlines() if "execveat(" in line]
    memfd = [line for line in text.splitlines() if "memfd_create(" in line]
    rename = [line for line in text.splitlines() if "rename(" in line]
    make = [
        line
        for line in text.splitlines()
        if "mknod(" in line or "mkfifo(" in line or "symlink(" in line
    ]
    close_range = [line for line in text.splitlines() if "close_range(" in line]
    seccomp = [line for line in text.splitlines() if "seccomp(" in line]
    return {
        "id": "selftest-strace",
        "started": init is not None,
        "init": init,
        "open_pts_or_enforce": opens[:20],
        "truncate": truncates[:10],
        "ioctl": ioctls[:10],
        "execveat": execveat[:10],
        "memfd_create": memfd[:8],
        "rename": rename[:8],
        "make": make[:12],
        "close_range": close_range[:8],
        "seccomp": seccomp[:8],
        "verdict": "self-test syscalls recorded",
        "stderr_tail": err[-200:] if err else "",
        "lines": lines,
    }


def hunt_close_range_fallback():
    src = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void) {
    int dir = open("/no-such-proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    printf("open_missing_proc errno=%d\n", dir < 0 ? errno : 0);
    if (dir >= 0) close(dir);
    return 0;
}
"""
    tmp = tempfile.mkdtemp(prefix="fcl-r5-fb-")
    cpath = Path(tmp) / "fb.c"
    cpath.write_text(src)
    out = Path(tmp) / "fb"
    sh(["gcc", "-O1", str(cpath), "-o", str(out)])
    run = subprocess.run([str(out)], check=True, capture_output=True, text=True)
    shutil.rmtree(tmp, ignore_errors=True)
    return {
        "id": "close-range-fallback",
        "host_has_close_range": True,
        "missing_proc": run.stdout.strip(),
        "verdict": "fallback not exercised on this host; missing /proc open fails closed in source",
    }


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    if not LAUNCHER.is_file():
        sys.exit(f"missing launcher {LAUNCHER}")
    bins = build_standins()
    tmp = Path(tempfile.mkdtemp(prefix="fcl-r5-hunts-"))
    hunts = []
    runners = [
        hunt_reexec_foreign,
        hunt_reexec_storage,
        hunt_swap_same_path,
        hunt_bind_mount,
        hunt_identity_fd,
        hunt_stdin_pty,
        hunt_memfd,
        hunt_memfd_exec_flag,
        hunt_reexec_self,
        hunt_memfd_procfd,
        hunt_shm_exec,
        hunt_denied_syscalls,
        hunt_stdin_socket_rights,
        hunt_stdin_pipe,
        hunt_ioctl_devnull,
        hunt_selftest_strace,
        hunt_close_range_fallback,
    ]
    try:
        for runner in runners:
            try:
                if runner is hunt_close_range_fallback:
                    hunts.append(runner())
                else:
                    hunts.append(runner(bins, tmp))
            except Exception as err:
                hunts.append({"id": runner.__name__, "error": str(err)})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    report = {
        "head": HEAD,
        "launcher": str(LAUNCHER),
        "hunts": hunts,
    }
    out = EVIDENCE / "attacks.json"
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
