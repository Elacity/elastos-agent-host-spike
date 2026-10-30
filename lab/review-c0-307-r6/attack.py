#!/usr/bin/env python3
"""Live r6 hunts against the built fcl-launch at 13447927.

Does not edit lab/fail-closed-linux. Needs FCL_SRC (the #307 detached
tree) and that tree's fcl-launch.
"""

from __future__ import annotations

import json
import os
import pty
import select
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
FCL_SRC = Path(
    os.environ.get("FCL_SRC", "/workspace/lab/fail-closed-linux")
)
LAUNCHER = Path(
    os.environ.get(
        "FCL_LAUNCH",
        str(FCL_SRC / "target" / "debug" / "fcl-launch"),
    )
)
BIN = HERE / "standins" / "bin"
EVIDENCE = HERE / "evidence"
HEAD = "1344792715fc21fef94dca5e973e14231ce604a6"


def sh(args, **kw):
    return subprocess.run(args, check=True, **kw)


def build_standins():
    BIN.mkdir(parents=True, exist_ok=True)
    hunter = BIN / "hunter"
    payload = BIN / "payload"
    sh(["gcc", "-static", "-O1", "-Wall", "-Wextra", str(HERE / "standins" / "hunter.c"), "-o", str(hunter)])
    sh(["gcc", "-static", "-O1", "-Wall", "-Wextra", str(HERE / "standins" / "payload.c"), "-o", str(payload)])
    script = BIN / "payload.sh"
    shutil.copy2(HERE / "standins" / "payload.sh", script)
    script.chmod(0o755)
    interp_script = BIN / "interp-script"
    interp_script.write_text(f"#!{payload}\n")
    interp_script.chmod(0o755)
    return {
        "hunter": str(hunter),
        "payload": str(payload),
        "script": str(script),
        "interp_script": str(interp_script),
    }


def start_launch(exe, args, storage, stdin=None, stdout=None, pass_fds=None, extra_env=None):
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
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    kw = dict(
        stdin=stdin if stdin is not None else subprocess.PIPE,
        stdout=stdout if stdout is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        env=env,
    )
    if pass_fds:
        kw["pass_fds"] = tuple(pass_fds)
    return subprocess.Popen(cmd, **kw)


def drain_stdout(proc, lines, timeout=0.2):
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
            if select.select([proc.stderr], [], [], 0.05)[0]:
                err = os.read(proc.stderr.fileno(), 8000)
        except OSError:
            err = b""
    return None, lines, err.decode("utf-8", "replace")


def wait_prefix(proc, already, prefixes, timeout=4.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for line in already:
            if any(line.startswith(p) or line == p for p in prefixes):
                return line, already
        drain_stdout(proc, already, timeout=0.15)
        if proc.poll() is not None:
            drain_stdout(proc, already, timeout=0.05)
            break
    for line in already:
        if any(line.startswith(p) or line == p for p in prefixes):
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


def payload_ran(lines):
    return any("payload pid=" in line or line.startswith("script_payload") for line in lines)


def verdict_exec(lines, tag):
    ran = payload_ran(lines)
    eperm = any(f"{tag} errno=1" in line or f"{tag} errno=13" in line for line in lines)
    if ran:
        return "SURVIVED"
    if eperm:
        return "CAUGHT"
    return "UNKNOWN"


def hunt_granted_twice(bins, tmp):
    storage = tmp / "granted-twice"
    storage.mkdir()
    proc = start_launch(bins["hunter"], ["granted-twice", bins["hunter"]], storage)
    init, lines, err = read_started(proc)
    wait_prefix(proc, lines, ["reexec1 ", "reexec2 ", "payload pid="], timeout=3)
    stop(proc)
    v = "SURVIVED" if payload_ran(lines) else (
        "CAUGHT" if any("reexec1 errno=" in x for x in lines) and any("reexec2 errno=" in x for x in lines) else "UNKNOWN"
    )
    return {
        "id": "granted-twice",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "note": "two pathname execve of the granted binary after start",
    }


def hunt_symlink_swap(bins, tmp):
    storage = tmp / "symlink-swap"
    storage.mkdir()
    link = storage / "granted-link"
    os.symlink(bins["hunter"], link)
    proc = start_launch(bins["hunter"], ["exec-path", str(link)], storage)
    init, lines, err = read_started(proc)
    wait_prefix(proc, lines, ["exec_path ", "payload pid="], timeout=3)
    # After start, retarget the symlink at the payload and ask the
    # confined process to execve that path (already in flight as exec-path).
    stop(proc)
    v = "SURVIVED" if payload_ran(lines) else (
        "CAUGHT" if any("exec_path errno=" in x for x in lines) else "UNKNOWN"
    )
    return {
        "id": "symlink-swap",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "note": "execve of a symlink under storage that names the granted binary",
    }


def hunt_bind_mount_swap(bins, tmp):
    storage = tmp / "bind-swap"
    storage.mkdir()
    granted = tmp / "bind-granted"
    shutil.copy2(bins["hunter"], granted)
    granted.chmod(0o755)
    proc = start_launch(str(granted), ["exec-path", str(granted)], storage)
    init, lines, err = read_started(proc)
    mount_err = None
    if init is not None:
        try:
            sh(["mount", "--bind", bins["payload"], str(granted)])
            mounted = True
        except subprocess.CalledProcessError as exc:
            mounted = False
            mount_err = exc.returncode
        wait_prefix(proc, lines, ["exec_path ", "payload pid="], timeout=2)
        if mounted:
            try:
                sh(["umount", str(granted)])
            except subprocess.CalledProcessError:
                pass
    else:
        mounted = False
    stop(proc)
    if mount_err is not None and not mounted:
        v = "NOT RUN"
        note = f"host bind-mount errno/exit={mount_err} (this uid)"
    elif payload_ran(lines):
        v = "SURVIVED"
        note = "bind-mount swap ran the payload"
    elif any("exec_path errno=" in x for x in lines):
        v = "CAUGHT"
        note = "execve after bind-mount returned errno"
    else:
        v = "UNKNOWN"
        note = "bind-mount attempted; no exec line"
    return {
        "id": "bind-mount-swap",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "note": note,
        "mounted": mounted,
    }


def hunt_proc_exe(bins, tmp):
    storage = tmp / "proc-exe"
    storage.mkdir()
    proc = start_launch(bins["hunter"], ["proc-exe"], storage)
    init, lines, err = read_started(proc)
    wait_prefix(proc, lines, ["proc_exe ", "payload pid="], timeout=3)
    stop(proc)
    v = "SURVIVED" if payload_ran(lines) else (
        "CAUGHT" if any("proc_exe errno=" in x for x in lines) else "UNKNOWN"
    )
    return {
        "id": "proc-self-exe",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "note": "execve(/proc/self/exe) after start",
    }


def hunt_shebang_after_start(bins, tmp):
    storage = tmp / "shebang-after"
    storage.mkdir()
    script = storage / "run.sh"
    script.write_text(f"#!{bins['payload']}\n")
    script.chmod(0o755)
    proc = start_launch(bins["hunter"], ["shebang", str(script)], storage)
    init, lines, err = read_started(proc)
    wait_prefix(proc, lines, ["shebang ", "payload pid="], timeout=3)
    stop(proc)
    v = "SURVIVED" if payload_ran(lines) else (
        "CAUGHT" if any("shebang errno=" in x for x in lines) else "UNKNOWN"
    )
    return {
        "id": "shebang-after-start",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "note": "execve of a #! script whose interpreter is ungranted",
    }


def hunt_shebang_as_granted(bins, tmp):
    """The helper's one allowed execve is of a #! script.

    The kernel then loads the interpreter. If that second image runs,
    the granted-path exception launched an ungranted interpreter.
    """
    storage = tmp / "shebang-granted"
    storage.mkdir()
    script = tmp / "granted.sh"
    script.write_text(f"#!{bins['payload']}\n")
    script.chmod(0o755)
    proc = start_launch(str(script), [], storage)
    init, lines, err = read_started(proc)
    # Give the interpreter a moment if it started.
    if init is not None:
        drain_stdout(proc, lines, timeout=0.8)
    else:
        drain_stdout(proc, lines, timeout=0.2)
    stop(proc)
    ran = payload_ran(lines)
    refused = "refused to start" in err or "the provider was not started" in err
    if ran:
        v = "SURVIVED"
    elif refused or init is None:
        v = "CAUGHT"
    else:
        v = "UNKNOWN"
    return {
        "id": "shebang-as-granted",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "note": "granted path is a #! script; interpreter is the payload",
    }


def hunt_fd3_socket_dup2(bins, tmp):
    storage = tmp / "fd3-sock"
    storage.mkdir()
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    # Put the child end on fd 3 of the launcher.
    child_fd = b.fileno()
    # Python may not put it on 3; fcl-launch inherits open fds. We dup to 3.
    os.set_inheritable(child_fd, True)
    # Also dup onto 3 explicitly if needed.
    try:
        os.dup2(child_fd, 3)
        os.set_inheritable(3, True)
        used = 3
    except OSError:
        used = child_fd
    proc = start_launch(
        bins["hunter"],
        ["dup2-sock", "3"],
        storage,
        pass_fds=[3] if used == 3 else [child_fd],
    )
    init, lines, err = read_started(proc)
    wait_prefix(proc, lines, ["inherit_fd_3 ", "dup2_3_to_0 ", "scm_rights"], timeout=3)
    # Try to send a host fd in case the socket survived.
    try:
        secret = tmp / "host-secret"
        secret.write_bytes(b"host-only")
        with open(secret, "rb") as fh:
            send_scm_rights(a.fileno(), fh.fileno())
    except OSError:
        pass
    drain_stdout(proc, lines, timeout=0.4)
    stop(proc)
    a.close()
    b.close()
    if any("scm_rights_after_dup2 ok" in x for x in lines) or any(
        x.startswith("dup2_3_to_0 ok") for x in lines
    ):
        v = "SURVIVED"
    elif any("inherit_fd_3 gone" in x for x in lines) or any(
        x.startswith("fd 0 kind=") and "sock" not in x for x in lines
    ):
        v = "CAUGHT"
    else:
        v = "UNKNOWN"
    return {
        "id": "fd3-socket-dup2",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "note": "socket inherited on fd 3, then dup2 onto 0 after sanitize",
    }


def send_scm_rights(sock_fd, payload_fd):
    import array

    payload = array.array("i", [payload_fd])
    sock = socket.fromfd(sock_fd, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, payload)])
    finally:
        # fromfd duplicates; close the wrapper only.
        sock.close()


def hunt_pipe_then_scm(bins, tmp):
    storage = tmp / "pipe-scm"
    storage.mkdir()
    r, w = os.pipe()
    os.set_inheritable(r, True)
    proc = start_launch(
        bins["hunter"],
        ["pipe-scm"],
        storage,
        stdin=r,
    )
    init, lines, err = read_started(proc)
    wait_prefix(proc, lines, ["stdin_kind=", "stdin_recvmsg ", "stdin_scm"], timeout=2)
    # Host cannot send SCM_RIGHTS on a pipe. Try anyway, then also
    # open a unix socket and send a fd to the pipe write end.
    try:
        send_scm_rights(w, w)
        send_ok = True
        send_err = 0
    except OSError as exc:
        send_ok = False
        send_err = exc.errno or 0
    drain_stdout(proc, lines, timeout=0.3)
    stop(proc)
    os.close(r)
    os.close(w)
    imported = any("stdin_scm_rights ok" in x for x in lines)
    if imported or send_ok:
        v = "SURVIVED"
    elif any("stdin_recvmsg errno=" in x for x in lines) or any(
        x.startswith("stdin_kind=pipe") for x in lines
    ):
        v = "CAUGHT"
    else:
        v = "UNKNOWN"
    return {
        "id": "pipe-then-scm",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "note": f"stdin is a pipe; host sendmsg SCM_RIGHTS send_ok={send_ok} errno={send_err}",
        "send_ok": send_ok,
        "send_errno": send_err,
    }


def hunt_tiocsti_high(bins, tmp):
    storage = tmp / "tiocsti-high"
    storage.mkdir()
    master, slave = pty.openpty()
    os.set_inheritable(slave, True)
    try:
        os.dup2(slave, 3)
        os.set_inheritable(3, True)
        extra = [3]
    except OSError:
        extra = [slave]
    proc = start_launch(
        bins["hunter"],
        ["tiocsti-high"],
        storage,
        pass_fds=extra,
    )
    init, lines, err = read_started(proc)
    wait_prefix(proc, lines, ["tiocsti_fd_", "fd "], timeout=3)
    stop(proc)
    os.close(master)
    os.close(slave)
    if any(x.startswith("tiocsti_fd_") and x.endswith(" ok") for x in lines):
        v = "SURVIVED"
    elif any("tiocsti_fd_3 errno=" in x for x in lines) or any(
        "fd 3 kind=" not in "".join(lines) and "tiocsti_fd_3 errno=9" in x for x in lines
    ):
        v = "CAUGHT"
    else:
        # fd 3 gone and ioctl on missing fd is EBADF=9
        v = "CAUGHT" if any("tiocsti_fd_3 errno=9" in x for x in lines) else "UNKNOWN"
    return {
        "id": "tiocsti-fd-above-2",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "note": "TIOCSTI on an inherited pty kept on fd 3+",
    }


def hunt_wrong_arch(bins, tmp):
    storage = tmp / "wrong-arch"
    storage.mkdir()
    proc = start_launch(bins["hunter"], ["wrong-arch", bins["hunter"]], storage)
    init, lines, err = read_started(proc)
    wait_prefix(proc, lines, ["int80_", "x32_", "wrong_arch_"], timeout=3)
    stop(proc)
    ran = payload_ran(lines)
    killed = any("wrong_arch_child signal=" in x for x in lines)
    eperm = any("int80_execve errno=" in x or "x32_execve errno=" in x for x in lines)
    if ran:
        v = "SURVIVED"
    elif killed or eperm:
        v = "CAUGHT"
    else:
        v = "UNKNOWN"
    return {
        "id": "wrong-arch-execve",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "note": "execve via int 0x80 and __X32_SYSCALL_BIT after start",
    }


def hunt_clone3(bins, tmp):
    storage = tmp / "clone3"
    storage.mkdir()
    proc = start_launch(bins["hunter"], ["clone3"], storage)
    init, lines, err = read_started(proc)
    wait_prefix(proc, lines, ["clone3_cgroup "], timeout=3)
    stop(proc)
    line = next((x for x in lines if x.startswith("clone3_cgroup ")), "")
    if "ret=" in line and "ret=-1" not in line and "errno=0" in line:
        v = "SURVIVED"
    elif "errno=38" in line or "errno=1" in line:
        v = "CAUGHT"
    else:
        v = "UNKNOWN"
    return {
        "id": "clone3-into-cgroup",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "note": "clone3(CLONE_INTO_CGROUP); 38=ENOSYS 1=EPERM",
    }


def hunt_io_uring(bins, tmp):
    storage = tmp / "io-uring"
    storage.mkdir()
    proc = start_launch(bins["hunter"], ["io-uring"], storage)
    init, lines, err = read_started(proc)
    wait_prefix(proc, lines, ["io_uring_setup "], timeout=3)
    stop(proc)
    setup = next((x for x in lines if x.startswith("io_uring_setup ")), "")
    if "errno=0" in setup and "ret=-1" not in setup:
        v = "SURVIVED"
    elif "errno=1" in setup or "errno=38" in setup:
        v = "CAUGHT"
    else:
        v = "UNKNOWN"
    return {
        "id": "io-uring-setup",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "note": "io_uring_setup / enter / register after start",
    }


def hunt_ptrace(bins, tmp):
    storage = tmp / "ptrace"
    storage.mkdir()
    proc = start_launch(bins["hunter"], ["ptrace"], storage)
    init, lines, err = read_started(proc)
    wait_prefix(proc, lines, ["ptrace_sibling ", "ptrace_traceme "], timeout=3)
    stop(proc)
    sib = next((x for x in lines if x.startswith("ptrace_sibling ")), "")
    if "errno=0" in sib:
        v = "SURVIVED"
    elif "errno=1" in sib:
        v = "CAUGHT"
    else:
        v = "UNKNOWN"
    return {
        "id": "ptrace-sibling",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "note": "ptrace(PTRACE_ATTACH) of a forked sibling",
    }


def hunt_dumpable(bins, tmp):
    storage = tmp / "dumpable"
    storage.mkdir()
    proc = start_launch(bins["hunter"], ["dumpable"], storage)
    init, lines, err = read_started(proc)
    wait_prefix(proc, lines, ["dumpable_", "set_ptracer_", "ptrace_"], timeout=3)
    # From the host, try to attach if the confined process set dumpable
    # and PR_SET_PTRACER_ANY.
    host_ptrace = None
    provider = innermost(init) if init else None
    if provider:
        try:
            rc = subprocess.run(
                ["python3", "-c", f"import ctypes; libc=ctypes.CDLL(None, use_errno=True); r=libc.ptrace(16, {provider}, 0, 0); e=ctypes.get_errno(); print(r, e)"],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
            host_ptrace = rc.stdout.strip() + " " + rc.stderr.strip()
        except (subprocess.TimeoutExpired, OSError) as exc:
            host_ptrace = str(exc)
    stop(proc)
    set1 = next((x for x in lines if x.startswith("dumpable_set1 ")), "")
    ptracer = next((x for x in lines if x.startswith("set_ptracer_any ")), "")
    sib = next((x for x in lines if x.startswith("ptrace_sibling ")), "")
    # dumpable prctl succeeding is not itself an escape. SURVIVED only if
    # ptrace then works (inside or from the host).
    host_ok = host_ptrace is not None and host_ptrace.split()[:1] == ["0"]
    if "errno=0" in sib or host_ok:
        v = "SURVIVED"
    elif "errno=1" in sib:
        v = "CAUGHT"
    else:
        v = "UNKNOWN"
    return {
        "id": "prctl-dumpable",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "host_ptrace": host_ptrace,
        "note": f"PR_SET_DUMPABLE / PR_SET_PTRACER_ANY; sibling ptrace; host attach={host_ptrace!r}; set1={set1} ptracer={ptracer}",
    }


def hunt_r5_regression(bins, tmp):
    """The r5 leftover: memfd without MFD_EXEC, then /proc/self/fd/N."""
    storage = tmp / "r5-procfd"
    storage.mkdir()
    # Reuse the official probe path via hunter exec of a tiny C snippet
    # inlined here: hunter does not have memfd-procfd mode; call the
    # official probe if present, else a one-off gcc.
    src = HERE / "standins" / "procfd.c"
    src.write_text(
        r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        printf("payload pid=%d\n", (int)getpid());
        return 0;
    }
    const char *self = argv[0];
    int src = open(self, O_RDONLY);
    if (src < 0) { printf("open errno=%d\n", errno); return 1; }
    struct stat st; fstat(src, &st);
    int mem = (int)syscall(SYS_memfd_create, "r6", 0UL);
    if (mem < 0) { printf("memfd errno=%d\n", errno); return 1; }
    char buf[4096]; ssize_t n;
    while ((n = read(src, buf, sizeof buf)) > 0) write(mem, buf, (size_t)n);
    close(src);
    fchmod(mem, 0755);
    char path[64]; snprintf(path, sizeof path, "/proc/self/fd/%d", mem);
    char *av[] = {path, "--child", NULL};
    char *ev[] = {NULL};
    execve(path, av, ev);
    printf("procfd_execve errno=%d\n", errno);
    pause();
    return 0;
}
"""
    )
    out = BIN / "procfd"
    sh(["gcc", "-static", "-O1", str(src), "-o", str(out)])
    proc = start_launch(str(out), [], storage)
    init, lines, err = read_started(proc)
    wait_prefix(proc, lines, ["procfd_execve ", "payload pid="], timeout=3)
    stop(proc)
    v = "SURVIVED" if payload_ran(lines) else (
        "CAUGHT" if any("procfd_execve errno=" in x for x in lines) else "UNKNOWN"
    )
    return {
        "id": "r5-memfd-procfd",
        "started": init is not None,
        "verdict": v,
        "lines": lines,
        "err": err,
        "note": "r5 leftover replant: memfd no MFD_EXEC, execve(/proc/self/fd/N)",
    }


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    if not LAUNCHER.is_file():
        print(f"missing launcher {LAUNCHER}", file=sys.stderr)
        return 2
    bins = build_standins()
    hunts = []
    with tempfile.TemporaryDirectory(prefix="fcl-r6-") as raw:
        tmp = Path(raw)
        for fn in (
            hunt_granted_twice,
            hunt_symlink_swap,
            hunt_bind_mount_swap,
            hunt_proc_exe,
            hunt_shebang_after_start,
            hunt_shebang_as_granted,
            hunt_fd3_socket_dup2,
            hunt_pipe_then_scm,
            hunt_tiocsti_high,
            hunt_wrong_arch,
            hunt_clone3,
            hunt_io_uring,
            hunt_ptrace,
            hunt_dumpable,
            hunt_r5_regression,
        ):
            try:
                hunts.append(fn(bins, tmp))
            except Exception as exc:  # noqa: BLE001 — one hunt must not stop the rest
                hunts.append(
                    {
                        "id": fn.__name__,
                        "started": False,
                        "verdict": "ERROR",
                        "lines": [],
                        "err": str(exc),
                        "note": "harness exception",
                    }
                )
    out = {
        "head": HEAD,
        "launcher": str(LAUNCHER),
        "hunts": hunts,
    }
    (EVIDENCE / "attacks.json").write_text(json.dumps(out, indent=2) + "\n")
    text_lines = [f"head={HEAD}", f"launcher={LAUNCHER}"]
    for h in hunts:
        text_lines.append(
            f"{h['id']}: {h['verdict']} started={h.get('started')} note={h.get('note')}"
        )
        for line in h.get("lines", []):
            text_lines.append(f"  {line}")
        if h.get("err"):
            text_lines.append(f"  stderr: {h['err'][:400]}")
        if h.get("host_ptrace"):
            text_lines.append(f"  host_ptrace: {h['host_ptrace']}")
    text = "\n".join(text_lines) + "\n"
    (EVIDENCE / "attacks.stdout.txt").write_text(text)
    print(text)
    unknown = sum(1 for h in hunts if h["verdict"] in ("UNKNOWN", "ERROR"))
    survived = [h["id"] for h in hunts if h["verdict"] == "SURVIVED"]
    print(f"summary survived={survived} unknown={unknown} total={len(hunts)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
