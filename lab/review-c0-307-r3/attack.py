#!/usr/bin/env python3
"""Live attacks against draft PR #307 at 26c55e6c.

Does not edit lab/fail-closed-linux. Writes evidence/attacks.json.
Needs FCL_LAUNCH, FCL_PROBE, and compiled standins in STANDIN_DIR.
"""

from __future__ import annotations

import json
import os
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REVIEW = Path(__file__).resolve().parent
EVIDENCE = REVIEW / "evidence"
LAUNCH = Path(
    os.environ.get(
        "FCL_LAUNCH",
        "/tmp/review-c0-307-r3-src/lab/fail-closed-linux/target/debug/fcl-launch",
    )
)
PROBE = Path(
    os.environ.get(
        "FCL_PROBE",
        "/tmp/review-c0-307-r3-src/lab/fail-closed-linux/target/build/debug/build/fail-closed-linux-1d11d7b03d991c2d/out/fcl-probe",
    )
)
STANDIN_DIR = Path(os.environ.get("STANDIN_DIR", REVIEW / "standins"))


def read_status(pid: int) -> dict:
    text = Path(f"/proc/{pid}/status").read_text()
    fields = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        fields[key] = value.strip()
    return fields


def children_of(pid: int) -> list[int]:
    path = Path(f"/proc/{pid}/task/{pid}/children")
    if not path.is_file():
        return []
    return [int(x) for x in path.read_text().split() if x]


def descendants(pid: int, depth: int = 6) -> list[int]:
    found = []
    stack = [pid]
    seen = {pid}
    while stack and depth > 0:
        depth -= 1
        nxt = []
        for cur in stack:
            for child in children_of(cur):
                if child not in seen:
                    seen.add(child)
                    found.append(child)
                    nxt.append(child)
        stack = nxt
    return found


def ns(pid: int, kind: str) -> str:
    return os.readlink(f"/proc/{pid}/ns/{kind}")


def nspid(pid: int) -> str:
    return read_status(pid).get("NSpid", "")


def alive(pid: int) -> bool:
    return Path(f"/proc/{pid}").exists()


def open_pty():
    master = os.open("/dev/ptmx", os.O_RDWR | os.O_NOCTTY)
    if os.isatty(master):
        pass
    import ctypes
    import ctypes.util

    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    if libc.grantpt(master) != 0 or libc.unlockpt(master) != 0:
        raise OSError("grantpt/unlockpt failed")
    buf = ctypes.create_string_buffer(128)
    if libc.ptsname_r(master, buf, 128) != 0:
        name = os.readlink(f"/proc/self/fd/{master}")
        # ptsname_r missing: fall back
        raise OSError("ptsname_r failed")
    return master, buf.value.decode()


def pts_path(master: int) -> str:
    return os.readlink(f"/proc/self/fd/{master}").replace("pts/", "pts/")


def make_pty():
    import pty as ptylib

    master, slave = ptylib.openpty()
    path = os.readlink(f"/proc/self/fd/{slave}")
    return master, slave, path


def read_lines_until(proc, done, secs=6.0) -> list[str]:
    assert proc.stdout is not None
    lines: list[str] = []
    buf = b""
    deadline = time.time() + secs
    while time.time() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], 0.1)
        if not ready:
            if proc.poll() is not None:
                rest = proc.stdout.read() or b""
                buf += rest
                break
            continue
        chunk = os.read(proc.stdout.fileno(), 4096)
        if not chunk:
            break
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            lines.append(line.decode("utf-8", "replace"))
            if done(lines):
                return lines
    if buf:
        lines.append(buf.decode("utf-8", "replace"))
    return lines


def start_cmd(executable: Path, extra_probe=None, extra_launch=None, env=None, pass_fds=None):
    work = Path(tempfile.mkdtemp(prefix="r3-atk-"))
    storage = work / "storage"
    outside = work / "outside"
    storage.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("outside")
    master, slave, tty_path = make_pty()
    cmd = [
        str(LAUNCH),
        "--provider",
        "did-provider",
        "--storage-root",
        str(storage),
        "--readable-path",
        tty_path,
    ]
    if extra_launch:
        cmd.extend(extra_launch)
    cmd += ["--", str(executable)]
    if extra_probe is not None:
        cmd.extend(extra_probe)
    else:
        cmd += [
            "did-provider",
            str(storage),
            str(outside / "secret.txt"),
            str(outside),
            "--tty-path",
            tty_path,
        ]
    popen_kwargs = dict(
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        bufsize=0,
        env=env,
        cwd=str(work),
    )
    if pass_fds:
        popen_kwargs["pass_fds"] = pass_fds
    proc = subprocess.Popen(cmd, **popen_kwargs)
    return proc, work, master, slave, tty_path


def start_probe(extra_probe=None, extra_launch=None, env=None):
    proc, work, master, slave, tty_path = start_cmd(
        PROBE, extra_probe=extra_probe, extra_launch=extra_launch, env=env
    )

    def done(lines):
        return any(line.startswith("started did-provider pid=") for line in lines) and (
            "ready" in lines or any(line.startswith("nspid=") for line in lines)
        )

    lines = read_lines_until(proc, done)
    init = None
    for line in lines:
        if line.startswith("started did-provider pid="):
            init = int(line.split("=", 1)[1])
    return proc, init, lines, work, master, slave, tty_path


def stop(proc, work, *fds):
    if proc.stdin:
        try:
            proc.stdin.close()
        except OSError:
            pass
    if proc.poll() is None:
        proc.send_signal(signal.SIGKILL)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass
    shutil.rmtree(work, ignore_errors=True)


def experiment_p3_p4_p7() -> dict:
    """Replay #355 P3 (helper beside provider), P4 (SIGKILL), P7 (daemonize)."""
    out = {}
    proc, init, lines, work, master, slave, tty = start_probe()
    try:
        if init is None:
            return {"error": "no started pid", "lines": lines}
        tree_children = children_of(init)
        launcher_children = children_of(proc.pid)
        helper_in_host = False
        host_ns = ns(os.getpid(), "pid")
        try:
            init_ns = ns(init, "pid")
        except FileNotFoundError:
            init_ns = None
        out["p3"] = {
            "returned_pid": init,
            "returned_nspid": nspid(init),
            "returned_shares_host_pid_ns": init_ns == host_ns,
            "launcher_children": launcher_children,
            "init_children": tree_children,
            "lines": lines,
            "helper_beside_provider": launcher_children != [init],
        }
        provider = tree_children[0] if tree_children else None
        out["p3"]["provider_pid"] = provider
        if provider:
            out["p3"]["provider_nspid"] = nspid(provider)
            out["p3"]["provider_pdeathsig"] = Path(
                f"/proc/{provider}/status"
            ).read_text()
        os.kill(init, signal.SIGKILL)
        try:
            status = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            status = proc.wait(timeout=2)
            out["p4"] = {"error": "launcher did not exit after SIGKILL", "status": status}
        else:
            out["p4"] = {
                "launcher_exit": status,
                "init_alive": alive(init),
                "provider_alive": alive(provider) if provider else None,
                "namespace_down": (not alive(init))
                and (provider is None or not alive(provider)),
            }
    finally:
        stop(proc, work, master, slave)

    proc, init, lines, work, master, slave, tty = start_probe(
        extra_probe=[
            "did-provider",
            "STORAGE",
            "OUT",
            "OUTDIR",
            "--tty-path",
            "TTY",
            "--daemonize",
        ]
    )
    # The extra_probe above used placeholders; do it properly.
    stop(proc, work, master, slave)

    proc, work, master, slave, tty = start_cmd(
        PROBE,
        extra_probe=[
            "did-provider",
            str(work / "storage"),
            str(work / "outside" / "secret.txt"),
            str(work / "outside"),
            "--tty-path",
            tty,
            "--daemonize",
        ],
    )

    def done(lines):
        return any(line.startswith("started did-provider pid=") for line in lines) and (
            "ready" in lines
        )

    lines = read_lines_until(proc, done)
    init = None
    for line in lines:
        if line.startswith("started did-provider pid="):
            init = int(line.split("=", 1)[1])
    time.sleep(0.15)
    leftover = descendants(init) if init else []
    launcher_still = proc.poll()
    if init:
        os.kill(init, signal.SIGKILL)
    try:
        status = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        status = proc.wait(timeout=2)
    out["p7_daemonize"] = {
        "returned_pid": init,
        "launcher_exited_after_daemonize": launcher_still is not None,
        "leftover_before_kill": leftover,
        "leftover_alive_after_kill": [p for p in leftover if alive(p)],
        "launcher_exit": status,
        "lines": lines,
    }
    stop(proc, work, master, slave)
    return out


def experiment_p6_confine_ready() -> dict:
    env = dict(os.environ)
    env["FCL_TEST_HOOKS"] = "1"
    proc, work, master, slave, tty = start_cmd(
        PROBE, extra_launch=["--test-confine-ready"], env=env
    )
    stdout, stderr = proc.communicate(timeout=5)
    return {
        "exit": proc.returncode,
        "stdout": stdout.decode("utf-8", "replace"),
        "stderr": stderr.decode("utf-8", "replace"),
        "marker_exists": (work / "storage" / "probe-ran").exists(),
        "refused": proc.returncode == 71
        and b"ConfineReady without execve is not a start" in stderr,
    }


def experiment_ioctl_357() -> dict:
    proc, init, lines, work, master, slave, tty = start_probe()
    try:
        confined = next((ln for ln in lines if ln.startswith("ioctl_dev ")), None)
        # unconfined TIOCGWINSZ on the same slave
        import ctypes
        import fcntl
        import struct

        slave_rw = os.open(tty, os.O_RDWR | os.O_NOCTTY)
        buf = bytearray(8)
        try:
            fcntl.ioctl(slave_rw, 0x5413, buf)
            unconfined = {"ok": True, "errno": 0}
        except OSError as err:
            unconfined = {"ok": False, "errno": err.errno}
        os.close(slave_rw)
        return {
            "confined_line": confined,
            "unconfined": unconfined,
            "confined_eacces": confined == "ioctl_dev errno=13",
            "unconfined_ok": unconfined["ok"],
        }
    finally:
        stop(proc, work, master, slave)


def experiment_sigterm_ignore() -> dict:
    standin = STANDIN_DIR / "ignore_sigterm.bin"
    proc, work, master, slave, tty = start_cmd(standin, extra_probe=[])

    def done(lines):
        return any(line.startswith("started did-provider pid=") for line in lines)

    lines = read_lines_until(proc, done)
    init = None
    for line in lines:
        if line.startswith("started did-provider pid="):
            init = int(line.split("=", 1)[1])
    if init is None:
        stderr = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
        stop(proc, work, master, slave)
        return {"error": "did not start", "lines": lines, "stderr": stderr}
    kids = descendants(init)
    os.kill(init, signal.SIGTERM)
    try:
        status = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        status = proc.wait(timeout=2)
        result = {"error": "launcher did not exit after SIGTERM of init", "status": status}
    else:
        result = {
            "returned_pid": init,
            "launcher_exit": status,
            "init_alive": alive(init),
            "kids_alive": [p for p in kids if alive(p)],
            "lines": lines,
            "killed_despite_ignored_sigterm": (not alive(init))
            and not any(alive(p) for p in kids),
        }
    stop(proc, work, master, slave)
    return result


def experiment_double_fork_setsid() -> dict:
    standin = STANDIN_DIR / "double_fork_setsid.bin"
    proc, work, master, slave, tty = start_cmd(standin, extra_probe=[])

    def done(lines):
        return any(line.startswith("started did-provider pid=") for line in lines)

    lines = read_lines_until(proc, done)
    init = None
    for line in lines:
        if line.startswith("started did-provider pid="):
            init = int(line.split("=", 1)[1])
    if init is None:
        stderr = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
        stop(proc, work, master, slave)
        return {"error": "did not start", "lines": lines, "stderr": stderr}
    time.sleep(0.2)
    leftover = descendants(init)
    host_ns = ns(os.getpid(), "pid")
    leftover_ns = []
    for pid in leftover:
        try:
            leftover_ns.append(
                {
                    "pid": pid,
                    "nspid": nspid(pid),
                    "shares_host": ns(pid, "pid") == host_ns,
                    "sid": Path(f"/proc/{pid}/stat").read_text().split()[5],
                }
            )
        except FileNotFoundError:
            leftover_ns.append({"pid": pid, "gone": True})
    escaped = any(item.get("shares_host") for item in leftover_ns)
    os.kill(init, signal.SIGKILL)
    try:
        status = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        status = proc.wait(timeout=2)
    still = [p for p in leftover if alive(p)]
    result = {
        "returned_pid": init,
        "leftover": leftover_ns,
        "escaped_to_host_pid_ns": escaped,
        "survived_init_kill": still,
        "launcher_exit": status,
        "lines": lines,
    }
    stop(proc, work, master, slave)
    return result


def experiment_exec_other_binary() -> dict:
    """Any successful execve of a granted static binary looks like a start.

    /bin/sleep is dynamically linked and Landlock has no library grant, so
    that path is EACCES. A second static stand-in is a different binary
    that writes nothing after execve.
    """
    sleep = Path("/bin/sleep")
    proc, work, master, slave, tty = start_cmd(sleep, extra_probe=["30"])

    def done(lines):
        return any(line.startswith("started did-provider pid=") for line in lines)

    lines = read_lines_until(proc, done, secs=3)
    init = None
    for line in lines:
        if line.startswith("started did-provider pid="):
            init = int(line.split("=", 1)[1])
    stderr = b""
    if proc.poll() is not None and proc.stderr:
        stderr = proc.stderr.read() or b""
    dyn = {
        "path": str(sleep),
        "started": init is not None,
        "returned_pid": init,
        "exit": proc.poll(),
        "stderr": stderr.decode("utf-8", "replace"),
        "lines": lines,
    }
    if init:
        os.kill(init, signal.SIGKILL)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    stop(proc, work, master, slave)

    other = STANDIN_DIR / "sleep_forever.bin"
    proc, work, master, slave, tty = start_cmd(other, extra_probe=[])

    def done2(lines2):
        return any(line.startswith("started did-provider pid=") for line in lines2)

    lines2 = read_lines_until(proc, done2, secs=3)
    init2 = None
    for line in lines2:
        if line.startswith("started did-provider pid="):
            init2 = int(line.split("=", 1)[1])
    static = {
        "path": str(other),
        "started": init2 is not None,
        "returned_pid": init2,
        "lines": lines2,
        "eof_accepted_different_binary": init2 is not None,
    }
    if init2:
        os.kill(init2, signal.SIGKILL)
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    stop(proc, work, master, slave)
    return {"dynamic_sleep": dyn, "static_other": static}


def experiment_inherited_tiocgwinsz() -> dict:
    standin = STANDIN_DIR / "inherit_ioctl.bin"
    work = Path(tempfile.mkdtemp(prefix="r3-inh-"))
    storage = work / "storage"
    storage.mkdir()
    master, slave, tty_path = make_pty()
    # Keep slave as fd 3 in the launcher, not close-on-exec.
    os.set_inheritable(slave, True)
    if slave != 3:
        os.dup2(slave, 3)
        os.set_inheritable(3, True)
    cmd = [
        str(LAUNCH),
        "--provider",
        "did-provider",
        "--storage-root",
        str(storage),
        "--readable-path",
        tty_path,
        "--",
        str(standin),
    ]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        bufsize=0,
        pass_fds=(3,),
        cwd=str(work),
    )
    lines = read_lines_until(
        proc, lambda ls: any(ln.startswith("inherit_ioctl ") for ln in ls), secs=5
    )
    stderr = b""
    if proc.poll() is not None and proc.stderr:
        stderr = proc.stderr.read() or b""
    result = {
        "lines": lines,
        "stderr": stderr.decode("utf-8", "replace"),
        "exit": proc.poll(),
        "inherited_ok": any(ln.startswith("inherit_ioctl ok") for ln in lines),
        "inherited_errno": next(
            (ln for ln in lines if ln.startswith("inherit_ioctl errno=")), None
        ),
    }
    if proc.poll() is None:
        proc.kill()
        proc.wait(timeout=2)
    try:
        os.close(3)
    except OSError:
        pass
    stop(proc, work, master, slave)
    return result


def experiment_empty_pipe_and_lie() -> dict:
    env = dict(os.environ)
    env["FCL_TEST_HOOKS"] = "1"
    out = {}
    for flag, key in (
        ("--test-empty-pipe", "empty_pipe"),
        ("--test-lie-rights", "lie_rights"),
    ):
        proc, work, master, slave, tty = start_cmd(PROBE, extra_launch=[flag], env=env)
        stdout, stderr = proc.communicate(timeout=5)
        out[key] = {
            "exit": proc.returncode,
            "stderr": stderr.decode("utf-8", "replace"),
            "marker": (work / "storage" / "probe-ran").exists(),
        }
        stop(proc, work, master, slave)
    return out


def experiment_pdeathsig() -> dict:
    standin = STANDIN_DIR / "print_pdeathsig.bin"
    proc, work, master, slave, tty = start_cmd(standin, extra_probe=[])
    stdout, stderr = proc.communicate(timeout=5)
    text = stdout.decode("utf-8", "replace")
    return {
        "exit": proc.returncode,
        "stdout": text,
        "stderr": stderr.decode("utf-8", "replace"),
        "pdeathsig_is_sigkill": "pdeathsig=9" in text,
    }


def experiment_pid_reuse_window() -> dict:
    """Returned pid must stay init after helper exit. Stress 20 launches."""
    rows = []
    for i in range(20):
        proc, init, lines, work, master, slave, tty = start_probe()
        try:
            if init is None:
                rows.append({"i": i, "error": "no pid", "lines": lines})
                continue
            comm = Path(f"/proc/{init}/comm").read_text().strip()
            nsp = nspid(init)
            kids = children_of(proc.pid)
            rows.append(
                {
                    "i": i,
                    "pid": init,
                    "comm": comm,
                    "nspid": nsp,
                    "launcher_children": kids,
                    "is_init": nsp.endswith("\t1") or nsp.endswith(" 1") or nsp == "1",
                    "helper_gone": kids == [init],
                }
            )
        finally:
            stop(proc, work, master, slave)
    bad = [r for r in rows if r.get("error") or not r.get("is_init") or not r.get("helper_gone")]
    return {"launches": len(rows), "bad": bad, "all_init_after_helper_exit": not bad}


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    missing = [p for p in (LAUNCH, PROBE) if not p.is_file()]
    standins = [
        STANDIN_DIR / name
        for name in (
            "ignore_sigterm.bin",
            "double_fork_setsid.bin",
            "inherit_ioctl.bin",
            "sleep_forever.bin",
            "print_pdeathsig.bin",
        )
    ]
    missing += [p for p in standins if not p.is_file()]
    if missing:
        print("missing binaries:", missing, file=sys.stderr)
        sys.exit(2)

    report = {
        "head": "26c55e6cbd59d1f4e740fc60dc8dd404b7d900da",
        "launch": str(LAUNCH),
        "probe": str(PROBE),
        "p3_p4_p7": experiment_p3_p4_p7(),
        "p6_confine_ready": experiment_p6_confine_ready(),
        "ioctl_357": experiment_ioctl_357(),
        "sigterm_ignore": experiment_sigterm_ignore(),
        "double_fork_setsid": experiment_double_fork_setsid(),
        "exec_other_binary": experiment_exec_other_binary(),
        "inherited_tiocgwinsz": experiment_inherited_tiocgwinsz(),
        "hooks": experiment_empty_pipe_and_lie(),
        "pid_reuse_window": experiment_pid_reuse_window(),
        "pdeathsig": experiment_pdeathsig(),
    }
    path = EVIDENCE / "attacks.json"
    path.write_text(json.dumps(report, indent=2, default=str) + "\n")
    print(json.dumps(report, indent=2, default=str))
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
