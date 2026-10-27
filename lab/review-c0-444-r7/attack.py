#!/usr/bin/env python3
"""Live r7 hunts against the built fcl-launch at 57cbd4af.

Does not edit lab/fail-closed-linux. Needs FCL_SRC and that tree's
fcl-launch.
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

HERE = Path(__file__).resolve().parent
FCL_SRC = Path(os.environ.get("FCL_SRC", "/workspace/lab/fail-closed-linux"))
BIN = HERE / "standins" / "bin"
EVIDENCE = HERE / "evidence"
HEAD = "57cbd4af261ebecaa5fbfd7d19b2dd57cc70d7f0"


def find_launcher() -> Path:
    env = os.environ.get("FCL_LAUNCH")
    if env:
        return Path(env)
    candidates = [
        FCL_SRC / "target" / "debug" / "fcl-launch",
        FCL_SRC / "target" / "build" / "debug" / "fcl-launch",
    ]
    for path in candidates:
        if path.is_file():
            return path
    raise SystemExit(f"fcl-launch not found under {FCL_SRC}/target")


LAUNCHER = find_launcher()


def sh(args, **kw):
    return subprocess.run(args, check=True, **kw)


def build_standins():
    BIN.mkdir(parents=True, exist_ok=True)
    hunter = BIN / "hunter"
    payload = BIN / "payload"
    host = BIN / "host-attacks"
    sh(
        [
            "gcc",
            "-static",
            "-O1",
            "-Wall",
            "-Wextra",
            str(HERE / "standins" / "hunter.c"),
            "-o",
            str(hunter),
        ]
    )
    sh(
        [
            "gcc",
            "-static",
            "-O1",
            "-Wall",
            "-Wextra",
            str(HERE / "standins" / "payload.c"),
            "-o",
            str(payload),
        ]
    )
    sh(
        [
            "gcc",
            "-O1",
            "-Wall",
            "-Wextra",
            str(HERE / "standins" / "host-attacks.c"),
            "-o",
            str(host),
        ]
    )
    return {"hunter": str(hunter), "payload": str(payload), "host": str(host)}


def host_run(bins, op, pid, pid2=None, timeout=3):
    cmd = [bins["host"], op, str(pid)]
    if pid2 is not None:
        cmd.append(str(pid2))
    try:
        done = subprocess.run(
            cmd, check=False, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "rc": 124,
            "out": (exc.stdout or b"").decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            "err": "timeout",
        }
    return {"rc": done.returncode, "out": done.stdout, "err": done.stderr}


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


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def start_launch(exe, args, storage, extra_env=None):
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
    return subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        env=env,
    )


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


def read_started(proc, timeout=8.0):
    lines = []
    deadline = time.time() + timeout
    init = None
    while time.time() < deadline:
        drain_stdout(proc, lines, timeout=0.15)
        for line in lines:
            if line.startswith("started ") and "pid=" in line:
                init = int(line.rsplit("=", 1)[1])
        if init is not None and any(line == "ready" for line in lines):
            break
        if proc.poll() is not None:
            drain_stdout(proc, lines, timeout=0.05)
            break
    err = ""
    if proc.stderr is not None:
        ready, _, _ = select.select([proc.stderr], [], [], 0.05)
        if ready:
            err = os.read(proc.stderr.fileno(), 8192).decode("utf-8", "replace")
    return init, lines, err


def stop(proc):
    if proc.poll() is None:
        proc.send_signal(signal.SIGKILL)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


def caught_errno(text, *tags):
    for tag in tags:
        if f"{tag} errno=" in text:
            return True
    return False


def ok_line(text, *tags):
    for tag in tags:
        if f"{tag} ok" in text:
            return True
    return False


def granted_copy(bins, tmp, name):
    """Copy the hunter. The guard chmod 0111s the granted path."""
    granted = tmp / f"{name}.granted"
    shutil.copy2(bins["hunter"], granted)
    granted.chmod(0o755)
    return granted


def start_ready(bins, tmp, name, extra_args=None):
    storage = tmp / name
    storage.mkdir()
    granted = granted_copy(bins, tmp, name)
    args = extra_args or []
    proc = start_launch(str(granted), args, storage)
    init, lines, err = read_started(proc)
    provider = innermost(init) if init else None
    return proc, init, provider, lines, err


def hunt_inside(bins, tmp):
    proc, init, provider, lines, err = start_ready(
        bins, tmp, "inside", extra_args=[bins["payload"]]
    )
    stop(proc)
    text = "\n".join(lines)
    rows = []

    def row(hid, note, verdict):
        rows.append(
            {
                "id": hid,
                "verdict": verdict,
                "started": init is not None,
                "init": init,
                "provider": provider,
                "lines": lines,
                "err": err,
                "note": note,
            }
        )

    row(
        "inside-process_vm",
        "provider process_vm_readv/writev of init",
        "CAUGHT"
        if caught_errno(text, "process_vm_readv", "process_vm_writev")
        and not ok_line(text, "process_vm_readv", "process_vm_writev")
        else ("SURVIVED" if ok_line(text, "process_vm_readv", "process_vm_writev") else "UNKNOWN"),
    )
    row(
        "inside-pidfd_getfd",
        "provider pidfd_getfd of init",
        "CAUGHT"
        if caught_errno(text, "pidfd_getfd_parent")
        else ("SURVIVED" if ok_line(text, "pidfd_getfd_parent") else "UNKNOWN"),
    )
    child_exec = (
        "child_exec_helper errno=" in text
        or "child_exec_self errno=" in text
        or "child_exec_self ran" in text
    )
    row(
        "inside-child-exec-ptrace",
        "child exec of a setuid-less helper, then ptrace",
        "SURVIVED"
        if "child_exec_self ran" in text or "payload pid=" in text
        else (
            "CAUGHT"
            if (
                caught_errno(text, "ptrace_traceme", "ptrace_parent", "ptrace_child")
                or "child_exec_helper errno=" in text
                or "child_exec_self errno=" in text
            )
            else "UNKNOWN"
        ),
    )
    row(
        "inside-prctl-x32",
        "PR_SET_DUMPABLE via prctl, high-32 alias, x32 ABI",
        "SURVIVED"
        if ok_line(text, "prctl_dumpable_1")
        else (
            "CAUGHT"
            if caught_errno(text, "prctl_dumpable_1", "prctl_x32")
            else "UNKNOWN"
        ),
    )
    row(
        "inside-io_uring",
        "io_uring_setup from the provider",
        "SURVIVED"
        if ok_line(text, "io_uring_setup")
        else ("CAUGHT" if caught_errno(text, "io_uring_setup") else "UNKNOWN"),
    )
    row(
        "inside-userfaultfd",
        "userfaultfd from the provider",
        "SURVIVED"
        if ok_line(text, "userfaultfd")
        else ("CAUGHT" if caught_errno(text, "userfaultfd") else "UNKNOWN"),
    )
    row(
        "inside-perf_event_open",
        "perf_event_open from the provider",
        "SURVIVED"
        if ok_line(text, "perf_event_open")
        else ("CAUGHT" if caught_errno(text, "perf_event_open") else "UNKNOWN"),
    )
    _ = child_exec
    return rows


def hunt_host_pair(bins, tmp, name, op, target, note):
    proc, init, provider, lines, err = start_ready(bins, tmp, name)
    who = {"init": init, "provider": provider}.get(target)
    result = {"rc": -1, "out": "", "err": "not started"}
    if who:
        result = host_run(bins, op, who)
    stop(proc)
    text = result["out"]
    if who is None:
        verdict = "UNKNOWN"
    elif ok_line(text, op, "ptrace_attach", "open_mem", "process_vm_readv", "process_vm_writev", "pidfd_getfd", "perf_event_open"):
        verdict = "SURVIVED"
    elif caught_errno(
        text,
        "ptrace_attach",
        "open_mem",
        "process_vm_readv",
        "process_vm_writev",
        "pidfd_getfd",
        "pidfd_open",
        "perf_event_open",
    ):
        verdict = "CAUGHT"
    else:
        verdict = "UNKNOWN"
    return {
        "id": name,
        "verdict": verdict,
        "started": init is not None,
        "init": init,
        "provider": provider,
        "target": target,
        "host": result,
        "lines": lines,
        "err": err,
        "note": note,
    }


def hunt_proc_files(bins, tmp, target):
    name = f"proc-files-{target}"
    proc, init, provider, lines, err = start_ready(bins, tmp, name)
    who = {"init": init, "provider": provider}.get(target)
    result = {"rc": -1, "out": "", "err": "not started"}
    if who:
        result = host_run(bins, "proc_files", who)
        owner = host_run(bins, "dumpable_owner", who)
        result["owner"] = owner["out"]
    stop(proc)
    text = result["out"]
    readable = []
    blocked = []
    for field in ("environ", "maps", "mem", "fd"):
        if f"read_{field} ok" in text or f"open_{field} ok" in text:
            readable.append(field)
        elif f"open_{field} errno=" in text or f"read_{field} errno=" in text:
            blocked.append(field)
    if who is None:
        verdict = "UNKNOWN"
    elif "mem" in readable:
        verdict = "SURVIVED"
    elif readable:
        # maps/status of a dumpable-0 process can still leak; call that out
        verdict = "SURVIVED" if target == "init" or "environ" in readable or "fd" in readable else "PARTIAL"
    elif blocked:
        verdict = "CAUGHT"
    else:
        verdict = "UNKNOWN"
    return {
        "id": name,
        "verdict": verdict,
        "started": init is not None,
        "init": init,
        "provider": provider,
        "host": result,
        "readable": readable,
        "blocked": blocked,
        "lines": lines,
        "err": err,
        "note": f"same-uid /proc/{target}/{{environ,maps,fd,mem}}",
    }


def hunt_kill_init(bins, tmp):
    proc, init, provider, lines, err = start_ready(bins, tmp, "kill-init")
    result = {"rc": -1, "out": "", "err": "not started"}
    provider_after = None
    if init and provider:
        result = host_run(bins, "kill", init, provider)
        time.sleep(0.1)
        provider_after = alive(provider)
        init_after = alive(init)
    else:
        init_after = None
    stop(proc)
    if provider is None:
        verdict = "UNKNOWN"
        note = "no provider pid"
    elif provider_after:
        verdict = "SURVIVED"
        note = "SIGKILL init; provider still running (untraced or still live)"
    else:
        verdict = "CAUGHT"
        note = "SIGKILL init; EXITKILL/namespace took the provider down"
    return {
        "id": "kill-init",
        "verdict": verdict,
        "started": init is not None,
        "init": init,
        "provider": provider,
        "init_after": init_after,
        "provider_after": provider_after,
        "host": result,
        "lines": lines,
        "err": err,
        "note": note,
    }


def hunt_signal_init(bins, tmp):
    proc, init, provider, lines, err = start_ready(bins, tmp, "stop-init")
    result = {"rc": -1, "out": "", "err": "not started"}
    if init and provider:
        result = host_run(bins, "stop", init, provider)
    stop(proc)
    text = result["out"]
    if provider is None:
        verdict = "UNKNOWN"
    elif "ptrace_attach ok" in text:
        verdict = "SURVIVED"
    elif "ptrace_attach errno=" in text:
        verdict = "CAUGHT"
    else:
        verdict = "UNKNOWN"
    return {
        "id": "signal-stop-init",
        "verdict": verdict,
        "started": init is not None,
        "init": init,
        "provider": provider,
        "host": result,
        "lines": lines,
        "err": err,
        "note": "SIGSTOP init, then same-uid PTRACE_ATTACH of the provider",
    }


def hunt_core(bins, tmp):
    proc, init, provider, lines, err = start_ready(bins, tmp, "core")
    cores_before = set(Path(".").glob("core*")) | set((tmp / "core").parent.glob("core*"))
    cwd_cores = set(Path("/tmp").glob("core*")) if Path("/tmp").exists() else set()
    result = {"rc": -1, "out": "", "err": "not started"}
    if provider:
        result = host_run(bins, "core", provider)
    time.sleep(0.2)
    cores_after = set(Path(".").glob("core*")) | set(Path("/tmp").glob("core*"))
    new_cores = [str(p) for p in (cores_after - cores_before - cwd_cores)]
    stop(proc)
    dumpable = "\n".join(lines)
    if new_cores:
        verdict = "SURVIVED"
        note = f"SIGQUIT left core files {new_cores}"
    elif "get_dumpable=0" in dumpable:
        verdict = "CAUGHT"
        note = "dumpable 0; SIGQUIT produced no new core file"
    else:
        verdict = "CAUGHT" if not new_cores else "UNKNOWN"
        note = f"no new core; hunter dumpable line in {dumpable}"
    return {
        "id": "core-dump",
        "verdict": verdict,
        "started": init is not None,
        "init": init,
        "provider": provider,
        "new_cores": new_cores,
        "host": result,
        "lines": lines,
        "err": err,
        "note": note,
    }


def hunt_confuse(bins, tmp):
    proc, init, provider, lines, err = start_ready(bins, tmp, "confuse")
    result = {"rc": -1, "out": "", "err": "not started"}
    if init and provider:
        result = host_run(bins, "confuse", init, provider, timeout=5)
    stop(proc)
    text = result["out"]
    if provider is None:
        verdict = "UNKNOWN"
        note = "no provider pid"
    elif "confuse_attach_provider ok" in text:
        verdict = "SURVIVED"
        note = "attached init, injected PTRACE_DETACH, then attached the provider"
    elif "confuse_attach_init errno=" in text:
        verdict = "CAUGHT"
        note = "could not attach init"
    elif "confuse_attach_init ok" in text and "confuse_attach_provider errno=" in text:
        verdict = "PARTIAL"
        note = "init is attachable; injected detach did not yield the provider"
    else:
        verdict = "UNKNOWN"
        note = text.strip() or result["err"]
    return {
        "id": "init-confused-deputy",
        "verdict": verdict,
        "started": init is not None,
        "init": init,
        "provider": provider,
        "host": result,
        "lines": lines,
        "err": err,
        "note": note,
    }


def hunt_race(bins, tmp):
    storage = tmp / "race"
    storage.mkdir()
    granted = granted_copy(bins, tmp, "race")
    proc = start_launch(str(granted), [], storage)
    hits = []
    deadline = time.time() + 3.0
    seen = set()
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        # Walk new pids that look like children of this launcher.
        try:
            kids = children_of(proc.pid)
        except Exception:
            kids = []
        for kid in kids:
            if kid in seen:
                continue
            seen.add(kid)
            attach = host_run(bins, "ptrace", kid)
            mem = host_run(bins, "mem", kid)
            hits.append({"pid": kid, "ptrace": attach["out"], "mem": mem["out"]})
            for grand in children_of(kid):
                if grand in seen:
                    continue
                seen.add(grand)
                attach = host_run(bins, "ptrace", grand)
                mem = host_run(bins, "mem", grand)
                hits.append({"pid": grand, "ptrace": attach["out"], "mem": mem["out"]})
        time.sleep(0.002)
    init, lines, err = read_started(proc, timeout=2.0)
    provider = innermost(init) if init else None
    stop(proc)
    attached = [h for h in hits if "ptrace_attach ok" in h["ptrace"]]
    opened = [h for h in hits if "open_mem ok" in h["mem"]]
    if attached and init and any(h["pid"] == provider for h in attached):
        verdict = "SURVIVED"
        note = "host won PTRACE_ATTACH of the provider before or without init"
    elif opened and provider and any(h["pid"] == provider for h in opened):
        verdict = "SURVIVED"
        note = "host opened /proc/<provider>/mem during the pre-exec window"
    elif init is None:
        verdict = "CAUGHT"
        note = "race attach made launch refuse, or start failed"
    else:
        verdict = "CAUGHT"
        note = f"start ok; {len(hits)} probes, {len(attached)} attaches, {len(opened)} mem opens"
    return {
        "id": "race-before-dumpable",
        "verdict": verdict,
        "started": init is not None,
        "init": init,
        "provider": provider,
        "hits": hits,
        "lines": lines,
        "err": err,
        "note": note,
    }


def hunt_bind_mount(bins, tmp):
    storage = tmp / "bind"
    storage.mkdir()
    granted = tmp / "bind-granted"
    shutil.copy2(bins["hunter"], granted)
    granted.chmod(0o755)
    proc = start_launch(str(granted), [], storage)
    init, lines, err = read_started(proc)
    mount_err = None
    mounted = False
    if init is not None:
        try:
            sh(["mount", "--bind", bins["payload"], str(granted)])
            mounted = True
        except subprocess.CalledProcessError as exc:
            mount_err = exc.returncode
    stop(proc)
    if not mounted:
        verdict = "NOT RUN"
        note = f"host bind-mount exit={mount_err} (this uid)"
    else:
        verdict = "UNKNOWN"
        note = "bind-mount succeeded; not a ptrace claim"
        try:
            sh(["umount", str(granted)])
        except subprocess.CalledProcessError:
            pass
    return {
        "id": "bind-mount",
        "verdict": verdict,
        "started": init is not None,
        "init": init,
        "err": err,
        "lines": lines,
        "note": note,
        "mounted": mounted,
    }


def hunt_false_fail(bins, tmp):
    """Cases that look like a fail but are not a C0 hole."""
    proc, init, provider, lines, err = start_ready(bins, tmp, "false-fail")
    init_owner = host_run(bins, "dumpable_owner", init) if init else {}
    provider_owner = host_run(bins, "dumpable_owner", provider) if provider else {}
    stop(proc)
    return {
        "id": "false-fail-init-dumpable",
        "verdict": "FALSE-FAIL-IF-REQUIRED",
        "started": init is not None,
        "init": init,
        "provider": provider,
        "init_owner": init_owner.get("out"),
        "provider_owner": provider_owner.get("out"),
        "lines": lines,
        "err": err,
        "note": (
            "Init is dumpable on purpose so the parent can read "
            "/proc/<init>/task/init/children. Requiring init /proc/mem "
            "EACCES would false-FAIL the current identity check."
        ),
    }


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    bins = build_standins()
    tmp = Path(tempfile.mkdtemp(prefix="fcl-r7-"))
    rows = []
    try:
        rows.extend(hunt_inside(bins, tmp))
        rows.append(
            hunt_host_pair(
                bins,
                tmp,
                "host-process_vm-provider",
                "process_vm_read",
                "provider",
                "same-uid process_vm_readv of the provider",
            )
        )
        rows.append(
            hunt_host_pair(
                bins,
                tmp,
                "host-process_vm-write-provider",
                "process_vm_write",
                "provider",
                "same-uid process_vm_writev of the provider",
            )
        )
        rows.append(
            hunt_host_pair(
                bins,
                tmp,
                "host-process_vm-init",
                "process_vm_read",
                "init",
                "same-uid process_vm_readv of init",
            )
        )
        rows.append(
            hunt_host_pair(
                bins,
                tmp,
                "host-pidfd-provider",
                "pidfd_getfd",
                "provider",
                "same-uid pidfd_getfd of the provider",
            )
        )
        rows.append(
            hunt_host_pair(
                bins,
                tmp,
                "host-pidfd-init",
                "pidfd_getfd",
                "init",
                "same-uid pidfd_getfd of init",
            )
        )
        rows.append(
            hunt_host_pair(
                bins,
                tmp,
                "host-ptrace-provider",
                "ptrace",
                "provider",
                "same-uid PTRACE_ATTACH of the provider",
            )
        )
        rows.append(
            hunt_host_pair(
                bins,
                tmp,
                "host-ptrace-init",
                "ptrace",
                "init",
                "same-uid PTRACE_ATTACH of init (claimed EPERM)",
            )
        )
        rows.append(
            hunt_host_pair(
                bins,
                tmp,
                "host-perf-provider",
                "perf",
                "provider",
                "same-uid perf_event_open of the provider",
            )
        )
        rows.append(hunt_proc_files(bins, tmp, "provider"))
        rows.append(hunt_proc_files(bins, tmp, "init"))
        rows.append(hunt_kill_init(bins, tmp))
        rows.append(hunt_signal_init(bins, tmp))
        rows.append(hunt_core(bins, tmp))
        rows.append(hunt_confuse(bins, tmp))
        rows.append(hunt_race(bins, tmp))
        rows.append(hunt_bind_mount(bins, tmp))
        rows.append(hunt_false_fail(bins, tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "attacks.json").write_text(json.dumps(rows, indent=2) + "\n")
    lines = [
        f"head={HEAD}",
        f"launcher={LAUNCHER}",
        f"yama={Path('/proc/sys/kernel/yama/ptrace_scope').read_text().strip() if Path('/proc/sys/kernel/yama/ptrace_scope').exists() else 'missing'}",
        "",
    ]
    for row in rows:
        lines.append(f"{row['id']:32} {row['verdict']:16} {row.get('note', '')}")
        print(f"{row['id']:32} {row['verdict']:16} {row.get('note', '')}")
    (EVIDENCE / "attacks.stdout.txt").write_text("\n".join(lines) + "\n")
    survivors = [r for r in rows if r["verdict"] == "SURVIVED"]
    print(f"\nsurvivors={len(survivors)} of {len(rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
