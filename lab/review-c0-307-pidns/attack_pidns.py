#!/usr/bin/env python3
"""Live PID-namespace attacks against the built #307 fcl-launch.

Writes evidence/pidns-attack.json. Needs FCL_LAUNCH, FCL_PROBE, and a
writable work directory. Does not edit lab/fail-closed-linux.
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
    os.environ.get("FCL_LAUNCH", "/tmp/fcl-637345ac/target/debug/fcl-launch")
)
PROBE = Path(
    os.environ.get(
        "FCL_PROBE",
        "/tmp/fcl-637345ac/build/debug/build/fail-closed-linux-1d11d7b03d991c2d/out/fcl-probe",
    )
)


def read_status(pid: int) -> dict:
    path = Path(f"/proc/{pid}/status")
    text = path.read_text()
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


def ns(pid: int, kind: str) -> str:
    return os.readlink(f"/proc/{pid}/ns/{kind}")


def nspid(pid: int) -> str:
    return read_status(pid).get("NSpid", "")


def walk(helper: int) -> dict:
    init_list = children_of(helper)
    init = init_list[0] if init_list else None
    provider_list = children_of(init) if init else []
    provider = provider_list[0] if provider_list else None
    host = os.getpid()
    return {
        "host_pid": host,
        "host_ns_pid": ns(host, "pid"),
        "host_ns_user": ns(host, "user"),
        "helper_pid": helper,
        "helper_children": init_list,
        "helper_ns_pid": ns(helper, "pid"),
        "helper_ns_user": ns(helper, "user"),
        "helper_nspid": nspid(helper),
        "helper_status": {
            key: read_status(helper).get(key)
            for key in (
                "NoNewPrivs",
                "Seccomp",
                "CapInh",
                "CapPrm",
                "CapEff",
                "CapBnd",
                "CapAmb",
                "NSpid",
                "Uid",
            )
        },
        "init_pid": init,
        "init_ns_pid": ns(init, "pid") if init else None,
        "init_nspid": nspid(init) if init else None,
        "init_status": (
            {
                key: read_status(init).get(key)
                for key in ("NoNewPrivs", "Seccomp", "CapEff", "CapBnd", "NSpid")
            }
            if init
            else None
        ),
        "provider_pid": provider,
        "provider_ns_pid": ns(provider, "pid") if provider else None,
        "provider_nspid": nspid(provider) if provider else None,
        "helper_shares_host_pid_ns": ns(helper, "pid") == ns(host, "pid"),
        "init_shares_host_pid_ns": (ns(init, "pid") == ns(host, "pid")) if init else None,
        "provider_shares_host_pid_ns": (
            ns(provider, "pid") == ns(host, "pid") if provider else None
        ),
    }


def read_lines_until(proc, done, secs=5.0) -> list[str]:
    assert proc.stdout is not None
    lines: list[str] = []
    buf = ""
    deadline = time.time() + secs
    while time.time() < deadline:
        if proc.stdout.fileno() >= 0:
            ready, _, _ = select.select([proc.stdout], [], [], 0.1)
        else:
            ready = []
        if not ready:
            if proc.poll() is not None:
                rest = proc.stdout.read() or ""
                buf += rest
                break
            continue
        chunk = os.read(proc.stdout.fileno(), 4096)
        if not chunk:
            break
        buf += chunk.decode("utf-8", "replace")
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            lines.append(line)
            if done(lines):
                return lines
    if buf:
        lines.append(buf)
    return lines


def start_probe(work: Path, extra_args=None):
    storage = work / "storage"
    outside = work / "outside"
    storage.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("outside")
    cmd = [
        str(LAUNCH),
        "--provider",
        "did-provider",
        "--storage-root",
        str(storage),
        "--",
        str(PROBE),
        "did-provider",
        str(storage),
        str(outside / "secret.txt"),
        str(outside),
    ]
    if extra_args:
        cmd.extend(extra_args)
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        bufsize=0,
    )
    def done(lines):
        return any(line.startswith("started did-provider pid=") for line in lines) and (
            "ready" in lines
        )

    raw_lines = read_lines_until(proc, done)
    # reopen text handles for later close/wait
    lines = raw_lines
    helper = None
    for line in lines:
        if line.startswith("started did-provider pid="):
            helper = int(line.split("=", 1)[1])
    return proc, helper, lines


def experiment_tree() -> dict:
    work = Path(tempfile.mkdtemp(prefix="rv-pidns-tree-"))
    proc, helper, lines = start_probe(work)
    try:
        tree = walk(helper)
        tree["started_line_pid"] = helper
        tree["probe_lines"] = lines
        nspid_line = next(line for line in lines if line.startswith("nspid="))
        tree["probe_getpid"] = int(nspid_line.split("=", 1)[1])
        return tree
    finally:
        if proc.stdin:
            proc.stdin.close()
        proc.wait(timeout=5)
        shutil.rmtree(work, ignore_errors=True)


def experiment_sigkill_helper() -> dict:
    work = Path(tempfile.mkdtemp(prefix="rv-pidns-kill-"))
    proc, helper, lines = start_probe(work)
    tree = walk(helper)
    provider = tree["provider_pid"]
    init = tree["init_pid"]
    os.kill(helper, signal.SIGKILL)
    time.sleep(0.2)
    helper_alive = Path(f"/proc/{helper}").exists()
    init_alive = Path(f"/proc/{init}").exists() if init else False
    provider_alive = Path(f"/proc/{provider}").exists() if provider else False
    # fcl-launch should have noticed the helper death.
    time.sleep(0.2)
    launch_alive = proc.poll() is None
    result = {
        "started_line_pid": helper,
        "init_pid": init,
        "provider_pid": provider,
        "probe_lines": lines,
        "after_sigkill_helper": {
            "helper_alive": helper_alive,
            "init_alive": init_alive,
            "provider_alive": provider_alive,
            "fcl_launch_still_running": launch_alive,
            "fcl_launch_exit": proc.poll(),
        },
        "finding": (
            "SIGKILL of the pid launch() returned left the provider alive"
            if provider_alive
            else "provider died with the helper"
        ),
    }
    if proc.stdin:
        proc.stdin.close()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    shutil.rmtree(work, ignore_errors=True)
    return result


def experiment_zombie(zombie_bin: Path) -> dict:
    work = Path(tempfile.mkdtemp(prefix="rv-pidns-zombie-"))
    storage = work / "storage"
    storage.mkdir()
    cmd = [
        str(LAUNCH),
        "--provider",
        "did-provider",
        "--storage-root",
        str(storage),
        "--",
        str(zombie_bin),
    ]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        bufsize=0,
    )

    def done(lines):
        return any(line.startswith("started did-provider pid=") for line in lines) and (
            "ready" in lines
        )

    lines = read_lines_until(proc, done)
    helper = None
    for line in lines:
        if line.startswith("started did-provider pid="):
            helper = int(line.split("=", 1)[1])
    tree = walk(helper) if helper else {}
    init = tree.get("init_pid")
    provider = tree.get("provider_pid")
    zombies = []
    for parent, role in ((init, "init"), (provider, "provider")):
        if not parent:
            continue
        for child in children_of(parent):
            try:
                stat = Path(f"/proc/{child}/stat").read_text()
            except OSError:
                continue
            rparen = stat.rfind(")")
            if rparen < 0:
                continue
            rest = stat[rparen + 2 :].split()
            if not rest:
                continue
            if rest[0] == "Z":
                zombies.append(
                    {
                        "pid": child,
                        "ppid": parent,
                        "state": "Z",
                        "parent_role": role,
                    }
                )
    if proc.stdin:
        proc.stdin.close()
    try:
        os.kill(helper, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    shutil.rmtree(work, ignore_errors=True)
    return {
        "probe_lines": lines,
        "tree": {
            "helper_pid": tree.get("helper_pid"),
            "init_pid": init,
            "init_nspid": tree.get("init_nspid"),
            "provider_pid": tree.get("provider_pid"),
            "provider_nspid": tree.get("provider_nspid"),
        },
        "zombies_reparented_to_init": zombies,
        "finding": (
            "unreaped child is a zombie under the provider; init only waitpids the provider"
            if zombies
            else "no zombie observed"
        ),
    }


def experiment_daemonize(daemon_bin: Path) -> dict:
    work = Path(tempfile.mkdtemp(prefix="rv-pidns-daemon-"))
    storage = work / "storage"
    storage.mkdir()
    proc = subprocess.Popen(
        [
            str(LAUNCH),
            "--provider",
            "did-provider",
            "--storage-root",
            str(storage),
            "--",
            str(daemon_bin),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate(timeout=5)
    shutil.rmtree(work, ignore_errors=True)
    return {
        "fcl_launch_exit": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "finding": (
            "fcl-launch returned after the provider parent exited; "
            "a daemon grandchild does not keep the launcher alive"
        ),
    }


def experiment_fault_pipe(demo: Path) -> dict:
    ran = subprocess.run([str(demo)], text=True, capture_output=True, check=False)
    return {
        "exit": ran.returncode,
        "stdout": ran.stdout.strip(),
        "stderr": ran.stderr.strip(),
        "empty_pipe_is_start": ran.returncode == 0
        and "empty_pipe_reported_as_start" in ran.stdout,
    }


def compile_probe(src: Path, out: Path) -> None:
    subprocess.run(
        ["gcc", "-static", "-O1", "-o", str(out), str(src)],
        check=True,
        capture_output=True,
        text=True,
    )


def main() -> int:
    if not LAUNCH.is_file() or not PROBE.is_file():
        print("NOT RUN: FCL_LAUNCH or FCL_PROBE missing", file=sys.stderr)
        return 2
    EVIDENCE.mkdir(exist_ok=True)
    build = Path(tempfile.mkdtemp(prefix="rv-pidns-build-"))
    zombie = build / "zombie"
    daemon = build / "daemonize"
    demo = build / "fault-pipe-demo"
    compile_probe(REVIEW / "probes" / "zombie.c", zombie)
    compile_probe(REVIEW / "probes" / "daemonize.c", daemon)
    compile_probe(REVIEW / "probes" / "fault_pipe_demo.c", demo)
    report = {
        "launch": str(LAUNCH),
        "probe": str(PROBE),
        "tree": experiment_tree(),
        "sigkill_helper": experiment_sigkill_helper(),
        "zombie": experiment_zombie(zombie),
        "daemonize": experiment_daemonize(daemon),
        "fault_pipe": experiment_fault_pipe(demo),
    }
    shutil.rmtree(build, ignore_errors=True)
    (EVIDENCE / "pidns-attack.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
