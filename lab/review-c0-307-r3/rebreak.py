#!/usr/bin/env python3
"""Re-break each claimed fix. Copies the #307 crate; does not touch its branch.

Official plants F25, F27, F28, F29, F31, F32 plus new r3 plants.
Writes evidence/rebreak.json.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REVIEW = Path(__file__).resolve().parent
EVIDENCE = REVIEW / "evidence"
SRC = Path(
    os.environ.get("FCL_SRC", "/tmp/review-c0-307-r3-src/lab/fail-closed-linux")
)
WORK = Path(os.environ.get("FCL_REBREAK", "/tmp/review-c0-307-r3-rebreak"))
MUTANTS = SRC / "mutants"

OFFICIAL = [
    "F25-empty-pipe-reported-as-start",
    "F27-helper-survives-as-returned-pid",
    "F28-first-child-exit-tears-down",
    "F29-init-does-not-reap-all",
    "F31-lying-abi-probe-skipped",
    "F32-ioctl-dev-dropped-from-handled",
]


def parse_plant(path: Path) -> dict:
    header = {"tests": []}
    old, new, section = [], [], "header"
    for line in path.read_text().splitlines():
        if section == "header":
            if line == "--- old":
                section = "old"
            elif line.strip():
                key, _, value = line.partition(": ")
                if key == "test":
                    header["tests"].append(value.strip())
                else:
                    header[key] = value.strip()
        elif section == "old":
            if line == "--- new":
                section = "new"
            else:
                old.append(line)
        elif section == "new":
            if line == "--- end":
                section = "end"
            else:
                new.append(line)
    return {
        "id": header["id"],
        "file": header["file"],
        "tests": header["tests"],
        "old": "\n".join(old),
        "new": "\n".join(new),
    }


NEW_PLANTS = [
    {
        "id": "R3-close-without-execve",
        "file": "src/real.rs",
        "tests": [],
        "old": """        unsafe {
            libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0,
                0,
                0,
            )
        };
        Ok(())
""",
        "new": """        unsafe {
            libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0,
                0,
                0,
            )
        };
        close_fault_write(self);
        loop {
            unsafe { libc::pause() };
        }
""",
        "kind": "live-start-without-execve",
    },
    {
        "id": "R3-close-pipe-before-confine",
        "file": "src/real.rs",
        "tests": [],
        "old": """            if plan.test_empty_pipe {
                unsafe { libc::_exit(REFUSAL_EXIT_CODE) };
            }
""",
        "new": """            close_fault_write(&mut RealKernel {
                fault_write,
                lie_rights: false,
            });
            if plan.test_empty_pipe {
                unsafe { libc::_exit(REFUSAL_EXIT_CODE) };
            }
""",
        "kind": "live-early-eof",
    },
    {
        "id": "R3-grandchild-holds-pipe",
        "file": "src/real.rs",
        "tests": [],
        "old": """        unsafe {
            libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0,
                0,
                0,
            )
        };
        Ok(())
""",
        "new": """        unsafe {
            libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0,
                0,
                0,
            )
        };
        let hold = unsafe { libc::fork() };
        if hold == 0 {
            loop {
                unsafe { libc::pause() };
            }
        }
        Ok(())
""",
        "kind": "live-held-write-end",
    },
]


def cargo(crate: Path, args: list[str], env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["cargo", *args],
        cwd=crate,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )


def apply_text(crate: Path, rel: str, old: str, new: str) -> str:
    path = crate / rel
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        return f"old text occurs {count} times"
    path.write_text(text.replace(old, new, 1))
    return "applied"


def run_official(plant_id: str) -> dict:
    plant = parse_plant(MUTANTS / f"{plant_id}.txt")
    base = WORK / plant_id
    shutil.rmtree(base, ignore_errors=True)
    crate = base / "crate"
    shutil.copytree(SRC, crate, ignore=shutil.ignore_patterns("target", "__pycache__"))
    err = apply_text(crate, plant["file"], plant["old"], plant["new"])
    if err != "applied":
        return {"id": plant_id, "verdict": "ERROR", "detail": err}
    env = dict(
        os.environ,
        CARGO_TARGET_DIR=str(base / "target"),
        CARGO_BUILD_BUILD_DIR=str(base / "build"),
        RUST_TEST_THREADS="2",
        CARGO_INCREMENTAL="0",
    )
    results = {}
    groups = {}
    for test in plant["tests"]:
        target, name = test.split("::", 1)
        groups.setdefault(target, []).append(name)
    for target, names in groups.items():
        selector = ["--lib"] if target == "lib" else ["--test", target]
        run = cargo(crate, ["test", "--locked", *selector, "--", "--exact", *names], env)
        (base / f"{target}.log").write_text(run.stdout + "\n" + run.stderr)
        for name in names:
            if f"test {name} ... FAILED" in run.stdout:
                results[f"{target}::{name}"] = "FAILED"
            elif f"test {name} ... ok" in run.stdout:
                results[f"{target}::{name}"] = "ok"
            else:
                results[f"{target}::{name}"] = "missing"
    caught = all(v == "FAILED" for v in results.values()) and results
    return {
        "id": plant_id,
        "verdict": "CAUGHT" if caught else "MISSED",
        "results": results,
    }


def build_mutant(plant: dict) -> dict:
    base = WORK / plant["id"]
    shutil.rmtree(base, ignore_errors=True)
    crate = base / "crate"
    shutil.copytree(SRC, crate, ignore=shutil.ignore_patterns("target", "__pycache__"))
    err = apply_text(crate, plant["file"], plant["old"], plant["new"])
    if err != "applied":
        return {"id": plant["id"], "verdict": "ERROR", "detail": err}
    env = dict(
        os.environ,
        CARGO_TARGET_DIR=str(base / "target"),
        CARGO_BUILD_BUILD_DIR=str(base / "build"),
        RUST_TEST_THREADS="2",
        CARGO_INCREMENTAL="0",
    )
    run = cargo(crate, ["build", "--locked", "--bin", "fcl-launch"], env)
    (base / "build.log").write_text(run.stdout + "\n" + run.stderr)
    if run.returncode != 0:
        return {
            "id": plant["id"],
            "verdict": "ERROR",
            "detail": "build failed",
            "log_tail": (run.stdout + run.stderr)[-2000:],
        }
    launch = base / "target" / "debug" / "fcl-launch"
    if not launch.is_file():
        # cargo may put it under CARGO_BUILD_BUILD_DIR
        found = list(base.rglob("fcl-launch"))
        if found:
            launch = found[0]
    return {
        "id": plant["id"],
        "verdict": "BUILT",
        "kind": plant["kind"],
        "launch": str(launch),
    }


def live_close_without_execve(launch: Path) -> dict:
    import signal
    import tempfile
    import time

    work = Path(tempfile.mkdtemp(prefix="r3-rb-"))
    storage = work / "storage"
    storage.mkdir()
    probe = Path(
        os.environ.get(
            "FCL_PROBE",
            "/tmp/review-c0-307-r3-src/lab/fail-closed-linux/target/build/debug/build/fail-closed-linux-1d11d7b03d991c2d/out/fcl-probe",
        )
    )
    cmd = [
        str(launch),
        "--provider",
        "did-provider",
        "--storage-root",
        str(storage),
        "--",
        str(probe),
        "did-provider",
        str(storage),
        str(work / "nope"),
        str(work),
    ]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    time.sleep(0.4)
    stdout = b""
    if proc.stdout:
        import select as sel

        if sel.select([proc.stdout], [], [], 0.2)[0]:
            stdout = os.read(proc.stdout.fileno(), 4096)
    line = stdout.decode("utf-8", "replace")
    started = "started did-provider pid=" in line
    pid = None
    if started:
        for part in line.splitlines():
            if part.startswith("started did-provider pid="):
                pid = int(part.split("=", 1)[1])
    comm = None
    marker = (storage / "probe-ran").exists()
    if pid:
        try:
            comm = Path(f"/proc/{pid}/comm").read_text().strip()
            kids = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
        except FileNotFoundError:
            kids = []
    else:
        kids = []
    if proc.poll() is None:
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=2)
    shutil.rmtree(work, ignore_errors=True)
    return {
        "started": started,
        "returned_pid": pid,
        "init_comm": comm,
        "marker_written": marker,
        "children": kids,
        "stdout": line,
        "fake_start_without_execve": started and not marker,
    }


def live_held_pipe(launch: Path, kill_init: bool) -> dict:
    import select as sel
    import signal
    import tempfile
    import time

    work = Path(tempfile.mkdtemp(prefix="r3-hold-"))
    storage = work / "storage"
    storage.mkdir()
    probe = Path(
        os.environ.get(
            "FCL_PROBE",
            "/tmp/review-c0-307-r3-src/lab/fail-closed-linux/target/build/debug/build/fail-closed-linux-1d11d7b03d991c2d/out/fcl-probe",
        )
    )
    cmd = [
        str(launch),
        "--provider",
        "did-provider",
        "--storage-root",
        str(storage),
        "--",
        str(probe),
        "did-provider",
        str(storage),
        str(work / "nope"),
        str(work),
    ]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    time.sleep(0.6)
    hanging = proc.poll() is None
    stdout = b""
    if proc.stdout and sel.select([proc.stdout], [], [], 0.1)[0]:
        stdout = os.read(proc.stdout.fileno(), 4096)
    started_already = b"started " in stdout
    init = None
    # The parent is blocked on the fault pipe. Init should still be a child.
    children = []
    try:
        children = Path(f"/proc/{proc.pid}/task/{proc.pid}/children").read_text().split()
    except FileNotFoundError:
        pass
    if children and kill_init:
        init = int(children[0])
        os.kill(init, signal.SIGKILL)
        try:
            code = proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = proc.wait(timeout=2)
            hanging_after = True
        else:
            hanging_after = False
        stderr = proc.stderr.read() if proc.stderr else b""
        result = {
            "launch_blocked_before_kill": hanging and not started_already,
            "init": init,
            "launcher_exit": code,
            "hanging_after_kill": hanging_after,
            "stdout": stdout.decode("utf-8", "replace"),
            "stderr": stderr.decode("utf-8", "replace"),
            "refused_after_init_kill": code == 71,
        }
    else:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)
        result = {
            "launch_blocked": hanging and not started_already,
            "started_already": started_already,
            "stdout": stdout.decode("utf-8", "replace"),
            "children": children,
        }
    shutil.rmtree(work, ignore_errors=True)
    return result


def silent_ignore_sim() -> dict:
    """A kernel that accepts every bit still launches. The probe only sees EINVAL."""
    crate = SRC
    env = dict(
        os.environ,
        CARGO_TARGET_DIR=str(SRC / "target"),
        CARGO_BUILD_BUILD_DIR=str(SRC / "target" / "build"),
        RUST_TEST_THREADS="2",
    )
    # The lying-ABI row is the inverse: accept ABI 1 bits while reporting 5.
    # Silent-ignore is: report ABI 5, accept every bit, never enforce.
    # SimKernel has no ioctl enforcement after launch, so accepted_fs=None
    # (full ABI bits) already launches. Prove it with the existing positive test.
    run = cargo(
        crate,
        [
            "test",
            "--locked",
            "--test",
            "simulated",
            "--",
            "--exact",
            "sim_confined_provider_starts_after_every_layer",
        ],
        env,
    )
    return {
        "note": (
            "landlock_can_handle_fs is create_ruleset-only. "
            "SimKernel never checks ioctl after a successful probe. "
            "A kernel that accepts the bit and does not enforce it launches."
        ),
        "positive_sim_still_passes": "test sim_confined_provider_starts_after_every_layer ... ok"
        in run.stdout,
        "probe_cannot_see_silent_ignore": True,
    }


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    report = {"official": [], "new": [], "silent_ignore": silent_ignore_sim()}
    for plant_id in OFFICIAL:
        print(f"rebreak {plant_id}...", flush=True)
        report["official"].append(run_official(plant_id))
    for plant in NEW_PLANTS:
        print(f"build {plant['id']}...", flush=True)
        built = build_mutant(plant)
        if built.get("verdict") == "BUILT":
            launch = Path(built["launch"])
            if plant["kind"] == "live-start-without-execve":
                built["live"] = live_close_without_execve(launch)
            elif plant["kind"] == "live-early-eof":
                built["live"] = live_close_without_execve(launch)
            elif plant["kind"] == "live-held-write-end":
                built["live_hold"] = live_held_pipe(launch, kill_init=False)
                built["live_kill_init"] = live_held_pipe(launch, kill_init=True)
        report["new"].append(built)
    path = EVIDENCE / "rebreak.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
