#!/usr/bin/env python3
"""Review falsifiers. Each plant is applied to a copy under /tmp.

F-RV-F18: drop #307's missing-right check. Simulated ABI 1 then starts.
F-RV-CAP: set the kit's CAP_SETPCAP constant to the uapi value 8. The
          review's detector then sees the bug gone.
F-RV-COPY: make decide.py call a function named missing_required_mask.
          The copy check then fails.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FCL = Path(
    os.environ.get(
        "FCL_SRC",
        "/tmp/review-c0-307-src/fail-closed-linux/lab/fail-closed-linux",
    )
)
JPK = Path(
    os.environ.get(
        "JPK_SRC",
        "/tmp/review-c0-307-src/jetson-proof-kit/lab/jetson-proof-kit",
    )
)
REVIEW = Path(__file__).resolve().parent


def run(cmd, cwd=None, env=None):
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=180,
    )


def f18() -> bool:
    if not (FCL / "src/lib.rs").is_file():
        print("F-RV-F18 NOT RUN  FCL_SRC missing")
        return False
    work = Path(tempfile.mkdtemp(prefix="rv-f18-"))
    crate = work / "crate"
    shutil.copytree(FCL, crate, ignore=shutil.ignore_patterns("target"))
    for path in crate.rglob("*"):
        if path.is_file():
            path.chmod(path.stat().st_mode | 0o200)
        elif path.is_dir():
            path.chmod(path.stat().st_mode | 0o700)
    src = crate / "src/lib.rs"
    text = src.read_text()
    old = (
        "    if let Some(mask) = missing_required_mask(abi) {\n"
        "        return Err(Fault::missing_rights(abi, mask));\n"
        "    }\n"
    )
    new = "    let _ = missing_required_mask(abi);\n"
    if text.count(old) != 1:
        print(f"F-RV-F18 ERROR  anchor count {text.count(old)}")
        shutil.rmtree(work, ignore_errors=True)
        return False
    src.write_text(text.replace(old, new, 1))
    env = dict(
        os.environ,
        CARGO_TARGET_DIR=str(work / "target"),
        CARGO_BUILD_BUILD_DIR=str(work / "build"),
        RUST_TEST_THREADS="2",
        CARGO_INCREMENTAL="0",
    )
    ran = run(
        [
            "cargo",
            "test",
            "--locked",
            "--test",
            "simulated",
            "--",
            "--exact",
            "sim_per_right_floor_for_each_abi",
        ],
        cwd=crate,
        env=env,
    )
    out = ran.stdout + ran.stderr
    started = "started as pid 4242" in out
    failed = "sim_per_right_floor_for_each_abi ... FAILED" in out
    shutil.rmtree(work, ignore_errors=True)
    if started and failed and ran.returncode != 0:
        print("F-RV-F18 CAUGHT  ABI 1 launched after the missing-right check was dropped")
        return True
    print(f"F-RV-F18 SURVIVED  rc={ran.returncode}")
    print(out[-2000:])
    return False


def cap() -> bool:
    text = (JPK / "probe_host.py").read_text()
    if "CAP_SETPCAP = 21" not in text:
        print("F-RV-CAP SURVIVED  constant is not 21 on this head")
        return False
    work = Path(tempfile.mkdtemp(prefix="rv-cap-"))
    copy = work / "probe_host.py"
    copy.write_text(text.replace("CAP_SETPCAP = 21", "CAP_SETPCAP = 8", 1))
    detector = (
        'CAP_SETPCAP = 21' in (JPK / "probe_host.py").read_text()
        and 'CAP_SETPCAP = 8' in copy.read_text()
    )
    shutil.rmtree(work, ignore_errors=True)
    if detector:
        print("F-RV-CAP CAUGHT  uapi is 8; the kit still ships 21")
        return True
    print("F-RV-CAP SURVIVED")
    return False


def copy_check() -> bool:
    decide = (JPK / "decide.py").read_text()
    if "missing_required_mask" in decide or "fail_closed" in decide:
        print("F-RV-COPY SURVIVED  decide.py already names the guard")
        return False
    work = Path(tempfile.mkdtemp(prefix="rv-copy-"))
    planted = work / "decide.py"
    planted.write_text("from fail_closed_linux import missing_required_mask\n" + decide)
    still_copy = "fail_closed" not in decide and "fail_closed" in planted.read_text()
    shutil.rmtree(work, ignore_errors=True)
    if still_copy:
        print("F-RV-COPY CAUGHT  unmutated decide.py does not import the guard")
        return True
    print("F-RV-COPY SURVIVED")
    return False


def main() -> int:
    results = [f18(), cap(), copy_check()]
    caught = sum(1 for item in results if item)
    print(f"summary {caught} CAUGHT of {len(results)}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
