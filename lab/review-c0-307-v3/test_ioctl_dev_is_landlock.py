#!/usr/bin/env python3
"""Standalone failing test for #307 fix 4 (probe ioctl is a Landlock denial).

#338 asked the probe to call a device ioctl and show it denied. On
1894f432 the probe does call FIONREAD on an inherited /dev/null
descriptor, and real_confined_provider_has_every_layer accepts any
`ioctl_dev errno=` line.

Landlock attaches IOCTL_DEV at open time (Linux 6.12 fs.c
hook_file_ioctl). The fixture opens /dev/null in the unconfined test
process, so the later domain does not apply to that file. FIONREAD on
/dev/null is ENOTTY (25) with no Landlock at all. A confined run that
prints the same errno has not measured ACCESS_FS_IOCTL_DEV.

This file fails unless the confined probe reports EACCES (13) and that
errno differs from the unconfined result.

usage: python3 -I test_ioctl_dev_is_landlock.py
env:   FCL_SRC  crate root (default /tmp/review-c0-307-v3-src/lab/fail-closed-linux)
       FCL_LAUNCH / FCL_PROBE  explicit binaries
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

LANE = Path(__file__).resolve().parent
FCL_SRC = Path(
    os.environ.get("FCL_SRC", "/tmp/review-c0-307-v3-src/lab/fail-closed-linux")
).resolve()
EACCES = 13
ENOTTY = 25
FIONREAD = 0x541B


def die(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def unconfined_fionread(path: str) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    fd = os.open(path, os.O_RDONLY)
    try:
        avail = ctypes.c_int(0)
        ctypes.set_errno(0)
        ret = libc.ioctl(fd, FIONREAD, ctypes.byref(avail))
        err = ctypes.get_errno()
        if ret == 0:
            return 0
        return err
    finally:
        os.close(fd)


def find_one(root: Path, name: str) -> Path | None:
    matches = sorted(
        path
        for path in root.rglob(name)
        if path.is_file() and os.access(path, os.X_OK)
    )
    return matches[0] if matches else None


def binaries() -> tuple[Path, Path]:
    launch = os.environ.get("FCL_LAUNCH")
    probe = os.environ.get("FCL_PROBE")
    launch_path = Path(launch) if launch else find_one(FCL_SRC / "target", "fcl-launch")
    probe_path = Path(probe) if probe else find_one(FCL_SRC / "target", "fcl-probe")
    if launch_path is None or not launch_path.is_file():
        die(f"NOT RUN: no fcl-launch under {FCL_SRC}/target (set FCL_LAUNCH)")
    if probe_path is None or not probe_path.is_file():
        die(f"NOT RUN: no fcl-probe under {FCL_SRC}/target (set FCL_PROBE)")
    mode = stat.S_IMODE(probe_path.stat().st_mode)
    if mode & 0o111 == 0:
        die(f"NOT RUN: probe is not executable: {probe_path}")
    return launch_path, probe_path


def confined_ioctl_errno(launch: Path, probe: Path) -> tuple[int | None, str]:
    with tempfile.TemporaryDirectory(prefix="review-c0-307-v3-ioctl-") as tmp:
        tmp_path = Path(tmp)
        storage = tmp_path / "storage"
        outside = tmp_path / "outside"
        storage.mkdir()
        outside.mkdir()
        secret = outside / "secret.txt"
        secret.write_bytes(b"outside the storage root")
        fd = os.open("/dev/null", os.O_RDONLY)
        try:
            flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            fcntl.fcntl(fd, fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)
            run = subprocess.run(
                [
                    str(launch),
                    "--provider",
                    "model-provider",
                    "--storage-root",
                    str(storage),
                    "--",
                    str(probe),
                    "model-provider",
                    str(storage),
                    str(secret),
                    str(outside),
                    "--device-fd",
                    str(fd),
                    "--exit",
                    "0",
                ],
                check=False,
                capture_output=True,
                text=True,
                close_fds=False,
            )
        finally:
            os.close(fd)
    stdout = run.stdout
    if run.returncode != 0:
        die(
            "NOT RUN: confined launch did not start the probe "
            f"(exit {run.returncode})\n{run.stderr}"
        )
    line = next(
        (row for row in stdout.splitlines() if row.startswith("ioctl_dev ")),
        None,
    )
    if line is None:
        die(f"NOT RUN: probe printed no ioctl_dev line\n{stdout}")
    if line == "ioctl_dev ok":
        return 0, stdout
    prefix = "ioctl_dev errno="
    if not line.startswith(prefix):
        die(f"NOT RUN: bad ioctl_dev line {line!r}")
    return int(line[len(prefix) :]), stdout


def main() -> None:
    if os.uname().sysname != "Linux":
        die("NOT RUN: Linux host required")
    host = unconfined_fionread("/dev/null")
    print(f"unconfined FIONREAD /dev/null errno={host} ({errno.errorcode.get(host, 'ok')})")
    if host != ENOTTY:
        print(
            f"note: this host's unconfined /dev/null FIONREAD is {host}, not ENOTTY; "
            "the Landlock check below still requires EACCES",
            file=sys.stderr,
        )

    launch, probe = binaries()
    print(f"launch {launch}")
    print(f"probe  {probe}")
    confined, stdout = confined_ioctl_errno(launch, probe)
    print(f"confined ioctl_dev errno={confined}")
    trunc = next(
        (row for row in stdout.splitlines() if row.startswith("truncate_outside ")),
        "missing",
    )
    print(f"confined {trunc}")

    if confined == host:
        die(
            f"confined ioctl_dev errno={confined} matches unconfined FIONREAD "
            f"({errno.errorcode.get(host, '?')}). Landlock IOCTL_DEV was not "
            "measured: the fd was opened before restrict_self, and the test "
            "accepts any errno=. Need EACCES (13) on a device opened after "
            "the domain, or on a path granted read without IOCTL_DEV."
        )
    if confined != EACCES:
        die(
            f"confined ioctl_dev errno={confined} "
            f"({errno.errorcode.get(confined or 0, 'ok')}) is not EACCES (13). "
            "A Landlock IOCTL_DEV denial is EACCES."
        )
    print("ioctl_dev is a Landlock EACCES denial (distinct from unconfined)")
    sys.exit(0)


if __name__ == "__main__":
    main()
