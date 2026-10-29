"""Probe one-byte writes to /dev/null, /dev/zero, and /dev/random.

Grade row 12 rests on the wallet, did, and model seatbelt profiles. A read
grant does not grant these writes. This module compiles one helper and runs
it under each live ``confine.sb``. Confined launches go through ``sbx.run``
only. The helper prints one line and returns 0. It writes one byte and
closes that descriptor before the next open. It does not read.

A deny is exit 0, empty stderr, and stdout ``nullw fd=-1 n=-1 errno=1 zerow
fd=-1 n=-1 errno=1 randw fd=-1 n=-1 errno=1 nullrw fd=-1 n=-1 errno=1 zerorw
fd=-1 n=-1 errno=1``. An allow is exit 0, empty stderr, every triple either
``fd=-1 n=-1 errno=1`` or ``fd=3 n=1 errno=0``, and at least one success
triple. The finding names each open that returned the success triple.

The three profiles are the live files. ``setUpModule`` records each sha256.
``tearDownModule`` calls ``changed``. An owner edit between those two points
raises ``the probe changed <rel>``. This file stores no commit, pull request,
or digest.

An allow on a real profile is CRITICAL. Wallet or did:
``findings/CRITICAL-confine-069.md``. Model:
``findings/CRITICAL-cc-model-confine-069.md``. The finding's first line
contains CRITICAL, the commit from ``last_change``, ``pr_label`` of that
commit, and the sha256 of the bytes this run read. The helper line is
``result.command``. The same paragraph is appended to ``CRITICAL.md``.
With no allow, this module writes neither file.

A recorded allow keeps the gate green. The deny test is an expected failure
and its docstring names that finding file. A later harness error still
fails. A recorded allow is not a skip. This module skips only when
``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` is missing.

``DevWriteProbe`` compiles and launches. ``DevWriteRules`` does not compile
and does not launch.
"""

import ast
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from functools import wraps
from itertools import combinations
from pathlib import Path
from unittest.mock import patch

import sbx
from test_confine_mach import (
    HarnessError as MachHarnessError,
    changed,
    last_change,
    pr_label,
    require_resolved,
    sha256_file,
)

# lab/redteam/py/<this> -> parents[3] is the repo root. Same rule as sbx.
ROOT = Path(__file__).resolve().parents[3]

CC = "/usr/bin/cc"
HELPER_TIMEOUT = 5
COMPILE_TIMEOUT = 60
SOURCE_NAME = "devwr.c"
BINARY_NAME = "devwr"
OPENS = ("nullw", "zerow", "randw", "nullrw", "zerorw")
SUCCESS = "fd=3 n=1 errno=0"
DENIED_TRIPLE = "fd=-1 n=-1 errno=1"
DENY_STDOUT = (
    "nullw fd=-1 n=-1 errno=1 zerow fd=-1 n=-1 errno=1 "
    "randw fd=-1 n=-1 errno=1 nullrw fd=-1 n=-1 errno=1 "
    "zerorw fd=-1 n=-1 errno=1\n"
)
ALL_STDOUT = (
    "nullw fd=3 n=1 errno=0 zerow fd=3 n=1 errno=0 "
    "randw fd=3 n=1 errno=0 nullrw fd=3 n=1 errno=0 "
    "zerorw fd=3 n=1 errno=0\n"
)
NULL_WRITE_STDOUT = (
    "nullw fd=3 n=1 errno=0 zerow fd=-1 n=-1 errno=1 "
    "randw fd=-1 n=-1 errno=1 nullrw fd=-1 n=-1 errno=1 "
    "zerorw fd=-1 n=-1 errno=1\n"
)
ZERO_WRITE_STDOUT = (
    "nullw fd=-1 n=-1 errno=1 zerow fd=3 n=1 errno=0 "
    "randw fd=-1 n=-1 errno=1 nullrw fd=-1 n=-1 errno=1 "
    "zerorw fd=-1 n=-1 errno=1\n"
)
RANDOM_WRITE_STDOUT = (
    "nullw fd=-1 n=-1 errno=1 zerow fd=-1 n=-1 errno=1 "
    "randw fd=3 n=1 errno=0 nullrw fd=-1 n=-1 errno=1 "
    "zerorw fd=-1 n=-1 errno=1\n"
)
NULL_RDWR_STDOUT = (
    "nullw fd=3 n=1 errno=0 zerow fd=-1 n=-1 errno=1 "
    "randw fd=-1 n=-1 errno=1 nullrw fd=3 n=1 errno=0 "
    "zerorw fd=-1 n=-1 errno=1\n"
)
ZERO_RDWR_STDOUT = (
    "nullw fd=-1 n=-1 errno=1 zerow fd=3 n=1 errno=0 "
    "randw fd=-1 n=-1 errno=1 nullrw fd=-1 n=-1 errno=1 "
    "zerorw fd=3 n=1 errno=0\n"
)
BROAD_WRITE_STDOUT = (
    "nullw fd=3 n=1 errno=0 zerow fd=3 n=1 errno=0 "
    "randw fd=3 n=1 errno=0 nullrw fd=-1 n=-1 errno=1 "
    "zerorw fd=-1 n=-1 errno=1\n"
)
DENY_DEFAULT = "(deny default)\n"
DENY_NETWORK = "(deny network*)\n"
ALLOW_NETWORK = "(allow network*)\n"
NULL_WRITE_LINE = '(allow file-write* (literal "/dev/null"))\n'
ZERO_WRITE_LINE = '(allow file-write* (literal "/dev/zero"))\n'
RANDOM_WRITE_LINE = '(allow file-write* (literal "/dev/random"))\n'
NULL_RDWR_LINE = '(allow file-read* file-write* (literal "/dev/null"))\n'
ZERO_RDWR_LINE = '(allow file-read* file-write* (literal "/dev/zero"))\n'
WRITE_DATA_NULL = '(allow file-write-data (literal "/dev/null"))\n'
WRITE_DATA_ZERO = '(allow file-write-data (literal "/dev/zero"))\n'
WRITE_DATA_RANDOM = '(allow file-write-data (literal "/dev/random"))\n'
RDWR_DATA_NULL = '(allow file-read-data file-write-data (literal "/dev/null"))\n'
RDWR_DATA_ZERO = '(allow file-read-data file-write-data (literal "/dev/zero"))\n'
READ_DATA_WRITE_NULL = '(allow file-read-data file-write* (literal "/dev/null"))\n'
READ_WRITE_DATA_NULL = '(allow file-read* file-write-data (literal "/dev/null"))\n'
BARE_WRITE = "(allow file-write*)\n"
BARE_WRITE_DATA = "(allow file-write-data)\n"


def _read_literal(node):
    return '(allow file-read* (literal "' + node + '"))\n'


READ_NULL = _read_literal("/dev/null")
READ_ZERO = _read_literal("/dev/zero")
READ_RANDOM = _read_literal("/dev/random")
READ_URANDOM = _read_literal("/dev/" + "urandom")

PLANT_ORDER = (
    "null-write",
    "zero-write",
    "random-write",
    "null-rdwr",
    "zero-rdwr",
)
PLANT_LINE = {
    "null-write": NULL_WRITE_LINE,
    "zero-write": ZERO_WRITE_LINE,
    "random-write": RANDOM_WRITE_LINE,
    "null-rdwr": NULL_RDWR_LINE,
    "zero-rdwr": ZERO_RDWR_LINE,
}
PLANT_OPENS = {
    "null-write": ("nullw",),
    "zero-write": ("zerow",),
    "random-write": ("randw",),
    "null-rdwr": ("nullw", "nullrw"),
    "zero-rdwr": ("zerow", "zerorw"),
}
PLANT_STDOUT = {
    "null-write": NULL_WRITE_STDOUT,
    "zero-write": ZERO_WRITE_STDOUT,
    "random-write": RANDOM_WRITE_STDOUT,
    "null-rdwr": NULL_RDWR_STDOUT,
    "zero-rdwr": ZERO_RDWR_STDOUT,
}
PLANT_LINES = tuple(
    (PLANT_LINE[name].rstrip("\n"), PLANT_LINE[name]) for name in PLANT_ORDER
)
# stem, kind, rule, opens. kind is append, deleted, network, or null-write-and-read.
NULL_WRITE_COPIES = (
    ("wallet-write-data-null", "append", WRITE_DATA_NULL, ("nullw",)),
    ("wallet-write-and-read-null", "null-write-and-read", None, ("nullw", "nullrw")),
    ("wallet-bare-write", "append", BARE_WRITE, ("nullw", "zerow", "randw")),
    ("wallet-bare-write-data", "append", BARE_WRITE_DATA, ("nullw", "zerow", "randw")),
    ("wallet-deleted", "deleted", None, ()),
    ("wallet-lookup", "append", "(allow mach-lookup)\n", ()),
    ("wallet-network", "network", None, ()),
    ("wallet-iokit-open", "append", "(allow iokit-open)\n", ()),
    ("wallet-iokit-set", "append", "(allow iokit-set-properties)\n", ()),
    ("wallet-sched", "append", "(allow system-sched)\n", ()),
    ("wallet-fork", "append", "(allow process-fork)\n", ()),
    ("wallet-extension", "append", "(allow file-issue-extension)\n", ()),
    ("wallet-shm", "append", "(allow ipc-posix-shm)\n", ()),
    ("wallet-pty", "append", "(allow pseudo-tty)\n", ()),
    ("wallet-signal", "append", "(allow signal)\n", ()),
    ("wallet-sysctl", "append", "(allow sysctl-write)\n", ()),
    ("wallet-fsctl", "append", "(allow system-fsctl)\n", ()),
    ("wallet-ioctl", "append", "(allow file-ioctl)\n", ()),
    ("wallet-read-null", "append", READ_NULL, ()),
    ("wallet-read-zero", "append", READ_ZERO, ()),
    ("wallet-read-random", "append", READ_RANDOM, ()),
    ("wallet-read-urandom", "append", READ_URANDOM, ()),
)
ZERO_WRITE_COPIES = (
    ("wallet-write-data-zero", "append", WRITE_DATA_ZERO, ("zerow",)),
)
RANDOM_WRITE_COPIES = (
    ("wallet-write-data-random", "append", WRITE_DATA_RANDOM, ("randw",)),
)
NULL_RDWR_COPIES = (
    ("wallet-rw-data-null", "append", RDWR_DATA_NULL, ("nullw", "nullrw")),
    ("wallet-read-data-write-null", "append", READ_DATA_WRITE_NULL, ("nullw", "nullrw")),
    ("wallet-read-write-data-null", "append", READ_WRITE_DATA_NULL, ("nullw", "nullrw")),
)
ZERO_RDWR_COPIES = (
    ("wallet-rw-data-zero", "append", RDWR_DATA_ZERO, ("zerow", "zerorw")),
)
PLANT_COPIES = {
    "null-write": NULL_WRITE_COPIES,
    "zero-write": ZERO_WRITE_COPIES,
    "random-write": RANDOM_WRITE_COPIES,
    "null-rdwr": NULL_RDWR_COPIES,
    "zero-rdwr": ZERO_RDWR_COPIES,
}
FINDINGS = {
    "wallet": "lab/redteam/findings/CRITICAL-confine-069.md",
    "did": "lab/redteam/findings/CRITICAL-confine-069.md",
    "model": "lab/redteam/findings/CRITICAL-cc-model-confine-069.md",
}
IDS = {
    "wallet": "CRITICAL-confine-069",
    "did": "CRITICAL-confine-069",
    "model": "CRITICAL-cc-model-confine-069",
}
PROFILES = (
    {
        "name": "wallet",
        "provider": "wallet-provider",
        "path": sbx.WALLET_CONFINE_SB,
    },
    {
        "name": "did",
        "provider": "did-provider",
        "path": sbx.REPO_ROOT / "capsules/did-provider/confine.sb",
    },
    {
        "name": "model",
        "provider": "model-provider",
        "path": sbx.REPO_ROOT / "capsules/model-provider/confine.sb",
    },
)
HELPER_C = r"""#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
static void write_one(const char *path, int flags, int *fd_out, int *n_out, int *err_out) {
    char byte = 'x';
    int saved;
    int n;
    int err = 0;
    errno = 0;
    saved = open(path, flags);
    if (saved < 0) {
        *fd_out = -1;
        *n_out = -1;
        *err_out = errno;
        return;
    }
    errno = 0;
    n = (int)write(saved, &byte, 1);
    if (n < 0) {
        err = errno;
    }
    close(saved);
    *fd_out = saved;
    *n_out = n;
    *err_out = err;
}
int main(void) {
    int nfd, nn, nerr, zfd, zn, zerr, rfd, rn, rerr, nrfd, nrn, nrerr, zrfd, zrn, zrerr;
    write_one("/dev/null", O_WRONLY, &nfd, &nn, &nerr);
    write_one("/dev/zero", O_WRONLY, &zfd, &zn, &zerr);
    write_one("/dev/random", O_WRONLY, &rfd, &rn, &rerr);
    write_one("/dev/null", O_RDWR, &nrfd, &nrn, &nrerr);
    write_one("/dev/zero", O_RDWR, &zrfd, &zrn, &zrerr);
    printf("nullw fd=%d n=%d errno=%d zerow fd=%d n=%d errno=%d randw fd=%d n=%d errno=%d nullrw fd=%d n=%d errno=%d zerorw fd=%d n=%d errno=%d\n",
        nfd, nn, nerr, zfd, zn, zerr, rfd, rn, rerr, nrfd, nrn, nrerr, zrfd, zrn, zrerr);
    return 0;
}
"""
_LINE = re.compile(
    r"nullw fd=(-?[0-9]+) n=(-?[0-9]+) errno=(-?[0-9]+) "
    r"zerow fd=(-?[0-9]+) n=(-?[0-9]+) errno=(-?[0-9]+) "
    r"randw fd=(-?[0-9]+) n=(-?[0-9]+) errno=(-?[0-9]+) "
    r"nullrw fd=(-?[0-9]+) n=(-?[0-9]+) errno=(-?[0-9]+) "
    r"zerorw fd=(-?[0-9]+) n=(-?[0-9]+) errno=(-?[0-9]+)\n"
)
_OPEN_WORD = re.compile(r"\b(?:nullrw|zerorw|nullw|zerow|randw)\b")

START_SHA = {}


class NotDenied(AssertionError):
    """The profile wrote one or more of the host devices."""

    def __init__(self, result):
        self.result = result
        super().__init__(
            "ALLOW: the profile wrote a host device.\n"
            f"  cmd: {result.command}\n"
            f"  argv: {result.argv!r}\n"
            f"  stdout: {result.stdout!r}\n"
            f"  stderr: {result.stderr!r}"
        )


class HarnessError(Exception):
    """A profile error, a bad launch, or a result that is not deny or allow.

    These fail the test. They are not a skip and they are not a deny.
    """


def skip_reason(cc_path=CC, sandbox_path=sbx.SANDBOX_EXEC):
    """None when both binaries exist. Otherwise a reason naming each missing path.

    This does not launch.
    """
    missing = []
    if not os.path.isfile(sandbox_path):
        missing.append(sandbox_path)
    if not os.path.isfile(cc_path):
        missing.append(cc_path)
    if not missing:
        return None
    return "missing " + " and ".join(missing)


def require_storage_path(path):
    """Reject an unresolved path before ``cc`` or ``sbx.run``.

    The check is ``require_resolved`` from the mach probe. A path that
    contains ``/var/folders`` and does not start with ``/private`` is a
    harness error. Resolving it here would hide that path.
    """
    try:
        return require_resolved(path)
    except MachHarnessError as caught:
        raise HarnessError(str(caught)) from caught


def stdout_for(opened):
    """The helper line for this set of successful opens. Others stay denied."""
    chosen = set(opened)
    parts = []
    for name in OPENS:
        triple = SUCCESS if name in chosen else DENIED_TRIPLE
        parts.append(f"{name} {triple}")
    return " ".join(parts) + "\n"


def stdout_with(name, fd, n, err):
    """One open replaced. The other four stay on the deny triple."""
    parts = []
    for current in OPENS:
        if current == name:
            parts.append(f"{current} fd={fd} n={n} errno={err}")
        else:
            parts.append(f"{current} {DENIED_TRIPLE}")
    return " ".join(parts) + "\n"


def union_opens(plant_names):
    """Opens granted by this set of plants, in helper order."""
    chosen = set()
    for name in plant_names:
        chosen.update(PLANT_OPENS[name])
    return tuple(name for name in OPENS if name in chosen)


def opens_for(text):
    """Opens a profile text grants. Exact allow lines only, including the newline.

    A write-only literal is not a substring of the read-write literal. A bare
    ``(allow file-write*)`` line is not a prefix of a path-specific line.
    Used by injected launches. The real helper is the measurement.
    """
    broad_write = BARE_WRITE in text or BARE_WRITE_DATA in text
    chosen = set()
    if broad_write or any(
        line in text
        for line in (
            NULL_WRITE_LINE,
            NULL_RDWR_LINE,
            WRITE_DATA_NULL,
            RDWR_DATA_NULL,
            READ_DATA_WRITE_NULL,
            READ_WRITE_DATA_NULL,
        )
    ):
        chosen.add("nullw")
    if any(
        line in text
        for line in (
            NULL_RDWR_LINE,
            RDWR_DATA_NULL,
            READ_DATA_WRITE_NULL,
            READ_WRITE_DATA_NULL,
        )
    ) or (NULL_WRITE_LINE in text and READ_NULL in text):
        chosen.add("nullrw")
    if broad_write or any(
        line in text
        for line in (ZERO_WRITE_LINE, ZERO_RDWR_LINE, WRITE_DATA_ZERO, RDWR_DATA_ZERO)
    ):
        chosen.add("zerow")
    if ZERO_RDWR_LINE in text or RDWR_DATA_ZERO in text:
        chosen.add("zerorw")
    if broad_write or RANDOM_WRITE_LINE in text or WRITE_DATA_RANDOM in text:
        chosen.add("randw")
    return tuple(name for name in OPENS if name in chosen)


def parse_line(stdout):
    """Five triples, or None when the line is malformed.

    Numeric text must be canonical. ``03`` and ``-0`` are harness errors.
    """
    match = _LINE.fullmatch(stdout)
    if match is None:
        return None
    parsed = []
    for index, part in enumerate(match.groups()):
        name = OPENS[index // 3]
        field = ("fd", "n", "errno")[index % 3]
        try:
            number = int(part)
        except ValueError as caught:
            raise HarnessError(
                f"unparseable {name} {field} integer {part!r} is a harness error, "
                "not a deny and not an allow"
            ) from caught
        if part != str(number):
            raise HarnessError(
                f"noncanonical {name} {field} integer {part!r} is a harness error, "
                "not a deny and not an allow"
            )
        if index % 3 == 2:
            fd = parsed[-1][1]
            n = parsed[-1][2]
            parsed[-1] = (name, fd, n, number)
        elif index % 3 == 0:
            parsed.append((name, number, None, None))
        else:
            name, fd, _n, _err = parsed[-1]
            parsed[-1] = (name, fd, number, None)
    return parsed


def triple_problem(name, fd, n, err):
    """None when the triple is deny or success. Otherwise the harness reason."""
    if (fd, n, err) == (3, 1, 0) or (fd, n, err) == (-1, -1, 1):
        return None
    if fd not in (-1, 3):
        if (n, err) == (1, 0):
            return (
                f"successful {name} fd other than 3 is a harness error, not an allow"
            )
        if (n, err) == (-1, 1):
            return (
                f"denied {name} fd other than -1 is a harness error, not a deny"
            )
        return f"wrong {name} fd is a harness error, not a deny and not an allow"
    if fd == 3 and n != 1:
        return (
            f"{name} n other than 1 on an allowed open is a harness error, "
            "not an allow"
        )
    if fd == -1 and n != -1:
        return (
            f"{name} n other than -1 on a denied open is a harness error, "
            "not a deny"
        )
    if fd == -1 and err != 1:
        return (
            f"wrong {name} errno on a denied open is a harness error, not a deny"
        )
    if fd == 3 and err != 0:
        return (
            f"wrong {name} errno on an allowed open is a harness error, not an allow"
        )
    return (
        f"malformed {name} triple is a harness error, not a deny and not an allow"
    )


def line_problem(stdout):
    """The harness reason for a line that is not a clean deny or allow."""
    try:
        parsed = parse_line(stdout)
    except HarnessError as caught:
        return str(caught)
    if parsed is None:
        return (
            "malformed stdout is a harness error, not a deny and not an allow: "
            + repr(stdout)
        )
    for name, fd, n, err in parsed:
        problem = triple_problem(name, fd, n, err)
        if problem is not None:
            return problem + ": " + repr(stdout)
    return (
        "malformed stdout is a harness error, not a deny and not an allow: "
        + repr(stdout)
    )


def _clean_opens(stdout):
    """Success names, or None when the line is not a clean deny or allow."""
    try:
        parsed = parse_line(stdout)
    except HarnessError:
        return None
    if parsed is None:
        return None
    opened = []
    for name, fd, n, err in parsed:
        if triple_problem(name, fd, n, err) is not None:
            return None
        if (fd, n, err) == (3, 1, 0):
            opened.append(name)
    return tuple(opened)


def opened_names(stdout):
    """Open names a confirmed allow wrote, in helper order."""
    opened = _clean_opens(stdout)
    if not opened:
        raise HarnessError("finding stdout is not an allow: " + repr(stdout))
    return opened


def opened_phrase(names):
    """Every successful open, in helper order, on one finding line."""
    parts = [name for name in OPENS if name in set(names)]
    if not parts:
        raise HarnessError("finding names no open")
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2:
        return f"{parts[0]} and {parts[1]}"
    return ", ".join(parts[:-1]) + ", and " + parts[-1]


def phrase_names(phrase):
    """Open names that appear as whole words in one finding line."""
    found = set(_OPEN_WORD.findall(phrase))
    return tuple(name for name in OPENS if name in found)


def classify(result):
    """``deny`` or ``allow``. Otherwise a harness error.

    Asks ``sbx.profile_error`` before it reads a deny or an allow. Exit 65
    is a profile error even when stderr says ``Operation not permitted``.
    Any non-empty set of success triples is an allow.
    """
    problem = sbx.profile_error(result)
    if problem is not None:
        raise HarnessError(
            f"profile error: {problem} -- a harness error, not a deny and not an allow. "
            f"stderr={result.stderr!r}"
        )
    if result.exit_code != 0:
        raise HarnessError(
            f"wrong exit {result.exit_code} is a harness error, not a deny and not an allow. "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    if result.stderr != "":
        opened = _clean_opens(result.stdout)
        if result.stdout == DENY_STDOUT:
            raise HarnessError(
                "nonempty deny stderr is a harness error, not a deny: "
                + repr(result.stderr)
            )
        if opened:
            raise HarnessError(
                "nonempty allow stderr is a harness error, not an allow: "
                + repr(result.stderr)
            )
        raise HarnessError(
            "nonempty stderr is a harness error, not a deny and not an allow: "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    try:
        parsed = parse_line(result.stdout)
    except HarnessError:
        raise
    if parsed is None:
        raise HarnessError(line_problem(result.stdout))
    opened = []
    for name, fd, n, err in parsed:
        problem = triple_problem(name, fd, n, err)
        if problem is not None:
            raise HarnessError(problem + ": " + repr(result.stdout))
        if (fd, n, err) == (3, 1, 0):
            opened.append(name)
    if not opened:
        return "deny"
    return "allow"


def compile_devwr(parent, root, source_text):
    """Compile ``source_text`` with ``/usr/bin/cc`` into ``<root>/devwr``.

    The source file sits in ``parent``. The command is ``/usr/bin/cc -o
    <root>/devwr <parent>/devwr.c``. No extra framework. This does not
    start ``sandbox-exec``. A nonzero exit, stderr on exit 0, or a missing
    executable is a harness error, not a skip.
    """
    require_storage_path(parent)
    require_storage_path(root)
    source = os.path.join(parent, SOURCE_NAME)
    with open(source, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(source_text)
    binary = os.path.join(root, BINARY_NAME)
    completed = subprocess.run(
        [CC, "-o", binary, source],
        capture_output=True,
        text=True,
        timeout=COMPILE_TIMEOUT,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no compiler output"
        raise HarnessError(
            f"{CC} failed with exit {completed.returncode}: {detail} "
            "-- a harness error, not a skip and not a deny"
        )
    if completed.stderr != "":
        raise HarnessError(
            "compiler stderr is a harness error, not a skip and not a deny: "
            + repr(completed.stderr)
        )
    require_storage_path(binary)
    if not os.access(binary, os.X_OK):
        raise HarnessError(f"{CC} wrote no executable at {binary}")
    return binary


def run_sandboxed(binary, root, parent, profile):
    """One confined launch. ``sbx.run`` is the only sandbox runner.

    The pinned executable and the launched executable are both ``binary``.
    The helper takes no argv.
    """
    require_storage_path(root)
    require_storage_path(parent)
    require_storage_path(binary)
    return sbx.run(
        pinned_exe=binary,
        launch_exe=binary,
        args=(),
        storage_root=root,
        storage_parent=parent,
        profile=profile,
        timeout=HELPER_TIMEOUT,
    )


def write_under(profile):
    """Run the compiled helper under ``profile``. Pass no argv."""
    binary = DevWriteProbe.binary
    root = DevWriteProbe.root
    parent = DevWriteProbe.parent
    if not binary or not root or not parent:
        raise HarnessError("the device-write helper is not compiled")
    return run_sandboxed(binary, root, parent, profile)


def require_unsandboxed_allow(result):
    """The unsandboxed control must be the five-success line.

    A deny, a single-plant line, a bad exit, stderr, or a malformed line is
    a harness error. An ordinary assertion is not this check.
    """
    if result.argv and os.fspath(result.argv[0]) == sbx.SANDBOX_EXEC:
        raise HarnessError(
            "unsandboxed control started sandbox-exec: " + repr(result.argv)
        )
    if classify(result) == "deny":
        raise HarnessError(
            "unsandboxed deny is a harness error, not a passing control: "
            + repr(result.stdout)
        )
    if result.stdout != ALL_STDOUT:
        raise HarnessError(
            "unsandboxed partial allow is a harness error, not a passing control: "
            + repr(result.stdout)
        )
    return result


def run_unsandboxed(binary):
    """The helper with no profile and no argv. This does not start ``sandbox-exec``."""
    require_storage_path(binary)
    completed = subprocess.run(
        [binary],
        capture_output=True,
        text=True,
        timeout=HELPER_TIMEOUT,
    )
    result = sbx.Result(
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        argv=[binary],
    )
    return require_unsandboxed_allow(result)


def require_denied(profile):
    """The one helper. ``profile`` must deny all five device writes.

    The three real-file tests and the plants call this. An allow raises
    ``NotDenied``. A harness error propagates and is not a deny.
    """
    result = write_under(profile)
    if classify(result) != "deny":
        raise NotDenied(result)
    return result


def append_line(text, line):
    """Append one exact rule line, including its newline."""
    if not line.endswith("\n"):
        raise HarnessError("plant line has no trailing newline")
    if not text.endswith("\n"):
        text += "\n"
    return text + line


def without_deny_default(text):
    """Delete the one ``(deny default)`` line. That deletion is not the plant."""
    if text.count(DENY_DEFAULT) != 1:
        raise HarnessError(
            f"(deny default) occurs {text.count(DENY_DEFAULT)} times, not once"
        )
    return text.replace(DENY_DEFAULT, "", 1)


def with_network_allow(text):
    """Replace the one ``(deny network*)`` line. That replacement is not the plant."""
    if text.count(DENY_NETWORK) != 1:
        raise HarnessError(
            f"(deny network*) occurs {text.count(DENY_NETWORK)} times, not once"
        )
    return text.replace(DENY_NETWORK, ALLOW_NETWORK, 1)


def write_copy(directory, name, text):
    path = os.path.join(directory, name + ".sb")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def launch_names(label, copies):
    """Copy basenames one plant falsifier launches, in order."""
    names = [f"{profile}-{label}.sb" for profile in ("wallet", "did", "model")]
    names.extend(stem + ".sb" for stem, _kind, _rule, _opens in copies)
    return names


def finding_paragraph(profile, result):
    """One CRITICAL record. The first line carries the live pin.

    The commit is ``git log -1 --format=%H HEAD -- <file>`` via
    ``last_change``. The digest is the bytes this run read. Neither value
    is stored in this file. ``opened`` names every open that returned the
    success triple. The helper line is ``result.command``.
    """
    commit = last_change(profile["path"])
    digest = sha256_file(profile["path"])
    opened = opened_phrase(opened_names(result.stdout))
    return (
        f"CRITICAL {IDS[profile['name']]} {commit} "
        f"{pr_label(last_change(profile['path']))} "
        f"sha256 {digest}\n"
        f"profile: {profile['rel']}\n"
        f"helper: {result.command}\n"
        f"observed: {result.stdout.strip()}\n"
        f"opened: {opened}\n"
    )


def require_finding_pins(paragraph, profile, result):
    """The PR label and the helper command are separate checks.

    A paragraph that drops only the PR label raises ``finding omits pr_label``.
    A paragraph that drops only ``result.command`` raises ``finding omits command``.
    """
    label = pr_label(last_change(profile["path"]))
    if not label or label not in paragraph:
        raise AssertionError("finding omits pr_label")
    command = result.command
    if not command or command not in paragraph:
        raise AssertionError("finding omits command")


def write_findings(repo, items):
    """Write allow findings under ``repo`` and append each paragraph.

    Wallet and did share one file. Model has its own. An empty ``items``
    writes nothing. ``CRITICAL.md`` receives the same paragraph.
    """
    if not items:
        return []
    grouped = {}
    order = []
    paragraphs = []
    for profile, result in items:
        rel = FINDINGS[profile["name"]]
        paragraph = finding_paragraph(profile, result)
        paragraphs.append((rel, paragraph))
        if rel not in grouped:
            order.append(rel)
            grouped[rel] = []
        grouped[rel].append(paragraph)
    for rel in order:
        path = Path(repo) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(grouped[rel]), encoding="utf-8")
    critical = Path(repo) / "lab" / "redteam" / "CRITICAL.md"
    existing = critical.read_text(encoding="utf-8") if critical.is_file() else ""
    addition = ""
    for _rel, paragraph in paragraphs:
        if paragraph not in existing and paragraph not in addition:
            addition += paragraph
    if addition:
        critical.parent.mkdir(parents=True, exist_ok=True)
        if existing and not existing.endswith("\n"):
            existing += "\n"
        critical.write_text(existing + addition, encoding="utf-8")
    return order


def mark_expected(case_cls, method_name, finding_rel):
    """Mark one deny test. Its docstring names the finding file.

    The mark is only for that recorded allow. A later harness error still
    fails the gate.
    """
    method = getattr(case_cls, method_name)

    @wraps(method)
    def recorded(self):
        try:
            return method(self)
        except NotDenied:
            raise
        except BaseException:
            if self._outcome is not None:
                self._outcome.expecting_failure = False
            raise

    recorded.__doc__ = (
        "The live profile allowed a device write. "
        f"Finding file: {finding_rel}"
    )
    wrapped = unittest.expectedFailure(recorded)
    setattr(case_cls, method_name, wrapped)
    case_cls.addClassCleanup(setattr, case_cls, method_name, method)


def observe(case_cls):
    """Classify each live profile. Record each allow before the next profile.

    A later harness error still propagates. Allows already confirmed stay
    written and marked. A refusal before any allow writes nothing.
    """
    case_cls.recorded_allows = {}
    confirmed = []
    for profile in PROFILES:
        result = write_under(profile["path"])
        if classify(result) != "allow":
            continue
        confirmed.append((profile, result))
        write_findings(ROOT, list(confirmed))
        case_cls.recorded_allows[profile["name"]] = FINDINGS[profile["name"]]
        mark_expected(
            case_cls,
            f"test_{profile['name']}_dev_write_is_denied",
            FINDINGS[profile["name"]],
        )


def setUpModule():
    """Record the three live profile digests. A missing file is an error."""
    for profile in PROFILES:
        rel = profile["path"].relative_to(ROOT).as_posix()
        profile["rel"] = rel
        START_SHA[rel] = sha256_file(profile["path"])


def require_unchanged(before):
    """The profile digest still matches ``before``.

    ``changed`` owns the comparison and the refusal text. This is the one
    end check for module teardown and for the falsifier.
    """
    for profile in PROFILES:
        changed(profile["rel"], before[profile["rel"]], sha256_file(profile["path"]))


def tearDownModule():
    """The digest at the end equals the digest from ``setUpModule``."""
    require_unchanged(START_SHA)


def _require_stdout_contract():
    """The generated lines are the task's literals. This does not launch."""
    if stdout_for(()) != DENY_STDOUT:
        raise HarnessError("deny stdout drifted")
    if stdout_for(OPENS) != ALL_STDOUT:
        raise HarnessError("unsandboxed stdout drifted")
    for name in PLANT_ORDER:
        if stdout_for(PLANT_OPENS[name]) != PLANT_STDOUT[name]:
            raise HarnessError(f"{name} stdout drifted")
    if stdout_for(("nullw", "zerow", "randw")) != BROAD_WRITE_STDOUT:
        raise HarnessError("broad write stdout drifted")
    if NULL_WRITE_LINE.rstrip("\n") in NULL_RDWR_LINE:
        raise HarnessError("null write line is a substring of the read-write plant")
    if ZERO_WRITE_LINE.rstrip("\n") in ZERO_RDWR_LINE:
        raise HarnessError("zero write line is a substring of the read-write plant")


class DevWriteProbe(unittest.TestCase):
    """The helper under the live profiles, and the five allow plants."""

    maxDiff = None
    skip_reason = None
    binary = None
    root = None
    parent = None
    recorded_allows = {}

    @classmethod
    def setUpClass(cls):
        _require_stdout_contract()
        cls.skip_reason = skip_reason()
        cls.binary = None
        cls.root = None
        cls.parent = None
        cls.recorded_allows = {}
        if cls.skip_reason:
            return
        cls.parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devwr-parent-"))
        cls.root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devwr-root-"))
        cls.addClassCleanup(shutil.rmtree, cls.parent, ignore_errors=True)
        cls.addClassCleanup(shutil.rmtree, cls.root, ignore_errors=True)
        cls.binary = compile_devwr(cls.parent, cls.root, HELPER_C)
        observe(cls)

    def setUp(self):
        if type(self).skip_reason:
            self.skipTest(type(self).skip_reason)
        self.binary = type(self).binary
        self.root = type(self).root
        self.parent = type(self).parent

    def test_cc_and_sandbox_present_or_skip(self):
        """This class runs only when both binaries exist.

        A missing ``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` skips the
        class, and the reason contains that path. Nothing else skips it.
        """
        self.assertIsNone(skip_reason())
        self.assertIsNone(type(self).skip_reason)
        self.assertTrue(os.path.isfile(CC))
        self.assertTrue(os.path.isfile(sbx.SANDBOX_EXEC))
        self.assertEqual(CC, "/usr/bin/cc")
        self.assertEqual(sbx.SANDBOX_EXEC, "/usr/bin/sandbox-exec")

    def test_unsandboxed_dev_write_succeeds(self):
        """Without ``sandbox-exec``, every open writes one byte on fd 3.

        Exit 0, stderr empty, stdout the five-success line. A failure here
        is a harness error, so a later deny is about the profile.
        """
        source = os.path.join(self.parent, SOURCE_NAME)
        self.assertEqual(Path(source).read_text(encoding="utf-8"), HELPER_C)
        self.assertIn("open(", HELPER_C)
        self.assertIn("write(", HELPER_C)
        self.assertIn('"/dev/null"', HELPER_C)
        self.assertIn('"/dev/zero"', HELPER_C)
        self.assertIn('"/dev/random"', HELPER_C)
        self.assertIn("O_WRONLY", HELPER_C)
        self.assertIn("O_RDWR", HELPER_C)
        self.assertNotIn("/dev/" + "urandom", HELPER_C)
        self.assertEqual(os.path.dirname(source), self.parent)
        self.assertEqual(os.path.dirname(self.binary), self.root)
        self.assertTrue(self.binary.endswith(os.sep + BINARY_NAME))
        self.assertNotEqual(self.root, self.parent)
        if "/var/folders" in self.binary:
            self.assertTrue(self.binary.startswith("/private/"))
        self.assertEqual(os.path.realpath(self.binary), self.binary)
        self.assertEqual(os.path.realpath(self.root), self.root)
        self.assertEqual(os.path.realpath(self.parent), self.parent)
        result = run_unsandboxed(self.binary)
        self.assertEqual(result.argv, [self.binary])
        self.assertNotIn(sbx.SANDBOX_EXEC, result.argv)
        self.assertIsNone(sbx.profile_error(result))
        self.assertEqual(result.exit_code, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, ALL_STDOUT)
        self.assertEqual(classify(result), "allow")
        self.assertEqual(opened_names(result.stdout), OPENS)

    def test_compile_failure_is_an_error(self):
        """``/usr/bin/cc`` on an empty source is a harness error, not a skip."""
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devwr-empty-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devwr-empty-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with self.assertRaises(HarnessError) as caught:
            compile_devwr(parent, root, "")
        message = str(caught.exception)
        self.assertIn(CC, message)
        self.assertIn("not a skip", message)
        self.assertNotIn("SKIPPED", message)
        self.assertNotIsInstance(caught.exception, unittest.SkipTest)

    def _expect_real_deny(self, profile):
        self.assertTrue(os.path.isfile(profile))
        result = require_denied(profile)
        self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
        self.assertIn(f"PROVIDER_EXECUTABLE={self.binary}", result.argv)
        self.assertIn(f"STORAGE_ROOT={self.root}", result.argv)
        self.assertIn(f"STORAGE_PARENT={self.parent}", result.argv)
        self.assertEqual(result.argv[-1], self.binary)
        self.assertEqual(result.argv[-2], os.fspath(profile))
        self.assertEqual(os.path.basename(result.argv[-1]), BINARY_NAME)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, DENY_STDOUT)
        self.assertEqual(classify(result), "deny")
        return result

    def test_wallet_dev_write_is_denied(self):
        """The real wallet profile denies all five device writes."""
        result = self._expect_real_deny(sbx.WALLET_CONFINE_SB)
        self.assertEqual(
            result.stdout,
            "nullw fd=-1 n=-1 errno=1 zerow fd=-1 n=-1 errno=1 "
            "randw fd=-1 n=-1 errno=1 nullrw fd=-1 n=-1 errno=1 "
            "zerorw fd=-1 n=-1 errno=1\n",
        )

    def test_did_dev_write_is_denied(self):
        """The real did profile denies all five device writes."""
        did = sbx.REPO_ROOT / "capsules/did-provider/confine.sb"
        self._expect_real_deny(did)

    def test_model_dev_write_is_denied(self):
        """The real model profile denies all five device writes.

        A root-directory read grant is not a reason to skip this file.
        The helper starts under the model profile.
        """
        model = sbx.REPO_ROOT / "capsules/model-provider/confine.sb"
        self._expect_real_deny(model)

    def _baseline_for(self, profile, text):
        """Count plants on the baseline, not on an unstripped live file.

        An unconditional zero-count on the live file turns a recorded allow
        into an ordinary failure. The count is the exact line, including
        its newline.
        """
        baseline = self._source_for_plant(profile["name"], text)
        if profile["name"] not in type(self).recorded_allows:
            for line in PLANT_LINE.values():
                self.assertEqual(text.count(line), 0)
            self.assertEqual(text.count(DENY_DEFAULT), 1)
            self.assertEqual(baseline, text)
        for line in PLANT_LINE.values():
            self.assertEqual(baseline.count(line), 0)
        self.assertEqual(baseline.count(DENY_DEFAULT), 1)
        self.assertTrue(baseline.endswith("\n"))
        return baseline

    def _assert_only_plant(self, text, line):
        for plant_line in PLANT_LINE.values():
            expect = 1 if plant_line == line else 0
            self.assertEqual(text.count(plant_line), expect, plant_line)
        self.assertEqual(text.count(DENY_DEFAULT), 1)

    def _assert_no_plants(self, text):
        for line in PLANT_LINE.values():
            self.assertEqual(text.count(line), 0, line)

    def _catch_allow(self, profile, copy_path, opens):
        expected = stdout_for(opens)
        with self.assertRaises(NotDenied) as caught:
            require_denied(copy_path)
        result = caught.exception.result
        self.assertIn("ALLOW", str(caught.exception))
        self.assertIsNone(sbx.profile_error(result))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, expected)
        self.assertEqual(classify(result), "allow")
        self.assertEqual(opened_names(result.stdout), tuple(opens))
        self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
        self.assertEqual(os.path.basename(result.argv[-1]), BINARY_NAME)
        self.assertEqual(result.argv[-2], copy_path)
        self.assertIn(copy_path, result.argv)
        self.assertNotIn(os.fspath(profile["path"]), result.argv)
        return result

    def _expect_deny_copy(self, profile, copy_path):
        denied = require_denied(copy_path)
        self.assertEqual(denied.stdout, DENY_STDOUT)
        self.assertEqual(denied.stderr, "")
        self.assertEqual(denied.exit_code, 0)
        self.assertEqual(classify(denied), "deny")
        self.assertEqual(denied.argv[0], sbx.SANDBOX_EXEC)
        self.assertIn(copy_path, denied.argv)
        self.assertNotIn(os.fspath(profile["path"]), denied.argv)
        return denied

    def _expect_copy(self, profile, copy_path, opens):
        if not opens:
            return self._expect_deny_copy(profile, copy_path)
        return self._catch_allow(profile, copy_path, opens)

    def _wallet_text(self, baseline, kind, rule):
        """One wallet copy. Plant lines are counted exactly, with the newline."""
        if kind == "append":
            self.assertEqual(baseline.count(rule), 0, rule)
            edited = append_line(baseline, rule)
            self.assertEqual(edited.count(rule), 1, rule)
            self._assert_no_plants(edited)
            self.assertEqual(edited.count(DENY_DEFAULT), 1)
            return edited
        if kind == "deleted":
            edited = without_deny_default(baseline)
            self.assertNotIn("(deny default)", edited)
            self.assertNotIn("(allow default)", edited)
            self._assert_no_plants(edited)
            return edited
        if kind == "network":
            self.assertEqual(baseline.count(DENY_NETWORK), 1)
            edited = with_network_allow(baseline)
            self.assertEqual(edited.count(DENY_NETWORK), 0)
            self.assertEqual(edited.count(ALLOW_NETWORK), baseline.count(ALLOW_NETWORK) + 1)
            self.assertEqual(edited.count(DENY_DEFAULT), 1)
            self._assert_no_plants(edited)
            return edited
        if kind == "null-write-and-read":
            edited = append_line(append_line(baseline, NULL_WRITE_LINE), READ_NULL)
            self.assertEqual(edited.count(NULL_WRITE_LINE), 1)
            self.assertEqual(edited.count(READ_NULL), 1)
            self.assertEqual(edited.count(NULL_RDWR_LINE), 0)
            self.assertEqual(edited.count(ZERO_WRITE_LINE), 0)
            self.assertEqual(edited.count(ZERO_RDWR_LINE), 0)
            self.assertEqual(edited.count(RANDOM_WRITE_LINE), 0)
            self.assertEqual(edited.count(DENY_DEFAULT), 1)
            return edited
        raise HarnessError(f"unknown wallet copy {kind}")

    def _exercise(self, label, copies):
        """Append one plant on each profile, then the wallet copies for it."""
        line = PLANT_LINE[label]
        opens = PLANT_OPENS[label]
        self.assertEqual(stdout_for(opens), PLANT_STDOUT[label])
        before = {
            profile["rel"]: sha256_file(profile["path"]) for profile in PROFILES
        }
        directory = os.path.realpath(tempfile.mkdtemp(prefix=f"ccrt-devwr-{label}-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        try:
            for profile in PROFILES:
                with self.subTest(profile=f"{profile['name']}-{label}"):
                    text = profile["path"].read_text(encoding="utf-8")
                    baseline = self._baseline_for(profile, text)
                    planted = append_line(baseline, line)
                    self.assertEqual(planted, baseline + line)
                    self._assert_only_plant(planted, line)
                    if label == "null-write":
                        self.assertEqual(planted.count(READ_NULL), baseline.count(READ_NULL))
                        self.assertEqual(planted.count(NULL_RDWR_LINE), 0)
                    if label == "null-rdwr":
                        self.assertEqual(planted.count(NULL_WRITE_LINE), 0)
                    if label == "zero-rdwr":
                        self.assertEqual(planted.count(ZERO_WRITE_LINE), 0)
                    copy_path = write_copy(directory, f"{profile['name']}-{label}", planted)
                    self.assertEqual(Path(copy_path).read_text(encoding="utf-8"), planted)
                    self.assertNotEqual(
                        os.path.realpath(copy_path),
                        os.path.realpath(profile["path"]),
                    )
                    self._expect_copy(profile, copy_path, opens)
                    self.assertEqual(profile["path"].read_text(encoding="utf-8"), text)
            if copies:
                wallet = PROFILES[0]
                self.assertEqual(wallet["name"], "wallet")
                wallet_text = wallet["path"].read_text(encoding="utf-8")
                baseline = self._baseline_for(wallet, wallet_text)
                for stem, kind, rule, copy_opens in copies:
                    with self.subTest(profile=stem):
                        edited = self._wallet_text(baseline, kind, rule)
                        self.assertEqual(opens_for(edited), tuple(copy_opens))
                        if copy_opens == ("nullw", "zerow", "randw"):
                            self.assertEqual(stdout_for(copy_opens), BROAD_WRITE_STDOUT)
                        copy_path = write_copy(directory, stem, edited)
                        self.assertEqual(Path(copy_path).read_text(encoding="utf-8"), edited)
                        self.assertNotEqual(
                            os.path.realpath(copy_path),
                            os.path.realpath(wallet["path"]),
                        )
                        self._expect_copy(wallet, copy_path, copy_opens)
                self.assertEqual(wallet["path"].read_text(encoding="utf-8"), wallet_text)
        finally:
            require_unchanged(before)

    def test_falsifier_allow_null_write_is_caught(self):
        """Appending the null write plant lets only ``nullw`` succeed.

        Each plant baseline contains each exact plant line zero times and
        ``(deny default)`` once. A recorded allow strips one exact copy of
        each injected plant line before that count. ``nullrw`` stays denied.
        The write-data form, the bare write forms, and the write line plus
        the read line are not this plant. The still-deny copies keep the
        deny line. The repo profile bytes stay unchanged.
        """
        self._exercise("null-write", NULL_WRITE_COPIES)

    def test_falsifier_allow_zero_write_is_caught(self):
        """Appending the zero write plant lets only ``zerow`` succeed.

        The write-data form is not the plant and allows only ``zerow``.
        The repo profile bytes stay unchanged.
        """
        self._exercise("zero-write", ZERO_WRITE_COPIES)

    def test_falsifier_allow_random_write_is_caught(self):
        """Appending the random write plant lets only ``randw`` succeed.

        The write-data form is not the plant and allows only ``randw``.
        The repo profile bytes stay unchanged.
        """
        self._exercise("random-write", RANDOM_WRITE_COPIES)

    def test_falsifier_allow_null_rdwr_is_caught(self):
        """Appending the null read-write plant allows ``nullw`` and ``nullrw``.

        The write-only null plant is absent. The data-pair and mixed
        read/write forms are not this plant and allow the same two opens.
        The repo profile bytes stay unchanged.
        """
        self._exercise("null-rdwr", NULL_RDWR_COPIES)

    def test_falsifier_allow_zero_rdwr_is_caught(self):
        """Appending the zero read-write plant allows ``zerow`` and ``zerorw``.

        The write-only zero plant is absent. The data pair is not this plant
        and allows the same two opens. The repo profile bytes stay unchanged.
        """
        self._exercise("zero-rdwr", ZERO_RDWR_COPIES)

    def _source_for_plant(self, name, text):
        """The text the temp plant edits. A recorded allow does not skip this.

        The deny test carries the finding-linked expected failure. The live
        file is not edited. One exact copy of each injected plant line is
        removed so the append is still that one line. The write-only line
        is not a substring of the read-write line, so that strip leaves the
        read-write plant in place until its own exact line is removed.
        """
        finding = type(self).recorded_allows.get(name)
        if finding is None:
            for rule, _line in PLANT_LINES:
                if rule in text:
                    raise AssertionError(f"{name} source contains {rule}")
            return text
        method = getattr(type(self), f"test_{name}_dev_write_is_denied")
        if not getattr(method, "__unittest_expecting_failure__", False):
            raise HarnessError(f"{name} allow has no finding-linked expected failure")
        if finding not in (method.__doc__ or ""):
            raise HarnessError(f"{name} allow docstring does not name {finding}")
        for rule, line in PLANT_LINES:
            occurrences = text.count(line)
            if occurrences > 1:
                raise HarnessError(
                    f"{rule} occurs {occurrences} times, not zero or one"
                )
            if occurrences == 1:
                text = text.replace(line, "", 1)
        for rule, _line in PLANT_LINES:
            if rule in text:
                raise HarnessError(f"{name} plant line has no trailing newline")
        return text


class DevWriteRules(unittest.TestCase):
    """Classifier, pins, and injected results. They compile nothing and launch nothing."""

    maxDiff = None

    def setUp(self):
        self.launch_guard = self.enter_patch(
            patch.object(
                subprocess, "run",
                side_effect=AssertionError("rules launched a process"),
            )
        )

    def enter_patch(self, patcher):
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def test_skip_reason_names_the_missing_path(self):
        """``skip_reason`` names each missing binary and does not launch."""
        def refuse_subprocess(*_args, **_kwargs):
            raise AssertionError("skip_reason launched a process")

        with patch.object(subprocess, "run", side_effect=refuse_subprocess), patch.object(
            os.path, "isfile", side_effect=lambda path: path in (CC, sbx.SANDBOX_EXEC)
        ):
            live = skip_reason()
            absent_cc = "/usr/bin/cc-not-here"
            absent_sandbox = "/usr/bin/sandbox-exec-not-here"
            missing_cc = skip_reason(cc_path=absent_cc)
            missing_both = skip_reason(cc_path=absent_cc, sandbox_path=absent_sandbox)
            missing_sandbox = skip_reason(sandbox_path=absent_sandbox)
            present = skip_reason(cc_path=CC, sandbox_path=sbx.SANDBOX_EXEC)
        self.assertIsNone(live)
        with patch.object(os.path, "isfile", return_value=False):
            live = skip_reason()
            self.assertIsNotNone(live)
            self.assertIn(CC, live)
            self.assertIn(sbx.SANDBOX_EXEC, live)
            self.assertEqual(live, f"missing {sbx.SANDBOX_EXEC} and {CC}")
        self.assertIn(absent_cc, missing_cc)
        self.assertIn(absent_cc, missing_both)
        self.assertIn(absent_sandbox, missing_both)
        self.assertEqual(missing_cc, f"missing {absent_cc}")
        self.assertEqual(missing_sandbox, f"missing {absent_sandbox}")
        self.assertEqual(missing_both, f"missing {absent_sandbox} and {absent_cc}")
        self.assertIsNone(present)
        self.launch_guard.assert_not_called()

    def test_skip_is_only_a_missing_toolchain(self):
        """``skipTest`` is only the missing compiler or ``sandbox-exec`` path."""
        source = Path(__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "skipTest":
                    calls.append(node)
        self.assertEqual(len(calls), 1)
        line = source.splitlines()[calls[0].lineno - 1]
        self.assertIn("skip_reason", line)
        with patch.object(os.path, "isfile", return_value=True):
            self.assertIsNone(skip_reason())
        self.launch_guard.assert_not_called()

    def test_missing_tools_skip_only_probe_class(self):
        """Each missing tool skips every probe while the classifier checks run."""
        classifier_names = (
            "test_skip_is_only_a_missing_toolchain",
            "test_recorded_allow_does_not_skip",
            "test_classifier_refusal_reasons",
        )
        probe_names = unittest.defaultTestLoader.getTestCaseNames(DevWriteProbe)
        for missing in ((sbx.SANDBOX_EXEC,), (CC,), (sbx.SANDBOX_EXEC, CC)):
            with self.subTest(missing=missing), patch.object(
                os.path, "isfile", side_effect=lambda path: path not in missing
            ), patch(
                __name__ + ".compile_devwr",
                side_effect=AssertionError("missing-tool probe compiled a helper"),
            ) as compiled, patch.object(
                sbx, "run",
                side_effect=AssertionError("missing-tool probe launched a helper"),
            ) as launched:
                class MissingTools(DevWriteProbe):
                    pass

                probes = unittest.TestResult()
                unittest.defaultTestLoader.loadTestsFromTestCase(MissingTools).run(probes)
                self.assertEqual(probes.testsRun, len(probe_names))
                self.assertEqual(probes.errors, [])
                self.assertEqual(probes.failures, [])
                self.assertEqual(
                    [(case._testMethodName, reason) for case, reason in probes.skipped],
                    [(name, "missing " + " and ".join(missing)) for name in probe_names],
                )
                classifiers = unittest.TestResult()
                for name in classifier_names:
                    type(self)(name).run(classifiers)
                self.assertEqual(classifiers.testsRun, len(classifier_names))
                self.assertEqual(classifiers.errors, [])
                self.assertEqual(classifiers.failures, [])
                self.assertEqual(classifiers.skipped, [])
                self.assertEqual(classifiers.expectedFailures, [])
                self.assertEqual(classifiers.unexpectedSuccesses, [])
                compiled.assert_not_called()
                launched.assert_not_called()
                self.launch_guard.assert_not_called()

    def test_recorded_allow_does_not_skip(self):
        """A recorded allow is a finding-linked expected failure, not a skip.

        The write-only line is not a substring of the read-write plant.
        Stripping counts the exact line, including its newline. Read-only,
        write-data, and bare write lines are not plants and stay.
        """
        self.assertNotIn(NULL_WRITE_LINE.rstrip("\n"), NULL_RDWR_LINE)
        self.assertNotIn(ZERO_WRITE_LINE.rstrip("\n"), ZERO_RDWR_LINE)
        self.assertIn('file-write* (literal "/dev/null")', NULL_RDWR_LINE)
        self.assertEqual(NULL_RDWR_LINE.count(NULL_WRITE_LINE), 0)
        self.assertEqual(ZERO_RDWR_LINE.count(ZERO_WRITE_LINE), 0)
        both = "(version 1)\n" + NULL_RDWR_LINE + NULL_WRITE_LINE
        self.assertEqual(both.count(NULL_WRITE_LINE), 1)
        self.assertEqual(both.replace(NULL_WRITE_LINE, "", 1), "(version 1)\n" + NULL_RDWR_LINE)
        with patch.object(os.path, "isfile", return_value=True):
            self.assertIsNone(skip_reason())
            self.assertTrue(os.path.isfile(CC))
            self.assertTrue(os.path.isfile(sbx.SANDBOX_EXEC))
        clean = "(version 1)\n(deny default)\n"
        one = {name: clean + PLANT_LINE[name] for name in PLANT_ORDER}
        all_five = clean + "".join(PLANT_LINE[name] for name in PLANT_ORDER)
        stayed = (
            clean
            + NULL_RDWR_LINE
            + WRITE_DATA_NULL
            + BARE_WRITE
            + READ_NULL
            + READ_URANDOM
        )

        class Recorded(DevWriteProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Recorded, "test_wallet_dev_write_is_denied", FINDINGS["wallet"])
        try:
            case = Recorded("test_falsifier_allow_null_write_is_caught")
            for name in PLANT_ORDER:
                self.assertEqual(case._source_for_plant("wallet", one[name]), clean)
            self.assertEqual(case._source_for_plant("wallet", all_five), clean)
            self.assertEqual(one["null-rdwr"].count(NULL_WRITE_LINE), 0)
            self.assertEqual(
                case._source_for_plant("wallet", stayed),
                clean + WRITE_DATA_NULL + BARE_WRITE + READ_NULL + READ_URANDOM,
            )
            self.assertEqual(case._source_for_plant("did", clean), clean)
        finally:
            Recorded.doClassCleanups()

        class Bare(DevWriteProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        bare = Bare("test_falsifier_allow_null_write_is_caught")
        with self.assertRaises(HarnessError) as unmarked:
            bare._source_for_plant("wallet", one["null-write"])
        self.assertEqual(
            str(unmarked.exception),
            "wallet allow has no finding-linked expected failure",
        )
        self.assertNotIsInstance(unmarked.exception, unittest.SkipTest)

        class WrongDoc(DevWriteProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        def body(self):
            raise NotDenied(
                sbx.Result(
                    exit_code=0, stdout=NULL_WRITE_STDOUT, stderr="", argv=[],
                )
            )

        body.__doc__ = "plain"
        body.__unittest_expecting_failure__ = True
        WrongDoc.test_wallet_dev_write_is_denied = body
        wrong = WrongDoc("test_falsifier_allow_null_write_is_caught")
        with self.assertRaises(HarnessError) as unnamed:
            wrong._source_for_plant("wallet", one["null-write"])
        self.assertEqual(
            str(unnamed.exception),
            f"wallet allow docstring does not name {FINDINGS['wallet']}",
        )

        class Twice(DevWriteProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Twice, "test_wallet_dev_write_is_denied", FINDINGS["wallet"])
        try:
            twice = Twice("test_falsifier_allow_null_write_is_caught")
            for name in PLANT_ORDER:
                with self.assertRaises(HarnessError) as extra:
                    twice._source_for_plant("wallet", one[name] + PLANT_LINE[name])
                self.assertEqual(
                    str(extra.exception),
                    f"{PLANT_LINE[name].rstrip(chr(10))} occurs 2 times, not zero or one",
                )
            bare_rule = clean + NULL_WRITE_LINE.rstrip("\n") + " trailing\n"
            with self.assertRaises(HarnessError) as naked:
                twice._source_for_plant("wallet", bare_rule)
            self.assertEqual(
                str(naked.exception),
                "wallet plant line has no trailing newline",
            )
        finally:
            Twice.doClassCleanups()

        class Clean(DevWriteProbe):
            recorded_allows = {}

        plain = Clean("test_falsifier_allow_null_write_is_caught")
        for name in PLANT_ORDER:
            with self.assertRaises(AssertionError) as present:
                plain._source_for_plant("wallet", one[name])
            self.assertEqual(
                str(present.exception),
                f"wallet source contains {PLANT_LINE[name].rstrip(chr(10))}",
            )
        self.assertEqual(plain._source_for_plant("wallet", clean), clean)
        self.assertEqual(
            plain._source_for_plant("wallet", clean + WRITE_DATA_NULL),
            clean + WRITE_DATA_NULL,
        )
        self.launch_guard.assert_not_called()

    def test_profile_bytes_match_the_start(self):
        """Each end digest equals the start digest through ``changed``.

        This stores no digest. A changed temporary profile, checked by
        module teardown, raises ``the probe changed <rel>``.
        """
        global PROFILES
        self.assertEqual(ROOT, Path(__file__).resolve().parents[3])
        self.assertEqual(ROOT, sbx.REPO_ROOT)
        self.assertEqual(
            [profile["name"] for profile in PROFILES],
            ["wallet", "did", "model"],
        )
        source = Path(__file__).read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"\b[0-9a-f]{40}\b", source))
        self.assertIsNone(re.search(r"\b[0-9a-f]{64}\b", source))
        for profile in PROFILES:
            expected = sbx.REPO_ROOT / "capsules" / profile["provider"] / "confine.sb"
            self.assertEqual(profile["path"], expected)
            if profile["name"] == "wallet":
                self.assertEqual(profile["path"], sbx.WALLET_CONFINE_SB)
            elif profile["name"] == "did":
                self.assertEqual(
                    profile["path"],
                    sbx.REPO_ROOT / "capsules/did-provider/confine.sb",
                )
            else:
                self.assertEqual(
                    profile["path"],
                    sbx.REPO_ROOT / "capsules/model-provider/confine.sb",
                )
            rel = profile["rel"]
            self.assertIn(rel, START_SHA)
            changed(rel, START_SHA[rel], sha256_file(profile["path"]))

        rel = "tmp/devwr-confine.sb"
        self.assertNotIn(rel, START_SHA)
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devwr-byte-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        path = Path(directory) / "confine.sb"
        path.write_bytes(b"(version 1)\n(deny default)\n")
        before = sha256_file(path)
        saved = PROFILES
        START_SHA[rel] = before
        try:
            PROFILES = ({"name": "temp", "rel": rel, "path": path},) + saved
            path.write_bytes(path.read_bytes() + b"\n")
            self.assertNotEqual(sha256_file(path), before)
            with self.assertRaises(AssertionError) as caught:
                tearDownModule()
            self.assertEqual(str(caught.exception), f"the probe changed {rel}")
        finally:
            PROFILES = saved
            START_SHA.pop(rel, None)
        self.launch_guard.assert_not_called()

    def test_compile_stderr_is_an_error(self):
        """Exit 0 with compiler stderr is its own harness error, not a skip.

        A nonzero exit, a missing executable, and an unresolved storage path
        each keep a different reason. Empty stderr still returns the binary.
        """
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devwr-cc-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devwr-cc-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        binary = os.path.join(root, BINARY_NAME)
        source = "int main(void) { return 0; }\n"
        reasons = []

        def compiled(completed, access=None):
            runners = patch.object(subprocess, "run", return_value=completed)
            if access is None:
                with runners:
                    return compile_devwr(parent, root, source)
            with runners, patch.object(os, "access", return_value=access):
                return compile_devwr(parent, root, source)

        exit_cases = (
            (
                "cc error\n",
                "",
                f"{CC} failed with exit 1: cc error "
                "-- a harness error, not a skip and not a deny",
            ),
            (
                "",
                "stdout only\n",
                f"{CC} failed with exit 1: stdout only "
                "-- a harness error, not a skip and not a deny",
            ),
            (
                "",
                "",
                f"{CC} failed with exit 1: no compiler output "
                "-- a harness error, not a skip and not a deny",
            ),
            (
                "Operation not permitted\n",
                "",
                f"{CC} failed with exit 65: Operation not permitted "
                "-- a harness error, not a skip and not a deny",
            ),
        )
        for stderr, stdout, expected in exit_cases:
            code = 65 if "Operation not permitted" in stderr else 1
            with self.subTest(exit=code, stderr=stderr, stdout=stdout):
                completed = subprocess.CompletedProcess(
                    args=[CC], returncode=code, stdout=stdout, stderr=stderr,
                )
                with self.assertRaises(HarnessError) as caught:
                    compiled(completed)
                self.assertEqual(str(caught.exception), expected)
                self.assertNotIn("SKIPPED", str(caught.exception))
                reasons.append(expected)

        warning = subprocess.CompletedProcess(
            args=[CC], returncode=0, stdout="", stderr="compiler warning\n",
        )
        stderr_reason = (
            "compiler stderr is a harness error, not a skip and not a deny: "
            + repr("compiler warning\n")
        )
        with self.assertRaises(HarnessError) as caught:
            compiled(warning, access=True)
        self.assertEqual(str(caught.exception), stderr_reason)
        self.assertNotIn("SKIPPED", stderr_reason)
        reasons.append(stderr_reason)

        silent = subprocess.CompletedProcess(
            args=[CC], returncode=0, stdout="", stderr="",
        )
        with self.assertRaises(HarnessError) as caught:
            compiled(silent)
        missing = f"{CC} wrote no executable at {binary}"
        self.assertEqual(str(caught.exception), missing)
        reasons.append(missing)
        self.assertEqual(compiled(silent, access=True), binary)

        def refuse_cc(*_args, **_kwargs):
            raise AssertionError("compiler started")

        for label, compile_parent, compile_root in (
            ("parent", "/var/folders/cc/devwr-parent", root),
            ("root", parent, "/var/folders/cc/devwr-root"),
        ):
            bad = compile_parent if label == "parent" else compile_root
            expected = (
                f"execvp: {bad} contains /var/folders without the /private prefix"
            )
            with self.subTest(path=label), patch.object(
                subprocess, "run", side_effect=refuse_cc
            ):
                with self.assertRaises(HarnessError) as caught:
                    compile_devwr(compile_parent, compile_root, source)
            self.assertEqual(str(caught.exception), expected)
            self.assertNotIn("/private" + bad, str(caught.exception))
            reasons.append(expected)

        self.assertEqual(len(set(reasons)), len(reasons))
        self.launch_guard.assert_not_called()

    def test_falsifier_change_check_calls_changed(self):
        """The profile-change check calls ``changed`` with the two digests.

        Different before and after bytes are injected. A local compare that
        raises ``the probe changed <rel>`` is not this rule.
        """
        source = Path(__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Raise):
                segment = ast.get_source_segment(source, node) or ""
                self.assertNotIn("the probe changed", segment)

        global PROFILES
        clean = b"(version 1)\n(deny default)\n(deny network*)\n"
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devwr-bytes-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        profiles = []
        for name in ("wallet", "did", "model"):
            path = Path(directory) / f"{name}.sb"
            path.write_bytes(clean)
            profiles.append({
                "name": name,
                "provider": f"{name}-provider",
                "rel": f"tmp/{name}-confine.sb",
                "path": path,
            })
        profiles = tuple(profiles)
        wallet = profiles[0]
        before_digest = sha256_file(wallet["path"])
        preview = Path(directory) / "after.sb"
        preview.write_bytes(clean + b"\n")
        after_bytes = preview.read_bytes()
        after_digest = sha256_file(preview)
        self.assertNotEqual(clean, after_bytes)
        self.assertNotEqual(before_digest, after_digest)
        equal_pairs = [
            (item["rel"], sha256_file(item["path"]), sha256_file(item["path"]))
            for item in profiles
        ]
        seen = []
        real_changed = changed

        def spy(name, start, end):
            seen.append((name, start, end))
            return real_changed(name, start, end)

        saved = PROFILES
        saved_sha = dict(START_SHA)
        try:
            with self.subTest(path="direct"):
                PROFILES = profiles
                seen.clear()
                with patch(__name__ + ".changed", new=spy):
                    require_unchanged({
                        item["rel"]: sha256_file(item["path"]) for item in profiles
                    })
                self.assertEqual(seen, equal_pairs)
                seen.clear()
                wallet["path"].write_bytes(after_bytes)
                with patch(__name__ + ".changed", new=spy):
                    with self.assertRaises(AssertionError) as caught:
                        require_unchanged({
                            item["rel"]: (
                                before_digest if item is wallet else sha256_file(item["path"])
                            )
                            for item in profiles
                        })
                self.assertEqual(seen, [(wallet["rel"], before_digest, after_digest)])
                self.assertEqual(
                    str(caught.exception), f"the probe changed {wallet['rel']}"
                )
                wallet["path"].write_bytes(clean)

            class Plant(DevWriteProbe):
                recorded_allows = {}

            state = {"mutate": False}

            def fake_denied(profile):
                profile = os.fspath(profile)
                text = Path(profile).read_text(encoding="utf-8")
                if state["mutate"] and profile.endswith(os.sep + "wallet-deleted.sb"):
                    wallet["path"].write_bytes(after_bytes)
                stdout = stdout_for(opens_for(text))
                result = sbx.Result(
                    exit_code=0,
                    stdout=stdout,
                    stderr="",
                    argv=[sbx.SANDBOX_EXEC, "-f", profile, "/private/devwr"],
                )
                if stdout != DENY_STDOUT:
                    raise NotDenied(result)
                return result

            case = Plant("test_falsifier_allow_null_write_is_caught")
            try:
                with patch(__name__ + ".PROFILES", profiles), patch(
                    __name__ + ".require_denied", new=fake_denied
                ), patch(__name__ + ".changed", new=spy):
                    with self.subTest(path="falsifier-equal"):
                        seen.clear()
                        state["mutate"] = False
                        case.test_falsifier_allow_null_write_is_caught()
                        self.assertEqual(seen, equal_pairs)
                    with self.subTest(path="falsifier-changed"):
                        seen.clear()
                        state["mutate"] = True
                        wallet["path"].write_bytes(clean)
                        with self.assertRaises(AssertionError) as caught:
                            case.test_falsifier_allow_null_write_is_caught()
                        self.assertEqual(
                            seen, [(wallet["rel"], before_digest, after_digest)]
                        )
                        self.assertEqual(
                            str(caught.exception),
                            f"the probe changed {wallet['rel']}",
                        )
            finally:
                case.doCleanups()

            with self.subTest(path="teardown"):
                tear_path = Path(directory) / "teardown.sb"
                tear_path.write_bytes(clean)
                tear_before = sha256_file(tear_path)
                tear_path.write_bytes(clean + b"\n")
                tear_after = sha256_file(tear_path)
                tear_rel = "tmp/teardown-confine.sb"
                self.assertNotEqual(tear_before, tear_after)
                START_SHA.clear()
                START_SHA[tear_rel] = tear_before
                PROFILES = ({
                    "name": "temp",
                    "rel": tear_rel,
                    "path": tear_path,
                },)
                seen.clear()
                with patch(__name__ + ".changed", new=spy):
                    with self.assertRaises(AssertionError) as caught:
                        tearDownModule()
                self.assertEqual(seen, [(tear_rel, tear_before, tear_after)])
                self.assertEqual(str(caught.exception), f"the probe changed {tear_rel}")
        finally:
            PROFILES = saved
            START_SHA.clear()
            START_SHA.update(saved_sha)
        self.launch_guard.assert_not_called()

    @staticmethod
    def refusal_samples():
        """Each sample is a label, a result, and the exact harness reason."""
        noise = "noise\n"
        permitted = "Operation not permitted\n"
        samples = [
            (
                "profile error",
                sbx.Result(
                    exit_code=sbx.PROFILE_ERROR_EXIT,
                    stdout=DENY_STDOUT,
                    stderr=permitted,
                    argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/devwr"],
                ),
                "profile error: profile read or compile error: sandbox-exec exited 65 "
                "and started no program, so nothing was denied -- a harness error, "
                "not a deny and not an allow. stderr='Operation not permitted\\n'",
            ),
            (
                "wrong exit",
                sbx.Result(
                    exit_code=2, stdout=DENY_STDOUT, stderr="", argv=["/private/devwr"],
                ),
                "wrong exit 2 is a harness error, not a deny and not an allow. "
                f"stdout={DENY_STDOUT!r} stderr=''",
            ),
        ]
        for name in OPENS:
            success_fd = stdout_with(name, 4, 1, 0)
            denied_fd = stdout_with(name, 2, -1, 1)
            denied_errno = stdout_with(name, -1, -1, 13)
            allowed_errno = stdout_with(name, 3, 1, 13)
            allowed_n = stdout_with(name, 3, 0, 0)
            denied_n = stdout_with(name, -1, 1, 1)
            rows = (
                (
                    f"successful {name} fd other than 3",
                    success_fd,
                    f"successful {name} fd other than 3 is a harness error, not an allow",
                ),
                (
                    f"denied {name} fd other than -1",
                    denied_fd,
                    f"denied {name} fd other than -1 is a harness error, not a deny",
                ),
                (
                    f"wrong {name} errno on a denied open",
                    denied_errno,
                    f"wrong {name} errno on a denied open is a harness error, not a deny",
                ),
                (
                    f"wrong {name} errno on an allowed open",
                    allowed_errno,
                    f"wrong {name} errno on an allowed open is a harness error, not an allow",
                ),
                (
                    f"{name} n other than 1 on an allowed open",
                    allowed_n,
                    f"{name} n other than 1 on an allowed open is a harness error, not an allow",
                ),
                (
                    f"{name} n other than -1 on a denied open",
                    denied_n,
                    f"{name} n other than -1 on a denied open is a harness error, not a deny",
                ),
            )
            for label, stdout, phrase in rows:
                samples.append((
                    label,
                    sbx.Result(
                        exit_code=0, stdout=stdout, stderr="", argv=["/private/devwr"],
                    ),
                    phrase + ": " + repr(stdout),
                ))
            for field, text, fd, n, err in (
                ("fd", "03", "03", 1, 0),
                ("n", "-0", 3, "-0", 0),
                ("errno", "01", -1, -1, "01"),
            ):
                label = f"noncanonical {name} {field} integer {text!r}"
                stdout = stdout_with(name, fd, n, err)
                samples.append((
                    label,
                    sbx.Result(
                        exit_code=0, stdout=stdout, stderr="", argv=["/private/devwr"],
                    ),
                    label + " is a harness error, not a deny and not an allow",
                ))
        samples.append((
            "nonempty deny stderr",
            sbx.Result(
                exit_code=0, stdout=DENY_STDOUT, stderr=noise, argv=["/private/devwr"],
            ),
            "nonempty deny stderr is a harness error, not a deny: " + repr(noise),
        ))
        samples.append((
            "nonempty allow stderr",
            sbx.Result(
                exit_code=0, stdout=NULL_WRITE_STDOUT, stderr=noise, argv=["/private/devwr"],
            ),
            "nonempty allow stderr is a harness error, not an allow: " + repr(noise),
        ))
        samples.append((
            "nonempty stderr",
            sbx.Result(
                exit_code=0, stdout="opened\n", stderr=noise, argv=["/private/devwr"],
            ),
            "nonempty stderr is a harness error, not a deny and not an allow: "
            f"stdout={'opened' + chr(10)!r} stderr={noise!r}",
        ))
        malformed = "opened\n"
        samples.append((
            "malformed stdout",
            sbx.Result(
                exit_code=0, stdout=malformed, stderr="", argv=["/private/devwr"],
            ),
            "malformed stdout is a harness error, not a deny and not an allow: "
            + repr(malformed),
        ))
        return tuple(samples)

    def test_classifier_refusal_reasons(self):
        """Each classifier refusal keeps its own reason. Nothing is launched.

        Exit 65 stays a profile error when stderr says ``Operation not
        permitted``. A success-shaped fd other than 3, a deny-shaped fd other
        than -1, a wrong errno, and an ``n`` other than 1 or -1 are harness
        errors. The allow is the union of the plants that are present.
        """
        _require_stdout_contract()
        self.assertEqual(
            classify(sbx.Result(
                exit_code=0, stdout=DENY_STDOUT, stderr="", argv=["/private/devwr"],
            )),
            "deny",
        )
        self.assertEqual(
            classify(sbx.Result(
                exit_code=0, stdout=ALL_STDOUT, stderr="", argv=["/private/devwr"],
            )),
            "allow",
        )
        self.assertEqual(opened_names(ALL_STDOUT), OPENS)
        self.assertEqual(
            opened_phrase(OPENS),
            "nullw, zerow, randw, nullrw, and zerorw",
        )
        for size in range(1, len(PLANT_ORDER) + 1):
            for combo in combinations(PLANT_ORDER, size):
                text = "(version 1)\n(deny default)\n" + "".join(
                    PLANT_LINE[name] for name in combo
                )
                granted = union_opens(combo)
                self.assertEqual(opens_for(text), granted)
                stdout = stdout_for(granted)
                self.assertEqual(
                    classify(sbx.Result(
                        exit_code=0, stdout=stdout, stderr="", argv=["/private/devwr"],
                    )),
                    "allow",
                )
                self.assertEqual(opened_names(stdout), granted)
                self.assertEqual(phrase_names(opened_phrase(granted)), granted)
        not_plants = (
            (WRITE_DATA_NULL, ("nullw",)),
            (WRITE_DATA_ZERO, ("zerow",)),
            (WRITE_DATA_RANDOM, ("randw",)),
            (RDWR_DATA_NULL, ("nullw", "nullrw")),
            (RDWR_DATA_ZERO, ("zerow", "zerorw")),
            (READ_DATA_WRITE_NULL, ("nullw", "nullrw")),
            (READ_WRITE_DATA_NULL, ("nullw", "nullrw")),
            (BARE_WRITE, ("nullw", "zerow", "randw")),
            (BARE_WRITE_DATA, ("nullw", "zerow", "randw")),
            (NULL_WRITE_LINE + READ_NULL, ("nullw", "nullrw")),
        )
        for line, granted in not_plants:
            self.assertEqual(
                opens_for("(version 1)\n(deny default)\n" + line),
                granted,
            )
        for line in (
            READ_NULL,
            READ_ZERO,
            READ_RANDOM,
            READ_URANDOM,
            "(allow mach-lookup)\n",
            "(allow iokit-open)\n",
            "(allow iokit-set-properties)\n",
            "(allow system-sched)\n",
            "(allow process-fork)\n",
            "(allow file-issue-extension)\n",
            "(allow ipc-posix-shm)\n",
            "(allow pseudo-tty)\n",
            "(allow signal)\n",
            "(allow sysctl-write)\n",
            "(allow system-fsctl)\n",
            "(allow file-ioctl)\n",
            ALLOW_NETWORK,
            '(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))\n',
        ):
            self.assertEqual(
                opens_for("(version 1)\n(deny default)\n" + line),
                (),
            )
        self.assertEqual(opens_for("(version 1)\n"), ())
        samples = self.refusal_samples()
        reasons = []
        for label, result, expected in samples:
            with self.subTest(label=label):
                if label == "profile error":
                    problem = sbx.profile_error(result)
                    self.assertIsNotNone(problem)
                    self.assertIn("65", problem)
                    self.assertIn("Operation not permitted", result.stderr)
                else:
                    self.assertIsNone(sbx.profile_error(result))
                with self.assertRaises(HarnessError) as caught:
                    classify(result)
                message = str(caught.exception)
                self.assertIn(label, message)
                self.assertEqual(message, expected)
                reasons.append(message)
        self.assertEqual(len(set(reasons)), len(samples))
        for message in reasons:
            hits = [label for label, _result, _expected in samples if label in message]
            self.assertEqual(len(hits), 1)
        parts = _LINE.fullmatch(DENY_STDOUT).groups()
        for index, part in enumerate(parts):
            name = OPENS[index // 3]
            field = ("fd", "n", "errno")[index % 3]
            expected = (
                f"unparseable {name} {field} integer {part!r} is a harness error, "
                "not a deny and not an allow"
            )
            with self.subTest(conversion=field, device=name), patch(
                __name__ + ".int",
                side_effect=[int(value) for value in parts[:index]] + [ValueError()],
                create=True,
            ):
                with self.assertRaises(HarnessError) as caught:
                    classify(sbx.Result(
                        exit_code=0, stdout=DENY_STDOUT, stderr="", argv=[],
                    ))
            self.assertEqual(str(caught.exception), expected)
        self.launch_guard.assert_not_called()

    def test_unsandboxed_failure_is_an_error(self):
        """A failed unsandboxed control is a harness error, not a skip.

        The deny line, each single-plant allow line, a nonzero exit, nonempty
        stderr, and a malformed line each raise ``HarnessError``. They launch
        nothing.
        """
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devwr-unsandboxed-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        binary = os.path.join(parent, BINARY_NAME)
        descriptor = os.open(binary, os.O_CREAT | os.O_WRONLY, 0o755)
        os.close(descriptor)
        binary = os.path.realpath(binary)
        cases = [
            (
                "unsandboxed deny",
                subprocess.CompletedProcess(
                    args=[binary], returncode=0, stdout=DENY_STDOUT, stderr="",
                ),
                "unsandboxed deny is a harness error, not a passing control: "
                + repr(DENY_STDOUT),
            ),
        ]
        for name in PLANT_ORDER:
            stdout = PLANT_STDOUT[name]
            cases.append((
                f"unsandboxed {name} allow",
                subprocess.CompletedProcess(
                    args=[binary], returncode=0, stdout=stdout, stderr="",
                ),
                "unsandboxed partial allow is a harness error, not a passing control: "
                + repr(stdout),
            ))
        cases.extend((
            (
                "wrong exit",
                subprocess.CompletedProcess(
                    args=[binary], returncode=2, stdout=ALL_STDOUT, stderr="",
                ),
                "wrong exit 2 is a harness error, not a deny and not an allow. "
                f"stdout={ALL_STDOUT!r} stderr=''",
            ),
            (
                "nonempty allow stderr",
                subprocess.CompletedProcess(
                    args=[binary], returncode=0, stdout=ALL_STDOUT, stderr="noise\n",
                ),
                "nonempty allow stderr is a harness error, not an allow: "
                + repr("noise\n"),
            ),
            (
                "malformed stdout",
                subprocess.CompletedProcess(
                    args=[binary], returncode=0, stdout="opened\n", stderr="",
                ),
                "malformed stdout is a harness error, not a deny and not an allow: "
                + repr("opened\n"),
            ),
        ))
        reasons = []
        for label, completed, expected in cases:
            with self.subTest(label=label):
                with patch.object(subprocess, "run", return_value=completed) as ran, patch.object(
                    sbx, "run", side_effect=AssertionError("sandbox-exec started")
                ) as sandbox:
                    with self.assertRaises(HarnessError) as caught:
                        run_unsandboxed(binary)
                    sandbox.assert_not_called()
                    ran.assert_called_once()
                message = str(caught.exception)
                self.assertEqual(message, expected)
                self.assertNotIsInstance(caught.exception, unittest.SkipTest)
                reasons.append(message)
        self.assertEqual(len(set(reasons)), len(cases))
        self.assertEqual(len(cases), 1 + len(PLANT_ORDER) + 3)
        self.launch_guard.assert_not_called()

    def test_observe_propagates_every_refusal(self):
        """A failed observation writes nothing and does not mark a deny test."""
        deny = sbx.Result(
            exit_code=0, stdout=DENY_STDOUT, stderr="", argv=["/private/devwr"],
        )
        for label, refused, expected in self.refusal_samples():
            for preceding in ([], [deny], [deny, deny]):
                with self.subTest(reason=label, position=len(preceding)):
                    class Observed(DevWriteProbe):
                        pass

                    with patch(
                        __name__ + ".write_under",
                        side_effect=preceding + [refused, deny],
                    ) as opened, patch(
                        __name__ + ".write_findings"
                    ) as writer, patch(__name__ + ".mark_expected") as marker:
                        with self.assertRaises(HarnessError) as caught:
                            observe(Observed)
                    self.assertEqual(str(caught.exception), expected)
                    self.assertEqual(opened.call_count, len(preceding) + 1)
                    writer.assert_not_called()
                    marker.assert_not_called()
                    self.assertEqual(Observed.recorded_allows, {})
        self.launch_guard.assert_not_called()

    def test_observe_records_allow_before_later_error(self):
        """A confirmed allow is written before the next profile is classified.

        Wallet allow, then a did profile error: the writer records the wallet
        allow, the wallet deny test is marked, and the error still propagates.
        Model is not opened. The clean paths stay unchanged.
        """
        live_names = (
            ROOT / "lab" / "redteam" / "CRITICAL.md",
            ROOT / FINDINGS["wallet"],
            ROOT / FINDINGS["model"],
        )
        before = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        allow = sbx.Result(
            exit_code=0,
            stdout=NULL_WRITE_STDOUT,
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/devwr"],
        )
        refused = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout="",
            stderr="Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb"],
        )
        self.assertEqual(classify(allow), "allow")
        with self.assertRaises(HarnessError) as sample:
            classify(refused)
        expected = str(sample.exception)
        self.assertIn("profile error", expected)
        self.assertIn("Operation not permitted", expected)

        def run_case(results):
            class Observed(DevWriteProbe):
                pass

            pending = list(results)
            order = []

            def opened(path):
                order.append(("open", path))
                return pending.pop(0)

            def written(_repo, items):
                order.append(("write", [item[0]["name"] for item in items]))

            with patch(__name__ + ".write_under", side_effect=opened), patch(
                __name__ + ".write_findings", side_effect=written
            ), patch(__name__ + ".mark_expected", wraps=mark_expected) as marker:
                with self.assertRaises(HarnessError) as caught:
                    observe(Observed)
            self.assertEqual(str(caught.exception), expected)
            return Observed, marker, order

        wallet, did, model = PROFILES
        observed = None
        try:
            observed, marker, order = run_case([allow, refused])
            self.assertEqual(
                order,
                [
                    ("open", wallet["path"]),
                    ("write", ["wallet"]),
                    ("open", did["path"]),
                ],
            )
            self.assertEqual(observed.recorded_allows, {"wallet": FINDINGS["wallet"]})
            self.assertEqual(marker.call_count, 1)
            method = observed.test_wallet_dev_write_is_denied
            self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
            self.assertIn(FINDINGS["wallet"], method.__doc__ or "")
            self.assertNotIn("model", observed.recorded_allows)
        finally:
            if observed is not None:
                observed.doClassCleanups()

        second = sbx.Result(
            exit_code=0,
            stdout=ZERO_WRITE_STDOUT,
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/devwr"],
        )
        observed = None
        try:
            observed, marker, order = run_case([allow, second, refused])
            self.assertEqual(
                order,
                [
                    ("open", wallet["path"]),
                    ("write", ["wallet"]),
                    ("open", did["path"]),
                    ("write", ["wallet", "did"]),
                    ("open", model["path"]),
                ],
            )
            self.assertEqual(
                observed.recorded_allows,
                {"wallet": FINDINGS["wallet"], "did": FINDINGS["did"]},
            )
            self.assertNotIn("model", observed.recorded_allows)
            self.assertEqual(marker.call_count, 2)
        finally:
            if observed is not None:
                observed.doClassCleanups()
        for path in live_names:
            self.assertEqual(
                path.read_bytes() if path.is_file() else None, before[path],
            )
        self.launch_guard.assert_not_called()

    def test_recorded_allow_is_expected_failure(self):
        """A recorded allow is an expected failure whose docstring names the finding.

        The wallet deny test is marked for each injected plant. That docstring
        names ``CRITICAL-confine-069.md``. The model deny test is marked for
        the null read-write plant and names
        ``CRITICAL-cc-model-confine-069.md``. A unittest run of each injected
        allow is one expected failure. ``require_finding_pins`` raises when
        only the PR label is dropped, and when only ``result.command`` is
        dropped. The clean run writes no finding.
        """
        provenance = self.enter_patch(patch(__name__ + ".last_change", return_value="a" * 40))
        self.enter_patch(patch(__name__ + ".pr_label", return_value="PR fixture"))
        self.enter_patch(patch(__name__ + ".sha256_file", return_value="b" * 64))
        command_argv = [sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/devwr"]

        def allow_for(opens):
            return sbx.Result(
                exit_code=0,
                stdout=stdout_for(opens),
                stderr="",
                argv=list(command_argv),
            )

        wallet = PROFILES[0]
        did = PROFILES[1]
        model = PROFILES[2]
        self.assertEqual(wallet["name"], "wallet")
        self.assertEqual(did["name"], "did")
        self.assertEqual(model["name"], "model")
        full = allow_for(OPENS)
        self.assertTrue(full.command)
        paragraph = finding_paragraph(wallet, full)
        label = pr_label(last_change(wallet["path"]))
        first = paragraph.splitlines()[0]
        self.assertIn("CRITICAL", first)
        self.assertIn(last_change(wallet["path"]), first)
        self.assertIn(label, first)
        self.assertIn(sha256_file(wallet["path"]), first)
        self.assertEqual(paragraph.splitlines()[1], f"profile: {wallet['rel']}")
        self.assertEqual(paragraph.splitlines()[2], f"helper: {full.command}")
        self.assertEqual(
            paragraph.splitlines()[3], f"observed: {full.stdout.strip()}",
        )
        self.assertEqual(phrase_names(paragraph.splitlines()[4]), OPENS)
        self.assertEqual(paragraph.count(label), 1)
        self.assertEqual(paragraph.count(full.command), 1)
        require_finding_pins(paragraph, wallet, full)
        pr_omitted = paragraph.replace(label, "", 1)
        with self.assertRaises(AssertionError) as omitted_pr:
            require_finding_pins(pr_omitted, wallet, full)
        self.assertEqual(str(omitted_pr.exception), "finding omits pr_label")
        self.assertIn(full.command, pr_omitted)
        command_omitted = paragraph.replace(full.command, "", 1)
        with self.assertRaises(AssertionError) as omitted_command:
            require_finding_pins(command_omitted, wallet, full)
        self.assertEqual(str(omitted_command.exception), "finding omits command")
        self.assertIn(label, command_omitted)
        for name in PLANT_ORDER:
            planted = allow_for(PLANT_OPENS[name])
            body = finding_paragraph(wallet, planted)
            self.assertEqual(
                phrase_names(body.split("opened: ", 1)[1].split("\n", 1)[0]),
                PLANT_OPENS[name],
            )
            require_finding_pins(body, wallet, planted)
        model_allow = allow_for(PLANT_OPENS["null-rdwr"])
        model_paragraph = finding_paragraph(model, model_allow)
        self.assertIn("CRITICAL-cc-model-confine-069", model_paragraph.splitlines()[0])
        self.assertEqual(
            phrase_names(model_paragraph.split("opened: ", 1)[1].split("\n", 1)[0]),
            ("nullw", "nullrw"),
        )
        require_finding_pins(model_paragraph, model, model_allow)
        live_names = (
            ROOT / "lab" / "redteam" / "CRITICAL.md",
            ROOT / FINDINGS["wallet"],
            ROOT / FINDINGS["model"],
        )
        before = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        with tempfile.TemporaryDirectory(prefix="ccrt-devwr-finding-") as tmp:
            repo = Path(tmp)
            self.assertEqual(write_findings(repo, []), [])
            self.assertFalse((repo / "lab" / "redteam" / "CRITICAL.md").exists())
            wallet_allow = allow_for(PLANT_OPENS["null-write"])
            did_allow = allow_for(PLANT_OPENS["zero-write"])
            written = write_findings(repo, [(wallet, wallet_allow), (did, did_allow)])
            self.assertEqual(written, [FINDINGS["wallet"]])
            self.assertFalse((repo / FINDINGS["model"]).exists())
            body = (repo / FINDINGS["wallet"]).read_text(encoding="utf-8")
            wallet_paragraph = finding_paragraph(wallet, wallet_allow)
            did_paragraph = finding_paragraph(did, did_allow)
            self.assertEqual(body, wallet_paragraph + did_paragraph)
            listed = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertIn(wallet_paragraph, listed)
            self.assertIn(did_paragraph, listed)
            model_written = write_findings(repo, [(model, model_allow)])
            self.assertEqual(model_written, [FINDINGS["model"]])
            self.assertEqual(
                (repo / FINDINGS["model"]).read_text(encoding="utf-8"),
                model_paragraph,
            )
            listed_again = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(
                encoding="utf-8",
            )
            self.assertEqual(listed_again.count(model_paragraph), 1)
            again = write_findings(repo, [(model, model_allow)])
            relisted = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertEqual(relisted, listed_again)
            self.assertEqual(again, [FINDINGS["model"]])
        after = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        self.assertEqual(before, after)

        def run_marked(profile_name, opens, finding_name):
            method_name = f"test_{profile_name}_dev_write_is_denied"

            class Recorded(DevWriteProbe):
                skip_reason = None

            mark_expected(Recorded, method_name, FINDINGS[profile_name])
            method = getattr(Recorded, method_name)
            self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
            self.assertIn(finding_name, method.__doc__)
            if profile_name == "model":
                self.assertIn("CRITICAL-cc-model-confine-069.md", method.__doc__)
            else:
                self.assertIn("CRITICAL-confine-069.md", method.__doc__)
                self.assertNotIn("cc-model", method.__doc__)
            recorded = unittest.TestResult()
            try:
                with patch(
                    __name__ + ".write_under", return_value=allow_for(opens),
                ), patch.object(os.path, "isfile", return_value=True):
                    Recorded(method_name).run(recorded)
            finally:
                Recorded.doClassCleanups()
            self.assertEqual(len(recorded.expectedFailures), 1)
            self.assertEqual(recorded.failures, [])
            self.assertEqual(recorded.errors, [])
            self.assertEqual(recorded.unexpectedSuccesses, [])
            self.assertEqual(recorded.skipped, [])
            self.assertTrue(recorded.wasSuccessful())

        for name in PLANT_ORDER:
            run_marked("wallet", PLANT_OPENS[name], "CRITICAL-confine-069.md")
        run_marked("model", PLANT_OPENS["null-rdwr"], "CRITICAL-cc-model-confine-069.md")
        self.assertEqual(
            {call.args[0] for call in provenance.call_args_list},
            {wallet["path"], did["path"], model["path"]},
        )
        self.launch_guard.assert_not_called()

    def test_wallet_controls_reject_allow_with_or_without_finding(self):
        """Each still-denies wallet copy fails on an allow, with or without a finding.

        The failure is ordinary. A recorded wallet allow does not excuse it.
        """
        stills = [stem for stem, _kind, _rule, opens in NULL_WRITE_COPIES if not opens]
        expected_names = launch_names("null-write", NULL_WRITE_COPIES)
        self.assertEqual(len(stills), 18)
        for recorded in (False, True):
            for control in stills:
                with self.subTest(recorded=recorded, control=control), tempfile.TemporaryDirectory(
                    prefix="ccrt-devwr-control-"
                ) as tmp:
                    profiles = []
                    for original in PROFILES:
                        profile = dict(original)
                        profile["path"] = Path(tmp) / f"{profile['name']}.sb"
                        text = "(version 1)\n(deny default)\n(deny network*)\n"
                        if recorded and profile["name"] == "wallet":
                            text += NULL_WRITE_LINE
                        profile["path"].write_text(text, encoding="utf-8")
                        profiles.append(profile)

                    class Control(DevWriteProbe):
                        skip_reason = None
                        recorded_allows = {}

                    if recorded:
                        finding = FINDINGS["wallet"]
                        Control.recorded_allows["wallet"] = finding
                        mark_expected(
                            Control, "test_wallet_dev_write_is_denied", finding,
                        )
                        method = Control.test_wallet_dev_write_is_denied
                        self.assertTrue(
                            getattr(method, "__unittest_expecting_failure__", False)
                        )
                        self.assertIn("CRITICAL-confine-069.md", method.__doc__ or "")

                    opened = []

                    def injected_open(profile, chosen=control):
                        path = Path(profile)
                        opened.append(path.name)
                        if path.stem == chosen:
                            stdout = ALL_STDOUT
                        else:
                            stdout = stdout_for(opens_for(path.read_text(encoding="utf-8")))
                        return sbx.Result(
                            exit_code=0,
                            stdout=stdout,
                            stderr="",
                            argv=[
                                sbx.SANDBOX_EXEC,
                                "-f",
                                os.fspath(path),
                                "/private/devwr",
                            ],
                        )

                    result = unittest.TestResult()
                    try:
                        with patch(__name__ + ".PROFILES", tuple(profiles)), patch(
                            __name__ + ".write_under", side_effect=injected_open
                        ):
                            Control("test_falsifier_allow_null_write_is_caught").run(result)
                    finally:
                        Control.doClassCleanups()
                    self.assertEqual(result.testsRun, 1)
                    self.assertEqual(result.errors, [])
                    self.assertEqual(result.skipped, [])
                    self.assertEqual(result.expectedFailures, [])
                    self.assertEqual(result.unexpectedSuccesses, [])
                    self.assertEqual(len(result.failures), 1)
                    failed, caught = result.failures[0]
                    self.assertEqual(failed.params["profile"], control)
                    self.assertIn("NotDenied", caught)
                    self.assertIn("ALLOW", caught)
                    self.assertIn(control + ".sb", caught)
                    self.assertIn("nullw fd=3 n=1 errno=0", caught)
                    self.assertFalse(result.wasSuccessful())
                    self.assertEqual(opened, expected_names)
        self.launch_guard.assert_not_called()

    def test_recorded_allow_keeps_complete_probe_suite_green(self):
        """Run every probe test with injected tools and profile text.

        Scenarios are no allow and every non-empty subset of the five plants
        on each profile. The allow is the union of the plants that are
        present. Only the deny test of a profile that contains a plant line
        is an expected failure. The plants still run, nothing skips, and the
        result is successful. The finding names every open that returned the
        success triple. The clean run writes no finding.
        """
        method_names = unittest.defaultTestLoader.getTestCaseNames(DevWriteProbe)
        scenarios = [((), None), ((), b"CRITICAL fixture from another probe\n")]
        for profile_name in ("wallet", "did", "model"):
            for size in range(1, len(PLANT_ORDER) + 1):
                for combo in combinations(PLANT_ORDER, size):
                    scenarios.append((((profile_name, combo),), None))
        self.assertEqual(len(scenarios), 2 + 3 * (2 ** len(PLANT_ORDER) - 1))
        for grants, existing_critical in scenarios:
            allowed = {}
            for profile_name, combo in grants:
                allowed[profile_name] = combo
            with self.subTest(allowed=tuple(allowed.items())), tempfile.TemporaryDirectory(
                prefix="ccrt-devwr-suite-"
            ) as tmp:
                repo = Path(tmp).resolve()
                critical = repo / "lab/redteam/CRITICAL.md"
                if existing_critical is not None:
                    critical.parent.mkdir(parents=True, exist_ok=True)
                    critical.write_bytes(existing_critical)
                profiles = []
                for original in PROFILES:
                    profile = dict(original)
                    profile["path"] = repo / profile["rel"]
                    profile["path"].parent.mkdir(parents=True, exist_ok=True)
                    text = "(version 1)\n(deny default)\n(deny network*)\n"
                    planted = allowed.get(profile["name"], ())
                    for name in PLANT_ORDER:
                        if name in planted:
                            text += PLANT_LINE[name]
                    profile["path"].write_text(text, encoding="utf-8")
                    profiles.append(profile)

                def injected_compile(parent, root, source_text):
                    if source_text == "":
                        raise HarnessError(
                            f"{CC} failed with exit 1: no compiler output "
                            "-- a harness error, not a skip and not a deny"
                        )
                    source = Path(parent, SOURCE_NAME)
                    with open(source, "w", encoding="utf-8", newline="\n") as handle:
                        handle.write(source_text)
                    binary = Path(root, BINARY_NAME)
                    binary.write_text(
                        "injected executable; never launched\n", encoding="utf-8",
                    )
                    binary.chmod(0o755)
                    return str(binary)

                def injected_control(binary):
                    return sbx.Result(
                        exit_code=0,
                        stdout=ALL_STDOUT,
                        stderr="",
                        argv=[binary],
                    )

                launched = []

                def injected_sandbox(**kwargs):
                    launched.append(os.fspath(kwargs["profile"]))
                    self.assertEqual(kwargs["pinned_exe"], kwargs["launch_exe"])
                    self.assertEqual(kwargs["timeout"], 5)
                    self.assertEqual(tuple(kwargs["args"]), ())
                    text = Path(kwargs["profile"]).read_text(encoding="utf-8")
                    return sbx.Result(
                        exit_code=0,
                        stdout=stdout_for(opens_for(text)),
                        stderr="",
                        argv=[
                            sbx.SANDBOX_EXEC,
                            "-D", f"PROVIDER_EXECUTABLE={kwargs['pinned_exe']}",
                            "-D", f"STORAGE_ROOT={kwargs['storage_root']}",
                            "-D", f"STORAGE_PARENT={kwargs['storage_parent']}",
                            "-f", os.fspath(kwargs["profile"]),
                            kwargs["launch_exe"],
                            *kwargs["args"],
                        ],
                    )

                with patch(__name__ + ".ROOT", repo), patch(
                    __name__ + ".PROFILES", tuple(profiles)
                ), patch.dict(
                    START_SHA, {}, clear=True
                ), patch.object(sbx, "REPO_ROOT", repo), patch.object(
                    sbx, "WALLET_CONFINE_SB", profiles[0]["path"]
                ), patch.object(os.path, "isfile", return_value=True), patch(
                    __name__ + ".compile_devwr", side_effect=injected_compile
                ), patch(__name__ + ".run_unsandboxed", side_effect=injected_control), patch.object(
                    sbx, "run", side_effect=injected_sandbox
                ), patch(__name__ + ".last_change", return_value="a" * 40), patch(
                    __name__ + ".pr_label", return_value="PR fixture"
                ), patch.multiple(
                    DevWriteProbe,
                    binary=None,
                    root=None,
                    parent=None,
                    skip_reason=None,
                    recorded_allows={},
                ):
                    result = unittest.TestResult()
                    unittest.defaultTestLoader.loadTestsFromTestCase(DevWriteProbe).run(result)
                    self.assertEqual(result.testsRun, len(method_names))
                    self.assertEqual(result.errors, [])
                    self.assertEqual(result.failures, [])
                    self.assertEqual(result.unexpectedSuccesses, [])
                    self.assertEqual(result.skipped, [])
                    self.assertIsNone(skip_reason())
                    self.assertEqual(len(result.expectedFailures), len(allowed))
                    self.assertEqual(
                        {case._testMethodName for case, _error in result.expectedFailures},
                        {f"test_{name}_dev_write_is_denied" for name in allowed},
                    )
                    for label, copies in PLANT_COPIES.items():
                        for stem in launch_names(label, copies):
                            self.assertTrue(
                                any(path.endswith(os.sep + stem) for path in launched),
                                stem,
                            )
                    self.assertTrue(result.wasSuccessful())
                    self.assertEqual(
                        DevWriteProbe.recorded_allows,
                        {name: FINDINGS[name] for name in allowed},
                    )
                    for name, planted in allowed.items():
                        body = (repo / FINDINGS[name]).read_text(encoding="utf-8")
                        profile = next(item for item in profiles if item["name"] == name)
                        granted = union_opens(planted)
                        opened_line = next(
                            line for line in body.splitlines() if line.startswith("opened: ")
                        )
                        self.assertEqual(phrase_names(opened_line), granted)
                        self.assertEqual(opened_line, "opened: " + opened_phrase(granted))
                        self.assertIn(sha256_file(profile["path"]), body)
                        self.assertIn(pr_label(last_change(profile["path"])), body)
                        self.assertIn(f"profile: {profile['rel']}", body)
                        helper_line = next(
                            line for line in body.splitlines() if line.startswith("helper: ")
                        )
                        self.assertIn(sbx.SANDBOX_EXEC, helper_line)
                        self.assertIn(DevWriteProbe.binary, helper_line)
                        self.assertIn(
                            body,
                            (repo / "lab/redteam/CRITICAL.md").read_text(encoding="utf-8"),
                        )
                    if not allowed:
                        if existing_critical is None:
                            self.assertFalse(critical.exists())
                        else:
                            self.assertEqual(critical.read_bytes(), existing_critical)
                        for rel in set(FINDINGS.values()):
                            self.assertFalse((repo / rel).exists())
                    else:
                        if "model" not in allowed:
                            self.assertFalse((repo / FINDINGS["model"]).exists())
                        if "wallet" not in allowed and "did" not in allowed:
                            self.assertFalse((repo / FINDINGS["wallet"]).exists())
                self.launch_guard.assert_not_called()

    def test_harness_error_stays_error(self):
        """A harness error stays an error after a recorded allow. It is not a skip."""
        allow = sbx.Result(
            exit_code=0,
            stdout=NULL_WRITE_STDOUT,
            stderr="",
            argv=["/private/devwr"],
        )
        deny = sbx.Result(
            exit_code=0, stdout=DENY_STDOUT, stderr="", argv=["/private/devwr"],
        )
        for profile in PROFILES:
            for label, refused, expected in self.refusal_samples():
                with self.subTest(profile=profile["name"], reason=label):
                    class Recorded(DevWriteProbe):
                        skip_reason = None

                    def observation(path, chosen=profile):
                        return allow if path == chosen["path"] else deny

                    with patch(__name__ + ".write_under", side_effect=observation), patch(
                        __name__ + ".write_findings"
                    ) as writer:
                        observe(Recorded)
                    writer.assert_called_once_with(ROOT, [(profile, allow)])
                    method_name = f"test_{profile['name']}_dev_write_is_denied"
                    method = getattr(Recorded, method_name)
                    self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
                    self.assertIn(FINDINGS[profile["name"]], method.__doc__)
                    result = unittest.TestResult()
                    try:
                        with patch(
                            __name__ + ".write_under", side_effect=[refused, deny]
                        ) as opened, patch.object(
                            os.path, "isfile", return_value=True
                        ), patch.object(result, "addError", wraps=result.addError) as added:
                            Recorded(method_name).run(result)
                        self.assertEqual(opened.call_count, 1)
                        self.assertEqual(len(result.errors), 1)
                        self.assertEqual(str(added.call_args.args[1][1]), expected)
                        self.assertEqual(result.failures, [])
                        self.assertEqual(result.expectedFailures, [])
                        self.assertEqual(result.unexpectedSuccesses, [])
                        self.assertEqual(result.skipped, [])
                        self.assertFalse(result.wasSuccessful())
                    finally:
                        Recorded.doClassCleanups()
        self.launch_guard.assert_not_called()

    def test_unresolved_storage_path_is_an_error(self):
        """A ``/var/folders`` storage path without ``/private`` errors before launch."""
        bad_parent = "/var/folders/cc/devwr-parent"
        bad_root = "/var/folders/cc/devwr-root"
        calls = []

        def refuse_run(*args, **kwargs):
            calls.append(("run", args, kwargs))
            raise AssertionError("sandbox-exec started")

        def refuse_subprocess(*args, **kwargs):
            calls.append(("subprocess", args, kwargs))
            raise AssertionError("cc started")

        original_run = sbx.run
        original_subprocess = subprocess.run
        sbx.run = refuse_run
        subprocess.run = refuse_subprocess
        try:
            with self.assertRaises(HarnessError) as compile_caught:
                compile_devwr(
                    bad_parent,
                    "/private/devwr-root",
                    "int main(void) { return 0; }\n",
                )
            compile_message = str(compile_caught.exception)
            self.assertIn(bad_parent, compile_message)
            self.assertIn("/var/folders", compile_message)
            self.assertNotIn("/private" + bad_parent, compile_message)

            with self.assertRaises(HarnessError) as launch_caught:
                run_sandboxed(
                    "/private/devwr",
                    bad_root,
                    "/private/devwr-parent",
                    sbx.WALLET_CONFINE_SB,
                )
            launch_message = str(launch_caught.exception)
            self.assertIn(bad_root, launch_message)
            self.assertIn("/var/folders", launch_message)
            self.assertNotIn("/private" + bad_root, launch_message)
        finally:
            sbx.run = original_run
            subprocess.run = original_subprocess
        self.assertEqual(calls, [])
        self.launch_guard.assert_not_called()


if __name__ == "__main__":
    unittest.main()
