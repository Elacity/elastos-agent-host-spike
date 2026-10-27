"""Probe read-only opens of /dev/zero, /dev/random, /dev/dtracehelper, and /dev/ptmx.

Grade row 12 rests on the wallet, did, and model seatbelt profiles. No merged
probe opens these four devices. This module compiles one helper and runs it
under each live ``confine.sb``. Confined launches go through ``sbx.run`` only.
The helper prints one line and returns 0. It reads 16 bytes from ``/dev/zero``
and ``/dev/random``. It opens ``/dev/dtracehelper`` and ``/dev/ptmx`` read-only
and closes them without reading. It opens no socket and uses no secrets.

A deny is stdout ``zero fd=-1 n=-1 errno=1 random fd=-1 n=-1 errno=1 dtrace
fd=-1 n=-1 errno=1 ptmx fd=-1 n=-1 errno=1`` and empty stderr. One plant opens
only that device. Two-device and three-device opens are allows through the
same classifier and the same finding path. The finding names every device
that opened. All four open is ``zero fd=3 n=16 errno=0 random fd=3 n=16
errno=0 dtrace fd=3 n=-1 errno=0 ptmx fd=3 n=-1 errno=0``. Any other fd, a
short read of zero or random, a dtrace or ptmx ``n`` other than -1, a wrong
errno, a nonzero exit, nonempty stderr, and a malformed line are harness
errors.

The three profiles are the live files. ``setUpModule`` records each sha256.
``tearDownModule`` and each falsifier's end check call ``require_unchanged``,
which compares the digest through ``changed`` from ``test_confine_mach``.
An owner edit between those two points raises ``the probe changed <rel>``.
A difference from an older measurement is not a failure. This file stores
no commit, pull request, or digest.

An allow on a real profile is CRITICAL. Wallet or did:
``findings/CRITICAL-confine-062.md``. Model:
``findings/CRITICAL-cc-model-confine-062.md``. The finding's first line
contains CRITICAL and names the commit from ``git log -1 --format=%H HEAD
-- <file>`` plus the sha256 of the bytes this run read. It names which
devices opened. The same paragraph is appended to ``CRITICAL.md``. With no
allow, this module writes neither file.

A recorded allow keeps the gate green. The deny test is an expected
failure and its docstring names that finding file (README guard b).
Each confirmed allow is written before the next profile is classified.
A later harness error still fails the gate. The plant still runs.
A recorded allow is not a skip. This module skips only when
``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` is missing.
A profile error, a failed compile, a failed unsandboxed control, nonempty
stderr, and an exit other than 0 are harness errors. They are not a deny
and they are not a skip.

``DevOpenProbe`` compiles and launches. It skips only when
``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` is missing, and the reason
names that path. ``DevOpenRules`` does not compile and does not launch.
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
SOURCE_NAME = "devop.c"
BINARY_NAME = "devop"
DENY_STDOUT = (
    "zero fd=-1 n=-1 errno=1 random fd=-1 n=-1 errno=1 "
    "dtrace fd=-1 n=-1 errno=1 ptmx fd=-1 n=-1 errno=1\n"
)
ALL_STDOUT = (
    "zero fd=3 n=16 errno=0 random fd=3 n=16 errno=0 "
    "dtrace fd=3 n=-1 errno=0 ptmx fd=3 n=-1 errno=0\n"
)
DENY_DEFAULT = "(deny default)\n"
DENY_NETWORK = "(deny network*)\n"
ALLOW_NETWORK = "(allow network*)\n"
MACH_LOOKUP = "(allow mach-lookup)\n"
PSEUDO_TTY = "(allow pseudo-tty)\n"
SUBPATH_DEV = '(allow file-read* (subpath "/dev"))\n'
URANDOM_ALLOW = '(allow file-read* (literal "/dev/urandom"))\n'
NULL_ALLOW = '(allow file-read* (literal "/dev/null"))\n'

# name, path, whether a successful open also reads 16 bytes.
DEVICES = (
    ("zero", "/dev/zero", True),
    ("random", "/dev/random", True),
    ("dtrace", "/dev/dtracehelper", False),
    ("ptmx", "/dev/ptmx", False),
)
DEVICE_NAMES = tuple(name for name, _path, _read in DEVICES)
PLANTS = {
    name: f'(allow file-read* (literal "{path}"))\n'
    for name, path, _read in DEVICES
}
PLANT_LINES = tuple((line.rstrip("\n"), line) for line in PLANTS.values())
READ_DATA = {
    name: f'(allow file-read-data (literal "{path}"))\n'
    for name, path, _read in DEVICES
}
READ_WRITE = {
    name: f'(allow file-read* file-write* (literal "{path}"))\n'
    for name, path, _read in DEVICES
}
WRITE_ONLY = {
    name: f'(allow file-write* (literal "{path}"))\n'
    for name, path, _read in DEVICES
}
# kind, copy stem, devices that open. Empty means the copy still denies all four.
EXTRAS = {
    "zero": (
        ("read-data", "wallet-read-data-zero", ("zero",)),
        ("write", "wallet-write-zero", ()),
        ("deleted", "wallet-deleted", ()),
        ("lookup", "wallet-lookup", ()),
        ("network", "wallet-network", ()),
    ),
    "random": (
        ("read-data", "wallet-read-data-random", ("random",)),
        ("write", "wallet-write-random", ()),
        ("urandom", "wallet-urandom", ()),
        ("null", "wallet-null", ()),
    ),
    "dtrace": (
        ("read-data", "wallet-read-data-dtrace", ("dtrace",)),
        ("read-write", "wallet-rw-dtrace", ("dtrace",)),
        ("write", "wallet-write-dtrace", ()),
        ("pseudo-tty", "wallet-pty", ()),
    ),
    "ptmx": (
        ("read-data", "wallet-read-data-ptmx", ("ptmx",)),
        ("read-write", "wallet-rw-ptmx", ("ptmx",)),
        ("subpath", "wallet-subpath", DEVICE_NAMES),
        ("write", "wallet-write-ptmx", ()),
    ),
}

HELPER_C = r"""#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
static void open_one(const char *path, int want_read, int *fd_out, int *n_out, int *err_out) {
    unsigned char buf[16];
    int err = 0;
    int n = -1;
    errno = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        err = errno;
    } else if (want_read) {
        n = (int)read(fd, buf, 16);
        if (n < 0) {
            err = errno;
        }
        close(fd);
    } else {
        close(fd);
    }
    *fd_out = fd;
    *n_out = n;
    *err_out = err;
}
int main(void) {
    int zfd, zn, zerr, rfd, rn, rerr, dfd, dn, derr, pfd, pn, perr;
    open_one("/dev/zero", 1, &zfd, &zn, &zerr);
    open_one("/dev/random", 1, &rfd, &rn, &rerr);
    open_one("/dev/dtracehelper", 0, &dfd, &dn, &derr);
    open_one("/dev/ptmx", 0, &pfd, &pn, &perr);
    printf("zero fd=%d n=%d errno=%d random fd=%d n=%d errno=%d dtrace fd=%d n=%d errno=%d ptmx fd=%d n=%d errno=%d\n",
        zfd, zn, zerr, rfd, rn, rerr, dfd, dn, derr, pfd, pn, perr);
    return 0;
}
"""

FINDINGS = {
    "wallet": "lab/redteam/findings/CRITICAL-confine-062.md",
    "did": "lab/redteam/findings/CRITICAL-confine-062.md",
    "model": "lab/redteam/findings/CRITICAL-cc-model-confine-062.md",
}
IDS = {
    "wallet": "CRITICAL-confine-062",
    "did": "CRITICAL-confine-062",
    "model": "CRITICAL-cc-model-confine-062",
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
_LINE = re.compile(
    r"zero fd=(-?[0-9]+) n=(-?[0-9]+) errno=(-?[0-9]+) "
    r"random fd=(-?[0-9]+) n=(-?[0-9]+) errno=(-?[0-9]+) "
    r"dtrace fd=(-?[0-9]+) n=(-?[0-9]+) errno=(-?[0-9]+) "
    r"ptmx fd=(-?[0-9]+) n=(-?[0-9]+) errno=(-?[0-9]+)\n"
)

START_SHA = {}


class NotDenied(AssertionError):
    """The profile opened one or more of the four host devices."""

    def __init__(self, result):
        self.result = result
        super().__init__(
            "ALLOW: the profile opened a host device.\n"
            f"  cmd: {result.command}\n"
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
    """Reject an unresolved path before a launch.

    The check is ``require_resolved`` from the mach probe. A path that
    contains ``/var/folders`` and does not start with ``/private`` is a
    harness error. Resolving it here would hide that path.
    """
    try:
        return require_resolved(path)
    except MachHarnessError as caught:
        raise HarnessError(str(caught)) from caught


def stdout_for_names(opened):
    """The helper line for this set of opened devices. Others stay denied."""
    chosen = set(opened)
    parts = []
    for name, _path, want_read in DEVICES:
        if name in chosen:
            read_n = 16 if want_read else -1
            parts.append(f"{name} fd=3 n={read_n} errno=0")
        else:
            parts.append(f"{name} fd=-1 n=-1 errno=1")
    return " ".join(parts) + "\n"


def stdout_with(device, fd, n, err):
    """One device replaced. The other three stay on the deny triple."""
    parts = []
    for name, _path, _read in DEVICES:
        if name == device:
            parts.append(f"{name} fd={fd} n={n} errno={err}")
        else:
            parts.append(f"{name} fd=-1 n=-1 errno=1")
    return " ".join(parts) + "\n"


def outcome_name(opened):
    """``deny``, ``all``, or the opened names joined in device order."""
    chosen = tuple(name for name in DEVICE_NAMES if name in set(opened))
    if not chosen:
        return "deny"
    if chosen == DEVICE_NAMES:
        return "all"
    return "+".join(chosen)


def parse_line(stdout):
    """Four tuples, or None for a malformed line; numeric text must be canonical."""
    match = _LINE.fullmatch(stdout)
    if match is None:
        return None
    numbers = []
    for index, part in enumerate(match.groups()):
        name = DEVICE_NAMES[index // 3]
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
        numbers.append(number)
    parsed = []
    for index, (name, _path, want_read) in enumerate(DEVICES):
        fd, n, err = numbers[index * 3:(index + 1) * 3]
        parsed.append((name, fd, n, err, want_read))
    return parsed


def triple_state(name, fd, n, err, want_read):
    """``deny``, ``allow``, or the harness reason for this one device."""
    if fd not in (-1, 3):
        return f"wrong {name} fd is a harness error, not a deny and not an allow"
    if want_read:
        if fd == 3 and 0 <= n < 16:
            return f"short {name} read is a harness error, not an allow"
        if fd == -1 and err != 1:
            return f"wrong {name} errno is a harness error, not a deny"
        if fd == 3 and err != 0:
            return f"wrong {name} open errno is a harness error, not an allow"
        if fd == -1 and n != -1:
            return (
                f"wrong {name} read is a harness error, not a deny and not an allow"
            )
        if fd == 3 and n != 16:
            return (
                f"wrong {name} read is a harness error, not a deny and not an allow"
            )
        if (fd, n, err) == (-1, -1, 1):
            return "deny"
        if (fd, n, err) == (3, 16, 0):
            return "allow"
    else:
        if n != -1:
            return (
                f"{name} n other than -1 is a harness error, "
                "not a deny and not an allow"
            )
        if fd == -1 and err != 1:
            return f"wrong {name} errno is a harness error, not a deny"
        if fd == 3 and err != 0:
            return f"wrong {name} open errno is a harness error, not an allow"
        if (fd, n, err) == (-1, -1, 1):
            return "deny"
        if (fd, n, err) == (3, -1, 0):
            return "allow"
    return (
        f"malformed {name} triple is a harness error, not a deny and not an allow"
    )


def line_problem(stdout):
    """A distinct harness reason for a line that is not deny or allow."""
    parsed = parse_line(stdout)
    if parsed is None:
        return (
            "malformed stdout is a harness error, not a deny and not an allow: "
            + repr(stdout)
        )
    for name, fd, n, err, want_read in parsed:
        state = triple_state(name, fd, n, err, want_read)
        if state not in ("deny", "allow"):
            return state + ": " + repr(stdout)
    return (
        "malformed stdout is a harness error, not a deny and not an allow: "
        + repr(stdout)
    )


def opened_names(stdout):
    """Device names a confirmed allow opened, in helper order."""
    parsed = parse_line(stdout)
    if parsed is None:
        raise HarnessError("finding stdout is not an allow: " + repr(stdout))
    opened = []
    for name, fd, n, err, want_read in parsed:
        state = triple_state(name, fd, n, err, want_read)
        if state == "allow":
            opened.append(name)
        elif state != "deny":
            raise HarnessError("finding stdout is not an allow: " + repr(stdout))
    if not opened:
        raise HarnessError("finding stdout is not an allow: " + repr(stdout))
    return tuple(opened)


def opened_phrase(names):
    """Every opened device, in helper order, on one finding line."""
    paths = [path for name, path, _read in DEVICES if name in set(names)]
    if not paths:
        raise HarnessError("finding names no device")
    if len(paths) == 1:
        return paths[0]
    if len(paths) == 2:
        return f"{paths[0]} and {paths[1]}"
    return ", ".join(paths[:-1]) + ", and " + paths[-1]


def classify(result):
    """``deny``, ``all``, or the opened-device names. Otherwise a harness error.

    Asks ``sbx.profile_error`` before it reads a deny or an allow. Exit 65
    is a profile error even when stderr says ``Operation not permitted``.
    Any non-empty subset of the four devices, including two- and
    three-device opens, is an allow.
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
        parsed = parse_line(result.stdout)
        states = []
        if parsed is not None:
            states = [
                triple_state(name, fd, n, err, want_read)
                for name, fd, n, err, want_read in parsed
            ]
        if result.stdout == DENY_STDOUT:
            raise HarnessError(
                "nonempty deny stderr is a harness error, not a deny: "
                + repr(result.stderr)
            )
        if states and all(state in ("deny", "allow") for state in states) and (
            "allow" in states
        ):
            raise HarnessError(
                "nonempty allow stderr is a harness error, not an allow: "
                + repr(result.stderr)
            )
        raise HarnessError(
            "nonempty stderr is a harness error, not a deny and not an allow: "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    parsed = parse_line(result.stdout)
    if parsed is None:
        raise HarnessError(line_problem(result.stdout))
    opened = []
    for name, fd, n, err, want_read in parsed:
        state = triple_state(name, fd, n, err, want_read)
        if state == "allow":
            opened.append(name)
        elif state == "deny":
            continue
        else:
            raise HarnessError(line_problem(result.stdout))
    return outcome_name(opened)


def compile_open(parent, root, source_text):
    """Compile ``source_text`` with ``/usr/bin/cc`` into ``<root>/devop``.

    The source file sits in ``parent``. This does not start ``sandbox-exec``.
    A nonzero exit, stderr on exit 0, or a missing executable is a harness
    error, not a skip.
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
    # A warning on exit 0 is not a compiled helper. Nonempty stderr stays a
    # harness error, with its own reason, distinct from a nonzero exit.
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


def open_under(profile):
    """Run the compiled helper under ``profile``. No argv."""
    binary = DevOpenProbe.binary
    root = DevOpenProbe.root
    parent = DevOpenProbe.parent
    if not binary or not root or not parent:
        raise HarnessError("the device-open helper is not compiled")
    return run_sandboxed(binary, root, parent, profile)


def require_unsandboxed_all(result):
    """The unsandboxed control must open all four devices.

    A deny, a partial allow, a bad exit, stderr, or a malformed line is a
    harness error. An ordinary assertion is not this check.
    """
    if result.argv and os.fspath(result.argv[0]) == sbx.SANDBOX_EXEC:
        raise HarnessError(
            "unsandboxed control started sandbox-exec: " + repr(result.argv)
        )
    outcome = classify(result)
    if outcome == "all":
        return result
    if outcome == "deny":
        raise HarnessError(
            "unsandboxed deny is a harness error, not a passing control: "
            + repr(result.stdout)
        )
    raise HarnessError(
        f"unsandboxed {outcome} allow is a harness error, not a passing control: "
        + repr(result.stdout)
    )


def run_unsandboxed(binary):
    """The helper with no profile. This does not start ``sandbox-exec``."""
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
    return require_unsandboxed_all(result)


def require_denied(profile):
    """The one helper. ``profile`` must deny all four device opens.

    The three real-file tests and the plants call this. An allow raises
    ``NotDenied``. A harness error propagates and is not a deny.
    """
    result = open_under(profile)
    if classify(result) != "deny":
        raise NotDenied(result)
    return result


def append_line(text, line):
    """Append one rule line. The caller names which rule this is."""
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
    """Replace the one ``(deny network*)`` line. That edit is not the plant."""
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


def granted_names(text):
    """Devices a profile text opens. Used by injected launches only.

    The real helper is the measurement. ``(allow file-read* (subpath "/dev"))``
    opens all four. ``file-read-data`` opens only its path. Read-write opens
    only ``/dev/dtracehelper`` or ``/dev/ptmx``. Write-only, ``pseudo-tty``,
    ``/dev/urandom``, and ``/dev/null`` open none of the four.
    """
    if SUBPATH_DEV in text:
        return DEVICE_NAMES
    opened = []
    for name, _path, want_read in DEVICES:
        if PLANTS[name] in text or READ_DATA[name] in text:
            opened.append(name)
            continue
        if not want_read and READ_WRITE[name] in text:
            opened.append(name)
    return tuple(opened)


def stdout_for_text(text):
    """The line a profile with these grants prints. Injection only."""
    return stdout_for_names(granted_names(text))


def launch_sequence(plant):
    """Copy basenames ``_run_plant`` launches, in order."""
    names = [f"{profile}-{plant}.sb" for profile in ("wallet", "did", "model")]
    names.extend(f"{stem}.sb" for _kind, stem, _opened in EXTRAS[plant])
    return names


def finding_paragraph(profile, result):
    """One CRITICAL record. The first line carries the live pin.

    The commit is ``git log -1 --format=%H HEAD -- <file>`` via
    ``last_change``. The digest is the bytes this run read. Neither value
    is stored in this file. ``opened`` names every device that opened.
    """
    commit = last_change(profile["path"])
    digest = sha256_file(profile["path"])
    return (
        f"CRITICAL {IDS[profile['name']]} {commit} {pr_label(commit)} "
        f"sha256 {digest}\n"
        f"profile: {profile['rel']}\n"
        f"opened: {opened_phrase(opened_names(result.stdout))}\n"
        f"helper: {result.command}\n"
        f"observed: {result.stdout.strip()}\n"
    )


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

    README guard (b): a recorded escape stays as ``expectedFailure``, so
    the gate stays green. The mark is only for that recorded allow.
    """
    method = getattr(case_cls, method_name)

    @wraps(method)
    def recorded(self):
        try:
            return method(self)
        except NotDenied:
            raise
        except BaseException:
            # unittest otherwise treats every exception in a marked body as
            # expected. Only the recorded allow has that status. Leave the
            # original exception for unittest to report as a failure/error.
            if self._outcome is not None:
                self._outcome.expecting_failure = False
            raise

    recorded.__doc__ = (
        "The live profile allowed a device open. "
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
        result = open_under(profile["path"])
        outcome = classify(result)
        if outcome == "deny":
            continue
        confirmed.append((profile, result))
        # Snapshot: a later append must not change the list this call recorded.
        write_findings(ROOT, list(confirmed))
        case_cls.recorded_allows[profile["name"]] = FINDINGS[profile["name"]]
        mark_expected(
            case_cls,
            f"test_{profile['name']}_dev_open_is_denied",
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


class DevOpenProbe(unittest.TestCase):
    """The helper under the live profiles, and the four allow plants."""

    skip_reason = None
    binary = None
    root = None
    parent = None
    recorded_allows = {}

    @classmethod
    def setUpClass(cls):
        cls.skip_reason = skip_reason()
        cls.binary = None
        cls.root = None
        cls.parent = None
        cls.recorded_allows = {}
        if cls.skip_reason:
            return
        cls.parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devop-parent-"))
        cls.root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devop-root-"))
        cls.addClassCleanup(shutil.rmtree, cls.parent, ignore_errors=True)
        cls.addClassCleanup(shutil.rmtree, cls.root, ignore_errors=True)
        cls.binary = compile_open(cls.parent, cls.root, HELPER_C)
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

    def test_unsandboxed_dev_open_succeeds(self):
        """Without ``sandbox-exec``, the helper opens all four devices.

        Exit 0, stderr empty, stdout the all-four line. A failure here is
        a harness error, so a later deny is about the profile.
        """
        source = os.path.join(self.parent, SOURCE_NAME)
        self.assertEqual(Path(source).read_text(encoding="utf-8"), HELPER_C)
        self.assertIn("open(", HELPER_C)
        self.assertIn('"/dev/zero"', HELPER_C)
        self.assertIn('"/dev/random"', HELPER_C)
        self.assertIn('"/dev/dtracehelper"', HELPER_C)
        self.assertIn('"/dev/ptmx"', HELPER_C)
        self.assertIn("O_RDONLY", HELPER_C)
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
        self.assertEqual(classify(result), "all")

    def test_compile_failure_is_an_error(self):
        """``/usr/bin/cc`` on an empty source is a harness error, not a skip."""
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devop-empty-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devop-empty-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with self.assertRaises(HarnessError) as caught:
            compile_open(parent, root, "")
        message = str(caught.exception)
        self.assertIn(CC, message)
        self.assertIn("not a skip", message)
        self.assertNotIn("SKIPPED", message)

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

    def test_wallet_dev_open_is_denied(self):
        """The real wallet profile denies all four device opens."""
        self._expect_real_deny(sbx.WALLET_CONFINE_SB)

    def test_did_dev_open_is_denied(self):
        """The real did profile denies all four device opens."""
        did = sbx.REPO_ROOT / "capsules/did-provider/confine.sb"
        self._expect_real_deny(did)

    def test_model_dev_open_is_denied(self):
        """The real model profile denies all four device opens.

        A root-directory read grant is not a reason to skip this file.
        The helper starts under the model profile.
        """
        model = sbx.REPO_ROOT / "capsules/model-provider/confine.sb"
        self._expect_real_deny(model)

    def _baseline_for(self, profile, text):
        """Count plants on the baseline, not on an unstripped live file.

        An unconditional zero-count on the live file turns a recorded allow
        into an ordinary failure.
        """
        baseline = self._source_for_plant(profile["name"], text)
        if profile["name"] not in type(self).recorded_allows:
            for line in PLANTS.values():
                self.assertEqual(text.count(line.rstrip("\n")), 0)
            self.assertEqual(text.count(DENY_DEFAULT), 1)
            self.assertEqual(baseline, text)
        for line in PLANTS.values():
            self.assertEqual(baseline.count(line.rstrip("\n")), 0)
            self.assertEqual(baseline.count(line), 0)
        self.assertEqual(baseline.count(DENY_DEFAULT), 1)
        self.assertTrue(baseline.endswith("\n"))
        return baseline

    def _assert_one_plant(self, text, plant):
        for name, line in PLANTS.items():
            expect = 1 if name == plant else 0
            self.assertEqual(text.count(line.rstrip("\n")), expect)
            self.assertEqual(text.count(line), expect)
        self.assertEqual(text.count(DENY_DEFAULT), 1)

    def _assert_no_plants(self, text):
        for line in PLANTS.values():
            self.assertEqual(text.count(line.rstrip("\n")), 0)
            self.assertEqual(text.count(line), 0)

    def _catch_allow(self, profile, copy, expected_stdout, expected_outcome):
        with self.assertRaises(NotDenied) as caught:
            require_denied(copy)
        result = caught.exception.result
        self.assertIn("ALLOW", str(caught.exception))
        self.assertIsNone(sbx.profile_error(result))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, expected_stdout)
        self.assertEqual(classify(result), expected_outcome)
        self.assertEqual(opened_names(result.stdout), opened_names(expected_stdout))
        self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
        self.assertEqual(os.path.basename(result.argv[-1]), BINARY_NAME)
        self.assertEqual(result.argv[-2], copy)
        self.assertIn(copy, result.argv)
        self.assertNotIn(os.fspath(profile["path"]), result.argv)
        return result

    def _expect_copy(self, profile, copy, opened):
        if not opened:
            denied = require_denied(copy)
            self.assertEqual(denied.stdout, DENY_STDOUT)
            self.assertEqual(denied.stderr, "")
            self.assertEqual(denied.exit_code, 0)
            self.assertEqual(classify(denied), "deny")
            self.assertEqual(denied.argv[0], sbx.SANDBOX_EXEC)
            self.assertIn(os.fspath(copy), denied.argv)
            self.assertNotIn(os.fspath(profile["path"]), denied.argv)
            return denied
        return self._catch_allow(
            profile, copy, stdout_for_names(opened), outcome_name(opened),
        )

    def _extra_text(self, baseline, plant, kind):
        """One wallet copy that is not the plant line."""
        for line in PLANTS.values():
            rule = line.rstrip("\n")
            self.assertNotIn(rule, READ_DATA[plant])
            self.assertNotIn(rule, WRITE_ONLY[plant])
            self.assertNotIn(rule, URANDOM_ALLOW)
            self.assertNotIn(rule, NULL_ALLOW)
            self.assertNotIn(rule, PSEUDO_TTY)
            self.assertNotIn(rule, SUBPATH_DEV)
            self.assertNotIn(rule, READ_WRITE[plant])
        if kind == "read-data":
            edited = append_line(baseline, READ_DATA[plant])
            self.assertIn(READ_DATA[plant], edited)
            self.assertNotIn(PLANTS[plant], edited)
        elif kind == "read-write":
            self.assertFalse(dict((name, read) for name, _path, read in DEVICES)[plant])
            edited = append_line(baseline, READ_WRITE[plant])
            self.assertIn(READ_WRITE[plant], edited)
            self.assertNotIn(PLANTS[plant], edited)
        elif kind == "write":
            self.assertNotIn("file-read", WRITE_ONLY[plant])
            edited = append_line(baseline, WRITE_ONLY[plant])
            self.assertIn(WRITE_ONLY[plant], edited)
        elif kind == "deleted":
            edited = without_deny_default(baseline)
            self.assertNotIn("(deny default)", edited)
            self.assertNotIn("(allow default)", edited)
        elif kind == "lookup":
            edited = append_line(baseline, MACH_LOOKUP)
            self.assertEqual(
                edited.count(MACH_LOOKUP), baseline.count(MACH_LOOKUP) + 1,
            )
        elif kind == "network":
            self.assertEqual(baseline.count(DENY_NETWORK), 1)
            edited = with_network_allow(baseline)
            self.assertEqual(edited.count(DENY_NETWORK), 0)
            self.assertEqual(
                edited.count(ALLOW_NETWORK), baseline.count(ALLOW_NETWORK) + 1,
            )
        elif kind == "pseudo-tty":
            edited = append_line(baseline, PSEUDO_TTY)
            self.assertEqual(edited.count(PSEUDO_TTY), baseline.count(PSEUDO_TTY) + 1)
        elif kind == "urandom":
            edited = append_line(baseline, URANDOM_ALLOW)
            self.assertIn(URANDOM_ALLOW, edited)
        elif kind == "null":
            edited = append_line(baseline, NULL_ALLOW)
            self.assertIn(NULL_ALLOW, edited)
        elif kind == "subpath":
            edited = append_line(baseline, SUBPATH_DEV)
            self.assertIn(SUBPATH_DEV, edited)
            self.assertNotIn('(literal "/dev/', SUBPATH_DEV)
        else:
            raise HarnessError(f"unknown extra {kind}")
        self._assert_no_plants(edited)
        if kind != "deleted":
            self.assertEqual(edited.count(DENY_DEFAULT), 1)
        return edited

    def _run_plant(self, plant):
        """Append one plant on each profile, then the wallet copies for it."""
        before = {
            profile["rel"]: sha256_file(profile["path"]) for profile in PROFILES
        }
        directory = os.path.realpath(tempfile.mkdtemp(prefix=f"ccrt-devop-{plant}-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        try:
            for profile in PROFILES:
                with self.subTest(profile=profile["name"]):
                    text = profile["path"].read_text(encoding="utf-8")
                    baseline = self._baseline_for(profile, text)
                    planted = append_line(baseline, PLANTS[plant])
                    self.assertEqual(planted, baseline + PLANTS[plant])
                    self._assert_one_plant(planted, plant)
                    copy = write_copy(directory, f"{profile['name']}-{plant}", planted)
                    self.assertEqual(Path(copy).read_text(encoding="utf-8"), planted)
                    self.assertNotEqual(
                        os.path.realpath(copy), os.path.realpath(profile["path"]),
                    )
                    self._expect_copy(profile, copy, (plant,))
                    self.assertEqual(profile["path"].read_text(encoding="utf-8"), text)

            wallet = PROFILES[0]
            self.assertEqual(wallet["name"], "wallet")
            wallet_text = wallet["path"].read_text(encoding="utf-8")
            baseline = self._baseline_for(wallet, wallet_text)
            for kind, stem, opened in EXTRAS[plant]:
                with self.subTest(profile=stem):
                    edited = self._extra_text(baseline, plant, kind)
                    copy = write_copy(directory, stem, edited)
                    self.assertEqual(Path(copy).read_text(encoding="utf-8"), edited)
                    self.assertNotEqual(
                        os.path.realpath(copy), os.path.realpath(wallet["path"]),
                    )
                    self._expect_copy(wallet, copy, opened)
            self.assertEqual(wallet["path"].read_text(encoding="utf-8"), wallet_text)
        finally:
            require_unchanged(before)

    def test_falsifier_allow_zero_is_caught(self):
        """Appending the zero plant lets only ``/dev/zero`` open.

        Each plant baseline contains each exact plant line zero times and
        ``(deny default)`` once. A recorded allow strips one exact copy of
        each injected plant line before that count. The other three devices
        stay denied. ``file-read-data`` of ``/dev/zero`` is not the plant
        and allows only zero. Write-only zero, deleting ``(deny default)``,
        appending ``(allow mach-lookup)``, and replacing ``(deny network*)``
        still deny all four. The repo bytes stay unchanged.
        """
        self._run_plant("zero")

    def test_falsifier_allow_random_is_caught(self):
        """Appending the random plant lets only ``/dev/random`` open.

        ``file-read-data`` of ``/dev/random`` is not the plant and allows
        only random. Write-only random, ``/dev/urandom``, and ``/dev/null``
        still deny all four. The repo profile bytes stay unchanged.
        """
        self._run_plant("random")

    def test_falsifier_allow_dtrace_is_caught(self):
        """Appending the dtrace plant lets only ``/dev/dtracehelper`` open.

        ``file-read-data`` and the read-write line are not the plant. Each
        allows only dtrace. Write-only dtrace and ``(allow pseudo-tty)``
        still deny all four. The repo profile bytes stay unchanged.
        """
        self._run_plant("dtrace")

    def test_falsifier_allow_ptmx_is_caught(self):
        """Appending the ptmx plant lets only ``/dev/ptmx`` open.

        ``file-read-data`` and the read-write line allow only ptmx.
        ``(allow file-read* (subpath "/dev"))`` is not the plant and allows
        all four. Write-only ptmx still denies all four. The repo profile
        bytes stay unchanged.
        """
        self._run_plant("ptmx")

    def _source_for_plant(self, name, text):
        """The text the temp plant edits. A recorded allow does not skip this.

        The deny test carries the finding-linked expected failure. The live
        file is not edited. One exact copy of each injected plant line is
        removed so the append is still that one line. Read-data, read-write,
        and subpath lines are not plants and stay.
        """
        finding = type(self).recorded_allows.get(name)
        if finding is None:
            for line in PLANTS.values():
                rule = line.rstrip("\n")
                if rule in text:
                    raise AssertionError(f"{name} source contains {rule}")
            return text
        method = getattr(type(self), f"test_{name}_dev_open_is_denied")
        if not getattr(method, "__unittest_expecting_failure__", False):
            raise HarnessError(f"{name} allow has no finding-linked expected failure")
        if finding not in (method.__doc__ or ""):
            raise HarnessError(f"{name} allow docstring does not name {finding}")
        for rule, line in PLANT_LINES:
            occurrences = text.count(line)
            if occurrences > 1:
                raise HarnessError(f"{rule} occurs {occurrences} times, not zero or one")
            if occurrences == 1:
                text = text.replace(line, "", 1)
        return text


class DevOpenRules(unittest.TestCase):
    """Classifier, pins, and injected results. They compile nothing and launch nothing."""

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
        probe_names = unittest.defaultTestLoader.getTestCaseNames(DevOpenProbe)
        for missing in ((sbx.SANDBOX_EXEC,), (CC,), (sbx.SANDBOX_EXEC, CC)):
            with self.subTest(missing=missing), patch.object(
                os.path, "isfile", side_effect=lambda path: path not in missing
            ), patch(
                __name__ + ".compile_open",
                side_effect=AssertionError("missing-tool probe compiled a helper"),
            ) as compiled, patch.object(
                sbx, "run",
                side_effect=AssertionError("missing-tool probe launched a helper"),
            ) as launched:
                class MissingTools(DevOpenProbe):
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

        Both tools are injected as present. The plant source is still produced.
        A recorded allow without that mark, a docstring that omits the finding,
        and a second plant line are each their own harness error. Read-data,
        read-write, and subpath lines are not plants.
        """
        with patch.object(os.path, "isfile", return_value=True):
            self.assertIsNone(skip_reason())
            self.assertTrue(os.path.isfile(CC))
            self.assertTrue(os.path.isfile(sbx.SANDBOX_EXEC))
        clean = "(version 1)\n(deny default)\n"
        one = {name: clean + PLANTS[name] for name in DEVICE_NAMES}
        all_four = clean + "".join(PLANTS[name] for name in DEVICE_NAMES)
        stayed = (
            clean
            + "".join(PLANTS[name] for name in DEVICE_NAMES)
            + READ_DATA["zero"]
            + READ_WRITE["dtrace"]
            + READ_WRITE["ptmx"]
            + SUBPATH_DEV
            + WRITE_ONLY["ptmx"]
            + PSEUDO_TTY
            + URANDOM_ALLOW
            + NULL_ALLOW
        )

        class Recorded(DevOpenProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Recorded, "test_wallet_dev_open_is_denied", FINDINGS["wallet"])
        try:
            case = Recorded("test_falsifier_allow_zero_is_caught")
            for name in DEVICE_NAMES:
                self.assertEqual(case._source_for_plant("wallet", one[name]), clean)
            self.assertEqual(case._source_for_plant("wallet", all_four), clean)
            self.assertEqual(
                case._source_for_plant("wallet", stayed),
                clean
                + READ_DATA["zero"]
                + READ_WRITE["dtrace"]
                + READ_WRITE["ptmx"]
                + SUBPATH_DEV
                + WRITE_ONLY["ptmx"]
                + PSEUDO_TTY
                + URANDOM_ALLOW
                + NULL_ALLOW,
            )
            self.assertEqual(case._source_for_plant("did", clean), clean)
        finally:
            Recorded.doClassCleanups()

        class Bare(DevOpenProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        bare = Bare("test_falsifier_allow_zero_is_caught")
        with self.assertRaises(HarnessError) as unmarked:
            bare._source_for_plant("wallet", one["zero"])
        self.assertEqual(
            str(unmarked.exception),
            "wallet allow has no finding-linked expected failure",
        )
        self.assertNotIsInstance(unmarked.exception, unittest.SkipTest)

        class WrongDoc(DevOpenProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        def body(self):
            raise NotDenied(
                sbx.Result(exit_code=0, stdout=stdout_for_names(("zero",)), stderr="", argv=[])
            )

        body.__doc__ = "plain"
        body.__unittest_expecting_failure__ = True
        WrongDoc.test_wallet_dev_open_is_denied = body
        wrong = WrongDoc("test_falsifier_allow_zero_is_caught")
        with self.assertRaises(HarnessError) as unnamed:
            wrong._source_for_plant("wallet", one["zero"])
        self.assertEqual(
            str(unnamed.exception),
            f"wallet allow docstring does not name {FINDINGS['wallet']}",
        )

        class Twice(DevOpenProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Twice, "test_wallet_dev_open_is_denied", FINDINGS["wallet"])
        try:
            twice = Twice("test_falsifier_allow_zero_is_caught")
            for name in DEVICE_NAMES:
                with self.assertRaises(HarnessError) as extra:
                    twice._source_for_plant("wallet", one[name] + PLANTS[name])
                self.assertEqual(
                    str(extra.exception),
                    f"{PLANTS[name].rstrip(chr(10))} occurs 2 times, not zero or one",
                )
        finally:
            Twice.doClassCleanups()

        class Clean(DevOpenProbe):
            recorded_allows = {}

        plain = Clean("test_falsifier_allow_zero_is_caught")
        for name in DEVICE_NAMES:
            with self.assertRaises(AssertionError) as present:
                plain._source_for_plant("wallet", one[name])
            self.assertEqual(
                str(present.exception),
                f"wallet source contains {PLANTS[name].rstrip(chr(10))}",
            )
        self.assertEqual(plain._source_for_plant("wallet", clean), clean)
        self.assertEqual(
            plain._source_for_plant("wallet", clean + SUBPATH_DEV),
            clean + SUBPATH_DEV,
        )
        self.launch_guard.assert_not_called()

    def test_profile_bytes_match_the_start(self):
        """Each end digest equals the start digest through ``changed``.

        This stores no digest. A changed temporary profile, checked by
        module teardown, raises ``the probe changed <rel>``. Removing the
        end check from ``tearDownModule`` makes this test fail.
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

        rel = "tmp/devop-confine.sb"
        self.assertNotIn(rel, START_SHA)
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devop-byte-"))
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
        """Exit 0 with compiler stderr is its own harness error.

        The injected result is ``CompletedProcess(returncode=0, stdout="",
        stderr="compiler warning\\n")`` and the executable check is true.
        A nonzero exit, a missing executable, and an unresolved storage path
        each keep a different reason. Empty stderr still returns the binary.
        """
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devop-cc-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devop-cc-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        binary = os.path.join(root, BINARY_NAME)
        source = "int main(void) { return 0; }\n"
        reasons = []

        def compiled(completed, access=None):
            runners = patch.object(subprocess, "run", return_value=completed)
            if access is None:
                with runners:
                    return compile_open(parent, root, source)
            with runners, patch.object(os, "access", return_value=access):
                return compile_open(parent, root, source)

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
            ("parent", "/var/folders/cc/devop-parent", root),
            ("root", parent, "/var/folders/cc/devop-root"),
        ):
            bad = compile_parent if label == "parent" else compile_root
            expected = (
                f"execvp: {bad} contains /var/folders without the /private prefix"
            )
            with self.subTest(path=label), patch.object(
                subprocess, "run", side_effect=refuse_cc
            ):
                with self.assertRaises(HarnessError) as caught:
                    compile_open(compile_parent, compile_root, source)
            self.assertEqual(str(caught.exception), expected)
            self.assertNotIn("/private/var/folders", str(caught.exception))
            reasons.append(expected)

        self.assertEqual(len(set(reasons)), len(reasons))
        self.launch_guard.assert_not_called()

    def test_falsifier_change_check_calls_changed(self):
        """The profile-change check calls ``changed`` with the two digests.

        Different before and after bytes are injected. Module teardown and
        the falsifier's end check both reach ``changed``. A local compare
        that raises ``the probe changed <rel>`` is not this rule.
        """
        source = Path(__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Raise):
                segment = ast.get_source_segment(source, node) or ""
                self.assertNotIn("the probe changed", segment)

        global PROFILES
        clean = b"(version 1)\n(deny default)\n(deny network*)\n"
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devop-bytes-"))
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

            class Plant(DevOpenProbe):
                recorded_allows = {}

            state = {"mutate": False}

            def fake_denied(profile):
                profile = os.fspath(profile)
                text = Path(profile).read_text(encoding="utf-8")
                if state["mutate"] and profile.endswith(os.sep + "wallet-deleted.sb"):
                    wallet["path"].write_bytes(after_bytes)
                stdout = stdout_for_text(text)
                result = sbx.Result(
                    exit_code=0,
                    stdout=stdout,
                    stderr="",
                    argv=[sbx.SANDBOX_EXEC, "-f", profile, "/private/devop"],
                )
                if stdout != DENY_STDOUT:
                    raise NotDenied(result)
                return result

            case = Plant("test_falsifier_allow_zero_is_caught")
            try:
                with patch(__name__ + ".PROFILES", profiles), patch(
                    __name__ + ".require_denied", new=fake_denied
                ), patch(__name__ + ".changed", new=spy):
                    with self.subTest(path="falsifier-equal"):
                        seen.clear()
                        state["mutate"] = False
                        case.test_falsifier_allow_zero_is_caught()
                        self.assertEqual(seen, equal_pairs)
                    with self.subTest(path="falsifier-changed"):
                        seen.clear()
                        state["mutate"] = True
                        wallet["path"].write_bytes(clean)
                        with self.assertRaises(AssertionError) as caught:
                            case.test_falsifier_allow_zero_is_caught()
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
                    argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/devop"],
                ),
                "profile error: profile read or compile error: sandbox-exec exited 65 "
                "and started no program, so nothing was denied -- a harness error, "
                "not a deny and not an allow. stderr='Operation not permitted\\n'",
            ),
            (
                "wrong exit",
                sbx.Result(
                    exit_code=2, stdout=DENY_STDOUT, stderr="", argv=["/private/devop"],
                ),
                "wrong exit 2 is a harness error, not a deny and not an allow. "
                f"stdout={DENY_STDOUT!r} stderr=''",
            ),
        ]
        device_cases = (
            ("wrong zero fd", "zero", 4, 16, 0,
             "wrong zero fd is a harness error, not a deny and not an allow"),
            ("wrong random fd", "random", 4, 16, 0,
             "wrong random fd is a harness error, not a deny and not an allow"),
            ("wrong dtrace fd", "dtrace", 4, -1, 0,
             "wrong dtrace fd is a harness error, not a deny and not an allow"),
            ("wrong ptmx fd", "ptmx", 4, -1, 0,
             "wrong ptmx fd is a harness error, not a deny and not an allow"),
            ("short zero read", "zero", 3, 8, 0,
             "short zero read is a harness error, not an allow"),
            ("short random read", "random", 3, 8, 0,
             "short random read is a harness error, not an allow"),
            ("dtrace n other than -1", "dtrace", 3, 0, 0,
             "dtrace n other than -1 is a harness error, not a deny and not an allow"),
            ("ptmx n other than -1", "ptmx", 3, 0, 0,
             "ptmx n other than -1 is a harness error, not a deny and not an allow"),
            ("wrong zero errno", "zero", -1, -1, 13,
             "wrong zero errno is a harness error, not a deny"),
            ("wrong random errno", "random", -1, -1, 13,
             "wrong random errno is a harness error, not a deny"),
            ("wrong dtrace errno", "dtrace", -1, -1, 13,
             "wrong dtrace errno is a harness error, not a deny"),
            ("wrong ptmx errno", "ptmx", -1, -1, 13,
             "wrong ptmx errno is a harness error, not a deny"),
            ("wrong zero open errno", "zero", 3, 16, 13,
             "wrong zero open errno is a harness error, not an allow"),
            ("wrong random open errno", "random", 3, 16, 13,
             "wrong random open errno is a harness error, not an allow"),
            ("wrong dtrace open errno", "dtrace", 3, -1, 13,
             "wrong dtrace open errno is a harness error, not an allow"),
            ("wrong ptmx open errno", "ptmx", 3, -1, 13,
             "wrong ptmx open errno is a harness error, not an allow"),
        )
        for label, device, fd, n, err, phrase in device_cases:
            stdout = stdout_with(device, fd, n, err)
            samples.append((
                label,
                sbx.Result(
                    exit_code=0, stdout=stdout, stderr="", argv=["/private/devop"],
                ),
                phrase + ": " + repr(stdout),
            ))
        for name, _path, want_read in DEVICES:
            read_n = 16 if want_read else -1
            numeric_cases = [
                ("fd", "-01", "-01", -1, 1),
                ("fd", "03", "03", read_n, 0),
                ("fd", "-0", "-0", read_n, 0),
                ("n", "-01", -1, "-01", 1),
                ("n", "-0", 3, "-0", 0),
                ("errno", "01", -1, -1, "01"),
                ("errno", "00", 3, read_n, "00"),
                ("errno", "-0", 3, read_n, "-0"),
            ]
            if want_read:
                numeric_cases.append(("n", "016", 3, "016", 0))
            for field, text, fd, n, err in numeric_cases:
                label = f"noncanonical {name} {field} integer {text!r}"
                samples.append((
                    label,
                    sbx.Result(
                        exit_code=0,
                        stdout=stdout_with(name, fd, n, err),
                        stderr="",
                        argv=["/private/devop"],
                    ),
                    label + " is a harness error, not a deny and not an allow",
                ))
        pair = stdout_for_names(("zero", "random"))
        samples.append((
            "nonempty deny stderr",
            sbx.Result(
                exit_code=0, stdout=DENY_STDOUT, stderr=noise, argv=["/private/devop"],
            ),
            "nonempty deny stderr is a harness error, not a deny: " + repr(noise),
        ))
        samples.append((
            "nonempty allow stderr",
            sbx.Result(
                exit_code=0, stdout=pair, stderr=noise, argv=["/private/devop"],
            ),
            "nonempty allow stderr is a harness error, not an allow: " + repr(noise),
        ))
        samples.append((
            "nonempty stderr",
            sbx.Result(
                exit_code=0, stdout="opened\n", stderr=noise, argv=["/private/devop"],
            ),
            "nonempty stderr is a harness error, not a deny and not an allow: "
            f"stdout={'opened' + chr(10)!r} stderr={noise!r}",
        ))
        malformed = "opened\n"
        samples.append((
            "malformed stdout",
            sbx.Result(
                exit_code=0, stdout=malformed, stderr="", argv=["/private/devop"],
            ),
            "malformed stdout is a harness error, not a deny and not an allow: "
            + repr(malformed),
        ))
        return tuple(samples)

    def test_classifier_refusal_reasons(self):
        """Each classifier refusal preserves its exact, distinct reason.

        Two- and three-device opens are allows, not malformed lines. Wrong
        errno on a denied device and on an allowed device is neither a deny
        nor an allow. Padded integers and negative zero in every numeric
        field are harness errors. These results launch nothing.
        """
        self.assertEqual(stdout_for_names(()), DENY_STDOUT)
        self.assertEqual(stdout_for_names(DEVICE_NAMES), ALL_STDOUT)
        self.assertEqual(
            opened_phrase(("zero", "random", "dtrace", "ptmx")),
            "/dev/zero, /dev/random, /dev/dtracehelper, and /dev/ptmx",
        )
        self.assertEqual(opened_phrase(("zero", "ptmx")), "/dev/zero and /dev/ptmx")
        self.assertEqual(
            opened_phrase(("random", "dtrace", "ptmx")),
            "/dev/random, /dev/dtracehelper, and /dev/ptmx",
        )
        self.assertEqual(opened_phrase(("dtrace",)), "/dev/dtracehelper")
        self.assertEqual(
            classify(sbx.Result(
                exit_code=0, stdout=DENY_STDOUT, stderr="", argv=["/private/devop"],
            )),
            "deny",
        )
        for size in range(1, 5):
            for subset in combinations(DEVICE_NAMES, size):
                stdout = stdout_for_names(subset)
                text = "(version 1)\n(deny default)\n" + "".join(
                    PLANTS[name] for name in subset
                )
                self.assertEqual(stdout_for_text(text), stdout)
                self.assertEqual(
                    classify(sbx.Result(
                        exit_code=0, stdout=stdout, stderr="", argv=["/private/devop"],
                    )),
                    outcome_name(subset),
                )
                self.assertEqual(opened_names(stdout), subset)
        self.assertEqual(
            stdout_for_text("(version 1)\n" + READ_DATA["zero"]),
            stdout_for_names(("zero",)),
        )
        self.assertEqual(
            stdout_for_text("(version 1)\n" + READ_DATA["random"]),
            stdout_for_names(("random",)),
        )
        self.assertEqual(
            stdout_for_text("(version 1)\n" + READ_DATA["dtrace"]),
            stdout_for_names(("dtrace",)),
        )
        self.assertEqual(
            stdout_for_text("(version 1)\n" + READ_DATA["ptmx"]),
            stdout_for_names(("ptmx",)),
        )
        self.assertEqual(
            stdout_for_text("(version 1)\n" + READ_WRITE["dtrace"]),
            stdout_for_names(("dtrace",)),
        )
        self.assertEqual(
            stdout_for_text("(version 1)\n" + READ_WRITE["ptmx"]),
            stdout_for_names(("ptmx",)),
        )
        self.assertEqual(stdout_for_text("(version 1)\n" + SUBPATH_DEV), ALL_STDOUT)
        for line in (
            WRITE_ONLY["zero"],
            WRITE_ONLY["random"],
            WRITE_ONLY["dtrace"],
            WRITE_ONLY["ptmx"],
            PSEUDO_TTY,
            URANDOM_ALLOW,
            NULL_ALLOW,
            MACH_LOOKUP,
            ALLOW_NETWORK,
        ):
            self.assertEqual(
                stdout_for_text("(version 1)\n(deny default)\n" + line),
                DENY_STDOUT,
            )
        self.assertEqual(
            stdout_for_text("(version 1)\n(allow network*)\n"),
            DENY_STDOUT,
        )
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
                if label != "malformed stdout":
                    self.assertNotIn("malformed stdout", message)
                reasons.append(message)
        self.assertEqual(len(set(reasons)), len(samples))
        for message in reasons:
            hits = [label for label, _result, _expected in samples if label in message]
            self.assertEqual(
                hits,
                [next(
                    label for label, _result, expected in samples if expected == message
                )],
            )
        # Conversion limits also produce HarnessError with the field's reason.
        # Inject the conversion failure so this holds for every Python digit limit.
        parts = _LINE.fullmatch(DENY_STDOUT).groups()
        for index, part in enumerate(parts):
            name = DEVICE_NAMES[index // 3]
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
        """A failed unsandboxed control is a harness error, not an assertion failure.

        A deny line, each single-device allow, a nonzero exit, nonempty
        stderr, and a malformed line each raise ``HarnessError``. One opened
        device is not a successful control. They launch nothing.
        """
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-devop-unsandboxed-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        binary = os.path.join(parent, BINARY_NAME)
        descriptor = os.open(binary, os.O_CREAT | os.O_WRONLY, 0o755)
        os.close(descriptor)
        binary = os.path.realpath(binary)
        cases = [
            (
                "unsandboxed deny",
                subprocess.CompletedProcess([binary], 0, DENY_STDOUT, ""),
                "unsandboxed deny is a harness error, not a passing control: "
                + repr(DENY_STDOUT),
            ),
        ]
        for name in DEVICE_NAMES:
            stdout = stdout_for_names((name,))
            cases.append((
                f"unsandboxed {name} allow",
                subprocess.CompletedProcess([binary], 0, stdout, ""),
                f"unsandboxed {name} allow is a harness error, not a passing control: "
                + repr(stdout),
            ))
        cases.extend((
            (
                "wrong exit",
                subprocess.CompletedProcess([binary], 2, ALL_STDOUT, ""),
                "wrong exit 2 is a harness error, not a deny and not an allow. "
                f"stdout={ALL_STDOUT!r} stderr=''",
            ),
            (
                "nonempty allow stderr",
                subprocess.CompletedProcess([binary], 0, ALL_STDOUT, "noise\n"),
                "nonempty allow stderr is a harness error, not an allow: " + repr("noise\n"),
            ),
            (
                "malformed stdout",
                subprocess.CompletedProcess([binary], 0, "opened\n", ""),
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
                self.assertIn(label, message)
                self.assertNotIsInstance(caught.exception, AssertionError)
                reasons.append(message)
        self.assertEqual(len(set(reasons)), len(cases))
        for message in reasons:
            hits = [label for label, _completed, _expected in cases if label in message]
            self.assertEqual(len(hits), 1)
        self.launch_guard.assert_not_called()

    def test_observe_propagates_every_refusal(self):
        """A failed observation stops before any later success or finding mark."""
        deny = sbx.Result(
            exit_code=0, stdout=DENY_STDOUT, stderr="", argv=["/private/devop"],
        )
        for label, refused, expected in self.refusal_samples():
            for preceding in ([], [deny], [deny, deny]):
                with self.subTest(reason=label, position=len(preceding)):
                    class Observed(DevOpenProbe):
                        pass

                    with patch(
                        __name__ + ".open_under",
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

        _label, refused, expected = self.refusal_samples()[0]
        with patch(__name__ + ".open_under", side_effect=[refused] * 3) as opened:
            with self.assertRaises(HarnessError) as caught:
                observe(Observed)
        self.assertEqual(str(caught.exception), expected)
        self.assertEqual(opened.call_count, 1)
        self.launch_guard.assert_not_called()

    def test_observe_records_allow_before_later_error(self):
        """A confirmed allow is written before the next profile is classified.

        Wallet allow, then a did profile error: the writer records the wallet
        allow, the wallet deny test is marked, and the error still propagates.
        Model is not opened. A did allow before a model error is recorded too.
        """
        zero = sbx.Result(
            exit_code=0,
            stdout=stdout_for_names(("zero",)),
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/devop"],
        )
        random = sbx.Result(
            exit_code=0,
            stdout=stdout_for_names(("random",)),
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/devop"],
        )
        refused = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout="",
            stderr="Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb"],
        )
        self.assertEqual(classify(zero), "zero")
        self.assertEqual(classify(random), "random")
        with self.assertRaises(HarnessError) as sample:
            classify(refused)
        expected = str(sample.exception)
        self.assertIn("profile error", expected)
        self.assertIn("Operation not permitted", expected)

        def run_case(results):
            class Observed(DevOpenProbe):
                pass

            pending = list(results)
            order = []

            def opened(path):
                order.append(("open", path))
                return pending.pop(0)

            def written(_repo, items):
                order.append(("write", [item[0]["name"] for item in items]))

            with patch(__name__ + ".open_under", side_effect=opened), patch(
                __name__ + ".write_findings", side_effect=written
            ), patch(__name__ + ".mark_expected", wraps=mark_expected) as marker:
                with self.assertRaises(HarnessError) as caught:
                    observe(Observed)
            self.assertEqual(str(caught.exception), expected)
            return Observed, marker, order

        wallet, did, model = PROFILES
        observed = None
        try:
            observed, marker, order = run_case([zero, refused])
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
            method = observed.test_wallet_dev_open_is_denied
            self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
            self.assertIn(FINDINGS["wallet"], method.__doc__ or "")
            self.assertNotIn("model", observed.recorded_allows)
        finally:
            if observed is not None:
                observed.doClassCleanups()

        observed = None
        try:
            observed, marker, order = run_case([zero, random, refused])
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
            did_method = observed.test_did_dev_open_is_denied
            self.assertTrue(getattr(did_method, "__unittest_expecting_failure__", False))
            self.assertIn(FINDINGS["did"], did_method.__doc__ or "")
        finally:
            if observed is not None:
                observed.doClassCleanups()
        self.launch_guard.assert_not_called()

    def test_recorded_allow_is_expected_failure(self):
        """A recorded allow is an expected failure whose docstring names the finding.

        Each injected plant marks the wallet deny test. The docstring names
        ``CRITICAL-confine-062.md``. The ptmx plant marks the model deny test
        and that docstring names ``CRITICAL-cc-model-confine-062.md``. A
        unittest run of each injected allow is one expected failure. The
        finding names every opened device. The clean run writes no finding.
        """
        provenance = self.enter_patch(patch(__name__ + ".last_change", return_value="a" * 40))
        self.enter_patch(patch(__name__ + ".pr_label", return_value="PR fixture"))
        self.enter_patch(patch(__name__ + ".sha256_file", return_value="b" * 64))
        wallet = PROFILES[0]
        did = PROFILES[1]
        model = PROFILES[2]
        self.assertEqual(wallet["name"], "wallet")
        self.assertEqual(did["name"], "did")
        self.assertEqual(model["name"], "model")
        live_names = (
            ROOT / "lab" / "redteam" / "CRITICAL.md",
            ROOT / FINDINGS["wallet"],
            ROOT / FINDINGS["model"],
        )
        before = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        with tempfile.TemporaryDirectory(prefix="ccrt-devop-finding-") as tmp:
            repo = Path(tmp)
            self.assertEqual(write_findings(repo, []), [])
            self.assertFalse((repo / "lab" / "redteam" / "CRITICAL.md").exists())
            single = {
                name: sbx.Result(
                    exit_code=0,
                    stdout=stdout_for_names((name,)),
                    stderr="",
                    argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/devop"],
                )
                for name in DEVICE_NAMES
            }
            for name in DEVICE_NAMES:
                paragraph = finding_paragraph(wallet, single[name])
                self.assertIn(f"opened: {opened_phrase((name,))}\n", paragraph)
                self.assertIn("CRITICAL", paragraph.splitlines()[0])
                for other, path, _read in DEVICES:
                    opened_line = paragraph.split("opened: ", 1)[1].split("\n", 1)[0]
                    if other == name:
                        self.assertIn(path, opened_line)
                    else:
                        self.assertNotIn(path, opened_line)
            for size in range(2, 5):
                for subset in combinations(DEVICE_NAMES, size):
                    result = sbx.Result(
                        exit_code=0,
                        stdout=stdout_for_names(subset),
                        stderr="",
                        argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/devop"],
                    )
                    paragraph = finding_paragraph(model, result)
                    self.assertIn(f"opened: {opened_phrase(subset)}\n", paragraph)
                    opened_line = paragraph.split("opened: ", 1)[1].split("\n", 1)[0]
                    for device, path, _read in DEVICES:
                        if device in subset:
                            self.assertIn(path, opened_line)
                        else:
                            self.assertNotIn(path, opened_line)
            written = write_findings(
                repo, [(wallet, single["zero"]), (did, single["random"])],
            )
            self.assertEqual(written, [FINDINGS["wallet"]])
            body = (repo / FINDINGS["wallet"]).read_text(encoding="utf-8")
            self.assertFalse((repo / FINDINGS["model"]).exists())
            zero_paragraph = finding_paragraph(wallet, single["zero"])
            random_paragraph = finding_paragraph(did, single["random"])
            self.assertEqual(body, zero_paragraph + random_paragraph)
            self.assertIn(last_change(wallet["path"]), zero_paragraph.splitlines()[0])
            self.assertIn(sha256_file(wallet["path"]), zero_paragraph.splitlines()[0])
            self.assertIn(pr_label(last_change(wallet["path"])), zero_paragraph)
            self.assertIn(f"profile: {wallet['rel']}", zero_paragraph)
            listed = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertIn(zero_paragraph, listed)
            self.assertIn(random_paragraph, listed)
            both = sbx.Result(
                exit_code=0,
                stdout=ALL_STDOUT,
                stderr="",
                argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/devop"],
            )
            model_paragraph = finding_paragraph(model, both)
            self.assertIn(
                "opened: /dev/zero, /dev/random, /dev/dtracehelper, and /dev/ptmx\n",
                model_paragraph,
            )
            model_written = write_findings(repo, [(model, both)])
            self.assertEqual(model_written, [FINDINGS["model"]])
            self.assertEqual(
                (repo / FINDINGS["model"]).read_text(encoding="utf-8"),
                model_paragraph,
            )
            self.assertIn("CRITICAL", model_paragraph.splitlines()[0])
            listed_again = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertIn(model_paragraph, listed_again)
            self.assertEqual(listed_again.count(model_paragraph), 1)
            again = write_findings(repo, [(model, both)])
            relisted = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertEqual(relisted, listed_again)
            self.assertEqual(again, [FINDINGS["model"]])
        after = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        self.assertEqual(before, after)

        for name in DEVICE_NAMES:
            allow = single[name]

            class Unmarked(DevOpenProbe):
                skip_reason = None

                def test_wallet_dev_open_is_denied(self):
                    """plain"""
                    raise NotDenied(allow)

            unmarked = unittest.TestResult()
            Unmarked("test_wallet_dev_open_is_denied").run(unmarked)
            self.assertEqual(len(unmarked.failures), 1)
            self.assertEqual(unmarked.expectedFailures, [])
            self.assertEqual(unmarked.errors, [])

            class Recorded(DevOpenProbe):
                skip_reason = None

            mark_expected(Recorded, "test_wallet_dev_open_is_denied", FINDINGS["wallet"])
            method = Recorded.test_wallet_dev_open_is_denied
            self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
            self.assertIn("CRITICAL-confine-062.md", method.__doc__)
            self.assertIn(FINDINGS["wallet"], method.__doc__)
            recorded = unittest.TestResult()
            try:
                with patch(__name__ + ".open_under", return_value=allow), patch.object(
                    os.path, "isfile", return_value=True
                ):
                    Recorded("test_wallet_dev_open_is_denied").run(recorded)
            finally:
                Recorded.doClassCleanups()
            self.assertEqual(len(recorded.expectedFailures), 1)
            self.assertEqual(recorded.failures, [])
            self.assertEqual(recorded.errors, [])
            self.assertEqual(recorded.unexpectedSuccesses, [])
            self.assertEqual(recorded.skipped, [])
            self.assertTrue(recorded.wasSuccessful())

        class ModelRecorded(DevOpenProbe):
            skip_reason = None

        mark_expected(
            ModelRecorded, "test_model_dev_open_is_denied", FINDINGS["model"],
        )
        model_method = ModelRecorded.test_model_dev_open_is_denied
        self.assertTrue(getattr(model_method, "__unittest_expecting_failure__", False))
        self.assertIn("CRITICAL-cc-model-confine-062.md", model_method.__doc__)
        self.assertIn(FINDINGS["model"], model_method.__doc__)
        model_result = unittest.TestResult()
        try:
            with patch(__name__ + ".open_under", return_value=single["ptmx"]), patch.object(
                os.path, "isfile", return_value=True
            ):
                ModelRecorded("test_model_dev_open_is_denied").run(model_result)
        finally:
            ModelRecorded.doClassCleanups()
        self.assertEqual(len(model_result.expectedFailures), 1)
        self.assertEqual(model_result.failures, [])
        self.assertEqual(model_result.errors, [])
        self.assertEqual(model_result.unexpectedSuccesses, [])
        self.assertEqual(model_result.skipped, [])
        self.assertTrue(model_result.wasSuccessful())
        self.assertEqual(
            {call.args[0] for call in provenance.call_args_list},
            {wallet["path"], did["path"], model["path"]},
        )
        self.launch_guard.assert_not_called()

    def test_wallet_controls_reject_allow_with_or_without_finding(self):
        """Each still-denies wallet copy fails on an allow, with or without a finding.

        Deleting ``(deny default)``, appending ``(allow mach-lookup)``,
        replacing ``(deny network*)``, write-only lines, ``(allow pseudo-tty)``,
        ``/dev/urandom``, and ``/dev/null`` are not excused by a live allow.
        The failure is ordinary, not expected.
        """
        injected = sbx.Result(
            exit_code=0,
            stdout=ALL_STDOUT,
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/devop"],
        )
        self.assertEqual(classify(injected), "all")
        for plant, extras in EXTRAS.items():
            method_name = f"test_falsifier_allow_{plant}_is_caught"
            stills = [stem for _kind, stem, opened in extras if not opened]
            expected_names = launch_sequence(plant)
            for recorded in (False, True):
                for control in stills:
                    with self.subTest(recorded=recorded, control=control), tempfile.TemporaryDirectory(
                        prefix="ccrt-devop-control-"
                    ) as tmp:
                        profiles = []
                        for original in PROFILES:
                            profile = dict(original)
                            profile["path"] = Path(tmp) / f"{profile['name']}.sb"
                            text = "(version 1)\n(deny default)\n(deny network*)\n"
                            if recorded and profile["name"] == "wallet":
                                text += PLANTS[plant]
                            profile["path"].write_text(text, encoding="utf-8")
                            profiles.append(profile)

                        class Control(DevOpenProbe):
                            skip_reason = None
                            recorded_allows = {}

                        if recorded:
                            finding = FINDINGS["wallet"]
                            Control.recorded_allows["wallet"] = finding
                            mark_expected(
                                Control, "test_wallet_dev_open_is_denied", finding,
                            )
                            method = Control.test_wallet_dev_open_is_denied
                            self.assertTrue(
                                getattr(method, "__unittest_expecting_failure__", False)
                            )
                            self.assertIn(finding, method.__doc__ or "")
                            self.assertIn("CRITICAL-confine-062.md", method.__doc__ or "")

                        opened = []

                        def injected_open(profile, chosen=control):
                            path = Path(profile)
                            opened.append(path.name)
                            if path.stem == chosen:
                                stdout = ALL_STDOUT
                            else:
                                stdout = stdout_for_text(path.read_text(encoding="utf-8"))
                            return sbx.Result(
                                exit_code=0,
                                stdout=stdout,
                                stderr="",
                                argv=[
                                    sbx.SANDBOX_EXEC,
                                    "-f",
                                    os.fspath(path),
                                    "/private/devop",
                                ],
                            )

                        result = unittest.TestResult()
                        try:
                            with patch(__name__ + ".PROFILES", tuple(profiles)), patch(
                                __name__ + ".open_under", side_effect=injected_open
                            ):
                                Control(method_name).run(result)
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
                        self.assertIn("ptmx fd=3 n=-1 errno=0", caught)
                        self.assertFalse(result.wasSuccessful())
                        self.assertEqual(opened, expected_names)
        self.launch_guard.assert_not_called()

    def test_recorded_allow_keeps_complete_probe_suite_green(self):
        """Run every probe test with injected tools and profile text.

        Scenarios are no allow, every non-empty plant subset on each profile,
        and all four plants on every profile at once. Two- and three-device
        subsets are allows. The finding names every opened device. Only the
        deny test of a profile that contains a plant line is an expected
        failure. The plants still run, nothing skips, and the result is
        successful.
        """
        method_names = unittest.defaultTestLoader.getTestCaseNames(DevOpenProbe)
        scenarios = [()]
        for profile in ("wallet", "did", "model"):
            for size in range(1, len(DEVICE_NAMES) + 1):
                for subset in combinations(DEVICE_NAMES, size):
                    scenarios.append(tuple((profile, plant) for plant in subset))
        scenarios.append(tuple(
            (profile, plant)
            for profile in ("wallet", "did", "model")
            for plant in DEVICE_NAMES
        ))
        for grants in scenarios:
            allowed = tuple(dict.fromkeys(name for name, _plant in grants))
            with self.subTest(grants=grants), tempfile.TemporaryDirectory(
                prefix="ccrt-devop-suite-"
            ) as tmp:
                repo = Path(tmp).resolve()
                profiles = []
                for original in PROFILES:
                    profile = dict(original)
                    profile["path"] = repo / profile["rel"]
                    profile["path"].parent.mkdir(parents=True, exist_ok=True)
                    text = "(version 1)\n(deny default)\n(deny network*)\n"
                    planted = {
                        plant
                        for profile_name, plant in grants
                        if profile_name == profile["name"]
                    }
                    for name in DEVICE_NAMES:
                        if name in planted:
                            text += PLANTS[name]
                    profile["path"].write_text(text, encoding="utf-8")
                    profiles.append(profile)

                def injected_compile(parent, root, source_text):
                    if not source_text:
                        raise HarnessError(
                            f"{CC} failed with exit 1: empty source "
                            "-- a harness error, not a skip and not a deny"
                        )
                    Path(parent, SOURCE_NAME).write_text(source_text, encoding="utf-8")
                    binary = Path(root, BINARY_NAME)
                    binary.write_text("injected executable; never launched\n", encoding="utf-8")
                    return str(binary)

                def injected_control(binary):
                    return sbx.Result(
                        exit_code=0, stdout=ALL_STDOUT, stderr="", argv=[binary],
                    )

                launched = []

                def injected_sandbox(**kwargs):
                    launched.append(os.fspath(kwargs["profile"]))
                    self.assertEqual(kwargs["pinned_exe"], kwargs["launch_exe"])
                    self.assertEqual(kwargs["timeout"], 5)
                    self.assertEqual(kwargs["args"], ())
                    text = Path(kwargs["profile"]).read_text(encoding="utf-8")
                    return sbx.Result(
                        exit_code=0,
                        stdout=stdout_for_text(text),
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
                    __name__ + ".compile_open", side_effect=injected_compile
                ), patch(__name__ + ".run_unsandboxed", side_effect=injected_control), patch.object(
                    sbx, "run", side_effect=injected_sandbox
                ), patch(__name__ + ".last_change", return_value="a" * 40), patch(
                    __name__ + ".pr_label", return_value="PR fixture"
                ), patch.multiple(
                    DevOpenProbe, binary=None, root=None, parent=None,
                    skip_reason=None, recorded_allows={},
                ):
                    result = unittest.TestResult()
                    unittest.defaultTestLoader.loadTestsFromTestCase(DevOpenProbe).run(result)
                    self.assertEqual(result.testsRun, len(method_names))
                    self.assertEqual(result.errors, [])
                    self.assertEqual(result.failures, [])
                    self.assertEqual(result.unexpectedSuccesses, [])
                    self.assertEqual(result.skipped, [])
                    self.assertIsNone(skip_reason())
                    self.assertEqual(len(result.expectedFailures), len(allowed))
                    self.assertEqual(
                        {case._testMethodName for case, _error in result.expectedFailures},
                        {f"test_{name}_dev_open_is_denied" for name in allowed},
                    )
                    for plant in DEVICE_NAMES:
                        self.assertEqual(
                            sorted(
                                os.path.basename(path)
                                for path in launched
                                if path.endswith(f"-{plant}.sb")
                                and os.path.basename(path) in {
                                    f"{profile}-{plant}.sb"
                                    for profile in ("wallet", "did", "model")
                                }
                            ),
                            [f"did-{plant}.sb", f"model-{plant}.sb", f"wallet-{plant}.sb"],
                        )
                    for suffix in (
                        "wallet-read-data-zero.sb",
                        "wallet-write-zero.sb",
                        "wallet-deleted.sb",
                        "wallet-lookup.sb",
                        "wallet-network.sb",
                        "wallet-read-data-random.sb",
                        "wallet-write-random.sb",
                        "wallet-urandom.sb",
                        "wallet-null.sb",
                        "wallet-read-data-dtrace.sb",
                        "wallet-rw-dtrace.sb",
                        "wallet-write-dtrace.sb",
                        "wallet-pty.sb",
                        "wallet-read-data-ptmx.sb",
                        "wallet-rw-ptmx.sb",
                        "wallet-subpath.sb",
                        "wallet-write-ptmx.sb",
                    ):
                        self.assertTrue(
                            any(path.endswith(os.sep + suffix) for path in launched)
                        )
                    self.assertTrue(result.wasSuccessful())
                    self.assertEqual(
                        DevOpenProbe.recorded_allows,
                        {name: FINDINGS[name] for name in allowed},
                    )
                    for name in allowed:
                        body = (repo / FINDINGS[name]).read_text(encoding="utf-8")
                        profile = next(item for item in profiles if item["name"] == name)
                        planted = tuple(
                            device
                            for device in DEVICE_NAMES
                            if any(
                                profile_name == name and plant == device
                                for profile_name, plant in grants
                            )
                        )
                        marker = f"profile: {profile['rel']}\n"
                        start = body.index(marker) + len(marker)
                        opened_line = body[start:].splitlines()[0]
                        self.assertEqual(opened_line, "opened: " + opened_phrase(planted))
                        for device, path, _read in DEVICES:
                            if device in planted:
                                self.assertIn(path, opened_line)
                            else:
                                self.assertNotIn(path, opened_line)
                        self.assertIn(sha256_file(profile["path"]), body)
                        self.assertIn(
                            f"profile: {profile['rel']}\nopened: {opened_phrase(planted)}\n",
                            (repo / "lab/redteam/CRITICAL.md").read_text(encoding="utf-8"),
                        )
                    if not allowed:
                        self.assertFalse((repo / "lab/redteam/CRITICAL.md").exists())
                        for rel in set(FINDINGS.values()):
                            self.assertFalse((repo / rel).exists())
                self.launch_guard.assert_not_called()

    def test_harness_error_stays_error(self):
        """Every refusal, including padded integers and negative zero, stays an error.

        Check each profile after its allow has been recorded and marked expected.
        """
        allow = sbx.Result(
            exit_code=0,
            stdout=stdout_for_names(("zero",)),
            stderr="",
            argv=["/private/devop"],
        )
        deny = sbx.Result(
            exit_code=0, stdout=DENY_STDOUT, stderr="", argv=["/private/devop"],
        )
        for profile in PROFILES:
            for label, refused, expected in self.refusal_samples():
                with self.subTest(profile=profile["name"], reason=label):
                    class Recorded(DevOpenProbe):
                        skip_reason = None

                    def observation(path, chosen=profile):
                        return allow if path == chosen["path"] else deny

                    with patch(__name__ + ".open_under", side_effect=observation), patch(
                        __name__ + ".write_findings"
                    ) as writer:
                        observe(Recorded)
                    writer.assert_called_once_with(ROOT, [(profile, allow)])
                    method_name = f"test_{profile['name']}_dev_open_is_denied"
                    method = getattr(Recorded, method_name)
                    self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
                    self.assertIn(FINDINGS[profile["name"]], method.__doc__)
                    result = unittest.TestResult()
                    try:
                        with patch(
                            __name__ + ".open_under", side_effect=[refused, deny]
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

        wrong_exit = sbx.Result(
            exit_code=2, stdout=DENY_STDOUT, stderr="", argv=["/private/devop"],
        )
        wrong_errno = sbx.Result(
            exit_code=0,
            stdout=stdout_with("zero", -1, -1, 13),
            stderr="",
            argv=["/private/devop"],
        )
        profile_error = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout=ALL_STDOUT,
            stderr="Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC],
        )
        injected = (wrong_exit, wrong_errno, profile_error)
        for result in injected:
            with self.assertRaises(HarnessError):
                classify(result)

        class Body(unittest.TestCase):
            def test_wallet_dev_open_is_denied(self):
                classify(wrong_exit)

        body = unittest.TestResult()
        Body("test_wallet_dev_open_is_denied").run(body)
        self.assertEqual(len(body.errors), 1)
        self.assertEqual(body.failures, [])
        self.assertEqual(body.expectedFailures, [])
        self.assertEqual(body.skipped, [])

        class Setup(unittest.TestCase):
            def setUp(self):
                raise HarnessError("wrong exit 2 is a harness error, not a deny")

            @unittest.expectedFailure
            def test_wallet_dev_open_is_denied(self):
                raise NotDenied(wrong_exit)

        setup = unittest.TestResult()
        Setup("test_wallet_dev_open_is_denied").run(setup)
        self.assertEqual(len(setup.errors), 1)
        self.assertEqual(setup.expectedFailures, [])
        self.assertEqual(setup.skipped, [])
        self.assertIn("wrong exit", setup.errors[0][1])
        self.launch_guard.assert_not_called()

    def test_unresolved_storage_path_is_an_error(self):
        """A ``/var/folders`` storage path without ``/private`` errors before launch."""
        bad_parent = "/var/folders/cc/devop-parent"
        bad_root = "/var/folders/cc/devop-root"
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
                compile_open(bad_parent, "/private/devop-root", "int main(void) { return 0; }\n")
            compile_message = str(compile_caught.exception)
            self.assertIn(bad_parent, compile_message)
            self.assertIn("/var/folders", compile_message)
            self.assertNotIn("/private" + bad_parent, compile_message)

            with self.assertRaises(HarnessError) as root_caught:
                compile_open("/private/devop-parent", bad_root, "int main(void) { return 0; }\n")
            self.assertIn(bad_root, str(root_caught.exception))
            self.assertIn("/var/folders", str(root_caught.exception))

            with self.assertRaises(HarnessError) as launch_caught:
                run_sandboxed(
                    "/private/devop",
                    bad_root,
                    "/private/devop-parent",
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
