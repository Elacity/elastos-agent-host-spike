"""Probe revoke of a pty slave on the wallet, did, and model profiles.

Grade row 12 rests on those seatbelt profiles. ``posix_openpt`` is scored
by the pty probe, ``grantpt`` and ``unlockpt`` by the grant probe, and the
slave open by the slave probe. This module asks ``revoke`` of the slave
name. It compiles one helper and runs it under each live ``confine.sb``.
Confined launches go through ``sbx.run`` only. The helper prints one line
and returns 0. It closes descriptors 3 through 63, then opens one pty
master. When that open fails it does not call ``grantpt``, ``unlockpt``,
``ptsname``, or ``revoke``. When the open succeeds it calls those three,
and it calls ``revoke`` only when the slave name starts with ``/dev/ttys``.

A deny is exit 0, empty stderr, and either the open-fail line or the
revoke-fail line. An allow is exit 0, empty stderr, and the full line
with ``revoke rc=0``. A line with ``revoke rc=0`` is an allow only when
it is that full line. ``name-bad`` and ``pts ok=0`` are harness errors.

The ptmx file line, the ptmx ioctl line, and the ttys read-write line are
setup, not the plant. Together they print the revoke-fail line. The plant
is the exact line ``(allow file-revoke)``. Beside the three setup lines it
prints the full allow. Alone it leaves the open denied. ``_source_for_plant``
strips one exact plant line and keeps each setup line.

The three profiles are the live files. ``setUpModule`` records each sha256.
``tearDownModule`` and the falsifier's end check call ``require_unchanged``,
which compares the digest through ``changed`` from ``test_confine_mach``.
An owner edit between those two points raises ``the probe changed <rel>``.
This file stores no commit, pull request, or digest.

An allow on a real profile is CRITICAL. Wallet or did:
``findings/CRITICAL-confine-073.md``. Model:
``findings/CRITICAL-cc-model-confine-073.md``. The finding's first line
contains CRITICAL and names the commit from ``git log -1 --format=%H HEAD
-- <file>`` plus the sha256 of the bytes this run read. It names ``revoke``
when ``revoke rc`` is 0. The same paragraph is appended to ``CRITICAL.md``.
With no allow, this module writes neither file.

A recorded allow keeps the gate green. The deny test is an expected
failure and its docstring names that finding file (README guard b).
Each confirmed allow is written before the next profile is classified.
A later harness error still fails the gate. The plant still runs.
A recorded allow is not a skip. This module skips only when
``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` is missing.
A profile error, a failed compile, a failed unsandboxed control,
nonempty stderr, and an exit other than 0 are harness errors. They are
not a deny and they are not a skip.

``RevokeProbe`` compiles and launches. It skips only when
``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` is missing, and the reason
names that path. ``RevokeRules`` does not compile and does not launch.
"""

import ast
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from functools import wraps
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
SOURCE_NAME = "ptyrevoke.c"
BINARY_NAME = "ptyrevoke"

OPEN_FAIL = (
    "open fd=-1 errno=1 grant ok=-1 errno=0 unlock ok=-1 errno=0 "
    "pts ok=-1 errno=0 revoke rc=-1 errno=0\n"
)
REVOKE_FAIL = (
    "open fd=3 errno=0 grant ok=1 errno=0 unlock ok=1 errno=0 "
    "pts ok=1 errno=0 revoke rc=-1 errno=1\n"
)
FULL_ALLOW = (
    "open fd=3 errno=0 grant ok=1 errno=0 unlock ok=1 errno=0 "
    "pts ok=1 errno=0 revoke rc=0 errno=0\n"
)
PTS_FAIL = (
    "open fd=3 errno=0 grant ok=1 errno=0 unlock ok=1 errno=0 "
    "pts ok=0 errno=1 revoke rc=-1 errno=0\n"
)
NAME_BAD = "name-bad\n"
DENY_LINES = (OPEN_FAIL, REVOKE_FAIL)

FILE_GRANT = '(allow file-read* file-write* (literal "/dev/ptmx"))\n'
IOCTL_LINE = '(allow file-ioctl (literal "/dev/ptmx"))\n'
TTYS_LINE = '(allow file-read* file-write* (regex #"^/dev/ttys[0-9]+$"))\n'
SETUP_LINES = (FILE_GRANT, IOCTL_LINE, TTYS_LINE)
PLANT_PHRASE = "(allow file-revoke)"
PLANT_LINE = PLANT_PHRASE + "\n"
BROADER_REVOKES = (
    '(allow file-revoke (regex #"^/dev/ttys[0-9]+$"))\n',
    '(allow file-revoke (regex #"^/dev/ttys"))\n',
    '(allow file-revoke (subpath "/dev"))\n',
    '(allow file-revoke (vnode-type TTY))\n',
)
DENY_DEFAULT = "(deny default)\n"
BARE_IOCTL = "(allow file-ioctl)\n"
ALLOW_SIGNAL = "(allow signal)\n"
MACH_LOOKUP = "(allow mach-lookup)\n"
ALLOW_FORK = "(allow process-fork)\n"
ALLOW_NETWORK = "(allow network*)\n"
ALLOW_SYSTEM_SOCKET = "(allow system-socket)\n"
ALLOW_IOKIT = "(allow iokit-open)\n"
ALLOW_PSEUDO = "(allow pseudo-tty)\n"
ALLOW_EXTENSION = "(allow file-issue-extension)\n"
ALLOW_SCHED = "(allow system-sched)\n"
ALLOW_SHM = "(allow ipc-posix-shm)\n"
ALLOW_DEBUG = "(allow system-debug)\n"
ALLOW_FSCTL = "(allow system-fsctl)\n"
ALLOW_SETUGID = "(allow file-write-setugid)\n"

HELPER_C = r"""#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void) {
    int fd;
    int gr;
    int ur;
    int ge;
    int ue;
    int pok;
    int pe;
    int rok;
    int re;
    char *name;
    for (fd = 3; fd < 64; fd++) {
        close(fd);
    }
    errno = 0;
    fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (fd < 0) {
        printf("open fd=-1 errno=%d grant ok=-1 errno=0 unlock ok=-1 errno=0 pts ok=-1 errno=0 revoke rc=-1 errno=0\n", errno);
        return 0;
    }
    errno = 0;
    gr = grantpt(fd);
    ge = gr == 0 ? 0 : errno;
    errno = 0;
    ur = unlockpt(fd);
    ue = ur == 0 ? 0 : errno;
    errno = 0;
    name = ptsname(fd);
    if (name == NULL) {
        pok = 0;
        pe = errno;
        rok = -1;
        re = 0;
    } else if (strncmp(name, "/dev/ttys", 9) != 0) {
        printf("name-bad\n");
        close(fd);
        return 0;
    } else {
        pok = 1;
        pe = 0;
        errno = 0;
        rok = revoke(name);
        re = rok == 0 ? 0 : errno;
    }
    printf("open fd=%d errno=0 grant ok=%d errno=%d unlock ok=%d errno=%d pts ok=%d errno=%d revoke rc=%d errno=%d\n",
        fd,
        gr == 0 ? 1 : 0, ge,
        ur == 0 ? 1 : 0, ue,
        pok, pe,
        rok, re);
    close(fd);
    return 0;
}
"""

FINDINGS = {
    "wallet": "lab/redteam/findings/CRITICAL-confine-073.md",
    "did": "lab/redteam/findings/CRITICAL-confine-073.md",
    "model": "lab/redteam/findings/CRITICAL-cc-model-confine-073.md",
}
IDS = {
    "wallet": "CRITICAL-confine-073",
    "did": "CRITICAL-confine-073",
    "model": "CRITICAL-cc-model-confine-073",
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
STILL_DENY_RULES = (
    ("wallet-deleted", "delete"),
    ("wallet-signal", ALLOW_SIGNAL),
    ("wallet-lookup", MACH_LOOKUP),
    ("wallet-fork", ALLOW_FORK),
    ("wallet-network", ALLOW_NETWORK),
    ("wallet-system-socket", ALLOW_SYSTEM_SOCKET),
    ("wallet-iokit", ALLOW_IOKIT),
    ("wallet-ioctl", BARE_IOCTL),
    ("wallet-pseudo", ALLOW_PSEUDO),
    ("wallet-extension", ALLOW_EXTENSION),
    ("wallet-sched", ALLOW_SCHED),
    ("wallet-shm", ALLOW_SHM),
    ("wallet-debug", ALLOW_DEBUG),
    ("wallet-fsctl", ALLOW_FSCTL),
    ("wallet-setugid", ALLOW_SETUGID),
)
FULL_ALLOW_RULES = (
    ("wallet-revoke-ttys-digits", BROADER_REVOKES[0]),
    ("wallet-revoke-ttys", BROADER_REVOKES[1]),
    ("wallet-revoke-dev", BROADER_REVOKES[2]),
    ("wallet-revoke-tty", BROADER_REVOKES[3]),
)
STILL_DENY_COPIES = tuple(stem for stem, _rule in STILL_DENY_RULES)

_LINE = re.compile(
    r"open fd=(-?[0-9]+) errno=(-?[0-9]+) "
    r"grant ok=(-?[0-9]+) errno=(-?[0-9]+) "
    r"unlock ok=(-?[0-9]+) errno=(-?[0-9]+) "
    r"pts ok=(-?[0-9]+) errno=(-?[0-9]+) "
    r"revoke rc=(-?[0-9]+) errno=(-?[0-9]+)\n"
)
_FIELDS = (
    "fd",
    "open errno",
    "grant ok",
    "grant errno",
    "unlock ok",
    "unlock errno",
    "pts ok",
    "pts errno",
    "revoke rc",
    "revoke errno",
)

START_SHA = {}


def launched_copy_names():
    """Basenames the falsifier launches, in order."""
    names = []
    for profile in PROFILES:
        names.append(profile["name"] + "-allow.sb")
        names.append(profile["name"] + "-setup.sb")
        names.append(profile["name"] + "-plant.sb")
    names.append("wallet-pts.sb")
    for stem, _rule in STILL_DENY_RULES:
        names.append(stem + ".sb")
    for stem, _line in FULL_ALLOW_RULES:
        names.append(stem + ".sb")
    return names


def format_open(
    fd, open_errno, grant_ok, grant_errno, unlock_ok, unlock_errno,
    pts_ok, pts_errno, revoke_rc, revoke_errno,
):
    """One helper line from the ten printed fields."""
    return (
        f"open fd={fd} errno={open_errno} "
        f"grant ok={grant_ok} errno={grant_errno} "
        f"unlock ok={unlock_ok} errno={unlock_errno} "
        f"pts ok={pts_ok} errno={pts_errno} "
        f"revoke rc={revoke_rc} errno={revoke_errno}\n"
    )


def revoke_allowed(text):
    """True when the text holds the plant or a broader file-revoke allow."""
    if PLANT_LINE in text:
        return True
    return any(line in text for line in BROADER_REVOKES)


def stdout_for_profile_text(text):
    """The measured line for a profile text. Injection uses this one rule.

    No ptmx file grant leaves the open denied, including the plant alone.
    The file grant and the ioctl grant without the ttys grant leave the
    slave name denied. All three setup lines leave ``revoke`` denied.
    The plant, or a broader file-revoke allow, beside those three lines
    is the full allow.
    """
    has_file = FILE_GRANT in text
    has_ioctl = IOCTL_LINE in text
    has_ttys = TTYS_LINE in text
    if has_file and has_ioctl and not has_ttys:
        return PTS_FAIL
    if has_file and has_ioctl and has_ttys and revoke_allowed(text):
        return FULL_ALLOW
    if has_file and has_ioctl and has_ttys:
        return REVOKE_FAIL
    return OPEN_FAIL


def broken_plant_phrase(text):
    """True when the plant phrase is present and is not a whole line.

    A longer file-revoke filter has a space after the phrase. That filter
    is not the plant. The exact line ends with a newline.
    """
    start = 0
    while True:
        at = text.find(PLANT_PHRASE, start)
        if at < 0:
            return False
        nxt = text[at + len(PLANT_PHRASE):at + len(PLANT_PHRASE) + 1]
        if nxt == "\n" or nxt == " ":
            start = at + len(PLANT_PHRASE)
            continue
        return True


class NotDenied(AssertionError):
    """The profile let ``revoke`` of the pty slave succeed."""

    def __init__(self, result):
        self.result = result
        super().__init__(
            "ALLOW: revoke succeeded under the profile.\n"
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


def canonical_decimal(text):
    """True when ``text`` is the helper's ``%d`` spelling."""
    return str(int(text)) == text


def parse_line(stdout):
    """The ten printed fields, or None when the line is not that shape.

    A non-canonical integer is its own harness error. ``int`` accepts ``01``
    and ``-0``; the helper's ``%d`` does not print them.
    """
    match = _LINE.fullmatch(stdout)
    if match is None:
        return None
    groups = match.groups()
    for name, text in zip(_FIELDS, groups):
        if not canonical_decimal(text):
            raise HarnessError(
                f"noncanonical {name} integer {text!r} is a harness error, "
                "not a deny and not an allow: " + repr(stdout)
            )
    return tuple(int(group) for group in groups)


def decision(stdout):
    """``deny`` or ``allow``. A bad line raises.

    Only the open-fail line and the revoke-fail line are denies. Only the
    full allow line is an allow. ``revoke rc=0`` on any other line is not.
    """
    if stdout == NAME_BAD:
        raise HarnessError(
            "name-bad is a harness error, not a deny and not an allow: "
            + repr(stdout)
        )
    parsed = parse_line(stdout)
    if parsed is None:
        raise HarnessError(
            "malformed stdout is a harness error, not a deny and not an allow: "
            + repr(stdout)
        )
    (
        fd, open_errno, grant_ok, grant_errno, unlock_ok, unlock_errno,
        pts_ok, pts_errno, revoke_rc, revoke_errno,
    ) = parsed
    if fd != -1 and fd != 3:
        raise HarnessError(
            "fd other than -1 or 3 is a harness error, "
            "not a deny and not an allow: " + repr(stdout)
        )
    if fd == -1 and open_errno != 1:
        raise HarnessError(
            "open errno other than 1 on fd=-1 is a harness error, "
            "not a deny and not an allow: " + repr(stdout)
        )
    if fd == 3 and open_errno != 0:
        raise HarnessError(
            "open errno other than 0 on fd 3 is a harness error, "
            "not a deny and not an allow: " + repr(stdout)
        )
    if fd == -1:
        if stdout != OPEN_FAIL:
            raise HarnessError(
                "fd=-1 stdout is not the open-fail deny: " + repr(stdout)
            )
        return "deny"
    if grant_ok == -1:
        raise HarnessError(
            "grant ok=-1 after open fd=3 is a harness error, "
            "not a deny and not an allow: " + repr(stdout)
        )
    if grant_ok == 0:
        raise HarnessError(
            "grant ok=0 after open fd=3 is a harness error, "
            "not a deny and not an allow: " + repr(stdout)
        )
    if grant_ok != 1:
        raise HarnessError(
            "grant ok other than 1 is a harness error, "
            "not a deny and not an allow: " + repr(stdout)
        )
    if grant_errno != 0:
        raise HarnessError(
            "grant ok=1 with errno other than 0 is a harness error, not an allow: "
            + repr(stdout)
        )
    if unlock_ok == -1:
        raise HarnessError(
            "unlock ok=-1 after open fd=3 is a harness error, "
            "not a deny and not an allow: " + repr(stdout)
        )
    if unlock_ok == 0:
        raise HarnessError(
            "unlock ok=0 after open fd=3 is a harness error, "
            "not a deny and not an allow: " + repr(stdout)
        )
    if unlock_ok != 1:
        raise HarnessError(
            "unlock ok other than 1 is a harness error, "
            "not a deny and not an allow: " + repr(stdout)
        )
    if unlock_errno != 0:
        raise HarnessError(
            "unlock ok=1 with errno other than 0 is a harness error, not an allow: "
            + repr(stdout)
        )
    if pts_ok == 0:
        raise HarnessError(
            "pts ok=0 after open fd=3 is a harness error, "
            "not a deny and not an allow: " + repr(stdout)
        )
    if pts_ok != 1:
        raise HarnessError(
            "pts ok other than 1 is a harness error, "
            "not a deny and not an allow: " + repr(stdout)
        )
    if pts_errno != 0:
        raise HarnessError(
            "pts ok=1 with errno other than 0 is a harness error, "
            "not a deny and not an allow: " + repr(stdout)
        )
    if revoke_rc == 0 and revoke_errno != 0:
        raise HarnessError(
            "revoke rc=0 with errno other than 0 is a harness error, not an allow: "
            + repr(stdout)
        )
    if revoke_rc == -1 and revoke_errno != 1:
        raise HarnessError(
            "revoke rc=-1 with errno other than 1 when pts ok is 1 "
            "is a harness error, not a deny and not an allow: " + repr(stdout)
        )
    if stdout == FULL_ALLOW:
        return "allow"
    if stdout == REVOKE_FAIL:
        return "deny"
    if revoke_rc == 0:
        raise HarnessError(
            "revoke rc=0 is an allow only on the full allow line: " + repr(stdout)
        )
    raise HarnessError(
        "stdout is not a deny and not an allow: " + repr(stdout)
    )


def classify(result):
    """``deny`` or ``allow``. Otherwise a harness error.

    Asks ``sbx.profile_error`` before it reads a deny or an allow. Exit 65
    is a profile error even when stderr says ``Operation not permitted``.
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
        if result.stdout in DENY_LINES:
            raise HarnessError(
                "nonempty deny stderr is a harness error, not a deny: "
                + repr(result.stderr)
            )
        if result.stdout == FULL_ALLOW:
            raise HarnessError(
                "nonempty allow stderr is a harness error, not an allow: "
                + repr(result.stderr)
            )
        raise HarnessError(
            "nonempty stderr is a harness error, not a deny and not an allow: "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    return decision(result.stdout)


def compile_revoke(parent, root, source_text):
    """Compile ``source_text`` with ``/usr/bin/cc`` into ``<root>/ptyrevoke``.

    The source file sits in ``parent``. The command is ``/usr/bin/cc -o
    <root>/ptyrevoke <parent>/ptyrevoke.c``. No extra framework. This does
    not start ``sandbox-exec``. Inherited descriptors are closed. A nonzero
    exit, stderr on exit 0, or a missing executable is a harness error,
    not a skip.
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
        timeout=60,
        cwd=parent,
        close_fds=True,
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


def revoke_under(profile):
    """Run the compiled helper under ``profile``. Pass no argv."""
    binary = RevokeProbe.binary
    root = RevokeProbe.root
    parent = RevokeProbe.parent
    if not binary or not root or not parent:
        raise HarnessError("the revoke helper is not compiled")
    return run_sandboxed(binary, root, parent, profile)


def require_unsandboxed_allow(result):
    """The unsandboxed control must be the full allow line.

    The open-fail line, the revoke-fail line, the pts-fail line, ``name-bad``,
    a bad exit, stderr, or a malformed line is a harness error. An ordinary
    assertion is not this check.
    """
    if result.argv and os.fspath(result.argv[0]) == sbx.SANDBOX_EXEC:
        raise HarnessError(
            "unsandboxed control started sandbox-exec: " + repr(result.argv)
        )
    if result.exit_code == 0 and result.stderr == "" and result.stdout == OPEN_FAIL:
        raise HarnessError(
            "unsandboxed open deny is a harness error, not a passing control: "
            + repr(result.stdout)
        )
    if result.exit_code == 0 and result.stderr == "" and result.stdout == REVOKE_FAIL:
        raise HarnessError(
            "unsandboxed revoke deny is a harness error, not a passing control: "
            + repr(result.stdout)
        )
    outcome = classify(result)
    if outcome != "allow" or result.stdout != FULL_ALLOW:
        raise HarnessError(
            "unsandboxed control is not the full allow: " + repr(result.stdout)
        )
    return result


def run_unsandboxed(binary):
    """The helper with no profile and no argv. This does not start ``sandbox-exec``.

    Inherited descriptors are closed, so the master is fd 3.
    """
    require_storage_path(binary)
    completed = subprocess.run(
        [binary],
        capture_output=True,
        text=True,
        timeout=HELPER_TIMEOUT,
        close_fds=True,
    )
    result = sbx.Result(
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        argv=[binary],
    )
    return require_unsandboxed_allow(result)


def require_denied(profile):
    """The one helper. ``profile`` must refuse ``revoke``.

    The three real-file tests and the plant call this. An allow raises
    ``NotDenied``. A harness error propagates and is not a deny.
    """
    result = revoke_under(profile)
    if classify(result) != "deny":
        raise NotDenied(result)
    return result


def ensure_trailing_newline(text):
    if text.endswith("\n"):
        return text
    return text + "\n"


def with_setup(text):
    """Append the three setup lines. Those lines are not the plant."""
    return ensure_trailing_newline(text) + FILE_GRANT + IOCTL_LINE + TTYS_LINE


def with_setup_and_plant(text):
    """Append the three setup lines and then the plant."""
    return with_setup(text) + PLANT_LINE


def ensure_setup(text):
    """The text with each setup line present once.

    A recorded baseline already has the lines. A clean baseline does not.
    """
    body = text
    for line in SETUP_LINES:
        if line not in body:
            body = ensure_trailing_newline(body) + line
    return body


def plant_only_text(text):
    """The plant on a copy whose setup lines have been removed.

    A recorded baseline still has the setup lines. Leaving them in place
    would allow ``revoke`` instead of failing the open.
    """
    base = text
    for line in SETUP_LINES:
        base = base.replace(line, "")
    planted = ensure_trailing_newline(base) + PLANT_LINE
    for line in SETUP_LINES:
        if line in planted:
            raise HarnessError("plant-only copy still has a setup line")
    return planted


def pts_fail_text(text):
    """The file grant, the ioctl grant, and the plant. No ttys line."""
    base = text.replace(TTYS_LINE, "")
    if FILE_GRANT not in base:
        base = ensure_trailing_newline(base) + FILE_GRANT
    if IOCTL_LINE not in base:
        base = ensure_trailing_newline(base) + IOCTL_LINE
    if PLANT_LINE not in base:
        base = ensure_trailing_newline(base) + PLANT_LINE
    if TTYS_LINE in base:
        raise HarnessError("pts copy still has the ttys line")
    return base


def without_deny_default(text):
    """Delete the one ``(deny default)`` line. That deletion is not the plant."""
    if text.count(DENY_DEFAULT) != 1:
        raise HarnessError(
            f"(deny default) occurs {text.count(DENY_DEFAULT)} times, not once"
        )
    return text.replace(DENY_DEFAULT, "", 1)


def still_deny_text(seat, kind):
    """One wallet edit that keeps the three setup lines and is not the plant."""
    for line in SETUP_LINES:
        if line not in seat:
            raise HarnessError("still-deny copy is missing a setup line")
    if PLANT_LINE in seat:
        raise HarnessError("still-deny copy contains the plant")
    if kind == "delete":
        return without_deny_default(seat)
    return ensure_trailing_newline(seat) + kind


def write_copy(directory, name, text):
    path = os.path.join(directory, name + ".sb")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def finding_paragraph(profile, result):
    """One CRITICAL record. The first line carries the live pin.

    The commit is ``git log -1 --format=%H HEAD -- <file>`` via
    ``last_change``. The digest is the bytes this run read. Neither value
    is stored in this file. The helper line is ``result.command``. The
    record names ``revoke`` when ``revoke rc`` is 0.
    """
    if "revoke rc=0" not in result.stdout:
        raise HarnessError("finding names no revoke: " + repr(result.stdout))
    commit = last_change(profile["path"])
    digest = sha256_file(profile["path"])
    return (
        f"CRITICAL {IDS[profile['name']]} {commit} {pr_label(commit)} "
        f"sha256 {digest}\n"
        f"profile: {profile['rel']}\n"
        f"helper: {result.command}\n"
        f"observed: {result.stdout.strip()}\n"
    )


def require_finding_pins(paragraph, profile, result):
    """The finding names the PR and the exact command. Each omission fails alone."""
    label = pr_label(last_change(profile["path"]))
    command = result.command
    if not label or label not in paragraph:
        raise AssertionError("finding omits pr_label")
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
        "The live profile allowed revoke of a pty slave. "
        f"Finding file: {finding_rel}"
    )
    wrapped = unittest.expectedFailure(recorded)
    setattr(case_cls, method_name, wrapped)
    case_cls.addClassCleanup(setattr, case_cls, method_name, method)


def observe(case_cls):
    """Classify each live profile. Record each allow before the next profile.

    A later harness error still propagates. Allows already confirmed stay
    written and marked. A refusal before any allow writes nothing.
    An open that fails is the clean deny, not a finding. The revoke-fail
    line is the clean deny of ``revoke``, not a finding.
    """
    case_cls.recorded_allows = {}
    confirmed = []
    for profile in PROFILES:
        result = revoke_under(profile["path"])
        outcome = classify(result)
        if outcome != "allow":
            continue
        confirmed.append((profile, result))
        # Snapshot: a later append must not change the list this call recorded.
        write_findings(ROOT, list(confirmed))
        case_cls.recorded_allows[profile["name"]] = FINDINGS[profile["name"]]
        mark_expected(
            case_cls,
            f"test_{profile['name']}_revoke_is_denied",
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


class RevokeProbe(unittest.TestCase):
    """The helper under the live profiles, and the file-revoke plant."""

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
        cls.parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptyrevoke-parent-"))
        cls.root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptyrevoke-root-"))
        cls.addClassCleanup(shutil.rmtree, cls.parent, ignore_errors=True)
        cls.addClassCleanup(shutil.rmtree, cls.root, ignore_errors=True)
        cls.binary = compile_revoke(cls.parent, cls.root, HELPER_C)
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

    def test_unsandboxed_revoke_succeeds(self):
        """Without ``sandbox-exec``, the helper exits 0 and ``revoke`` succeeds.

        Inherited descriptors are closed. Stderr is empty. Stdout is the
        full allow line. A failure here is a harness error, so a later deny
        is about the profile.
        """
        source = os.path.join(self.parent, SOURCE_NAME)
        self.assertEqual(Path(source).read_text(encoding="utf-8"), HELPER_C)
        self.assertIn("posix_openpt", HELPER_C)
        self.assertIn("grantpt", HELPER_C)
        self.assertIn("unlockpt", HELPER_C)
        self.assertIn("ptsname", HELPER_C)
        self.assertIn("revoke", HELPER_C)
        self.assertIn("for (fd = 3; fd < 64; fd++)", HELPER_C)
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
        self.assertEqual(result.stdout, FULL_ALLOW)
        self.assertEqual(classify(result), "allow")
        self.assertIn("revoke rc=0", result.stdout)

    def test_compile_failure_is_an_error(self):
        """``/usr/bin/cc`` on an empty source is a harness error, not a skip."""
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptyrevoke-empty-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptyrevoke-empty-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with self.assertRaises(HarnessError) as caught:
            compile_revoke(parent, root, "")
        message = str(caught.exception)
        self.assertIn(CC, message)
        self.assertIn("not a skip", message)
        self.assertNotIn("SKIPPED", message)

    def _expect_real_deny(self, profile):
        self.assertTrue(os.path.isfile(profile))
        result = require_denied(profile)
        self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
        self.assertIn(f"PROVIDER_EXECUTABLE={self.binary}", result.argv)
        self.assertEqual(result.argv[-1], self.binary)
        self.assertEqual(result.argv[-2], os.fspath(profile))
        self.assertIn(os.fspath(profile), result.argv)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, OPEN_FAIL)
        self.assertEqual(classify(result), "deny")
        return result

    def test_wallet_revoke_is_denied(self):
        """The real wallet profile denies the open, so revoke is not called."""
        self._expect_real_deny(sbx.WALLET_CONFINE_SB)

    def test_did_revoke_is_denied(self):
        """The real did profile denies the open, so revoke is not called."""
        did = sbx.REPO_ROOT / "capsules/did-provider/confine.sb"
        self._expect_real_deny(did)

    def test_model_revoke_is_denied(self):
        """The real model profile denies the open. The helper starts under it."""
        model = sbx.REPO_ROOT / "capsules/model-provider/confine.sb"
        self._expect_real_deny(model)

    def _expect_allow_copy(self, profile, copy):
        with self.assertRaises(NotDenied) as caught:
            require_denied(copy)
        result = caught.exception.result
        self.assertIn("ALLOW", str(caught.exception))
        self.assertIn("revoke", str(caught.exception))
        self.assertIsNone(sbx.profile_error(result))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, FULL_ALLOW)
        self.assertEqual(classify(result), "allow")
        self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
        self.assertIn(copy, result.argv)
        self.assertNotIn(os.fspath(profile["path"]), result.argv)
        return result

    def _expect_deny_copy(self, profile, copy, stdout):
        denied = require_denied(copy)
        self.assertEqual(denied.stdout, stdout)
        self.assertEqual(denied.stderr, "")
        self.assertEqual(denied.exit_code, 0)
        self.assertEqual(classify(denied), "deny")
        self.assertEqual(denied.argv[0], sbx.SANDBOX_EXEC)
        self.assertIn(copy, denied.argv)
        self.assertNotIn(os.fspath(profile["path"]), denied.argv)
        return denied

    def test_falsifier_allow_revoke_is_caught(self):
        """The file-revoke plant beside the three setup lines allows revoke.

        The zero-count reads the plant baseline from ``_source_for_plant``.
        It counts the exact plant line. Clean input has that line and each
        setup line zero times. Recorded input keeps one of each setup line;
        the plant line is stripped and is not counted. ``(deny default)``
        occurs once. A temp copy that appends the three setup lines and the
        plant prints the full allow line, and the helper pointed at the copy
        fails the deny check. A temp copy that appends the three setup lines
        and not the plant prints the revoke-fail line. A temp copy that
        appends only the plant prints the open-fail line. The file grant,
        the ioctl grant, and the plant, without the ttys line, are a harness
        error. One wallet copy for each still-deny edit, with the three
        setup lines, still prints the revoke-fail line. One wallet copy for
        each broader file-revoke allow prints the full allow line and is
        not the plant. The repo profile bytes stay unchanged.
        """
        before = {
            profile["rel"]: sha256_file(profile["path"]) for profile in PROFILES
        }
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptyrevoke-profile-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        try:
            for profile in PROFILES:
                with self.subTest(profile=profile["name"]):
                    text = profile["path"].read_text(encoding="utf-8")
                    baseline = self._source_for_plant(profile["name"], text)
                    self.assertEqual(text.count(DENY_DEFAULT), 1)
                    self.assertEqual(baseline.count(DENY_DEFAULT), 1)
                    self.assertEqual(baseline.count(PLANT_LINE), 0)
                    self.assertNotEqual(PLANT_LINE, FILE_GRANT)
                    self.assertNotEqual(PLANT_LINE, IOCTL_LINE)
                    self.assertNotEqual(PLANT_LINE, TTYS_LINE)
                    for broader in BROADER_REVOKES:
                        self.assertNotIn(PLANT_LINE, broader)
                        self.assertNotEqual(broader, PLANT_LINE)
                    recorded = profile["name"] in type(self).recorded_allows
                    if recorded and PLANT_LINE in text:
                        self.assertEqual(text.count(PLANT_LINE), 1)
                        for line in SETUP_LINES:
                            self.assertEqual(text.count(line), 1)
                            self.assertEqual(baseline.count(line), 1)
                        self.assertNotEqual(baseline, text)
                    elif not recorded:
                        self.assertEqual(text.count(PLANT_LINE), 0)
                        self.assertEqual(baseline, text)
                        for line in SETUP_LINES:
                            self.assertEqual(text.count(line), 0)
                            self.assertEqual(baseline.count(line), 0)
                        for broader in BROADER_REVOKES:
                            self.assertEqual(text.count(broader), 0)
                            self.assertEqual(baseline.count(broader), 0)
                    else:
                        for line in SETUP_LINES:
                            self.assertEqual(
                                baseline.count(line), text.count(line)
                            )
                    self.assertTrue(baseline.endswith("\n"))

                    planted = with_setup_and_plant(baseline)
                    self.assertEqual(planted.count(PLANT_LINE), baseline.count(PLANT_LINE) + 1)
                    for line in SETUP_LINES:
                        self.assertEqual(planted.count(line), baseline.count(line) + 1)
                    self.assertEqual(planted.count(DENY_DEFAULT), 1)
                    copy = write_copy(directory, profile["name"] + "-allow", planted)
                    self.assertEqual(Path(copy).read_text(encoding="utf-8"), planted)
                    self.assertNotEqual(
                        os.path.realpath(copy), os.path.realpath(profile["path"])
                    )
                    self._expect_allow_copy(profile, copy)

                    setup_only = with_setup(baseline)
                    self.assertEqual(setup_only.count(PLANT_LINE), 0)
                    setup_copy = write_copy(
                        directory, profile["name"] + "-setup", setup_only
                    )
                    self._expect_deny_copy(profile, setup_copy, REVOKE_FAIL)

                    only_plant = plant_only_text(baseline)
                    self.assertEqual(only_plant.count(PLANT_LINE), 1)
                    for line in SETUP_LINES:
                        self.assertNotIn(line, only_plant)
                    self.assertNotEqual(only_plant, text)
                    plant_copy = write_copy(
                        directory, profile["name"] + "-plant", only_plant
                    )
                    self._expect_deny_copy(profile, plant_copy, OPEN_FAIL)
                    self.assertEqual(
                        profile["path"].read_text(encoding="utf-8"), text
                    )

            wallet = PROFILES[0]
            self.assertEqual(wallet["name"], "wallet")
            wallet_text = wallet["path"].read_text(encoding="utf-8")
            baseline = self._source_for_plant("wallet", wallet_text)
            seat = ensure_setup(baseline)
            for line in SETUP_LINES:
                self.assertEqual(seat.count(line), 1)
            self.assertEqual(seat.count(PLANT_LINE), 0)
            self.assertEqual(seat.count(DENY_DEFAULT), 1)
            self.assertEqual(baseline.count(PLANT_LINE), 0)

            pts = pts_fail_text(baseline)
            self.assertIn(FILE_GRANT, pts)
            self.assertIn(IOCTL_LINE, pts)
            self.assertIn(PLANT_LINE, pts)
            self.assertNotIn(TTYS_LINE, pts)
            pts_copy = write_copy(directory, "wallet-pts", pts)
            with self.subTest(profile="wallet-pts"):
                with self.assertRaises(HarnessError) as caught:
                    require_denied(pts_copy)
                self.assertIn("pts ok=0", str(caught.exception))
                self.assertIn(repr(PTS_FAIL), str(caught.exception))
                self.assertNotIsInstance(caught.exception, NotDenied)

            for stem, kind in STILL_DENY_RULES:
                with self.subTest(profile=stem):
                    edited = still_deny_text(seat, kind)
                    for line in SETUP_LINES:
                        self.assertEqual(edited.count(line), 1)
                    self.assertEqual(edited.count(PLANT_LINE), 0)
                    self.assertNotIn(PLANT_LINE, edited)
                    if kind == "delete":
                        self.assertNotIn("(deny default)", edited)
                        self.assertNotIn("(allow default)", edited)
                    else:
                        self.assertEqual(edited.count(kind), seat.count(kind) + 1)
                        self.assertEqual(edited.count(DENY_DEFAULT), 1)
                        self.assertNotEqual(kind, PLANT_LINE)
                    copy = write_copy(directory, stem, edited)
                    self.assertEqual(Path(copy).read_text(encoding="utf-8"), edited)
                    self.assertNotEqual(
                        os.path.realpath(copy), os.path.realpath(wallet["path"])
                    )
                    self._expect_deny_copy(wallet, copy, REVOKE_FAIL)

            for stem, line in FULL_ALLOW_RULES:
                with self.subTest(profile=stem):
                    edited = ensure_trailing_newline(seat) + line
                    for setup in SETUP_LINES:
                        self.assertEqual(edited.count(setup), 1)
                    self.assertEqual(edited.count(PLANT_LINE), 0)
                    self.assertEqual(edited.count(line), 1)
                    self.assertNotEqual(line, PLANT_LINE)
                    copy = write_copy(directory, stem, edited)
                    self._expect_allow_copy(wallet, copy)
            self.assertEqual(wallet["path"].read_text(encoding="utf-8"), wallet_text)
        finally:
            require_unchanged(before)

    def _source_for_plant(self, name, text):
        """The text the temp plant edits. A recorded allow does not skip this.

        The deny test carries the finding-linked expected failure. The live
        file is not edited. One exact plant line is removed from the copy
        so the append is still that one line. The setup lines stay. A plant
        phrase with no trailing newline is its own harness error. A longer
        file-revoke filter is not the plant line.
        """
        finding = type(self).recorded_allows.get(name)
        if finding is None:
            if PLANT_LINE in text or broken_plant_phrase(text):
                raise AssertionError(f"{name} source contains {PLANT_PHRASE}")
            return text
        method = getattr(type(self), f"test_{name}_revoke_is_denied")
        if not getattr(method, "__unittest_expecting_failure__", False):
            raise HarnessError(f"{name} allow has no finding-linked expected failure")
        if finding not in (method.__doc__ or ""):
            raise HarnessError(f"{name} allow docstring does not name {finding}")
        occurrences = text.count(PLANT_LINE)
        if occurrences > 1:
            raise HarnessError(
                f"{PLANT_PHRASE} occurs {occurrences} times, not zero or one"
            )
        if occurrences == 1:
            text = text.replace(PLANT_LINE, "", 1)
        if broken_plant_phrase(text):
            raise HarnessError(f"{name} plant line has no trailing newline")
        return text


class RevokeRules(unittest.TestCase):
    """Classifier, pins, and injected results. They compile nothing and launch nothing."""

    def setUp(self):
        self.launch_guard = self.enter_patch(
            patch.object(
                subprocess, "run",
                side_effect=AssertionError("classifier launched a process"),
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
        probe_names = unittest.defaultTestLoader.getTestCaseNames(RevokeProbe)
        for missing in ((sbx.SANDBOX_EXEC,), (CC,), (sbx.SANDBOX_EXEC, CC)):
            with self.subTest(missing=missing), patch.object(
                os.path, "isfile", side_effect=lambda path: path not in missing
            ), patch(
                __name__ + ".compile_revoke",
                side_effect=AssertionError("missing-tool probe compiled a helper"),
            ) as compiled, patch.object(
                sbx, "run",
                side_effect=AssertionError("missing-tool probe launched a helper"),
            ) as launched:
                class MissingTools(RevokeProbe):
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
        The setup lines stay when the plant line is stripped. A recorded
        allow without that mark, a docstring that omits the finding, and a
        second plant line are each their own harness error. A longer
        file-revoke filter is not the plant.
        """
        with patch.object(os.path, "isfile", return_value=True):
            self.assertIsNone(skip_reason())
            self.assertTrue(os.path.isfile(CC))
            self.assertTrue(os.path.isfile(sbx.SANDBOX_EXEC))
        clean = "(version 1)\n(deny default)\n"
        setup = FILE_GRANT + IOCTL_LINE + TTYS_LINE
        recorded_text = clean + setup + PLANT_LINE
        broader_text = clean + setup + BROADER_REVOKES[0]
        self.assertEqual(stdout_for_profile_text(clean), OPEN_FAIL)
        self.assertEqual(stdout_for_profile_text(clean + PLANT_LINE), OPEN_FAIL)
        self.assertEqual(stdout_for_profile_text(clean + setup), REVOKE_FAIL)
        self.assertEqual(stdout_for_profile_text(recorded_text), FULL_ALLOW)
        self.assertEqual(
            stdout_for_profile_text(clean + FILE_GRANT + IOCTL_LINE + PLANT_LINE),
            PTS_FAIL,
        )
        for line in BROADER_REVOKES:
            self.assertEqual(stdout_for_profile_text(clean + setup + line), FULL_ALLOW)
            self.assertEqual(stdout_for_profile_text(clean + line), OPEN_FAIL)
            self.assertNotIn(PLANT_LINE, line)
        for _stem, rule in STILL_DENY_RULES:
            if rule == "delete":
                deleted = (clean + setup).replace(DENY_DEFAULT, "", 1)
                self.assertNotIn(DENY_DEFAULT, deleted)
                self.assertEqual(stdout_for_profile_text(deleted), REVOKE_FAIL)
            else:
                self.assertEqual(
                    stdout_for_profile_text(clean + setup + rule), REVOKE_FAIL,
                )

        class Recorded(RevokeProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Recorded, "test_wallet_revoke_is_denied", FINDINGS["wallet"])
        try:
            case = Recorded("test_falsifier_allow_revoke_is_caught")
            baseline = case._source_for_plant("wallet", recorded_text)
            self.assertEqual(baseline, clean + setup)
            self.assertEqual(baseline.count(PLANT_LINE), 0)
            for line in SETUP_LINES:
                self.assertEqual(baseline.count(line), 1)
            self.assertEqual(
                case._source_for_plant("wallet", broader_text),
                broader_text,
            )
            self.assertEqual(case._source_for_plant("did", clean), clean)
            self.assertNotIsInstance(baseline, type(unittest.SkipTest("x")))
        finally:
            Recorded.doClassCleanups()

        class Bare(RevokeProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        bare = Bare("test_falsifier_allow_revoke_is_caught")
        with self.assertRaises(HarnessError) as unmarked:
            bare._source_for_plant("wallet", recorded_text)
        self.assertEqual(
            str(unmarked.exception),
            "wallet allow has no finding-linked expected failure",
        )
        self.assertNotIsInstance(unmarked.exception, unittest.SkipTest)

        class WrongDoc(RevokeProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        def body(self):
            raise NotDenied(
                sbx.Result(exit_code=0, stdout=FULL_ALLOW, stderr="", argv=[])
            )

        body.__doc__ = "plain"
        body.__unittest_expecting_failure__ = True
        WrongDoc.test_wallet_revoke_is_denied = body
        wrong = WrongDoc("test_falsifier_allow_revoke_is_caught")
        with self.assertRaises(HarnessError) as unnamed:
            wrong._source_for_plant("wallet", recorded_text)
        self.assertEqual(
            str(unnamed.exception),
            f"wallet allow docstring does not name {FINDINGS['wallet']}",
        )

        class Twice(RevokeProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Twice, "test_wallet_revoke_is_denied", FINDINGS["wallet"])
        try:
            twice = Twice("test_falsifier_allow_revoke_is_caught")
            with self.assertRaises(HarnessError) as extra:
                twice._source_for_plant("wallet", recorded_text + PLANT_LINE)
            self.assertEqual(
                str(extra.exception),
                f"{PLANT_PHRASE} occurs 2 times, not zero or one",
            )
        finally:
            Twice.doClassCleanups()

        class BareLine(RevokeProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(BareLine, "test_wallet_revoke_is_denied", FINDINGS["wallet"])
        try:
            bare_line = BareLine("test_falsifier_allow_revoke_is_caught")
            missing_newline = "wallet plant line has no trailing newline"
            with self.assertRaises(HarnessError) as bare_phrase:
                bare_line._source_for_plant("wallet", clean + PLANT_PHRASE)
            self.assertEqual(str(bare_phrase.exception), missing_newline)
            with self.assertRaises(HarnessError) as mixed:
                bare_line._source_for_plant(
                    "wallet", clean + setup + PLANT_LINE + PLANT_PHRASE
                )
            self.assertEqual(str(mixed.exception), missing_newline)
        finally:
            BareLine.doClassCleanups()

        class Clean(RevokeProbe):
            recorded_allows = {}

        plain = Clean("test_falsifier_allow_revoke_is_caught")
        with self.assertRaises(AssertionError) as present:
            plain._source_for_plant("wallet", recorded_text)
        self.assertEqual(
            str(present.exception),
            f"wallet source contains {PLANT_PHRASE}",
        )
        self.assertEqual(plain._source_for_plant("wallet", clean), clean)
        self.assertEqual(plain._source_for_plant("wallet", clean + setup), clean + setup)
        self.assertEqual(plain._source_for_plant("wallet", broader_text), broader_text)
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

        rel = "tmp/ptyrevoke-confine.sb"
        self.assertNotIn(rel, START_SHA)
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptyrevoke-byte-"))
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
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptyrevoke-cc-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptyrevoke-cc-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        binary = os.path.join(root, BINARY_NAME)
        source = "int main(void) { return 0; }\n"
        reasons = []

        def compiled(completed, access=None):
            runners = patch.object(subprocess, "run", return_value=completed)
            if access is None:
                with runners:
                    return compile_revoke(parent, root, source)
            with runners, patch.object(os, "access", return_value=access):
                return compile_revoke(parent, root, source)

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
        source_path = os.path.join(parent, SOURCE_NAME)
        with patch.object(subprocess, "run", return_value=silent) as ran, patch.object(
            os, "access", return_value=True
        ):
            self.assertEqual(compile_revoke(parent, root, source), binary)
        self.assertEqual(ran.call_args.args[0], [CC, "-o", binary, source_path])
        self.assertTrue(ran.call_args.kwargs.get("close_fds"))

        def refuse_cc(*_args, **_kwargs):
            raise AssertionError("compiler started")

        for label, compile_parent, compile_root in (
            ("parent", "/var/folders/cc/ptyrevoke-parent", root),
            ("root", parent, "/var/folders/cc/ptyrevoke-root"),
        ):
            bad = compile_parent if label == "parent" else compile_root
            expected = (
                f"execvp: {bad} contains /var/folders without the /private prefix"
            )
            with self.subTest(path=label), patch.object(
                subprocess, "run", side_effect=refuse_cc
            ):
                with self.assertRaises(HarnessError) as caught:
                    compile_revoke(compile_parent, compile_root, source)
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
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptyrevoke-bytes-"))
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

            class Plant(RevokeProbe):
                recorded_allows = {}

            state = {"mutate": False}

            def fake_denied(profile):
                profile = os.fspath(profile)
                text = Path(profile).read_text(encoding="utf-8")
                stdout = stdout_for_profile_text(text)
                result = sbx.Result(
                    exit_code=0,
                    stdout=stdout,
                    stderr="",
                    argv=[sbx.SANDBOX_EXEC, "-f", profile, "/private/ptyrevoke"],
                )
                if state["mutate"] and profile.endswith(os.sep + "wallet-deleted.sb"):
                    wallet["path"].write_bytes(after_bytes)
                if classify(result) != "deny":
                    raise NotDenied(result)
                return result

            case = Plant("test_falsifier_allow_revoke_is_caught")
            try:
                with patch(__name__ + ".PROFILES", profiles), patch(
                    __name__ + ".require_denied", new=fake_denied
                ), patch(__name__ + ".changed", new=spy):
                    with self.subTest(path="falsifier-equal"):
                        seen.clear()
                        state["mutate"] = False
                        case.test_falsifier_allow_revoke_is_caught()
                        self.assertEqual(seen, equal_pairs)
                    with self.subTest(path="falsifier-changed"):
                        seen.clear()
                        state["mutate"] = True
                        wallet["path"].write_bytes(clean)
                        with self.assertRaises(AssertionError) as caught:
                            case.test_falsifier_allow_revoke_is_caught()
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
        def described(reason, stdout):
            return reason + ": " + repr(stdout)

        other_fd = format_open(4, 0, 1, 0, 1, 0, 1, 0, 0, 0)
        wrong_open = format_open(-1, 2, -1, 0, -1, 0, -1, 0, -1, 0)
        grant_absent = format_open(3, 0, -1, 0, -1, 0, -1, 0, -1, 0)
        grant_zero = format_open(3, 0, 0, 1, 0, 1, 0, 1, -1, 0)
        revoke_errno = format_open(3, 0, 1, 0, 1, 0, 1, 0, 0, 2)
        revoke_zero = format_open(3, 0, 1, 0, 1, 0, 1, 0, -1, 0)
        malformed = "open nope\n"
        return (
            (
                "wrong exit",
                sbx.Result(
                    exit_code=2, stdout=OPEN_FAIL, stderr="", argv=["/private/ptyrevoke"],
                ),
                "wrong exit 2 is a harness error, not a deny and not an allow. "
                f"stdout={OPEN_FAIL!r} stderr=''",
            ),
            (
                "fd other than -1 or 3",
                sbx.Result(
                    exit_code=0, stdout=other_fd, stderr="", argv=["/private/ptyrevoke"],
                ),
                described(
                    "fd other than -1 or 3 is a harness error, "
                    "not a deny and not an allow",
                    other_fd,
                ),
            ),
            (
                "open errno other than 1 on fd=-1",
                sbx.Result(
                    exit_code=0, stdout=wrong_open, stderr="", argv=["/private/ptyrevoke"],
                ),
                described(
                    "open errno other than 1 on fd=-1 is a harness error, "
                    "not a deny and not an allow",
                    wrong_open,
                ),
            ),
            (
                "grant ok=-1 after open fd=3",
                sbx.Result(
                    exit_code=0, stdout=grant_absent, stderr="", argv=["/private/ptyrevoke"],
                ),
                described(
                    "grant ok=-1 after open fd=3 is a harness error, "
                    "not a deny and not an allow",
                    grant_absent,
                ),
            ),
            (
                "pts ok=0 after open fd=3",
                sbx.Result(
                    exit_code=0, stdout=PTS_FAIL, stderr="", argv=["/private/ptyrevoke"],
                ),
                described(
                    "pts ok=0 after open fd=3 is a harness error, "
                    "not a deny and not an allow",
                    PTS_FAIL,
                ),
            ),
            (
                "grant ok=0 after open fd=3",
                sbx.Result(
                    exit_code=0, stdout=grant_zero, stderr="", argv=["/private/ptyrevoke"],
                ),
                described(
                    "grant ok=0 after open fd=3 is a harness error, "
                    "not a deny and not an allow",
                    grant_zero,
                ),
            ),
            (
                "revoke rc=0 with errno other than 0",
                sbx.Result(
                    exit_code=0, stdout=revoke_errno, stderr="", argv=["/private/ptyrevoke"],
                ),
                described(
                    "revoke rc=0 with errno other than 0 is a harness error, not an allow",
                    revoke_errno,
                ),
            ),
            (
                "revoke rc=-1 with errno other than 1 when pts ok is 1",
                sbx.Result(
                    exit_code=0, stdout=revoke_zero, stderr="", argv=["/private/ptyrevoke"],
                ),
                described(
                    "revoke rc=-1 with errno other than 1 when pts ok is 1 "
                    "is a harness error, not a deny and not an allow",
                    revoke_zero,
                ),
            ),
            (
                "name-bad is a harness error",
                sbx.Result(
                    exit_code=0, stdout=NAME_BAD, stderr="", argv=["/private/ptyrevoke"],
                ),
                "name-bad is a harness error, not a deny and not an allow: "
                + repr(NAME_BAD),
            ),
            (
                "nonempty deny stderr",
                sbx.Result(
                    exit_code=0, stdout=OPEN_FAIL, stderr="noise\n", argv=["/private/ptyrevoke"],
                ),
                "nonempty deny stderr is a harness error, not a deny: " + repr("noise\n"),
            ),
            (
                "nonempty allow stderr",
                sbx.Result(
                    exit_code=0, stdout=FULL_ALLOW, stderr="noise\n", argv=["/private/ptyrevoke"],
                ),
                "nonempty allow stderr is a harness error, not an allow: " + repr("noise\n"),
            ),
            (
                "malformed stdout",
                sbx.Result(
                    exit_code=0, stdout=malformed, stderr="", argv=["/private/ptyrevoke"],
                ),
                "malformed stdout is a harness error, not a deny and not an allow: "
                + repr(malformed),
            ),
            (
                "profile error",
                sbx.Result(
                    exit_code=sbx.PROFILE_ERROR_EXIT,
                    stdout=OPEN_FAIL,
                    stderr="Operation not permitted\n",
                    argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/ptyrevoke"],
                ),
                "profile error: profile read or compile error: sandbox-exec exited 65 "
                "and started no program, so nothing was denied -- a harness error, "
                "not a deny and not an allow. stderr='Operation not permitted\\n'",
            ),
        )

    def test_classifier_refusal_reasons(self):
        """Each classifier refusal preserves its exact, distinct reason.

        These results are built here. Nothing is launched. Exit 65 stays a
        profile error when stderr says ``Operation not permitted``.
        ``revoke rc=0`` is an allow only on the full allow line.
        """
        self.assertEqual(
            format_open(-1, 1, -1, 0, -1, 0, -1, 0, -1, 0), OPEN_FAIL,
        )
        self.assertEqual(
            format_open(3, 0, 1, 0, 1, 0, 1, 0, -1, 1), REVOKE_FAIL,
        )
        self.assertEqual(
            format_open(3, 0, 1, 0, 1, 0, 1, 0, 0, 0), FULL_ALLOW,
        )
        self.assertEqual(
            format_open(3, 0, 1, 0, 1, 0, 0, 1, -1, 0), PTS_FAIL,
        )
        for stdout in DENY_LINES:
            self.assertEqual(
                classify(sbx.Result(
                    exit_code=0, stdout=stdout, stderr="", argv=["/private/ptyrevoke"],
                )),
                "deny",
            )
        allow = sbx.Result(
            exit_code=0, stdout=FULL_ALLOW, stderr="", argv=["/private/ptyrevoke"],
        )
        self.assertEqual(classify(allow), "allow")
        unlock_zero = format_open(3, 0, 1, 0, 0, 1, 1, 0, -1, 1)
        with self.assertRaises(HarnessError) as unlock_caught:
            classify(sbx.Result(
                exit_code=0, stdout=unlock_zero, stderr="", argv=["/private/ptyrevoke"],
            ))
        self.assertIn("unlock ok=0 after open fd=3", str(unlock_caught.exception))
        revoke_noise = sbx.Result(
            exit_code=0, stdout=REVOKE_FAIL, stderr="noise\n", argv=["/private/ptyrevoke"],
        )
        with self.assertRaises(HarnessError) as revoke_stderr:
            classify(revoke_noise)
        self.assertEqual(
            str(revoke_stderr.exception),
            "nonempty deny stderr is a harness error, not a deny: " + repr("noise\n"),
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
                reasons.append(message)
        self.assertEqual(len(set(reasons)), len(samples))
        for message in reasons:
            hits = [label for label, _result, _expected in samples if label in message]
            self.assertEqual(hits, [next(
                label for label, result, expected in samples
                if expected == message
            )])
        self.launch_guard.assert_not_called()

    def test_unsandboxed_failure_is_an_error(self):
        """A failed unsandboxed control is a harness error, not an assertion failure.

        The open-fail line, the revoke-fail line, the pts-fail line,
        ``name-bad``, a nonzero exit, nonempty stderr, and a malformed line
        each raise ``HarnessError``. They launch nothing.
        """
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptyrevoke-unsandboxed-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        binary = os.path.join(parent, BINARY_NAME)
        descriptor = os.open(binary, os.O_CREAT | os.O_WRONLY, 0o755)
        os.close(descriptor)
        binary = os.path.realpath(binary)
        cases = (
            (
                "unsandboxed open deny",
                subprocess.CompletedProcess([binary], 0, OPEN_FAIL, ""),
                "unsandboxed open deny is a harness error, not a passing control: "
                + repr(OPEN_FAIL),
            ),
            (
                "unsandboxed revoke deny",
                subprocess.CompletedProcess([binary], 0, REVOKE_FAIL, ""),
                "unsandboxed revoke deny is a harness error, not a passing control: "
                + repr(REVOKE_FAIL),
            ),
            (
                "pts ok=0 after open fd=3",
                subprocess.CompletedProcess([binary], 0, PTS_FAIL, ""),
                "pts ok=0 after open fd=3 is a harness error, "
                "not a deny and not an allow: " + repr(PTS_FAIL),
            ),
            (
                "name-bad is a harness error",
                subprocess.CompletedProcess([binary], 0, NAME_BAD, ""),
                "name-bad is a harness error, not a deny and not an allow: "
                + repr(NAME_BAD),
            ),
            (
                "wrong exit",
                subprocess.CompletedProcess([binary], 2, FULL_ALLOW, ""),
                "wrong exit 2 is a harness error, not a deny and not an allow. "
                f"stdout={FULL_ALLOW!r} stderr=''",
            ),
            (
                "nonempty allow stderr",
                subprocess.CompletedProcess([binary], 0, FULL_ALLOW, "noise\n"),
                "nonempty allow stderr is a harness error, not an allow: " + repr("noise\n"),
            ),
            (
                "malformed stdout",
                subprocess.CompletedProcess([binary], 0, "open nope\n", ""),
                "malformed stdout is a harness error, not a deny and not an allow: "
                + repr("open nope\n"),
            ),
        )
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
                    self.assertEqual(ran.call_args.args[0], [binary])
                    self.assertTrue(ran.call_args.kwargs.get("close_fds"))
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
            exit_code=0, stdout=OPEN_FAIL, stderr="", argv=["/private/ptyrevoke"],
        )
        for label, refused, expected in self.refusal_samples():
            for preceding in ([], [deny], [deny, deny]):
                with self.subTest(reason=label, position=len(preceding)):
                    class Observed(RevokeProbe):
                        pass

                    with patch(
                        __name__ + ".revoke_under",
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

        _label, refused, expected = self.refusal_samples()[-1]
        with patch(__name__ + ".revoke_under", side_effect=[refused] * 3) as opened:
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
        The clean run writes no finding.
        """
        allow = sbx.Result(
            exit_code=0,
            stdout=FULL_ALLOW,
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/ptyrevoke"],
        )
        refused = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout="",
            stderr="Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb"],
        )
        self.assertEqual(classify(allow), "allow")
        self.assertIn("revoke rc=0", allow.stdout)
        with self.assertRaises(HarnessError) as sample:
            classify(refused)
        expected = str(sample.exception)
        self.assertIn("profile error", expected)
        self.assertIn("Operation not permitted", expected)
        live_names = (
            ROOT / "lab" / "redteam" / "CRITICAL.md",
            ROOT / FINDINGS["wallet"],
            ROOT / FINDINGS["model"],
        )
        before = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }

        def run_case(results):
            class Observed(RevokeProbe):
                pass

            pending = list(results)
            order = []

            def opened(path):
                order.append(("open", path))
                return pending.pop(0)

            def written(_repo, items):
                order.append(("write", [item[0]["name"] for item in items]))

            with patch(__name__ + ".revoke_under", side_effect=opened), patch(
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
            method = observed.test_wallet_revoke_is_denied
            self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
            self.assertIn(FINDINGS["wallet"], method.__doc__ or "")
            self.assertNotIn("model", observed.recorded_allows)
        finally:
            if observed is not None:
                observed.doClassCleanups()

        observed = None
        try:
            observed, marker, order = run_case([allow, allow, refused])
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
            did_method = observed.test_did_revoke_is_denied
            self.assertTrue(getattr(did_method, "__unittest_expecting_failure__", False))
            self.assertIn(FINDINGS["did"], did_method.__doc__ or "")
        finally:
            if observed is not None:
                observed.doClassCleanups()
        after = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        self.assertEqual(before, after)
        self.launch_guard.assert_not_called()

    def test_recorded_allow_is_expected_failure(self):
        """A recorded allow is an expected failure whose docstring names the finding.

        The result is injected. The finding is written under a temp repo.
        Its first line contains CRITICAL, the commit from ``last_change``,
        ``pr_label`` of that commit, and the sha256. The helper line is
        ``result.command``. The injected profile contains the three setup
        lines and the plant line. The wallet docstring names
        ``CRITICAL-confine-073.md``. The model docstring names
        ``CRITICAL-cc-model-confine-073.md``. A unittest run of each
        injected allow is one expected failure. Dropping only the PR label
        raises ``finding omits pr_label``. Dropping only the command raises
        ``finding omits command``. The finding names ``revoke``. The clean
        run writes no finding.
        """
        provenance = self.enter_patch(patch(__name__ + ".last_change", return_value="a" * 40))
        self.enter_patch(patch(__name__ + ".pr_label", return_value="PR fixture"))
        self.enter_patch(patch(__name__ + ".sha256_file", return_value="b" * 64))
        command_argv = [sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/ptyrevoke"]
        full = sbx.Result(
            exit_code=0,
            stdout=FULL_ALLOW,
            stderr="",
            argv=list(command_argv),
        )
        self.assertTrue(full.command)
        self.assertIsNone(sbx.profile_error(full))
        self.assertEqual(classify(full), "allow")
        wallet = PROFILES[0]
        did = PROFILES[1]
        model = PROFILES[2]
        self.assertEqual(wallet["name"], "wallet")
        self.assertEqual(did["name"], "did")
        self.assertEqual(model["name"], "model")
        paragraph = finding_paragraph(wallet, full)
        self.assertIn("revoke", paragraph)
        self.assertIn("revoke rc=0", paragraph)
        self.assertIn(pr_label(last_change(wallet["path"])), paragraph)
        self.assertIn(full.command, paragraph)
        require_finding_pins(paragraph, wallet, full)
        label = pr_label(last_change(wallet["path"]))
        self.assertIn("CRITICAL", paragraph.splitlines()[0])
        self.assertIn(last_change(wallet["path"]), paragraph.splitlines()[0])
        self.assertIn(sha256_file(wallet["path"]), paragraph.splitlines()[0])
        self.assertIn(label, paragraph.splitlines()[0])
        self.assertIn(f"helper: {full.command}\n", paragraph)
        self.assertIn(f"profile: {wallet['rel']}\n", paragraph)
        self.assertIn(f"observed: {full.stdout.strip()}\n", paragraph)
        self.assertEqual(
            paragraph.splitlines()[1:],
            [
                f"profile: {wallet['rel']}",
                f"helper: {full.command}",
                f"observed: {full.stdout.strip()}",
            ],
        )
        self.assertNotIn(label, full.command)
        self.assertNotIn(full.command, label)
        self.assertEqual(paragraph.count(label), 1)
        self.assertEqual(paragraph.count(full.command), 1)
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
        model_paragraph = finding_paragraph(model, full)
        self.assertIn("CRITICAL-cc-model-confine-073", model_paragraph)
        self.assertIn("revoke", model_paragraph)
        require_finding_pins(model_paragraph, model, full)
        live_names = (
            ROOT / "lab" / "redteam" / "CRITICAL.md",
            ROOT / FINDINGS["wallet"],
            ROOT / FINDINGS["model"],
        )
        before = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        with tempfile.TemporaryDirectory(prefix="ccrt-ptyrevoke-finding-") as tmp:
            repo = Path(tmp)
            self.assertEqual(write_findings(repo, []), [])
            self.assertFalse((repo / "lab" / "redteam" / "CRITICAL.md").exists())
            written = write_findings(repo, [(wallet, full), (did, full)])
            self.assertEqual(written, [FINDINGS["wallet"]])
            body = (repo / FINDINGS["wallet"]).read_text(encoding="utf-8")
            self.assertFalse((repo / FINDINGS["model"]).exists())
            did_paragraph = finding_paragraph(did, full)
            self.assertEqual(body, paragraph + did_paragraph)
            self.assertIn("revoke", body)
            listed = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertIn(paragraph, listed)
            self.assertIn(did_paragraph, listed)
            model_written = write_findings(repo, [(model, full)])
            self.assertEqual(model_written, [FINDINGS["model"]])
            model_body = (repo / FINDINGS["model"]).read_text(encoding="utf-8")
            stored_model = finding_paragraph(model, full)
            self.assertEqual(model_body, stored_model)
            self.assertIn("CRITICAL", stored_model.splitlines()[0])
            listed_again = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertIn(stored_model, listed_again)
            self.assertEqual(listed_again.count(stored_model), 1)
            again = write_findings(repo, [(model, full)])
            relisted = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertEqual(relisted, listed_again)
            self.assertEqual(again, [FINDINGS["model"]])
        after = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        self.assertEqual(before, after)

        injected = "(version 1)\n(deny default)\n" + FILE_GRANT + IOCTL_LINE + TTYS_LINE + PLANT_LINE
        for line in SETUP_LINES:
            self.assertEqual(injected.count(line), 1)
        self.assertEqual(injected.count(PLANT_LINE), 1)

        class Planted(RevokeProbe):
            recorded_allows = {
                "wallet": FINDINGS["wallet"],
                "model": FINDINGS["model"],
            }

        mark_expected(Planted, "test_wallet_revoke_is_denied", FINDINGS["wallet"])
        mark_expected(Planted, "test_model_revoke_is_denied", FINDINGS["model"])
        try:
            planted = Planted("test_falsifier_allow_revoke_is_caught")
            self.assertIn("CRITICAL-confine-073.md", Planted.test_wallet_revoke_is_denied.__doc__)
            self.assertIn(
                "CRITICAL-cc-model-confine-073.md",
                Planted.test_model_revoke_is_denied.__doc__,
            )
            kept = "(version 1)\n(deny default)\n" + FILE_GRANT + IOCTL_LINE + TTYS_LINE
            self.assertEqual(planted._source_for_plant("wallet", injected), kept)
            self.assertEqual(planted._source_for_plant("model", injected), kept)
        finally:
            Planted.doClassCleanups()

        class Unmarked(unittest.TestCase):
            def test_wallet_revoke_is_denied(self):
                """plain"""
                raise NotDenied(full)

        unmarked = unittest.TestResult()
        Unmarked("test_wallet_revoke_is_denied").run(unmarked)
        self.assertEqual(len(unmarked.failures), 1)
        self.assertEqual(unmarked.expectedFailures, [])
        self.assertEqual(unmarked.errors, [])

        def run_marked(name):
            method_name = f"test_{name}_revoke_is_denied"

            class Recorded(unittest.TestCase):
                pass

            def deny_body(self):
                """plain"""
                raise NotDenied(full)

            deny_body.__name__ = method_name
            setattr(Recorded, method_name, deny_body)
            mark_expected(Recorded, method_name, FINDINGS[name])
            method = getattr(Recorded, method_name)
            self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
            self.assertIn(FINDINGS[name], method.__doc__)
            if name == "model":
                self.assertIn("CRITICAL-cc-model-confine-073.md", method.__doc__)
            else:
                self.assertIn("CRITICAL-confine-073.md", method.__doc__)
            self.assertIn("revoke", method.__doc__)
            recorded = unittest.TestResult()
            Recorded(method_name).run(recorded)
            self.assertEqual(len(recorded.expectedFailures), 1)
            self.assertEqual(recorded.failures, [])
            self.assertEqual(recorded.errors, [])
            self.assertEqual(recorded.unexpectedSuccesses, [])
            self.assertEqual(recorded.skipped, [])
            self.assertTrue(recorded.wasSuccessful())
            self.assertEqual(
                recorded.expectedFailures[0][0]._testMethodName,
                method_name,
            )
            Recorded.doClassCleanups()

        run_marked("wallet")
        run_marked("model")
        self.assertEqual(
            {call.args[0] for call in provenance.call_args_list},
            {wallet["path"], did["path"], model["path"]},
        )
        self.launch_guard.assert_not_called()

    def test_wallet_controls_reject_allow_with_or_without_finding(self):
        """Each wallet control fails on an allow, with or without a recorded finding.

        The still-deny copies are not excused by a live allow. The failure is
        ordinary, not expected.
        """
        for recorded in (False, True):
            for control in STILL_DENY_COPIES:
                with self.subTest(recorded=recorded, control=control), tempfile.TemporaryDirectory(
                    prefix="ccrt-ptyrevoke-control-"
                ) as tmp:
                    profiles = []
                    for original in PROFILES:
                        profile = dict(original)
                        profile["path"] = Path(tmp) / f"{profile['name']}.sb"
                        text = "(version 1)\n(deny default)\n(deny network*)\n"
                        if recorded and profile["name"] == "wallet":
                            text = (
                                text + FILE_GRANT + IOCTL_LINE + TTYS_LINE + PLANT_LINE
                            )
                        profile["path"].write_text(text, encoding="utf-8")
                        profiles.append(profile)

                    class Control(RevokeProbe):
                        skip_reason = None
                        recorded_allows = {}

                    if recorded:
                        finding = FINDINGS["wallet"]
                        Control.recorded_allows["wallet"] = finding
                        mark_expected(
                            Control, "test_wallet_revoke_is_denied", finding,
                        )
                        method = Control.test_wallet_revoke_is_denied
                        self.assertTrue(
                            getattr(method, "__unittest_expecting_failure__", False)
                        )
                        self.assertIn(finding, method.__doc__ or "")

                    opened = []

                    def injected_open(profile):
                        path = Path(profile)
                        opened.append(path.name)
                        text = path.read_text(encoding="utf-8")
                        if path.stem == control:
                            stdout = FULL_ALLOW
                        else:
                            stdout = stdout_for_profile_text(text)
                        return sbx.Result(
                            exit_code=0,
                            stdout=stdout,
                            stderr="",
                            argv=[sbx.SANDBOX_EXEC, "-f", os.fspath(path), "/private/ptyrevoke"],
                        )

                    result = unittest.TestResult()
                    try:
                        with patch(__name__ + ".PROFILES", tuple(profiles)), patch(
                            __name__ + ".revoke_under", side_effect=injected_open
                        ):
                            Control(
                                "test_falsifier_allow_revoke_is_caught"
                            ).run(result)
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
                    self.assertIn("revoke rc=0", caught)
                    self.assertFalse(result.wasSuccessful())
                    self.assertEqual(opened, launched_copy_names())
        self.launch_guard.assert_not_called()

    def test_recorded_allow_keeps_complete_probe_suite_green(self):
        """Run every real probe method against injected tools and profile text.

        No added lines, and the three setup lines plus the plant on each
        profile, keep the suite green. Only the deny test of a profile whose
        text contains all three setup lines and the plant line is an expected
        failure. One wallet temp copy holds the plant and none of the setup
        lines, prints the open-fail line, and is not the injected module
        text. The plant still runs, nothing skips, and the result is
        successful. The finding names ``revoke``.
        """
        method_names = unittest.defaultTestLoader.getTestCaseNames(RevokeProbe)
        scenarios = ((), ("wallet",), ("did",), ("model",), ("wallet", "did", "model"))
        for allowed in scenarios:
            with self.subTest(allowed=allowed), tempfile.TemporaryDirectory(
                prefix="ccrt-ptyrevoke-suite-"
            ) as tmp:
                repo = Path(tmp).resolve()
                profiles = []
                for original in PROFILES:
                    profile = dict(original)
                    profile["path"] = repo / profile["rel"]
                    profile["path"].parent.mkdir(parents=True, exist_ok=True)
                    text = "(version 1)\n(deny default)\n(deny network*)\n"
                    if profile["name"] in allowed:
                        text = text + FILE_GRANT + IOCTL_LINE + TTYS_LINE + PLANT_LINE
                        for line in SETUP_LINES:
                            self.assertEqual(text.count(line), 1)
                        self.assertEqual(text.count(PLANT_LINE), 1)
                    else:
                        for line in SETUP_LINES:
                            self.assertEqual(text.count(line), 0)
                        self.assertEqual(text.count(PLANT_LINE), 0)
                    profile["path"].write_text(text, encoding="utf-8")
                    profiles.append(profile)

                def injected_compile(parent, root, source_text):
                    if not source_text:
                        raise HarnessError(
                            f"{CC} failed with exit 1: empty source "
                            "-- a harness error, not a skip and not a deny"
                        )
                    source = Path(parent, SOURCE_NAME)
                    with open(source, "w", encoding="utf-8", newline="\n") as handle:
                        handle.write(source_text)
                    binary = Path(root, BINARY_NAME)
                    binary.write_text(
                        "injected executable; never launched\n", encoding="utf-8",
                    )
                    return str(binary)

                def injected_control(binary):
                    return sbx.Result(
                        exit_code=0,
                        stdout=FULL_ALLOW,
                        stderr="",
                        argv=[binary],
                    )

                launched = []

                def injected_sandbox(**kwargs):
                    text = Path(kwargs["profile"]).read_text(encoding="utf-8")
                    stdout = stdout_for_profile_text(text)
                    launched.append((os.fspath(kwargs["profile"]), text, stdout))
                    self.assertEqual(kwargs["pinned_exe"], kwargs["launch_exe"])
                    self.assertEqual(kwargs["timeout"], 5)
                    self.assertEqual(tuple(kwargs["args"]), ())
                    return sbx.Result(
                        exit_code=0,
                        stdout=stdout,
                        stderr="",
                        argv=[
                            sbx.SANDBOX_EXEC, "-D",
                            f"PROVIDER_EXECUTABLE={kwargs['pinned_exe']}",
                            "-D", f"STORAGE_ROOT={kwargs['storage_root']}",
                            "-D", f"STORAGE_PARENT={kwargs['storage_parent']}",
                            "-f", os.fspath(kwargs["profile"]),
                            kwargs["launch_exe"], *kwargs["args"],
                        ],
                    )

                with patch(__name__ + ".ROOT", repo), patch(
                    __name__ + ".PROFILES", tuple(profiles)
                ), patch.dict(
                    START_SHA, {}, clear=True
                ), patch.object(sbx, "REPO_ROOT", repo), patch.object(
                    sbx, "WALLET_CONFINE_SB", profiles[0]["path"]
                ), patch.object(os.path, "isfile", return_value=True), patch(
                    __name__ + ".compile_revoke", side_effect=injected_compile
                ), patch(__name__ + ".run_unsandboxed", side_effect=injected_control), patch.object(
                    sbx, "run", side_effect=injected_sandbox
                ), patch(__name__ + ".last_change", return_value="a" * 40), patch(
                    __name__ + ".pr_label", return_value="PR fixture"
                ), patch.multiple(
                    RevokeProbe, binary=None, root=None, parent=None,
                    skip_reason=None, recorded_allows={},
                ):
                    result = unittest.TestResult()
                    unittest.defaultTestLoader.loadTestsFromTestCase(RevokeProbe).run(result)
                    self.assertEqual(result.testsRun, len(method_names))
                    self.assertEqual(result.errors, [])
                    self.assertEqual(result.failures, [])
                    self.assertEqual(result.unexpectedSuccesses, [])
                    self.assertEqual(result.skipped, [])
                    self.assertIsNone(skip_reason())
                    self.assertEqual(len(result.expectedFailures), len(allowed))
                    self.assertEqual(
                        {case._testMethodName for case, _error in result.expectedFailures},
                        {f"test_{name}_revoke_is_denied" for name in allowed},
                    )
                    paths = [item[0] for item in launched]
                    for suffix in ("-allow.sb", "-setup.sb", "-plant.sb"):
                        self.assertEqual(
                            sorted(
                                os.path.basename(path)
                                for path in paths
                                if os.path.basename(path).endswith(suffix)
                                and os.path.basename(path).startswith(("wallet", "did", "model"))
                            ),
                            [f"did{suffix}", f"model{suffix}", f"wallet{suffix}"],
                        )
                    for name in STILL_DENY_COPIES:
                        self.assertTrue(
                            any(path.endswith(os.sep + name + ".sb") for path in paths),
                            name,
                        )
                    for stem, _line in FULL_ALLOW_RULES:
                        self.assertTrue(
                            any(path.endswith(os.sep + stem + ".sb") for path in paths),
                            stem,
                        )
                    plant_records = [
                        item for item in launched
                        if os.path.basename(item[0]) == "wallet-plant.sb"
                    ]
                    self.assertEqual(len(plant_records), 1)
                    _path, plant_text, plant_stdout = plant_records[0]
                    self.assertIn(PLANT_LINE, plant_text)
                    for line in SETUP_LINES:
                        self.assertNotIn(line, plant_text)
                    self.assertEqual(plant_stdout, OPEN_FAIL)
                    self.assertNotEqual(plant_text, profiles[0]["path"].read_text(encoding="utf-8"))
                    self.assertTrue(result.wasSuccessful())
                    self.assertEqual(
                        RevokeProbe.recorded_allows,
                        {name: FINDINGS[name] for name in allowed},
                    )
                    for name in allowed:
                        body = (repo / FINDINGS[name]).read_text(encoding="utf-8")
                        profile = next(item for item in profiles if item["name"] == name)
                        self.assertIn("revoke", body)
                        self.assertIn("revoke rc=0", body)
                        self.assertIn(f"profile: {profile['rel']}\n", body)
                        self.assertIn(sha256_file(profile["path"]), body)
                        self.assertIn(pr_label(last_change(profile["path"])), body)
                        helper_line = next(
                            line for line in body.splitlines() if line.startswith("helper: ")
                        )
                        self.assertIn(sbx.SANDBOX_EXEC, helper_line)
                        self.assertIn(RevokeProbe.binary, helper_line)
                        self.assertIn(
                            body,
                            (repo / "lab/redteam/CRITICAL.md").read_text(encoding="utf-8"),
                        )
                    if not allowed:
                        self.assertFalse((repo / "lab/redteam/CRITICAL.md").exists())
                        for rel in set(FINDINGS.values()):
                            self.assertFalse((repo / rel).exists())
                self.launch_guard.assert_not_called()

    def test_harness_error_stays_error(self):
        """An injected harness error stays an error. It is not a deny, an allow, or a skip."""
        allow = sbx.Result(
            exit_code=0, stdout=FULL_ALLOW, stderr="", argv=["/private/ptyrevoke"],
        )
        deny = sbx.Result(
            exit_code=0, stdout=OPEN_FAIL, stderr="", argv=["/private/ptyrevoke"],
        )
        for profile in PROFILES:
            for label, refused, expected in self.refusal_samples():
                with self.subTest(profile=profile["name"], reason=label):
                    class Recorded(RevokeProbe):
                        skip_reason = None

                    def observation(path, profile=profile, allow=allow, deny=deny):
                        return allow if path == profile["path"] else deny

                    with patch(__name__ + ".revoke_under", side_effect=observation), patch(
                        __name__ + ".write_findings"
                    ) as writer:
                        observe(Recorded)
                    writer.assert_called_once_with(ROOT, [(profile, allow)])
                    method_name = f"test_{profile['name']}_revoke_is_denied"
                    method = getattr(Recorded, method_name)
                    self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
                    self.assertIn(FINDINGS[profile["name"]], method.__doc__)
                    result = unittest.TestResult()
                    try:
                        with patch(
                            __name__ + ".revoke_under", side_effect=[refused, deny]
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
            exit_code=2,
            stdout=OPEN_FAIL,
            stderr="",
            argv=["/private/ptyrevoke"],
        )
        other_fd = sbx.Result(
            exit_code=0,
            stdout=format_open(4, 0, 1, 0, 1, 0, 1, 0, 0, 0),
            stderr="",
            argv=["/private/ptyrevoke"],
        )
        profile_error = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout=FULL_ALLOW,
            stderr="Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC],
        )
        injected = (wrong_exit, other_fd, profile_error)
        for result in injected:
            with self.assertRaises(HarnessError):
                classify(result)

        class Body(unittest.TestCase):
            def test_wallet_revoke_is_denied(self):
                classify(wrong_exit)

        body = unittest.TestResult()
        Body("test_wallet_revoke_is_denied").run(body)
        self.assertEqual(len(body.errors), 1)
        self.assertEqual(body.failures, [])
        self.assertEqual(body.expectedFailures, [])
        self.assertEqual(body.skipped, [])

        class Setup(unittest.TestCase):
            def setUp(self):
                raise HarnessError("wrong exit 2 is a harness error, not a deny")

            @unittest.expectedFailure
            def test_wallet_revoke_is_denied(self):
                raise NotDenied(wrong_exit)

        setup = unittest.TestResult()
        Setup("test_wallet_revoke_is_denied").run(setup)
        self.assertEqual(len(setup.errors), 1)
        self.assertEqual(setup.expectedFailures, [])
        self.assertEqual(setup.skipped, [])
        self.assertIn("wrong exit", setup.errors[0][1])
        self.launch_guard.assert_not_called()

    def test_unresolved_storage_path_is_an_error(self):
        """A ``/var/folders`` storage path without ``/private`` errors before launch."""
        bad_parent = "/var/folders/cc/ptyrevoke-parent"
        bad_root = "/var/folders/cc/ptyrevoke-root"
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
                compile_revoke(
                    bad_parent,
                    "/private/ptyrevoke-root",
                    "int main(void) { return 0; }\n",
                )
            compile_message = str(compile_caught.exception)
            self.assertIn(bad_parent, compile_message)
            self.assertIn("/var/folders", compile_message)
            self.assertNotIn("/private" + bad_parent, compile_message)

            with self.assertRaises(HarnessError) as launch_caught:
                run_sandboxed(
                    "/private/ptyrevoke",
                    bad_root,
                    "/private/ptyrevoke-parent",
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
