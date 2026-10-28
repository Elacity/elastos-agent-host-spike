"""Probe the pty slave on the wallet, did, and model profiles.

Grade row 12 rests on those seatbelt profiles. The helper opens one pty
master, asks for its slave name, and opens that slave. Confined launches go
through ``sbx.run`` only. The helper prints one line and returns 0.

A deny is exit 0, stderr empty, and stdout either the open-fail line or the
ptsname line. An allow is exit 0, stderr empty, ``pts ok=1 errno=0``, and
the open succeeded. The full allow also has slave fd 4 and ``ioctl ok=1``.
A partial allow returns the slave name and still denies the slave open.
The named call is ``pts`` for a partial allow, and ``pts`` and ``slave``
for the full allow.

The file-grant line and the ioctl line are setup. They are not the plant.
The plant, beside those two lines, is the ``/dev/ttys`` read-write grant.
The three profiles are the live files. ``setUpModule`` records each sha256.
``tearDownModule`` calls ``changed``. An owner edit between those two points
raises ``the probe changed <rel>``. This file stores no commit, pull
request, or digest.

An allow on a real profile is CRITICAL. Wallet or did:
``findings/CRITICAL-confine-072.md``. Model:
``findings/CRITICAL-cc-model-confine-072.md``. The finding's first line
contains CRITICAL and names the commit from ``last_change``, ``pr_label``
of that commit, and the sha256 of the bytes this run read. The helper line
is ``result.command``. The same paragraph is appended to ``CRITICAL.md``.
With no allow, this module writes neither file.

A recorded allow keeps the gate green. The deny test is an expected
failure and its docstring names that finding file. A later harness error
still fails. A recorded allow is not a skip. This module skips only when
``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` is missing.

``SlaveProbe`` compiles once and launches. ``SlaveRules`` does not compile
and does not launch.
"""

import ast
import contextlib
import inspect
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
BINARY_NAME = "ptyslave"

FILE_GRANT = '(allow file-read* file-write* (literal "/dev/ptmx"))\n'
IOCTL_LINE = '(allow file-ioctl (literal "/dev/ptmx"))\n'
PLANT_PHRASE = '(allow file-read* file-write* (regex #"^/dev/ttys[0-9]+$"))'
PLANT = PLANT_PHRASE + "\n"
DENY_DEFAULT = "(deny default)\n"
DELETE_DEFAULT = "delete-default"

HELPER_C = """\
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
int main(void) {
    int fd;
    int grant_rc;
    int unlock_rc;
    int gerr;
    int uerr;
    int perr;
    int serr;
    int ierr;
    int pok;
    int sfd;
    int iok;
    char *name;
    struct termios tio;
    errno = 0;
    fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (fd < 0) {
        printf("open fd=-1 errno=%d grant ok=-1 errno=0 unlock ok=-1 errno=0 pts ok=-1 errno=0 slave fd=-1 errno=0 ioctl ok=-1 errno=0\\n", errno);
        return 0;
    }
    errno = 0;
    grant_rc = grantpt(fd);
    gerr = grant_rc == 0 ? 0 : errno;
    errno = 0;
    unlock_rc = unlockpt(fd);
    uerr = unlock_rc == 0 ? 0 : errno;
    errno = 0;
    name = ptsname(fd);
    if (name == NULL) {
        pok = 0;
        perr = errno;
        sfd = -1;
        serr = 0;
        iok = -1;
        ierr = 0;
    } else {
        pok = 1;
        perr = 0;
        errno = 0;
        sfd = open(name, O_RDWR | O_NOCTTY);
        if (sfd < 0) {
            serr = errno;
            iok = -1;
            ierr = 0;
        } else {
            serr = 0;
            errno = 0;
            if (ioctl(sfd, TIOCGETA, &tio) == 0) {
                iok = 1;
                ierr = 0;
            } else {
                iok = 0;
                ierr = errno;
            }
            close(sfd);
        }
    }
    printf("open fd=%d errno=0 grant ok=%d errno=%d unlock ok=%d errno=%d pts ok=%d errno=%d slave fd=%d errno=%d ioctl ok=%d errno=%d\\n",
        fd,
        grant_rc == 0 ? 1 : 0, gerr,
        unlock_rc == 0 ? 1 : 0, uerr,
        pok, perr,
        sfd < 0 ? -1 : sfd, serr,
        iok, ierr);
    close(fd);
    return 0;
}
"""

FINDINGS = {
    "wallet": "lab/redteam/findings/CRITICAL-confine-072.md",
    "did": "lab/redteam/findings/CRITICAL-confine-072.md",
    "model": "lab/redteam/findings/CRITICAL-cc-model-confine-072.md",
}
IDS = {
    "wallet": "CRITICAL-confine-072",
    "did": "CRITICAL-confine-072",
    "model": "CRITICAL-cc-model-confine-072",
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
STILL_DENY_EDITS = (
    ("wallet-deleted", DELETE_DEFAULT),
    ("wallet-write-star", '(allow file-write* (regex #"^/dev/ttys[0-9]+$"))\n'),
    (
        "wallet-data-both",
        '(allow file-read-data file-write-data (regex #"^/dev/ttys[0-9]+$"))\n',
    ),
    (
        "wallet-data-write",
        '(allow file-read-data file-write* (regex #"^/dev/ttys[0-9]+$"))\n',
    ),
    ("wallet-ioctl-regex", '(allow file-ioctl (regex #"^/dev/ttys[0-9]+$"))\n'),
    (
        "wallet-subpath-ttys",
        '(allow file-read* file-write* (subpath "/dev/ttys"))\n',
    ),
    ("wallet-pseudo", "(allow pseudo-tty)\n"),
    ("wallet-ioctl-bare", "(allow file-ioctl)\n"),
    ("wallet-network", "(allow network*)\n"),
    ("wallet-lookup", "(allow mach-lookup)\n"),
    ("wallet-sched", "(allow system-sched)\n"),
    ("wallet-iokit", "(allow iokit-open)\n"),
    ("wallet-signal", "(allow signal)\n"),
    ("wallet-fork", "(allow process-fork)\n"),
    ("wallet-debug", "(allow system-debug)\n"),
    ("wallet-sysctl", "(allow sysctl-write)\n"),
    ("wallet-extension", "(allow file-issue-extension)\n"),
    ("wallet-shm", "(allow ipc-posix-shm)\n"),
    ("wallet-fsctl", "(allow system-fsctl)\n"),
    ("wallet-setugid", "(allow file-write-setugid)\n"),
)
FULL_EDITS = (
    ("wallet-ttys-prefix", '(allow file-read* file-write* (regex #"^/dev/ttys"))\n'),
    (
        "wallet-write-data",
        '(allow file-read* file-write-data (regex #"^/dev/ttys[0-9]+$"))\n',
    ),
    ("wallet-subpath-dev", '(allow file-read* file-write* (subpath "/dev"))\n'),
)
PARTIAL_EDITS = (
    ("wallet-read-star", '(allow file-read* (regex #"^/dev/ttys[0-9]+$"))\n'),
    ("wallet-metadata", '(allow file-read-metadata (subpath "/dev"))\n'),
)
FULL_EDIT_LINES = tuple(line for _name, line in FULL_EDITS)
PARTIAL_EDIT_LINES = tuple(line for _name, line in PARTIAL_EDITS)
_LINE = re.compile(
    r"open fd=(?P<fd>-?[0-9]+) errno=(?P<ferr>-?[0-9]+) "
    r"grant ok=(?P<gok>-?[0-9]+) errno=(?P<gerr>-?[0-9]+) "
    r"unlock ok=(?P<uok>-?[0-9]+) errno=(?P<uerr>-?[0-9]+) "
    r"pts ok=(?P<pok>-?[0-9]+) errno=(?P<perr>-?[0-9]+) "
    r"slave fd=(?P<sfd>-?[0-9]+) errno=(?P<serr>-?[0-9]+) "
    r"ioctl ok=(?P<iok>-?[0-9]+) errno=(?P<ierr>-?[0-9]+)\n"
)
_FIELD_LABELS = (
    ("fd", "open fd"),
    ("ferr", "open errno"),
    ("gok", "grant ok"),
    ("gerr", "grant errno"),
    ("uok", "unlock ok"),
    ("uerr", "unlock errno"),
    ("pok", "pts ok"),
    ("perr", "pts errno"),
    ("sfd", "slave fd"),
    ("serr", "slave errno"),
    ("iok", "ioctl ok"),
    ("ierr", "ioctl errno"),
)

START_SHA = {}


def slave_line(fd, ferr, gok, gerr, uok, uerr, pok, perr, sfd, serr, iok, ierr):
    """One helper line. Callers pass canonical decimal fields."""
    return (
        "open fd=%s errno=%s grant ok=%s errno=%s unlock ok=%s errno=%s "
        "pts ok=%s errno=%s slave fd=%s errno=%s ioctl ok=%s errno=%s\n"
        % (fd, ferr, gok, gerr, uok, uerr, pok, perr, sfd, serr, iok, ierr)
    )


OPEN_FAIL = slave_line(-1, 1, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0)
PTS_DENY = slave_line(3, 0, 1, 0, 1, 0, 0, 1, -1, 0, -1, 0)
FULL_ALLOW = slave_line(3, 0, 1, 0, 1, 0, 1, 0, 4, 0, 1, 0)
PARTIAL_ALLOW = slave_line(3, 0, 1, 0, 1, 0, 1, 0, -1, 1, -1, 0)
DENY_LINES = (OPEN_FAIL, PTS_DENY)
ALLOW_LINES = (FULL_ALLOW, PARTIAL_ALLOW)
# Synthetic scenarios start here. Live profile bytes are not a base.
CLEAN_PROFILE = "(version 1)\n(deny default)\n(deny network*)\n"


class NotDenied(AssertionError):
    """The profile let the helper reach the slave name or the slave fd."""

    def __init__(self, result):
        self.result = result
        super().__init__(
            "ALLOW: pty slave opened under the profile.\n"
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
    except Exception as caught:
        message = str(caught)
        if not message.startswith("execvp:"):
            raise
        raise HarnessError(message) from caught


def harness(reason, stdout):
    """One classifier reason that names ``reason`` and the stdout it refused."""
    return (
        f"{reason} is a harness error, not a deny and not an allow: "
        + repr(stdout)
    )


def wrong_exit_reason(result):
    return (
        f"wrong exit {result.exit_code} is a harness error, not a deny and not an allow. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def profile_reason(result, problem):
    return (
        f"profile error: {problem} -- a harness error, not a deny and not an allow. "
        f"stderr={result.stderr!r}"
    )


def deny_stderr_reason(stderr):
    return "nonempty deny stderr is a harness error, not a deny: " + repr(stderr)


def allow_stderr_reason(stderr):
    return "nonempty allow stderr is a harness error, not an allow: " + repr(stderr)


def named_calls(stdout):
    """``pts`` when the name was returned, and ``slave`` when the slave fd is 4."""
    if stdout == FULL_ALLOW:
        return ("pts", "slave")
    if stdout == PARTIAL_ALLOW:
        return ("pts",)
    return ()


def named_phrase(names):
    """The finding's name for an allow. A deny has no name."""
    if names == ("pts", "slave"):
        return "pts and slave"
    if names == ("pts",):
        return "pts"
    raise HarnessError("finding names no call: " + repr(names))


def _field_values(stdout):
    """Parsed decimals, or ``(None, reason)`` when the line is not canonical."""
    match = _LINE.fullmatch(stdout)
    if match is None:
        return None, harness("malformed stdout", stdout)
    values = {}
    for key, label in _FIELD_LABELS:
        text = match.group(key)
        if str(int(text)) != text:
            return None, harness("malformed " + label, stdout)
        values[key] = int(text)
    return values, None


def line_problem(stdout):
    """None when ``stdout`` is a deny or an allow. Otherwise the harness reason."""
    if stdout in DENY_LINES or stdout in ALLOW_LINES:
        return None
    values, reason = _field_values(stdout)
    if reason is not None:
        return reason
    fd = values["fd"]
    ferr = values["ferr"]
    if fd != -1 and fd != 3:
        return harness("open fd other than -1 or 3", stdout)
    if fd == -1:
        if ferr != 1:
            return harness("open errno other than 1 on fd=-1", stdout)
        return harness("open fd=-1 line is not the deny", stdout)
    if ferr != 0:
        return harness("open errno other than 0 when fd is 3", stdout)
    gok = values["gok"]
    gerr = values["gerr"]
    if gok == -1:
        return harness("open fd=3 with grant ok=-1", stdout)
    if gok == 0:
        return harness("open fd=3 with grant ok=0", stdout)
    if gok != 1 or gerr != 0:
        return harness("grant other than ok=1 errno=0 when fd is 3", stdout)
    uok = values["uok"]
    uerr = values["uerr"]
    if uok == 0:
        return harness("unlock ok=0", stdout)
    if uok == -1:
        return harness("unlock ok=-1 when fd is 3", stdout)
    if uok != 1 or uerr != 0:
        return harness("unlock other than ok=1 errno=0 when fd is 3", stdout)
    pok = values["pok"]
    perr = values["perr"]
    if pok == -1:
        return harness("open fd=3 with pts ok=-1", stdout)
    if pok == 0 and perr != 1:
        return harness("pts ok=0 with errno other than 1", stdout)
    if pok == 1 and perr != 0:
        return harness("pts ok=1 with a nonzero errno", stdout)
    if pok != 0 and pok != 1:
        return harness("pts ok other than 0 or 1", stdout)
    sfd = values["sfd"]
    serr = values["serr"]
    if sfd != -1 and sfd != 4:
        return harness("slave fd other than -1 or 4", stdout)
    iok = values["iok"]
    ierr = values["ierr"]
    if sfd == 4 and iok == 0:
        return harness("slave fd=4 with ioctl ok=0", stdout)
    if iok == 0:
        return harness("ioctl ok=0", stdout)
    if pok == 0:
        if sfd == -1 and serr != 0:
            return harness(
                "slave fd=-1 with errno other than 0 when pts ok is 0", stdout
            )
        if sfd == 4 and iok == -1:
            return harness("ioctl ok=-1 when slave fd is 4", stdout)
        if sfd == 4:
            return harness("slave fd=4 with ioctl other than ok=1 errno=0", stdout)
        return harness("pts ok=0 line is not the deny", stdout)
    if sfd == -1 and serr == 0:
        return harness("slave fd=-1 and errno=0 with pts ok=1", stdout)
    if sfd == -1 and serr != 1:
        return harness(
            "slave fd=-1 with errno other than 1 when pts ok is 1", stdout
        )
    if sfd == 4 and iok == -1:
        return harness("ioctl ok=-1 when slave fd is 4", stdout)
    if sfd == 4 and (iok != 1 or ierr != 0 or serr != 0):
        return harness("slave fd=4 with ioctl other than ok=1 errno=0", stdout)
    if sfd == -1 and iok == 1:
        return harness("ioctl ok=1 when slave fd is -1", stdout)
    return harness("malformed stdout", stdout)


def classify(result):
    """``deny`` or ``allow``. Otherwise a harness error.

    Asks ``sbx.profile_error`` before it reads a deny or an allow. Exit 65
    is a profile error even when stderr says ``Operation not permitted``.
    A partial allow is an allow and names ``pts``. The full allow names
    ``pts`` and ``slave``. A grant or unlock failure on an open master is
    a harness error.
    """
    problem = sbx.profile_error(result)
    if problem is not None:
        raise HarnessError(profile_reason(result, problem))
    if result.exit_code != 0:
        raise HarnessError(wrong_exit_reason(result))
    if result.stderr != "":
        if result.stdout in DENY_LINES:
            raise HarnessError(deny_stderr_reason(result.stderr))
        if result.stdout in ALLOW_LINES:
            raise HarnessError(allow_stderr_reason(result.stderr))
        raise HarnessError(
            "nonempty stderr is a harness error, not a deny and not an allow: "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    if result.stdout in DENY_LINES:
        return "deny"
    if result.stdout in ALLOW_LINES:
        return "allow"
    reason = line_problem(result.stdout)
    if reason is None:
        raise HarnessError(harness("malformed stdout", result.stdout))
    raise HarnessError(reason)


def compile_slave(parent, root, source_text):
    """Compile ``source_text`` with ``/usr/bin/cc`` into ``<root>/ptyslave``.

    The source file sits in ``parent``. Inherited descriptors are closed.
    This does not start ``sandbox-exec``. A nonzero exit, stderr on exit 0,
    or a missing executable is a harness error, not a skip.
    """
    require_storage_path(parent)
    require_storage_path(root)
    source = os.path.join(parent, "ptyslave.c")
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


def slave_under(profile):
    """Run the compiled helper under ``profile``. Pass no argv."""
    binary = SlaveProbe.binary
    root = SlaveProbe.root
    parent = SlaveProbe.parent
    if not binary or not root or not parent:
        raise HarnessError("the slave helper is not compiled")
    return run_sandboxed(binary, root, parent, profile)


def require_unsandboxed_allow(result):
    """The unsandboxed control must be the full allow.

    The open-fail line, the ptsname line, a partial allow, a bad exit,
    stderr, or a malformed line is a harness error.
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
    if result.exit_code == 0 and result.stderr == "" and result.stdout == PTS_DENY:
        raise HarnessError(
            "unsandboxed pts deny is a harness error, not a passing control: "
            + repr(result.stdout)
        )
    if result.exit_code == 0 and result.stderr == "" and result.stdout == PARTIAL_ALLOW:
        raise HarnessError(
            "unsandboxed partial allow is a harness error, not a passing control: "
            + repr(result.stdout)
        )
    outcome = classify(result)
    if outcome != "allow" or result.stdout != FULL_ALLOW:
        raise HarnessError(
            "unsandboxed deny is a harness error, not a passing control: "
            + repr(result.stdout)
        )
    return result


def run_unsandboxed(binary):
    """The helper with no profile and no argv. Inherited descriptors are closed.

    This does not start ``sandbox-exec``.
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
    """The one helper. ``profile`` must refuse the slave.

    An allow raises ``NotDenied``. A harness error propagates and is not a deny.
    """
    result = slave_under(profile)
    if classify(result) != "deny":
        raise NotDenied(result)
    return result


def ensure_nl(text):
    if text.endswith("\n"):
        return text
    return text + "\n"


def with_setup(text):
    """Append the file-grant line and the ioctl line. Those lines are not the plant."""
    return ensure_nl(text) + FILE_GRANT + IOCTL_LINE


def with_plant(text):
    """Append the one plant line."""
    return ensure_nl(text) + PLANT


def without_setup(text):
    """Remove the setup lines. The plant line stays."""
    return text.replace(FILE_GRANT, "").replace(IOCTL_LINE, "")


def without_deny_default(text):
    """Delete the one ``(deny default)`` line. That deletion is not the plant."""
    if text.count(DENY_DEFAULT) != 1:
        raise HarnessError(
            f"(deny default) occurs {text.count(DENY_DEFAULT)} times, not once"
        )
    return text.replace(DENY_DEFAULT, "", 1)


def edit_text(baseline, line):
    """Setup plus one wallet edit. ``delete-default`` removes the default deny."""
    setup = with_setup(baseline)
    if line == DELETE_DEFAULT:
        return without_deny_default(setup)
    return setup + line


def injected_stdout(text):
    """The measured line for a profile text. Injected tests do not launch.

    The real falsifier launches. This map is only the test double.
    """
    has_setup = FILE_GRANT in text and IOCTL_LINE in text
    if not has_setup:
        return OPEN_FAIL
    if PLANT in text:
        return FULL_ALLOW
    for line in FULL_EDIT_LINES:
        if line in text:
            return FULL_ALLOW
    for line in PARTIAL_EDIT_LINES:
        if line in text:
            return PARTIAL_ALLOW
    return PTS_DENY


def synthetic_profile(added_lines=""):
    """One scenario profile. The clean fixture is the only base.

    Live profile bytes are not an input, so a planted file cannot be
    copied and then given another setup line. Each of the three grants
    occurs at most once. A second copy is its own harness error.
    """
    text = CLEAN_PROFILE + added_lines
    for line in (FILE_GRANT, IOCTL_LINE, PLANT):
        count = text.count(line)
        if count > 1:
            raise HarnessError(
                "scenario profile holds "
                + repr(line)
                + f" {count} times, not zero or one"
            )
    return text


def scenario_texts(allowed, added_lines):
    """Text for one synthetic scenario. Profiles not in ``allowed`` stay clean.

    This does not read a profile file. ``added_lines`` is appended to the
    clean fixture, never to bytes already on disk.
    """
    texts = {}
    for profile in PROFILES:
        added = added_lines if profile["name"] in allowed else ""
        texts[profile["name"]] = synthetic_profile(added)
    return texts


def suite_scenarios():
    """The injected suite. The first group is the plant. The rest force an allow."""
    allowed_profiles = (
        (),
        ("wallet",),
        ("did",),
        ("model",),
        ("wallet", "did", "model"),
    )
    scenarios = [
        (allowed, FILE_GRANT + IOCTL_LINE + PLANT, None)
        for allowed in allowed_profiles
    ]
    scenarios.extend(
        (allowed, added, stdout)
        for allowed in allowed_profiles[1:]
        for added in ("", FILE_GRANT, IOCTL_LINE, FILE_GRANT + IOCTL_LINE)
        for stdout in (PARTIAL_ALLOW, FULL_ALLOW)
    )
    return tuple(scenarios)


def write_copy(directory, name, text):
    path = os.path.join(directory, name + ".sb")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def falsifier_stems():
    """Copy names the falsifier launches, in launch order."""
    stems = []
    for name in ("wallet", "did", "model"):
        stems.extend((name + "-allow", name + "-setup", name + "-plant"))
    stems.extend(name for name, _line in STILL_DENY_EDITS)
    stems.extend(name for name, _line in FULL_EDITS)
    stems.extend(name for name, _line in PARTIAL_EDITS)
    return stems


def finding_paragraph(profile, result):
    """One CRITICAL record. The first line carries the live pin.

    The commit is ``last_change``. The label is ``pr_label`` of that commit.
    The digest is the bytes this run read. The helper line is
    ``result.command``. ``observed`` names ``pts`` when the name was
    returned and ``slave`` when the slave fd is 4.
    """
    commit = last_change(profile["path"])
    digest = sha256_file(profile["path"])
    names = named_calls(result.stdout)
    if names == ():
        raise HarnessError("finding stdout is not an allow: " + repr(result.stdout))
    return (
        f"CRITICAL {IDS[profile['name']]} {commit} {pr_label(commit)} "
        f"sha256 {digest}\n"
        f"profile: {profile['rel']}\n"
        f"helper: {result.command}\n"
        f"observed: {named_phrase(names)} {result.stdout.strip()}\n"
    )


def require_finding_pins(paragraph, profile, result):
    """The finding names the PR and the exact command. Each omission fails alone."""
    label = pr_label(last_change(profile["path"]))
    command = result.command
    if label == "" or label not in paragraph:
        raise AssertionError("finding omits pr_label")
    if command == "" or command not in paragraph:
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
            if self._outcome is not None:
                self._outcome.expecting_failure = False
            raise

    recorded.__doc__ = (
        "The live profile returned the pty slave. "
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
        result = slave_under(profile["path"])
        outcome = classify(result)
        if outcome != "allow":
            continue
        confirmed.append((profile, result))
        write_findings(ROOT, list(confirmed))
        case_cls.recorded_allows[profile["name"]] = FINDINGS[profile["name"]]
        mark_expected(
            case_cls,
            f"test_{profile['name']}_slave_is_denied",
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


class SlaveProbe(unittest.TestCase):
    """The helper under the live profiles, and the allow plant."""

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
        cls.parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-slave-parent-"))
        cls.root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-slave-root-"))
        cls.addClassCleanup(shutil.rmtree, cls.parent, ignore_errors=True)
        cls.addClassCleanup(shutil.rmtree, cls.root, ignore_errors=True)
        cls.binary = compile_slave(cls.parent, cls.root, HELPER_C)
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

    def test_unsandboxed_slave_succeeds(self):
        """Without ``sandbox-exec``, the helper opens the slave on fd 4.

        Inherited descriptors are closed, so the master is fd 3. Stderr is
        empty. A failure here is a harness error, so a later deny is about
        the profile.
        """
        source = os.path.join(self.parent, "ptyslave.c")
        self.assertEqual(Path(source).read_text(encoding="utf-8"), HELPER_C)
        self.assertIn("posix_openpt", HELPER_C)
        self.assertIn("grantpt", HELPER_C)
        self.assertIn("unlockpt", HELPER_C)
        self.assertIn("ptsname", HELPER_C)
        self.assertIn("TIOCGETA", HELPER_C)
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
        self.assertEqual(named_calls(result.stdout), ("pts", "slave"))

    def test_compile_failure_is_an_error(self):
        """``/usr/bin/cc`` on an empty source is a harness error, not a skip."""
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-slave-empty-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-slave-empty-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with self.assertRaises(HarnessError) as caught:
            compile_slave(parent, root, "")
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

    def test_wallet_slave_is_denied(self):
        """The real wallet profile refuses the pty slave at the open."""
        self._expect_real_deny(sbx.WALLET_CONFINE_SB)

    def test_did_slave_is_denied(self):
        """The real did profile refuses the pty slave at the open."""
        did = sbx.REPO_ROOT / "capsules/did-provider/confine.sb"
        self._expect_real_deny(did)

    def test_model_slave_is_denied(self):
        """The real model profile refuses the pty slave at the open.

        The helper starts under it.
        """
        model = sbx.REPO_ROOT / "capsules/model-provider/confine.sb"
        self._expect_real_deny(model)

    def _assert_line_identity(self):
        self.assertEqual(PLANT, PLANT_PHRASE + "\n")
        self.assertNotEqual(PLANT, FILE_GRANT)
        self.assertNotEqual(PLANT, IOCTL_LINE)
        self.assertEqual((FILE_GRANT + IOCTL_LINE).count(PLANT), 0)
        for line in FULL_EDIT_LINES + PARTIAL_EDIT_LINES:
            self.assertNotEqual(line, PLANT)
            self.assertEqual(line.count(PLANT), 0)
            self.assertEqual(PLANT.count(line), 0)
        near_write = FULL_EDITS[1][1]
        near_short = FULL_EDITS[0][1]
        self.assertEqual(near_write.count(PLANT), 0)
        self.assertEqual(near_short.count(PLANT), 0)
        self.assertEqual((near_write + near_short).count(PLANT), 0)

    def _assert_source_counts(self, name, text):
        self.assertEqual(text.count(DENY_DEFAULT), 1)
        for _edit, line in STILL_DENY_EDITS:
            if line == DELETE_DEFAULT:
                continue
            self.assertEqual(text.count(line), 0)
        for line in FULL_EDIT_LINES + PARTIAL_EDIT_LINES:
            self.assertEqual(text.count(line), 0)
        if name not in type(self).recorded_allows:
            self.assertEqual(text.count(PLANT), 0)
            self.assertEqual(text.count(PLANT_PHRASE), 0)
            self.assertEqual(text.count(FILE_GRANT), 0)
            self.assertEqual(text.count(IOCTL_LINE), 0)
            return
        # An observed allow does not identify the grants in the source.
        for line in (PLANT, FILE_GRANT, IOCTL_LINE):
            if line in text:
                self.assertEqual(text.count(line), 1)
            else:
                self.assertEqual(text.count(line), 0)

    def _assert_baseline(self, name, text, baseline):
        self.assertEqual(baseline.count(PLANT), 0)
        self.assertEqual(baseline.count(PLANT_PHRASE), 0)
        self.assertEqual(baseline.count(DENY_DEFAULT), 1)
        self.assertTrue(baseline.endswith("\n"))
        if name not in type(self).recorded_allows:
            self.assertEqual(baseline, text)
            self.assertEqual(baseline.count(FILE_GRANT), 0)
            self.assertEqual(baseline.count(IOCTL_LINE), 0)
            return
        self.assertEqual(baseline, text.replace(PLANT, "", 1))
        for line in (FILE_GRANT, IOCTL_LINE):
            if line in text:
                self.assertEqual(baseline.count(line), 1)
                self.assertNotEqual(baseline.count(line), 0)
            else:
                self.assertEqual(baseline.count(line), 0)

    def _expect_copy(self, profile, path, stdout):
        repo = os.fspath(profile["path"])
        if stdout in DENY_LINES:
            denied = require_denied(path)
            self.assertEqual(denied.stdout, stdout)
            self.assertEqual(denied.stderr, "")
            self.assertEqual(denied.exit_code, 0)
            self.assertEqual(classify(denied), "deny")
            self.assertEqual(denied.argv[0], sbx.SANDBOX_EXEC)
            self.assertIn(path, denied.argv)
            self.assertNotIn(repo, denied.argv)
            return denied
        with self.assertRaises(NotDenied) as caught:
            require_denied(path)
        result = caught.exception.result
        self.assertIn("ALLOW", str(caught.exception))
        self.assertIsNone(sbx.profile_error(result))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, stdout)
        self.assertEqual(classify(result), "allow")
        if stdout == FULL_ALLOW:
            self.assertEqual(named_calls(result.stdout), ("pts", "slave"))
        else:
            self.assertEqual(named_calls(result.stdout), ("pts",))
        self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
        self.assertIn(path, result.argv)
        self.assertNotIn(repo, result.argv)
        return result

    def test_falsifier_allow_slave_is_caught(self):
        """The plant beside the two setup lines opens the slave.

        The zero-count reads the plant baseline from ``_source_for_plant``.
        A recorded allow strips an exact plant line when present and keeps the
        file-grant line and the ioctl line. On a clean source those three
        counts are zero and ``(deny default)`` occurs once. After the strip,
        the plant count is zero. Each setup line keeps its source count,
        including when an allow was observed from unchanged source text.

        Setup plus the plant prints the full allow, and the deny check
        fails. Setup without the plant prints the ptsname line, and the
        deny check passes. The plant alone prints the open-fail line, and
        the deny check passes. The wallet edits that still deny, that fully
        allow, and that partially allow are not this plant. The repo profile
        bytes stay unchanged.
        """
        before = {
            profile["rel"]: sha256_file(profile["path"]) for profile in PROFILES
        }
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-slave-profile-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        try:
            self._assert_line_identity()
            for profile in PROFILES:
                with self.subTest(profile=profile["name"]):
                    text = profile["path"].read_text(encoding="utf-8")
                    self._assert_source_counts(profile["name"], text)
                    baseline = self._source_for_plant(profile["name"], text)
                    self._assert_baseline(profile["name"], text, baseline)
                    planted = with_plant(with_setup(baseline))
                    self.assertEqual(planted.count(PLANT), baseline.count(PLANT) + 1)
                    self.assertEqual(
                        planted.count(FILE_GRANT), baseline.count(FILE_GRANT) + 1
                    )
                    self.assertEqual(
                        planted.count(IOCTL_LINE), baseline.count(IOCTL_LINE) + 1
                    )
                    allow_copy = write_copy(directory, profile["name"] + "-allow", planted)
                    self.assertEqual(Path(allow_copy).read_text(encoding="utf-8"), planted)
                    self.assertNotEqual(
                        os.path.realpath(allow_copy), os.path.realpath(profile["path"])
                    )
                    self._expect_copy(profile, allow_copy, FULL_ALLOW)

                    setup_only = with_setup(baseline)
                    self.assertEqual(setup_only.count(PLANT), 0)
                    self.assertGreaterEqual(setup_only.count(FILE_GRANT), 1)
                    self.assertGreaterEqual(setup_only.count(IOCTL_LINE), 1)
                    setup_copy = write_copy(
                        directory, profile["name"] + "-setup", setup_only
                    )
                    self._expect_copy(profile, setup_copy, PTS_DENY)

                    bare = without_setup(baseline)
                    self.assertEqual(bare.count(FILE_GRANT), 0)
                    self.assertEqual(bare.count(IOCTL_LINE), 0)
                    self.assertNotIn(PLANT, bare)
                    plant_only = with_plant(bare)
                    self.assertEqual(plant_only.count(PLANT), 1)
                    self.assertEqual(plant_only.count(FILE_GRANT), 0)
                    self.assertEqual(plant_only.count(IOCTL_LINE), 0)
                    self.assertNotEqual(plant_only, text)
                    plant_copy = write_copy(
                        directory, profile["name"] + "-plant", plant_only
                    )
                    self._expect_copy(profile, plant_copy, OPEN_FAIL)
                    self.assertEqual(profile["path"].read_text(encoding="utf-8"), text)

            wallet = PROFILES[0]
            self.assertEqual(wallet["name"], "wallet")
            wallet_text = wallet["path"].read_text(encoding="utf-8")
            baseline = self._source_for_plant("wallet", wallet_text)
            self._assert_baseline("wallet", wallet_text, baseline)
            for name, line in STILL_DENY_EDITS:
                with self.subTest(profile=name):
                    widened = edit_text(baseline, line)
                    self.assertEqual(widened.count(PLANT), 0)
                    self.assertIn(FILE_GRANT, widened)
                    self.assertIn(IOCTL_LINE, widened)
                    if line == DELETE_DEFAULT:
                        self.assertNotIn("(deny default)", widened)
                    else:
                        self.assertNotEqual(line, PLANT)
                        self.assertEqual(widened.count(line), baseline.count(line) + 1)
                        self.assertEqual(widened.count(DENY_DEFAULT), 1)
                    copy = write_copy(directory, name, widened)
                    self._expect_copy(wallet, copy, PTS_DENY)
            for name, line in FULL_EDITS:
                with self.subTest(profile=name):
                    widened = edit_text(baseline, line)
                    self.assertNotEqual(line, PLANT)
                    self.assertEqual(widened.count(PLANT), 0)
                    self.assertEqual(widened.count(line), 1)
                    self.assertIn(FILE_GRANT, widened)
                    self.assertIn(IOCTL_LINE, widened)
                    copy = write_copy(directory, name, widened)
                    self._expect_copy(wallet, copy, FULL_ALLOW)
            for name, line in PARTIAL_EDITS:
                with self.subTest(profile=name):
                    widened = edit_text(baseline, line)
                    self.assertNotEqual(line, PLANT)
                    self.assertEqual(widened.count(PLANT), 0)
                    self.assertEqual(widened.count(line), 1)
                    self.assertIn(FILE_GRANT, widened)
                    self.assertIn(IOCTL_LINE, widened)
                    copy = write_copy(directory, name, widened)
                    self._expect_copy(wallet, copy, PARTIAL_ALLOW)
            self.assertEqual(wallet["path"].read_text(encoding="utf-8"), wallet_text)
        finally:
            require_unchanged(before)

    def _source_for_plant(self, name, text):
        """The text the temp plant edits. A recorded allow does not skip this.

        The deny test carries the finding-linked expected failure. The live
        file is not edited. One exact plant line is removed from the copy.
        The file-grant line and the ioctl line stay. A plant phrase with no
        trailing newline is its own harness error.
        """
        finding = type(self).recorded_allows.get(name)
        if finding is None:
            if PLANT_PHRASE in text:
                raise AssertionError(f"{name} source contains {PLANT_PHRASE}")
            return text
        method = getattr(type(self), f"test_{name}_slave_is_denied")
        if not getattr(method, "__unittest_expecting_failure__", False):
            raise HarnessError(f"{name} allow has no finding-linked expected failure")
        if finding not in (method.__doc__ or ""):
            raise HarnessError(f"{name} allow docstring does not name {finding}")
        occurrences = text.count(PLANT)
        if occurrences > 1:
            raise HarnessError(
                f"{PLANT_PHRASE} occurs {occurrences} times, not zero or one"
            )
        if occurrences == 1:
            text = text.replace(PLANT, "", 1)
        if PLANT_PHRASE in text:
            raise HarnessError(f"{name} plant line has no trailing newline")
        return text


class SlaveRules(unittest.TestCase):
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
        )
        probe_names = unittest.defaultTestLoader.getTestCaseNames(SlaveProbe)
        for missing in ((sbx.SANDBOX_EXEC,), (CC,), (sbx.SANDBOX_EXEC, CC)):
            with self.subTest(missing=missing), patch.object(
                os.path, "isfile", side_effect=lambda path: path not in missing
            ), patch(
                __name__ + ".compile_slave",
                side_effect=AssertionError("missing-tool probe compiled a helper"),
            ) as compiled, patch.object(
                sbx, "run",
                side_effect=AssertionError("missing-tool probe launched a helper"),
            ) as launched:
                class MissingTools(SlaveProbe):
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

        Both tools are injected as present. The plant source is still
        produced. Stripping the plant leaves the file-grant line and the
        ioctl line. A recorded allow without that mark, a docstring that
        omits the finding, and a second plant line are each their own
        harness error.
        """
        with patch.object(os.path, "isfile", return_value=True):
            self.assertIsNone(skip_reason())
            self.assertTrue(os.path.isfile(CC))
            self.assertTrue(os.path.isfile(sbx.SANDBOX_EXEC))
        base = "(version 1)\n(deny default)\n"
        text = base + FILE_GRANT + IOCTL_LINE + PLANT
        clean = base + FILE_GRANT + IOCTL_LINE

        class Recorded(SlaveProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Recorded, "test_wallet_slave_is_denied", FINDINGS["wallet"])
        try:
            case = Recorded("test_falsifier_allow_slave_is_caught")
            baseline = case._source_for_plant("wallet", text)
            self.assertEqual(baseline, clean)
            self.assertEqual(baseline.count(PLANT), 0)
            self.assertEqual(baseline.count(FILE_GRANT), 1)
            self.assertEqual(baseline.count(IOCTL_LINE), 1)
            self.assertEqual(case._source_for_plant("did", base), base)
            self.assertNotIsInstance(baseline, type(unittest.SkipTest("x")))
        finally:
            Recorded.doClassCleanups()

        class Bare(SlaveProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        bare = Bare("test_falsifier_allow_slave_is_caught")
        with self.assertRaises(HarnessError) as unmarked:
            bare._source_for_plant("wallet", text)
        self.assertEqual(
            str(unmarked.exception),
            "wallet allow has no finding-linked expected failure",
        )
        self.assertNotIsInstance(unmarked.exception, unittest.SkipTest)

        class WrongDoc(SlaveProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        def body(self):
            raise NotDenied(
                sbx.Result(exit_code=0, stdout=FULL_ALLOW, stderr="", argv=[])
            )

        body.__doc__ = "plain"
        body.__unittest_expecting_failure__ = True
        WrongDoc.test_wallet_slave_is_denied = body
        wrong = WrongDoc("test_falsifier_allow_slave_is_caught")
        with self.assertRaises(HarnessError) as unnamed:
            wrong._source_for_plant("wallet", text)
        self.assertEqual(
            str(unnamed.exception),
            f"wallet allow docstring does not name {FINDINGS['wallet']}",
        )

        class Twice(SlaveProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Twice, "test_wallet_slave_is_denied", FINDINGS["wallet"])
        try:
            twice = Twice("test_falsifier_allow_slave_is_caught")
            with self.assertRaises(HarnessError) as extra:
                twice._source_for_plant("wallet", text + PLANT)
            self.assertEqual(
                str(extra.exception),
                f"{PLANT_PHRASE} occurs 2 times, not zero or one",
            )
        finally:
            Twice.doClassCleanups()

        class BareLine(SlaveProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(BareLine, "test_wallet_slave_is_denied", FINDINGS["wallet"])
        try:
            bare_line = BareLine("test_falsifier_allow_slave_is_caught")
            missing_newline = "wallet plant line has no trailing newline"
            with self.assertRaises(HarnessError) as bare_phrase:
                bare_line._source_for_plant("wallet", clean + PLANT_PHRASE)
            self.assertEqual(str(bare_phrase.exception), missing_newline)
            with self.assertRaises(HarnessError) as mixed:
                bare_line._source_for_plant("wallet", clean + PLANT + PLANT_PHRASE)
            self.assertEqual(str(mixed.exception), missing_newline)
        finally:
            BareLine.doClassCleanups()

        class Clean(SlaveProbe):
            recorded_allows = {}

        plain = Clean("test_falsifier_allow_slave_is_caught")
        with self.assertRaises(AssertionError) as present:
            plain._source_for_plant("wallet", text)
        self.assertEqual(
            str(present.exception),
            f"wallet source contains {PLANT_PHRASE}",
        )
        self.assertEqual(plain._source_for_plant("wallet", base), base)
        self.assertEqual(plain._source_for_plant("wallet", clean), clean)
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

        rel = "tmp/slave-confine.sb"
        self.assertNotIn(rel, START_SHA)
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-slave-byte-"))
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

        A nonzero exit, a missing executable, and an unresolved storage path
        each keep a different reason. Empty stderr still returns the binary.
        The compiler command is ``/usr/bin/cc -o`` the binary and the source,
        with inherited descriptors closed.
        """
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-slave-cc-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-slave-cc-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        binary = os.path.join(root, BINARY_NAME)
        source = "int main(void) { return 0; }\n"
        reasons = []

        def compiled(completed, access=None):
            runners = patch.object(subprocess, "run", return_value=completed)
            if access is None:
                with runners:
                    return compile_slave(parent, root, source)
            with runners, patch.object(os, "access", return_value=access):
                return compile_slave(parent, root, source)

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
        with patch.object(subprocess, "run", return_value=silent) as ran, patch.object(
            os, "access", return_value=True
        ):
            self.assertEqual(compile_slave(parent, root, source), binary)
        command = ran.call_args.args[0]
        self.assertEqual(command, [CC, "-o", binary, os.path.join(parent, "ptyslave.c")])
        self.assertNotIn("-framework", command)
        self.assertTrue(ran.call_args.kwargs["close_fds"])

        def refuse_cc(*_args, **_kwargs):
            raise AssertionError("compiler started")

        for label, compile_parent, compile_root in (
            ("parent", "/var/folders/cc/slave-parent", root),
            ("root", parent, "/var/folders/cc/slave-root"),
        ):
            bad = compile_parent if label == "parent" else compile_root
            expected = (
                f"execvp: {bad} contains /var/folders without the /private prefix"
            )
            with self.subTest(path=label), patch.object(
                subprocess, "run", side_effect=refuse_cc
            ):
                with self.assertRaises(HarnessError) as caught:
                    compile_slave(compile_parent, compile_root, source)
            self.assertEqual(str(caught.exception), expected)
            self.assertNotIn("/private" + bad, str(caught.exception))
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
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-slave-bytes-"))
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

            class Plant(SlaveProbe):
                recorded_allows = {}

            state = {"mutate": False}

            def fake_denied(profile):
                profile = os.fspath(profile)
                body = Path(profile).read_text(encoding="utf-8")
                if state["mutate"] and profile.endswith(os.sep + "wallet-deleted.sb"):
                    wallet["path"].write_bytes(after_bytes)
                stdout = injected_stdout(body)
                result = sbx.Result(
                    exit_code=0,
                    stdout=stdout,
                    stderr="",
                    argv=[sbx.SANDBOX_EXEC, "-f", profile, "/private/ptyslave"],
                )
                if classify(result) != "deny":
                    raise NotDenied(result)
                return result

            case = Plant("test_falsifier_allow_slave_is_caught")
            try:
                with patch(__name__ + ".PROFILES", profiles), patch(
                    __name__ + ".require_denied", new=fake_denied
                ), patch(__name__ + ".changed", new=spy):
                    with self.subTest(path="falsifier-equal"):
                        seen.clear()
                        state["mutate"] = False
                        case.test_falsifier_allow_slave_is_caught()
                        self.assertEqual(seen, equal_pairs)
                    with self.subTest(path="falsifier-changed"):
                        seen.clear()
                        state["mutate"] = True
                        wallet["path"].write_bytes(clean)
                        with self.assertRaises(AssertionError) as caught:
                            case.test_falsifier_allow_slave_is_caught()
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
        def sample(label, stdout, expected=None, exit_code=0, stderr=""):
            result = sbx.Result(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                argv=["/private/ptyslave"],
            )
            if expected is None:
                expected = harness(label, stdout)
            return (label, result, expected)

        wrong = sbx.Result(
            exit_code=2, stdout=OPEN_FAIL, stderr="", argv=["/private/ptyslave"],
        )
        denied_noise = sbx.Result(
            exit_code=0, stdout=OPEN_FAIL, stderr="noise\n", argv=["/private/ptyslave"],
        )
        allowed_noise = sbx.Result(
            exit_code=0, stdout=FULL_ALLOW, stderr="noise\n", argv=["/private/ptyslave"],
        )
        profile_error = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout=OPEN_FAIL,
            stderr="Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/ptyslave"],
        )
        return (
            sample("wrong exit", OPEN_FAIL, wrong_exit_reason(wrong), exit_code=2),
            sample(
                "open fd other than -1 or 3",
                slave_line(5, 0, 1, 0, 1, 0, 1, 0, 4, 0, 1, 0),
            ),
            sample(
                "open errno other than 1 on fd=-1",
                slave_line(-1, 2, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0),
            ),
            sample(
                "open fd=3 with grant ok=-1",
                slave_line(3, 0, -1, 1, 1, 0, 0, 1, -1, 0, -1, 0),
            ),
            sample(
                "open fd=3 with pts ok=-1",
                slave_line(3, 0, 1, 0, 1, 0, -1, 0, -1, 0, -1, 0),
            ),
            sample(
                "open fd=3 with grant ok=0",
                slave_line(3, 0, 0, 1, 1, 0, -1, 0, -1, 0, -1, 0),
            ),
            sample("unlock ok=0", slave_line(3, 0, 1, 0, 0, 1, 0, 1, -1, 0, -1, 0)),
            sample(
                "pts ok=1 with a nonzero errno",
                slave_line(3, 0, 1, 0, 1, 0, 1, 2, 4, 0, 1, 0),
            ),
            sample(
                "pts ok=0 with errno other than 1",
                slave_line(3, 0, 1, 0, 1, 0, 0, 2, -1, 0, -1, 0),
            ),
            sample(
                "slave fd other than -1 or 4",
                slave_line(3, 0, 1, 0, 1, 0, 1, 0, 5, 0, -1, 0),
            ),
            sample(
                "slave fd=4 with ioctl ok=0",
                slave_line(3, 0, 1, 0, 1, 0, 1, 0, 4, 0, 0, 1),
            ),
            sample(
                "ioctl ok=-1 when slave fd is 4",
                slave_line(3, 0, 1, 0, 1, 0, 1, 0, 4, 0, -1, 0),
            ),
            sample(
                "slave fd=-1 and errno=0 with pts ok=1",
                slave_line(3, 0, 1, 0, 1, 0, 1, 0, -1, 0, -1, 0),
            ),
            (
                "nonempty deny stderr",
                denied_noise,
                deny_stderr_reason("noise\n"),
            ),
            (
                "nonempty allow stderr",
                allowed_noise,
                allow_stderr_reason("noise\n"),
            ),
            sample("malformed stdout", "open nope\n"),
            (
                "profile error",
                profile_error,
                profile_reason(profile_error, sbx.profile_error(profile_error)),
            ),
        )

    def test_classifier_refusal_reasons(self):
        """Each classifier refusal preserves its exact, distinct reason.

        These results are built here. Nothing is launched. Exit 65 stays a
        profile error when stderr says ``Operation not permitted``. The
        open-fail line and the ptsname line are denies. The full line and
        the partial line are allows.
        """
        self.assertEqual(
            OPEN_FAIL,
            "open fd=-1 errno=1 grant ok=-1 errno=0 unlock ok=-1 errno=0 "
            "pts ok=-1 errno=0 slave fd=-1 errno=0 ioctl ok=-1 errno=0\n",
        )
        self.assertEqual(
            PTS_DENY,
            "open fd=3 errno=0 grant ok=1 errno=0 unlock ok=1 errno=0 "
            "pts ok=0 errno=1 slave fd=-1 errno=0 ioctl ok=-1 errno=0\n",
        )
        self.assertEqual(
            FULL_ALLOW,
            "open fd=3 errno=0 grant ok=1 errno=0 unlock ok=1 errno=0 "
            "pts ok=1 errno=0 slave fd=4 errno=0 ioctl ok=1 errno=0\n",
        )
        self.assertEqual(
            PARTIAL_ALLOW,
            "open fd=3 errno=0 grant ok=1 errno=0 unlock ok=1 errno=0 "
            "pts ok=1 errno=0 slave fd=-1 errno=1 ioctl ok=-1 errno=0\n",
        )
        self.assertEqual(
            classify(sbx.Result(
                exit_code=0, stdout=FULL_ALLOW, stderr="", argv=["/private/ptyslave"],
            )),
            "allow",
        )
        self.assertEqual(named_calls(FULL_ALLOW), ("pts", "slave"))
        self.assertEqual(
            classify(sbx.Result(
                exit_code=0, stdout=PARTIAL_ALLOW, stderr="", argv=["/private/ptyslave"],
            )),
            "allow",
        )
        self.assertEqual(named_calls(PARTIAL_ALLOW), ("pts",))
        self.assertEqual(
            classify(sbx.Result(
                exit_code=0, stdout=OPEN_FAIL, stderr="", argv=["/private/ptyslave"],
            )),
            "deny",
        )
        self.assertEqual(
            classify(sbx.Result(
                exit_code=0, stdout=PTS_DENY, stderr="", argv=["/private/ptyslave"],
            )),
            "deny",
        )
        self.assertEqual(named_calls(OPEN_FAIL), ())
        self.assertEqual(named_calls(PTS_DENY), ())
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
                label for label, _result, expected in samples if expected == message
            )])
        self.launch_guard.assert_not_called()

    def test_partial_ptsname_is_an_allow(self):
        """The partial line is an allow. The named call is ``pts``.

        Exit is 0 and stderr is empty. The slave fd stays closed. This is
        not a harness error.
        """
        result = sbx.Result(
            exit_code=0,
            stdout=PARTIAL_ALLOW,
            stderr="",
            argv=["/private/ptyslave"],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(classify(result), "allow")
        self.assertEqual(named_calls(result.stdout), ("pts",))
        self.assertEqual(named_phrase(named_calls(result.stdout)), "pts")
        self.assertNotIn("slave", named_phrase(named_calls(result.stdout)))
        self.assertNotEqual(result.stdout, FULL_ALLOW)
        self.assertNotEqual(result.stdout, OPEN_FAIL)
        self.assertNotEqual(result.stdout, PTS_DENY)
        self.launch_guard.assert_not_called()

    def test_unsandboxed_failure_is_an_error(self):
        """A failed unsandboxed control is a harness error, not an assertion failure.

        The open-fail line, the ptsname line, the partial allow, a nonzero
        exit, stderr, and a malformed line each raise ``HarnessError``.
        They launch nothing. The control closes inherited descriptors.
        """
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-slave-unsandboxed-"))
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
                "unsandboxed pts deny",
                subprocess.CompletedProcess([binary], 0, PTS_DENY, ""),
                "unsandboxed pts deny is a harness error, not a passing control: "
                + repr(PTS_DENY),
            ),
            (
                "unsandboxed partial allow",
                subprocess.CompletedProcess([binary], 0, PARTIAL_ALLOW, ""),
                "unsandboxed partial allow is a harness error, not a passing control: "
                + repr(PARTIAL_ALLOW),
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
                "nonempty allow stderr is a harness error, not an allow: "
                + repr("noise\n"),
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
                    self.assertTrue(ran.call_args.kwargs["close_fds"])
                message = str(caught.exception)
                self.assertEqual(message, expected)
                self.assertIn(label, message)
                self.assertNotIsInstance(caught.exception, AssertionError)
                reasons.append(message)
        self.assertEqual(len(set(reasons)), len(cases))
        self.launch_guard.assert_not_called()

    def test_observe_propagates_every_refusal(self):
        """A failed observation stops before any later success or finding mark."""
        deny = sbx.Result(
            exit_code=0, stdout=OPEN_FAIL, stderr="", argv=["/private/ptyslave"],
        )
        for label, refused, expected in self.refusal_samples():
            for preceding in ([], [deny], [deny, deny]):
                with self.subTest(reason=label, position=len(preceding)):
                    class Observed(SlaveProbe):
                        pass

                    with patch(
                        __name__ + ".slave_under",
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
        with patch(__name__ + ".slave_under", side_effect=[refused] * 3) as opened:
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
            stdout=FULL_ALLOW,
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/ptyslave"],
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
            class Observed(SlaveProbe):
                pass

            pending = list(results)
            order = []

            def opened(path):
                order.append(("open", path))
                return pending.pop(0)

            def written(_repo, items):
                order.append(("write", [item[0]["name"] for item in items]))

            with patch(__name__ + ".slave_under", side_effect=opened), patch(
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
            method = observed.test_wallet_slave_is_denied
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
            did_method = observed.test_did_slave_is_denied
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

        The injected profile contains the file-grant line, the ioctl line,
        and the plant line. The finding's first line contains the commit from
        ``last_change``, ``pr_label`` of that commit, and the sha256. The
        helper line is ``result.command``. The finding names ``pts`` and
        ``slave``. The wallet docstring names ``CRITICAL-confine-072.md``.
        The model docstring names ``CRITICAL-cc-model-confine-072.md``. A
        unittest run of each injected allow is one expected failure.
        Dropping only the PR label raises ``finding omits pr_label``.
        Dropping only ``result.command`` raises ``finding omits command``.
        The clean run writes no finding.
        """
        self.enter_patch(patch(__name__ + ".last_change", return_value="a" * 40))
        self.enter_patch(patch(__name__ + ".pr_label", return_value="PR fixture"))
        injected = "(version 1)\n(deny default)\n" + FILE_GRANT + IOCTL_LINE + PLANT
        self.assertEqual(injected.count(FILE_GRANT), 1)
        self.assertEqual(injected.count(IOCTL_LINE), 1)
        self.assertEqual(injected.count(PLANT), 1)
        wallet = dict(PROFILES[0])
        did = dict(PROFILES[1])
        model = dict(PROFILES[2])
        self.assertEqual(wallet["name"], "wallet")
        self.assertEqual(did["name"], "did")
        self.assertEqual(model["name"], "model")
        command_argv = [sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/ptyslave"]
        allow = sbx.Result(
            exit_code=0, stdout=FULL_ALLOW, stderr="", argv=list(command_argv),
        )
        partial = sbx.Result(
            exit_code=0, stdout=PARTIAL_ALLOW, stderr="", argv=list(command_argv),
        )
        self.assertTrue(allow.command)
        self.assertIsNone(sbx.profile_error(allow))
        self.assertEqual(classify(allow), "allow")
        self.assertEqual(named_calls(allow.stdout), ("pts", "slave"))
        live_names = (
            ROOT / "lab" / "redteam" / "CRITICAL.md",
            ROOT / FINDINGS["wallet"],
            ROOT / FINDINGS["model"],
        )
        before = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        with tempfile.TemporaryDirectory(prefix="ccrt-slave-finding-") as tmp:
            repo = Path(tmp)
            for profile in (wallet, did, model):
                path = repo / (profile["name"] + ".sb")
                path.write_text(injected, encoding="utf-8")
                profile["path"] = path
            paragraph = finding_paragraph(wallet, allow)
            label = pr_label(last_change(wallet["path"]))
            digest = sha256_file(wallet["path"])
            commit = last_change(wallet["path"])
            first = paragraph.splitlines()[0]
            self.assertIn("CRITICAL", first)
            self.assertIn(IDS["wallet"], first)
            self.assertIn(commit, first)
            self.assertIn(label, first)
            self.assertIn(digest, first)
            self.assertIn(f"helper: {allow.command}\n", paragraph)
            self.assertIn("observed: pts and slave ", paragraph)
            self.assertIn(FULL_ALLOW.strip(), paragraph)
            self.assertEqual(paragraph.count(label), 1)
            self.assertEqual(paragraph.count(allow.command), 1)
            self.assertNotIn(label, allow.command)
            self.assertNotIn(allow.command, label)
            require_finding_pins(paragraph, wallet, allow)
            pr_omitted = paragraph.replace(label, "", 1)
            with self.assertRaises(AssertionError) as omitted_pr:
                require_finding_pins(pr_omitted, wallet, allow)
            self.assertEqual(str(omitted_pr.exception), "finding omits pr_label")
            self.assertIn(allow.command, pr_omitted)
            command_omitted = paragraph.replace(allow.command, "", 1)
            with self.assertRaises(AssertionError) as omitted_command:
                require_finding_pins(command_omitted, wallet, allow)
            self.assertEqual(str(omitted_command.exception), "finding omits command")
            self.assertIn(label, command_omitted)
            partial_paragraph = finding_paragraph(wallet, partial)
            self.assertIn("observed: pts ", partial_paragraph)
            self.assertNotIn("observed: pts and slave", partial_paragraph)
            require_finding_pins(partial_paragraph, wallet, partial)
            self.assertEqual(write_findings(repo, []), [])
            self.assertFalse((repo / "lab" / "redteam" / "CRITICAL.md").exists())
            written = write_findings(repo, [(wallet, allow), (did, allow)])
            self.assertEqual(written, [FINDINGS["wallet"]])
            body = (repo / FINDINGS["wallet"]).read_text(encoding="utf-8")
            did_paragraph = finding_paragraph(did, allow)
            self.assertEqual(body, paragraph + did_paragraph)
            self.assertIn("pts and slave", body)
            listed = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertIn(paragraph, listed)
            self.assertIn(did_paragraph, listed)
            model_paragraph = finding_paragraph(model, allow)
            model_written = write_findings(repo, [(model, allow)])
            self.assertEqual(model_written, [FINDINGS["model"]])
            model_body = (repo / FINDINGS["model"]).read_text(encoding="utf-8")
            self.assertEqual(model_body, model_paragraph)
            self.assertIn("CRITICAL", model_paragraph.splitlines()[0])
            self.assertIn("CRITICAL-cc-model-confine-072", model_paragraph)
            self.assertIn("pts and slave", model_paragraph)
            listed_again = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(
                encoding="utf-8"
            )
            self.assertIn(model_paragraph, listed_again)
            self.assertEqual(listed_again.count(model_paragraph), 1)

        after = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        self.assertEqual(before, after)

        class Unmarked(unittest.TestCase):
            def test_wallet_slave_is_denied(self):
                """plain"""
                raise NotDenied(allow)

        unmarked = unittest.TestResult()
        Unmarked("test_wallet_slave_is_denied").run(unmarked)
        self.assertEqual(len(unmarked.failures), 1)
        self.assertEqual(unmarked.expectedFailures, [])
        self.assertEqual(unmarked.errors, [])

        def run_marked(name):
            method_name = f"test_{name}_slave_is_denied"

            class Recorded(SlaveProbe):
                skip_reason = None

            mark_expected(Recorded, method_name, FINDINGS[name])
            method = getattr(Recorded, method_name)
            self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
            self.assertIn(FINDINGS[name], method.__doc__)
            if name == "model":
                self.assertIn("CRITICAL-cc-model-confine-072.md", method.__doc__)
            else:
                self.assertIn("CRITICAL-confine-072.md", method.__doc__)
                self.assertNotIn("cc-model", method.__doc__)

            def opened(profile):
                body = Path(profile).read_text(encoding="utf-8")
                self.assertIn(FILE_GRANT, body)
                self.assertIn(IOCTL_LINE, body)
                self.assertIn(PLANT, body)
                return allow

            result = unittest.TestResult()
            try:
                with tempfile.TemporaryDirectory(prefix="ccrt-slave-marked-") as tmp:
                    root = Path(tmp)
                    if name == "wallet":
                        path = root / "wallet.sb"
                        path.write_text(injected, encoding="utf-8")
                        target = patch.object(sbx, "WALLET_CONFINE_SB", path)
                    else:
                        path = root / "capsules" / "model-provider" / "confine.sb"
                        path.parent.mkdir(parents=True)
                        path.write_text(injected, encoding="utf-8")
                        target = patch.object(sbx, "REPO_ROOT", root)
                    with target, patch(__name__ + ".slave_under", side_effect=opened):
                        Recorded(method_name).run(result)
            finally:
                Recorded.doClassCleanups()
            self.assertEqual(len(result.expectedFailures), 1)
            self.assertEqual(result.failures, [])
            self.assertEqual(result.errors, [])
            self.assertEqual(result.unexpectedSuccesses, [])
            self.assertEqual(result.skipped, [])
            self.assertTrue(result.wasSuccessful())
            self.assertEqual(result.expectedFailures[0][0]._testMethodName, method_name)

        run_marked("wallet")
        run_marked("model")
        self.launch_guard.assert_not_called()

    def test_wallet_controls_reject_allow_with_or_without_finding(self):
        """Each still-deny copy fails on an allow, with or without a recorded finding.

        The failure is ordinary, not expected, and not a skip.
        """
        injected = "(version 1)\n(deny default)\n(deny network*)\n"
        planted = injected + FILE_GRANT + IOCTL_LINE + PLANT
        for recorded in (False, True):
            for control, _line in STILL_DENY_EDITS:
                with self.subTest(recorded=recorded, control=control), tempfile.TemporaryDirectory(
                    prefix="ccrt-slave-control-"
                ) as tmp:
                    profiles = []
                    for original in PROFILES:
                        profile = dict(original)
                        profile["path"] = Path(tmp) / f"{profile['name']}.sb"
                        text = planted if recorded and profile["name"] == "wallet" else injected
                        profile["path"].write_text(text, encoding="utf-8")
                        profiles.append(profile)

                    class Control(SlaveProbe):
                        skip_reason = None
                        recorded_allows = {}

                    if recorded:
                        finding = FINDINGS["wallet"]
                        Control.recorded_allows["wallet"] = finding
                        mark_expected(Control, "test_wallet_slave_is_denied", finding)
                        method = Control.test_wallet_slave_is_denied
                        self.assertTrue(
                            getattr(method, "__unittest_expecting_failure__", False)
                        )
                        self.assertIn(finding, method.__doc__ or "")

                    opened = []

                    def injected_open(profile):
                        path = Path(profile)
                        opened.append(path.name)
                        body = path.read_text(encoding="utf-8")
                        stdout = (
                            FULL_ALLOW if path.stem == control else injected_stdout(body)
                        )
                        return sbx.Result(
                            exit_code=0,
                            stdout=stdout,
                            stderr="",
                            argv=[sbx.SANDBOX_EXEC, "-f", os.fspath(path)],
                        )

                    result = unittest.TestResult()
                    try:
                        with patch(__name__ + ".PROFILES", tuple(profiles)), patch(
                            __name__ + ".slave_under", side_effect=injected_open
                        ):
                            Control("test_falsifier_allow_slave_is_caught").run(result)
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
                    self.assertIn("open fd=3", caught)
                    self.assertFalse(result.wasSuccessful())
                    self.assertEqual(
                        opened, [stem + ".sb" for stem in falsifier_stems()]
                    )
        self.launch_guard.assert_not_called()

    @contextlib.contextmanager
    def _injected_probe_class(self, texts, observations):
        """Run ``SlaveProbe`` on ``texts``. A grant line may occur once.

        ``observations`` forces the stdout of that profile. Other launches
        use ``injected_stdout``. This does not read a live profile.
        """
        for name, text in texts.items():
            for line in (FILE_GRANT, IOCTL_LINE, PLANT):
                count = text.count(line)
                if count > 1:
                    raise HarnessError(
                        f"{name} scenario profile holds "
                        + repr(line)
                        + f" {count} times, not zero or one"
                    )
        with tempfile.TemporaryDirectory(prefix="ccrt-slave-suite-") as tmp:
            repo = Path(tmp).resolve()
            profiles = []
            source_copies = {}
            path_observations = {}
            for original in PROFILES:
                if original["name"] not in texts:
                    raise HarnessError(f"scenario omits {original['name']}")
                profile = dict(original)
                profile["path"] = repo / profile["rel"]
                profile["path"].parent.mkdir(parents=True, exist_ok=True)
                text = texts[profile["name"]]
                profile["path"].write_text(text, encoding="utf-8")
                source_copies[profile["path"]] = text
                if profile["name"] in observations:
                    path_observations[profile["path"].resolve()] = observations[
                        profile["name"]
                    ]
                profiles.append(profile)

            def injected_compile(parent, root, source_text):
                if not source_text:
                    raise HarnessError(
                        f"{CC} failed with exit 1: empty source "
                        "-- a harness error, not a skip and not a deny"
                    )
                source = Path(parent, "ptyslave.c")
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
                launched.append(os.fspath(kwargs["profile"]))
                self.assertEqual(kwargs["pinned_exe"], kwargs["launch_exe"])
                self.assertEqual(kwargs["timeout"], 5)
                self.assertEqual(tuple(kwargs["args"]), ())
                text = Path(kwargs["profile"]).read_text(encoding="utf-8")
                stdout = path_observations.get(
                    Path(kwargs["profile"]).resolve(), injected_stdout(text),
                )
                return sbx.Result(
                    exit_code=0,
                    stdout=stdout,
                    stderr="",
                    argv=[
                        sbx.SANDBOX_EXEC, "-D",
                        f"PROVIDER_EXECUTABLE={kwargs['pinned_exe']}",
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
                __name__ + ".compile_slave", side_effect=injected_compile
            ), patch(__name__ + ".run_unsandboxed", side_effect=injected_control), patch.object(
                sbx, "run", side_effect=injected_sandbox
            ), patch(__name__ + ".last_change", return_value="a" * 40), patch(
                __name__ + ".pr_label", return_value="PR fixture"
            ), patch.multiple(
                SlaveProbe, binary=None, root=None, parent=None,
                skip_reason=None, recorded_allows={},
            ):
                result = unittest.TestResult()
                unittest.TestLoader().loadTestsFromTestCase(SlaveProbe).run(result)
                yield {
                    "result": result,
                    "launched": launched,
                    "profiles": profiles,
                    "repo": repo,
                    "source_copies": source_copies,
                }

    def _assert_complete_suite(self, probe, allowed, observed_stdout, method_names):
        """The injected ``SlaveProbe`` class stayed green for ``allowed``."""
        result = probe["result"]
        launched = probe["launched"]
        profiles = probe["profiles"]
        repo = probe["repo"]
        self.assertEqual(result.testsRun, len(method_names))
        self.assertEqual(result.errors, [])
        self.assertEqual(result.failures, [])
        self.assertEqual(result.unexpectedSuccesses, [])
        self.assertEqual(result.skipped, [])
        self.assertIsNone(skip_reason())
        self.assertEqual(len(result.expectedFailures), len(allowed))
        self.assertEqual(
            {case._testMethodName for case, _error in result.expectedFailures},
            {f"test_{name}_slave_is_denied" for name in allowed},
        )
        self.assertEqual(
            sorted(
                os.path.basename(path)
                for path in launched
                if path.endswith("-allow.sb")
            ),
            ["did-allow.sb", "model-allow.sb", "wallet-allow.sb"],
        )
        for name, _line in STILL_DENY_EDITS:
            self.assertTrue(
                any(path.endswith(os.sep + name + ".sb") for path in launched),
                name,
            )
        for name, _line in FULL_EDITS + PARTIAL_EDITS:
            self.assertTrue(
                any(path.endswith(os.sep + name + ".sb") for path in launched),
                name,
            )
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(
            SlaveProbe.recorded_allows,
            {name: FINDINGS[name] for name in allowed},
        )
        for name in allowed:
            body = (repo / FINDINGS[name]).read_text(encoding="utf-8")
            profile = next(item for item in profiles if item["name"] == name)
            self.assertIn(f"profile: {profile['rel']}", body)
            self.assertIn(sha256_file(profile["path"]), body)
            self.assertIn("a" * 40, body)
            self.assertIn("PR fixture", body)
            if observed_stdout == PARTIAL_ALLOW:
                self.assertIn("observed: pts " + PARTIAL_ALLOW.strip(), body)
            else:
                self.assertIn("observed: pts and slave ", body)
            self.assertIn("helper: ", body)
            self.assertIn(
                body,
                (repo / "lab/redteam/CRITICAL.md").read_text(encoding="utf-8"),
            )
        if not allowed:
            self.assertFalse((repo / "lab/redteam/CRITICAL.md").exists())
            for rel in set(FINDINGS.values()):
                self.assertFalse((repo / rel).exists())

    def _assert_plant_only_copy(self, probe):
        """The plant without either setup line is the open-fail deny."""
        profiles = probe["profiles"]
        hold = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-slave-hold-"))
        self.addCleanup(shutil.rmtree, hold, ignore_errors=True)
        binary = os.path.join(hold, BINARY_NAME)
        descriptor = os.open(binary, os.O_CREAT | os.O_WRONLY, 0o755)
        os.close(descriptor)
        SlaveProbe.binary = binary
        SlaveProbe.root = hold
        SlaveProbe.parent = hold
        plant_only = os.path.join(hold, "wallet-plant-only.sb")
        plant_text = "(version 1)\n(deny default)\n" + PLANT
        with open(plant_only, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(plant_text)
        self.assertNotIn(FILE_GRANT, plant_text)
        self.assertNotIn(IOCTL_LINE, plant_text)
        self.assertNotEqual(
            plant_text, profiles[0]["path"].read_text(encoding="utf-8")
        )
        self.assertNotEqual(
            os.path.realpath(plant_only),
            os.path.realpath(profiles[0]["path"]),
        )
        denied = require_denied(plant_only)
        self.assertEqual(denied.stdout, OPEN_FAIL)
        self.assertEqual(denied.stderr, "")
        self.assertEqual(denied.exit_code, 0)
        self.assertEqual(classify(denied), "deny")
        for path, text in probe["source_copies"].items():
            self.assertEqual(path.read_text(encoding="utf-8"), text)

    def _run_suite_scenario(self, allowed, added_lines, observed_stdout, method_names):
        """One clean-fixture scenario. The profile file is not an input."""
        texts = scenario_texts(allowed, added_lines)
        observations = {}
        if observed_stdout is not None:
            for name in allowed:
                observations[name] = observed_stdout
        with self._injected_probe_class(texts, observations) as probe:
            self._assert_complete_suite(
                probe, allowed, observed_stdout, method_names,
            )
            self._assert_plant_only_copy(probe)
        self.launch_guard.assert_not_called()

    def test_recorded_allow_keeps_complete_probe_suite_green(self):
        """Run every probe with injected tools and profile text.

        Scenarios use a clean fixture, not the live profile bytes. No added
        lines, and the file-grant line, the ioctl line, and the plant
        together on each profile, keep the suite green. Partial and full
        allows from that clean fixture, or with either or both setup lines,
        also keep the suite green. Only the deny test of a profile whose
        result allows is an expected failure. One wallet copy that contains
        the plant and neither setup line prints the open-fail line, the
        deny check passes, and that copy is not the injected module text.
        The plant still runs, nothing skips, and the result is successful.
        """
        method_names = unittest.TestLoader().getTestCaseNames(SlaveProbe)
        for allowed, added_lines, observed_stdout in suite_scenarios():
            with self.subTest(
                allowed=allowed, added_lines=added_lines, stdout=observed_stdout
            ):
                self._run_suite_scenario(
                    allowed, added_lines, observed_stdout, method_names,
                )

    def test_already_planted_profile_keeps_both_classes_green(self):
        """Both classes stay green when each grant line is already present once.

        A recorded allow whose file holds the file-grant line, the ioctl
        line, and the plant is not an ordinary failure. Copying that file
        and appending the file-grant line again makes ``_assert_source_counts``
        raise ``2 != 1``. Synthetic scenarios do not do that. They start
        from a clean fixture. ``SlaveProbe`` runs on the planted bytes.
        ``SlaveRules`` runs the suite scenarios while those planted files
        are installed, and the scenarios do not read them.
        """
        planted = synthetic_profile(FILE_GRANT + IOCTL_LINE + PLANT)
        self.assertEqual(planted.count(FILE_GRANT), 1)
        self.assertEqual(planted.count(IOCTL_LINE), 1)
        self.assertEqual(planted.count(PLANT), 1)
        self.assertEqual(planted.count(DENY_DEFAULT), 1)
        doubled = planted + FILE_GRANT
        self.assertEqual(doubled.count(FILE_GRANT), 2)
        self.assertEqual(doubled.count(IOCTL_LINE), 1)
        self.assertEqual(doubled.count(PLANT), 1)

        class Counted(SlaveProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        counted = Counted("test_falsifier_allow_slave_is_caught")
        counted._assert_source_counts("wallet", planted)
        with self.assertRaises(AssertionError) as caught:
            counted._assert_source_counts("wallet", doubled)
        self.assertEqual(str(caught.exception), "2 != 1")
        with self.assertRaises(HarnessError) as repeated:
            synthetic_profile(FILE_GRANT + FILE_GRANT)
        repeated_reason = str(repeated.exception)
        self.assertIn(FILE_GRANT.strip(), repeated_reason)
        self.assertIn("2 times, not zero or one", repeated_reason)
        with self.assertRaises(HarnessError) as runner_doubled:
            with self._injected_probe_class({"wallet": doubled}, {}):
                self.fail("doubled grants launched a probe")
        runner_reason = str(runner_doubled.exception)
        self.assertIn("wallet", runner_reason)
        self.assertIn(FILE_GRANT.strip(), runner_reason)
        self.assertIn("2 times, not zero or one", runner_reason)

        suite_source = inspect.getsource(
            SlaveRules.test_recorded_allow_keeps_complete_probe_suite_green
        )
        runner_source = inspect.getsource(SlaveRules._run_suite_scenario)
        self.assertIn("_run_suite_scenario(", suite_source)
        self.assertNotIn("source_texts", suite_source)
        self.assertNotIn("read_text", suite_source)
        self.assertIn("scenario_texts(", runner_source)
        self.assertNotIn("read_text", runner_source)

        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-slave-planted-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        planted_profiles = []
        for original in PROFILES:
            profile = dict(original)
            profile["path"] = Path(directory) / profile["rel"]
            profile["path"].parent.mkdir(parents=True, exist_ok=True)
            profile["path"].write_text(planted, encoding="utf-8")
            planted_profiles.append(profile)
        planted_profiles = tuple(planted_profiles)
        planted_paths = {profile["path"].resolve() for profile in planted_profiles}
        file_texts = {
            profile["name"]: profile["path"].read_text(encoding="utf-8")
            for profile in planted_profiles
        }
        self.assertEqual(file_texts["wallet"], planted)
        self.assertEqual(file_texts["did"], planted)
        self.assertEqual(file_texts["model"], planted)
        method_names = unittest.TestLoader().getTestCaseNames(SlaveProbe)
        live = tuple(PROFILES)
        real_read = Path.read_text

        def guarded_read(path_obj, *args, **kwargs):
            if path_obj.resolve() in planted_paths:
                raise AssertionError(
                    "scenario read a planted profile: " + os.fspath(path_obj)
                )
            return real_read(path_obj, *args, **kwargs)

        try:
            with patch(__name__ + ".PROFILES", planted_profiles), patch.object(
                Path, "read_text", guarded_read
            ):
                with self._injected_probe_class(file_texts, {}) as probe:
                    self._assert_complete_suite(
                        probe, ("wallet", "did", "model"), None, method_names,
                    )
                    self._assert_plant_only_copy(probe)
                for allowed, added, _stdout in suite_scenarios():
                    texts = scenario_texts(allowed, added)
                    for profile in planted_profiles:
                        added_for = added if profile["name"] in allowed else ""
                        built = texts[profile["name"]]
                        self.assertEqual(built, synthetic_profile(added_for))
                        self.assertLessEqual(built.count(FILE_GRANT), 1)
                        self.assertLessEqual(built.count(IOCTL_LINE), 1)
                        self.assertLessEqual(built.count(PLANT), 1)
                        self.assertNotEqual(built, planted + added)
                self._run_suite_scenario(
                    ("wallet",), FILE_GRANT, FULL_ALLOW, method_names,
                )
                self._run_suite_scenario(
                    ("wallet",), IOCTL_LINE, PARTIAL_ALLOW, method_names,
                )
                self._run_suite_scenario(
                    ("wallet", "did", "model"),
                    FILE_GRANT + IOCTL_LINE + PLANT,
                    None,
                    method_names,
                )
                self._run_suite_scenario(
                    ("did",), "", FULL_ALLOW, method_names,
                )
        finally:
            self.assertEqual(tuple(PROFILES), live)
        for profile in planted_profiles:
            self.assertEqual(
                profile["path"].read_text(encoding="utf-8"), planted
            )
        for profile in live:
            changed(
                profile["rel"], START_SHA[profile["rel"]], sha256_file(profile["path"]),
            )
        self.launch_guard.assert_not_called()

    def test_harness_error_stays_error(self):
        """An injected harness error stays an error. It is not a deny, an allow, or a skip."""
        allow = sbx.Result(
            exit_code=0, stdout=FULL_ALLOW, stderr="", argv=["/private/ptyslave"],
        )
        deny = sbx.Result(
            exit_code=0, stdout=OPEN_FAIL, stderr="", argv=["/private/ptyslave"],
        )
        for profile in PROFILES:
            for label, refused, expected in self.refusal_samples():
                with self.subTest(profile=profile["name"], reason=label):
                    class Recorded(SlaveProbe):
                        skip_reason = None

                    def observation(path, profile=profile, allow=allow, deny=deny):
                        return allow if path == profile["path"] else deny

                    with patch(__name__ + ".slave_under", side_effect=observation), patch(
                        __name__ + ".write_findings"
                    ) as writer:
                        observe(Recorded)
                    writer.assert_called_once_with(ROOT, [(profile, allow)])
                    method_name = f"test_{profile['name']}_slave_is_denied"
                    method = getattr(Recorded, method_name)
                    self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
                    self.assertIn(FINDINGS[profile["name"]], method.__doc__)
                    result = unittest.TestResult()
                    try:
                        with patch(
                            __name__ + ".slave_under", side_effect=[refused, deny]
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
            exit_code=2, stdout=OPEN_FAIL, stderr="", argv=["/private/ptyslave"],
        )
        other_fd = sbx.Result(
            exit_code=0,
            stdout=slave_line(5, 0, 1, 0, 1, 0, 1, 0, 4, 0, 1, 0),
            stderr="",
            argv=["/private/ptyslave"],
        )
        profile_error = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout=FULL_ALLOW,
            stderr="Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC],
        )
        for result in (wrong_exit, other_fd, profile_error):
            with self.assertRaises(HarnessError):
                classify(result)

        class Body(unittest.TestCase):
            def test_wallet_slave_is_denied(self):
                classify(wrong_exit)

        body = unittest.TestResult()
        Body("test_wallet_slave_is_denied").run(body)
        self.assertEqual(len(body.errors), 1)
        self.assertEqual(body.failures, [])
        self.assertEqual(body.expectedFailures, [])
        self.assertEqual(body.skipped, [])

        class Setup(unittest.TestCase):
            def setUp(self):
                raise HarnessError("wrong exit 2 is a harness error, not a deny")

            @unittest.expectedFailure
            def test_wallet_slave_is_denied(self):
                raise NotDenied(wrong_exit)

        setup = unittest.TestResult()
        Setup("test_wallet_slave_is_denied").run(setup)
        self.assertEqual(len(setup.errors), 1)
        self.assertEqual(setup.expectedFailures, [])
        self.assertEqual(setup.skipped, [])
        self.assertIn("wrong exit", setup.errors[0][1])
        self.launch_guard.assert_not_called()

    def test_unresolved_storage_path_is_an_error(self):
        """A ``/var/folders`` storage path without ``/private`` errors before launch."""
        bad_parent = "/var/folders/cc/slave-parent"
        bad_root = "/var/folders/cc/slave-root"
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
                compile_slave(
                    bad_parent,
                    "/private/slave-root",
                    "int main(void) { return 0; }\n",
                )
            compile_message = str(compile_caught.exception)
            self.assertIn(bad_parent, compile_message)
            self.assertIn("/var/folders", compile_message)
            self.assertNotIn("/private" + bad_parent, compile_message)

            with self.assertRaises(HarnessError) as launch_caught:
                run_sandboxed(
                    "/private/ptyslave",
                    bad_root,
                    "/private/slave-parent",
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
