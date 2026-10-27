"""Probe grantpt and unlockpt on a pty master.

Grade row 12 rests on the wallet, did, and model seatbelt profiles. The
ptmx file grant opens the master and still leaves ``grantpt`` and
``unlockpt`` denied. This module compiles one helper and runs it under
each live ``confine.sb``. Confined launches go through ``sbx.run`` only.
The helper prints one line and returns 0. It opens one pty master. When
that open fails it does not call ``grantpt`` or ``unlockpt``. When the
open succeeds it calls ``grantpt`` and then ``unlockpt``, and it closes
the master.

A deny is exit 0, empty stderr, and either the open-fail line or the
grant-fail line. An allow is exit 0, empty stderr, ``open fd=3 errno=0``,
and at least one of ``grant`` and ``unlock`` with ``ok=1`` and ``errno=0``.
The full allow is both calls. A partial allow is exactly one of them.

The file-grant line opens the master. It is setup, not the plant. The
plant is the exact line ``(allow file-ioctl (literal "/dev/ptmx"))``.
A bare ``(allow file-ioctl)`` line is not that plant. ``_source_for_plant``
strips one exact plant line and keeps the file-grant line.

The three profiles are the live files. ``setUpModule`` records each sha256.
``tearDownModule`` and the falsifier's end check call ``require_unchanged``,
which compares the digest through ``changed`` from ``test_confine_mach``.
An owner edit between those two points raises ``the probe changed <rel>``.
A difference from an older measurement is not a failure. This file stores
no commit, pull request, or digest.

An allow on a real profile is CRITICAL. Wallet or did:
``findings/CRITICAL-confine-071.md``. Model:
``findings/CRITICAL-cc-model-confine-071.md``. The finding's first line
contains CRITICAL and names the commit from ``git log -1 --format=%H HEAD
-- <file>`` plus the sha256 of the bytes this run read. It names each of
``grant`` and ``unlock`` whose ``ok`` is 1. The same paragraph is appended
to ``CRITICAL.md``. With no allow, this module writes neither file.

A recorded allow keeps the gate green. The deny test is an expected
failure and its docstring names that finding file (README guard b).
Each confirmed allow is written before the next profile is classified.
A later harness error still fails the gate. The plant still runs.
A recorded allow is not a skip. This module skips only when
``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` is missing.
A profile error, a failed compile, a failed unsandboxed control,
nonempty stderr, and an exit other than 0 are harness errors. They are
not a deny and they are not a skip.

``GrantProbe`` compiles and launches. It skips only when
``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` is missing, and the reason
names that path. ``GrantRules`` does not compile and does not launch.
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
SOURCE_NAME = "ptygrant.c"
BINARY_NAME = "ptygrant"
CALLS = ("grant", "unlock")

OPEN_FAIL = "open fd=-1 errno=1 grant ok=-1 errno=0 unlock ok=-1 errno=0\n"
GRANT_FAIL = "open fd=3 errno=0 grant ok=0 errno=1 unlock ok=0 errno=1\n"
FULL_ALLOW = "open fd=3 errno=0 grant ok=1 errno=0 unlock ok=1 errno=0\n"
GRANT_ONLY = "open fd=3 errno=0 grant ok=1 errno=0 unlock ok=0 errno=1\n"
UNLOCK_ONLY = "open fd=3 errno=0 grant ok=0 errno=1 unlock ok=1 errno=0\n"
DENY_LINES = (OPEN_FAIL, GRANT_FAIL)

FILE_GRANT = '(allow file-read* file-write* (literal "/dev/ptmx"))\n'
PLANT_PHRASE = '(allow file-ioctl (literal "/dev/ptmx"))'
PLANT_LINE = PLANT_PHRASE + "\n"
BARE_IOCTL = "(allow file-ioctl)\n"
ALLOW_PSEUDO = "(allow pseudo-tty)\n"
ALLOW_NULL_IOCTL = '(allow file-ioctl (literal "/dev/null"))\n'
DENY_DEFAULT = "(deny default)\n"
MACH_LOOKUP = "(allow mach-lookup)\n"
ALLOW_SCHED = "(allow system-sched)\n"
ALLOW_IOKIT = "(allow iokit-open)\n"
ALLOW_IOKIT_SET = "(allow iokit-set-properties)\n"
ALLOW_FORK = "(allow process-fork)\n"
ALLOW_SIGNAL = "(allow signal)\n"
ALLOW_DEBUG = "(allow system-debug)\n"
ALLOW_SYSCTL = "(allow sysctl-write)\n"
ALLOW_EXTENSION = "(allow file-issue-extension)\n"
DENY_NETWORK = "(deny network*)\n"
ALLOW_NETWORK = "(allow network*)\n"

HELPER_C = r"""#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    int fd;
    int grant_rc;
    int unlock_rc;
    int gerr;
    int uerr;
    errno = 0;
    fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (fd < 0) {
        printf("open fd=-1 errno=%d grant ok=-1 errno=0 unlock ok=-1 errno=0\n", errno);
        return 0;
    }
    errno = 0;
    grant_rc = grantpt(fd);
    gerr = grant_rc == 0 ? 0 : errno;
    errno = 0;
    unlock_rc = unlockpt(fd);
    uerr = unlock_rc == 0 ? 0 : errno;
    printf("open fd=%d errno=0 grant ok=%d errno=%d unlock ok=%d errno=%d\n",
        fd, grant_rc == 0 ? 1 : 0, gerr, unlock_rc == 0 ? 1 : 0, uerr);
    close(fd);
    return 0;
}
"""

FINDINGS = {
    "wallet": "lab/redteam/findings/CRITICAL-confine-071.md",
    "did": "lab/redteam/findings/CRITICAL-confine-071.md",
    "model": "lab/redteam/findings/CRITICAL-cc-model-confine-071.md",
}
IDS = {
    "wallet": "CRITICAL-confine-071",
    "did": "CRITICAL-confine-071",
    "model": "CRITICAL-cc-model-confine-071",
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
    ("wallet-pseudo", ALLOW_PSEUDO),
    ("wallet-null-ioctl", ALLOW_NULL_IOCTL),
    ("wallet-lookup", MACH_LOOKUP),
    ("wallet-sched", ALLOW_SCHED),
    ("wallet-iokit", ALLOW_IOKIT),
    ("wallet-iokit-set", ALLOW_IOKIT_SET),
    ("wallet-fork", ALLOW_FORK),
    ("wallet-signal", ALLOW_SIGNAL),
    ("wallet-debug", ALLOW_DEBUG),
    ("wallet-sysctl", ALLOW_SYSCTL),
    ("wallet-extension", ALLOW_EXTENSION),
    ("wallet-network-append", ALLOW_NETWORK),
    ("wallet-network", "network"),
)
STILL_DENY_COPIES = tuple(stem for stem, _rule in STILL_DENY_RULES)

_LINE = re.compile(
    r"open fd=(-?[0-9]+) errno=(-?[0-9]+) "
    r"grant ok=(-?[0-9]+) errno=(-?[0-9]+) "
    r"unlock ok=(-?[0-9]+) errno=(-?[0-9]+)\n"
)
_FIELDS = (
    "fd",
    "open errno",
    "grant ok",
    "grant errno",
    "unlock ok",
    "unlock errno",
)

START_SHA = {}


def launched_copy_names():
    """Basenames the falsifier launches, in order."""
    names = []
    for profile in PROFILES:
        names.append(profile["name"] + "-allow.sb")
        names.append(profile["name"] + "-file.sb")
        names.append(profile["name"] + "-plant.sb")
    for stem in STILL_DENY_COPIES:
        names.append(stem + ".sb")
    names.append("wallet-bare-ioctl.sb")
    return names


def format_open(fd, open_errno, grant_ok, grant_errno, unlock_ok, unlock_errno):
    """One helper line from the six printed fields."""
    return (
        f"open fd={fd} errno={open_errno} "
        f"grant ok={grant_ok} errno={grant_errno} "
        f"unlock ok={unlock_ok} errno={unlock_errno}\n"
    )


def stdout_for_profile_text(text):
    """The measured line for a profile text. Injection uses this one rule.

    The file grant opens the master and leaves both calls denied. The
    ptmx ioctl plant, or a bare file-ioctl line, beside that grant allows
    both calls. The ioctl line without the file grant leaves the open denied.
    """
    has_file = FILE_GRANT in text
    has_plant = PLANT_LINE in text
    has_bare = BARE_IOCTL in text
    if has_file and (has_plant or has_bare):
        return FULL_ALLOW
    if has_file:
        return GRANT_FAIL
    return OPEN_FAIL


class NotDenied(AssertionError):
    """The profile let ``grantpt`` or ``unlockpt`` succeed."""

    def __init__(self, result):
        self.result = result
        named = ", ".join(allowed_names(result.stdout))
        super().__init__(
            "ALLOW: grantpt or unlockpt succeeded under the profile.\n"
            f"  allowed: {named}\n"
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
    """``(fd, open_errno, calls)`` or None when the line is not that shape.

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
    calls = (
        ("grant", int(groups[2]), int(groups[3])),
        ("unlock", int(groups[4]), int(groups[5])),
    )
    return int(groups[0]), int(groups[1]), calls


def _call_problem(name, ok, errno, fd):
    """The harness reason for one call, or None when the pair can be deny or allow."""
    if ok not in (-1, 0, 1):
        return (
            f"{name} ok other than -1, 0, or 1 is a harness error, "
            "not a deny and not an allow"
        )
    if fd == 3 and ok == -1:
        return (
            f"{name} ok=-1 after open fd=3 is a harness error, "
            "not a deny and not an allow"
        )
    if ok == 1 and errno != 0:
        return (
            f"{name} ok=1 with errno other than 0 is a harness error, not an allow"
        )
    if ok == 0 and errno != 1:
        return (
            f"{name} ok=0 with errno other than 1 is a harness error, not a deny"
        )
    if ok == -1 and errno != 0:
        return (
            f"{name} ok=-1 with errno other than 0 is a harness error, not a deny"
        )
    return None


def decision(stdout):
    """``(deny, ())`` or ``(allow, names)``. A bad line raises.

    Names are ``grant`` and ``unlock`` whose ok is 1, in helper order.
    Only the open-fail line and the grant-fail line are denies.
    """
    parsed = parse_line(stdout)
    if parsed is None:
        raise HarnessError(
            "malformed stdout is a harness error, not a deny and not an allow: "
            + repr(stdout)
        )
    fd, open_errno, calls = parsed
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
    allowed = []
    for name, ok, errno in calls:
        reason = _call_problem(name, ok, errno, fd)
        if reason is not None:
            raise HarnessError(reason + ": " + repr(stdout))
        if ok == 1:
            allowed.append(name)
    if fd == -1:
        if allowed or any(ok != -1 or errno != 0 for _name, ok, errno in calls):
            raise HarnessError(
                "fd=-1 stdout is not the open-fail deny: " + repr(stdout)
            )
        return "deny", ()
    if not allowed:
        return "deny", ()
    return "allow", tuple(allowed)


def allowed_names(stdout):
    """Calls whose ok is 1, in helper order."""
    kind, names = decision(stdout)
    if kind != "allow":
        raise HarnessError("finding stdout is not an allow: " + repr(stdout))
    if not names:
        raise HarnessError("finding names no call")
    return names


def allowed_phrase(names):
    """Every allowed call, in helper order, on one finding line."""
    parts = list(names)
    if parts == ["grant", "unlock"]:
        return "grant and unlock"
    if parts == ["grant"] or parts == ["unlock"]:
        return parts[0]
    raise HarnessError("finding names no call")


def classify(result):
    """``deny`` or ``allow``. Otherwise a harness error.

    Asks ``sbx.profile_error`` before it reads a deny or an allow. Exit 65
    is a profile error even when stderr says ``Operation not permitted``.
    A partial allow names the call whose ok is 1.
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
        try:
            kind, _names = decision(result.stdout)
        except HarnessError:
            kind = None
        if kind == "allow":
            raise HarnessError(
                "nonempty allow stderr is a harness error, not an allow: "
                + repr(result.stderr)
            )
        raise HarnessError(
            "nonempty stderr is a harness error, not a deny and not an allow: "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    kind, _names = decision(result.stdout)
    return kind


def compile_grant(parent, root, source_text):
    """Compile ``source_text`` with ``/usr/bin/cc`` into ``<root>/ptygrant``.

    The source file sits in ``parent``. The command is ``/usr/bin/cc -o
    <root>/ptygrant <parent>/ptygrant.c``. No extra framework. This does
    not start ``sandbox-exec``. A nonzero exit, stderr on exit 0, or a
    missing executable is a harness error, not a skip.
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


def grant_under(profile):
    """Run the compiled helper under ``profile``. Pass no argv."""
    binary = GrantProbe.binary
    root = GrantProbe.root
    parent = GrantProbe.parent
    if not binary or not root or not parent:
        raise HarnessError("the grantpt helper is not compiled")
    return run_sandboxed(binary, root, parent, profile)


def require_unsandboxed_allow(result):
    """The unsandboxed control must be the full allow line.

    A deny, a partial allow, a bad exit, stderr, or a malformed line is a
    harness error. An ordinary assertion is not this check.
    """
    if result.argv and os.fspath(result.argv[0]) == sbx.SANDBOX_EXEC:
        raise HarnessError(
            "unsandboxed control started sandbox-exec: " + repr(result.argv)
        )
    outcome = classify(result)
    if outcome == "deny":
        if result.stdout == OPEN_FAIL:
            raise HarnessError(
                "unsandboxed open deny is a harness error, not a passing control: "
                + repr(result.stdout)
            )
        raise HarnessError(
            "unsandboxed grant deny is a harness error, not a passing control: "
            + repr(result.stdout)
        )
    if result.stdout == GRANT_ONLY:
        raise HarnessError(
            "unsandboxed partial grant is a harness error, not a passing control: "
            + repr(result.stdout)
        )
    if result.stdout == UNLOCK_ONLY:
        raise HarnessError(
            "unsandboxed partial unlock is a harness error, not a passing control: "
            + repr(result.stdout)
        )
    if result.stdout != FULL_ALLOW:
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
    """The one helper. ``profile`` must deny ``grantpt`` and ``unlockpt``.

    The three real-file tests and the plant call this. An allow raises
    ``NotDenied``. A harness error propagates and is not a deny.
    """
    result = grant_under(profile)
    if classify(result) != "deny":
        raise NotDenied(result)
    return result


def ensure_trailing_newline(text):
    if text.endswith("\n"):
        return text
    return text + "\n"


def with_file_grant(text):
    """Append the file-grant line. That line opens the master and is not the plant."""
    return ensure_trailing_newline(text) + FILE_GRANT


def ensure_file_grant(text):
    """The text with the file-grant line present once.

    A recorded baseline already has the line. A clean baseline does not.
    """
    if FILE_GRANT in text:
        return text
    return with_file_grant(text)


def with_file_and_plant(text):
    """Append the file grant and then the plant. Both together are the full allow."""
    return ensure_trailing_newline(text) + FILE_GRANT + PLANT_LINE


def plant_only_text(text):
    """The ioctl plant on a copy whose file grant has been removed.

    A recorded baseline still has the file grant. Leaving it in place would
    allow both calls instead of failing the open.
    """
    base = text.replace(FILE_GRANT, "")
    planted = ensure_trailing_newline(base) + PLANT_LINE
    if FILE_GRANT in planted:
        raise HarnessError("plant-only copy still has the file grant")
    return planted


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


def still_deny_text(seat, kind):
    """One wallet edit that keeps the file grant and is not the plant."""
    if FILE_GRANT not in seat:
        raise HarnessError("still-deny copy has no file grant")
    if kind == "delete":
        return without_deny_default(seat)
    if kind == "network":
        return with_network_allow(seat)
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
    is stored in this file. ``allowed`` names every call whose ok is 1.
    The helper line is ``result.command``.
    """
    commit = last_change(profile["path"])
    digest = sha256_file(profile["path"])
    names = allowed_names(result.stdout)
    return (
        f"CRITICAL {IDS[profile['name']]} {commit} {pr_label(commit)} "
        f"sha256 {digest}\n"
        f"profile: {profile['rel']}\n"
        f"allowed: {allowed_phrase(names)}\n"
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
        "The live profile allowed grantpt or unlockpt. "
        f"Finding file: {finding_rel}"
    )
    wrapped = unittest.expectedFailure(recorded)
    setattr(case_cls, method_name, wrapped)
    case_cls.addClassCleanup(setattr, case_cls, method_name, method)


def observe(case_cls):
    """Classify each live profile. Record each allow before the next profile.

    A later harness error still propagates. Allows already confirmed stay
    written and marked. A refusal before any allow writes nothing.
    An open that fails is the clean deny, not a finding.
    """
    case_cls.recorded_allows = {}
    confirmed = []
    for profile in PROFILES:
        result = grant_under(profile["path"])
        outcome = classify(result)
        if outcome != "allow":
            continue
        confirmed.append((profile, result))
        # Snapshot: a later append must not change the list this call recorded.
        write_findings(ROOT, list(confirmed))
        case_cls.recorded_allows[profile["name"]] = FINDINGS[profile["name"]]
        mark_expected(
            case_cls,
            f"test_{profile['name']}_grantpt_is_denied",
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


class GrantProbe(unittest.TestCase):
    """The helper under the live profiles, and the ioctl plant."""

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
        cls.parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptygrant-parent-"))
        cls.root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptygrant-root-"))
        cls.addClassCleanup(shutil.rmtree, cls.parent, ignore_errors=True)
        cls.addClassCleanup(shutil.rmtree, cls.root, ignore_errors=True)
        cls.binary = compile_grant(cls.parent, cls.root, HELPER_C)
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

    def test_unsandboxed_grantpt_succeeds(self):
        """Without ``sandbox-exec``, the helper exits 0 and both calls succeed.

        Stderr is empty. Stdout is the full allow line. A failure here is a
        harness error, so a later deny is about the profile.
        """
        source = os.path.join(self.parent, SOURCE_NAME)
        self.assertEqual(Path(source).read_text(encoding="utf-8"), HELPER_C)
        self.assertIn("posix_openpt", HELPER_C)
        self.assertIn("grantpt", HELPER_C)
        self.assertIn("unlockpt", HELPER_C)
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
        self.assertEqual(allowed_names(result.stdout), CALLS)

    def test_compile_failure_is_an_error(self):
        """``/usr/bin/cc`` on an empty source is a harness error, not a skip."""
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptygrant-empty-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptygrant-empty-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with self.assertRaises(HarnessError) as caught:
            compile_grant(parent, root, "")
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

    def test_wallet_grantpt_is_denied(self):
        """The real wallet profile denies the open, so grantpt is not called."""
        self._expect_real_deny(sbx.WALLET_CONFINE_SB)

    def test_did_grantpt_is_denied(self):
        """The real did profile denies the open, so grantpt is not called."""
        did = sbx.REPO_ROOT / "capsules/did-provider/confine.sb"
        self._expect_real_deny(did)

    def test_model_grantpt_is_denied(self):
        """The real model profile denies the open. The helper starts under it."""
        model = sbx.REPO_ROOT / "capsules/model-provider/confine.sb"
        self._expect_real_deny(model)

    def _expect_allow_copy(self, profile, copy):
        with self.assertRaises(NotDenied) as caught:
            require_denied(copy)
        result = caught.exception.result
        self.assertIn("ALLOW", str(caught.exception))
        self.assertIsNone(sbx.profile_error(result))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, FULL_ALLOW)
        self.assertEqual(classify(result), "allow")
        self.assertEqual(allowed_names(result.stdout), CALLS)
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

    def test_falsifier_allow_pty_ioctl_is_caught(self):
        """The ptmx ioctl plant beside the file grant allows both calls.

        The zero-count reads the plant baseline from ``_source_for_plant``.
        Clean input has the plant line and the file-grant line zero times.
        Recorded input that already contains the file-grant line keeps that
        one line; the plant line is stripped and is not counted. ``(deny
        default)`` occurs once. A temp copy that appends both lines prints
        the full allow line, and the helper pointed at the copy fails the
        deny check. A temp copy that appends only the file grant prints the
        grant-fail line. A temp copy of the baseline with the file grant
        removed, plus only the plant, prints the open-fail line. One wallet
        copy for each still-deny edit, with the file grant present, still
        prints the grant-fail line. A bare file-ioctl line beside the file
        grant prints the full allow line and is not the plant. The repo
        profile bytes stay unchanged.
        """
        before = {
            profile["rel"]: sha256_file(profile["path"]) for profile in PROFILES
        }
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptygrant-profile-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        try:
            for profile in PROFILES:
                with self.subTest(profile=profile["name"]):
                    text = profile["path"].read_text(encoding="utf-8")
                    baseline = self._source_for_plant(profile["name"], text)
                    self.assertEqual(text.count(DENY_DEFAULT), 1)
                    self.assertEqual(baseline.count(DENY_DEFAULT), 1)
                    self.assertEqual(baseline.count(PLANT_LINE), 0)
                    self.assertEqual(baseline.count(PLANT_PHRASE), 0)
                    self.assertNotEqual(PLANT_LINE, BARE_IOCTL)
                    self.assertNotIn(BARE_IOCTL, PLANT_LINE)
                    self.assertNotIn(PLANT_LINE, BARE_IOCTL)
                    self.assertNotIn(PLANT_PHRASE, FILE_GRANT)
                    if profile["name"] in type(self).recorded_allows and PLANT_LINE in text:
                        self.assertEqual(text.count(PLANT_LINE), 1)
                        self.assertEqual(text.count(FILE_GRANT), 1)
                        self.assertEqual(baseline.count(FILE_GRANT), 1)
                        self.assertNotEqual(baseline, text)
                    elif profile["name"] not in type(self).recorded_allows:
                        self.assertEqual(text.count(FILE_GRANT), 0)
                        self.assertEqual(text.count(PLANT_LINE), 0)
                        self.assertEqual(text.count(PLANT_PHRASE), 0)
                        self.assertEqual(baseline.count(FILE_GRANT), 0)
                        self.assertEqual(baseline, text)
                    else:
                        self.assertEqual(
                            baseline.count(FILE_GRANT), text.count(FILE_GRANT)
                        )
                    self.assertTrue(baseline.endswith("\n"))

                    planted = with_file_and_plant(baseline)
                    self.assertEqual(
                        planted.count(FILE_GRANT), baseline.count(FILE_GRANT) + 1
                    )
                    self.assertEqual(planted.count(PLANT_LINE), 1)
                    self.assertEqual(planted.count(DENY_DEFAULT), 1)
                    copy = write_copy(directory, profile["name"] + "-allow", planted)
                    self.assertEqual(Path(copy).read_text(encoding="utf-8"), planted)
                    self.assertNotEqual(
                        os.path.realpath(copy), os.path.realpath(profile["path"])
                    )
                    self._expect_allow_copy(profile, copy)

                    file_only = with_file_grant(baseline)
                    self.assertEqual(file_only.count(PLANT_LINE), 0)
                    self.assertNotIn(PLANT_PHRASE, file_only[len(baseline):])
                    file_copy = write_copy(directory, profile["name"] + "-file", file_only)
                    self._expect_deny_copy(profile, file_copy, GRANT_FAIL)

                    only_plant = plant_only_text(baseline)
                    self.assertEqual(only_plant.count(FILE_GRANT), 0)
                    self.assertEqual(only_plant.count(PLANT_LINE), 1)
                    self.assertNotIn(FILE_GRANT, only_plant)
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
            seat = ensure_file_grant(baseline)
            self.assertEqual(seat.count(FILE_GRANT), 1)
            self.assertEqual(seat.count(PLANT_LINE), 0)
            self.assertEqual(seat.count(DENY_DEFAULT), 1)
            self.assertEqual(baseline.count(PLANT_LINE), 0)

            for stem, kind in STILL_DENY_RULES:
                with self.subTest(profile=stem):
                    edited = still_deny_text(seat, kind)
                    self.assertEqual(edited.count(FILE_GRANT), 1)
                    self.assertEqual(edited.count(PLANT_LINE), 0)
                    self.assertNotIn(PLANT_PHRASE, edited)
                    self.assertNotIn(BARE_IOCTL, edited)
                    if kind == "delete":
                        self.assertNotIn("(deny default)", edited)
                        self.assertEqual(edited.count(DENY_NETWORK), seat.count(DENY_NETWORK))
                        self.assertNotIn("(allow default)", edited)
                    elif kind == "network":
                        self.assertEqual(edited.count(DENY_NETWORK), 0)
                        self.assertEqual(
                            edited.count(ALLOW_NETWORK),
                            seat.count(ALLOW_NETWORK) + 1,
                        )
                        self.assertEqual(edited.count(DENY_DEFAULT), 1)
                    else:
                        self.assertEqual(edited.count(kind), seat.count(kind) + 1)
                        self.assertEqual(edited.count(DENY_DEFAULT), 1)
                        if kind == ALLOW_NETWORK:
                            self.assertEqual(edited.count(DENY_NETWORK), 1)
                    copy = write_copy(directory, stem, edited)
                    self.assertEqual(Path(copy).read_text(encoding="utf-8"), edited)
                    self.assertNotEqual(
                        os.path.realpath(copy), os.path.realpath(wallet["path"])
                    )
                    self._expect_deny_copy(wallet, copy, GRANT_FAIL)

            with self.subTest(profile="wallet-bare-ioctl"):
                bare = ensure_trailing_newline(seat) + BARE_IOCTL
                self.assertEqual(bare.count(FILE_GRANT), 1)
                self.assertEqual(bare.count(PLANT_LINE), 0)
                self.assertEqual(bare.count(PLANT_PHRASE), 0)
                self.assertEqual(bare.count(BARE_IOCTL), 1)
                self.assertNotEqual(BARE_IOCTL, PLANT_LINE)
                copy = write_copy(directory, "wallet-bare-ioctl", bare)
                self._expect_allow_copy(wallet, copy)
            self.assertEqual(wallet["path"].read_text(encoding="utf-8"), wallet_text)
        finally:
            require_unchanged(before)

    def _source_for_plant(self, name, text):
        """The text the temp plant edits. A recorded allow does not skip this.

        The deny test carries the finding-linked expected failure. The live
        file is not edited. One exact plant line is removed from the copy
        so the append is still that one line. The file-grant line stays.
        A plant phrase with no trailing newline is its own harness error.
        A bare file-ioctl line is not the plant line.
        """
        finding = type(self).recorded_allows.get(name)
        if finding is None:
            if PLANT_PHRASE in text:
                raise AssertionError(f"{name} source contains {PLANT_PHRASE}")
            return text
        method = getattr(type(self), f"test_{name}_grantpt_is_denied")
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
        if PLANT_PHRASE in text:
            raise HarnessError(f"{name} plant line has no trailing newline")
        return text


class GrantRules(unittest.TestCase):
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
        probe_names = unittest.defaultTestLoader.getTestCaseNames(GrantProbe)
        for missing in ((sbx.SANDBOX_EXEC,), (CC,), (sbx.SANDBOX_EXEC, CC)):
            with self.subTest(missing=missing), patch.object(
                os.path, "isfile", side_effect=lambda path: path not in missing
            ), patch(
                __name__ + ".compile_grant",
                side_effect=AssertionError("missing-tool probe compiled a helper"),
            ) as compiled, patch.object(
                sbx, "run",
                side_effect=AssertionError("missing-tool probe launched a helper"),
            ) as launched:
                class MissingTools(GrantProbe):
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
        The file-grant line stays when the plant line is stripped. A recorded
        allow without that mark, a docstring that omits the finding, and a
        second plant line are each their own harness error. A bare file-ioctl
        line is not the plant.
        """
        with patch.object(os.path, "isfile", return_value=True):
            self.assertIsNone(skip_reason())
            self.assertTrue(os.path.isfile(CC))
            self.assertTrue(os.path.isfile(sbx.SANDBOX_EXEC))
        clean = "(version 1)\n(deny default)\n"
        recorded_text = clean + FILE_GRANT + PLANT_LINE
        bare_text = clean + FILE_GRANT + BARE_IOCTL

        class Recorded(GrantProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Recorded, "test_wallet_grantpt_is_denied", FINDINGS["wallet"])
        try:
            case = Recorded("test_falsifier_allow_pty_ioctl_is_caught")
            baseline = case._source_for_plant("wallet", recorded_text)
            self.assertEqual(baseline, clean + FILE_GRANT)
            self.assertEqual(baseline.count(FILE_GRANT), 1)
            self.assertEqual(baseline.count(PLANT_LINE), 0)
            self.assertEqual(
                case._source_for_plant("wallet", clean + FILE_GRANT + FILE_GRANT + PLANT_LINE),
                clean + FILE_GRANT + FILE_GRANT,
            )
            self.assertEqual(
                case._source_for_plant("wallet", recorded_text + BARE_IOCTL),
                clean + FILE_GRANT + BARE_IOCTL,
            )
            self.assertEqual(case._source_for_plant("did", clean), clean)
            self.assertNotIsInstance(baseline, type(unittest.SkipTest("x")))
        finally:
            Recorded.doClassCleanups()

        class Bare(GrantProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        bare = Bare("test_falsifier_allow_pty_ioctl_is_caught")
        with self.assertRaises(HarnessError) as unmarked:
            bare._source_for_plant("wallet", recorded_text)
        self.assertEqual(
            str(unmarked.exception),
            "wallet allow has no finding-linked expected failure",
        )
        self.assertNotIsInstance(unmarked.exception, unittest.SkipTest)

        class WrongDoc(GrantProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        def body(self):
            raise NotDenied(
                sbx.Result(exit_code=0, stdout=FULL_ALLOW, stderr="", argv=[])
            )

        body.__doc__ = "plain"
        body.__unittest_expecting_failure__ = True
        WrongDoc.test_wallet_grantpt_is_denied = body
        wrong = WrongDoc("test_falsifier_allow_pty_ioctl_is_caught")
        with self.assertRaises(HarnessError) as unnamed:
            wrong._source_for_plant("wallet", recorded_text)
        self.assertEqual(
            str(unnamed.exception),
            f"wallet allow docstring does not name {FINDINGS['wallet']}",
        )

        class Twice(GrantProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Twice, "test_wallet_grantpt_is_denied", FINDINGS["wallet"])
        try:
            twice = Twice("test_falsifier_allow_pty_ioctl_is_caught")
            with self.assertRaises(HarnessError) as extra:
                twice._source_for_plant("wallet", recorded_text + PLANT_LINE)
            self.assertEqual(
                str(extra.exception),
                f"{PLANT_PHRASE} occurs 2 times, not zero or one",
            )
        finally:
            Twice.doClassCleanups()

        class BareLine(GrantProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(BareLine, "test_wallet_grantpt_is_denied", FINDINGS["wallet"])
        try:
            bare_line = BareLine("test_falsifier_allow_pty_ioctl_is_caught")
            missing_newline = "wallet plant line has no trailing newline"
            with self.assertRaises(HarnessError) as bare_phrase:
                bare_line._source_for_plant("wallet", clean + PLANT_PHRASE)
            self.assertEqual(str(bare_phrase.exception), missing_newline)
            with self.assertRaises(HarnessError) as mixed:
                bare_line._source_for_plant(
                    "wallet", clean + FILE_GRANT + PLANT_LINE + PLANT_PHRASE
                )
            self.assertEqual(str(mixed.exception), missing_newline)
        finally:
            BareLine.doClassCleanups()

        class Clean(GrantProbe):
            recorded_allows = {}

        plain = Clean("test_falsifier_allow_pty_ioctl_is_caught")
        with self.assertRaises(AssertionError) as present:
            plain._source_for_plant("wallet", recorded_text)
        self.assertEqual(
            str(present.exception),
            f"wallet source contains {PLANT_PHRASE}",
        )
        self.assertEqual(plain._source_for_plant("wallet", clean), clean)
        self.assertEqual(plain._source_for_plant("wallet", clean + FILE_GRANT), clean + FILE_GRANT)
        self.assertEqual(plain._source_for_plant("wallet", bare_text), bare_text)
        self.assertEqual(plain._source_for_plant("wallet", clean + BARE_IOCTL), clean + BARE_IOCTL)
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

        rel = "tmp/ptygrant-confine.sb"
        self.assertNotIn(rel, START_SHA)
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptygrant-byte-"))
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
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptygrant-cc-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptygrant-cc-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        binary = os.path.join(root, BINARY_NAME)
        source = "int main(void) { return 0; }\n"
        reasons = []

        def compiled(completed, access=None):
            runners = patch.object(subprocess, "run", return_value=completed)
            if access is None:
                with runners:
                    return compile_grant(parent, root, source)
            with runners, patch.object(os, "access", return_value=access):
                return compile_grant(parent, root, source)

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
            ("parent", "/var/folders/cc/ptygrant-parent", root),
            ("root", parent, "/var/folders/cc/ptygrant-root"),
        ):
            bad = compile_parent if label == "parent" else compile_root
            expected = (
                f"execvp: {bad} contains /var/folders without the /private prefix"
            )
            with self.subTest(path=label), patch.object(
                subprocess, "run", side_effect=refuse_cc
            ):
                with self.assertRaises(HarnessError) as caught:
                    compile_grant(compile_parent, compile_root, source)
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
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptygrant-bytes-"))
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

            class Plant(GrantProbe):
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
                    argv=[sbx.SANDBOX_EXEC, "-f", profile, "/private/ptygrant"],
                )
                if state["mutate"] and profile.endswith(os.sep + "wallet-deleted.sb"):
                    wallet["path"].write_bytes(after_bytes)
                if stdout == FULL_ALLOW:
                    raise NotDenied(result)
                return result

            case = Plant("test_falsifier_allow_pty_ioctl_is_caught")
            try:
                with patch(__name__ + ".PROFILES", profiles), patch(
                    __name__ + ".require_denied", new=fake_denied
                ), patch(__name__ + ".changed", new=spy):
                    with self.subTest(path="falsifier-equal"):
                        seen.clear()
                        state["mutate"] = False
                        case.test_falsifier_allow_pty_ioctl_is_caught()
                        self.assertEqual(seen, equal_pairs)
                    with self.subTest(path="falsifier-changed"):
                        seen.clear()
                        state["mutate"] = True
                        wallet["path"].write_bytes(clean)
                        with self.assertRaises(AssertionError) as caught:
                            case.test_falsifier_allow_pty_ioctl_is_caught()
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

        other_fd = format_open(4, 0, 0, 1, 0, 1)
        wrong_open = format_open(-1, 2, -1, 0, -1, 0)
        bad_open_fd3 = format_open(3, 1, 0, 1, 0, 1)
        grant_ok = format_open(3, 0, 2, 0, 0, 1)
        unlock_ok = format_open(3, 0, 0, 1, 2, 0)
        grant_errno = format_open(3, 0, 1, 2, 0, 1)
        unlock_errno = format_open(3, 0, 0, 1, 1, 2)
        grant_zero = format_open(3, 0, 0, 2, 0, 1)
        unlock_zero = format_open(3, 0, 0, 1, 0, 2)
        grant_absent = format_open(3, 0, -1, 0, 0, 1)
        unlock_absent = format_open(3, 0, 0, 1, -1, 0)
        grant_absent_errno = format_open(-1, 1, -1, 2, -1, 0)
        unlock_absent_errno = format_open(-1, 1, -1, 0, -1, 2)
        called_on_open_fail = format_open(-1, 1, 0, 1, -1, 0)
        malformed = "open nope\n"
        padded_fd = format_open("03", 0, 0, 1, 0, 1)
        padded_open = format_open(-1, "01", -1, 0, -1, 0)
        padded_grant_ok = format_open(3, 0, "01", 0, 0, 1)
        padded_grant_errno = format_open(3, 0, 0, "01", 0, 1)
        padded_unlock_ok = format_open(3, 0, 0, 1, "01", 0)
        padded_unlock_errno = format_open(3, 0, 0, 1, 0, "01")

        return (
            (
                "wrong exit",
                sbx.Result(
                    exit_code=2, stdout=OPEN_FAIL, stderr="", argv=["/private/ptygrant"],
                ),
                "wrong exit 2 is a harness error, not a deny and not an allow. "
                f"stdout={OPEN_FAIL!r} stderr=''",
            ),
            (
                "fd other than -1 or 3",
                sbx.Result(
                    exit_code=0, stdout=other_fd, stderr="", argv=["/private/ptygrant"],
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
                    exit_code=0, stdout=wrong_open, stderr="", argv=["/private/ptygrant"],
                ),
                described(
                    "open errno other than 1 on fd=-1 is a harness error, "
                    "not a deny and not an allow",
                    wrong_open,
                ),
            ),
            (
                "open errno other than 0 on fd 3",
                sbx.Result(
                    exit_code=0, stdout=bad_open_fd3, stderr="", argv=["/private/ptygrant"],
                ),
                described(
                    "open errno other than 0 on fd 3 is a harness error, "
                    "not a deny and not an allow",
                    bad_open_fd3,
                ),
            ),
            (
                "grant ok other than -1, 0, or 1",
                sbx.Result(
                    exit_code=0, stdout=grant_ok, stderr="", argv=["/private/ptygrant"],
                ),
                described(
                    "grant ok other than -1, 0, or 1 is a harness error, "
                    "not a deny and not an allow",
                    grant_ok,
                ),
            ),
            (
                "unlock ok other than -1, 0, or 1",
                sbx.Result(
                    exit_code=0, stdout=unlock_ok, stderr="", argv=["/private/ptygrant"],
                ),
                described(
                    "unlock ok other than -1, 0, or 1 is a harness error, "
                    "not a deny and not an allow",
                    unlock_ok,
                ),
            ),
            (
                "grant ok=1 with errno other than 0",
                sbx.Result(
                    exit_code=0, stdout=grant_errno, stderr="", argv=["/private/ptygrant"],
                ),
                described(
                    "grant ok=1 with errno other than 0 is a harness error, not an allow",
                    grant_errno,
                ),
            ),
            (
                "unlock ok=1 with errno other than 0",
                sbx.Result(
                    exit_code=0, stdout=unlock_errno, stderr="", argv=["/private/ptygrant"],
                ),
                described(
                    "unlock ok=1 with errno other than 0 is a harness error, not an allow",
                    unlock_errno,
                ),
            ),
            (
                "grant ok=0 with errno other than 1",
                sbx.Result(
                    exit_code=0, stdout=grant_zero, stderr="", argv=["/private/ptygrant"],
                ),
                described(
                    "grant ok=0 with errno other than 1 is a harness error, not a deny",
                    grant_zero,
                ),
            ),
            (
                "unlock ok=0 with errno other than 1",
                sbx.Result(
                    exit_code=0, stdout=unlock_zero, stderr="", argv=["/private/ptygrant"],
                ),
                described(
                    "unlock ok=0 with errno other than 1 is a harness error, not a deny",
                    unlock_zero,
                ),
            ),
            (
                "grant ok=-1 after open fd=3",
                sbx.Result(
                    exit_code=0, stdout=grant_absent, stderr="", argv=["/private/ptygrant"],
                ),
                described(
                    "grant ok=-1 after open fd=3 is a harness error, "
                    "not a deny and not an allow",
                    grant_absent,
                ),
            ),
            (
                "unlock ok=-1 after open fd=3",
                sbx.Result(
                    exit_code=0, stdout=unlock_absent, stderr="", argv=["/private/ptygrant"],
                ),
                described(
                    "unlock ok=-1 after open fd=3 is a harness error, "
                    "not a deny and not an allow",
                    unlock_absent,
                ),
            ),
            (
                "grant ok=-1 with errno other than 0",
                sbx.Result(
                    exit_code=0,
                    stdout=grant_absent_errno,
                    stderr="",
                    argv=["/private/ptygrant"],
                ),
                described(
                    "grant ok=-1 with errno other than 0 is a harness error, not a deny",
                    grant_absent_errno,
                ),
            ),
            (
                "unlock ok=-1 with errno other than 0",
                sbx.Result(
                    exit_code=0,
                    stdout=unlock_absent_errno,
                    stderr="",
                    argv=["/private/ptygrant"],
                ),
                described(
                    "unlock ok=-1 with errno other than 0 is a harness error, not a deny",
                    unlock_absent_errno,
                ),
            ),
            (
                "fd=-1 stdout is not the open-fail deny",
                sbx.Result(
                    exit_code=0,
                    stdout=called_on_open_fail,
                    stderr="",
                    argv=["/private/ptygrant"],
                ),
                described(
                    "fd=-1 stdout is not the open-fail deny",
                    called_on_open_fail,
                ),
            ),
            (
                "noncanonical fd",
                sbx.Result(
                    exit_code=0, stdout=padded_fd, stderr="", argv=["/private/ptygrant"],
                ),
                described(
                    "noncanonical fd integer '03' is a harness error, "
                    "not a deny and not an allow",
                    padded_fd,
                ),
            ),
            (
                "noncanonical open errno",
                sbx.Result(
                    exit_code=0, stdout=padded_open, stderr="", argv=["/private/ptygrant"],
                ),
                described(
                    "noncanonical open errno integer '01' is a harness error, "
                    "not a deny and not an allow",
                    padded_open,
                ),
            ),
            (
                "noncanonical grant ok",
                sbx.Result(
                    exit_code=0,
                    stdout=padded_grant_ok,
                    stderr="",
                    argv=["/private/ptygrant"],
                ),
                described(
                    "noncanonical grant ok integer '01' is a harness error, "
                    "not a deny and not an allow",
                    padded_grant_ok,
                ),
            ),
            (
                "noncanonical grant errno",
                sbx.Result(
                    exit_code=0,
                    stdout=padded_grant_errno,
                    stderr="",
                    argv=["/private/ptygrant"],
                ),
                described(
                    "noncanonical grant errno integer '01' is a harness error, "
                    "not a deny and not an allow",
                    padded_grant_errno,
                ),
            ),
            (
                "noncanonical unlock ok",
                sbx.Result(
                    exit_code=0,
                    stdout=padded_unlock_ok,
                    stderr="",
                    argv=["/private/ptygrant"],
                ),
                described(
                    "noncanonical unlock ok integer '01' is a harness error, "
                    "not a deny and not an allow",
                    padded_unlock_ok,
                ),
            ),
            (
                "noncanonical unlock errno",
                sbx.Result(
                    exit_code=0,
                    stdout=padded_unlock_errno,
                    stderr="",
                    argv=["/private/ptygrant"],
                ),
                described(
                    "noncanonical unlock errno integer '01' is a harness error, "
                    "not a deny and not an allow",
                    padded_unlock_errno,
                ),
            ),
            (
                "nonempty deny stderr",
                sbx.Result(
                    exit_code=0,
                    stdout=OPEN_FAIL,
                    stderr="noise\n",
                    argv=["/private/ptygrant"],
                ),
                "nonempty deny stderr is a harness error, not a deny: " + repr("noise\n"),
            ),
            (
                "nonempty allow stderr",
                sbx.Result(
                    exit_code=0,
                    stdout=FULL_ALLOW,
                    stderr="noise\n",
                    argv=["/private/ptygrant"],
                ),
                "nonempty allow stderr is a harness error, not an allow: " + repr("noise\n"),
            ),
            (
                "malformed stdout",
                sbx.Result(
                    exit_code=0, stdout=malformed, stderr="", argv=["/private/ptygrant"],
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
                    argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/ptygrant"],
                ),
                "profile error: profile read or compile error: sandbox-exec exited 65 "
                "and started no program, so nothing was denied -- a harness error, "
                "not a deny and not an allow. stderr='Operation not permitted\\n'",
            ),
        )

    def test_classifier_refusal_reasons(self):
        """Each classifier refusal preserves its exact, distinct reason.

        These results are built here. Nothing is launched. Exit 65 stays a
        profile error when stderr says ``Operation not permitted``. ``fd=3``
        with ``ok=-1`` is its own reason for ``grant`` and for ``unlock``.
        """
        self.assertEqual(format_open(-1, 1, -1, 0, -1, 0), OPEN_FAIL)
        self.assertEqual(format_open(3, 0, 0, 1, 0, 1), GRANT_FAIL)
        self.assertEqual(format_open(3, 0, 1, 0, 1, 0), FULL_ALLOW)
        self.assertEqual(format_open(3, 0, 1, 0, 0, 1), GRANT_ONLY)
        self.assertEqual(format_open(3, 0, 0, 1, 1, 0), UNLOCK_ONLY)
        for stdout, names in (
            (FULL_ALLOW, CALLS),
            (GRANT_ONLY, ("grant",)),
            (UNLOCK_ONLY, ("unlock",)),
        ):
            result = sbx.Result(
                exit_code=0, stdout=stdout, stderr="", argv=["/private/ptygrant"],
            )
            self.assertEqual(classify(result), "allow")
            self.assertEqual(allowed_names(stdout), names)
        for stdout in DENY_LINES:
            self.assertEqual(
                classify(sbx.Result(
                    exit_code=0, stdout=stdout, stderr="", argv=["/private/ptygrant"],
                )),
                "deny",
            )
        grant_fail_stderr = sbx.Result(
            exit_code=0, stdout=GRANT_FAIL, stderr="noise\n", argv=["/private/ptygrant"],
        )
        with self.assertRaises(HarnessError) as grant_noise:
            classify(grant_fail_stderr)
        self.assertEqual(
            str(grant_noise.exception),
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
        grant_absent = next(
            message for label, _result, message in (
                (label, result, expected) for label, result, expected in samples
            ) if label == "grant ok=-1 after open fd=3"
        )
        unlock_absent = next(
            expected for label, _result, expected in samples
            if label == "unlock ok=-1 after open fd=3"
        )
        self.assertNotEqual(grant_absent, unlock_absent)
        self.assertNotIn("unlock ok=-1 after open fd=3", grant_absent)
        self.assertNotIn("grant ok=-1 after open fd=3", unlock_absent)
        self.launch_guard.assert_not_called()

    def test_partial_grant_is_an_allow(self):
        """One successful call is an allow, and the name is that call.

        Both lines have ``open fd=3 errno=0``. Exit is 0 and stderr is empty.
        Neither line is a harness error.
        """
        samples = (
            (("grant",), GRANT_ONLY),
            (("unlock",), UNLOCK_ONLY),
        )
        for names, stdout in samples:
            with self.subTest(allowed=names):
                result = sbx.Result(
                    exit_code=0, stdout=stdout, stderr="", argv=["/private/ptygrant"],
                )
                self.assertEqual(result.exit_code, 0)
                self.assertEqual(result.stderr, "")
                self.assertTrue(stdout.startswith("open fd=3 errno=0 "))
                self.assertEqual(classify(result), "allow")
                self.assertEqual(allowed_names(result.stdout), names)
                self.assertEqual(allowed_phrase(names), names[0])
                self.assertNotIn(CALLS[1] if names == ("grant",) else CALLS[0], allowed_phrase(names))
                self.assertNotEqual(result.stdout, OPEN_FAIL)
                self.assertNotEqual(result.stdout, GRANT_FAIL)
                self.assertNotEqual(result.stdout, FULL_ALLOW)
        self.launch_guard.assert_not_called()

    def test_unsandboxed_failure_is_an_error(self):
        """A failed unsandboxed control is a harness error, not an assertion failure.

        The open-fail line, the grant-fail line, both partial allows, a
        nonzero exit, nonempty stderr, and a malformed line each raise
        ``HarnessError``. They launch nothing.
        """
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-ptygrant-unsandboxed-"))
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
                "unsandboxed grant deny",
                subprocess.CompletedProcess([binary], 0, GRANT_FAIL, ""),
                "unsandboxed grant deny is a harness error, not a passing control: "
                + repr(GRANT_FAIL),
            ),
            (
                "unsandboxed partial grant",
                subprocess.CompletedProcess([binary], 0, GRANT_ONLY, ""),
                "unsandboxed partial grant is a harness error, not a passing control: "
                + repr(GRANT_ONLY),
            ),
            (
                "unsandboxed partial unlock",
                subprocess.CompletedProcess([binary], 0, UNLOCK_ONLY, ""),
                "unsandboxed partial unlock is a harness error, not a passing control: "
                + repr(UNLOCK_ONLY),
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
            exit_code=0, stdout=OPEN_FAIL, stderr="", argv=["/private/ptygrant"],
        )
        for label, refused, expected in self.refusal_samples():
            for preceding in ([], [deny], [deny, deny]):
                with self.subTest(reason=label, position=len(preceding)):
                    class Observed(GrantProbe):
                        pass

                    with patch(
                        __name__ + ".grant_under",
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
        with patch(__name__ + ".grant_under", side_effect=[refused] * 3) as opened:
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
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/ptygrant"],
        )
        refused = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout="",
            stderr="Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb"],
        )
        self.assertEqual(classify(allow), "allow")
        self.assertEqual(allowed_names(allow.stdout), CALLS)
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
            class Observed(GrantProbe):
                pass

            pending = list(results)
            order = []

            def opened(path):
                order.append(("open", path))
                return pending.pop(0)

            def written(_repo, items):
                order.append(("write", [item[0]["name"] for item in items]))

            with patch(__name__ + ".grant_under", side_effect=opened), patch(
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
            method = observed.test_wallet_grantpt_is_denied
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
            did_method = observed.test_did_grantpt_is_denied
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
        ``result.command``. The injected profile contains the file-grant
        line and the plant line. The wallet docstring names
        ``CRITICAL-confine-071.md``. The model docstring names
        ``CRITICAL-cc-model-confine-071.md``. A unittest run of each
        injected allow is one expected failure. Dropping only the PR label
        raises ``finding omits pr_label``. Dropping only the command raises
        ``finding omits command``. The clean run writes no finding.
        """
        provenance = self.enter_patch(patch(__name__ + ".last_change", return_value="a" * 40))
        self.enter_patch(patch(__name__ + ".pr_label", return_value="PR fixture"))
        self.enter_patch(patch(__name__ + ".sha256_file", return_value="b" * 64))
        command_argv = [sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/ptygrant"]

        def allow_for(stdout):
            return sbx.Result(
                exit_code=0,
                stdout=stdout,
                stderr="",
                argv=list(command_argv),
            )

        full = allow_for(FULL_ALLOW)
        grant_only = allow_for(GRANT_ONLY)
        unlock_only = allow_for(UNLOCK_ONLY)
        self.assertTrue(full.command)
        self.assertIsNone(sbx.profile_error(full))
        self.assertEqual(classify(full), "allow")
        wallet = PROFILES[0]
        did = PROFILES[1]
        model = PROFILES[2]
        self.assertEqual(wallet["name"], "wallet")
        self.assertEqual(did["name"], "did")
        self.assertEqual(model["name"], "model")
        for result, phrase in (
            (full, "grant and unlock"),
            (grant_only, "grant"),
            (unlock_only, "unlock"),
        ):
            paragraph = finding_paragraph(wallet, result)
            self.assertIn(f"allowed: {phrase}\n", paragraph)
            allowed_line = paragraph.split("allowed: ", 1)[1].split("\n", 1)[0]
            self.assertEqual(allowed_line, phrase)
            for name in CALLS:
                if name in phrase.split(" and "):
                    self.assertIn(name, allowed_line)
                else:
                    self.assertNotIn(name, allowed_line)
            self.assertIn(pr_label(last_change(wallet["path"])), paragraph)
            self.assertIn(result.command, paragraph)
            require_finding_pins(paragraph, wallet, result)
        wallet_paragraph = finding_paragraph(wallet, full)
        label = pr_label(last_change(wallet["path"]))
        self.assertIn("CRITICAL", wallet_paragraph.splitlines()[0])
        self.assertIn(last_change(wallet["path"]), wallet_paragraph.splitlines()[0])
        self.assertIn(sha256_file(wallet["path"]), wallet_paragraph.splitlines()[0])
        self.assertIn(label, wallet_paragraph.splitlines()[0])
        self.assertIn(full.command, wallet_paragraph)
        self.assertIn(f"helper: {full.command}\n", wallet_paragraph)
        self.assertIn(f"profile: {wallet['rel']}\n", wallet_paragraph)
        self.assertIn(f"observed: {full.stdout.strip()}\n", wallet_paragraph)
        self.assertNotIn(label, full.command)
        self.assertNotIn(full.command, label)
        self.assertEqual(wallet_paragraph.count(label), 1)
        self.assertEqual(wallet_paragraph.count(full.command), 1)
        pr_omitted = wallet_paragraph.replace(label, "", 1)
        with self.assertRaises(AssertionError) as omitted_pr:
            require_finding_pins(pr_omitted, wallet, full)
        self.assertEqual(str(omitted_pr.exception), "finding omits pr_label")
        self.assertIn(full.command, pr_omitted)
        with self.assertRaises(AssertionError):
            self.assertIn(label, pr_omitted)
        command_omitted = wallet_paragraph.replace(full.command, "", 1)
        with self.assertRaises(AssertionError) as omitted_command:
            require_finding_pins(command_omitted, wallet, full)
        self.assertEqual(str(omitted_command.exception), "finding omits command")
        self.assertIn(label, command_omitted)
        with self.assertRaises(AssertionError):
            self.assertIn(full.command, command_omitted)
        model_paragraph = finding_paragraph(model, unlock_only)
        self.assertIn(pr_label(last_change(model["path"])), model_paragraph)
        self.assertIn(unlock_only.command, model_paragraph)
        require_finding_pins(model_paragraph, model, unlock_only)
        self.assertIn("allowed: unlock\n", model_paragraph)
        self.assertIn("CRITICAL-cc-model-confine-071", model_paragraph)
        live_names = (
            ROOT / "lab" / "redteam" / "CRITICAL.md",
            ROOT / FINDINGS["wallet"],
            ROOT / FINDINGS["model"],
        )
        before = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        with tempfile.TemporaryDirectory(prefix="ccrt-ptygrant-finding-") as tmp:
            repo = Path(tmp)
            self.assertEqual(write_findings(repo, []), [])
            self.assertFalse((repo / "lab" / "redteam" / "CRITICAL.md").exists())
            written = write_findings(repo, [(wallet, full), (did, full)])
            self.assertEqual(written, [FINDINGS["wallet"]])
            body = (repo / FINDINGS["wallet"]).read_text(encoding="utf-8")
            self.assertFalse((repo / FINDINGS["model"]).exists())
            did_paragraph = finding_paragraph(did, full)
            self.assertEqual(body, wallet_paragraph + did_paragraph)
            listed = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertIn(wallet_paragraph, listed)
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

        injected = "(version 1)\n(deny default)\n" + FILE_GRANT + PLANT_LINE
        self.assertEqual(injected.count(FILE_GRANT), 1)
        self.assertEqual(injected.count(PLANT_LINE), 1)

        class Planted(GrantProbe):
            recorded_allows = {
                "wallet": FINDINGS["wallet"],
                "model": FINDINGS["model"],
            }

        mark_expected(Planted, "test_wallet_grantpt_is_denied", FINDINGS["wallet"])
        mark_expected(Planted, "test_model_grantpt_is_denied", FINDINGS["model"])
        try:
            planted = Planted("test_falsifier_allow_pty_ioctl_is_caught")
            self.assertIn("CRITICAL-confine-071.md", Planted.test_wallet_grantpt_is_denied.__doc__)
            self.assertIn(
                "CRITICAL-cc-model-confine-071.md",
                Planted.test_model_grantpt_is_denied.__doc__,
            )
            self.assertEqual(
                planted._source_for_plant("wallet", injected),
                "(version 1)\n(deny default)\n" + FILE_GRANT,
            )
            self.assertEqual(
                planted._source_for_plant("model", injected),
                "(version 1)\n(deny default)\n" + FILE_GRANT,
            )
        finally:
            Planted.doClassCleanups()

        class Unmarked(unittest.TestCase):
            def test_wallet_grantpt_is_denied(self):
                """plain"""
                raise NotDenied(full)

        unmarked = unittest.TestResult()
        Unmarked("test_wallet_grantpt_is_denied").run(unmarked)
        self.assertEqual(len(unmarked.failures), 1)
        self.assertEqual(unmarked.expectedFailures, [])
        self.assertEqual(unmarked.errors, [])

        def run_marked(name):
            method_name = f"test_{name}_grantpt_is_denied"

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
                self.assertIn("CRITICAL-cc-model-confine-071.md", method.__doc__)
            else:
                self.assertIn("CRITICAL-confine-071.md", method.__doc__)
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
                    prefix="ccrt-ptygrant-control-"
                ) as tmp:
                    profiles = []
                    for original in PROFILES:
                        profile = dict(original)
                        profile["path"] = Path(tmp) / f"{profile['name']}.sb"
                        text = "(version 1)\n(deny default)\n(deny network*)\n"
                        if recorded and profile["name"] == "wallet":
                            text = text + FILE_GRANT + PLANT_LINE
                        profile["path"].write_text(text, encoding="utf-8")
                        profiles.append(profile)

                    class Control(GrantProbe):
                        skip_reason = None
                        recorded_allows = {}

                    if recorded:
                        finding = FINDINGS["wallet"]
                        Control.recorded_allows["wallet"] = finding
                        mark_expected(
                            Control, "test_wallet_grantpt_is_denied", finding,
                        )
                        method = Control.test_wallet_grantpt_is_denied
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
                            argv=[sbx.SANDBOX_EXEC, "-f", os.fspath(path), "/private/ptygrant"],
                        )

                    result = unittest.TestResult()
                    try:
                        with patch(__name__ + ".PROFILES", tuple(profiles)), patch(
                            __name__ + ".grant_under", side_effect=injected_open
                        ):
                            Control(
                                "test_falsifier_allow_pty_ioctl_is_caught"
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
                    self.assertIn("grant ok=1 errno=0", caught)
                    self.assertFalse(result.wasSuccessful())
                    self.assertEqual(opened, launched_copy_names())
        self.launch_guard.assert_not_called()

    def test_recorded_allow_keeps_complete_probe_suite_green(self):
        """Run every real probe method against injected tools and profile text.

        No allow, and the plant plus the file-grant line on each profile,
        keep the suite green. Clean input has zero file-grant lines. Recorded
        input keeps one. Only the deny test of the profile that contains the
        plant line is an expected failure. The plant still runs, including
        the plant-only copy with the file grant removed, and nothing skips.
        The finding names every call that returned ``ok=1``.
        """
        method_names = unittest.defaultTestLoader.getTestCaseNames(GrantProbe)
        scenarios = ((), ("wallet",), ("did",), ("model",), ("wallet", "did", "model"))
        for allowed in scenarios:
            with self.subTest(allowed=allowed), tempfile.TemporaryDirectory(
                prefix="ccrt-ptygrant-suite-"
            ) as tmp:
                repo = Path(tmp).resolve()
                profiles = []
                for original in PROFILES:
                    profile = dict(original)
                    profile["path"] = repo / profile["rel"]
                    profile["path"].parent.mkdir(parents=True, exist_ok=True)
                    text = "(version 1)\n(deny default)\n(deny network*)\n"
                    if profile["name"] in allowed:
                        text = text + FILE_GRANT + PLANT_LINE
                        self.assertEqual(text.count(FILE_GRANT), 1)
                        self.assertEqual(text.count(PLANT_LINE), 1)
                    else:
                        self.assertEqual(text.count(FILE_GRANT), 0)
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
                    launched.append(os.fspath(kwargs["profile"]))
                    self.assertEqual(kwargs["pinned_exe"], kwargs["launch_exe"])
                    self.assertEqual(kwargs["timeout"], 5)
                    self.assertEqual(tuple(kwargs["args"]), ())
                    text = Path(kwargs["profile"]).read_text(encoding="utf-8")
                    return sbx.Result(
                        exit_code=0,
                        stdout=stdout_for_profile_text(text),
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
                    __name__ + ".compile_grant", side_effect=injected_compile
                ), patch(__name__ + ".run_unsandboxed", side_effect=injected_control), patch.object(
                    sbx, "run", side_effect=injected_sandbox
                ), patch(__name__ + ".last_change", return_value="a" * 40), patch(
                    __name__ + ".pr_label", return_value="PR fixture"
                ), patch.multiple(
                    GrantProbe, binary=None, root=None, parent=None,
                    skip_reason=None, recorded_allows={},
                ):
                    result = unittest.TestResult()
                    unittest.defaultTestLoader.loadTestsFromTestCase(GrantProbe).run(result)
                    self.assertEqual(result.testsRun, len(method_names))
                    self.assertEqual(result.errors, [])
                    self.assertEqual(result.failures, [])
                    self.assertEqual(result.unexpectedSuccesses, [])
                    self.assertEqual(result.skipped, [])
                    self.assertIsNone(skip_reason())
                    self.assertEqual(len(result.expectedFailures), len(allowed))
                    self.assertEqual(
                        {case._testMethodName for case, _error in result.expectedFailures},
                        {f"test_{name}_grantpt_is_denied" for name in allowed},
                    )
                    for suffix in ("-allow.sb", "-file.sb", "-plant.sb"):
                        self.assertEqual(
                            sorted(
                                os.path.basename(path)
                                for path in launched
                                if os.path.basename(path).endswith(suffix)
                                and os.path.basename(path).startswith(("wallet", "did", "model"))
                            ),
                            [f"did{suffix}", f"model{suffix}", f"wallet{suffix}"],
                        )
                    for name in STILL_DENY_COPIES:
                        self.assertTrue(
                            any(path.endswith(os.sep + name + ".sb") for path in launched),
                            name,
                        )
                    self.assertTrue(
                        any(path.endswith(os.sep + "wallet-bare-ioctl.sb") for path in launched)
                    )
                    self.assertTrue(result.wasSuccessful())
                    self.assertEqual(
                        GrantProbe.recorded_allows,
                        {name: FINDINGS[name] for name in allowed},
                    )
                    for name in allowed:
                        body = (repo / FINDINGS[name]).read_text(encoding="utf-8")
                        profile = next(item for item in profiles if item["name"] == name)
                        self.assertIn("allowed: grant and unlock\n", body)
                        self.assertIn(f"profile: {profile['rel']}\n", body)
                        self.assertIn(sha256_file(profile["path"]), body)
                        self.assertIn(pr_label(last_change(profile["path"])), body)
                        helper_line = next(
                            line for line in body.splitlines() if line.startswith("helper: ")
                        )
                        self.assertIn(sbx.SANDBOX_EXEC, helper_line)
                        self.assertIn(GrantProbe.binary, helper_line)
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
            exit_code=0, stdout=FULL_ALLOW, stderr="", argv=["/private/ptygrant"],
        )
        deny = sbx.Result(
            exit_code=0, stdout=OPEN_FAIL, stderr="", argv=["/private/ptygrant"],
        )
        for profile in PROFILES:
            for label, refused, expected in self.refusal_samples():
                with self.subTest(profile=profile["name"], reason=label):
                    class Recorded(GrantProbe):
                        skip_reason = None

                    def observation(path, profile=profile, allow=allow, deny=deny):
                        return allow if path == profile["path"] else deny

                    with patch(__name__ + ".grant_under", side_effect=observation), patch(
                        __name__ + ".write_findings"
                    ) as writer:
                        observe(Recorded)
                    writer.assert_called_once_with(ROOT, [(profile, allow)])
                    method_name = f"test_{profile['name']}_grantpt_is_denied"
                    method = getattr(Recorded, method_name)
                    self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
                    self.assertIn(FINDINGS[profile["name"]], method.__doc__)
                    result = unittest.TestResult()
                    try:
                        with patch(
                            __name__ + ".grant_under", side_effect=[refused, deny]
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
            argv=["/private/ptygrant"],
        )
        other_fd = sbx.Result(
            exit_code=0,
            stdout=format_open(4, 0, 0, 1, 0, 1),
            stderr="",
            argv=["/private/ptygrant"],
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
            def test_wallet_grantpt_is_denied(self):
                classify(wrong_exit)

        body = unittest.TestResult()
        Body("test_wallet_grantpt_is_denied").run(body)
        self.assertEqual(len(body.errors), 1)
        self.assertEqual(body.failures, [])
        self.assertEqual(body.expectedFailures, [])
        self.assertEqual(body.skipped, [])

        class Setup(unittest.TestCase):
            def setUp(self):
                raise HarnessError("wrong exit 2 is a harness error, not a deny")

            @unittest.expectedFailure
            def test_wallet_grantpt_is_denied(self):
                raise NotDenied(wrong_exit)

        setup = unittest.TestResult()
        Setup("test_wallet_grantpt_is_denied").run(setup)
        self.assertEqual(len(setup.errors), 1)
        self.assertEqual(setup.expectedFailures, [])
        self.assertEqual(setup.skipped, [])
        self.assertIn("wrong exit", setup.errors[0][1])
        self.launch_guard.assert_not_called()

    def test_unresolved_storage_path_is_an_error(self):
        """A ``/var/folders`` storage path without ``/private`` errors before launch."""
        bad_parent = "/var/folders/cc/ptygrant-parent"
        bad_root = "/var/folders/cc/ptygrant-root"
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
                compile_grant(
                    bad_parent,
                    "/private/ptygrant-root",
                    "int main(void) { return 0; }\n",
                )
            compile_message = str(compile_caught.exception)
            self.assertIn(bad_parent, compile_message)
            self.assertIn("/var/folders", compile_message)
            self.assertNotIn("/private" + bad_parent, compile_message)

            with self.assertRaises(HarnessError) as launch_caught:
                run_sandboxed(
                    "/private/ptygrant",
                    bad_root,
                    "/private/ptygrant-parent",
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
