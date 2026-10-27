"""Probe mach, generic, and IOKit seatbelt extensions.

Grade row 12 rests on the wallet, did, and model profiles. No merged probe
calls ``sandbox_extension_issue_mach``, ``sandbox_extension_issue_generic``,
or ``sandbox_extension_issue_iokit_registry_entry_class``. This module
compiles one helper and runs it under each live ``confine.sb``. Confined
launches go through ``sbx.run`` only. The helper prints one line and
returns 0. It mints one mach extension, one generic extension, and one
IOKit registry-entry extension, frees every token, and does not consume
a token.

A deny is exit 0, empty stderr, and stdout ``mach ok=0 errno=1 generic
ok=0 errno=1 iokit ok=0 errno=1``. Each single-call allow, each pair, and
the full allow is exit 0 with empty stderr. The partial names are the
calls whose ``ok`` is 1. The other calls on that line stay denied.

The three profiles are the live files. ``setUpModule`` records each sha256.
``tearDownModule`` and the falsifier's end check call ``require_unchanged``,
which compares the digest through ``changed`` from ``test_confine_mach``.
An owner edit between those two points raises ``the probe changed <rel>``.
A difference from an older measurement is not a failure. This file stores
no commit, pull request, or digest.

An allow on a real profile is CRITICAL. Wallet or did:
``findings/CRITICAL-confine-067.md``. Model:
``findings/CRITICAL-cc-model-confine-067.md``. The finding's first line
contains CRITICAL and names the commit from ``git log -1 --format=%H HEAD
-- <file>`` plus the sha256 of the bytes this run read. It names each
call that returned a token. The same paragraph is appended to
``CRITICAL.md``. With no allow, this module writes neither file.

A recorded allow keeps the gate green. The deny test is an expected
failure and its docstring names that finding file (README guard b).
Each confirmed allow is written before the next profile is classified.
A later harness error still fails the gate. The plant still runs.
A recorded allow is not a skip. This module skips only when
``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` is missing.
A profile error, a failed compile, a failed unsandboxed control,
nonempty stderr, and an exit other than 0 are harness errors. They are
not a deny and they are not a skip.

``IssueProbe`` compiles and launches. It skips only when
``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` is missing, and the reason
names that path. ``IssueRules`` does not compile and does not launch.
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
CALLS = ("mach", "generic", "iokit")
SOURCE_NAME = "issue.c"
BINARY_NAME = "issue"

HELPER_C = r"""#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
extern char *sandbox_extension_issue_mach(const char *extension_class, const char *name, unsigned int flags);
extern char *sandbox_extension_issue_generic(const char *extension_class, unsigned int flags);
extern char *sandbox_extension_issue_iokit_registry_entry_class(const char *extension_class, const char *registry_entry_class, unsigned int flags);
static void issue_named(char *(*fn)(const char *, const char *, unsigned int), const char *class_name, const char *arg, int *ok_out, int *err_out) {
    errno = 0;
    char *token = fn(class_name, arg, 0);
    if (token != NULL) {
        free(token);
        *ok_out = 1;
        *err_out = 0;
        return;
    }
    *ok_out = 0;
    *err_out = errno;
}
int main(void) {
    int mok, merr, gok, gerr, iok, ierr;
    char *gtok;
    issue_named(sandbox_extension_issue_mach, "com.apple.app-sandbox.mach", "com.apple.system.logger", &mok, &merr);
    errno = 0;
    gtok = sandbox_extension_issue_generic("com.apple.app-sandbox.generic", 0);
    if (gtok != NULL) {
        free(gtok);
        gok = 1;
        gerr = 0;
    } else {
        gok = 0;
        gerr = errno;
    }
    issue_named(sandbox_extension_issue_iokit_registry_entry_class, "com.apple.app-sandbox.iokit", "IOSurfaceRoot", &iok, &ierr);
    printf("mach ok=%d errno=%d generic ok=%d errno=%d iokit ok=%d errno=%d\n", mok, merr, gok, gerr, iok, ierr);
    return 0;
}
"""

FINDINGS = {
    "wallet": "lab/redteam/findings/CRITICAL-confine-067.md",
    "did": "lab/redteam/findings/CRITICAL-confine-067.md",
    "model": "lab/redteam/findings/CRITICAL-cc-model-confine-067.md",
}
IDS = {
    "wallet": "CRITICAL-confine-067",
    "did": "CRITICAL-confine-067",
    "model": "CRITICAL-cc-model-confine-067",
}
PROFILES = (
    {
        "name": "wallet",
        "path": sbx.WALLET_CONFINE_SB,
    },
    {
        "name": "did",
        "path": sbx.REPO_ROOT / "capsules/did-provider/confine.sb",
    },
    {
        "name": "model",
        "path": sbx.REPO_ROOT / "capsules/model-provider/confine.sb",
    },
)
PLANT_LINE = {
    "mach": "(allow mach-issue-extension)\n",
    "generic": "(allow generic-issue-extension)\n",
    "iokit": "(allow iokit-issue-extension)\n",
}
PLANT_LINES = tuple((name, PLANT_LINE[name].rstrip("\n"), PLANT_LINE[name]) for name in CALLS)
MACH_GROUPS = (
    (("mach",), "mach"),
    (("mach", "generic"), "mach-generic"),
    (("mach", "iokit"), "mach-iokit"),
    (("generic", "iokit"), "generic-iokit"),
    (("mach", "generic", "iokit"), "all"),
)
SINGLE_GROUPS = {
    "mach": MACH_GROUPS[:1],
    "generic": ((("generic",), "generic"),),
    "iokit": ((("iokit",), "iokit"),),
}
DENY_DEFAULT = "(deny default)\n"
DENY_NETWORK = "(deny network*)\n"
ALLOW_NETWORK = "(allow network*)\n"
STILL_DENY_RULES = (
    ("wallet-file-extension", "(allow file-issue-extension)\n"),
    ("wallet-lookup", "(allow mach-lookup)\n"),
    ("wallet-iokit-open", "(allow iokit-open)\n"),
    ("wallet-iokit-set", "(allow iokit-set-properties)\n"),
    ("wallet-sched", "(allow system-sched)\n"),
    ("wallet-fork", "(allow process-fork)\n"),
    ("wallet-sysctl", "(allow sysctl-write)\n"),
    ("wallet-file-write", "(allow file-write*)\n"),
    ("wallet-fsctl", "(allow system-fsctl)\n"),
    ("wallet-debug", "(allow system-debug)\n"),
)
STILL_DENY_COPIES = (
    "wallet-deleted",
    *(stem for stem, _rule in STILL_DENY_RULES),
    "wallet-network",
)
ALLOW_GROUPS = (
    ("mach",),
    ("generic",),
    ("iokit",),
    ("mach", "generic"),
    ("mach", "iokit"),
    ("generic", "iokit"),
    ("mach", "generic", "iokit"),
)

_LINE = re.compile(
    r"mach ok=(-?[0-9]+) errno=(-?[0-9]+) "
    r"generic ok=(-?[0-9]+) errno=(-?[0-9]+) "
    r"iokit ok=(-?[0-9]+) errno=(-?[0-9]+)\n"
)

START_SHA = {}


def format_line(rows):
    """One helper line. ``rows`` is ``(ok, errno)`` for mach, generic, iokit."""
    parts = []
    for name, row in zip(CALLS, rows):
        ok, errno = row
        parts.append(f"{name} ok={ok} errno={errno}")
    return " ".join(parts) + "\n"


def line_for(names):
    """The helper line for exactly the calls in ``names``."""
    rows = []
    for name in CALLS:
        if name in names:
            rows.append((1, 0))
        else:
            rows.append((0, 1))
    return format_line(rows)


DENY_STDOUT = line_for(())
FULL_STDOUT = line_for(CALLS)


def plants_in(text):
    """Plant names present as an exact allow line, in helper order."""
    return tuple(name for name in CALLS if PLANT_LINE[name] in text)


def with_plants(text, names):
    """Append one exact plant line for each name, in the given order."""
    if not text.endswith("\n"):
        text += "\n"
    return text + "".join(PLANT_LINE[name] for name in names)


def mach_copy_names():
    """Basenames the mach falsifier launches, in order."""
    names = []
    for _group, label in MACH_GROUPS:
        for profile in ("wallet", "did", "model"):
            names.append(f"{profile}-{label}.sb")
    for stem in STILL_DENY_COPIES:
        names.append(stem + ".sb")
    return names


class NotDenied(AssertionError):
    """The profile minted a mach, generic, or IOKit extension."""

    def __init__(self, result):
        self.result = result
        minted = ", ".join(minted_names(result.stdout))
        super().__init__(
            "ALLOW: a seatbelt extension was minted under the profile.\n"
            f"  minted: {minted}\n"
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
    """Three ``(name, ok, errno)`` tuples, or None when the line is not that shape.

    A non-canonical integer is its own harness error. ``int`` accepts ``01``
    and ``-0``; the helper's ``%d`` does not print them.
    """
    match = _LINE.fullmatch(stdout)
    if match is None:
        return None
    parsed = []
    groups = match.groups()
    for index, name in enumerate(CALLS):
        ok_text = groups[index * 2]
        err_text = groups[index * 2 + 1]
        if not canonical_decimal(ok_text):
            raise HarnessError(
                f"noncanonical {name} ok integer {ok_text!r} is a harness error, "
                "not a deny and not an allow: " + repr(stdout)
            )
        if not canonical_decimal(err_text):
            raise HarnessError(
                f"noncanonical {name} errno integer {err_text!r} is a harness error, "
                "not a deny and not an allow: " + repr(stdout)
            )
        parsed.append((name, int(ok_text), int(err_text)))
    return tuple(parsed)


def call_problem(name, ok, errno):
    """The harness reason for one call, or None when the pair is deny or allow."""
    if ok != 0 and ok != 1:
        return (
            f"{name} ok other than 0 or 1 is a harness error, "
            "not a deny and not an allow"
        )
    if ok == 1 and errno != 0:
        return (
            f"{name} errno other than 0 on an allowed call is a harness error, "
            "not an allow"
        )
    if ok == 0 and errno != 1:
        return (
            f"{name} errno other than 1 on a denied call is a harness error, "
            "not a deny"
        )
    return None


def decision(stdout):
    """``(deny, ())`` or ``(allow, names)``. A bad line raises.

    Names are the calls whose ok is 1, in helper order. An ok other than
    0 or 1, an errno other than 0 on an allowed call, and an errno other
    than 1 on a denied call are harness errors.
    """
    parsed = parse_line(stdout)
    if parsed is None:
        raise HarnessError(
            "malformed stdout is a harness error, not a deny and not an allow: "
            + repr(stdout)
        )
    minted = []
    for name, ok, errno in parsed:
        reason = call_problem(name, ok, errno)
        if reason is not None:
            raise HarnessError(reason + ": " + repr(stdout))
        if ok == 1:
            minted.append(name)
    if not minted:
        return "deny", ()
    return "allow", tuple(minted)


def allow_names(stdout):
    """Minted names when ``stdout`` is an allow, else None. This does not raise."""
    try:
        kind, names = decision(stdout)
    except HarnessError:
        return None
    if kind != "allow":
        return None
    return names


def minted_names(stdout):
    """Calls a confirmed allow minted, in helper order."""
    kind, names = decision(stdout)
    if kind != "allow":
        raise HarnessError("finding stdout is not an allow: " + repr(stdout))
    return names


def minted_phrase(names):
    """Every minted call, in helper order, on one finding line."""
    parts = list(names)
    if not parts:
        raise HarnessError("finding names no call")
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2:
        return f"{parts[0]} and {parts[1]}"
    return ", ".join(parts[:-1]) + ", and " + parts[-1]


def classify(result):
    """``deny`` or ``allow``. Otherwise a harness error.

    Asks ``sbx.profile_error`` before it reads a deny or an allow. Exit 65
    is a profile error even when stderr says ``Operation not permitted``.
    A partial mint is an allow and names each call whose ok is 1.
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
        if result.stdout == DENY_STDOUT:
            raise HarnessError(
                "nonempty deny stderr is a harness error, not a deny: "
                + repr(result.stderr)
            )
        if allow_names(result.stdout) is not None:
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


def compile_issue(parent, root, source_text):
    """Compile ``source_text`` with ``/usr/bin/cc`` into ``<root>/issue``.

    The source file sits in ``parent``. The command is ``/usr/bin/cc -o
    <root>/issue <parent>/issue.c``. No extra framework. This does not
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


def issue_under(profile):
    """Run the compiled helper under ``profile``. Pass no argv."""
    binary = IssueProbe.binary
    root = IssueProbe.root
    parent = IssueProbe.parent
    if not binary or not root or not parent:
        raise HarnessError("the issue helper is not compiled")
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
        raise HarnessError(
            "unsandboxed deny is a harness error, not a passing control: "
            + repr(result.stdout)
        )
    if result.stdout != FULL_STDOUT:
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
    """The one helper. ``profile`` must deny every extension mint.

    The three real-file tests and the plant call this. An allow raises
    ``NotDenied``. A harness error propagates and is not a deny.
    """
    result = issue_under(profile)
    if classify(result) != "deny":
        raise NotDenied(result)
    return result


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


def finding_paragraph(profile, result):
    """One CRITICAL record. The first line carries the live pin.

    The commit is ``git log -1 --format=%H HEAD -- <file>`` via
    ``last_change``. The digest is the bytes this run read. Neither value
    is stored in this file. ``minted`` names every call that returned a token.
    The helper line is ``result.command``.
    """
    commit = last_change(profile["path"])
    digest = sha256_file(profile["path"])
    return (
        f"CRITICAL {IDS[profile['name']]} {commit} {pr_label(last_change(profile['path']))} "
        f"sha256 {digest}\n"
        f"profile: {profile['rel']}\n"
        f"minted: {minted_phrase(minted_names(result.stdout))}\n"
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
        "The live profile minted a seatbelt extension. "
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
        result = issue_under(profile["path"])
        outcome = classify(result)
        if outcome != "allow":
            continue
        confirmed.append((profile, result))
        # Snapshot: a later append must not change the list this call recorded.
        write_findings(ROOT, list(confirmed))
        case_cls.recorded_allows[profile["name"]] = FINDINGS[profile["name"]]
        mark_expected(
            case_cls,
            f"test_{profile['name']}_issue_is_denied",
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


class IssueProbe(unittest.TestCase):
    """The helper under the live profiles, and the allow plants."""

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
        cls.parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-issue-parent-"))
        cls.root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-issue-root-"))
        cls.addClassCleanup(shutil.rmtree, cls.parent, ignore_errors=True)
        cls.addClassCleanup(shutil.rmtree, cls.root, ignore_errors=True)
        cls.binary = compile_issue(cls.parent, cls.root, HELPER_C)
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

    def test_unsandboxed_issue_succeeds(self):
        """Without ``sandbox-exec``, the helper exits 0 and mints every extension.

        Stderr is empty. Stdout is the full allow line. A failure here is a
        harness error, so a later deny is about the profile.
        """
        source = os.path.join(self.parent, SOURCE_NAME)
        self.assertEqual(Path(source).read_text(encoding="utf-8"), HELPER_C)
        self.assertIn("sandbox_extension_issue_mach", HELPER_C)
        self.assertIn("sandbox_extension_issue_generic", HELPER_C)
        self.assertIn("sandbox_extension_issue_iokit_registry_entry_class", HELPER_C)
        self.assertIn("com.apple.app-sandbox.mach", HELPER_C)
        self.assertIn("com.apple.app-sandbox.generic", HELPER_C)
        self.assertIn("com.apple.app-sandbox.iokit", HELPER_C)
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
        self.assertEqual(result.stdout, FULL_STDOUT)
        self.assertEqual(
            result.stdout,
            "mach ok=1 errno=0 generic ok=1 errno=0 iokit ok=1 errno=0\n",
        )
        self.assertEqual(classify(result), "allow")
        self.assertEqual(minted_names(result.stdout), CALLS)

    def test_compile_failure_is_an_error(self):
        """``/usr/bin/cc`` on an empty source is a harness error, not a skip."""
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-issue-empty-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-issue-empty-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with self.assertRaises(HarnessError) as caught:
            compile_issue(parent, root, "")
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
        self.assertEqual(result.argv[-1], self.binary)
        self.assertEqual(result.argv[-2], os.fspath(profile))
        self.assertIn(os.fspath(profile), result.argv)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, DENY_STDOUT)
        self.assertEqual(
            result.stdout,
            "mach ok=0 errno=1 generic ok=0 errno=1 iokit ok=0 errno=1\n",
        )
        self.assertEqual(classify(result), "deny")
        return result

    def test_wallet_issue_is_denied(self):
        """The real wallet profile denies every mach, generic, and IOKit extension."""
        self._expect_real_deny(sbx.WALLET_CONFINE_SB)

    def test_did_issue_is_denied(self):
        """The real did profile denies every mach, generic, and IOKit extension."""
        did = sbx.REPO_ROOT / "capsules/did-provider/confine.sb"
        self._expect_real_deny(did)

    def test_model_issue_is_denied(self):
        """The real model profile denies every mach, generic, and IOKit extension.

        The helper starts under it.
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
            for line in PLANT_LINE.values():
                self.assertEqual(text.count(line), 0)
                self.assertEqual(text.count(line.rstrip("\n")), 0)
            self.assertEqual(text.count(DENY_DEFAULT), 1)
            self.assertEqual(baseline, text)
        for line in PLANT_LINE.values():
            self.assertEqual(baseline.count(line), 0)
            self.assertEqual(baseline.count(line.rstrip("\n")), 0)
        self.assertEqual(baseline.count(DENY_DEFAULT), 1)
        self.assertTrue(baseline.endswith("\n"))
        return baseline

    def _catch_allow(self, profile, copy_path, names):
        expected = line_for(names)
        with self.assertRaises(NotDenied) as caught:
            require_denied(copy_path)
        result = caught.exception.result
        self.assertIn("ALLOW", str(caught.exception))
        self.assertIsNone(sbx.profile_error(result))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, expected)
        self.assertEqual(classify(result), "allow")
        self.assertEqual(minted_names(result.stdout), names)
        for name in CALLS:
            if name in names:
                self.assertIn(f"{name} ok=1 errno=0", result.stdout)
            else:
                self.assertIn(f"{name} ok=0 errno=1", result.stdout)
        self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
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

    def _still_deny_text(self, baseline, stem):
        """One wallet copy that is not a plant. Every extension stays denied."""
        for line in PLANT_LINE.values():
            self.assertEqual(baseline.count(line), 0)
        if stem == "wallet-deleted":
            edited = without_deny_default(baseline)
            self.assertNotIn("(deny default)", edited)
            self.assertNotIn("(allow default)", edited)
            self.assertEqual(edited.count(DENY_NETWORK), baseline.count(DENY_NETWORK))
        elif stem == "wallet-network":
            self.assertEqual(baseline.count(DENY_NETWORK), 1)
            edited = with_network_allow(baseline)
            self.assertEqual(edited.count(DENY_NETWORK), 0)
            self.assertEqual(edited.count(ALLOW_NETWORK), baseline.count(ALLOW_NETWORK) + 1)
            self.assertEqual(edited.count(DENY_DEFAULT), 1)
        else:
            rule = dict(STILL_DENY_RULES)[stem]
            self.assertEqual(baseline.count(rule), 0)
            edited = baseline + rule
            self.assertEqual(edited.count(rule), 1)
            self.assertEqual(edited.count(DENY_DEFAULT), 1)
        self.assertEqual(plants_in(edited), ())
        for line in PLANT_LINE.values():
            self.assertEqual(edited.count(line), 0)
        return edited

    def _run_named_groups(self, groups, still_deny):
        """Append each group on a temp copy of each profile.

        ``still_deny`` also builds the wallet copies that must keep the deny.
        The live profile bytes are not edited.
        """
        before = {
            profile["rel"]: sha256_file(profile["path"]) for profile in PROFILES
        }
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-issue-profile-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        try:
            for names, label in groups:
                for profile in PROFILES:
                    with self.subTest(profile=f"{profile['name']}-{label}"):
                        text = profile["path"].read_text(encoding="utf-8")
                        baseline = self._baseline_for(profile, text)
                        planted = with_plants(baseline, names)
                        addition = "".join(PLANT_LINE[name] for name in names)
                        self.assertEqual(planted, baseline + addition)
                        for name in CALLS:
                            expect = 1 if name in names else 0
                            self.assertEqual(planted.count(PLANT_LINE[name]), expect)
                        self.assertEqual(planted.count(DENY_DEFAULT), 1)
                        copy_path = write_copy(
                            directory, f"{profile['name']}-{label}", planted,
                        )
                        self.assertEqual(
                            Path(copy_path).read_text(encoding="utf-8"), planted,
                        )
                        self.assertNotEqual(
                            os.path.realpath(copy_path),
                            os.path.realpath(profile["path"]),
                        )
                        self._catch_allow(profile, copy_path, names)
                        self.assertEqual(
                            profile["path"].read_text(encoding="utf-8"), text,
                        )
            if still_deny:
                wallet = PROFILES[0]
                self.assertEqual(wallet["name"], "wallet")
                wallet_text = wallet["path"].read_text(encoding="utf-8")
                baseline = self._baseline_for(wallet, wallet_text)
                for stem in STILL_DENY_COPIES:
                    with self.subTest(profile=stem):
                        edited = self._still_deny_text(baseline, stem)
                        copy_path = write_copy(directory, stem, edited)
                        self.assertEqual(
                            Path(copy_path).read_text(encoding="utf-8"), edited,
                        )
                        self.assertNotEqual(
                            os.path.realpath(copy_path),
                            os.path.realpath(wallet["path"]),
                        )
                        self._expect_deny_copy(wallet, copy_path)
                self.assertEqual(wallet["path"].read_text(encoding="utf-8"), wallet_text)
        finally:
            require_unchanged(before)

    def test_falsifier_allow_mach_is_caught(self):
        """Appending ``(allow mach-issue-extension)`` mints only the mach extension.

        Each plant baseline contains each exact plant line zero times and
        ``(deny default)`` once. A recorded allow strips one exact copy of
        each injected plant line before that count. A temp copy that appends
        one pair prints that pair's line. A temp copy that appends all three
        prints the full allow line. One wallet copy for each still-deny edit
        still denies all three. The repo profile bytes stay unchanged.
        """
        self._run_named_groups(MACH_GROUPS, still_deny=True)

    def test_falsifier_allow_generic_is_caught(self):
        """Appending ``(allow generic-issue-extension)`` mints only the generic extension.

        The mach and IOKit calls stay denied. The repo profile bytes stay unchanged.
        """
        self._run_named_groups(SINGLE_GROUPS["generic"], still_deny=False)

    def test_falsifier_allow_iokit_is_caught(self):
        """Appending ``(allow iokit-issue-extension)`` mints only the IOKit extension.

        The mach and generic calls stay denied. The repo profile bytes stay unchanged.
        """
        self._run_named_groups(SINGLE_GROUPS["iokit"], still_deny=False)

    def _source_for_plant(self, name, text):
        """The text the temp plant edits. A recorded allow does not skip this.

        The deny test carries the finding-linked expected failure. The live
        file is not edited. One exact copy of each injected plant line is
        removed so the append is still that one line. A plant phrase with no
        trailing newline is its own harness error.
        """
        finding = type(self).recorded_allows.get(name)
        if finding is None:
            for _call, rule, _line in PLANT_LINES:
                if rule in text:
                    raise AssertionError(f"{name} source contains {rule}")
            return text
        method = getattr(type(self), f"test_{name}_issue_is_denied")
        if not getattr(method, "__unittest_expecting_failure__", False):
            raise HarnessError(f"{name} allow has no finding-linked expected failure")
        if finding not in (method.__doc__ or ""):
            raise HarnessError(f"{name} allow docstring does not name {finding}")
        for _call, rule, line in PLANT_LINES:
            occurrences = text.count(line)
            if occurrences > 1:
                raise HarnessError(f"{rule} occurs {occurrences} times, not zero or one")
            if occurrences == 1:
                text = text.replace(line, "", 1)
        for _call, rule, _line in PLANT_LINES:
            if rule in text:
                raise HarnessError(f"{name} plant line has no trailing newline")
        return text


class IssueRules(unittest.TestCase):
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
        probe_names = unittest.defaultTestLoader.getTestCaseNames(IssueProbe)
        for missing in ((sbx.SANDBOX_EXEC,), (CC,), (sbx.SANDBOX_EXEC, CC)):
            with self.subTest(missing=missing), patch.object(
                os.path, "isfile", side_effect=lambda path: path not in missing
            ), patch(
                __name__ + ".compile_issue",
                side_effect=AssertionError("missing-tool probe compiled a helper"),
            ) as compiled, patch.object(
                sbx, "run",
                side_effect=AssertionError("missing-tool probe launched a helper"),
            ) as launched:
                class MissingTools(IssueProbe):
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
        and a second plant line are each their own harness error.
        """
        with patch.object(os.path, "isfile", return_value=True):
            self.assertIsNone(skip_reason())
            self.assertTrue(os.path.isfile(CC))
            self.assertTrue(os.path.isfile(sbx.SANDBOX_EXEC))
        clean = "(version 1)\n(deny default)\n"
        one = {name: clean + PLANT_LINE[name] for name in CALLS}
        all_three = clean + "".join(PLANT_LINE[name] for name in CALLS)
        stayed = all_three + "".join(rule for _stem, rule in STILL_DENY_RULES)

        class Recorded(IssueProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Recorded, "test_wallet_issue_is_denied", FINDINGS["wallet"])
        try:
            case = Recorded("test_falsifier_allow_mach_is_caught")
            for name in CALLS:
                self.assertEqual(case._source_for_plant("wallet", one[name]), clean)
            self.assertEqual(case._source_for_plant("wallet", all_three), clean)
            self.assertEqual(
                case._source_for_plant("wallet", stayed),
                clean + "".join(rule for _stem, rule in STILL_DENY_RULES),
            )
            self.assertEqual(case._source_for_plant("did", clean), clean)
            self.assertNotIsInstance(clean, type(unittest.SkipTest("x")))
        finally:
            Recorded.doClassCleanups()

        class Bare(IssueProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        bare = Bare("test_falsifier_allow_mach_is_caught")
        with self.assertRaises(HarnessError) as unmarked:
            bare._source_for_plant("wallet", one["mach"])
        self.assertEqual(
            str(unmarked.exception),
            "wallet allow has no finding-linked expected failure",
        )
        self.assertNotIsInstance(unmarked.exception, unittest.SkipTest)

        class WrongDoc(IssueProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        def body(self):
            raise NotDenied(
                sbx.Result(exit_code=0, stdout=FULL_STDOUT, stderr="", argv=["/private/issue"])
            )

        body.__doc__ = "plain"
        body.__unittest_expecting_failure__ = True
        WrongDoc.test_wallet_issue_is_denied = body
        wrong = WrongDoc("test_falsifier_allow_mach_is_caught")
        with self.assertRaises(HarnessError) as unnamed:
            wrong._source_for_plant("wallet", one["mach"])
        self.assertEqual(
            str(unnamed.exception),
            f"wallet allow docstring does not name {FINDINGS['wallet']}",
        )

        class Twice(IssueProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Twice, "test_wallet_issue_is_denied", FINDINGS["wallet"])
        try:
            twice = Twice("test_falsifier_allow_mach_is_caught")
            for name in CALLS:
                rule = PLANT_LINE[name].rstrip("\n")
                with self.assertRaises(HarnessError) as extra:
                    twice._source_for_plant("wallet", one[name] + PLANT_LINE[name])
                self.assertEqual(
                    str(extra.exception),
                    f"{rule} occurs 2 times, not zero or one",
                )
        finally:
            Twice.doClassCleanups()

        class BareLine(IssueProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(BareLine, "test_wallet_issue_is_denied", FINDINGS["wallet"])
        try:
            bare_line = BareLine("test_falsifier_allow_mach_is_caught")
            missing_newline = "wallet plant line has no trailing newline"
            for name in CALLS:
                rule = PLANT_LINE[name].rstrip("\n")
                with self.assertRaises(HarnessError) as bare_phrase:
                    bare_line._source_for_plant("wallet", clean + rule)
                self.assertEqual(str(bare_phrase.exception), missing_newline)
                with self.assertRaises(HarnessError) as mixed:
                    bare_line._source_for_plant(
                        "wallet", clean + PLANT_LINE[name] + rule,
                    )
                self.assertEqual(str(mixed.exception), missing_newline)
        finally:
            BareLine.doClassCleanups()

        class Clean(IssueProbe):
            recorded_allows = {}

        plain = Clean("test_falsifier_allow_mach_is_caught")
        for name in CALLS:
            rule = PLANT_LINE[name].rstrip("\n")
            with self.assertRaises(AssertionError) as present:
                plain._source_for_plant("wallet", one[name])
            self.assertEqual(str(present.exception), f"wallet source contains {rule}")
        self.assertEqual(plain._source_for_plant("wallet", clean), clean)
        filtered = clean + "".join(rule for _stem, rule in STILL_DENY_RULES) + ALLOW_NETWORK
        self.assertEqual(plain._source_for_plant("wallet", filtered), filtered)
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
        expected_paths = {
            "wallet": sbx.WALLET_CONFINE_SB,
            "did": sbx.REPO_ROOT / "capsules/did-provider/confine.sb",
            "model": sbx.REPO_ROOT / "capsules/model-provider/confine.sb",
        }
        for profile in PROFILES:
            self.assertEqual(profile["path"], expected_paths[profile["name"]])
            rel = profile["rel"]
            self.assertIn(rel, START_SHA)
            changed(rel, START_SHA[rel], sha256_file(profile["path"]))

        rel = "tmp/issue-confine.sb"
        self.assertNotIn(rel, START_SHA)
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-issue-byte-"))
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
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-issue-cc-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-issue-cc-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        binary = os.path.join(root, BINARY_NAME)
        source = "int main(void) { return 0; }\n"
        reasons = []

        def compiled(completed, access=None):
            runners = patch.object(subprocess, "run", return_value=completed)
            if access is None:
                with runners:
                    return compile_issue(parent, root, source)
            with runners, patch.object(os, "access", return_value=access):
                return compile_issue(parent, root, source)

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
            ("parent", "/var/folders/cc/issue-parent", root),
            ("root", parent, "/var/folders/cc/issue-root"),
        ):
            bad = compile_parent if label == "parent" else compile_root
            expected = (
                f"execvp: {bad} contains /var/folders without the /private prefix"
            )
            with self.subTest(path=label), patch.object(
                subprocess, "run", side_effect=refuse_cc
            ):
                with self.assertRaises(HarnessError) as caught:
                    compile_issue(compile_parent, compile_root, source)
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
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-issue-bytes-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        profiles = []
        for name in ("wallet", "did", "model"):
            path = Path(directory) / f"{name}.sb"
            path.write_bytes(clean)
            profiles.append({
                "name": name,
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

            class Plant(IssueProbe):
                recorded_allows = {}

            state = {"mutate": False}

            def fake_denied(profile):
                profile = os.fspath(profile)
                text = Path(profile).read_text(encoding="utf-8")
                names = plants_in(text)
                argv = [sbx.SANDBOX_EXEC, "-f", profile, "/private/issue"]
                if names:
                    raise NotDenied(sbx.Result(
                        exit_code=0,
                        stdout=line_for(names),
                        stderr="",
                        argv=argv,
                    ))
                if state["mutate"] and profile.endswith(os.sep + "wallet-deleted.sb"):
                    wallet["path"].write_bytes(after_bytes)
                return sbx.Result(
                    exit_code=0,
                    stdout=DENY_STDOUT,
                    stderr="",
                    argv=argv,
                )

            case = Plant("test_falsifier_allow_mach_is_caught")
            try:
                with patch(__name__ + ".PROFILES", profiles), patch(
                    __name__ + ".require_denied", new=fake_denied
                ), patch(__name__ + ".changed", new=spy):
                    with self.subTest(path="falsifier-equal"):
                        seen.clear()
                        state["mutate"] = False
                        wallet["path"].write_bytes(clean)
                        case.test_falsifier_allow_mach_is_caught()
                        self.assertEqual(seen, equal_pairs)
                    with self.subTest(path="falsifier-changed"):
                        seen.clear()
                        state["mutate"] = True
                        wallet["path"].write_bytes(clean)
                        with self.assertRaises(AssertionError) as caught:
                            case.test_falsifier_allow_mach_is_caught()
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
        bad_ok = format_line(((2, 0), (0, 1), (0, 1)))
        bad_allowed_errno = format_line(((1, 2), (0, 1), (0, 1)))
        bad_denied_errno = format_line(((0, 0), (0, 1), (0, 1)))
        malformed = "mach ok=1"
        padded_ok = format_line((("01", 1), (0, 1), (0, 1)))
        signed_zero = format_line(((1, "-0"), (0, 1), (0, 1)))
        return (
            (
                "wrong exit",
                sbx.Result(
                    exit_code=2, stdout=DENY_STDOUT, stderr="", argv=["/private/issue"],
                ),
                "wrong exit 2 is a harness error, not a deny and not an allow. "
                f"stdout={DENY_STDOUT!r} stderr=''",
            ),
            (
                "ok other than 0 or 1",
                sbx.Result(
                    exit_code=0, stdout=bad_ok, stderr="", argv=["/private/issue"],
                ),
                "mach ok other than 0 or 1 is a harness error, "
                "not a deny and not an allow: " + repr(bad_ok),
            ),
            (
                "errno other than 0",
                sbx.Result(
                    exit_code=0, stdout=bad_allowed_errno, stderr="", argv=["/private/issue"],
                ),
                "mach errno other than 0 on an allowed call is a harness error, "
                "not an allow: " + repr(bad_allowed_errno),
            ),
            (
                "errno other than 1",
                sbx.Result(
                    exit_code=0, stdout=bad_denied_errno, stderr="", argv=["/private/issue"],
                ),
                "mach errno other than 1 on a denied call is a harness error, "
                "not a deny: " + repr(bad_denied_errno),
            ),
            (
                "noncanonical mach ok",
                sbx.Result(
                    exit_code=0, stdout=padded_ok, stderr="", argv=["/private/issue"],
                ),
                "noncanonical mach ok integer '01' is a harness error, "
                "not a deny and not an allow: " + repr(padded_ok),
            ),
            (
                "noncanonical mach errno",
                sbx.Result(
                    exit_code=0, stdout=signed_zero, stderr="", argv=["/private/issue"],
                ),
                "noncanonical mach errno integer '-0' is a harness error, "
                "not a deny and not an allow: " + repr(signed_zero),
            ),
            (
                "nonempty deny stderr",
                sbx.Result(
                    exit_code=0,
                    stdout=DENY_STDOUT,
                    stderr="noise\n",
                    argv=["/private/issue"],
                ),
                "nonempty deny stderr is a harness error, not a deny: " + repr("noise\n"),
            ),
            (
                "nonempty allow stderr",
                sbx.Result(
                    exit_code=0,
                    stdout=FULL_STDOUT,
                    stderr="noise\n",
                    argv=["/private/issue"],
                ),
                "nonempty allow stderr is a harness error, not an allow: " + repr("noise\n"),
            ),
            (
                "malformed stdout",
                sbx.Result(
                    exit_code=0, stdout=malformed, stderr="", argv=["/private/issue"],
                ),
                "malformed stdout is a harness error, not a deny and not an allow: "
                + repr(malformed),
            ),
            (
                "profile error",
                sbx.Result(
                    exit_code=sbx.PROFILE_ERROR_EXIT,
                    stdout=FULL_STDOUT,
                    stderr="Operation not permitted\n",
                    argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/issue"],
                ),
                "profile error: profile read or compile error: sandbox-exec exited 65 "
                "and started no program, so nothing was denied -- a harness error, "
                "not a deny and not an allow. stderr='Operation not permitted\\n'",
            ),
        )

    def test_classifier_refusal_reasons(self):
        """Each classifier refusal preserves its exact, distinct reason.

        These results are built here. Nothing is launched. Exit 65 stays a
        profile error when stderr says ``Operation not permitted``. An ok
        other than 0 or 1, an errno other than 0 on an allowed call, and an
        errno other than 1 on a denied call stay distinct from a malformed line.
        """
        self.assertEqual(
            DENY_STDOUT,
            "mach ok=0 errno=1 generic ok=0 errno=1 iokit ok=0 errno=1\n",
        )
        self.assertEqual(
            FULL_STDOUT,
            "mach ok=1 errno=0 generic ok=1 errno=0 iokit ok=1 errno=0\n",
        )
        self.assertEqual(
            classify(sbx.Result(
                exit_code=0, stdout=FULL_STDOUT, stderr="", argv=["/private/issue"],
            )),
            "allow",
        )
        self.assertEqual(minted_names(FULL_STDOUT), CALLS)
        self.assertEqual(
            classify(sbx.Result(
                exit_code=0, stdout=DENY_STDOUT, stderr="", argv=["/private/issue"],
            )),
            "deny",
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
            self.assertEqual(len(hits), 1)
        for name, index in (("generic", 1), ("iokit", 2)):
            rows = [(0, 1), (0, 1), (0, 1)]
            rows[index] = (2, 0)
            stdout = format_line(rows)
            with self.assertRaises(HarnessError) as caught:
                classify(sbx.Result(
                    exit_code=0, stdout=stdout, stderr="", argv=["/private/issue"],
                ))
            self.assertIn(f"{name} ok other than 0 or 1", str(caught.exception))
            rows[index] = (1, 2)
            stdout = format_line(rows)
            with self.assertRaises(HarnessError) as caught:
                classify(sbx.Result(
                    exit_code=0, stdout=stdout, stderr="", argv=["/private/issue"],
                ))
            self.assertIn(
                f"{name} errno other than 0 on an allowed call",
                str(caught.exception),
            )
            rows[index] = (0, 0)
            stdout = format_line(rows)
            with self.assertRaises(HarnessError) as caught:
                classify(sbx.Result(
                    exit_code=0, stdout=stdout, stderr="", argv=["/private/issue"],
                ))
            self.assertIn(
                f"{name} errno other than 1 on a denied call",
                str(caught.exception),
            )
        self.launch_guard.assert_not_called()

    def test_partial_issue_is_an_allow(self):
        """Each single call, each pair, and the full line is an allow.

        Exit is 0 and stderr is empty. The named calls are exactly the ones
        whose ok is 1. None of these is a harness error.
        """
        literals = {
            ("mach",): "mach ok=1 errno=0 generic ok=0 errno=1 iokit ok=0 errno=1\n",
            ("generic",): "mach ok=0 errno=1 generic ok=1 errno=0 iokit ok=0 errno=1\n",
            ("iokit",): "mach ok=0 errno=1 generic ok=0 errno=1 iokit ok=1 errno=0\n",
            ("mach", "generic"): (
                "mach ok=1 errno=0 generic ok=1 errno=0 iokit ok=0 errno=1\n"
            ),
            ("mach", "iokit"): (
                "mach ok=1 errno=0 generic ok=0 errno=1 iokit ok=1 errno=0\n"
            ),
            ("generic", "iokit"): (
                "mach ok=0 errno=1 generic ok=1 errno=0 iokit ok=1 errno=0\n"
            ),
            ("mach", "generic", "iokit"): (
                "mach ok=1 errno=0 generic ok=1 errno=0 iokit ok=1 errno=0\n"
            ),
        }
        self.assertEqual(tuple(literals), ALLOW_GROUPS)
        for names, stdout in literals.items():
            with self.subTest(minted=names):
                self.assertEqual(line_for(names), stdout)
                result = sbx.Result(
                    exit_code=0, stdout=stdout, stderr="", argv=["/private/issue"],
                )
                self.assertEqual(result.exit_code, 0)
                self.assertEqual(result.stderr, "")
                self.assertEqual(classify(result), "allow")
                self.assertEqual(minted_names(result.stdout), names)
                self.assertNotEqual(result.stdout, DENY_STDOUT)
                if len(names) == 1:
                    phrase = names[0]
                elif len(names) == 2:
                    phrase = f"{names[0]} and {names[1]}"
                else:
                    phrase = "mach, generic, and iokit"
                self.assertEqual(minted_phrase(names), phrase)
        self.launch_guard.assert_not_called()

    def test_unsandboxed_failure_is_an_error(self):
        """A failed unsandboxed control is a harness error, not an assertion failure.

        The deny line, each single-call allow, each pair, a nonzero exit,
        nonempty stderr, and a malformed line each raise ``HarnessError``.
        They launch nothing.
        """
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-issue-unsandboxed-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        binary = os.path.join(parent, BINARY_NAME)
        descriptor = os.open(binary, os.O_CREAT | os.O_WRONLY, 0o755)
        os.close(descriptor)
        binary = os.path.realpath(binary)
        deny_reason = (
            "unsandboxed deny is a harness error, not a passing control: "
            + repr(DENY_STDOUT)
        )
        cases = [
            (
                "unsandboxed deny",
                subprocess.CompletedProcess([binary], 0, DENY_STDOUT, ""),
                deny_reason,
            ),
        ]
        for names in ALLOW_GROUPS:
            if names == CALLS:
                continue
            stdout = line_for(names)
            cases.append((
                "unsandboxed " + " ".join(names),
                subprocess.CompletedProcess([binary], 0, stdout, ""),
                "unsandboxed partial allow is a harness error, not a passing control: "
                + repr(stdout),
            ))
        cases.extend((
            (
                "wrong exit",
                subprocess.CompletedProcess([binary], 2, FULL_STDOUT, ""),
                "wrong exit 2 is a harness error, not a deny and not an allow. "
                f"stdout={FULL_STDOUT!r} stderr=''",
            ),
            (
                "nonempty allow stderr",
                subprocess.CompletedProcess([binary], 0, FULL_STDOUT, "noise\n"),
                "nonempty allow stderr is a harness error, not an allow: " + repr("noise\n"),
            ),
            (
                "malformed stdout",
                subprocess.CompletedProcess([binary], 0, "mach nope\n", ""),
                "malformed stdout is a harness error, not a deny and not an allow: "
                + repr("mach nope\n"),
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
                self.assertIn(label.split()[0], message)
                self.assertNotIsInstance(caught.exception, AssertionError)
                reasons.append(message)
        self.assertEqual(len(set(reasons)), len(cases))
        self.assertEqual(len(cases), 1 + 6 + 3)
        self.launch_guard.assert_not_called()

    def test_observe_propagates_every_refusal(self):
        """A failed observation stops before any later success or finding mark."""
        deny = sbx.Result(
            exit_code=0, stdout=DENY_STDOUT, stderr="", argv=["/private/issue"],
        )
        for label, refused, expected in self.refusal_samples():
            for preceding in ([], [deny], [deny, deny]):
                with self.subTest(reason=label, position=len(preceding)):
                    class Observed(IssueProbe):
                        pass

                    with patch(
                        __name__ + ".issue_under",
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
        with patch(__name__ + ".issue_under", side_effect=[refused] * 3) as opened:
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
            stdout=FULL_STDOUT,
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/issue"],
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
            class Observed(IssueProbe):
                pass

            pending = list(results)
            order = []

            def opened(path):
                order.append(("open", path))
                return pending.pop(0)

            def written(_repo, items):
                order.append(("write", [item[0]["name"] for item in items]))

            with patch(__name__ + ".issue_under", side_effect=opened), patch(
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
            method = observed.test_wallet_issue_is_denied
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
            did_method = observed.test_did_issue_is_denied
            self.assertTrue(getattr(did_method, "__unittest_expecting_failure__", False))
            self.assertIn(FINDINGS["did"], did_method.__doc__ or "")
        finally:
            if observed is not None:
                observed.doClassCleanups()
        live_names = (
            ROOT / "lab" / "redteam" / "CRITICAL.md",
            ROOT / FINDINGS["wallet"],
            ROOT / FINDINGS["model"],
        )
        for path in live_names:
            self.assertFalse(path.exists())
        self.launch_guard.assert_not_called()

    def test_recorded_allow_is_expected_failure(self):
        """A recorded allow is an expected failure whose docstring names the finding.

        The result is injected. The finding is written under a temp repo.
        Its first line contains CRITICAL and injected provenance. It names
        each call that returned a token, the PR from ``pr_label(last_change)``,
        and ``result.command``. ``CRITICAL.md`` receives that same paragraph.
        The wallet docstring names ``CRITICAL-confine-067.md`` for each plant.
        The model docstring names ``CRITICAL-cc-model-confine-067.md``.
        A unittest run of each injected allow is one expected failure.
        Omitting the PR or the command fails that field's assertion alone.
        The same raise without the mark is a failure. The clean run writes
        no finding.
        """
        provenance = self.enter_patch(patch(__name__ + ".last_change", return_value="a" * 40))
        self.enter_patch(patch(__name__ + ".pr_label", return_value="PR fixture"))
        self.enter_patch(patch(__name__ + ".sha256_file", return_value="b" * 64))
        command_argv = [sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/issue"]

        def allow_for(names):
            return sbx.Result(
                exit_code=0,
                stdout=line_for(names),
                stderr="",
                argv=list(command_argv),
            )

        allows = {names: allow_for(names) for names in ALLOW_GROUPS}
        full = allows[CALLS]
        self.assertTrue(full.command)
        self.assertIsNone(sbx.profile_error(full))
        self.assertEqual(classify(full), "allow")
        wallet = PROFILES[0]
        did = PROFILES[1]
        model = PROFILES[2]
        self.assertEqual(wallet["name"], "wallet")
        self.assertEqual(did["name"], "did")
        self.assertEqual(model["name"], "model")
        for names, result in allows.items():
            paragraph = finding_paragraph(wallet, result)
            self.assertIn(f"minted: {minted_phrase(names)}\n", paragraph)
            minted_line = paragraph.split("minted: ", 1)[1].split("\n", 1)[0]
            for name in CALLS:
                if name in names:
                    self.assertIn(name, minted_line)
                else:
                    self.assertNotIn(name, minted_line)
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
        model_paragraph = finding_paragraph(model, allows[(("iokit",))])
        self.assertIn(pr_label(last_change(model["path"])), model_paragraph)
        self.assertIn(allows[(("iokit",))].command, model_paragraph)
        require_finding_pins(model_paragraph, model, allows[(("iokit",))])
        self.assertIn("minted: iokit\n", model_paragraph)
        live_names = (
            ROOT / "lab" / "redteam" / "CRITICAL.md",
            ROOT / FINDINGS["wallet"],
            ROOT / FINDINGS["model"],
        )
        before = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        with tempfile.TemporaryDirectory(prefix="ccrt-issue-finding-") as tmp:
            repo = Path(tmp)
            self.assertEqual(write_findings(repo, []), [])
            self.assertFalse((repo / "lab" / "redteam" / "CRITICAL.md").exists())
            written = write_findings(repo, [(wallet, full), (did, allows[(("generic",))])])
            self.assertEqual(written, [FINDINGS["wallet"]])
            body = (repo / FINDINGS["wallet"]).read_text(encoding="utf-8")
            self.assertFalse((repo / FINDINGS["model"]).exists())
            did_paragraph = finding_paragraph(did, allows[(("generic",))])
            self.assertEqual(body, wallet_paragraph + did_paragraph)
            self.assertIn(f"profile: {wallet['rel']}", wallet_paragraph)
            self.assertIn("minted: mach, generic, and iokit\n", wallet_paragraph)
            self.assertIn("minted: generic\n", did_paragraph)
            listed = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertIn(wallet_paragraph, listed)
            self.assertIn(did_paragraph, listed)
            model_written = write_findings(repo, [(model, allows[(("iokit",))])])
            self.assertEqual(model_written, [FINDINGS["model"]])
            model_body = (repo / FINDINGS["model"]).read_text(encoding="utf-8")
            self.assertEqual(model_body, model_paragraph)
            self.assertIn("CRITICAL", model_paragraph.splitlines()[0])
            self.assertIn("CRITICAL-cc-model-confine-067", model_paragraph)
            listed_again = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertIn(model_paragraph, listed_again)
            self.assertEqual(listed_again.count(model_paragraph), 1)
            again = write_findings(repo, [(model, allows[(("iokit",))])])
            relisted = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertEqual(relisted, listed_again)
            self.assertEqual(again, [FINDINGS["model"]])
        after = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        self.assertEqual(before, after)

        class Unmarked(unittest.TestCase):
            def test_wallet_issue_is_denied(self):
                """plain"""
                raise NotDenied(full)

        unmarked = unittest.TestResult()
        Unmarked("test_wallet_issue_is_denied").run(unmarked)
        self.assertEqual(len(unmarked.failures), 1)
        self.assertEqual(unmarked.expectedFailures, [])
        self.assertEqual(unmarked.errors, [])

        def run_marked(name, names):
            method_name = f"test_{name}_issue_is_denied"

            class Recorded(IssueProbe):
                skip_reason = None

            mark_expected(Recorded, method_name, FINDINGS[name])
            method = getattr(Recorded, method_name)
            self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
            self.assertIn(FINDINGS[name], method.__doc__)
            if name == "model":
                self.assertIn("CRITICAL-cc-model-confine-067.md", method.__doc__)
            else:
                self.assertIn("CRITICAL-confine-067.md", method.__doc__)
                self.assertNotIn("cc-model", method.__doc__)
            recorded = unittest.TestResult()
            try:
                with patch(
                    __name__ + ".issue_under", return_value=allow_for(names),
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
            self.assertEqual(
                recorded.expectedFailures[0][0]._testMethodName,
                method_name,
            )

        for names in (("mach",), ("generic",), ("iokit",)):
            run_marked("wallet", names)
        run_marked("model", ("iokit",))
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
                    prefix="ccrt-issue-control-"
                ) as tmp:
                    profiles = []
                    for original in PROFILES:
                        profile = dict(original)
                        profile["path"] = Path(tmp) / f"{profile['name']}.sb"
                        text = "(version 1)\n(deny default)\n(deny network*)\n"
                        if recorded and profile["name"] == "wallet":
                            text = with_plants(text, ("mach",))
                        profile["path"].write_text(text, encoding="utf-8")
                        profiles.append(profile)

                    class Control(IssueProbe):
                        skip_reason = None
                        recorded_allows = {}

                    if recorded:
                        finding = FINDINGS["wallet"]
                        Control.recorded_allows["wallet"] = finding
                        mark_expected(
                            Control, "test_wallet_issue_is_denied", finding,
                        )
                        method = Control.test_wallet_issue_is_denied
                        self.assertTrue(
                            getattr(method, "__unittest_expecting_failure__", False)
                        )
                        self.assertIn(finding, method.__doc__ or "")

                    opened = []

                    def injected_open(profile):
                        path = Path(profile)
                        opened.append(path.name)
                        text = path.read_text(encoding="utf-8")
                        names = plants_in(text)
                        if path.stem == control:
                            stdout = FULL_STDOUT
                        else:
                            stdout = line_for(names)
                        return sbx.Result(
                            exit_code=0,
                            stdout=stdout,
                            stderr="",
                            argv=[sbx.SANDBOX_EXEC, "-f", os.fspath(path), "/private/issue"],
                        )

                    result = unittest.TestResult()
                    try:
                        with patch(__name__ + ".PROFILES", tuple(profiles)), patch(
                            __name__ + ".issue_under", side_effect=injected_open
                        ):
                            Control("test_falsifier_allow_mach_is_caught").run(result)
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
                    self.assertIn("mach ok=1 errno=0", caught)
                    self.assertFalse(result.wasSuccessful())
                    self.assertEqual(opened, mach_copy_names())
        self.launch_guard.assert_not_called()

    def test_recorded_allow_keeps_complete_probe_suite_green(self):
        """Run every real probe method against injected tools and profile text.

        No allow, each single plant on each profile, each pair on each
        profile, and all three plants on each profile keep the suite green.
        Only the deny test of a profile that contains a plant line is an
        expected failure. The finding names every call that returned a token.
        The plants still run, nothing skips, and the result is successful.
        """
        method_names = unittest.defaultTestLoader.getTestCaseNames(IssueProbe)
        scenarios = [{}]
        for profile_name in ("wallet", "did", "model"):
            for names in ALLOW_GROUPS:
                scenarios.append({profile_name: names})
        self.assertEqual(len(scenarios), 1 + 3 * len(ALLOW_GROUPS))
        for allowed in scenarios:
            with self.subTest(allowed=tuple(allowed.items())), tempfile.TemporaryDirectory(
                prefix="ccrt-issue-suite-"
            ) as tmp:
                repo = Path(tmp).resolve()
                profiles = []
                for original in PROFILES:
                    profile = dict(original)
                    profile["path"] = repo / profile["rel"]
                    profile["path"].parent.mkdir(parents=True, exist_ok=True)
                    text = "(version 1)\n(deny default)\n(deny network*)\n"
                    names = allowed.get(profile["name"], ())
                    if names:
                        text = with_plants(text, names)
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
                        stdout=FULL_STDOUT,
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
                        stdout=line_for(plants_in(text)),
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
                    __name__ + ".compile_issue", side_effect=injected_compile
                ), patch(__name__ + ".run_unsandboxed", side_effect=injected_control), patch.object(
                    sbx, "run", side_effect=injected_sandbox
                ), patch(__name__ + ".last_change", return_value="a" * 40), patch(
                    __name__ + ".pr_label", return_value="PR fixture"
                ), patch.multiple(
                    IssueProbe, binary=None, root=None, parent=None,
                    skip_reason=None, recorded_allows={},
                ):
                    result = unittest.TestResult()
                    unittest.defaultTestLoader.loadTestsFromTestCase(IssueProbe).run(result)
                    self.assertEqual(result.testsRun, len(method_names))
                    self.assertEqual(result.errors, [])
                    self.assertEqual(result.failures, [])
                    self.assertEqual(result.unexpectedSuccesses, [])
                    self.assertEqual(result.skipped, [])
                    self.assertIsNone(skip_reason())
                    self.assertEqual(len(result.expectedFailures), len(allowed))
                    self.assertEqual(
                        {case._testMethodName for case, _error in result.expectedFailures},
                        {f"test_{name}_issue_is_denied" for name in allowed},
                    )
                    for label in (
                        "mach", "generic", "iokit",
                        "mach-generic", "mach-iokit", "generic-iokit", "all",
                    ):
                        self.assertEqual(
                            sorted(
                                os.path.basename(path)
                                for path in launched
                                if os.path.basename(path) in {
                                    f"{profile}-{label}.sb"
                                    for profile in ("wallet", "did", "model")
                                }
                            ),
                            [f"did-{label}.sb", f"model-{label}.sb", f"wallet-{label}.sb"],
                        )
                    for stem in STILL_DENY_COPIES:
                        self.assertTrue(
                            any(path.endswith(os.sep + stem + ".sb") for path in launched),
                            stem,
                        )
                    self.assertTrue(result.wasSuccessful())
                    self.assertEqual(
                        IssueProbe.recorded_allows,
                        {name: FINDINGS[name] for name in allowed},
                    )
                    for name, planted in allowed.items():
                        body = (repo / FINDINGS[name]).read_text(encoding="utf-8")
                        profile = next(item for item in profiles if item["name"] == name)
                        minted_line = "minted: " + minted_phrase(planted)
                        self.assertIn(minted_line, body)
                        self.assertIn(f"profile: {profile['rel']}", body)
                        self.assertIn(sha256_file(profile["path"]), body)
                        self.assertIn(pr_label(last_change(profile["path"])), body)
                        helper_line = next(
                            line for line in body.splitlines() if line.startswith("helper: ")
                        )
                        self.assertIn(sbx.SANDBOX_EXEC, helper_line)
                        self.assertIn(IssueProbe.binary, helper_line)
                        for call in CALLS:
                            if call in planted:
                                self.assertIn(call, minted_line)
                            else:
                                self.assertNotIn(call, minted_line)
                        self.assertIn(
                            body,
                            (repo / "lab/redteam/CRITICAL.md").read_text(encoding="utf-8"),
                        )
                    if not allowed:
                        self.assertFalse((repo / "lab/redteam/CRITICAL.md").exists())
                        for rel in set(FINDINGS.values()):
                            self.assertFalse((repo / rel).exists())
                    else:
                        if "model" not in allowed:
                            self.assertFalse((repo / FINDINGS["model"]).exists())
                        if "wallet" not in allowed and "did" not in allowed:
                            self.assertFalse((repo / FINDINGS["wallet"]).exists())
                self.launch_guard.assert_not_called()

    def test_harness_error_stays_error(self):
        """An injected harness error stays an error. It is not a deny, an allow, or a skip."""
        allow = sbx.Result(
            exit_code=0, stdout=FULL_STDOUT, stderr="", argv=["/private/issue"],
        )
        deny = sbx.Result(
            exit_code=0, stdout=DENY_STDOUT, stderr="", argv=["/private/issue"],
        )
        for profile in PROFILES:
            for label, refused, expected in self.refusal_samples():
                with self.subTest(profile=profile["name"], reason=label):
                    class Recorded(IssueProbe):
                        skip_reason = None

                    def observation(path, chosen=profile, allowed=allow, refused_result=deny):
                        return allowed if path == chosen["path"] else refused_result

                    with patch(__name__ + ".issue_under", side_effect=observation), patch(
                        __name__ + ".write_findings"
                    ) as writer:
                        observe(Recorded)
                    writer.assert_called_once_with(ROOT, [(profile, allow)])
                    method_name = f"test_{profile['name']}_issue_is_denied"
                    method = getattr(Recorded, method_name)
                    self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
                    self.assertIn(FINDINGS[profile["name"]], method.__doc__)
                    result = unittest.TestResult()
                    try:
                        with patch(
                            __name__ + ".issue_under", side_effect=[refused, deny]
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
            stdout=DENY_STDOUT,
            stderr="",
            argv=["/private/issue"],
        )
        bad_ok = sbx.Result(
            exit_code=0,
            stdout=format_line(((2, 0), (0, 1), (0, 1))),
            stderr="",
            argv=["/private/issue"],
        )
        profile_error = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout=FULL_STDOUT,
            stderr="Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC],
        )
        for result in (wrong_exit, bad_ok, profile_error):
            with self.assertRaises(HarnessError):
                classify(result)

        class Body(unittest.TestCase):
            def test_wallet_issue_is_denied(self):
                classify(wrong_exit)

        body = unittest.TestResult()
        Body("test_wallet_issue_is_denied").run(body)
        self.assertEqual(len(body.errors), 1)
        self.assertEqual(body.failures, [])
        self.assertEqual(body.expectedFailures, [])
        self.assertEqual(body.skipped, [])

        class Setup(unittest.TestCase):
            def setUp(self):
                raise HarnessError("wrong exit 2 is a harness error, not a deny")

            @unittest.expectedFailure
            def test_wallet_issue_is_denied(self):
                raise NotDenied(wrong_exit)

        setup = unittest.TestResult()
        Setup("test_wallet_issue_is_denied").run(setup)
        self.assertEqual(len(setup.errors), 1)
        self.assertEqual(setup.expectedFailures, [])
        self.assertEqual(setup.skipped, [])
        self.assertIn("wrong exit", setup.errors[0][1])
        self.launch_guard.assert_not_called()

    def test_unresolved_storage_path_is_an_error(self):
        """A ``/var/folders`` storage path without ``/private`` errors before launch."""
        bad_parent = "/var/folders/cc/issue-parent"
        bad_root = "/var/folders/cc/issue-root"
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
                compile_issue(
                    bad_parent,
                    "/private/issue-root",
                    "int main(void) { return 0; }\n",
                )
            compile_message = str(compile_caught.exception)
            self.assertIn(bad_parent, compile_message)
            self.assertIn("/var/folders", compile_message)
            self.assertNotIn("/private" + bad_parent, compile_message)

            with self.assertRaises(HarnessError) as launch_caught:
                run_sandboxed(
                    "/private/issue",
                    bad_root,
                    "/private/issue-parent",
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
