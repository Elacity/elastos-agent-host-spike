"""Probe task_for_pid on the wallet, did, and model profiles.

Grade row 12 rests on those seatbelt profiles. No merged probe calls
``task_for_pid``. This module compiles one helper and runs it under each live
``confine.sb``. Confined launches go through ``sbx.run`` only. The helper
calls ``task_for_pid`` on its own pid, prints one line, and returns 0.
A deny is stdout ``task kr=5 port=0`` and empty stderr. An allow is stdout
``task kr=0 port=<integer >= 1>`` and empty stderr. ``task kr=0 port=0``
is not an allow.

The three profiles are the live files. ``setUpModule`` records each sha256.
``tearDownModule`` and the falsifier's end check call ``require_unchanged``,
which compares the digest through ``changed`` from ``test_confine_mach``.
An owner edit between those two points raises ``the probe changed <rel>``.
A difference from an older measurement is not a failure. This file stores
no commit, pull request, or digest.

An allow on a real profile is CRITICAL. Wallet or did:
``findings/CRITICAL-confine-054.md``. Model:
``findings/CRITICAL-cc-model-confine-054.md``. The finding's first line
contains CRITICAL and names the commit from ``git log -1 --format=%H HEAD
-- <file>`` plus the sha256 of the bytes this run read. The same paragraph
is appended to ``CRITICAL.md``. With no allow, this module writes neither
file.

A recorded allow keeps the gate green. The deny test is an expected
failure and its docstring names that finding file (README guard b).
Each confirmed allow is written before the next profile is classified.
A later harness error still fails the gate. The plant still runs.
A recorded allow is not a skip. This module skips only when
``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` is missing.
A profile error, a failed compile, a failed
unsandboxed control, nonempty stderr, and an exit other than 0 are harness
errors. They are not a deny and they are not a skip.

``TaskForPidProbe`` compiles and launches. It skips only when
``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` is missing, and the reason
names that path. ``TaskForPidRules`` does not compile and does not launch.
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
DENY_STDOUT = "task kr=5 port=0\n"
ALLOW_TASK = "(allow mach-priv-task-port)\n"
DENY_DEFAULT = "(deny default)\n"
MACH_LOOKUP = "(allow mach-lookup)\n"

HELPER_C = """\
#include <stdio.h>
#include <unistd.h>
#include <mach/mach.h>
int main(void) {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), getpid(), &port);
    printf("task kr=%d port=%u\\n", kr, port);
    return 0;
}
"""

FINDINGS = {
    "wallet": "lab/redteam/findings/CRITICAL-confine-054.md",
    "did": "lab/redteam/findings/CRITICAL-confine-054.md",
    "model": "lab/redteam/findings/CRITICAL-cc-model-confine-054.md",
}
IDS = {
    "wallet": "CRITICAL-confine-054",
    "did": "CRITICAL-confine-054",
    "model": "CRITICAL-cc-model-confine-054",
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

_ALLOW_STDOUT = re.compile(r"task kr=0 port=([0-9]+)\n")
_TASK_LINE = re.compile(r"task kr=(-?[0-9]+) port=[0-9]+\n")

START_SHA = {}


class NotDenied(AssertionError):
    """The profile allowed ``task_for_pid``."""

    def __init__(self, result):
        self.result = result
        super().__init__(
            "ALLOW: task_for_pid succeeded under the profile.\n"
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


def allow_port(stdout):
    """The port from an allow line, or None when stdout is not that line.

    ``task kr=0 port=0`` is not an allow. A port of zero matches the digits
    and is still refused here.
    """
    match = _ALLOW_STDOUT.fullmatch(stdout)
    if match is None:
        return None
    port = int(match.group(1))
    if port < 1:
        return None
    return port


def classify(result):
    """``deny``, ``allow``, or a harness error.

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
        if result.stdout == DENY_STDOUT:
            raise HarnessError(
                "nonempty deny stderr is a harness error, not a deny: "
                + repr(result.stderr)
            )
        if allow_port(result.stdout) is not None:
            raise HarnessError(
                "nonempty allow stderr is a harness error, not an allow: "
                + repr(result.stderr)
            )
        raise HarnessError(
            "nonempty stderr is a harness error, not a deny and not an allow: "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    if result.stdout == DENY_STDOUT:
        return "deny"
    parsed = _TASK_LINE.fullmatch(result.stdout)
    if parsed is not None and int(parsed.group(1)) not in (0, 5):
        raise HarnessError(
            "wrong kr is a harness error, not a deny and not an allow: "
            + repr(result.stdout)
        )
    if allow_port(result.stdout) is not None:
        return "allow"
    raise HarnessError(
        "malformed allow stdout is a harness error, not an allow: "
        + repr(result.stdout)
    )


def compile_task(parent, root, source_text):
    """Compile ``source_text`` with ``/usr/bin/cc`` into ``<root>/task``.

    The source file sits in ``parent``. This does not start ``sandbox-exec``.
    A nonzero exit, stderr on exit 0, or a missing executable is a harness
    error, not a skip.
    """
    require_storage_path(parent)
    require_storage_path(root)
    source = os.path.join(parent, "task.c")
    with open(source, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(source_text)
    binary = os.path.join(root, "task")
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


def task_under(profile):
    """Run the compiled helper under ``profile``. No argv."""
    binary = TaskForPidProbe.binary
    root = TaskForPidProbe.root
    parent = TaskForPidProbe.parent
    if not binary or not root or not parent:
        raise HarnessError("the task helper is not compiled")
    return run_sandboxed(binary, root, parent, profile)


def run_unsandboxed(binary):
    """The helper with no profile. This does not start ``sandbox-exec``."""
    require_storage_path(binary)
    completed = subprocess.run(
        [binary],
        capture_output=True,
        text=True,
        timeout=HELPER_TIMEOUT,
    )
    return sbx.Result(
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        argv=[binary],
    )


def require_denied(profile):
    """The one helper. ``profile`` must deny ``task_for_pid``.

    The three real-file tests and the plant call this. An allow raises
    ``NotDenied``. A harness error propagates and is not a deny.
    """
    result = task_under(profile)
    if classify(result) != "deny":
        raise NotDenied(result)
    return result


def with_task_allow(text):
    """Append the one plant line. A filtered form is not this plant."""
    if not text.endswith("\n"):
        text += "\n"
    return text + ALLOW_TASK


def without_deny_default(text):
    """Delete the one ``(deny default)`` line. That deletion is not the plant."""
    if text.count(DENY_DEFAULT) != 1:
        raise HarnessError(
            f"(deny default) occurs {text.count(DENY_DEFAULT)} times, not once"
        )
    return text.replace(DENY_DEFAULT, "", 1)


def write_copy(directory, name, text):
    path = os.path.join(directory, name + ".sb")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def finding_paragraph(profile, result):
    """One CRITICAL record. The first line carries the live pin.

    The commit is ``git log -1 --format=%H HEAD -- <file>`` via
    ``last_change``. The digest is the bytes this run read. Neither value
    is stored in this file.
    """
    commit = last_change(profile["path"])
    digest = sha256_file(profile["path"])
    return (
        f"CRITICAL {IDS[profile['name']]} {commit} {pr_label(commit)} "
        f"sha256 {digest}\n"
        f"profile: {profile['rel']}\n"
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
        "The live profile allowed task_for_pid. "
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
        result = task_under(profile["path"])
        outcome = classify(result)
        if outcome != "allow":
            continue
        confirmed.append((profile, result))
        # Snapshot: a later append must not change the list this call recorded.
        write_findings(ROOT, list(confirmed))
        case_cls.recorded_allows[profile["name"]] = FINDINGS[profile["name"]]
        mark_expected(
            case_cls,
            f"test_{profile['name']}_task_for_pid_is_denied",
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


class TaskForPidProbe(unittest.TestCase):
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
        cls.parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-task-parent-"))
        cls.root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-task-root-"))
        cls.addClassCleanup(shutil.rmtree, cls.parent, ignore_errors=True)
        cls.addClassCleanup(shutil.rmtree, cls.root, ignore_errors=True)
        cls.binary = compile_task(cls.parent, cls.root, HELPER_C)
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

    def test_unsandboxed_task_for_pid_succeeds(self):
        """Without ``sandbox-exec``, the helper exits 0 and gets a task port.

        Stderr is empty. Stdout matches ``task kr=0 port=<integer >= 1>``.
        ``task kr=0 port=0`` is not that line. A failure here is an error,
        so a later deny is about the profile.
        """
        source = os.path.join(self.parent, "task.c")
        self.assertEqual(Path(source).read_text(encoding="utf-8"), HELPER_C)
        self.assertEqual(os.path.dirname(self.binary), self.root)
        self.assertTrue(self.binary.endswith(os.sep + "task"))
        self.assertNotEqual(self.root, self.parent)
        if "/var/folders" in self.binary:
            self.assertTrue(self.binary.startswith("/private/"))
        self.assertEqual(os.path.realpath(self.binary), self.binary)
        self.assertEqual(os.path.realpath(self.root), self.root)
        self.assertEqual(os.path.realpath(self.parent), self.parent)
        result = run_unsandboxed(self.binary)
        self.assertEqual(result.argv, [self.binary])
        self.assertEqual(len(result.argv), 1)
        self.assertNotIn(sbx.SANDBOX_EXEC, result.argv)
        self.assertIsNone(sbx.profile_error(result))
        self.assertEqual(result.exit_code, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        port = allow_port(result.stdout)
        self.assertIsNotNone(port, result.stdout)
        self.assertGreaterEqual(port, 1)
        self.assertNotEqual(result.stdout, "task kr=0 port=0\n")
        self.assertEqual(classify(result), "allow")

    def test_compile_failure_is_an_error(self):
        """``/usr/bin/cc`` on an empty source is a harness error, not a skip."""
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-task-empty-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-task-empty-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with self.assertRaises(HarnessError) as caught:
            compile_task(parent, root, "")
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
        self.assertEqual(result.stdout, DENY_STDOUT)
        self.assertEqual(classify(result), "deny")
        return result

    def test_wallet_task_for_pid_is_denied(self):
        """The real wallet profile denies ``task_for_pid``."""
        self._expect_real_deny(sbx.WALLET_CONFINE_SB)

    def test_did_task_for_pid_is_denied(self):
        """The real did profile denies ``task_for_pid``."""
        did = sbx.REPO_ROOT / "capsules/did-provider/confine.sb"
        self._expect_real_deny(did)

    def test_model_task_for_pid_is_denied(self):
        """The real model profile denies ``task_for_pid``.

        ``file-read-data (literal "/")`` is not a reason to skip this file.
        The helper starts under it.
        """
        model = sbx.REPO_ROOT / "capsules/model-provider/confine.sb"
        self._expect_real_deny(model)

    def test_falsifier_allow_mach_priv_task_port_is_caught(self):
        """Appending ``(allow mach-priv-task-port)`` lets ``task_for_pid`` succeed.

        Each real file contains that text zero times and ``(deny default)``
        once, unless a recorded allow already planted the line. The temp
        baseline from ``_source_for_plant`` is that text with one exact plant
        line removed. A temp copy appends that one line. The copy's stdout
        matches ``task kr=0 port=<integer >= 1>``, and the helper pointed at
        the copy fails the deny check. A filtered allow is not the plant.
        Replacing ``(deny default)`` with ``(allow default)`` is not the plant.
        Deleting ``(deny default)`` on the wallet copy still denies. Appending
        a mach-lookup allow on the wallet copy still denies. The repo profile
        bytes stay unchanged.
        """
        before = {
            profile["rel"]: sha256_file(profile["path"]) for profile in PROFILES
        }
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-task-profile-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        try:
            for profile in PROFILES:
                with self.subTest(profile=profile["name"]):
                    text = profile["path"].read_text(encoding="utf-8")
                    baseline = self._source_for_plant(profile["name"], text)
                    if profile["name"] not in type(self).recorded_allows:
                        self.assertEqual(text.count("(allow mach-priv-task-port)"), 0)
                        self.assertEqual(text.count(DENY_DEFAULT), 1)
                        self.assertEqual(baseline, text)
                    self.assertEqual(baseline.count(ALLOW_TASK), 0)
                    self.assertEqual(baseline.count(DENY_DEFAULT), 1)
                    self.assertTrue(baseline.endswith("\n"))
                    planted = with_task_allow(baseline)
                    self.assertEqual(planted, baseline + "(allow mach-priv-task-port)\n")
                    self.assertEqual(planted.count("(allow mach-priv-task-port)"), 1)
                    self.assertEqual(planted.count(DENY_DEFAULT), 1)
                    self.assertNotIn("(allow mach-priv-task-port (", planted)
                    self.assertEqual(
                        planted.count("(allow default)"),
                        baseline.count("(allow default)"),
                    )
                    copy = write_copy(directory, profile["name"] + "-allow", planted)
                    self.assertEqual(Path(copy).read_text(encoding="utf-8"), planted)
                    self.assertNotEqual(
                        os.path.realpath(copy), os.path.realpath(profile["path"])
                    )
                    with self.assertRaises(NotDenied) as caught:
                        require_denied(copy)
                    result = caught.exception.result
                    self.assertIn("ALLOW", str(caught.exception))
                    self.assertIsNone(sbx.profile_error(result))
                    self.assertEqual(result.exit_code, 0)
                    self.assertEqual(result.stderr, "")
                    port = allow_port(result.stdout)
                    self.assertIsNotNone(port, result.stdout)
                    self.assertGreaterEqual(port, 1)
                    self.assertEqual(classify(result), "allow")
                    self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
                    self.assertIn(copy, result.argv)
                    self.assertNotIn(os.fspath(profile["path"]), result.argv)

            with self.subTest(profile="wallet-deleted"):
                wallet = PROFILES[0]
                self.assertEqual(wallet["name"], "wallet")
                baseline = self._source_for_plant(
                    "wallet", wallet["path"].read_text(encoding="utf-8")
                )
                deleted = without_deny_default(baseline)
                self.assertNotIn("(deny default)", deleted)
                self.assertEqual(deleted.count("(allow mach-priv-task-port)"), 0)
                self.assertNotIn("(allow default)", deleted)
                removed = write_copy(directory, "wallet-deleted", deleted)
                finding = type(self).recorded_allows.get("wallet")
                try:
                    denied = require_denied(removed)
                except NotDenied as caught:
                    if not finding:
                        raise
                    method = getattr(type(self), "test_wallet_task_for_pid_is_denied")
                    self.assertTrue(
                        getattr(method, "__unittest_expecting_failure__", False)
                    )
                    self.assertIn(finding, method.__doc__ or "")
                    self.assertIn("ALLOW", str(caught))
                else:
                    self.assertEqual(denied.stdout, DENY_STDOUT)
                    self.assertEqual(denied.stderr, "")
                    self.assertEqual(denied.exit_code, 0)

            with self.subTest(profile="wallet-lookup"):
                wallet = PROFILES[0]
                self.assertEqual(wallet["name"], "wallet")
                baseline = self._source_for_plant(
                    "wallet", wallet["path"].read_text(encoding="utf-8")
                )
                if not baseline.endswith("\n"):
                    baseline += "\n"
                looked = baseline + MACH_LOOKUP
                self.assertEqual(looked.count(MACH_LOOKUP), 1)
                self.assertEqual(looked.count(ALLOW_TASK), 0)
                self.assertEqual(baseline.count(DENY_DEFAULT), 1)
                self.assertNotIn("(allow mach-priv-task-port)", looked)
                looked_path = write_copy(directory, "wallet-lookup", looked)
                self.assertEqual(Path(looked_path).read_text(encoding="utf-8"), looked)
                denied = require_denied(looked_path)
                self.assertEqual(denied.stdout, DENY_STDOUT)
                self.assertEqual(denied.stderr, "")
                self.assertEqual(denied.exit_code, 0)
                self.assertEqual(classify(denied), "deny")
                self.assertEqual(denied.argv[0], sbx.SANDBOX_EXEC)
                self.assertIn(looked_path, denied.argv)
                self.assertNotIn(os.fspath(wallet["path"]), denied.argv)
        finally:
            require_unchanged(before)

    def _source_for_plant(self, name, text):
        """The text the temp plant edits. A recorded allow does not skip this.

        The deny test carries the finding-linked expected failure. The live
        file is not edited. One exact plant line is removed from the copy
        so the append is still that one line.
        """
        finding = type(self).recorded_allows.get(name)
        if finding is None:
            if "(allow mach-priv-task-port)" in text:
                raise AssertionError(f"{name} source contains (allow mach-priv-task-port)")
            return text
        method = getattr(type(self), f"test_{name}_task_for_pid_is_denied")
        if not getattr(method, "__unittest_expecting_failure__", False):
            raise HarnessError(f"{name} allow has no finding-linked expected failure")
        if finding not in (method.__doc__ or ""):
            raise HarnessError(f"{name} allow docstring does not name {finding}")
        occurrences = text.count(ALLOW_TASK)
        if occurrences > 1:
            raise HarnessError(
                f"(allow mach-priv-task-port) occurs {occurrences} times, not zero or one"
            )
        if occurrences == 1:
            text = text.replace(ALLOW_TASK, "", 1)
        return text


class TaskForPidRules(unittest.TestCase):
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
        probe_names = unittest.defaultTestLoader.getTestCaseNames(TaskForPidProbe)
        for missing in ((sbx.SANDBOX_EXEC,), (CC,), (sbx.SANDBOX_EXEC, CC)):
            with self.subTest(missing=missing), patch.object(
                os.path, "isfile", side_effect=lambda path: path not in missing
            ), patch(
                __name__ + ".compile_task",
                side_effect=AssertionError("missing-tool probe compiled a helper"),
            ) as compiled, patch.object(
                sbx, "run",
                side_effect=AssertionError("missing-tool probe launched a helper"),
            ) as launched:
                class MissingTools(TaskForPidProbe):
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

        Both tools are injected as present. The plant source is still produced. A recorded
        allow without that mark, a docstring that omits the finding, and a
        second plant line are each their own harness error.
        """
        with patch.object(os.path, "isfile", return_value=True):
            self.assertIsNone(skip_reason())
            self.assertTrue(os.path.isfile(CC))
            self.assertTrue(os.path.isfile(sbx.SANDBOX_EXEC))
        text = "(version 1)\n(deny default)\n(allow mach-priv-task-port)\n"
        clean = "(version 1)\n(deny default)\n"

        class Recorded(TaskForPidProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Recorded, "test_wallet_task_for_pid_is_denied", FINDINGS["wallet"])
        try:
            case = Recorded("test_falsifier_allow_mach_priv_task_port_is_caught")
            baseline = case._source_for_plant("wallet", text)
            self.assertEqual(baseline, clean)
            self.assertEqual(case._source_for_plant("did", clean), clean)
        finally:
            Recorded.doClassCleanups()

        class Bare(TaskForPidProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        bare = Bare("test_falsifier_allow_mach_priv_task_port_is_caught")
        with self.assertRaises(HarnessError) as unmarked:
            bare._source_for_plant("wallet", text)
        self.assertEqual(
            str(unmarked.exception),
            "wallet allow has no finding-linked expected failure",
        )
        self.assertNotIsInstance(unmarked.exception, unittest.SkipTest)

        class WrongDoc(TaskForPidProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        def body(self):
            raise NotDenied(
                sbx.Result(exit_code=0, stdout="task kr=0 port=1\n", stderr="", argv=[])
            )

        body.__doc__ = "plain"
        body.__unittest_expecting_failure__ = True
        WrongDoc.test_wallet_task_for_pid_is_denied = body
        wrong = WrongDoc("test_falsifier_allow_mach_priv_task_port_is_caught")
        with self.assertRaises(HarnessError) as unnamed:
            wrong._source_for_plant("wallet", text)
        self.assertEqual(
            str(unnamed.exception),
            f"wallet allow docstring does not name {FINDINGS['wallet']}",
        )

        class Twice(TaskForPidProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Twice, "test_wallet_task_for_pid_is_denied", FINDINGS["wallet"])
        try:
            twice = Twice("test_falsifier_allow_mach_priv_task_port_is_caught")
            with self.assertRaises(HarnessError) as extra:
                twice._source_for_plant("wallet", text + ALLOW_TASK)
            self.assertEqual(
                str(extra.exception),
                "(allow mach-priv-task-port) occurs 2 times, not zero or one",
            )
        finally:
            Twice.doClassCleanups()

        class Clean(TaskForPidProbe):
            recorded_allows = {}

        plain = Clean("test_falsifier_allow_mach_priv_task_port_is_caught")
        with self.assertRaises(AssertionError) as present:
            plain._source_for_plant("wallet", text)
        self.assertEqual(
            str(present.exception),
            "wallet source contains (allow mach-priv-task-port)",
        )
        self.assertEqual(plain._source_for_plant("wallet", clean), clean)
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

        rel = "tmp/task-confine.sb"
        self.assertNotIn(rel, START_SHA)
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-task-byte-"))
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

    def test_compile_stderr_is_an_error(self):
        """Exit 0 with compiler stderr is its own harness error.

        The injected result is ``CompletedProcess(returncode=0, stdout="",
        stderr="compiler warning\\n")`` and the executable check is true.
        A nonzero exit, a missing executable, and an unresolved storage path
        each keep a different reason. Empty stderr still returns the binary.
        """
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-task-cc-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-task-cc-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        binary = os.path.join(root, "task")
        source = "int main(void) { return 0; }\n"
        reasons = []

        def compiled(completed, access=None):
            runners = patch.object(subprocess, "run", return_value=completed)
            if access is None:
                with runners:
                    return compile_task(parent, root, source)
            with runners, patch.object(os, "access", return_value=access):
                return compile_task(parent, root, source)

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
            ("parent", "/var/folders/cc/task-parent", root),
            ("root", parent, "/var/folders/cc/task-root"),
        ):
            bad = compile_parent if label == "parent" else compile_root
            expected = (
                f"execvp: {bad} contains /var/folders without the /private prefix"
            )
            with self.subTest(path=label), patch.object(
                subprocess, "run", side_effect=refuse_cc
            ):
                with self.assertRaises(HarnessError) as caught:
                    compile_task(compile_parent, compile_root, source)
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
        clean = b"(version 1)\n(deny default)\n"
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-task-bytes-"))
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
                            item["rel"]: before_digest if item is wallet else sha256_file(item["path"])
                            for item in profiles
                        })
                self.assertEqual(seen, [(wallet["rel"], before_digest, after_digest)])
                self.assertEqual(
                    str(caught.exception), f"the probe changed {wallet['rel']}"
                )
                wallet["path"].write_bytes(clean)

            class Plant(TaskForPidProbe):
                recorded_allows = {}

            state = {"mutate": False}

            def fake_denied(profile):
                profile = os.fspath(profile)
                text = Path(profile).read_text(encoding="utf-8")
                if "(allow mach-priv-task-port)" in text:
                    raise NotDenied(sbx.Result(
                        exit_code=0,
                        stdout="task kr=0 port=1\n",
                        stderr="",
                        argv=[
                            sbx.SANDBOX_EXEC, "-f", profile,
                            "/private/task",
                        ],
                    ))
                if state["mutate"] and profile.endswith(os.sep + "wallet-deleted.sb"):
                    wallet["path"].write_bytes(after_bytes)
                return sbx.Result(
                    exit_code=0,
                    stdout=DENY_STDOUT,
                    stderr="",
                    argv=[sbx.SANDBOX_EXEC, "-f", profile],
                )

            case = Plant("test_falsifier_allow_mach_priv_task_port_is_caught")
            try:
                with patch(__name__ + ".PROFILES", profiles), patch(
                    __name__ + ".require_denied", new=fake_denied
                ), patch(__name__ + ".changed", new=spy):
                    with self.subTest(path="falsifier-equal"):
                        seen.clear()
                        state["mutate"] = False
                        case.test_falsifier_allow_mach_priv_task_port_is_caught()
                        self.assertEqual(seen, equal_pairs)
                    with self.subTest(path="falsifier-changed"):
                        seen.clear()
                        state["mutate"] = True
                        wallet["path"].write_bytes(clean)
                        with self.assertRaises(AssertionError) as caught:
                            case.test_falsifier_allow_mach_priv_task_port_is_caught()
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
        return (
            (
                "wrong exit",
                sbx.Result(
                    exit_code=2, stdout=DENY_STDOUT, stderr="", argv=["/private/task"],
                ),
                "wrong exit 2 is a harness error, not a deny and not an allow. "
                "stdout='task kr=5 port=0\\n' stderr=''",
            ),
            (
                "wrong kr",
                sbx.Result(
                    exit_code=0,
                    stdout="task kr=4 port=0\n",
                    stderr="",
                    argv=["/private/task"],
                ),
                "wrong kr is a harness error, not a deny and not an allow: "
                "'task kr=4 port=0\\n'",
            ),
            (
                "nonempty deny stderr",
                sbx.Result(
                    exit_code=0,
                    stdout=DENY_STDOUT,
                    stderr="noise\n",
                    argv=["/private/task"],
                ),
                "nonempty deny stderr is a harness error, not a deny: 'noise\\n'",
            ),
            (
                "malformed allow stdout",
                sbx.Result(
                    exit_code=0,
                    stdout="task kr=0 port=0\n",
                    stderr="",
                    argv=["/private/task"],
                ),
                "malformed allow stdout is a harness error, not an allow: "
                "'task kr=0 port=0\\n'",
            ),
            (
                "nonempty allow stderr",
                sbx.Result(
                    exit_code=0,
                    stdout="task kr=0 port=1\n",
                    stderr="noise\n",
                    argv=["/private/task"],
                ),
                "nonempty allow stderr is a harness error, not an allow: 'noise\\n'",
            ),
            (
                "nonempty stderr",
                sbx.Result(
                    exit_code=0, stdout="bad\n", stderr="noise\n", argv=["/private/task"],
                ),
                "nonempty stderr is a harness error, not a deny and not an allow: "
                "stdout='bad\\n' stderr='noise\\n'",
            ),
            (
                "profile error",
                sbx.Result(
                    exit_code=sbx.PROFILE_ERROR_EXIT,
                    stdout=DENY_STDOUT,
                    stderr="Operation not permitted\n",
                    argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/task"],
                ),
                "profile error: profile read or compile error: sandbox-exec exited 65 "
                "and started no program, so nothing was denied -- a harness error, "
                "not a deny and not an allow. stderr='Operation not permitted\\n'",
            ),
        )

    def test_classifier_refusal_reasons(self):
        """Each classifier refusal preserves its exact, distinct reason."""
        self.assertIsNone(allow_port("task kr=0 port=0\n"))
        self.assertEqual(allow_port("task kr=0 port=1\n"), 1)
        self.assertEqual(
            classify(sbx.Result(
                exit_code=0, stdout="task kr=0 port=1\n", stderr="", argv=["/private/task"],
            )),
            "allow",
        )
        self.assertEqual(
            classify(sbx.Result(
                exit_code=0, stdout=DENY_STDOUT, stderr="", argv=["/private/task"],
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
                if label == "malformed allow stdout":
                    self.assertEqual(result.stdout, "task kr=0 port=0\n")
                    self.assertIsNone(allow_port(result.stdout))
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
        self.launch_guard.assert_not_called()

    def test_observe_propagates_every_refusal(self):
        """A failed observation stops before any later success or finding mark."""
        deny = sbx.Result(
            exit_code=0, stdout=DENY_STDOUT, stderr="", argv=["/private/task"],
        )
        for label, refused, expected in self.refusal_samples():
            for preceding in ([], [deny], [deny, deny]):
                with self.subTest(reason=label, position=len(preceding)):
                    class Observed(TaskForPidProbe):
                        pass

                    with patch(
                        __name__ + ".task_under",
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

        # Three consecutive profile errors also stop on the first refusal.
        _label, refused, expected = self.refusal_samples()[-1]
        with patch(__name__ + ".task_under", side_effect=[refused] * 3) as opened:
            with self.assertRaises(HarnessError) as caught:
                observe(Observed)
        self.assertEqual(str(caught.exception), expected)
        self.assertEqual(opened.call_count, 1)

    def test_observe_records_allow_before_later_error(self):
        """A confirmed allow is written before the next profile is classified.

        Wallet allow, then a did profile error: the writer records the wallet
        allow, the wallet deny test is marked, and the error still propagates.
        Model is not opened. A did allow before a model error is recorded too.
        """
        allow = sbx.Result(
            exit_code=0,
            stdout="task kr=0 port=1\n",
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/task"],
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
            class Observed(TaskForPidProbe):
                pass

            pending = list(results)
            order = []

            def opened(path):
                order.append(("open", path))
                return pending.pop(0)

            def written(_repo, items):
                order.append(("write", [item[0]["name"] for item in items]))

            with patch(__name__ + ".task_under", side_effect=opened), patch(
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
            method = observed.test_wallet_task_for_pid_is_denied
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
            did_method = observed.test_did_task_for_pid_is_denied
            self.assertTrue(getattr(did_method, "__unittest_expecting_failure__", False))
            self.assertIn(FINDINGS["did"], did_method.__doc__ or "")
        finally:
            if observed is not None:
                observed.doClassCleanups()
        self.launch_guard.assert_not_called()

    def test_recorded_allow_is_expected_failure(self):
        """A recorded allow is an expected failure whose docstring names the finding.

        The result is injected. The finding is written under a temp repo.
        Its first line contains CRITICAL and injected provenance.
        ``CRITICAL.md`` receives that same paragraph. The marked
        test is an expected failure, so the gate stays green. The same
        raise without the mark is a failure.
        """
        provenance = self.enter_patch(patch(__name__ + ".last_change", return_value="a" * 40))
        self.enter_patch(patch(__name__ + ".pr_label", return_value="PR fixture"))
        self.enter_patch(patch(__name__ + ".sha256_file", return_value="b" * 64))
        allow = sbx.Result(
            exit_code=0,
            stdout="task kr=0 port=1\n",
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/task"],
        )
        self.assertIsNone(sbx.profile_error(allow))
        self.assertEqual(classify(allow), "allow")
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
        with tempfile.TemporaryDirectory(prefix="ccrt-task-finding-") as tmp:
            repo = Path(tmp)
            self.assertEqual(write_findings(repo, []), [])
            self.assertFalse((repo / "lab" / "redteam" / "CRITICAL.md").exists())
            written = write_findings(repo, [(wallet, allow), (did, allow)])
            self.assertEqual(written, [FINDINGS["wallet"]])
            body = (repo / FINDINGS["wallet"]).read_text(encoding="utf-8")
            self.assertFalse((repo / FINDINGS["model"]).exists())
            wallet_paragraph = finding_paragraph(wallet, allow)
            did_paragraph = finding_paragraph(did, allow)
            self.assertEqual(body, wallet_paragraph + did_paragraph)
            self.assertIn("CRITICAL", wallet_paragraph.splitlines()[0])
            self.assertIn(last_change(wallet["path"]), wallet_paragraph.splitlines()[0])
            self.assertIn(sha256_file(wallet["path"]), wallet_paragraph.splitlines()[0])
            self.assertIn(pr_label(last_change(wallet["path"])), wallet_paragraph)
            self.assertIn(f"profile: {wallet['rel']}", wallet_paragraph)
            listed = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertIn(wallet_paragraph, listed)
            self.assertIn(did_paragraph, listed)
            model_written = write_findings(repo, [(model, allow)])
            self.assertEqual(model_written, [FINDINGS["model"]])
            model_paragraph = finding_paragraph(model, allow)
            model_body = (repo / FINDINGS["model"]).read_text(encoding="utf-8")
            self.assertEqual(model_body, model_paragraph)
            self.assertIn("CRITICAL", model_paragraph.splitlines()[0])
            listed_again = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertIn(model_paragraph, listed_again)
            self.assertEqual(listed_again.count(model_paragraph), 1)
            again = write_findings(repo, [(model, allow)])
            relisted = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertEqual(relisted, listed_again)
            self.assertEqual(again, [FINDINGS["model"]])
        after = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        self.assertEqual(before, after)

        class Unmarked(unittest.TestCase):
            def test_wallet_task_for_pid_is_denied(self):
                """plain"""
                raise NotDenied(allow)

        unmarked = unittest.TestResult()
        Unmarked("test_wallet_task_for_pid_is_denied").run(unmarked)
        self.assertEqual(len(unmarked.failures), 1)
        self.assertEqual(unmarked.expectedFailures, [])
        self.assertEqual(unmarked.errors, [])

        class Recorded(unittest.TestCase):
            def test_wallet_task_for_pid_is_denied(self):
                """plain"""
                raise NotDenied(allow)

        mark_expected(Recorded, "test_wallet_task_for_pid_is_denied", FINDINGS["wallet"])
        method = Recorded.test_wallet_task_for_pid_is_denied
        self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
        self.assertIn("CRITICAL-confine-054.md", method.__doc__)
        self.assertIn(FINDINGS["wallet"], method.__doc__)
        recorded = unittest.TestResult()
        Recorded("test_wallet_task_for_pid_is_denied").run(recorded)
        self.assertEqual(len(recorded.expectedFailures), 1)
        self.assertEqual(recorded.failures, [])
        self.assertEqual(recorded.errors, [])
        self.assertEqual(recorded.unexpectedSuccesses, [])
        self.assertTrue(recorded.wasSuccessful())
        self.assertEqual(
            {call.args[0] for call in provenance.call_args_list},
            {wallet["path"], did["path"], model["path"]},
        )
        self.launch_guard.assert_not_called()
        Recorded.doClassCleanups()

    def test_recorded_allow_keeps_complete_probe_suite_green(self):
        """Run every real probe method against injected tools and profile text.

        Each provider and all providers together can already grant
        mach-priv-task-port. Only their deny tests expect failure. The plant
        still runs, including the wallet deletion and the mach-lookup copy,
        and nothing skips.
        """
        method_names = unittest.defaultTestLoader.getTestCaseNames(TaskForPidProbe)
        scenarios = ((), ("wallet",), ("did",), ("model",), ("wallet", "did", "model"))
        for allowed in scenarios:
            with self.subTest(allowed=allowed), tempfile.TemporaryDirectory(
                prefix="ccrt-task-suite-"
            ) as tmp:
                repo = Path(tmp).resolve()
                profiles = []
                for original in PROFILES:
                    profile = dict(original)
                    profile["path"] = repo / profile["rel"]
                    profile["path"].parent.mkdir(parents=True, exist_ok=True)
                    text = "(version 1)\n(deny default)\n"
                    if profile["name"] in allowed:
                        text = with_task_allow(text)
                    profile["path"].write_text(text, encoding="utf-8")
                    profiles.append(profile)

                def injected_compile(parent, root, source_text):
                    if not source_text:
                        raise HarnessError(
                            f"{CC} failed with exit 1: empty source "
                            "-- a harness error, not a skip and not a deny"
                        )
                    Path(parent, "task.c").write_text(source_text, encoding="utf-8")
                    binary = Path(root, "task")
                    binary.write_text(
                        "injected executable; never launched\n", encoding="utf-8",
                    )
                    return str(binary)

                def injected_control(binary):
                    return sbx.Result(
                        exit_code=0,
                        stdout="task kr=0 port=1\n",
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
                        stdout="task kr=0 port=1\n" if ALLOW_TASK in text else DENY_STDOUT,
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
                    __name__ + ".compile_task", side_effect=injected_compile
                ), patch(__name__ + ".run_unsandboxed", side_effect=injected_control), patch.object(
                    sbx, "run", side_effect=injected_sandbox
                ), patch(__name__ + ".last_change", return_value="a" * 40), patch(
                    __name__ + ".pr_label", return_value="PR fixture"
                ), patch.multiple(
                    TaskForPidProbe, binary=None, root=None, parent=None,
                    skip_reason=None, recorded_allows={},
                ):
                    result = unittest.TestResult()
                    unittest.defaultTestLoader.loadTestsFromTestCase(TaskForPidProbe).run(result)
                    self.assertEqual(result.testsRun, len(method_names))
                    self.assertEqual(result.errors, [])
                    self.assertEqual(result.failures, [])
                    self.assertEqual(result.unexpectedSuccesses, [])
                    self.assertEqual(result.skipped, [])
                    self.assertIsNone(skip_reason())
                    self.assertEqual(len(result.expectedFailures), len(allowed))
                    self.assertEqual(
                        {case._testMethodName for case, _error in result.expectedFailures},
                        {f"test_{name}_task_for_pid_is_denied" for name in allowed},
                    )
                    self.assertEqual(
                        sorted(
                            os.path.basename(path)
                            for path in launched
                            if path.endswith("-allow.sb")
                        ),
                        ["did-allow.sb", "model-allow.sb", "wallet-allow.sb"],
                    )
                    self.assertTrue(
                        any(path.endswith(os.sep + "wallet-deleted.sb") for path in launched)
                    )
                    self.assertTrue(
                        any(path.endswith(os.sep + "wallet-lookup.sb") for path in launched)
                    )
                    self.assertTrue(result.wasSuccessful())
                    self.assertEqual(
                        TaskForPidProbe.recorded_allows,
                        {name: FINDINGS[name] for name in allowed},
                    )
                    for name in allowed:
                        body = (repo / FINDINGS[name]).read_text(encoding="utf-8")
                        profile = next(item for item in profiles if item["name"] == name)
                        self.assertIn(f"profile: {profile['rel']}", body)
                        self.assertIn(sha256_file(profile["path"]), body)
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
            exit_code=0, stdout="task kr=0 port=1\n", stderr="", argv=["/private/task"],
        )
        deny = sbx.Result(
            exit_code=0, stdout=DENY_STDOUT, stderr="", argv=["/private/task"],
        )
        for profile in PROFILES:
            for label, refused, expected in self.refusal_samples():
                with self.subTest(profile=profile["name"], reason=label):
                    class Recorded(TaskForPidProbe):
                        skip_reason = None

                    def observation(path, profile=profile, allow=allow, deny=deny):
                        return allow if path == profile["path"] else deny

                    with patch(__name__ + ".task_under", side_effect=observation), patch(
                        __name__ + ".write_findings"
                    ) as writer:
                        observe(Recorded)
                    writer.assert_called_once_with(ROOT, [(profile, allow)])
                    method_name = f"test_{profile['name']}_task_for_pid_is_denied"
                    method = getattr(Recorded, method_name)
                    self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
                    self.assertIn(FINDINGS[profile["name"]], method.__doc__)
                    result = unittest.TestResult()
                    try:
                        with patch(
                            __name__ + ".task_under", side_effect=[refused, deny]
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
            argv=["/private/task"],
        )
        wrong_kr = sbx.Result(
            exit_code=0,
            stdout="task kr=13 port=0\n",
            stderr="",
            argv=["/private/task"],
        )
        profile_error = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout="task kr=0 port=1\n",
            stderr="Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC],
        )
        injected = (wrong_exit, wrong_kr, profile_error)
        for result in injected:
            with self.assertRaises(HarnessError):
                classify(result)

        class Body(unittest.TestCase):
            def test_wallet_task_for_pid_is_denied(self):
                classify(wrong_exit)

        body = unittest.TestResult()
        Body("test_wallet_task_for_pid_is_denied").run(body)
        self.assertEqual(len(body.errors), 1)
        self.assertEqual(body.failures, [])
        self.assertEqual(body.expectedFailures, [])
        self.assertEqual(body.skipped, [])

        class Setup(unittest.TestCase):
            def setUp(self):
                raise HarnessError("wrong exit 2 is a harness error, not a deny")

            @unittest.expectedFailure
            def test_wallet_task_for_pid_is_denied(self):
                raise NotDenied(wrong_exit)

        setup = unittest.TestResult()
        Setup("test_wallet_task_for_pid_is_denied").run(setup)
        self.assertEqual(len(setup.errors), 1)
        self.assertEqual(setup.expectedFailures, [])
        self.assertEqual(setup.skipped, [])
        self.assertIn("wrong exit", setup.errors[0][1])

    def test_unresolved_storage_path_is_an_error(self):
        """A ``/var/folders`` storage path without ``/private`` errors before launch."""
        bad_parent = "/var/folders/cc/task-parent"
        bad_root = "/var/folders/cc/task-root"
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
                compile_task(
                    bad_parent,
                    "/private/task-root",
                    "int main(void) { return 0; }\n",
                )
            compile_message = str(compile_caught.exception)
            self.assertIn(bad_parent, compile_message)
            self.assertIn("/var/folders", compile_message)
            self.assertNotIn("/private" + bad_parent, compile_message)

            with self.assertRaises(HarnessError) as launch_caught:
                run_sandboxed(
                    "/private/task",
                    bad_root,
                    "/private/parent",
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
