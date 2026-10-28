"""Probe a loaded-kext query on the wallet, did, and model profiles.

Grade row 12 rests on those seatbelt profiles. The helper asks whether
``com.apple.kpi.libkern`` reports ``OSBundleStarted``, then whether a URL
exists for that identifier. It does not load or unload an extension.
Confined launches go through ``sbx.run`` only. The helper prints two lines
and returns 0.

A deny is exit 0, stdout ``kext info=0`` and ``kext url=0``, and the
two-line kernel refusal. An allow is exit 0, stdout ``kext info=1`` and
``kext url=0``, and empty stderr. ``kext info=1`` and ``kext url=1`` with
empty stderr is the unsandboxed line, and under a profile it is an allow
of the query. ``kext info=0`` and ``kext url=1`` with the deny stderr is
the mach-lookup result: not an allow and not the live-profile deny.

The plant appends ``(allow system-kext-query)``. The three profiles are
the live files. ``setUpModule`` records each sha256. ``tearDownModule``
calls ``changed``. An owner edit between those two points raises
``the probe changed <rel>``. This file stores no commit, pull request,
or digest.

An allow on a real profile is CRITICAL. Wallet or did:
``findings/CRITICAL-confine-075.md``. Model:
``findings/CRITICAL-cc-model-confine-075.md``. The finding's first line
contains CRITICAL and names the commit from ``last_change``, ``pr_label``
of that commit, and the sha256 of the bytes this run read. The helper
line is ``result.command``. The finding names ``kext`` when ``kext info``
is 1. The same paragraph is appended to ``CRITICAL.md``. With no allow,
this module writes neither file.

A recorded allow keeps the gate green. The deny test is an expected
failure and its docstring names that finding file. A later harness error
still fails. A recorded allow is not a skip. This module skips only when
``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` is missing.

``KextProbe`` compiles once and launches. ``KextRules`` does not compile
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
SOURCE_NAME = "kextq.c"
BINARY_NAME = "kextq"
CC_TAIL = ("-framework", "IOKit", "-framework", "CoreFoundation")

DENY_STDOUT = "kext info=0\nkext url=0\n"
ALLOW_STDOUT = "kext info=1\nkext url=0\n"
UNSANDBOXED_STDOUT = "kext info=1\nkext url=1\n"
QUERY_STILL_STDOUT = "kext info=0\nkext url=1\n"
DENY_STDERR = (
    "(kernel) Failed to query kext info (MAC policy error 0x1).\n"
    "Failed to read loaded kext info from kernel - (libkern/kext) internal error.\n"
)

PLANT_PHRASE = "(allow system-kext-query)"
PLANT = PLANT_PHRASE + "\n"
# The wildcard allows the same query. It is a different line, so the exact
# plant count stays zero and a recorded strip must leave it in place.
STAR = "(allow system-kext*)\n"
# A bundle-id filter is not the operation this helper hits. The strip must
# leave it in place, and the copy must keep the live deny.
FILTERED_QUERY = (
    '(allow system-kext-query (kext-bundle-id "com.apple.kpi.libkern"))\n'
)
LOOKUP = "(allow mach-lookup)\n"
DENY_DEFAULT = "(deny default)\n"

HELPER_C = """\
#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/kext/KextManager.h>
int main(void) {
    CFStringRef ident = CFSTR("com.apple.kpi.libkern");
    CFStringRef key = CFSTR("OSBundleStarted");
    CFArrayRef ids = CFArrayCreate(NULL, (const void **)&ident, 1, &kCFTypeArrayCallBacks);
    CFArrayRef keys = CFArrayCreate(NULL, (const void **)&key, 1, &kCFTypeArrayCallBacks);
    CFDictionaryRef info = KextManagerCopyLoadedKextInfo(ids, keys);
    int count = info == NULL ? 0 : (int)CFDictionaryGetCount(info);
    printf("kext info=%d\\n", count > 0);
    if (info != NULL) CFRelease(info);
    CFURLRef url = KextManagerCreateURLForBundleIdentifier(NULL, ident);
    printf("kext url=%d\\n", url != NULL);
    if (url != NULL) CFRelease(url);
    CFRelease(ids);
    CFRelease(keys);
    return 0;
}
"""

FINDINGS = {
    "wallet": "lab/redteam/findings/CRITICAL-confine-075.md",
    "did": "lab/redteam/findings/CRITICAL-confine-075.md",
    "model": "lab/redteam/findings/CRITICAL-cc-model-confine-075.md",
}
IDS = {
    "wallet": "CRITICAL-confine-075",
    "did": "CRITICAL-confine-075",
    "model": "CRITICAL-cc-model-confine-075",
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
# Each of these keeps the live deny. None is the exact plant line.
STILL_DENY_EDITS = (
    ("wallet-kext-load", "(allow system-kext-load)\n"),
    (
        "wallet-kext-load-id",
        '(allow system-kext-load (kext-bundle-id "com.apple.kpi.libkern"))\n',
    ),
    ("wallet-kext-query-id", FILTERED_QUERY),
    ("wallet-iokit", "(allow iokit-open)\n"),
    ("wallet-socket", "(allow system-socket)\n"),
    ("wallet-network", "(allow network*)\n"),
    ("wallet-signal", "(allow signal)\n"),
    ("wallet-fork", "(allow process-fork)\n"),
    ("wallet-revoke", "(allow file-revoke)\n"),
    ("wallet-fsctl", "(allow system-fsctl)\n"),
    ("wallet-pty", "(allow pseudo-tty)\n"),
    ("wallet-debug", "(allow system-debug)\n"),
    ("wallet-extension", "(allow file-issue-extension)\n"),
    ("wallet-register", "(allow mach-register)\n"),
    (
        "wallet-system-ext",
        '(allow file-read* (subpath "/System/Library/Extensions"))\n',
    ),
    (
        "wallet-library-ext",
        '(allow file-read* (subpath "/Library/Extensions"))\n',
    ),
)
STILL_DENY_COPIES = ("wallet-deleted", *(name for name, _line in STILL_DENY_EDITS))

START_SHA = {}


class NotDenied(AssertionError):
    """The profile returned loaded kext info."""

    def __init__(self, result):
        self.result = result
        super().__init__(
            "ALLOW: loaded kext info was returned under the profile.\n"
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


def names_kext(stdout):
    """True when the query returned loaded kext info."""
    return "kext info=1" in stdout


def sandbox_outcome(text):
    """Stdout and stderr for an injected profile. The live probe does not call this.

    ``sbx.run`` is the live path. Injected suites share this one stand-in so
    the plant, the wildcard, and the mach-lookup copy cannot drift apart.
    """
    if PLANT in text or STAR in text:
        return ALLOW_STDOUT, ""
    if LOOKUP in text:
        return QUERY_STILL_STDOUT, DENY_STDERR
    return DENY_STDOUT, DENY_STDERR


def classify(result):
    """``deny``, ``allow``, or a harness error.

    Asks ``sbx.profile_error`` before it reads a deny or an allow. Exit 65
    is a profile error even when stderr says ``Operation not permitted``,
    ``Backtrace:``, or ``MAC policy``. The URL-only line is not the live
    deny: that result belongs to mach-lookup, and treating it as this
    probe's deny would hide the split.
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
    stdout = result.stdout
    stderr = result.stderr
    if stdout == ALLOW_STDOUT:
        if stderr != "":
            raise HarnessError(
                "nonempty stderr on the allow stdout is a harness error, not an allow: "
                + repr(stderr)
            )
        return "allow"
    if stdout == UNSANDBOXED_STDOUT:
        if stderr != "":
            raise HarnessError(
                "nonempty stderr on kext info=1 kext url=1 is a harness error, not an allow: "
                + repr(stderr)
            )
        return "allow"
    if stdout == DENY_STDOUT:
        if stderr == DENY_STDERR:
            return "deny"
        if stderr == "":
            raise HarnessError(
                "empty stderr on the deny stdout is a harness error, not a deny: "
                + repr(stdout)
            )
        raise HarnessError(
            "different stderr on the deny stdout is a harness error, not a deny: "
            + repr(stderr)
        )
    if stdout == QUERY_STILL_STDOUT:
        if stderr == "":
            raise HarnessError(
                "empty stderr on the query-still-denied stdout is a harness error, not a deny: "
                + repr(stdout)
            )
        if stderr == DENY_STDERR:
            raise HarnessError(
                "query-still-denied is a harness error, not an allow and not the live-profile deny: "
                + repr(stdout)
            )
        raise HarnessError(
            "different stderr on the query-still-denied stdout is a harness error, not a deny: "
            + repr(stderr)
        )
    if stderr != "":
        raise HarnessError(
            "different stderr is a harness error, not a deny and not an allow: "
            f"stdout={stdout!r} stderr={stderr!r}"
        )
    raise HarnessError(
        "malformed stdout is a harness error, not a deny and not an allow: "
        + repr(stdout)
    )


def compile_kext(parent, root, source_text):
    """Compile ``source_text`` with ``/usr/bin/cc`` into ``<root>/kextq``.

    The source file sits in ``parent``. The command is
    ``/usr/bin/cc -o <root>/kextq <parent>/kextq.c -framework IOKit
    -framework CoreFoundation``. This does not start ``sandbox-exec``.
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
        [CC, "-o", binary, source, *CC_TAIL],
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
    There is no argv.
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


def query_under(profile):
    """Run the compiled helper under ``profile``. No argv."""
    binary = KextProbe.binary
    root = KextProbe.root
    parent = KextProbe.parent
    if not binary or not root or not parent:
        raise HarnessError("the kext helper is not compiled")
    return run_sandboxed(binary, root, parent, profile)


def require_unsandboxed(result):
    """The unsandboxed control must return ``kext info=1`` and ``kext url=1``.

    The plant's allow line, the live deny, the URL-only line, a bad exit,
    stderr, or a malformed line is a harness error. An ordinary assertion
    is not this check.
    """
    if result.argv and os.fspath(result.argv[0]) == sbx.SANDBOX_EXEC:
        raise HarnessError(
            "unsandboxed control started sandbox-exec: " + repr(result.argv)
        )
    outcome = classify(result)
    if outcome != "allow":
        raise HarnessError(
            "unsandboxed deny is a harness error, not a passing control: "
            + repr(result.stdout)
        )
    if result.stdout != UNSANDBOXED_STDOUT:
        raise HarnessError(
            "unsandboxed allow line is a harness error, not a passing control: "
            + repr(result.stdout)
        )
    return result


def run_unsandboxed(binary):
    """The helper with no profile and no argv.

    This does not start ``sandbox-exec``.
    """
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
    return require_unsandboxed(result)


def require_denied(profile):
    """The one helper. ``profile`` must refuse the loaded-kext query.

    The three real-file tests and the plant call this. An allow raises
    ``NotDenied``. A URL-only result and any other harness error propagate.
    They are not the live-profile deny.
    """
    result = query_under(profile)
    if classify(result) == "allow":
        raise NotDenied(result)
    return result


def with_kext_query_allow(text):
    """Append the one plant line. The wildcard and the bundle filter are not it."""
    if not text.endswith("\n"):
        text += "\n"
    return text + PLANT


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
    ``last_change``. The label is ``pr_label`` of that commit. The digest
    is the bytes this run read. The helper line is ``result.command``.
    ``named`` is ``kext`` when ``kext info`` is 1. Neither pin is stored
    in this file.
    """
    commit = last_change(profile["path"])
    label = pr_label(last_change(profile["path"]))
    digest = sha256_file(profile["path"])
    text = (
        f"CRITICAL {IDS[profile['name']]} {commit} {label} "
        f"sha256 {digest}\n"
        f"profile: {profile['rel']}\n"
        f"helper: {result.command}\n"
        f"observed: {result.stdout.strip()}\n"
    )
    if names_kext(result.stdout):
        text += "named: kext\n"
    return text


def require_finding_pins(paragraph, profile, result):
    """The finding names the PR and the exact command.

    A paragraph that drops only the label raises ``finding omits pr_label``.
    A paragraph that drops only the command raises ``finding omits command``.
    The two checks are separate, so one omission does not report the other.
    """
    label = pr_label(last_change(profile["path"]))
    if label == "" or label not in paragraph:
        raise AssertionError("finding omits pr_label")
    command = result.command
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
            # unittest otherwise treats every exception in a marked body as
            # expected. Only the recorded allow has that status. Leave the
            # original exception for unittest to report as a failure/error.
            if self._outcome is not None:
                self._outcome.expecting_failure = False
            raise

    recorded.__doc__ = (
        "The live profile returned loaded kext info. "
        f"Finding file: {finding_rel}"
    )
    wrapped = unittest.expectedFailure(recorded)
    setattr(case_cls, method_name, wrapped)
    case_cls.addClassCleanup(setattr, case_cls, method_name, method)


def observe(case_cls):
    """Classify each live profile. Record each allow before the next profile.

    A later harness error still propagates. Allows already confirmed stay
    written and marked. A refusal before any allow writes nothing. A
    URL-only result is a harness error, not a deny and not an allow.
    """
    case_cls.recorded_allows = {}
    confirmed = []
    for profile in PROFILES:
        result = query_under(profile["path"])
        outcome = classify(result)
        if outcome != "allow":
            continue
        confirmed.append((profile, result))
        # Snapshot: a later append must not change the list this call recorded.
        write_findings(ROOT, list(confirmed))
        case_cls.recorded_allows[profile["name"]] = FINDINGS[profile["name"]]
        mark_expected(
            case_cls,
            f"test_{profile['name']}_kext_query_is_denied",
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


class KextProbe(unittest.TestCase):
    """The helper under the live profiles, and the allow plant."""

    # Python 3.9 stores class cleanups on TestCase itself. A subclass that
    # runs doClassCleanups would otherwise remove this class's temp dirs.
    _class_cleanups = []
    skip_reason = None
    binary = None
    root = None
    parent = None
    recorded_allows = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls._class_cleanups = []

    @classmethod
    def setUpClass(cls):
        cls.skip_reason = skip_reason()
        cls.binary = None
        cls.root = None
        cls.parent = None
        cls.recorded_allows = {}
        if cls.skip_reason:
            return
        cls.parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-kext-parent-"))
        cls.root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-kext-root-"))
        cls.addClassCleanup(shutil.rmtree, cls.parent, ignore_errors=True)
        cls.addClassCleanup(shutil.rmtree, cls.root, ignore_errors=True)
        cls.binary = compile_kext(cls.parent, cls.root, HELPER_C)
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

    def test_helper_does_not_load_a_kext(self):
        """The helper queries loaded info and a URL. It does not load or unload.

        The two arrays passed to ``KextManagerCopyLoadedKextInfo`` are not
        NULL. ``KextManagerLoad``, ``KextManagerUnload``, and ``kext_request``
        are absent.
        """
        self.assertIn("KextManagerCopyLoadedKextInfo", HELPER_C)
        self.assertIn("KextManagerCreateURLForBundleIdentifier", HELPER_C)
        self.assertIn('CFSTR("com.apple.kpi.libkern")', HELPER_C)
        self.assertIn('CFSTR("OSBundleStarted")', HELPER_C)
        self.assertIn("KextManagerCopyLoadedKextInfo(ids, keys)", HELPER_C)
        self.assertNotIn("KextManagerCopyLoadedKextInfo(NULL", HELPER_C)
        self.assertEqual(HELPER_C.count("KextManagerCopyLoadedKextInfo"), 1)
        self.assertEqual(HELPER_C.count("KextManagerCreateURLForBundleIdentifier"), 1)
        for banned in ("KextManagerLoad", "KextManagerUnload", "kext_request"):
            self.assertNotIn(banned, HELPER_C)

    def test_unsandboxed_kext_query_succeeds(self):
        """Without ``sandbox-exec``, the helper reports info and a URL.

        Exit 0, stderr empty, and stdout is ``kext info=1`` and
        ``kext url=1``. There is no argv. A failure here is a harness
        error, so a later deny is about the profile.
        """
        source = os.path.join(self.parent, SOURCE_NAME)
        self.assertEqual(Path(source).read_text(encoding="utf-8"), HELPER_C)
        self.assertIn("KextManagerCopyLoadedKextInfo", HELPER_C)
        self.assertIn("KextManagerCreateURLForBundleIdentifier", HELPER_C)
        self.assertEqual(os.path.dirname(self.binary), self.root)
        self.assertEqual(os.path.dirname(source), self.parent)
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
        self.assertEqual(result.stdout, UNSANDBOXED_STDOUT)
        self.assertEqual(classify(result), "allow")
        self.assertTrue(names_kext(result.stdout))

    def test_compile_failure_is_an_error(self):
        """``/usr/bin/cc`` on an empty source is a harness error, not a skip."""
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-kext-empty-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-kext-empty-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with self.assertRaises(HarnessError) as caught:
            compile_kext(parent, root, "")
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
        self.assertEqual(result.stderr, DENY_STDERR)
        self.assertEqual(result.stdout, DENY_STDOUT)
        self.assertEqual(result.stdout, "kext info=0\nkext url=0\n")
        self.assertEqual(classify(result), "deny")
        self.assertFalse(names_kext(result.stdout))
        return result

    def test_wallet_kext_query_is_denied(self):
        """The real wallet profile denies the loaded-kext query."""
        self._expect_real_deny(sbx.WALLET_CONFINE_SB)

    def test_did_kext_query_is_denied(self):
        """The real did profile denies the loaded-kext query."""
        did = sbx.REPO_ROOT / "capsules/did-provider/confine.sb"
        self._expect_real_deny(did)

    def test_model_kext_query_is_denied(self):
        """The real model profile denies the loaded-kext query.

        The helper starts under it.
        """
        model = sbx.REPO_ROOT / "capsules/model-provider/confine.sb"
        self._expect_real_deny(model)

    def _expect_denied_copy(self, wallet, copy):
        denied = require_denied(copy)
        self.assertEqual(denied.stdout, DENY_STDOUT)
        self.assertEqual(denied.stderr, DENY_STDERR)
        self.assertEqual(denied.exit_code, 0)
        self.assertEqual(classify(denied), "deny")
        self.assertEqual(denied.argv[0], sbx.SANDBOX_EXEC)
        self.assertIn(copy, denied.argv)
        self.assertNotIn(os.fspath(wallet["path"]), denied.argv)
        return denied

    def _expect_allow(self, copy, profile_path):
        with self.assertRaises(NotDenied) as caught:
            require_denied(copy)
        result = caught.exception.result
        self.assertIn("ALLOW", str(caught.exception))
        self.assertIsNone(sbx.profile_error(result))
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, ALLOW_STDOUT)
        self.assertEqual(classify(result), "allow")
        self.assertTrue(names_kext(result.stdout))
        self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
        self.assertIn(copy, result.argv)
        self.assertNotIn(os.fspath(profile_path), result.argv)
        return result

    def test_falsifier_allow_kext_query_is_caught(self):
        """Appending ``(allow system-kext-query)`` lets the query return info.

        The zero-count reads the plant baseline from ``_source_for_plant``.
        It counts the exact line ``(allow system-kext-query)``. Each
        baseline contains that line zero times and ``(deny default)`` once.
        A recorded allow strips one exact copy of the injected plant line
        before that count and does not strip ``(allow system-kext*)``.
        A temp copy that appends the plant prints the allow line, and the
        helper pointed at the copy fails the deny check. The wildcard
        prints that same allow line and its exact plant count stays zero.
        ``(allow mach-lookup)`` prints the URL-only line, and the deny
        check of the live-profile line fails. The still-deny edits keep
        the deny line and the deny stderr. The repo profile bytes stay
        unchanged.
        """
        self.assertNotIn(PLANT, STAR)
        self.assertNotIn(PLANT, FILTERED_QUERY)
        self.assertNotEqual(STAR, PLANT)
        self.assertNotEqual(FILTERED_QUERY, PLANT)
        self._recorded_strip_leaves_star_and_filter()

        before = {
            profile["rel"]: sha256_file(profile["path"]) for profile in PROFILES
        }
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-kext-profile-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        try:
            for profile in PROFILES:
                with self.subTest(profile=profile["name"]):
                    text = profile["path"].read_text(encoding="utf-8")
                    # Count the baseline. An unconditional zero on the live
                    # file turns a recorded allow into an ordinary failure.
                    baseline = self._source_for_plant(profile["name"], text)
                    self.assertEqual(text.count(DENY_DEFAULT), 1)
                    if profile["name"] not in type(self).recorded_allows:
                        self.assertEqual(text.count(PLANT), 0)
                        self.assertEqual(baseline, text)
                    self.assertEqual(baseline.count(PLANT), 0)
                    self.assertEqual(baseline.count(DENY_DEFAULT), 1)
                    self.assertEqual(baseline.count(STAR), 0)
                    self.assertTrue(baseline.endswith("\n"))
                    planted = with_kext_query_allow(baseline)
                    self.assertEqual(planted, baseline + PLANT)
                    self.assertEqual(planted.count(PLANT), 1)
                    self.assertEqual(planted.count(DENY_DEFAULT), 1)
                    self.assertNotIn(FILTERED_QUERY, planted)
                    copy = write_copy(directory, profile["name"] + "-allow", planted)
                    self.assertEqual(Path(copy).read_text(encoding="utf-8"), planted)
                    self.assertNotEqual(
                        os.path.realpath(copy), os.path.realpath(profile["path"])
                    )
                    self._expect_allow(copy, profile["path"])
                    self.assertEqual(profile["path"].read_text(encoding="utf-8"), text)

            wallet = PROFILES[0]
            self.assertEqual(wallet["name"], "wallet")
            wallet_text = wallet["path"].read_text(encoding="utf-8")
            baseline = self._source_for_plant("wallet", wallet_text)
            self.assertEqual(baseline.count(PLANT), 0)
            self.assertEqual(baseline.count(DENY_DEFAULT), 1)
            self.assertEqual(STILL_DENY_COPIES[0], "wallet-deleted")
            self.assertNotIn("wallet-star", STILL_DENY_COPIES)
            self.assertNotIn("wallet-lookup", STILL_DENY_COPIES)

            with self.subTest(profile="wallet-deleted"):
                deleted = without_deny_default(baseline)
                self.assertNotIn("(deny default)", deleted)
                self.assertEqual(deleted.count(PLANT), 0)
                self.assertNotIn("(allow default)", deleted)
                removed = write_copy(directory, "wallet-deleted", deleted)
                self._expect_denied_copy(wallet, removed)

            for name, line in STILL_DENY_EDITS:
                with self.subTest(profile=name):
                    self.assertNotEqual(line, PLANT)
                    self.assertNotEqual(line, STAR)
                    self.assertNotIn(PLANT, line)
                    self.assertEqual(baseline.count(line), 0)
                    widened = baseline + line
                    self.assertEqual(widened.count(line), 1)
                    self.assertEqual(widened.count(PLANT), 0)
                    self.assertEqual(widened.count(DENY_DEFAULT), 1)
                    copy = write_copy(directory, name, widened)
                    self.assertEqual(Path(copy).read_text(encoding="utf-8"), widened)
                    self._expect_denied_copy(wallet, copy)

            with self.subTest(profile="wallet-star"):
                self.assertNotEqual(STAR, PLANT)
                self.assertNotIn(PLANT, STAR)
                self.assertEqual(baseline.count(STAR), 0)
                star_text = baseline + STAR
                self.assertEqual(star_text.count(PLANT), 0)
                self.assertEqual(star_text.count(STAR), 1)
                self.assertEqual(star_text.count(DENY_DEFAULT), 1)
                star_copy = write_copy(directory, "wallet-star", star_text)
                self.assertEqual(Path(star_copy).read_text(encoding="utf-8"), star_text)
                self._expect_allow(star_copy, wallet["path"])
                self.assertEqual(wallet["path"].read_text(encoding="utf-8"), wallet_text)

            with self.subTest(profile="wallet-lookup"):
                self.assertNotEqual(LOOKUP, PLANT)
                self.assertEqual(baseline.count(LOOKUP), 0)
                looked = baseline + LOOKUP
                self.assertEqual(looked.count(PLANT), 0)
                self.assertEqual(looked.count(DENY_DEFAULT), 1)
                looked_copy = write_copy(directory, "wallet-lookup", looked)
                result = query_under(looked_copy)
                self.assertEqual(result.exit_code, 0)
                self.assertEqual(result.stdout, QUERY_STILL_STDOUT)
                self.assertEqual(result.stderr, DENY_STDERR)
                self.assertNotEqual(result.stdout, DENY_STDOUT)
                self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
                self.assertIn(looked_copy, result.argv)
                with self.assertRaises(HarnessError) as caught:
                    require_denied(looked_copy)
                self.assertIn("query-still-denied", str(caught.exception))
                self.assertNotIsInstance(caught.exception, NotDenied)
                self.assertEqual(wallet["path"].read_text(encoding="utf-8"), wallet_text)
        finally:
            require_unchanged(before)

    def _recorded_strip_leaves_star_and_filter(self):
        """A recorded allow removes one exact plant line and nothing nearby."""
        sample = "(version 1)\n" + DENY_DEFAULT + PLANT + STAR + FILTERED_QUERY

        class Recorded(KextProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Recorded, "test_wallet_kext_query_is_denied", FINDINGS["wallet"])
        try:
            recorded = Recorded("test_falsifier_allow_kext_query_is_caught")
            stripped = recorded._source_for_plant("wallet", sample)
            self.assertEqual(stripped.count(PLANT), 0)
            self.assertIn(STAR, stripped)
            self.assertIn(FILTERED_QUERY, stripped)
            self.assertEqual(stripped.count(STAR), 1)
            self.assertEqual(stripped.count(FILTERED_QUERY), 1)
            self.assertEqual(stripped.count(DENY_DEFAULT), 1)
        finally:
            Recorded.doClassCleanups()

    def _source_for_plant(self, name, text):
        """The text the temp plant edits. A recorded allow does not skip this.

        The deny test carries the finding-linked expected failure. The live
        file is not edited. One exact plant line is removed from the copy
        so the append is still that one line. ``(allow system-kext*)`` and
        the bundle-id filter are not that line, and the strip leaves them
        in place.
        """
        finding = type(self).recorded_allows.get(name)
        if finding is None:
            if PLANT in text:
                raise AssertionError(f"{name} source contains {PLANT_PHRASE}")
            return text
        method = getattr(type(self), f"test_{name}_kext_query_is_denied")
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
        return text


class KextRules(unittest.TestCase):
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
        probe_names = unittest.defaultTestLoader.getTestCaseNames(KextProbe)
        for missing in ((sbx.SANDBOX_EXEC,), (CC,), (sbx.SANDBOX_EXEC, CC)):
            with self.subTest(missing=missing), patch.object(
                os.path, "isfile", side_effect=lambda path: path not in missing
            ), patch(
                __name__ + ".compile_kext",
                side_effect=AssertionError("missing-tool probe compiled a helper"),
            ) as compiled, patch.object(
                sbx, "run",
                side_effect=AssertionError("missing-tool probe launched a helper"),
            ) as launched:
                class MissingTools(KextProbe):
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
        produced. A recorded allow without that mark, a docstring that
        omits the finding, and a second plant line are each their own
        harness error. The wildcard and the bundle-id filter are not the
        exact plant line. A recorded baseline leaves them in place. A
        clean baseline keeps them too.
        """
        with patch.object(os.path, "isfile", return_value=True):
            self.assertIsNone(skip_reason())
            self.assertTrue(os.path.isfile(CC))
            self.assertTrue(os.path.isfile(sbx.SANDBOX_EXEC))
        text = "(version 1)\n" + DENY_DEFAULT + PLANT
        clean = "(version 1)\n" + DENY_DEFAULT
        self.assertNotIn(PLANT, STAR)
        self.assertNotIn(PLANT, FILTERED_QUERY)

        class Recorded(KextProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Recorded, "test_wallet_kext_query_is_denied", FINDINGS["wallet"])
        try:
            case = Recorded("test_falsifier_allow_kext_query_is_caught")
            baseline = case._source_for_plant("wallet", text)
            self.assertEqual(baseline, clean)
            self.assertEqual(case._source_for_plant("did", clean), clean)
            self.assertEqual(case._source_for_plant("wallet", clean + STAR), clean + STAR)
            self.assertEqual(
                case._source_for_plant("wallet", text + STAR),
                clean + STAR,
            )
            self.assertEqual(
                case._source_for_plant("wallet", text + FILTERED_QUERY),
                clean + FILTERED_QUERY,
            )
            self.assertEqual((clean + STAR).count(PLANT), 0)
            self.assertEqual((clean + FILTERED_QUERY).count(PLANT), 0)
            self.assertNotIsInstance(baseline, type(unittest.SkipTest("x")))
        finally:
            Recorded.doClassCleanups()

        class Bare(KextProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        bare = Bare("test_falsifier_allow_kext_query_is_caught")
        with self.assertRaises(HarnessError) as unmarked:
            bare._source_for_plant("wallet", text)
        self.assertEqual(
            str(unmarked.exception),
            "wallet allow has no finding-linked expected failure",
        )
        self.assertNotIsInstance(unmarked.exception, unittest.SkipTest)

        class WrongDoc(KextProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        def body(self):
            raise NotDenied(sbx.Result(
                exit_code=0, stdout=ALLOW_STDOUT, stderr="", argv=[],
            ))

        body.__doc__ = "plain"
        body.__unittest_expecting_failure__ = True
        WrongDoc.test_wallet_kext_query_is_denied = body
        wrong = WrongDoc("test_falsifier_allow_kext_query_is_caught")
        with self.assertRaises(HarnessError) as unnamed:
            wrong._source_for_plant("wallet", text)
        self.assertEqual(
            str(unnamed.exception),
            f"wallet allow docstring does not name {FINDINGS['wallet']}",
        )

        class Twice(KextProbe):
            recorded_allows = {"wallet": FINDINGS["wallet"]}

        mark_expected(Twice, "test_wallet_kext_query_is_denied", FINDINGS["wallet"])
        try:
            twice = Twice("test_falsifier_allow_kext_query_is_caught")
            with self.assertRaises(HarnessError) as extra:
                twice._source_for_plant("wallet", text + PLANT)
            self.assertEqual(
                str(extra.exception),
                f"{PLANT_PHRASE} occurs 2 times, not zero or one",
            )
        finally:
            Twice.doClassCleanups()

        class Clean(KextProbe):
            recorded_allows = {}

        plain = Clean("test_falsifier_allow_kext_query_is_caught")
        with self.assertRaises(AssertionError) as present:
            plain._source_for_plant("wallet", text)
        self.assertEqual(
            str(present.exception),
            f"wallet source contains {PLANT_PHRASE}",
        )
        self.assertEqual(plain._source_for_plant("wallet", clean), clean)
        kept = clean + STAR + FILTERED_QUERY
        self.assertEqual(kept.count(PLANT), 0)
        self.assertEqual(plain._source_for_plant("wallet", kept), kept)
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

        rel = "tmp/kext-confine.sb"
        self.assertNotIn(rel, START_SHA)
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-kext-byte-"))
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
        The success command is ``/usr/bin/cc -o <root>/kextq <parent>/kextq.c
        -framework IOKit -framework CoreFoundation``.
        """
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-kext-cc-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-kext-cc-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        binary = os.path.join(root, BINARY_NAME)
        source = "int main(void) { return 0; }\n"
        reasons = []

        def compiled(completed, access=None):
            runners = patch.object(subprocess, "run", return_value=completed)
            if access is None:
                with runners:
                    return compile_kext(parent, root, source)
            with runners, patch.object(os, "access", return_value=access):
                return compile_kext(parent, root, source)

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
        calls = []

        def recording(args, **_kwargs):
            calls.append(list(args))
            return silent

        source_path = os.path.join(parent, SOURCE_NAME)
        with patch.object(subprocess, "run", side_effect=recording), patch.object(
            os, "access", return_value=True
        ):
            self.assertEqual(compile_kext(parent, root, source), binary)
        self.assertEqual(calls, [[CC, "-o", binary, source_path, *CC_TAIL]])

        def refuse_cc(*_args, **_kwargs):
            raise AssertionError("compiler started")

        for label, compile_parent, compile_root in (
            ("parent", "/var/folders/cc/kext-parent", root),
            ("root", parent, "/var/folders/cc/kext-root"),
        ):
            bad = compile_parent if label == "parent" else compile_root
            expected = (
                f"execvp: {bad} contains /var/folders without the /private prefix"
            )
            with self.subTest(path=label), patch.object(
                subprocess, "run", side_effect=refuse_cc
            ):
                with self.assertRaises(HarnessError) as caught:
                    compile_kext(compile_parent, compile_root, source)
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
        clean = b"(version 1)\n(deny default)\n"
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-kext-bytes-"))
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

            class Plant(KextProbe):
                recorded_allows = {}

            state = {"mutate": False}

            def fake_query(profile):
                path = os.fspath(profile)
                text = Path(path).read_text(encoding="utf-8")
                if state["mutate"] and path.endswith(os.sep + "wallet-deleted.sb"):
                    wallet["path"].write_bytes(after_bytes)
                stdout, stderr = sandbox_outcome(text)
                return sbx.Result(
                    exit_code=0,
                    stdout=stdout,
                    stderr=stderr,
                    argv=[sbx.SANDBOX_EXEC, "-f", path, "/private/kextq"],
                )

            case = Plant("test_falsifier_allow_kext_query_is_caught")
            try:
                with patch(__name__ + ".PROFILES", profiles), patch(
                    __name__ + ".query_under", new=fake_query
                ), patch(__name__ + ".changed", new=spy):
                    with self.subTest(path="falsifier-equal"):
                        seen.clear()
                        state["mutate"] = False
                        case.test_falsifier_allow_kext_query_is_caught()
                        self.assertEqual(seen, equal_pairs)
                    with self.subTest(path="falsifier-changed"):
                        seen.clear()
                        state["mutate"] = True
                        wallet["path"].write_bytes(clean)
                        with self.assertRaises(AssertionError) as caught:
                            case.test_falsifier_allow_kext_query_is_caught()
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
        """Each harness reason the classifier must keep distinct."""
        malformed = "kext nope\n"
        other_stderr = "other\n"

        def profile_case(stderr):
            result = sbx.Result(
                exit_code=sbx.PROFILE_ERROR_EXIT,
                stdout=DENY_STDOUT,
                stderr=stderr,
                argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/kextq"],
            )
            problem = sbx.profile_error(result)
            expected = (
                "profile error: " + problem
                + " -- a harness error, not a deny and not an allow. "
                f"stderr={stderr!r}"
            )
            return result, expected

        operation, operation_reason = profile_case("Operation not permitted\n")
        backtrace, backtrace_reason = profile_case("Backtrace: seatbelt\n")
        mac_policy, mac_reason = profile_case("MAC policy error 0x1\n")
        return (
            ("Operation not permitted", operation, operation_reason),
            ("Backtrace:", backtrace, backtrace_reason),
            ("MAC policy", mac_policy, mac_reason),
            (
                "wrong exit",
                sbx.Result(
                    exit_code=2, stdout=DENY_STDOUT, stderr="", argv=["/private/kextq"],
                ),
                "wrong exit 2 is a harness error, not a deny and not an allow. "
                f"stdout={DENY_STDOUT!r} stderr=''",
            ),
            (
                "empty stderr on the deny stdout",
                sbx.Result(
                    exit_code=0, stdout=DENY_STDOUT, stderr="", argv=["/private/kextq"],
                ),
                "empty stderr on the deny stdout is a harness error, not a deny: "
                + repr(DENY_STDOUT),
            ),
            (
                "different stderr on the deny stdout",
                sbx.Result(
                    exit_code=0,
                    stdout=DENY_STDOUT,
                    stderr=other_stderr,
                    argv=["/private/kextq"],
                ),
                "different stderr on the deny stdout is a harness error, not a deny: "
                + repr(other_stderr),
            ),
            (
                "nonempty stderr on the allow stdout",
                sbx.Result(
                    exit_code=0,
                    stdout=ALLOW_STDOUT,
                    stderr=DENY_STDERR,
                    argv=["/private/kextq"],
                ),
                "nonempty stderr on the allow stdout is a harness error, not an allow: "
                + repr(DENY_STDERR),
            ),
            (
                "nonempty stderr on kext info=1 kext url=1",
                sbx.Result(
                    exit_code=0,
                    stdout=UNSANDBOXED_STDOUT,
                    stderr=DENY_STDERR,
                    argv=["/private/kextq"],
                ),
                "nonempty stderr on kext info=1 kext url=1 is a harness error, not an allow: "
                + repr(DENY_STDERR),
            ),
            (
                "empty stderr on the query-still-denied stdout",
                sbx.Result(
                    exit_code=0,
                    stdout=QUERY_STILL_STDOUT,
                    stderr="",
                    argv=["/private/kextq"],
                ),
                "empty stderr on the query-still-denied stdout is a harness error, not a deny: "
                + repr(QUERY_STILL_STDOUT),
            ),
            (
                "malformed stdout",
                sbx.Result(
                    exit_code=0, stdout=malformed, stderr="", argv=["/private/kextq"],
                ),
                "malformed stdout is a harness error, not a deny and not an allow: "
                + repr(malformed),
            ),
            (
                "query-still-denied",
                sbx.Result(
                    exit_code=0,
                    stdout=QUERY_STILL_STDOUT,
                    stderr=DENY_STDERR,
                    argv=["/private/kextq"],
                ),
                "query-still-denied is a harness error, not an allow and not the live-profile deny: "
                + repr(QUERY_STILL_STDOUT),
            ),
        )

    def test_classifier_refusal_reasons(self):
        """Each classifier refusal preserves its exact, distinct reason.

        These results are built here. Nothing is launched. Exit 65 stays a
        profile error when stderr says ``Operation not permitted``,
        ``Backtrace:``, or ``MAC policy``. Empty stderr on ``kext info=0``,
        a different stderr, nonempty stderr on ``kext info=1``, a nonzero
        exit, and a malformed line each keep their own reason.
        """
        self.assertEqual(
            classify(sbx.Result(
                exit_code=0, stdout=ALLOW_STDOUT, stderr="", argv=["/private/kextq"],
            )),
            "allow",
        )
        self.assertEqual(
            classify(sbx.Result(
                exit_code=0,
                stdout=UNSANDBOXED_STDOUT,
                stderr="",
                argv=["/private/kextq"],
            )),
            "allow",
        )
        self.assertEqual(
            classify(sbx.Result(
                exit_code=0,
                stdout=DENY_STDOUT,
                stderr=DENY_STDERR,
                argv=["/private/kextq"],
            )),
            "deny",
        )
        samples = self.refusal_samples()
        reasons = []
        for label, result, expected in samples:
            with self.subTest(label=label):
                if result.exit_code == sbx.PROFILE_ERROR_EXIT:
                    self.assertIsNotNone(sbx.profile_error(result))
                with self.assertRaises(HarnessError) as caught:
                    classify(result)
                self.assertEqual(str(caught.exception), expected)
                self.assertIn(label, str(caught.exception))
                reasons.append(str(caught.exception))
        self.assertEqual(len(set(reasons)), len(samples))
        backtrace = reasons[1]
        self.assertIn("profile evaluation error", backtrace)
        self.assertNotIn("profile evaluation error", reasons[0])
        self.assertNotIn("profile evaluation error", reasons[2])
        self.launch_guard.assert_not_called()

    def test_require_denied_uses_classifier_decision(self):
        """The classifier owns output validation for both decisions."""
        profile = PROFILES[0]["path"]
        for label, result, _expected in self.refusal_samples():
            for outcome in ("deny", "allow"):
                with self.subTest(result=label, outcome=outcome), patch(
                    __name__ + ".query_under", return_value=result
                ) as queried, patch(
                    __name__ + ".classify", return_value=outcome
                ) as classified:
                    if outcome == "deny":
                        self.assertIs(require_denied(profile), result)
                    else:
                        with self.assertRaises(NotDenied) as caught:
                            require_denied(profile)
                        self.assertIs(caught.exception.result, result)
                    queried.assert_called_once_with(profile)
                    classified.assert_called_once_with(result)
        self.launch_guard.assert_not_called()

    def test_unsandboxed_failure_is_an_error(self):
        """A failed unsandboxed control is a harness error, not an assertion failure.

        The deny line, the allow line, the query-still-denied line, a
        nonzero exit, nonempty stderr, and a malformed line each raise
        ``HarnessError`` with its own reason. They launch nothing.
        """
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-kext-unsandboxed-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        binary = os.path.join(parent, BINARY_NAME)
        descriptor = os.open(binary, os.O_CREAT | os.O_WRONLY, 0o755)
        os.close(descriptor)
        binary = os.path.realpath(binary)
        malformed = "kext nope\n"
        cases = (
            (
                "unsandboxed deny",
                subprocess.CompletedProcess(
                    [binary], 0, DENY_STDOUT, DENY_STDERR,
                ),
                "unsandboxed deny is a harness error, not a passing control: "
                + repr(DENY_STDOUT),
            ),
            (
                "unsandboxed allow line",
                subprocess.CompletedProcess([binary], 0, ALLOW_STDOUT, ""),
                "unsandboxed allow line is a harness error, not a passing control: "
                + repr(ALLOW_STDOUT),
            ),
            (
                "query-still-denied",
                subprocess.CompletedProcess(
                    [binary], 0, QUERY_STILL_STDOUT, DENY_STDERR,
                ),
                "query-still-denied is a harness error, not an allow and not the live-profile deny: "
                + repr(QUERY_STILL_STDOUT),
            ),
            (
                "wrong exit",
                subprocess.CompletedProcess(
                    [binary], 2, UNSANDBOXED_STDOUT, "",
                ),
                "wrong exit 2 is a harness error, not a deny and not an allow. "
                f"stdout={UNSANDBOXED_STDOUT!r} stderr=''",
            ),
            (
                "nonempty stderr",
                subprocess.CompletedProcess(
                    [binary], 0, UNSANDBOXED_STDOUT, "noise\n",
                ),
                "nonempty stderr on kext info=1 kext url=1 is a harness error, not an allow: "
                + repr("noise\n"),
            ),
            (
                "malformed stdout",
                subprocess.CompletedProcess([binary], 0, malformed, ""),
                "malformed stdout is a harness error, not a deny and not an allow: "
                + repr(malformed),
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
        self.launch_guard.assert_not_called()

    def test_observe_propagates_every_refusal(self):
        """A failed observation stops before any later success or finding mark."""
        deny = sbx.Result(
            exit_code=0,
            stdout=DENY_STDOUT,
            stderr=DENY_STDERR,
            argv=["/private/kextq"],
        )
        for label, refused, expected in self.refusal_samples():
            for preceding in ([], [deny], [deny, deny]):
                with self.subTest(reason=label, position=len(preceding)):
                    class Observed(KextProbe):
                        pass

                    with patch(
                        __name__ + ".query_under",
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
        Model is not opened. A did allow before a model error is recorded too.
        The clean run writes no finding. ``kext info=1`` and ``kext url=1``
        is recorded the same way.
        """
        allow = sbx.Result(
            exit_code=0,
            stdout=ALLOW_STDOUT,
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/kextq"],
        )
        both = sbx.Result(
            exit_code=0,
            stdout=UNSANDBOXED_STDOUT,
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/kextq"],
        )
        refused = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout="",
            stderr="Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb"],
        )
        self.assertEqual(classify(allow), "allow")
        self.assertEqual(classify(both), "allow")
        with self.assertRaises(HarnessError) as sample:
            classify(refused)
        expected = str(sample.exception)
        self.assertIn("profile error", expected)
        self.assertIn("Operation not permitted", expected)

        def run_case(results):
            class Observed(KextProbe):
                pass

            pending = list(results)
            order = []

            def opened(path):
                order.append(("open", path))
                return pending.pop(0)

            def written(_repo, items):
                order.append(("write", [item[0]["name"] for item in items]))

            with patch(__name__ + ".query_under", side_effect=opened), patch(
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
            method = observed.test_wallet_kext_query_is_denied
            self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
            self.assertIn(FINDINGS["wallet"], method.__doc__ or "")
            self.assertNotIn("model", observed.recorded_allows)
        finally:
            if observed is not None:
                observed.doClassCleanups()

        observed = None
        try:
            observed, marker, order = run_case([both, both, refused])
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
            with patch(__name__ + ".last_change", return_value="a" * 40), patch(
                __name__ + ".pr_label", return_value="PR fixture"
            ), patch(__name__ + ".sha256_file", return_value="b" * 64):
                self.assertIn("named: kext", finding_paragraph(wallet, both))
            self.assertNotIn("model", observed.recorded_allows)
        finally:
            if observed is not None:
                observed.doClassCleanups()
        self.launch_guard.assert_not_called()

    def test_recorded_allow_is_expected_failure(self):
        """A recorded allow is an expected failure whose docstring names the finding.

        The result is injected. The finding is written under a temp repo.
        Its first line contains CRITICAL, the commit from ``last_change``,
        ``pr_label`` of that commit, and the sha256. The helper line is
        ``result.command``. ``require_finding_pins`` raises
        ``finding omits pr_label`` when only the label is dropped, and
        ``finding omits command`` when only the command is dropped.
        ``CRITICAL.md`` receives that same paragraph. The wallet docstring
        names ``CRITICAL-confine-075.md``. The model docstring names
        ``CRITICAL-cc-model-confine-075.md``. A unittest run of each injected
        allow is one expected failure. The same raise without the mark is a
        failure. The clean run writes no finding. The finding names ``kext``.

        Exit 0, stdout ``kext info=1`` and ``kext url=1``, and empty stderr
        under an injected profile is also an allow: it writes a finding and
        the deny test is an expected failure.
        """
        provenance = self.enter_patch(patch(__name__ + ".last_change", return_value="a" * 40))
        self.enter_patch(patch(__name__ + ".pr_label", return_value="PR fixture"))
        self.enter_patch(patch(__name__ + ".sha256_file", return_value="b" * 64))
        allow = sbx.Result(
            exit_code=0,
            stdout=ALLOW_STDOUT,
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/kextq"],
        )
        both = sbx.Result(
            exit_code=0,
            stdout=UNSANDBOXED_STDOUT,
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/kextq"],
        )
        self.assertIsNone(sbx.profile_error(allow))
        self.assertEqual(classify(allow), "allow")
        self.assertEqual(classify(both), "allow")
        self.assertTrue(names_kext(allow.stdout))
        self.assertTrue(names_kext(both.stdout))
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

        def assert_paragraph(paragraph, profile, result):
            first = paragraph.splitlines()[0]
            self.assertIn("CRITICAL", first)
            self.assertIn(last_change(profile["path"]), first)
            self.assertIn(pr_label(last_change(profile["path"])), first)
            self.assertIn(sha256_file(profile["path"]), first)
            self.assertEqual(paragraph.splitlines()[2], f"helper: {result.command}")
            self.assertIn("named: kext", paragraph)
            self.assertIn("kext info=1", paragraph)
            require_finding_pins(paragraph, profile, result)
            label = pr_label(last_change(profile["path"]))
            without_label = paragraph.replace(label, "", 1)
            self.assertNotIn(label, without_label)
            self.assertIn(result.command, without_label)
            with self.assertRaises(AssertionError) as omitted_label:
                require_finding_pins(without_label, profile, result)
            self.assertEqual(str(omitted_label.exception), "finding omits pr_label")
            without_command = paragraph.replace(result.command, "", 1)
            self.assertIn(label, without_command)
            self.assertNotIn(result.command, without_command)
            with self.assertRaises(AssertionError) as omitted_command:
                require_finding_pins(without_command, profile, result)
            self.assertEqual(str(omitted_command.exception), "finding omits command")

        with tempfile.TemporaryDirectory(prefix="ccrt-kext-finding-") as tmp:
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
            assert_paragraph(wallet_paragraph, wallet, allow)
            self.assertIn(f"profile: {wallet['rel']}", wallet_paragraph)
            listed = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertIn(wallet_paragraph, listed)
            self.assertIn(did_paragraph, listed)
            model_written = write_findings(repo, [(model, allow)])
            self.assertEqual(model_written, [FINDINGS["model"]])
            model_paragraph = finding_paragraph(model, allow)
            model_body = (repo / FINDINGS["model"]).read_text(encoding="utf-8")
            self.assertEqual(model_body, model_paragraph)
            self.assertIn("CRITICAL-cc-model-confine-075", model_paragraph)
            self.assertIn("named: kext", model_paragraph)
            listed_again = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertIn(model_paragraph, listed_again)
            self.assertEqual(listed_again.count(model_paragraph), 1)
            again = write_findings(repo, [(model, allow)])
            relisted = (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8")
            self.assertEqual(relisted, listed_again)
            self.assertEqual(again, [FINDINGS["model"]])

            both_written = write_findings(repo, [(wallet, both)])
            self.assertEqual(both_written, [FINDINGS["wallet"]])
            both_paragraph = finding_paragraph(wallet, both)
            both_body = (repo / FINDINGS["wallet"]).read_text(encoding="utf-8")
            self.assertEqual(both_body, both_paragraph)
            assert_paragraph(both_paragraph, wallet, both)
            self.assertIn("kext url=1", both_paragraph)
            self.assertIn(
                both_paragraph,
                (repo / "lab" / "redteam" / "CRITICAL.md").read_text(encoding="utf-8"),
            )
        after = {
            path: path.read_bytes() if path.is_file() else None for path in live_names
        }
        self.assertEqual(before, after)

        class Unmarked(unittest.TestCase):
            def test_wallet_kext_query_is_denied(self):
                """plain"""
                raise NotDenied(allow)

        unmarked = unittest.TestResult()
        Unmarked("test_wallet_kext_query_is_denied").run(unmarked)
        self.assertEqual(len(unmarked.failures), 1)
        self.assertEqual(unmarked.expectedFailures, [])
        self.assertEqual(unmarked.errors, [])

        def run_marked(name, outcome):
            method_name = f"test_{name}_kext_query_is_denied"

            class Recorded(KextProbe):
                skip_reason = None

            def body(self):
                result = query_under(PROFILES[0]["path"])
                if classify(result) != "deny":
                    raise NotDenied(result)

            body.__doc__ = "injected"
            setattr(Recorded, method_name, body)
            mark_expected(Recorded, method_name, FINDINGS[name])
            method = getattr(Recorded, method_name)
            self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
            self.assertIn(FINDINGS[name], method.__doc__)
            if name == "model":
                self.assertIn("CRITICAL-cc-model-confine-075.md", method.__doc__)
            else:
                self.assertIn("CRITICAL-confine-075.md", method.__doc__)
            recorded = unittest.TestResult()
            try:
                with patch(__name__ + ".query_under", return_value=outcome):
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

        run_marked("wallet", allow)
        run_marked("model", allow)
        run_marked("wallet", both)
        run_marked("model", both)
        self.assertGreaterEqual(provenance.call_count, 1)
        self.launch_guard.assert_not_called()

    def test_wallet_controls_reject_allow_with_or_without_finding(self):
        """Each wallet control fails on an allow, with or without a recorded finding.

        The still-deny copies are not excused by a live allow. The failure is
        ordinary, not expected.
        """
        for recorded in (False, True):
            for control in STILL_DENY_COPIES:
                with self.subTest(recorded=recorded, control=control), tempfile.TemporaryDirectory(
                    prefix="ccrt-kext-control-"
                ) as tmp:
                    profiles = []
                    for original in PROFILES:
                        profile = dict(original)
                        profile["path"] = Path(tmp) / f"{profile['name']}.sb"
                        text = "(version 1)\n(deny default)\n"
                        if recorded and profile["name"] == "wallet":
                            text = with_kext_query_allow(text)
                        profile["path"].write_text(text, encoding="utf-8")
                        profiles.append(profile)

                    class Control(KextProbe):
                        skip_reason = None
                        recorded_allows = {}

                    if recorded:
                        finding = FINDINGS["wallet"]
                        Control.recorded_allows["wallet"] = finding
                        mark_expected(
                            Control, "test_wallet_kext_query_is_denied", finding,
                        )
                        method = Control.test_wallet_kext_query_is_denied
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
                            stdout, stderr = ALLOW_STDOUT, ""
                        else:
                            stdout, stderr = sandbox_outcome(text)
                        return sbx.Result(
                            exit_code=0,
                            stdout=stdout,
                            stderr=stderr,
                            argv=[sbx.SANDBOX_EXEC, "-f", os.fspath(path)],
                        )

                    result = unittest.TestResult()
                    try:
                        with patch(__name__ + ".PROFILES", tuple(profiles)), patch(
                            __name__ + ".query_under", side_effect=injected_open
                        ):
                            Control(
                                "test_falsifier_allow_kext_query_is_caught"
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
                    self.assertIn("kext info=1", caught)
                    self.assertFalse(result.wasSuccessful())
                    self.assertEqual(opened, [
                        "wallet-allow.sb", "did-allow.sb", "model-allow.sb",
                        *[name + ".sb" for name in STILL_DENY_COPIES],
                        "wallet-star.sb",
                        "wallet-lookup.sb", "wallet-lookup.sb",
                    ])
        self.launch_guard.assert_not_called()

    def test_recorded_allow_keeps_complete_probe_suite_green(self):
        """Run every real probe method against injected tools and profile text.

        No allow, and the plant on each profile, keep the suite green. Only
        the deny test of the profile that contains the exact plant line is an
        expected failure. The plant still runs, including each wallet control
        that still denies, and nothing skips. The finding names ``kext``.
        """
        method_names = unittest.defaultTestLoader.getTestCaseNames(KextProbe)
        scenarios = ((), ("wallet",), ("did",), ("model",), ("wallet", "did", "model"))
        for allowed in scenarios:
            with self.subTest(allowed=allowed), tempfile.TemporaryDirectory(
                prefix="ccrt-kext-suite-"
            ) as tmp:
                repo = Path(tmp).resolve()
                profiles = []
                for original in PROFILES:
                    profile = dict(original)
                    profile["path"] = repo / profile["rel"]
                    profile["path"].parent.mkdir(parents=True, exist_ok=True)
                    text = "(version 1)\n(deny default)\n"
                    if profile["name"] in allowed:
                        text = with_kext_query_allow(text)
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
                        stdout=UNSANDBOXED_STDOUT,
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
                    stdout, stderr = sandbox_outcome(text)
                    return sbx.Result(
                        exit_code=0,
                        stdout=stdout,
                        stderr=stderr,
                        argv=[
                            sbx.SANDBOX_EXEC, "-D",
                            f"PROVIDER_EXECUTABLE={kwargs['pinned_exe']}",
                            "-D",
                            f"STORAGE_ROOT={kwargs['storage_root']}",
                            "-D",
                            f"STORAGE_PARENT={kwargs['storage_parent']}",
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
                    __name__ + ".compile_kext", side_effect=injected_compile
                ), patch(__name__ + ".run_unsandboxed", side_effect=injected_control), patch.object(
                    sbx, "run", side_effect=injected_sandbox
                ), patch(__name__ + ".last_change", return_value="a" * 40), patch(
                    __name__ + ".pr_label", return_value="PR fixture"
                ), patch.multiple(
                    KextProbe, binary=None, root=None, parent=None,
                    skip_reason=None, recorded_allows={},
                ):
                    result = unittest.TestResult()
                    unittest.defaultTestLoader.loadTestsFromTestCase(KextProbe).run(result)
                    self.assertEqual(result.testsRun, len(method_names))
                    self.assertEqual(result.errors, [])
                    self.assertEqual(result.failures, [])
                    self.assertEqual(result.unexpectedSuccesses, [])
                    self.assertEqual(result.skipped, [])
                    self.assertIsNone(skip_reason())
                    self.assertEqual(len(result.expectedFailures), len(allowed))
                    self.assertEqual(
                        {case._testMethodName for case, _error in result.expectedFailures},
                        {f"test_{name}_kext_query_is_denied" for name in allowed},
                    )
                    self.assertEqual(
                        sorted(
                            os.path.basename(path)
                            for path in launched
                            if path.endswith("-allow.sb")
                        ),
                        ["did-allow.sb", "model-allow.sb", "wallet-allow.sb"],
                    )
                    for name in STILL_DENY_COPIES:
                        self.assertTrue(
                            any(path.endswith(os.sep + name + ".sb") for path in launched),
                            name,
                        )
                    self.assertTrue(
                        any(path.endswith(os.sep + "wallet-star.sb") for path in launched)
                    )
                    self.assertTrue(
                        any(path.endswith(os.sep + "wallet-lookup.sb") for path in launched)
                    )
                    self.assertTrue(result.wasSuccessful())
                    self.assertEqual(
                        KextProbe.recorded_allows,
                        {name: FINDINGS[name] for name in allowed},
                    )
                    for name in allowed:
                        body = (repo / FINDINGS[name]).read_text(encoding="utf-8")
                        profile = next(item for item in profiles if item["name"] == name)
                        self.assertIn(f"profile: {profile['rel']}", body)
                        self.assertIn(sha256_file(profile["path"]), body)
                        self.assertIn("named: kext", body)
                        self.assertIn("kext", body)
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
        """An injected harness error stays an error. It is not a deny, an allow, or a skip.

        ``kext info=0`` and ``kext url=1`` with the deny stderr, on a real
        profile path and on an already-marked deny test, stays a
        ``HarnessError``.
        """
        allow = sbx.Result(
            exit_code=0, stdout=ALLOW_STDOUT, stderr="", argv=["/private/kextq"],
        )
        deny = sbx.Result(
            exit_code=0,
            stdout=DENY_STDOUT,
            stderr=DENY_STDERR,
            argv=["/private/kextq"],
        )
        for profile in PROFILES:
            for label, refused, expected in self.refusal_samples():
                with self.subTest(profile=profile["name"], reason=label):
                    class Recorded(KextProbe):
                        skip_reason = None

                    def observation(path, profile=profile, allow=allow, deny=deny):
                        return allow if path == profile["path"] else deny

                    with patch(__name__ + ".query_under", side_effect=observation), patch(
                        __name__ + ".write_findings"
                    ) as writer:
                        observe(Recorded)
                    writer.assert_called_once_with(ROOT, [(profile, allow)])
                    method_name = f"test_{profile['name']}_kext_query_is_denied"
                    method = getattr(Recorded, method_name)
                    self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
                    self.assertIn(FINDINGS[profile["name"]], method.__doc__)
                    result = unittest.TestResult()
                    try:
                        with patch(
                            __name__ + ".query_under", side_effect=[refused, deny]
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

        wallet = PROFILES[0]
        query_still = sbx.Result(
            exit_code=0,
            stdout=QUERY_STILL_STDOUT,
            stderr=DENY_STDERR,
            argv=[sbx.SANDBOX_EXEC, "-f", os.fspath(wallet["path"]), "/private/kextq"],
        )
        with self.assertRaises(HarnessError) as caught:
            classify(query_still)
        query_reason = str(caught.exception)
        self.assertIn("query-still-denied", query_reason)
        self.assertIn(repr(QUERY_STILL_STDOUT), query_reason)

        class Fresh(KextProbe):
            pass

        seen = []

        def opened_fresh(path):
            seen.append(os.fspath(path))
            self.assertEqual(os.fspath(path), os.fspath(wallet["path"]))
            return query_still

        with patch(__name__ + ".query_under", side_effect=opened_fresh), patch(
            __name__ + ".write_findings"
        ) as writer, patch(__name__ + ".mark_expected") as marker:
            with self.assertRaises(HarnessError) as caught:
                observe(Fresh)
        self.assertEqual(str(caught.exception), query_reason)
        self.assertEqual(seen, [os.fspath(wallet["path"])])
        writer.assert_not_called()
        marker.assert_not_called()
        self.assertEqual(Fresh.recorded_allows, {})

        class Marked(KextProbe):
            skip_reason = None

        mark_expected(Marked, "test_wallet_kext_query_is_denied", FINDINGS["wallet"])
        marked_paths = []

        def opened_marked(path):
            marked_paths.append(os.fspath(path))
            return query_still

        marked = unittest.TestResult()
        try:
            with patch(__name__ + ".query_under", side_effect=opened_marked), patch.object(
                os.path, "isfile", return_value=True
            ):
                Marked("test_wallet_kext_query_is_denied").run(marked)
        finally:
            Marked.doClassCleanups()
        self.assertEqual(marked_paths, [os.fspath(sbx.WALLET_CONFINE_SB)])
        self.assertEqual(len(marked.errors), 1)
        self.assertIn("HarnessError", marked.errors[0][1])
        self.assertIn("query-still-denied", marked.errors[0][1])
        self.assertEqual(marked.expectedFailures, [])
        self.assertEqual(marked.failures, [])
        self.assertEqual(marked.skipped, [])
        self.assertFalse(marked.wasSuccessful())

        wrong_exit = sbx.Result(
            exit_code=2,
            stdout=DENY_STDOUT,
            stderr="",
            argv=["/private/kextq"],
        )
        for sample in (wrong_exit, query_still):
            with self.assertRaises(HarnessError):
                classify(sample)

        class Body(unittest.TestCase):
            def test_wallet_kext_query_is_denied(self):
                classify(wrong_exit)

        body = unittest.TestResult()
        Body("test_wallet_kext_query_is_denied").run(body)
        self.assertEqual(len(body.errors), 1)
        self.assertEqual(body.failures, [])
        self.assertEqual(body.expectedFailures, [])
        self.assertEqual(body.skipped, [])

        class Setup(unittest.TestCase):
            def setUp(self):
                raise HarnessError("wrong exit 2 is a harness error, not a deny")

            @unittest.expectedFailure
            def test_wallet_kext_query_is_denied(self):
                raise NotDenied(wrong_exit)

        setup = unittest.TestResult()
        Setup("test_wallet_kext_query_is_denied").run(setup)
        self.assertEqual(len(setup.errors), 1)
        self.assertEqual(setup.expectedFailures, [])
        self.assertEqual(setup.skipped, [])
        self.assertIn("wrong exit", setup.errors[0][1])
        self.launch_guard.assert_not_called()

    def test_unresolved_storage_path_is_an_error(self):
        """A ``/var/folders`` storage path without ``/private`` errors before launch."""
        bad_parent = "/var/folders/cc/kext-parent"
        bad_root = "/var/folders/cc/kext-root"
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
                compile_kext(
                    bad_parent,
                    "/private/kext-root",
                    "int main(void) { return 0; }\n",
                )
            compile_message = str(compile_caught.exception)
            self.assertIn(bad_parent, compile_message)
            self.assertIn("/var/folders", compile_message)
            self.assertNotIn("/private" + bad_parent, compile_message)

            with self.assertRaises(HarnessError) as launch_caught:
                run_sandboxed(
                    "/private/kextq",
                    bad_root,
                    "/private/kext-parent",
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
