"""Probe posix shared-memory open on the wallet, did, and model profiles.

Grade row 12 rests on those seatbelt profiles. No merged probe calls
``shm_open``. This module compiles one helper and runs it under each live
``confine.sb``. Confined launches go through ``sbx.run`` only. The helper
always exits 0. A deny is stdout ``fd=-1 errno=1`` and empty stderr. An
allow is stdout ``fd=<integer >= 0> errno=0`` and empty stderr.

The three profiles are the live files. ``setUpModule`` records each sha256.
``tearDownModule`` compares the digest at the end through ``changed`` from
``test_confine_mach``. An owner edit between those two points raises
``the probe changed <rel>``. A difference from an older measurement is not
a failure. This file stores no commit, pull request, or digest.

An allow on a real profile is CRITICAL. Wallet or did:
``findings/CRITICAL-confine-042.md``. Model:
``findings/CRITICAL-cc-model-confine-042.md``. The finding's first line
contains CRITICAL and names the commit from ``git log -1 --format=%H HEAD
-- <file>`` plus the sha256 of the bytes this run read. The same paragraph
is appended to ``CRITICAL.md``. With no allow, this module writes neither
file.

A recorded allow keeps the gate green. The deny test is marked
``@unittest.expectedFailure`` and its docstring names that finding file
(README guard b). A harness error is not an allow, so it is not marked and
it still fails the gate. A profile error, a failed compile, a failed
unsandboxed control, nonempty stderr, and an exit other than 0 are harness
errors. They are not a deny and they are not a skip.

``ShmOpenProbe`` compiles and launches. It skips only when
``/usr/bin/sandbox-exec`` or ``/usr/bin/cc`` is missing, and the reason
names that path. ``ShmOpenClassifier`` does not compile and does not launch.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

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
DENY_STDOUT = "fd=-1 errno=1\n"
ALLOW_IPC = "(allow ipc-posix-shm)\n"
DENY_DEFAULT = "(deny default)\n"

HELPER_C = """\
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *name;
    int fd;
    if (argc != 2) {
        printf("fd=-1 errno=0\\n");
        return 0;
    }
    name = argv[1];
    fd = shm_open(name, O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        printf("fd=-1 errno=%d\\n", errno);
        fflush(stdout);
        return 0;
    }
    printf("fd=%d errno=0\\n", fd);
    fflush(stdout);
    close(fd);
    shm_unlink(name);
    return 0;
}
"""

FINDINGS = {
    "wallet": "lab/redteam/findings/CRITICAL-confine-042.md",
    "did": "lab/redteam/findings/CRITICAL-confine-042.md",
    "model": "lab/redteam/findings/CRITICAL-cc-model-confine-042.md",
}
IDS = {
    "wallet": "CRITICAL-confine-042",
    "did": "CRITICAL-confine-042",
    "model": "CRITICAL-cc-model-confine-042",
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

_ALLOW_STDOUT = re.compile(r"fd=([0-9]+) errno=0\n")
_WRONG_ERRNO = re.compile(r"fd=-1 errno=(?!1\n)[0-9]+\n")
_SHM_NAME = re.compile(r"/ccrt[0-9]+\Z")

START_SHA = {}
_SHM_SEQ = 0


class NotDenied(AssertionError):
    """The profile allowed ``shm_open``."""

    def __init__(self, result):
        self.result = result
        super().__init__(
            "ALLOW: posix shared memory opened under the profile.\n"
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


def require_shm_name(name):
    """A legal shm name is ``/ccrt`` plus digits and nothing else."""
    if _SHM_NAME.fullmatch(name) is None:
        raise HarnessError(f"shm name {name!r} is not /ccrt plus digits")
    return name


def next_shm_name():
    global _SHM_SEQ
    _SHM_SEQ += 1
    return require_shm_name(f"/ccrt{os.getpid()}{_SHM_SEQ}")


def allow_fd(stdout):
    """The fd from an allow line, or None when stdout is not that line."""
    match = _ALLOW_STDOUT.fullmatch(stdout)
    if match is None:
        return None
    return int(match.group(1))


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
        if allow_fd(result.stdout) is not None:
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
    if _WRONG_ERRNO.fullmatch(result.stdout):
        raise HarnessError(
            f"wrong errno is a harness error, not a deny: {result.stdout!r}"
        )
    if allow_fd(result.stdout) is not None:
        return "allow"
    raise HarnessError(
        f"malformed allow stdout is a harness error, not an allow: {result.stdout!r}"
    )


def compile_shm(parent, root, source_text):
    """Compile ``source_text`` with ``/usr/bin/cc`` into ``<root>/shm``.

    The source file sits in ``parent``. This does not start ``sandbox-exec``.
    A compiler failure is a harness error, not a skip.
    """
    require_storage_path(parent)
    require_storage_path(root)
    source = os.path.join(parent, "shm.c")
    with open(source, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(source_text)
    binary = os.path.join(root, "shm")
    completed = subprocess.run(
        [CC, "-o", binary, source],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no compiler output"
        raise HarnessError(
            f"{CC} failed with exit {completed.returncode}: {detail} "
            "-- a harness error, not a skip and not a deny"
        )
    require_storage_path(binary)
    if not os.access(binary, os.X_OK):
        raise HarnessError(f"{CC} wrote no executable at {binary}")
    return binary


def run_sandboxed(binary, root, parent, profile, name):
    """One confined launch. ``sbx.run`` is the only sandbox runner."""
    require_storage_path(root)
    require_storage_path(parent)
    require_storage_path(binary)
    require_shm_name(name)
    return sbx.run(
        pinned_exe=binary,
        launch_exe=binary,
        args=(name,),
        storage_root=root,
        storage_parent=parent,
        profile=profile,
        timeout=HELPER_TIMEOUT,
    )


def open_under(profile):
    """Run the compiled helper under ``profile``. One argv entry, the shm name."""
    binary = ShmOpenProbe.binary
    root = ShmOpenProbe.root
    parent = ShmOpenProbe.parent
    if not binary or not root or not parent:
        raise HarnessError("the shm helper is not compiled")
    return run_sandboxed(binary, root, parent, profile, next_shm_name())


def run_unsandboxed(binary):
    """The helper with no profile. This does not start ``sandbox-exec``."""
    require_storage_path(binary)
    name = next_shm_name()
    completed = subprocess.run(
        [binary, name],
        capture_output=True,
        text=True,
        timeout=HELPER_TIMEOUT,
    )
    return sbx.Result(
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        argv=[binary, name],
    )


def require_denied(profile):
    """The one helper. ``profile`` must deny ``shm_open``.

    The three real-file tests and the plant call this. An allow raises
    ``NotDenied``. A harness error propagates and is not a deny.
    """
    result = open_under(profile)
    if classify(result) != "deny":
        raise NotDenied(result)
    return result


def with_shm_allow(text):
    """Append the one plant line. A filtered form is not this plant."""
    if not text.endswith("\n"):
        text += "\n"
    return text + ALLOW_IPC


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
    method.__doc__ = (
        "The live profile allowed a posix shared-memory open. "
        f"Finding file: {finding_rel}"
    )
    wrapped = unittest.expectedFailure(method)
    wrapped.__doc__ = method.__doc__
    setattr(case_cls, method_name, wrapped)


def observe(case_cls):
    """Classify each live profile once, so an allow is marked before its test."""
    items = []
    for profile in PROFILES:
        result = open_under(profile["path"])
        try:
            outcome = classify(result)
        except HarnessError:
            continue
        if outcome == "allow":
            items.append((profile, result))
    if not items:
        return
    write_findings(ROOT, items)
    for profile, _result in items:
        mark_expected(
            case_cls,
            f"test_{profile['name']}_shm_open_is_denied",
            FINDINGS[profile["name"]],
        )


def setUpModule():
    """Record the three live profile digests. A missing file is an error."""
    for profile in PROFILES:
        rel = profile["path"].relative_to(ROOT).as_posix()
        profile["rel"] = rel
        START_SHA[rel] = sha256_file(profile["path"])


def tearDownModule():
    """The digest at the end equals the digest from ``setUpModule``."""
    for profile in PROFILES:
        changed(profile["rel"], START_SHA[profile["rel"]], sha256_file(profile["path"]))


class ShmOpenProbe(unittest.TestCase):
    """The helper under the live profiles, and the allow plant."""

    skip_reason = None
    binary = None
    root = None
    parent = None

    @classmethod
    def setUpClass(cls):
        cls.skip_reason = skip_reason()
        cls.binary = None
        cls.root = None
        cls.parent = None
        if cls.skip_reason:
            return
        cls.parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-shm-parent-"))
        cls.root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-shm-root-"))
        cls.addClassCleanup(shutil.rmtree, cls.parent, ignore_errors=True)
        cls.addClassCleanup(shutil.rmtree, cls.root, ignore_errors=True)
        cls.binary = compile_shm(cls.parent, cls.root, HELPER_C)
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

    def test_unsandboxed_shm_open_succeeds(self):
        """Without ``sandbox-exec``, the helper exits 0 and opens a name.

        Stderr is empty. Stdout matches ``fd=<integer >= 0> errno=0``. A
        failure here is an error, so a later deny is about the profile.
        """
        source = os.path.join(self.parent, "shm.c")
        self.assertEqual(Path(source).read_text(encoding="utf-8"), HELPER_C)
        self.assertEqual(os.path.dirname(self.binary), self.root)
        self.assertTrue(self.binary.endswith(os.sep + "shm"))
        self.assertNotEqual(self.root, self.parent)
        if "/var/folders" in self.binary:
            self.assertTrue(self.binary.startswith("/private/"))
        self.assertEqual(os.path.realpath(self.binary), self.binary)
        self.assertEqual(os.path.realpath(self.root), self.root)
        self.assertEqual(os.path.realpath(self.parent), self.parent)
        result = run_unsandboxed(self.binary)
        self.assertEqual(result.argv[0], self.binary)
        self.assertEqual(len(result.argv), 2)
        self.assertRegex(result.argv[1], r"\A/ccrt[0-9]+\Z")
        self.assertNotIn(sbx.SANDBOX_EXEC, result.argv)
        self.assertIsNone(sbx.profile_error(result))
        self.assertEqual(result.exit_code, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        fd = allow_fd(result.stdout)
        self.assertIsNotNone(fd, result.stdout)
        self.assertGreaterEqual(fd, 0)
        self.assertEqual(classify(result), "allow")

    def test_compile_failure_is_an_error(self):
        """``/usr/bin/cc`` on an empty source is a harness error, not a skip."""
        parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-shm-empty-parent-"))
        root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-shm-empty-root-"))
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        with self.assertRaises(HarnessError) as caught:
            compile_shm(parent, root, "")
        message = str(caught.exception)
        self.assertIn(CC, message)
        self.assertIn("not a skip", message)
        self.assertNotIn("SKIPPED", message)

    def _expect_real_deny(self, profile):
        self.assertTrue(os.path.isfile(profile))
        result = require_denied(profile)
        self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
        self.assertIn(f"PROVIDER_EXECUTABLE={self.binary}", result.argv)
        self.assertEqual(result.argv[-2], self.binary)
        self.assertRegex(result.argv[-1], r"\A/ccrt[0-9]+\Z")
        self.assertIn(os.fspath(profile), result.argv)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stderr, "")
        self.assertEqual(result.stdout, DENY_STDOUT)
        self.assertEqual(classify(result), "deny")
        return result

    def test_wallet_shm_open_is_denied(self):
        """The real wallet profile denies ``shm_open``."""
        self._expect_real_deny(sbx.WALLET_CONFINE_SB)

    def test_did_shm_open_is_denied(self):
        """The real did profile denies ``shm_open``."""
        did = sbx.REPO_ROOT / "capsules/did-provider/confine.sb"
        self._expect_real_deny(did)

    def test_model_shm_open_is_denied(self):
        """The real model profile denies ``shm_open``.

        ``file-read-data (literal "/")`` is not a reason to skip this file.
        The helper starts under it.
        """
        model = sbx.REPO_ROOT / "capsules/model-provider/confine.sb"
        text = model.read_text(encoding="utf-8")
        self.assertIn('file-read-data (literal "/")', text)
        self._expect_real_deny(model)

    def test_falsifier_allow_ipc_posix_shm_is_caught(self):
        """Appending ``(allow ipc-posix-shm)`` lets ``shm_open`` succeed.

        Each real file contains that text zero times and ``(deny default)``
        once. A temp copy appends that one line. The copy's stdout matches
        the allow line, and the helper pointed at the copy fails the deny
        check. A filtered allow is not the plant. Replacing ``(deny default)``
        with ``(allow default)`` is not the plant. Deleting ``(deny default)``
        on the wallet copy still denies. The repo profile bytes stay unchanged.
        """
        originals = {
            profile["path"]: profile["path"].read_bytes() for profile in PROFILES
        }
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-shm-profile-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        try:
            for profile in PROFILES:
                with self.subTest(profile=profile["name"]):
                    text = profile["path"].read_text(encoding="utf-8")
                    self.assertEqual(text.count("(allow ipc-posix-shm)"), 0)
                    self.assertEqual(text.count(DENY_DEFAULT), 1)
                    self.assertTrue(text.endswith("\n"))
                    planted = with_shm_allow(text)
                    self.assertEqual(planted, text + "(allow ipc-posix-shm)\n")
                    self.assertEqual(planted.count("(allow ipc-posix-shm)"), 1)
                    self.assertEqual(planted.count(DENY_DEFAULT), 1)
                    self.assertNotIn("(allow ipc-posix-shm (", planted)
                    self.assertEqual(
                        planted.count("(allow default)"),
                        text.count("(allow default)"),
                    )
                    copy = write_copy(directory, profile["name"] + "-allow", planted)
                    self.assertEqual(Path(copy).read_text(encoding="utf-8"), planted)
                    self.assertNotEqual(os.path.realpath(copy), os.path.realpath(profile["path"]))
                    with self.assertRaises(NotDenied) as caught:
                        require_denied(copy)
                    result = caught.exception.result
                    self.assertIn("ALLOW", str(caught.exception))
                    self.assertIsNone(sbx.profile_error(result))
                    self.assertEqual(result.exit_code, 0)
                    self.assertEqual(result.stderr, "")
                    self.assertGreaterEqual(allow_fd(result.stdout), 0)
                    self.assertEqual(classify(result), "allow")
                    self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
                    self.assertIn(copy, result.argv)
                    self.assertNotIn(os.fspath(profile["path"]), result.argv)

            wallet = PROFILES[0]
            self.assertEqual(wallet["name"], "wallet")
            wallet_text = wallet["path"].read_text(encoding="utf-8")
            deleted = without_deny_default(wallet_text)
            self.assertNotIn("(deny default)", deleted)
            self.assertEqual(deleted.count("(allow ipc-posix-shm)"), 0)
            self.assertNotIn("(allow default)", deleted)
            removed = write_copy(directory, "wallet-deleted", deleted)
            denied = require_denied(removed)
            self.assertEqual(denied.stdout, DENY_STDOUT)
            self.assertEqual(denied.stderr, "")
            self.assertEqual(denied.exit_code, 0)
        finally:
            for profile in PROFILES:
                if profile["path"].read_bytes() != originals[profile["path"]]:
                    raise AssertionError(f"the probe changed {profile['rel']}")


class ShmOpenClassifier(unittest.TestCase):
    """Classifier, pins, and injected results. They compile nothing and launch nothing."""

    def test_skip_reason_names_the_missing_path(self):
        """``skip_reason`` names each missing binary and does not launch."""
        def refuse_subprocess(*_args, **_kwargs):
            raise AssertionError("skip_reason launched a process")

        original = subprocess.run
        subprocess.run = refuse_subprocess
        try:
            live = skip_reason()
            absent_cc = "/usr/bin/cc-not-here"
            absent_sandbox = "/usr/bin/sandbox-exec-not-here"
            missing_cc = skip_reason(cc_path=absent_cc)
            missing_both = skip_reason(cc_path=absent_cc, sandbox_path=absent_sandbox)
            present = skip_reason(cc_path=CC, sandbox_path=sbx.SANDBOX_EXEC)
        finally:
            subprocess.run = original
        if os.path.isfile(CC) and os.path.isfile(sbx.SANDBOX_EXEC):
            self.assertIsNone(live)
        else:
            self.assertIsNotNone(live)
            if not os.path.isfile(CC):
                self.assertIn(CC, live)
            if not os.path.isfile(sbx.SANDBOX_EXEC):
                self.assertIn(sbx.SANDBOX_EXEC, live)
        self.assertIn(absent_cc, missing_cc)
        self.assertIn(absent_cc, missing_both)
        self.assertIn(absent_sandbox, missing_both)
        self.assertIsNone(present)

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

        rel = "tmp/shm-confine.sb"
        self.assertNotIn(rel, START_SHA)
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-shm-byte-"))
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

    def test_classifier_refusal_reasons(self):
        """Each bad result is a harness error with its own reason.

        The cases are a wrong exit, a wrong errno, nonempty deny stderr, a
        malformed allow stdout, nonempty allow stderr, and a profile error
        whose text says ``Operation not permitted``. They launch nothing.
        """
        samples = (
            (
                "wrong exit",
                sbx.Result(exit_code=2, stdout=DENY_STDOUT, stderr="", argv=["/private/shm"]),
            ),
            (
                "wrong errno",
                sbx.Result(
                    exit_code=0,
                    stdout="fd=-1 errno=2\n",
                    stderr="",
                    argv=["/private/shm"],
                ),
            ),
            (
                "nonempty deny stderr",
                sbx.Result(
                    exit_code=0,
                    stdout=DENY_STDOUT,
                    stderr="noise\n",
                    argv=["/private/shm"],
                ),
            ),
            (
                "malformed allow stdout",
                sbx.Result(
                    exit_code=0,
                    stdout="fd=3 errno=0",
                    stderr="",
                    argv=["/private/shm"],
                ),
            ),
            (
                "nonempty allow stderr",
                sbx.Result(
                    exit_code=0,
                    stdout="fd=3 errno=0\n",
                    stderr="noise\n",
                    argv=["/private/shm"],
                ),
            ),
            (
                "profile error",
                sbx.Result(
                    exit_code=sbx.PROFILE_ERROR_EXIT,
                    stdout=DENY_STDOUT,
                    stderr="Operation not permitted\n",
                    argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/shm"],
                ),
            ),
        )
        reasons = []
        for label, result in samples:
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
                reasons.append(message)
        self.assertEqual(len(set(reasons)), len(samples))
        for message in reasons:
            hits = [label for label, _result in samples if label in message]
            self.assertEqual(len(hits), 1)

    def test_recorded_allow_is_expected_failure(self):
        """A recorded allow is an expected failure whose docstring names the finding.

        The result is injected. The finding is written under a temp repo.
        Its first line contains CRITICAL, the live commit, and the live
        sha256. ``CRITICAL.md`` receives that same paragraph. The marked
        test is an expected failure, so the gate stays green. The same
        raise without the mark is a failure.
        """
        allow = sbx.Result(
            exit_code=0,
            stdout="fd=3 errno=0\n",
            stderr="",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", "/private/shm", "/ccrt042"],
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
        with tempfile.TemporaryDirectory(prefix="ccrt-shm-finding-") as tmp:
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
            def test_wallet_shm_open_is_denied(self):
                """plain"""
                raise NotDenied(allow)

        unmarked = unittest.TestResult()
        Unmarked("test_wallet_shm_open_is_denied").run(unmarked)
        self.assertEqual(len(unmarked.failures), 1)
        self.assertEqual(unmarked.expectedFailures, [])
        self.assertEqual(unmarked.errors, [])

        class Recorded(unittest.TestCase):
            def test_wallet_shm_open_is_denied(self):
                """plain"""
                raise NotDenied(allow)

        mark_expected(Recorded, "test_wallet_shm_open_is_denied", FINDINGS["wallet"])
        method = Recorded.test_wallet_shm_open_is_denied
        self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
        self.assertIn(FINDINGS["wallet"], method.__doc__)
        recorded = unittest.TestResult()
        Recorded("test_wallet_shm_open_is_denied").run(recorded)
        self.assertEqual(len(recorded.expectedFailures), 1)
        self.assertEqual(recorded.failures, [])
        self.assertEqual(recorded.errors, [])
        self.assertEqual(recorded.unexpectedSuccesses, [])

    def test_harness_error_stays_error(self):
        """An injected harness error stays an error. It is not a deny, an allow, or a skip."""
        wrong_exit = sbx.Result(
            exit_code=2,
            stdout=DENY_STDOUT,
            stderr="",
            argv=["/private/shm"],
        )
        wrong_errno = sbx.Result(
            exit_code=0,
            stdout="fd=-1 errno=13\n",
            stderr="",
            argv=["/private/shm"],
        )
        profile_error = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout="fd=3 errno=0\n",
            stderr="Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC],
        )
        injected = (wrong_exit, wrong_errno, profile_error)
        for result in injected:
            with self.assertRaises(HarnessError):
                classify(result)

        class Body(unittest.TestCase):
            def test_wallet_shm_open_is_denied(self):
                classify(wrong_exit)

        body = unittest.TestResult()
        Body("test_wallet_shm_open_is_denied").run(body)
        self.assertEqual(len(body.errors), 1)
        self.assertEqual(body.failures, [])
        self.assertEqual(body.expectedFailures, [])
        self.assertEqual(body.skipped, [])

        class Setup(unittest.TestCase):
            def setUp(self):
                raise HarnessError("wrong exit 2 is a harness error, not a deny")

            @unittest.expectedFailure
            def test_wallet_shm_open_is_denied(self):
                raise NotDenied(wrong_exit)

        setup = unittest.TestResult()
        Setup("test_wallet_shm_open_is_denied").run(setup)
        self.assertEqual(len(setup.errors), 1)
        self.assertEqual(setup.expectedFailures, [])
        self.assertEqual(setup.skipped, [])
        self.assertIn("wrong exit", setup.errors[0][1])

    def test_unresolved_storage_path_is_an_error(self):
        """A ``/var/folders`` storage path without ``/private`` errors before launch."""
        bad = "/var/folders/cc/shm-root"
        calls = []

        def refuse_run(*args, **kwargs):
            calls.append(("run", args, kwargs))
            raise AssertionError("sandbox-exec started")

        def refuse_subprocess(*args, **kwargs):
            calls.append(("subprocess", args, kwargs))
            raise AssertionError("subprocess started")

        original_run = sbx.run
        original_subprocess = subprocess.run
        sbx.run = refuse_run
        subprocess.run = refuse_subprocess
        try:
            with self.assertRaises(HarnessError) as caught:
                run_sandboxed(
                    "/private/shm",
                    bad,
                    "/private/parent",
                    sbx.WALLET_CONFINE_SB,
                    "/ccrt042",
                )
        finally:
            sbx.run = original_run
            subprocess.run = original_subprocess
        self.assertEqual(calls, [])
        message = str(caught.exception)
        self.assertIn(bad, message)
        self.assertIn("/var/folders", message)
        self.assertNotIn("/private/var/folders/cc/shm-root", message)


if __name__ == "__main__":
    unittest.main()
