"""Probe ``/bin/kill -0`` of another pid on the wallet, did, and model profiles.

Grade row 12 rests on those seatbelt profiles. Each profile refuses a signal
that no rule grants. The pinned executable and the launched executable are
both ``/bin/kill``. The arguments are ``-0`` and this process's pid. The
signal does not kill the target.

Confined launches go through ``sbx.run`` only. The unsandboxed control and
the two git commands are ``subprocess``. They do not start ``sandbox-exec``.

``setUpModule`` records each profile sha256. ``tearDownModule`` compares it
through ``changed`` from ``test_confine_mach``. An owner edit between those
two calls raises ``the probe changed <rel>``. A difference from an older
measurement is not a failure.

An allow on a real profile is CRITICAL. Wallet or did:
``findings/CRITICAL-confine-044.md``. Model:
``findings/CRITICAL-cc-model-confine-044.md``. The finding names the
profile file's last commit, that commit's subject, and the sha256 of the
bytes this run read. A deny writes neither file. ``(allow signal)`` is the
plant. ``(allow signal (target self))`` and deleting ``(deny default)`` are
not.
"""

import inspect
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import sbx
from test_confine_mach import changed, require_resolved, sha256_file

# lab/redteam/py/<this> -> parents[3] is the repo root. Same rule as sbx.
ROOT = Path(__file__).resolve().parents[3]

KILL = "/bin/kill"
ALLOW_SIGNAL = "(allow signal)"
DENY_DEFAULT = "(deny default)"
SELF_SIGNAL = "(allow signal (target self))"
PR_UNKNOWN = "PR unknown"

FINDINGS = {
    "wallet": "lab/redteam/findings/CRITICAL-confine-044.md",
    "did": "lab/redteam/findings/CRITICAL-confine-044.md",
    "model": "lab/redteam/findings/CRITICAL-cc-model-confine-044.md",
}
FINDING_IDS = {
    "wallet": "CRITICAL-confine-044",
    "did": "CRITICAL-confine-044",
    "model": "CRITICAL-cc-model-confine-044",
}
PROFILES = (
    {"name": "wallet", "path": sbx.WALLET_CONFINE_SB},
    {
        "name": "did",
        "path": sbx.REPO_ROOT / "capsules/did-provider/confine.sb",
    },
    {
        "name": "model",
        "path": sbx.REPO_ROOT / "capsules/model-provider/confine.sb",
    },
)
DENY_TESTS = {
    "wallet": "test_wallet_signal_is_denied",
    "did": "test_did_signal_is_denied",
    "model": "test_model_signal_is_denied",
}
TEST_PROFILE = {method: name for name, method in DENY_TESTS.items()}

START_SHA = {}
START_FINDINGS = {}
ALLOWS = set()
# .gitkeep and grant-binding-002.md must both exist. A finding another
# module creates or removes is recorded when present and omitted when absent.
REQUIRED_FINDINGS = (".gitkeep", "grant-binding-002.md")
PRESERVED = (".gitkeep", "grant-binding-002.md")
COMMAND_TIMEOUT_SECONDS = 5


class NotDenied(AssertionError):
    """The profile allowed the signal."""


class HarnessError(Exception):
    """A profile error, a bad control, or a result that is not a deny.

    These fail the test. They are not a skip and they are not a deny.
    ``expectedFailure`` hides every exception in the test body, so a
    profile error is raised from ``setUp`` instead.
    """


def git_env():
    """Git sees the given repo, not a caller-injected ``GIT_DIR``."""
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def git_text(repo, *args):
    """One git command. The two finding lookups are the only callers."""
    completed = subprocess.run(
        ["git", "-C", os.fspath(repo), *args],
        capture_output=True,
        text=True,
        env=git_env(),
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "git " + " ".join(args) + " failed"
        raise HarnessError(detail)
    return completed.stdout.strip()


def profile_commit(repo, relative):
    """``git log -1 --format=%H HEAD -- <file>`` for the bytes under test."""
    commit = git_text(repo, "log", "-1", "--format=%H", "HEAD", "--", relative)
    if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
        raise HarnessError(f"{relative} is not a full sha: {commit!r}")
    return commit


def profile_subject(repo, commit):
    """``git log -1 --format=%s <commit>``. The commit is the profile's last change.

    ``HEAD``'s subject can name a later, unrelated pull request. The finding
    uses this commit's subject, not that one.
    """
    return git_text(repo, "log", "-1", "--format=%s", commit)


def commit_and_subject(repo, relative):
    """The profile file's last commit and that commit's subject."""
    commit = profile_commit(repo, relative)
    return commit, profile_subject(repo, commit)


def pr_label(subject):
    """``PR #N`` when the subject contains ``PR #`` and digits. Otherwise ``PR unknown``."""
    token = "PR #"
    start = 0
    while True:
        at = subject.find(token, start)
        if at < 0:
            return PR_UNKNOWN
        digits = []
        for char in subject[at + len(token):]:
            if not char.isdigit():
                break
            digits.append(char)
        if digits:
            return "PR #" + "".join(digits)
        start = at + len(token)


def profile_key(path):
    return Path(path).resolve().relative_to(ROOT.resolve()).as_posix()


def by_name(name):
    for profile in PROFILES:
        if profile["name"] == name:
            return profile
    raise HarnessError(f"unknown profile {name}")


def critical_line(name, commit, subject, digest):
    """The finding's first line. It carries the commit, the PR, and the sha256."""
    return (
        f"CRITICAL {FINDING_IDS[name]} {commit} {pr_label(subject)} "
        f"sha256 {digest}"
    )


def describe(git_root, name, relative, digest):
    """The finding body. The subject is the profile file's last-change commit."""
    commit, subject = commit_and_subject(git_root, relative)
    line = critical_line(name, commit, subject, digest)
    body = f"{line}\nprofile: {relative}\nobserved: allow signal\n"
    return commit, subject, body


def skip_reason(sandbox_path=sbx.SANDBOX_EXEC, kill_path=KILL):
    """None when both binaries exist. Otherwise a reason naming each missing path.

    This does not launch and it does not read a control result.
    """
    missing = [
        path for path in (sandbox_path, kill_path) if not os.path.isfile(path)
    ]
    if not missing:
        return None
    return "missing " + " ".join(missing)


def classify(result, pid):
    """``deny``, ``allow``, or a harness error.

    Asks ``sbx.profile_error`` before a deny or an allow. Exit 65 is that
    profile error even when stderr contains the pid and ``Operation not
    permitted``.
    """
    problem = sbx.profile_error(result)
    if problem is not None:
        raise HarnessError(f"{problem} -- not a deny")
    target = str(pid)
    stdout_empty = result.stdout == ""
    stderr_empty = result.stderr == ""
    has_pid = target in result.stderr
    has_permission = "Operation not permitted" in result.stderr
    if result.exit_code == 0 and stdout_empty and stderr_empty:
        return "allow"
    if result.exit_code == 1 and stdout_empty and has_pid and has_permission:
        return "deny"
    if result.exit_code == 1 and not stdout_empty:
        raise HarnessError("deny stdout")
    if result.exit_code == 1 and stderr_empty:
        raise HarnessError("empty stderr")
    if result.exit_code == 1 and not has_pid:
        raise HarnessError("missing target pid")
    if result.exit_code == 1 and not has_permission:
        raise HarnessError("missing permission text")
    if result.exit_code == 0 and not stderr_empty:
        raise HarnessError("allow stderr")
    if result.exit_code == 0 and not stdout_empty:
        raise HarnessError("allow stdout")
    raise HarnessError(f"wrong exit {result.exit_code}")


def signal_under(profile, pid):
    """Run ``/bin/kill -0 <pid>`` under ``profile``. ``sbx.run`` is the only launcher."""
    parent = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-sig-parent-"))
    root = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-sig-root-"))
    try:
        require_resolved(root)
        require_resolved(parent)
        return sbx.run(
            pinned_exe=KILL,
            launch_exe=KILL,
            args=("-0", str(pid)),
            storage_root=root,
            storage_parent=parent,
            profile=profile,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    finally:
        shutil.rmtree(parent, ignore_errors=True)
        shutil.rmtree(root, ignore_errors=True)


def require_signal_denied(profile, pid):
    """The one helper. A deny returns the result. An allow raises ``NotDenied``."""
    result = signal_under(profile, pid)
    if classify(result, pid) != "deny":
        raise NotDenied(
            "ALLOW: kill -0 reached another pid under the profile.\n"
            f"  exit: {result.exit_code}\n"
            f"  stdout: {result.stdout!r}\n"
            f"  stderr: {result.stderr!r}"
        )
    return result


def run_unsandboxed(pid):
    """``/bin/kill -0 <pid>`` with no ``sandbox-exec``."""
    argv = [KILL, "-0", str(pid)]
    completed = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    return sbx.Result(
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        argv=argv,
    )


def require_unsandboxed(result):
    """The control must exit 0 with empty streams. Any other result is an error.

    This does not skip.
    """
    if result.argv and result.argv[0] == sbx.SANDBOX_EXEC:
        raise HarnessError("unsandboxed control started sandbox-exec")
    if result.exit_code == 0 and result.stdout == "" and result.stderr == "":
        return
    raise HarnessError(
        "unsandboxed kill is a harness error, not a skip and not a deny: "
        f"exit {result.exit_code} stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def append_rule(text, rule):
    """Append one profile line. This does not interpret the profile."""
    body = text if text.endswith("\n") else text + "\n"
    return body + rule + "\n"


def write_copy(directory, name, text):
    path = os.path.join(directory, name + ".sb")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def probe_tests(case_cls):
    """Test functions defined on ``case_cls`` itself."""
    found = {}
    for name, member in case_cls.__dict__.items():
        if name.startswith("test_") and inspect.isfunction(member):
            found[name] = member
    return found


def mark_snapshot(case_cls):
    found = {}
    for name, member in probe_tests(case_cls).items():
        found[name] = (
            member.__doc__,
            getattr(member, "__unittest_expecting_failure__", False),
        )
    return found


def restore_marks(case_cls, baseline):
    """Put every probe test's docstring and marker back."""
    for name, (doc, flag) in baseline.items():
        method = getattr(case_cls, name)
        method.__doc__ = doc
        if flag:
            method.__unittest_expecting_failure__ = True
        elif hasattr(method, "__unittest_expecting_failure__"):
            del method.__unittest_expecting_failure__


def mark_recorded(case_cls, name):
    """Mark only that profile's deny test. The docstring names the finding file."""
    method = getattr(case_cls, DENY_TESTS[name])
    method.__doc__ = (
        "The live profile allowed a signal to another pid. "
        f"Finding file: {FINDINGS[name]}"
    )
    method.__unittest_expecting_failure__ = True


def marker_problems(case_cls, allowed_name, baseline):
    """Missing, overbroad, or untitled marks after a recorded allow of one profile.

    The target test must be marked and its docstring must name the finding.
    A sibling test, any other test, or the class gaining a mark is overbroad.
    """
    problems = []
    if getattr(case_cls, "__unittest_expecting_failure__", False):
        problems.append("overbroad class")
    target = DENY_TESTS[allowed_name]
    for name, member in probe_tests(case_cls).items():
        marked = getattr(member, "__unittest_expecting_failure__", False)
        doc = member.__doc__ or ""
        if name == target:
            if not marked:
                problems.append("missing marker")
            elif FINDINGS[allowed_name] not in doc:
                problems.append("missing finding docstring")
            continue
        base_doc, base_flag = baseline[name]
        if marked != base_flag or doc != (base_doc or ""):
            problems.append(f"overbroad {name}")
    return problems


def leaked_markers(case_cls, baseline):
    """Markers that differ from ``baseline`` after the injection is restored."""
    leaked = []
    if getattr(case_cls, "__unittest_expecting_failure__", False):
        leaked.append("class")
    for name, (doc, flag) in baseline.items():
        method = getattr(case_cls, name)
        marked = getattr(method, "__unittest_expecting_failure__", False)
        if marked != flag or (method.__doc__ or "") != (doc or ""):
            leaked.append(name)
    return leaked


def append_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    if text in existing:
        return
    if existing and not existing.endswith("\n"):
        existing += "\n"
    path.write_text(existing + text, encoding="utf-8")


def append_line_once(path, line):
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.is_file() else ""
    if line in existing.splitlines():
        return
    if existing and not existing.endswith("\n"):
        existing += "\n"
    path.write_text(existing + line + "\n", encoding="utf-8")


def apply_allow(repo, name):
    """Write one allow finding under ``repo`` and mark only that deny test.

    The commit and the subject come from the profile file's last change on
    ``HEAD``. The sha256 is the bytes this call read. Nothing is stored.
    """
    profile = by_name(name)
    relative = profile_key(profile["path"])
    _commit, _subject, body = describe(
        ROOT, name, relative, sha256_file(profile["path"])
    )
    destination = Path(repo) / FINDINGS[name]
    append_text(destination, body)
    append_line_once(Path(repo) / "lab" / "redteam" / "CRITICAL.md", FINDINGS[name])
    mark_recorded(SignalProbe, name)
    return destination


def note_signal(repo, name, outcome):
    """A deny writes nothing. An allow is ``apply_allow``."""
    if outcome != "allow":
        return None
    apply_allow(repo, name)
    return FINDINGS[name]


def findings_snapshot(repo=ROOT):
    """Bytes of ``lab/redteam/findings`` plus ``CRITICAL.md``, if that file exists.

    ``.gitkeep`` and ``grant-binding-002.md`` must both exist. A finding
    another module creates or removes is recorded when present and omitted
    when absent.
    """
    directory = Path(repo) / "lab" / "redteam" / "findings"
    if not directory.is_dir():
        raise HarnessError(
            "missing preserved findings: " + ", ".join(REQUIRED_FINDINGS)
        )
    found = {}
    for path in directory.iterdir():
        if path.is_file():
            found[path.name] = path.read_bytes()
    missing = [name for name in REQUIRED_FINDINGS if name not in found]
    if missing:
        raise HarnessError("missing preserved findings: " + ", ".join(missing))
    critical = Path(repo) / "lab" / "redteam" / "CRITICAL.md"
    found["/CRITICAL.md"] = critical.read_bytes() if critical.is_file() else None
    return found


def preserved_view(snapshot):
    """The findings this probe must leave byte-identical, absent or present."""
    return {name: snapshot.get(name) for name in PRESERVED}


def unchanged_findings(start, end):
    """Raise when any finding's bytes differ, including one that appeared or vanished.

    A name missing from both sides is unchanged. The reason lists every such name.
    """
    names = sorted(set(start) | set(end))
    changed_names = [name for name in names if start.get(name) != end.get(name)]
    if changed_names:
        raise AssertionError(
            "deny changed lab/redteam/findings: " + ", ".join(changed_names)
        )


PTY_FINDING_NAMES = (
    "CRITICAL-confine-061.md",
    "CRITICAL-cc-model-confine-061.md",
)


def plant_pty_finding(repo):
    """An existing 061 record, the kind a pty allow writes beside a signal deny.

    The signal deny does not create this file. Callers check that a later
    deny leaves these bytes in place.
    """
    findings = Path(repo) / "lab" / "redteam" / "findings"
    findings.mkdir(parents=True)
    (findings / ".gitkeep").write_bytes(b"")
    (findings / "grant-binding-002.md").write_bytes(b"kept\n")
    wallet = b"CRITICAL CRITICAL-confine-061 pty open preserved\n"
    model = b"CRITICAL CRITICAL-cc-model-confine-061 pty open preserved\n"
    (findings / "CRITICAL-confine-061.md").write_bytes(wallet)
    (findings / "CRITICAL-cc-model-confine-061.md").write_bytes(model)
    body = wallet + model
    (Path(repo) / "lab" / "redteam" / "CRITICAL.md").write_bytes(body)
    return body


def assert_pty_critical_preserved(start, end):
    """Keep a 061 ``CRITICAL.md`` that was already present.

    ``unchanged_findings`` owns byte preservation for the whole snapshot.
    Present content must name 061 and must be free of signal findings.
    """
    unchanged_findings(start, end)
    end_critical = end.get("/CRITICAL.md")
    if end_critical is None:
        return
    text = end_critical.decode("utf-8")
    if "CRITICAL-confine-044" in text or "CRITICAL-cc-model-confine-044" in text:
        raise AssertionError("lab/redteam/CRITICAL.md contains a signal finding while signals are denied")
    if "061" not in text:
        raise AssertionError("lab/redteam/CRITICAL.md lacks a 061 PTY finding")


def _git(repo, *args):
    """A git command in a temporary repo. It does not touch this checkout."""
    completed = subprocess.run(
        [
            "git", "-C", repo,
            "-c", "user.name=probe",
            "-c", "user.email=probe@example.invalid",
            "-c", "commit.gpgsign=false",
            "-c", "core.hooksPath=/dev/null",
            *args,
        ],
        capture_output=True,
        text=True,
        env=git_env(),
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.strip() or "git failed")
    return completed.stdout.strip()


def setUpModule():
    """Record the three live profile digests and the findings directory."""
    for profile in PROFILES:
        START_SHA[profile_key(profile["path"])] = sha256_file(profile["path"])
    global START_FINDINGS
    START_FINDINGS = findings_snapshot()


def tearDownModule():
    """The digest at the end equals the digest from ``setUpModule``.

    A deny creates neither 044 finding and leaves the existing findings bytes
    unchanged.
    """
    for profile in PROFILES:
        rel = profile_key(profile["path"])
        changed(rel, START_SHA[rel], sha256_file(profile["path"]))
    end = findings_snapshot()
    unchanged_findings(preserved_view(START_FINDINGS), preserved_view(end))
    if ALLOWS:
        return
    unchanged_findings(START_FINDINGS, end)


class SignalProbe(unittest.TestCase):
    """``/bin/kill -0`` under the live profiles, and the allow plant."""

    skip_reason = None

    @classmethod
    def setUpClass(cls):
        cls.skip_reason = skip_reason()
        if cls.skip_reason:
            return
        pid = os.getpid()
        for profile in PROFILES:
            result = signal_under(profile["path"], pid)
            # A profile error stops the class. A later deny must not hide it.
            outcome = classify(result, pid)
            if outcome == "allow":
                ALLOWS.add(profile["name"])
                note_signal(ROOT, profile["name"], outcome)

    def setUp(self):
        if type(self).skip_reason:
            self.skipTest(type(self).skip_reason)
        self.profile_name = TEST_PROFILE.get(self._testMethodName)
        if self.profile_name is None:
            return
        self.pid = os.getpid()
        # One launch, classified once. expectedFailure swallows a profile
        # error raised in the test body, so that error still leaves setUp.
        # Only a validated allow is stored for the test body to raise.
        self.signal_failure = None
        try:
            self.signal_result = require_signal_denied(
                by_name(self.profile_name)["path"], self.pid
            )
        except NotDenied as error:
            self.signal_failure = error

    def test_kill_and_sandbox_present_or_skip(self):
        """Both binaries exist, or this class skips with the missing path."""
        reason = skip_reason()
        if reason:
            self.skipTest(reason)
        self.assertIsNone(reason)
        self.assertTrue(os.path.isfile(KILL))
        self.assertTrue(os.path.isfile(sbx.SANDBOX_EXEC))
        self.assertEqual(KILL, "/bin/kill")
        self.assertEqual(sbx.SANDBOX_EXEC, "/usr/bin/sandbox-exec")

    def test_unsandboxed_kill_reaches_the_pid(self):
        """``/bin/kill -0 <pid>`` with no sandbox-exec exits 0 and both streams are empty.

        A failure here is an error, so a later deny is about the profile.
        """
        pid = os.getpid()
        result = run_unsandboxed(pid)
        self.assertEqual(result.argv, [KILL, "-0", str(pid)])
        self.assertNotEqual(result.argv[0], sbx.SANDBOX_EXEC)
        self.assertNotIn(sbx.SANDBOX_EXEC, result.argv)
        require_unsandboxed(result)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_harness_error_stays_error(self):
        """An unsandboxed exit of 1 is a harness error. It does not skip."""
        bad = sbx.Result(
            exit_code=1,
            stdout="",
            stderr="",
            argv=[KILL, "-0", str(os.getpid())],
        )
        with self.assertRaises(HarnessError) as caught:
            require_unsandboxed(bad)
        self.assertIn("unsandboxed", str(caught.exception))
        self.assertNotIsInstance(caught.exception, unittest.SkipTest)

    def _expect_real(self, name):
        self.assertEqual(self.profile_name, name)
        if self.signal_failure is not None:
            raise self.signal_failure
        result = self.signal_result
        # Deny is require_signal_denied's classify. This checks the launch.
        self.assertEqual(result.argv[0], sbx.SANDBOX_EXEC)
        self.assertIn(f"PROVIDER_EXECUTABLE={KILL}", result.argv)
        self.assertEqual(result.argv[-3:], [KILL, "-0", str(self.pid)])
        return result

    def test_wallet_signal_is_denied(self):
        """The real wallet profile denies ``kill -0`` of another pid."""
        self._expect_real("wallet")

    def test_did_signal_is_denied(self):
        """The real did profile denies ``kill -0`` of another pid."""
        self._expect_real("did")

    def test_model_signal_is_denied(self):
        """The real model profile denies ``kill -0`` of another pid.

        ``file-read-data (literal "/")`` is not a reason to skip this file.
        ``/bin/kill`` starts under it.
        """
        self._expect_real("model")

    def test_falsifier_allow_signal_is_caught(self):
        """Appending ``(allow signal)`` lets ``kill -0`` through.

        On a real deny, each source contains that exact string zero times.
        A temp copy appends it, the copy exits 0 with empty streams, and the
        helper pointed at the copy fails the deny check. The repo bytes stay
        unchanged.

        ``(allow signal (target self))`` does not contain that exact string
        and still denies. Deleting ``(deny default)`` still denies. Those two
        edits, and the zero-count check, run only when that profile denied.
        A recorded allow is already the finding.
        """
        pid = os.getpid()
        originals = {
            profile["path"]: profile["path"].read_bytes() for profile in PROFILES
        }
        directory = os.path.realpath(tempfile.mkdtemp(prefix="ccrt-sig-copy-"))
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        try:
            for profile in PROFILES:
                with self.subTest(profile=profile["name"]):
                    text = profile["path"].read_text(encoding="utf-8")
                    if profile["name"] not in ALLOWS:
                        self.assertEqual(text.count(ALLOW_SIGNAL), 0, profile["name"])
                        self.assertEqual(text.count(DENY_DEFAULT), 1, profile["name"])
                    planted = append_rule(text, ALLOW_SIGNAL)
                    self.assertGreaterEqual(planted.count(ALLOW_SIGNAL), 1)
                    copy = write_copy(directory, profile["name"] + "-allow", planted)
                    self.assertNotEqual(
                        os.path.realpath(copy), os.path.realpath(profile["path"])
                    )
                    result = signal_under(copy, pid)
                    self.assertIsNone(sbx.profile_error(result))
                    self.assertEqual(result.exit_code, 0, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(classify(result, pid), "allow")
                    with self.assertRaises(NotDenied) as caught:
                        require_signal_denied(copy, pid)
                    self.assertIn("ALLOW", str(caught.exception))
            if "wallet" in ALLOWS:
                return
            wallet = by_name("wallet")["path"].read_text(encoding="utf-8")
            self_text = append_rule(wallet, SELF_SIGNAL)
            self.assertEqual(self_text.count(ALLOW_SIGNAL), 0)
            self_result = require_signal_denied(
                write_copy(directory, "wallet-self", self_text), pid
            )
            self.assertEqual(self_result.exit_code, 1)
            self.assertEqual(self_result.stdout, "")
            self.assertIn(str(pid), self_result.stderr)
            self.assertIn("Operation not permitted", self_result.stderr)
            deny_line = DENY_DEFAULT + "\n"
            self.assertEqual(wallet.count(deny_line), 1)
            deleted = wallet.replace(deny_line, "", 1)
            self.assertEqual(deleted.count(DENY_DEFAULT), 0)
            self.assertNotIn(ALLOW_SIGNAL, deleted)
            deleted_result = require_signal_denied(
                write_copy(directory, "wallet-deleted", deleted), pid
            )
            self.assertEqual(deleted_result.exit_code, 1)
            self.assertIn("Operation not permitted", deleted_result.stderr)
        finally:
            changed_paths = [
                profile_key(path)
                for path, blob in originals.items()
                if path.read_bytes() != blob
            ]
            if changed_paths:
                raise AssertionError(
                    "the probe changed " + " ".join(changed_paths)
                )


class SignalRules(unittest.TestCase):
    """Classifiers, markers, and provenance. They do not launch ``/bin/kill``."""

    def assert_findings_match_allows(self, repo, allows):
        """Each finding path belongs to all profiles that name it."""
        recorded = {FINDINGS[name] for name in allows}
        for relative in set(FINDINGS.values()):
            path = Path(repo) / relative
            if relative in recorded:
                self.assertTrue(path.is_file(), relative)
            else:
                self.assertFalse(path.exists(), relative)

    def test_skip_policy_falsifiers(self):
        """``skip_reason`` names each missing path, launches nothing, and takes no control."""
        signature = inspect.signature(skip_reason)
        self.assertNotIn("result", signature.parameters)
        self.assertNotIn("stdout", signature.parameters)
        with self.assertRaises(TypeError):
            skip_reason(result=sbx.Result(exit_code=0, stdout="", stderr="", argv=[]))

        def boom(*_args, **_kwargs):
            raise AssertionError("skip_reason launched")

        saved_run = subprocess.run
        saved_sbx = sbx.run
        subprocess.run = boom
        sbx.run = boom
        try:
            with tempfile.TemporaryDirectory(prefix="ccrt-sig-skip-") as directory:
                present_sandbox = os.path.join(directory, "sandbox-exec")
                present_kill = os.path.join(directory, "kill")
                absent_sandbox = os.path.join(directory, "no-sandbox-exec")
                absent_kill = os.path.join(directory, "no-kill")
                for path in (present_sandbox, present_kill):
                    open(path, "w", encoding="utf-8").close()
                sandbox_only = skip_reason(
                    sandbox_path=absent_sandbox, kill_path=present_kill
                )
                self.assertIn(absent_sandbox, sandbox_only)
                self.assertNotIn(absent_kill, sandbox_only)
                self.assertNotIn(present_kill, sandbox_only)
                kill_only = skip_reason(
                    sandbox_path=present_sandbox, kill_path=absent_kill
                )
                self.assertIn(absent_kill, kill_only)
                self.assertNotIn(absent_sandbox, kill_only)
                self.assertNotIn(present_sandbox, kill_only)
                both = skip_reason(
                    sandbox_path=absent_sandbox, kill_path=absent_kill
                )
                self.assertIn(absent_sandbox, both)
                self.assertIn(absent_kill, both)
                self.assertIsNone(
                    skip_reason(
                        sandbox_path=present_sandbox, kill_path=present_kill
                    )
                )
        finally:
            subprocess.run = saved_run
            sbx.run = saved_sbx

    def test_profile_bytes_match_the_start(self):
        """Each end digest matches the start digest. Unequal digests name the rel.

        This test stores no digest. ``tearDownModule`` calls ``changed``.
        """
        source = Path(__file__).read_text(encoding="utf-8")
        self.assertIn("changed(", inspect.getsource(tearDownModule))
        self.assertEqual(ROOT, sbx.REPO_ROOT)
        self.assertEqual(ROOT, Path(__file__).resolve().parents[3])
        for profile in PROFILES:
            rel = profile_key(profile["path"])
            digest = sha256_file(profile["path"])
            self.assertNotIn(digest, source)
            changed(rel, START_SHA[rel], digest)
            if profile["name"] == "wallet":
                self.assertEqual(profile["path"], sbx.WALLET_CONFINE_SB)
        with self.assertRaises(AssertionError) as caught:
            changed("temporary/rel", "aaa", "bbb")
        self.assertEqual(str(caught.exception), "the probe changed temporary/rel")

    def test_unresolved_storage_path_is_an_error(self):
        """A ``/var/folders`` path that does not start with ``/private`` is an error.

        This does not launch.
        """
        bad = "/var/folders/xx/ccrt-signal"
        self.assertIn("/var/folders", bad)
        self.assertFalse(bad.startswith("/private"))
        with self.assertRaises(Exception) as caught:
            require_resolved(bad)
        message = str(caught.exception)
        self.assertIn("execvp", message)
        self.assertIn("/var/folders", message)

    def test_classifier_refusal_reasons(self):
        """Each harness reason is distinct. A profile error is not a deny.

        These results are built here. Nothing is launched.
        """
        pid = "4242"

        def sample(exit_code, stdout, stderr):
            return sbx.Result(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                argv=[KILL, "-0", pid],
            )

        def reason(result):
            with self.assertRaises(HarnessError) as caught:
                classify(result, pid)
            return str(caught.exception)

        self.assertEqual(
            classify(sample(1, "", f"kill: {pid}: Operation not permitted\n"), pid),
            "deny",
        )
        self.assertEqual(
            classify(
                sample(1, "", f"kill: {pid}: Operation not permitted\n\n"),
                pid,
            ),
            "deny",
        )
        self.assertEqual(classify(sample(0, "", ""), pid), "allow")
        self.assertIn(
            "wrong exit",
            reason(sample(2, "", f"kill: {pid}: Operation not permitted\n")),
        )
        self.assertIn(
            "deny stdout",
            reason(sample(1, "x", f"kill: {pid}: Operation not permitted\n")),
        )
        self.assertIn("empty stderr", reason(sample(1, "", "")))
        self.assertIn(
            "missing target pid",
            reason(sample(1, "", "Operation not permitted\n")),
        )
        self.assertIn(
            "missing permission text",
            reason(sample(1, "", f"kill: {pid}: No such process\n")),
        )
        self.assertIn("allow stderr", reason(sample(0, "", "noise\n")))
        self.assertIn("allow stdout", reason(sample(0, "noise\n", "")))
        profile_error = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout="",
            stderr=f"kill: {pid}: Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", KILL, "-0", pid],
        )
        problem = sbx.profile_error(profile_error)
        self.assertIsNotNone(problem)
        self.assertIn(str(pid), profile_error.stderr)
        self.assertIn("Operation not permitted", profile_error.stderr)
        message = reason(profile_error)
        self.assertIn(problem, message)
        self.assertIn("not a deny", message)

    def test_shared_deny_accepts_extra_stderr(self):
        """The wallet deny test uses ``require_signal_denied``, not an exact stderr line.

        One extra newline is still a deny. A second, stricter stderr check
        fails this test.
        """
        pid = os.getpid()
        deny = sbx.Result(
            exit_code=1,
            stdout="",
            stderr=f"kill: {pid}: Operation not permitted\n\n",
            argv=[
                sbx.SANDBOX_EXEC,
                "-D",
                f"PROVIDER_EXECUTABLE={KILL}",
                KILL,
                "-0",
                str(pid),
            ],
        )
        self.assertEqual(classify(deny, pid), "deny")
        baseline = mark_snapshot(SignalProbe)
        saved = signal_under
        saved_skip = SignalProbe.skip_reason
        method = getattr(SignalProbe, "test_wallet_signal_is_denied")
        method.__doc__ = baseline["test_wallet_signal_is_denied"][0]
        if hasattr(method, "__unittest_expecting_failure__"):
            del method.__unittest_expecting_failure__
        SignalProbe.skip_reason = None
        globals()["signal_under"] = lambda _profile, _launched: deny
        try:
            outcome = unittest.TestResult()
            SignalProbe("test_wallet_signal_is_denied").run(outcome)
            self.assertEqual(outcome.failures, [])
            self.assertEqual(outcome.errors, [])
            self.assertEqual(outcome.expectedFailures, [])
            self.assertEqual(outcome.skipped, [])
            self.assertTrue(outcome.wasSuccessful())
        finally:
            globals()["signal_under"] = saved
            SignalProbe.skip_reason = saved_skip
            restore_marks(SignalProbe, baseline)

    def test_recorded_allow_is_expected_failure(self):
        """``apply_allow`` writes the finding under the temp repo and marks one test.

        The wallet test's docstring names the finding. Sibling tests stay as
        they were. Restoring clears the marker. A missing marker, an overbroad
        marker, and a leaked marker are each reported. A deny writes nothing.
        The temp directory is gone when this returns. The live findings stay
        as they were. An existing 061 pty finding, and its ``CRITICAL.md``
        paragraph, stay byte-identical when signals remain denied.
        """
        baseline = mark_snapshot(SignalProbe)
        live = findings_snapshot()
        directory = tempfile.mkdtemp(prefix="ccrt-sig-finding-")
        quiet = tempfile.mkdtemp(prefix="ccrt-sig-deny-")
        case_cls = SignalProbe
        wallet_name = DENY_TESTS["wallet"]
        try:
            self.assertIsNone(note_signal(quiet, "wallet", "deny"))
            self.assertFalse((Path(quiet) / FINDINGS["wallet"]).exists())
            self.assertFalse((Path(quiet) / "lab" / "redteam" / "CRITICAL.md").exists())
            self.assertEqual(leaked_markers(case_cls, baseline), [])

            destination = apply_allow(directory, "wallet")
            text = destination.read_text(encoding="utf-8")
            first = text.splitlines()[0]
            self.assertTrue(first.startswith("CRITICAL "))
            relative = profile_key(by_name("wallet")["path"])
            commit, subject = commit_and_subject(ROOT, relative)
            digest = sha256_file(by_name("wallet")["path"])
            self.assertIn(commit, first)
            self.assertIn(digest, first)
            self.assertIn(pr_label(subject), first)
            self.assertIn(FINDING_IDS["wallet"], first)
            self.assertNotIn(commit, Path(__file__).read_text(encoding="utf-8"))
            self.assertNotIn(digest, Path(__file__).read_text(encoding="utf-8"))
            listed = (Path(directory) / "lab" / "redteam" / "CRITICAL.md").read_text(
                encoding="utf-8"
            )
            self.assertIn(FINDINGS["wallet"], listed)
            self.assertFalse((Path(directory) / FINDINGS["model"]).exists())
            self.assertEqual(marker_problems(case_cls, "wallet", baseline), [])
            wallet_method = getattr(case_cls, wallet_name)
            self.assertTrue(getattr(wallet_method, "__unittest_expecting_failure__", False))
            self.assertIn(FINDINGS["wallet"], wallet_method.__doc__)
            for name, method_name in DENY_TESTS.items():
                if name == "wallet":
                    continue
                method = getattr(case_cls, method_name)
                self.assertEqual(method.__doc__, baseline[method_name][0])
                self.assertEqual(
                    getattr(method, "__unittest_expecting_failure__", False),
                    baseline[method_name][1],
                )

            del wallet_method.__unittest_expecting_failure__
            self.assertIn("missing marker", marker_problems(case_cls, "wallet", baseline))
            wallet_method.__unittest_expecting_failure__ = True
            wallet_method.__doc__ = "plain"
            self.assertIn(
                "missing finding docstring",
                marker_problems(case_cls, "wallet", baseline),
            )
            mark_recorded(case_cls, "wallet")

            extra = getattr(case_cls, "test_falsifier_allow_signal_is_caught")
            extra_flag = getattr(extra, "__unittest_expecting_failure__", False)
            extra.__unittest_expecting_failure__ = not extra_flag
            self.assertIn(
                "overbroad test_falsifier_allow_signal_is_caught",
                marker_problems(case_cls, "wallet", baseline),
            )
            if extra_flag:
                extra.__unittest_expecting_failure__ = True
            else:
                del extra.__unittest_expecting_failure__

            case_cls.__unittest_expecting_failure__ = True
            self.assertIn("overbroad class", marker_problems(case_cls, "wallet", baseline))
            del case_cls.__unittest_expecting_failure__

            self.assertEqual(marker_problems(case_cls, "wallet", baseline), [])
            restore_marks(case_cls, baseline)
            self.assertEqual(leaked_markers(case_cls, baseline), [])
            wallet_method = getattr(case_cls, wallet_name)
            wallet_method.__unittest_expecting_failure__ = not baseline[wallet_name][1]
            self.assertIn(wallet_name, leaked_markers(case_cls, baseline))
            restore_marks(case_cls, baseline)
            self.assertEqual(leaked_markers(case_cls, baseline), [])
        finally:
            if getattr(case_cls, "__unittest_expecting_failure__", False):
                del case_cls.__unittest_expecting_failure__
            restore_marks(case_cls, baseline)
            shutil.rmtree(directory)
            shutil.rmtree(quiet)
        self.assertFalse(os.path.exists(directory))
        self.assertFalse(os.path.exists(quiet))
        self.assertEqual(leaked_markers(case_cls, baseline), [])
        self.assertEqual(findings_snapshot(), live)
        self.assert_findings_match_allows(ROOT, ALLOWS)
        if not ALLOWS:
            assert_pty_critical_preserved(live, findings_snapshot())
        with tempfile.TemporaryDirectory(prefix="ccrt-sig-pty-") as pty_repo:
            body = plant_pty_finding(pty_repo)
            before_pty = findings_snapshot(pty_repo)
            self.assertIsNone(note_signal(pty_repo, "wallet", "deny"))
            after_pty = findings_snapshot(pty_repo)
            assert_pty_critical_preserved(before_pty, after_pty)
            self.assertEqual(after_pty["CRITICAL-confine-061.md"], body.split(
                b"CRITICAL CRITICAL-cc-model-confine-061", 1
            )[0])
            self.assertEqual(after_pty["/CRITICAL.md"], body)
            self.assertIn(b"061", after_pty["/CRITICAL.md"])
            self.assertNotIn(b"CRITICAL-confine-044", after_pty["/CRITICAL.md"])
            self.assertFalse((Path(pty_repo) / FINDINGS["wallet"]).exists())
            removed = dict(after_pty)
            del removed["CRITICAL-confine-061.md"]
            with self.assertRaises(AssertionError) as caught:
                unchanged_findings(after_pty, removed)
            self.assertIn("CRITICAL-confine-061.md", str(caught.exception))

    def test_recorded_allow_keeps_gate_green(self):
        """Each profile's sole recorded allow keeps its real deny test green.

        This includes did alone, which owns the same finding path as wallet.
        The launch result is injected, so the probe's binary skip state is
        cleared for the injection and restored afterwards. Sibling tests and
        live findings stay as they were.
        """
        baseline = mark_snapshot(SignalProbe)
        live = findings_snapshot()
        pid = str(os.getpid())
        allow = sbx.Result(exit_code=0, stdout="", stderr="", argv=[KILL, "-0", pid])
        saved = signal_under
        saved_skip = SignalProbe.skip_reason

        def injected(_profile, _pid):
            return allow

        try:
            SignalProbe.skip_reason = None
            for name, method_name in DENY_TESTS.items():
                with self.subTest(profile=name):
                    restore_marks(SignalProbe, baseline)
                    with tempfile.TemporaryDirectory(prefix="ccrt-sig-green-") as directory:
                        apply_allow(directory, name)
                        self.assert_findings_match_allows(directory, {name})
                        self.assertEqual(marker_problems(SignalProbe, name, baseline), [])
                        # Marker falsifiers also run after a real allow has
                        # already marked a deny test before this injection.
                        self.test_recorded_allow_is_expected_failure()
                        globals()["signal_under"] = injected
                        result = unittest.TestResult()
                        SignalProbe(method_name).run(result)
                        self.assertEqual(result.failures, [])
                        self.assertEqual(result.errors, [])
                        self.assertEqual(result.skipped, [])
                        self.assertEqual(result.unexpectedSuccesses, [])
                        self.assertEqual(len(result.expectedFailures), 1)
                        self.assertEqual(
                            result.expectedFailures[0][0]._testMethodName,
                            method_name,
                        )
                        self.assertTrue(result.wasSuccessful())
                        for sibling, sibling_method in DENY_TESTS.items():
                            if sibling == name:
                                continue
                            method = getattr(SignalProbe, sibling_method)
                            self.assertEqual(method.__doc__, baseline[sibling_method][0])
                            self.assertEqual(
                                getattr(method, "__unittest_expecting_failure__", False),
                                baseline[sibling_method][1],
                            )
                    self.assertFalse(os.path.exists(directory))
        finally:
            globals()["signal_under"] = saved
            SignalProbe.skip_reason = saved_skip
            restore_marks(SignalProbe, baseline)
        self.assertEqual(SignalProbe.skip_reason, saved_skip)
        self.assertEqual(leaked_markers(SignalProbe, baseline), [])
        self.assertEqual(findings_snapshot(), live)
        self.assert_findings_match_allows(ROOT, ALLOWS)

    def test_recorded_allow_keeps_gate_green_when_tools_missing(self):
        """Launch-free allow injections restore each missing-binary skip state."""
        saved_skip = SignalProbe.skip_reason
        try:
            for missing in (sbx.SANDBOX_EXEC, KILL, f"{sbx.SANDBOX_EXEC} {KILL}"):
                with self.subTest(missing=missing):
                    reason = "missing " + missing
                    SignalProbe.skip_reason = reason
                    self.test_recorded_allow_keeps_gate_green()
                    self.assertEqual(SignalProbe.skip_reason, reason)
        finally:
            SignalProbe.skip_reason = saved_skip

    def test_harness_error_is_not_expected_failure(self):
        """Exit 65 on the one launch of each marked deny test is a unittest error.

        Class setup raises on that same exit before a later deny can hide it.
        A classifier call alone cannot prove that ``expectedFailure`` leaves
        these errors visible.
        """
        baseline = mark_snapshot(SignalProbe)
        live = findings_snapshot()
        directory = tempfile.mkdtemp(prefix="ccrt-sig-harness-")
        pid = str(os.getpid())
        injected_result = sbx.Result(
            exit_code=sbx.PROFILE_ERROR_EXIT,
            stdout="",
            stderr=f"kill: {pid}: Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", KILL, "-0", pid],
        )
        deny = sbx.Result(
            exit_code=1,
            stdout="",
            stderr=f"kill: {pid}: Operation not permitted\n",
            argv=[sbx.SANDBOX_EXEC, "-f", "confine.sb", KILL, "-0", pid],
        )
        saved = signal_under
        saved_skip_fn = skip_reason
        saved_skip = SignalProbe.skip_reason
        SignalProbe.skip_reason = None

        def injected(_profile, _pid):
            calls.append((_profile, _pid))
            return next(launches)

        def present_tools(*_args, **_kwargs):
            return None

        try:
            for name, method_name in DENY_TESTS.items():
                restore_marks(SignalProbe, baseline)
                apply_allow(directory, name)
                method = getattr(SignalProbe, method_name)
                self.assertTrue(getattr(method, "__unittest_expecting_failure__", False))
                self.assertIn(FINDINGS[name], method.__doc__)
                with self.subTest(profile=name, launch="profile error"):
                    calls = []
                    launches = iter([injected_result])
                    globals()["signal_under"] = injected
                    result = unittest.TestResult()
                    SignalProbe(method_name).run(result)
                    self.assertEqual(result.expectedFailures, [])
                    self.assertEqual(result.failures, [])
                    self.assertEqual(result.unexpectedSuccesses, [])
                    self.assertEqual(result.skipped, [])
                    self.assertEqual(len(result.errors), 1)
                    self.assertFalse(result.wasSuccessful())
                    message = result.errors[0][1]
                    self.assertIn("not a deny", message)
                    self.assertIn("65", message)
                    self.assertIn(sbx.profile_error(injected_result), message)
                    self.assertEqual(
                        calls, [(by_name(name)["path"], int(pid))]
                    )
            with self.subTest(profile="wallet", launch="class setup"):
                saved_allows = set(ALLOWS)
                globals()["skip_reason"] = present_tools
                try:
                    calls = []
                    launches = iter([injected_result, deny, deny])
                    with self.assertRaises(HarnessError) as caught:
                        SignalProbe.setUpClass()
                    self.assertIn("not a deny", str(caught.exception))
                    self.assertEqual(
                        calls, [(by_name("wallet")["path"], int(pid))]
                    )
                    calls = []
                    launches = iter([injected_result, deny, deny])
                    suite_result = unittest.TestResult()
                    suite_result._testRunEntered = True
                    suite_result._previousTestClass = SignalRules
                    unittest.TestSuite(
                        [SignalProbe("test_wallet_signal_is_denied")]
                    ).run(suite_result)
                finally:
                    globals()["skip_reason"] = saved_skip_fn
                    ALLOWS.clear()
                    ALLOWS.update(saved_allows)
                    SignalProbe._classSetupFailed = False
                self.assertEqual(calls, [(by_name("wallet")["path"], int(pid))])
                self.assertEqual(suite_result.testsRun, 0)
                self.assertEqual(suite_result.failures, [])
                self.assertEqual(suite_result.expectedFailures, [])
                self.assertEqual(len(suite_result.errors), 1)
                self.assertFalse(suite_result.wasSuccessful())
                self.assertIn("setUpClass", str(suite_result.errors[0][0]))
                setup_message = suite_result.errors[0][1]
                self.assertIn("not a deny", setup_message)
                self.assertIn("65", setup_message)
                self.assertIn(sbx.profile_error(injected_result), setup_message)
        finally:
            globals()["signal_under"] = saved
            globals()["skip_reason"] = saved_skip_fn
            SignalProbe.skip_reason = saved_skip
            SignalProbe._classSetupFailed = False
            if getattr(SignalProbe, "__unittest_expecting_failure__", False):
                del SignalProbe.__unittest_expecting_failure__
            restore_marks(SignalProbe, baseline)
            shutil.rmtree(directory, ignore_errors=True)
        self.assertEqual(leaked_markers(SignalProbe, baseline), [])
        self.assertEqual(findings_snapshot(), live)

    def test_finding_provenance(self):
        """The finding's PR is the profile file's last commit, not ``HEAD``.

        The profile commit's subject contains ``PR #157``. ``HEAD`` contains
        ``PR #999``. A lookup of ``HEAD``'s subject attributes the allow to
        the wrong request.
        """
        self.assertEqual(pr_label("Merge pull request #8 from Elacity/spark"), PR_UNKNOWN)
        self.assertEqual(pr_label("no number here"), PR_UNKNOWN)
        self.assertEqual(pr_label("see PR #42 now"), "PR #42")
        self.assertIn("timeout=", inspect.getsource(git_text))
        seen_timeouts = []
        real_run = subprocess.run

        def record_run(argv, **kwargs):
            if argv and argv[0] == "git":
                seen_timeouts.append(kwargs.get("timeout"))
            return real_run(argv, **kwargs)

        repo = tempfile.mkdtemp(prefix="ccrt-sig-git-")
        subprocess.run = record_run
        try:
            _git(repo, "init", "-q")
            relative = "capsules/wallet-provider/confine.sb"
            path = Path(repo) / relative
            path.parent.mkdir(parents=True)
            path.write_text("(deny default)\n", encoding="utf-8")
            _git(repo, "add", relative)
            _git(repo, "commit", "-q", "-m", "wallet profile PR #157")
            profile_sha = _git(repo, "rev-parse", "HEAD")
            Path(repo, "other.txt").write_text("x\n", encoding="utf-8")
            _git(repo, "add", "other.txt")
            _git(repo, "commit", "-q", "-m", "unrelated head PR #999")
            head = _git(repo, "rev-parse", "HEAD")
            self.assertNotEqual(profile_sha, head)
            commit, subject, body = describe(repo, "wallet", relative, "ab" * 32)
            self.assertEqual(commit, profile_sha)
            self.assertNotEqual(commit, head)
            self.assertEqual(pr_label(subject), "PR #157")
            self.assertNotEqual(pr_label(subject), "PR #999")
            first = body.splitlines()[0]
            self.assertTrue(first.startswith("CRITICAL "))
            self.assertIn("PR #157", first)
            self.assertNotIn("PR #999", first)
            self.assertIn(commit, first)
            self.assertNotIn(head, first)
            head_subject = git_text(repo, "log", "-1", "--format=%s", "HEAD")
            self.assertEqual(pr_label(head_subject), "PR #999")
            self.assertNotEqual(subject, head_subject)
            self.assertTrue(seen_timeouts)
            self.assertTrue(
                all(item == COMMAND_TIMEOUT_SECONDS for item in seen_timeouts)
            )
        finally:
            subprocess.run = real_run
            shutil.rmtree(repo)

    def test_findings_snapshot_requires_preserved_files(self):
        """``.gitkeep`` and ``grant-binding-002.md`` must both exist.

        A directory that is not a findings directory names both. A directory
        that contains only ``.gitkeep`` is
        ``missing preserved findings: grant-binding-002.md``.
        ``grant-binding-003.md`` is not required.

        Dropping either required name, or accepting a missing directory,
        fails the checks below.
        """
        self.assertEqual(REQUIRED_FINDINGS, (".gitkeep", "grant-binding-002.md"))
        self.assertNotIn("grant-binding-003.md", REQUIRED_FINDINGS)
        with tempfile.TemporaryDirectory(prefix="ccrt-sig-required-") as root:
            missing = Path(root) / "not-findings"
            missing.mkdir()
            only_keep_repo = Path(root) / "only-keep"
            only_keep = only_keep_repo / "lab" / "redteam" / "findings"
            only_keep.mkdir(parents=True)
            (only_keep / ".gitkeep").write_bytes(b"")
            only_grant_repo = Path(root) / "only-grant"
            only_grant = only_grant_repo / "lab" / "redteam" / "findings"
            only_grant.mkdir(parents=True)
            (only_grant / "grant-binding-002.md").write_bytes(b"kept\n")

            def require_preserved_files():
                with self.assertRaises(HarnessError) as caught:
                    findings_snapshot(missing)
                self.assertEqual(
                    str(caught.exception),
                    "missing preserved findings: .gitkeep, grant-binding-002.md",
                )
                with self.assertRaises(HarnessError) as caught:
                    findings_snapshot(only_keep_repo)
                self.assertEqual(
                    str(caught.exception),
                    "missing preserved findings: grant-binding-002.md",
                )
                with self.assertRaises(HarnessError) as caught:
                    findings_snapshot(only_grant_repo)
                self.assertEqual(
                    str(caught.exception),
                    "missing preserved findings: .gitkeep",
                )

            require_preserved_files()
            required = REQUIRED_FINDINGS
            real_snapshot = findings_snapshot

            def assert_plant_fails(apply_plant, restore_plant):
                apply_plant()
                try:
                    with self.assertRaises(AssertionError):
                        require_preserved_files()
                finally:
                    restore_plant()

            def drop(name):
                def apply_plant():
                    globals()["REQUIRED_FINDINGS"] = tuple(
                        item for item in required if item != name
                    )

                def restore_plant():
                    globals()["REQUIRED_FINDINGS"] = required

                assert_plant_fails(apply_plant, restore_plant)

            drop(".gitkeep")
            drop("grant-binding-002.md")

            def apply_bypass():
                def accept_missing(repo=ROOT):
                    directory = Path(repo) / "lab" / "redteam" / "findings"
                    if not directory.is_dir():
                        return {}
                    return real_snapshot(repo)

                globals()["findings_snapshot"] = accept_missing

            def restore_snapshot():
                globals()["findings_snapshot"] = real_snapshot

            assert_plant_fails(apply_bypass, restore_snapshot)
            require_preserved_files()
            self.assertEqual(REQUIRED_FINDINGS, required)
            self.assertIs(findings_snapshot, real_snapshot)

    def test_removed_existing_finding_is_caught(self):
        """A byte change in a watched finding is a deny change.

        Losing or editing bytes that were present is reported. Two views
        that both omit a name stay unchanged in memory. Unlinking
        ``grant-binding-002.md`` raises
        ``missing preserved findings: grant-binding-002.md``. This test
        writes only a temporary directory. ``tearDownModule`` uses the
        same checks.
        """
        self.assertIn("grant-binding-002.md", PRESERVED)
        self.assertIn("unchanged_findings(", inspect.getsource(tearDownModule))
        absent = preserved_view({".gitkeep": b"", "/CRITICAL.md": None})
        unchanged_findings(absent, absent)
        kept = preserved_view(
            {
                ".gitkeep": b"",
                "grant-binding-002.md": b"kept\n",
                "/CRITICAL.md": None,
            }
        )
        dropped = preserved_view({".gitkeep": b"", "/CRITICAL.md": None})
        with self.assertRaises(AssertionError) as caught:
            unchanged_findings(kept, dropped)
        self.assertEqual(
            str(caught.exception),
            "deny changed lab/redteam/findings: grant-binding-002.md",
        )
        unchanged_findings(dropped, dropped)
        with self.assertRaises(AssertionError) as caught:
            unchanged_findings(dropped, kept)
        self.assertEqual(
            str(caught.exception),
            "deny changed lab/redteam/findings: grant-binding-002.md",
        )
        edited = dict(kept)
        edited["grant-binding-002.md"] = b"edited\n"
        with self.assertRaises(AssertionError) as caught:
            unchanged_findings(kept, edited)
        self.assertEqual(
            str(caught.exception),
            "deny changed lab/redteam/findings: grant-binding-002.md",
        )
        with self.assertRaises(AssertionError) as caught:
            unchanged_findings(
                {".gitkeep": b"", "grant-binding-002.md": b"kept\n"},
                {".gitkeep": b"x", "grant-binding-002.md": b"edited\n"},
            )
        self.assertEqual(
            str(caught.exception),
            "deny changed lab/redteam/findings: .gitkeep, grant-binding-002.md",
        )
        with tempfile.TemporaryDirectory(prefix="ccrt-sig-preserved-") as repo:
            directory = Path(repo) / "lab" / "redteam" / "findings"
            directory.mkdir(parents=True)
            for name, blob in kept.items():
                (directory / name).write_bytes(blob)
            self.assertEqual(preserved_view(findings_snapshot(repo)), kept)
            binding = directory / "grant-binding-002.md"
            binding.unlink()
            with self.assertRaises(HarnessError) as caught:
                findings_snapshot(repo)
            self.assertEqual(
                str(caught.exception),
                "missing preserved findings: grant-binding-002.md",
            )
            binding.write_bytes(kept["grant-binding-002.md"])
            anchor = directory / ".gitkeep"
            anchor.unlink()
            with self.assertRaises(HarnessError) as caught:
                findings_snapshot(repo)
            self.assertEqual(
                str(caught.exception), "missing preserved findings: .gitkeep"
            )

    def test_deny_leaves_findings_unchanged(self):
        """A deny creates neither 044 finding. Existing finding bytes stay put.

        The live snapshot contains ``grant-binding-002.md``. ``.gitkeep``
        matches the module-start bytes. An existing 061 pty finding,
        including its ``CRITICAL.md`` paragraph, stays byte-identical.
        A signal paragraph in that file is rejected even with equal bytes.
        """
        end = findings_snapshot()
        self.assertIn(".gitkeep", end)
        self.assertIn("grant-binding-002.md", end)
        unchanged_findings(preserved_view(START_FINDINGS), preserved_view(end))
        self.assert_findings_match_allows(ROOT, ALLOWS)
        if not ALLOWS:
            unchanged_findings(START_FINDINGS, end)
            self.assertNotIn("CRITICAL-confine-044.md", end)
            self.assertNotIn("CRITICAL-cc-model-confine-044.md", end)
            assert_pty_critical_preserved(START_FINDINGS, end)
        with tempfile.TemporaryDirectory(prefix="ccrt-sig-pty-deny-") as pty_repo:
            body = plant_pty_finding(pty_repo)
            start = findings_snapshot(pty_repo)
            kept = findings_snapshot(pty_repo)
            assert_pty_critical_preserved(start, kept)
            self.assertEqual(kept["/CRITICAL.md"], body)
            self.assertEqual(kept["CRITICAL-confine-061.md"] + kept[
                "CRITICAL-cc-model-confine-061.md"
            ], body)
            self.assertNotIn("CRITICAL-confine-044.md", kept)
            self.assertNotIn("CRITICAL-cc-model-confine-044.md", kept)
            removed = dict(kept)
            del removed["CRITICAL-cc-model-confine-061.md"]
            with self.assertRaises(AssertionError) as caught:
                unchanged_findings(kept, removed)
            self.assertIn(
                "CRITICAL-cc-model-confine-061.md", str(caught.exception)
            )
            leaked = dict(kept)
            leaked["/CRITICAL.md"] = b"CRITICAL-confine-044.md leaked\n"
            with self.assertRaises(AssertionError) as caught:
                assert_pty_critical_preserved(kept, leaked)
            self.assertIn("/CRITICAL.md", str(caught.exception))

    def test_pty_critical_preservation_checks_all_snapshot_bytes(self):
        """The shared checker catches additions, edits and removals before content checks."""
        pty = b"CRITICAL CRITICAL-confine-061 pty open preserved\n"
        for critical in (None, pty):
            start = {name: pty for name in PTY_FINDING_NAMES}
            start["/CRITICAL.md"] = critical
            assert_pty_critical_preserved(start, dict(start))
            for name in start:
                removed = dict(start)
                del removed[name]
                edited = dict(start)
                edited[name] = b"changed\n"
                cases = [("edited", start, edited)]
                if start[name] is not None:
                    cases.extend((
                        ("removed", start, removed),
                        ("added", removed, start),
                    ))
                for change, before, after in cases:
                    with self.subTest(critical=critical, name=name, change=change):
                        with self.assertRaises(AssertionError) as caught:
                            assert_pty_critical_preserved(before, after)
                        self.assertEqual(
                            str(caught.exception),
                            "deny changed lab/redteam/findings: " + name,
                        )

    def test_pty_critical_content_refusal_reasons(self):
        """Equal snapshots reach each content refusal independently of preservation."""
        pty = b"CRITICAL CRITICAL-confine-061 pty open preserved\n"
        cases = (
            (
                pty + b"CRITICAL-confine-044.md leaked\n",
                "lab/redteam/CRITICAL.md contains a signal finding while signals are denied",
            ),
            (
                pty + b"CRITICAL-cc-model-confine-044.md leaked\n",
                "lab/redteam/CRITICAL.md contains a signal finding while signals are denied",
            ),
            (
                b"CRITICAL unrelated finding\n",
                "lab/redteam/CRITICAL.md lacks a 061 PTY finding",
            ),
            (b"", "lab/redteam/CRITICAL.md lacks a 061 PTY finding"),
        )
        for content, expected in cases:
            with self.subTest(content=content):
                start = {name: pty for name in PTY_FINDING_NAMES}
                start["/CRITICAL.md"] = content
                with self.assertRaises(AssertionError) as caught:
                    assert_pty_critical_preserved(start, dict(start))
                self.assertEqual(str(caught.exception), expected)


if __name__ == "__main__":
    unittest.main()
