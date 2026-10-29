"""Red-team probe 080: does an allow-once grant authorise only one operation?

Target (owner lane cx-agent-conformance), read only. ``StandIn::authorise`` is
the lab stand-in entry, not the Runtime: this probe makes no claim about the
shipping product. ``docs/AGENT_ARCHITECTURE.md`` (Delegation and mandates)
says allow once authorises one exact operation. A second ``Ok`` from the same
seeded grant is ``findings/cx-agent-conformance-001.md``.

One temp package outside this repo path-depends on ``lab/agent-conformance``
and calls only the public stand-in. Its two tests seed ``req-once`` with
duration ``once`` and ``req-session`` with duration ``session``, each owned by
``Caller::Client { session_id: "component-1" }``. The first call on each grant
must be ``Ok``. The second call on the once grant must be refused with a
non-empty reason; the second call on the session grant must be ``Ok``. No
``post_capsules``, no disk and no clock.

The driver imports the lane's one cargo launcher and result classifier
(``cargo`` and ``outcome_for``) from ``test_grant_replay``. The package runs
through that launcher with the package timeout of 900 s; its
``generate-lockfile`` and ``test`` stay ``--offline``.

The session control must pass before any finding is written. A compile error,
a missing result, a failed session control, an empty refusal and an unrelated
failure each raise without writing. A pass deletes a stale finding. On this
base ``authorise`` is ``&self`` and reads no ``duration``, so the plant is
skipped with ``plant: skipped, no once-spend check in authorise``; that skip is
not the journey and it is not CAUGHT.
"""

from __future__ import annotations

import inspect
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_grant_replay import (
    TIMEOUT_S,
    Outcome,
    ProbeError,
    apply_once,
    assert_outside,
    cargo,
    changed_target,
    git_text,
    outcome_for,
    sha256_file,
    toolchain_reason,
)

REPO = Path(__file__).resolve().parents[3]
CRATE = REPO / "lab" / "agent-conformance"
STANDIN_REL = "lab/agent-conformance/standin-runtime/mod.rs"
STANDIN = REPO / STANDIN_REL
FINDINGS = REPO / "lab" / "redteam" / "findings"
FINDING = FINDINGS / "cx-agent-conformance-001.md"

FINDING_ID = "cx-agent-conformance-001"
ONCE_NAME = "test_once_grant_second_authorise_is_refused"
SESSION_NAME = "test_session_grant_second_authorise_is_allowed"
ONCE_PANIC = "once grant spent twice"
EMPTY_REFUSAL = "empty once refusal"
SKIP_LINE = "plant: skipped, no once-spend check in authorise"
CAUGHT_LINE = "plant: once-spend removal caught"
# The only spend shape this base names. ``authorise`` is ``&self`` and spends
# nothing, so ``once_spend`` finds no anchor and the plant is skipped.
ONCE_SPEND = "grant.life = Life::Exhausted;"
ONCE_TIMEOUT_S = 900

ONCE_RS = r"""//! Allow-once probe. Public stand-in API only.
use agent_conformance::standin_runtime::{Caller, Life, StandIn};

#[test]
fn test_once_grant_second_authorise_is_refused() {
    let mut standin = StandIn::new();
    standin.seed_grant(
        "req-once",
        "component-1",
        "res",
        "read",
        "once",
        1,
        Life::Live,
        false,
    );
    let owner = Caller::Client {
        session_id: "component-1",
    };
    standin
        .authorise(owner, "req-once")
        .expect("first once authorise");
    match standin.authorise(owner, "req-once") {
        Ok(()) => panic!("once grant spent twice"),
        Err((_, reason)) => assert!(!reason.is_empty(), "empty once refusal"),
    }
}

#[test]
fn test_session_grant_second_authorise_is_allowed() {
    let mut standin = StandIn::new();
    standin.seed_grant(
        "req-session",
        "component-1",
        "res",
        "read",
        "session",
        1,
        Life::Live,
        false,
    );
    let owner = Caller::Client {
        session_id: "component-1",
    };
    standin
        .authorise(owner, "req-session")
        .expect("first session authorise");
    standin
        .authorise(owner, "req-session")
        .expect("second session authorise");
}
"""


def expected_text(commit, digest):
    """The finding contract, written out. A hard-coded pin or a wrong line differs."""
    return (
        f"{FINDING_ID} {STANDIN_REL} {commit} sha256 {digest}\n"
        "\n"
        f"probe: {ONCE_NAME}\n"
        "falsifier: F-once-twice\n"
        "observed: second authorise returned Ok\n"
    )


def once_commit():
    """Last commit that changed the stand-in file at HEAD."""
    return git_text("log", "-1", "--format=%H", "HEAD", "--", STANDIN_REL)


def once_digest():
    """sha256 of the live stand-in bytes."""
    return sha256_file(STANDIN)


def finding_text(commit, digest):
    """The finding body from the live pin values."""
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ProbeError(f"stand-in commit is not 40 hex: {commit}")
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ProbeError(f"stand-in digest is not 64 hex: {digest}")
    return (
        f"{FINDING_ID} {STANDIN_REL} {commit} sha256 {digest}\n"
        "\n"
        f"probe: {ONCE_NAME}\n"
        "falsifier: F-once-twice\n"
        "observed: second authorise returned Ok\n"
    )


def once_pin_line():
    """The first line from the live file, not a baked value."""
    return finding_text(once_commit(), once_digest()).splitlines()[0]


def write_once_finding(finding):
    """Write the finding from the live stand-in bytes."""
    text = finding_text(once_commit(), once_digest())
    Path(finding).write_text(text)
    return text


def handle_once(real_error, session, once, finding):
    """Classify two results from one cargo transcript, or raise without writing.

    A set ``real_error`` is raised and writes nothing. The session control
    must pass before the once result is consulted. A pass deletes a stale
    finding. The ``once grant spent twice`` panic writes the finding. A
    compile error, a missing result, an empty refusal and an unrelated
    failure each raise their own reason and leave the destination unchanged.
    """
    if real_error is not None:
        raise real_error
    if session is None or once is None:
        raise ProbeError("once probe did not run")
    if session.kind == "error":
        raise ProbeError(f"session control was error: {session.detail}")
    if session.kind != "passed":
        raise ProbeError(f"session control was {session.kind}")
    path = Path(finding)
    if once.kind == "error":
        raise ProbeError(f"once outcome was error: {once.detail}")
    if once.kind == "passed":
        if path.is_file():
            path.unlink()
        return "refused", None
    if once.kind != "failed":
        raise ProbeError(f"once outcome was {once.kind}")
    if EMPTY_REFUSAL in once.output:
        raise ProbeError("once refusal was empty")
    if ONCE_PANIC not in once.output:
        raise ProbeError("once outcome was an unrelated failure")
    return "finding", write_once_finding(path)


def authorise_body(text):
    """The live ``authorise`` method text."""
    start = text.find("pub fn authorise(")
    if start < 0:
        raise ProbeError("the stand-in holds no authorise")
    end = text.find("\n    }\n", start)
    if end < 0:
        raise ProbeError("the authorise body is not bounded")
    return text[start:end]


def once_spend(text=None):
    """The once-spend statement inside ``authorise``, or None when it reads no duration."""
    body = authorise_body(STANDIN.read_text() if text is None else text)
    if "duration" not in body:
        return None
    if ONCE_SPEND not in body:
        raise ProbeError("authorise reads duration without the named once-spend anchor")
    return ONCE_SPEND


def write_package(pkg, crate):
    """One temp package outside the repo that path-depends on the lane crate."""
    pkg = Path(pkg)
    assert_outside(pkg)
    if pkg.exists():
        raise ProbeError(f"{pkg} already exists")
    (pkg / "src").mkdir(parents=True)
    (pkg / "tests").mkdir()
    (pkg / "src" / "lib.rs").write_text(
        "//! External probe package. The tests call the stand-in.\n"
    )
    (pkg / "tests" / "once.rs").write_text(ONCE_RS)
    manifest = (
        "[package]\n"
        "name = \"once-grant-probe\"\n"
        "version = \"0.0.0\"\n"
        "edition = \"2021\"\n"
        "publish = false\n"
        "\n"
        "[workspace]\n"
        "\n"
        "[dependencies]\n"
        f"agent-conformance = {{ path = {json.dumps(str(Path(crate).resolve()))} }}\n"
    )
    (pkg / "Cargo.toml").write_text(manifest)
    return pkg


def run_once(pkg, target, timeout=ONCE_TIMEOUT_S):
    """One lockfile and one test run, both offline, through the lane launcher."""
    pkg = Path(pkg)
    code, output = cargo(
        pkg,
        ["generate-lockfile", "--offline", "--manifest-path", str(pkg / "Cargo.toml")],
        target,
        timeout,
    )
    if code != 0 or not (pkg / "Cargo.lock").is_file():
        raise ProbeError(f"cargo generate-lockfile exited {code}\n{output[-2000:]}")
    code, output = cargo(
        pkg,
        [
            "test", "--offline", "--locked",
            "--manifest-path", str(pkg / "Cargo.toml"),
        ],
        target,
        timeout,
    )
    by_name = {name: outcome_for(name, code, output) for name in (ONCE_NAME, SESSION_NAME)}
    return code, output, by_name


def ignore_target(_directory, names):
    return [name for name in names if name == "target"]


class OnceGrantProbe(unittest.TestCase):
    """The allow-once probe, its session control and the honesty checks."""

    skip_reason = None
    work = None
    target = None
    pkg = None
    code = 0
    output = ""
    by_name = None
    suite_error = None
    standin_sha = None

    @classmethod
    def setUpClass(cls):
        cls.skip_reason = toolchain_reason()
        if cls.skip_reason:
            return
        cls.standin_sha = sha256_file(STANDIN)
        cls.work = Path(tempfile.mkdtemp(prefix="redteam-080-")).resolve()
        cls.target = cls.work / "target"
        cls.target.mkdir()
        cls.pkg = cls.work / "probe-once"
        try:
            write_package(cls.pkg, CRATE)
            cls.code, cls.output, cls.by_name = run_once(cls.pkg, cls.target)
        except ProbeError as exc:
            cls.by_name = None
            cls.suite_error = exc

    def setUp(self):
        if self._testMethodName == "test_toolchain_present_or_skip":
            return
        if self.skip_reason:
            self.skipTest(self.skip_reason)

    def test_toolchain_present_or_skip(self):
        """Skip when cargo or rustc is missing. When both exist, the later tests run."""
        reason = toolchain_reason()
        if reason:
            self.skipTest(reason)
        self.assertIsNotNone(shutil.which("cargo"))
        self.assertIsNotNone(shutil.which("rustc"))
        self.assertTrue(self.target.resolve().is_relative_to(self.work.resolve()))
        self.assertFalse(self.work.resolve().is_relative_to(REPO.resolve()))

    def test_once_grant_second_authorise_is_refused(self):
        """A second Ok records cx-agent-conformance-001. A refusal leaves no finding."""
        if self.suite_error is not None:
            raise self.suite_error
        session = self.by_name[SESSION_NAME]
        once = self.by_name[ONCE_NAME]
        status, text = handle_once(None, session, once, FINDING)
        if status == "refused":
            self.assertFalse(FINDING.exists())
            self.assertIsNone(text)
            print("once grant: refused", file=sys.stderr, flush=True)
            return
        self.assertEqual(status, "finding")
        self.assertEqual(FINDING.read_text(), text)
        self.assertEqual(text.splitlines()[0], once_pin_line())
        self.assertEqual(
            text.splitlines()[0].split(" "),
            [FINDING_ID, STANDIN_REL, once_commit(), "sha256", once_digest()],
        )
        self.assertEqual(text.splitlines()[2], f"probe: {ONCE_NAME}")
        self.assertEqual(text.splitlines()[3], "falsifier: F-once-twice")
        self.assertEqual(text.splitlines()[4], "observed: second authorise returned Ok")
        print("once grant: finding", file=sys.stderr, flush=True)

    def expect_once_error(self, handler, real_error, session, once, dest):
        """Run one error case. The handler must raise and leave the bytes unchanged."""
        with self.assertRaises(ProbeError) as caught:
            handler(real_error, session, once, dest)
        self.assertEqual(Path(dest).read_bytes(), b"keep\n")
        return str(caught.exception)

    def test_once_errors_write_nothing(self):
        """Each error path is its own reason and writes nothing.

        The falsifiers swallow an error and scribble over the destination;
        both are caught by ``expect_once_error``.
        """
        boom = ProbeError("real suite failed")
        passed_session = Outcome("passed", f"test {SESSION_NAME} ... ok", "")
        compile_session = Outcome("error", "compile error", "could not compile\n")
        compile_once = Outcome("error", "compile error", "could not compile\n")
        missing_once = Outcome(
            "error", "cargo exited 1 with no test result", "error: test failed\n"
        )
        cases = (
            ("real_error", boom, passed_session, Outcome("passed", "ok", ""), boom, True),
            (
                "compile error",
                None,
                compile_session,
                compile_once,
                "session control was error: compile error",
                False,
            ),
            (
                "missing result",
                None,
                passed_session,
                missing_once,
                "once outcome was error: cargo exited 1 with no test result",
                False,
            ),
            (
                "failed session",
                None,
                Outcome("failed", f"test {SESSION_NAME} ... FAILED", ""),
                Outcome("failed", f"test {ONCE_NAME} ... FAILED", ONCE_PANIC),
                "session control was failed",
                False,
            ),
            (
                "empty refusal",
                None,
                passed_session,
                Outcome("failed", f"test {ONCE_NAME} ... FAILED", EMPTY_REFUSAL),
                "once refusal was empty",
                False,
            ),
            (
                "unrelated failure",
                None,
                passed_session,
                Outcome("failed", f"test {ONCE_NAME} ... FAILED", "assertion failed: x"),
                "once outcome was an unrelated failure",
                False,
            ),
            (
                "other kind",
                None,
                passed_session,
                Outcome("skipped", "skipped", ONCE_PANIC),
                "once outcome was skipped",
                False,
            ),
        )
        reasons = []
        root = self.work / "once-errors"
        root.mkdir(parents=True, exist_ok=True)
        before = {
            path.name: path.read_bytes()
            for path in FINDINGS.iterdir()
            if path.is_file()
        }
        for index, (name, real_error, session, once, reason, same) in enumerate(cases):
            with self.subTest(name):
                dest = root / f"{index}.md"
                dest.write_bytes(b"keep\n")
                caught = self.expect_once_error(
                    handle_once, real_error, session, once, dest
                )
                if same:
                    self.assertEqual(caught, str(boom))
                else:
                    self.assertEqual(caught, reason)
                reasons.append(caught)

        def swallow(real_error, session, once, finding):
            if real_error is not None or session.kind != "passed" or once.kind == "error":
                if Path(finding).is_file():
                    Path(finding).unlink()
                return "refused", None
            return handle_once(real_error, session, once, finding)

        def scribble(real_error, session, once, finding):
            Path(finding).write_bytes(b"changed\n")
            raise ProbeError("once outcome was an unrelated failure")

        dest = root / "swallow.md"
        dest.write_bytes(b"keep\n")
        with self.assertRaises(AssertionError):
            self.expect_once_error(swallow, None, compile_session, compile_once, dest)
        dest = root / "scribble.md"
        dest.write_bytes(b"keep\n")
        with self.assertRaises(AssertionError):
            self.expect_once_error(
                scribble, None, passed_session, missing_once, dest
            )

        self.assertEqual(len(reasons), len(set(reasons)))
        after = {
            path.name: path.read_bytes()
            for path in FINDINGS.iterdir()
            if path.is_file()
        }
        self.assertEqual(after, before)

    def expect_finding_write(self, write, commit, digest, dest):
        """The writer must produce the contract from the supplied pin values."""
        text = write(dest)
        self.assertEqual(text, expected_text(commit, digest))
        self.assertEqual(Path(dest).read_text(), expected_text(commit, digest))

    def test_once_finding_contract(self):
        """The writer reads the live pin and replaces stale bytes.

        The falsifiers bake the pin and change an observed line; both differ
        from the contract. A pass must delete a stale finding.
        """
        self.assertNotIn("introducing_merge", inspect.getsource(once_pin_line))
        self.assertNotIn("introducing_merge", inspect.getsource(write_once_finding))
        self.assertIn("once_commit", inspect.getsource(write_once_finding))
        self.assertIn("once_digest", inspect.getsource(write_once_finding))
        commit = once_commit()
        digest = once_digest()
        self.assertRegex(commit, r"^[0-9a-f]{40}$")
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(once_pin_line(), expected_text(commit, digest).splitlines()[0])
        with self.assertRaises(ProbeError):
            finding_text("0" * 39, digest)
        with self.assertRaises(ProbeError):
            finding_text(commit, "0" * 63)

        root = self.work / "once-contract"
        root.mkdir(parents=True, exist_ok=True)
        stale_commit = "0" * 40
        stale_digest = "ab" * 32
        self.assertNotEqual(stale_commit, commit)
        self.assertNotEqual(stale_digest, digest)
        def baked(dest):
            """The falsifier: pins baked in instead of read from the live file."""
            text = expected_text(commit, digest)
            Path(dest).write_text(text)
            return text

        saved_git = globals()["git_text"]
        saved_sha = globals()["sha256_file"]
        try:
            globals()["git_text"] = lambda *args: stale_commit
            globals()["sha256_file"] = lambda path: stale_digest
            dest = root / "live.md"
            self.expect_finding_write(write_once_finding, stale_commit, stale_digest, dest)
            self.assertNotIn(commit, dest.read_text())
            self.assertNotIn(digest, dest.read_text())
            with self.assertRaises(AssertionError):
                self.expect_finding_write(baked, stale_commit, stale_digest, root / "baked.md")
        finally:
            globals()["git_text"] = saved_git
            globals()["sha256_file"] = saved_sha

        def mistyped(dest):
            text = expected_text(commit, digest).replace(
                "observed: second authorise returned Ok", "observed: refused"
            )
            Path(dest).write_text(text)
            return text

        with self.subTest("mistyped"):
            dest = root / "mistyped.md"
            with self.assertRaises(AssertionError):
                self.expect_finding_write(mistyped, commit, digest, dest)

        stale_path = root / "stale.md"
        stale_path.write_text(expected_text(stale_commit, stale_digest))
        passed = Outcome("passed", f"test {ONCE_NAME} ... ok", "")
        status, text = handle_once(None, passed, passed, stale_path)
        self.assertEqual(status, "refused")
        self.assertIsNone(text)
        self.assertFalse(stale_path.exists())

        status, text = handle_once(
            None,
            passed,
            Outcome("failed", f"test {ONCE_NAME} ... FAILED", ONCE_PANIC),
            stale_path,
        )
        self.assertEqual(status, "finding")
        self.assertEqual(stale_path.read_text(), text)
        self.assertNotIn(stale_commit, text)

        with self.assertRaises(AssertionError):
            self.expect_pass_deletes(lambda *_args: ("refused", None), stale_path)

    def expect_pass_deletes(self, handler, dest):
        """A pass must remove the destination or the journey is not proven."""
        Path(dest).write_text("stale\n")
        status, text = handler(None, Outcome("passed", "ok", ""), Outcome("passed", "ok", ""), dest)
        self.assertEqual(status, "refused")
        self.assertIsNone(text)
        self.assertFalse(Path(dest).exists())

    def test_cargo_timeout_override(self):
        """The launcher uses TIMEOUT_S by default and 900 when supplied.

        The falsifier drops the override; the recorder then sees TIMEOUT_S.
        """
        self.assertEqual(TIMEOUT_S, inspect.signature(cargo).parameters["timeout"].default)
        self.assertEqual(ONCE_TIMEOUT_S, 900)
        self.assertIn("ONCE_TIMEOUT_S", inspect.getsource(run_once))
        seen = []
        saved_popen = subprocess.Popen

        class FakeProc:
            returncode = 0

            def __init__(self, argv, **_options):
                self.argv = list(argv)
                self.options = _options

            def communicate(self, timeout=None):
                seen.append(timeout)
                if "generate-lockfile" in self.argv:
                    cwd = Path(self.options["cwd"])
                    (cwd / "Cargo.lock").write_text("")
                return "", ""

        def fake_popen(argv, **options):
            return FakeProc(argv, **options)

        def ignoring(pkg, args, target, timeout=ONCE_TIMEOUT_S):
            return cargo(pkg, args, target)

        root = Path(self.work) / "timeout-pkg"
        root.mkdir(parents=True, exist_ok=True)
        (root / "Cargo.toml").write_text("[package]\n")
        try:
            subprocess.Popen = fake_popen
            seen.clear()
            cargo(root, ["--version"], self.target)
            self.assertEqual(seen, [TIMEOUT_S])

            seen.clear()
            cargo(root, ["--version"], self.target, ONCE_TIMEOUT_S)
            self.assertEqual(seen, [ONCE_TIMEOUT_S])

            seen.clear()
            run_once(root, self.target)
            self.assertEqual(seen, [ONCE_TIMEOUT_S, ONCE_TIMEOUT_S])

            seen.clear()
            ignoring(root, ["--version"], self.target, ONCE_TIMEOUT_S)
            self.assertEqual(seen, [TIMEOUT_S])
            self.assertNotEqual(seen, [ONCE_TIMEOUT_S])
        finally:
            subprocess.Popen = saved_popen

    def test_once_grant_plant(self):
        """Remove a live once spend in a temp copy, or record why this base cannot plant.

        ``authorise`` reads no ``duration`` on this base, so the plant is
        skipped and the live bytes stay unchanged. A spend removal must fail
        the once test with ``once grant spent twice`` and leave the session
        control passing.
        """
        if self.suite_error is not None:
            raise self.suite_error
        self.assertIsNone(once_spend("    pub fn authorise(&self) { Ok(()) }\n    }\n"))
        with self.assertRaises(ProbeError):
            once_spend(
                "    pub fn authorise(&self) {\n"
                "        if grant.duration == \"once\" {\n"
                "            return Err(spent());\n"
                "        }\n"
                "        Ok(())\n"
                "    }\n"
            )
        self.assertEqual(
            once_spend(
                "    pub fn authorise(&mut self) {\n"
                "        if grant.duration == \"once\" {\n"
                f"            {ONCE_SPEND}\n"
                "        }\n"
                "    }\n"
            ),
            ONCE_SPEND,
        )

        anchor = once_spend()
        if anchor is None:
            print(SKIP_LINE, file=sys.stderr, flush=True)
            self.assertEqual(sha256_file(STANDIN), self.standin_sha)
            return

        root = Path(self.work) / "plant"
        lab = root / "lab"
        lab.mkdir(parents=True)
        copy = lab / "agent-conformance"
        shutil.copytree(CRATE, copy, ignore=ignore_target)
        (root / "elastos").symlink_to(REPO / "elastos", target_is_directory=True)
        (lab / "capsule-identity").symlink_to(
            REPO / "lab" / "capsule-identity", target_is_directory=True
        )
        apply_once(copy, "standin-runtime/mod.rs", anchor, "")
        pkg = Path(self.work) / "probe-plant"
        write_package(pkg, copy)
        code, output, by_name = run_once(pkg, self.target)
        once = by_name[ONCE_NAME]
        self.assertTrue(once.caught, output[-2000:])
        self.assertIn(ONCE_PANIC, once.output)
        self.assertEqual(by_name[SESSION_NAME].kind, "passed", output[-2000:])
        self.assertEqual(sha256_file(STANDIN), self.standin_sha)
        print(CAUGHT_LINE, file=sys.stderr, flush=True)


def tearDownModule():
    work = OnceGrantProbe.work
    standin_sha = OnceGrantProbe.standin_sha
    try:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
            OnceGrantProbe.work = None
        if standin_sha is not None:
            changed_target(STANDIN_REL, standin_sha, sha256_file(STANDIN))
    finally:
        OnceGrantProbe.work = None
