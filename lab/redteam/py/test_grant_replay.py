"""Red-team probe 009: a grant call opened before the session or instance changes.

Target (owner lane grant-binding), read only. The run records ``git rev-parse
HEAD`` and the sha256 of the bytes it read from ``lab/grant-binding/src/lib.rs``
and ``lab/grant-binding/src/ledger.rs``. A later commit on those files still
passes while the probed property holds.

The owner's session and instance tests open the call after the registry
change. This probe opens it first. The same call must then be refused, and
the refused reserve must not spend the ceiling. The same call's child path
is refused after the session change. ``ledger.held`` stays inside
the crate. The probe watches the ceiling: a refused reserve of 5, then a
reserve of 5 that must succeed, then a reserve of 1 that must be over the
ceiling.

One driver. A temp package outside this repo path-depends on the crate and
runs ``cargo test --offline --locked``. Plants edit a temp copy that omits
``target/`` and ``src/plant.rs``. The probe does not run the owner's tests.

A replay the real crate accepts, or a binding refusal followed by
``OverCeiling``, is ``findings/grant-binding-001.md``. Only a probe named
there is an expected failure. A compile error, a run of zero tests, and a
second unrecorded failure stay failures.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CRATE = REPO / "lab" / "grant-binding"
LIB = CRATE / "src" / "lib.rs"
LEDGER = CRATE / "src" / "ledger.rs"
FINDING = REPO / "lab" / "redteam" / "findings" / "grant-binding-001.md"

FINDING_ID = "grant-binding-001"

SESSION_NAME = "test_stale_call_session_replay_is_refused"
SIBLING_NAME = "test_stale_call_sibling_instance_replay_is_refused"
CLEAN_NAME = "test_clean_full_ceiling_reserve_succeeds"
PATH_NAME = "test_stale_call_use_path_is_refused"
PROBE_NAMES = (SESSION_NAME, SIBLING_NAME, CLEAN_NAME, PATH_NAME)
STALE_NAMES = (SESSION_NAME, SIBLING_NAME)

TIMEOUT_S = 240
CLEAN = "these two stale calls were refused and did not spend the ceiling, and the same call's child path was refused, on {commit}"

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_COMPILE = re.compile(r"could not compile|error\[E\d+\]")

SESSION_OLD = (
    "        if live.session != grant.session {\n"
    "            return Err(Refuse::Session);\n"
    "        }\n"
)
INSTANCE_OLD = (
    "        if call.instance != grant.instance {\n"
    "            return Err(Refuse::Instance);\n"
    "        }\n"
)
RESERVE_OLD = (
    "        self.resolve(*call, request.handle)\n"
    "            .map_err(ReserveRefuse::Binding)?;\n"
    "        let mut ledger = self.ledger.lock().expect(\"ledger lock\");\n"
    "        let held = ledger.held;\n"
)
# Charge before resolve and keep that charge when resolve refuses.
# Give it back when resolve succeeds, so a valid reservation is charged once.
ACCOUNTING_NEW = (
    "        {\n"
    "            let mut early = self.ledger.lock().expect(\"ledger lock\");\n"
    "            early.held = early.held.checked_add(amount).expect(\"charge fits\");\n"
    "        }\n"
    "        if let Err(refusal) = self.resolve(*call, request.handle) {\n"
    "            return Err(ReserveRefuse::Binding(refusal));\n"
    "        }\n"
    "        let mut ledger = self.ledger.lock().expect(\"ledger lock\");\n"
    "        ledger.held -= amount;\n"
    "        let held = ledger.held;\n"
)
# Add the amount once here and once in the ceiling check below.
DOUBLE_NEW = (
    "        self.resolve(*call, request.handle)\n"
    "            .map_err(ReserveRefuse::Binding)?;\n"
    "        let mut ledger = self.ledger.lock().expect(\"ledger lock\");\n"
    "        ledger.held = ledger.held.checked_add(amount).expect(\"double charge\");\n"
    "        let held = ledger.held;\n"
)
COMPILE_OLD = "        Call { instance }\n"
COMPILE_NEW = "        let _: u32 = \"compile error\";\n        Call { instance }\n"

REPLAY_RS = r"""//! Stale-call probe. Public API only. The crate's ledger stays private.

use grant_binding::ledger::ReserveRefuse;
use grant_binding::{GuestRequest, Handle, Refuse, Rights, Verifier};

fn rights() -> Rights {
    Rights {
        append: true,
        overwrite: false,
        child_journal: true,
    }
}

fn guest(handle: Handle) -> GuestRequest {
    GuestRequest {
        handle,
        forged_identity: None,
        forged_session: None,
        forged_instance: None,
        reported_usage: 0,
        forged_ceiling: 0,
        forged_append: false,
        forged_overwrite: false,
        forged_child_journal: false,
    }
}

#[test]
fn test_stale_call_session_replay_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let request = guest(handle);
    // This call is the one the later checks reuse. Nothing opens a second call.
    let call = verifier.open_call(instance);
    let decision = verifier
        .use_grant(call, &request)
        .expect("grant before the session change");
    assert_eq!(decision.session, "session-a");
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");

    verifier
        .host_set_session(instance, "session-b")
        .expect("set session");
    let refusal = match verifier.use_grant(call, &request) {
        Err(refusal) => refusal,
        Ok(decision) => panic!("accepted replay: use_grant returned Ok({decision:?})"),
    };
    assert_eq!(refusal, Refuse::Session);
    assert_eq!(refusal.to_string(), "session does not match the grant");

    verifier.admit(5);
    let reserved = match verifier.reserve(&call, &request, 5) {
        Err(refusal) => refusal,
        Ok(_) => panic!("accepted replay: reserve returned Ok"),
    };
    assert_eq!(reserved, ReserveRefuse::Binding(Refuse::Session));
    assert_eq!(reserved.to_string(), "session does not match the grant");

    verifier
        .host_set_session(instance, "session-a")
        .expect("restore session");
    match verifier.reserve(&call, &request, 5) {
        Ok(_) => {}
        Err(err @ ReserveRefuse::OverCeiling { .. }) => {
            panic!("lost accounting: binding refusal was followed by OverCeiling: {err}")
        }
        Err(other) => panic!("restored reserve was {other}"),
    }
    let over = verifier
        .reserve(&call, &request, 1)
        .expect_err("one past the ceiling");
    assert_eq!(
        over,
        ReserveRefuse::OverCeiling {
            ceiling: 5,
            held: 5,
            asked: 1,
        }
    );
    assert_eq!(over.to_string(), "reservation exceeds the ceiling");
}

#[test]
fn test_stale_call_sibling_instance_replay_is_refused() {
    let mut verifier = Verifier::new();
    let owner = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(owner, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let request = guest(handle);
    // Open the owner's call before any sibling exists.
    let call = verifier.open_call(owner);
    let decision = verifier.use_grant(call, &request).expect("owner grant");
    assert_eq!(decision.instance, owner);
    assert_eq!(decision.session, "session-a");

    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, owner);
    let sibling_call = verifier.open_call(sibling);
    let refusal = match verifier.use_grant(sibling_call, &request) {
        Err(refusal) => refusal,
        Ok(decision) => panic!("accepted replay: use_grant returned Ok({decision:?})"),
    };
    assert_eq!(refusal, Refuse::Instance);
    assert_eq!(refusal.to_string(), "instance does not match the grant");

    verifier.admit(5);
    let reserved = match verifier.reserve(&sibling_call, &request, 5) {
        Err(refusal) => refusal,
        Ok(_) => panic!("accepted replay: reserve returned Ok"),
    };
    assert_eq!(reserved, ReserveRefuse::Binding(Refuse::Instance));
    assert_eq!(reserved.to_string(), "instance does not match the grant");

    match verifier.reserve(&call, &request, 5) {
        Ok(_) => {}
        Err(err @ ReserveRefuse::OverCeiling { .. }) => {
            panic!("lost accounting: binding refusal was followed by OverCeiling: {err}")
        }
        Err(other) => panic!("owner reserve was {other}"),
    }
    let over = verifier
        .reserve(&call, &request, 1)
        .expect_err("one past the ceiling");
    assert_eq!(
        over,
        ReserveRefuse::OverCeiling {
            ceiling: 5,
            held: 5,
            asked: 1,
        }
    );
    assert_eq!(over.to_string(), "reservation exceeds the ceiling");
}

#[test]
fn test_clean_full_ceiling_reserve_succeeds() {
    // No session change and no sibling. A charge that fails here did not
    // follow a refused replay.
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let request = guest(handle);
    let call = verifier.open_call(instance);
    verifier.use_grant(call, &request).expect("grant");
    verifier.admit(5);
    match verifier.reserve(&call, &request, 5) {
        Ok(_) => {}
        Err(err) => panic!("full ceiling reserve failed without a refused replay: {err}"),
    }
    let over = verifier
        .reserve(&call, &request, 1)
        .expect_err("one past the ceiling");
    assert_eq!(
        over,
        ReserveRefuse::OverCeiling {
            ceiling: 5,
            held: 5,
            asked: 1,
        }
    );
    assert_eq!(over.to_string(), "reservation exceeds the ceiling");
}

#[test]
fn test_stale_call_use_path_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let request = guest(handle);
    let call = verifier.open_call(instance);
    verifier
        .use_path(&call, &request, "UsersAI/agent-1/notes/page.md")
        .expect("child path before the session change");
    verifier
        .host_set_session(instance, "session-b")
        .expect("set session");
    match verifier.use_path(&call, &request, "UsersAI/agent-1/notes/page.md") {
        Err(refusal) => {
            assert_eq!(refusal, Refuse::Session);
            assert_eq!(refusal.to_string(), "session does not match the grant");
        }
        Ok(()) => panic!("accepted replay: use_path returned Ok"),
    }
}
"""


class ProbeError(Exception):
    """The driver could not run the probe. This is not a skipped test and not a caught plant."""


class Outcome:
    """One named test inside one cargo run."""

    def __init__(self, kind, detail, output):
        self.kind = kind
        self.detail = detail
        self.output = output

    @property
    def caught(self):
        """True only when that test's own result line ends in FAILED."""
        return self.kind == "failed"

    def __repr__(self):
        return f"Outcome({self.kind}, {self.detail!r})"


class Suite:
    """One cargo test of the probe package."""

    def __init__(self, code, output, by_name):
        self.code = code
        self.output = output
        self.by_name = by_name


def sha256_file(path):
    """Hex sha256 of the live file's bytes."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pin_line():
    """The finding's first line from the live files.

    Finding id, then for each grant file the relative path, the last-change
    commit, the sha256, and the live digest. A pull-request number is included
    when the merge subject has one. A failed lookup omits the PR.
    """
    parts = [FINDING_ID]
    for rel in (
        "lab/grant-binding/src/lib.rs",
        "lab/grant-binding/src/ledger.rs",
    ):
        commit = git_text("log", "-1", "--format=%H", "HEAD", "--", rel)
        digest = sha256_file(REPO / rel)
        parts.append(rel)
        parts.append(commit)
        pr = None
        try:
            entry = introducing_merge(commit)
            subject = git_text("log", "-1", "--format=%s", entry)
            match = re.search(r"Merge pull request #(\d+) ", subject)
            if match is not None:
                pr = match.group(1)
        except ProbeError:
            pr = None
        if pr is not None:
            parts.append(f"PR #{pr}")
        parts.append("sha256")
        parts.append(digest)
    return " ".join(parts)


def toolchain_reason():
    """Why cargo or rustc cannot run, or None when both are on PATH."""
    missing = [name for name in ("cargo", "rustc") if shutil.which(name) is None]
    if not missing:
        return None
    if len(missing) == 2:
        return "cargo and rustc are missing"
    return f"{missing[0]} is missing"


def git_env():
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def git_bytes(*args):
    proc = subprocess.run(
        ["git", "-C", str(REPO), *args],
        capture_output=True,
        env=git_env(),
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise ProbeError(detail or f"git {' '.join(args)} failed")
    return proc.stdout


def git_text(*args):
    return git_bytes(*args).decode("utf-8", "replace").strip()


_FIRST_PARENT_LINE = None


def first_parent_line():
    """HEAD's first-parent line, newest first. Read once per process."""
    global _FIRST_PARENT_LINE
    if _FIRST_PARENT_LINE is None:
        _FIRST_PARENT_LINE = tuple(git_text("rev-list", "--first-parent", "HEAD").split())
    return _FIRST_PARENT_LINE


def first_containing(change, line, descendants):
    """First commit on ``line`` (newest first) that contains ``change``."""
    if change in line:
        return change
    for item in reversed(line):
        if item in descendants:
            return item
    raise ProbeError(f"{change} does not reach HEAD's first-parent line")


def introducing_merge(change):
    """The first commit on HEAD's first-parent line that contains ``change``.

    That merge's subject names the pull request. ``change`` stays the last
    commit from ``git log -1`` that touched the file. A sync merge at the
    branch tip does not replace either one.
    """
    line = first_parent_line()
    if change in line:
        return change
    descendants = set(git_text("rev-list", "--ancestry-path", f"{change}..HEAD").split())
    return first_containing(change, line, descendants)


def verify_pins():
    """``git rev-parse HEAD`` when that value is 40 hex digits."""
    head = git_text("rev-parse", "HEAD")
    if re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise ProbeError(f"HEAD is not a full sha: {head}")
    return head


def changed_target(rel, before, after):
    """Raise when the live digest is not the digest stored before the probe ran."""
    if before != after:
        raise ProbeError(f"the probe changed {rel}")


def anchor_reason(relative, count, name, head):
    """None when ``count`` is 1. Otherwise this run does not cover that plant."""
    if count == 1:
        return None
    return (
        f"{relative} on {head} holds {count} copies of the {name} anchor, "
        "not one. This run does not cover that plant."
    )


def recorded_from(text):
    """Probe names in a finding. The first line is the live pin. The body records Ok or OverCeiling.

    A finding may name a stale probe or the use_path probe. The clean reserve
    and a compile-error name stay unknown.
    """
    lines = text.splitlines()
    if not lines:
        raise ProbeError("finding is empty")
    if lines[0] != pin_line():
        raise ProbeError("finding first line is not the live pin")
    names = set()
    observed = False
    for line in lines[1:]:
        if line.startswith("probe: "):
            name = line[len("probe: "):].strip()
            if name not in STALE_NAMES and name != PATH_NAME:
                raise ProbeError(f"finding names an unknown probe {name}")
            names.add(name)
        if line.startswith("observed: Ok") or line.startswith("observed: OverCeiling"):
            observed = True
    if not names:
        raise ProbeError("finding names no probe")
    if not observed:
        raise ProbeError("finding records neither Ok nor OverCeiling")
    return names


def recorded_probes():
    if not FINDING.is_file():
        return set()
    return recorded_from(FINDING.read_text())


def expect_recorded(case_cls, recorded):
    """Mark only the named probe methods. A compile error is not in this set."""
    for name, method in list(vars(case_cls).items()):
        if not name.startswith("test_") or not callable(method):
            continue
        if name in recorded:
            setattr(case_cls, name, unittest.expectedFailure(method))


def gate_kind(outcome, name, recorded):
    """How the gate treats one cargo result.

    ``expected`` is only a recorded stale probe whose test failed.
    A compile error and a run of zero tests are ``error`` even when the
    probe name is recorded.
    """
    if outcome.kind == "error":
        return "error"
    if outcome.kind == "passed":
        return "pass"
    if outcome.kind == "failed" and name in recorded:
        return "expected"
    if outcome.kind == "failed":
        return "fail"
    return "error"


def accounting_plant_caught(session, sibling, clean):
    """True when both stale tests failed on the ceiling and the clean reserve passed.

    A double charge fails the clean reserve with no refused replay. That is
    not a catch of this rule, even when the stale tests fail as well.
    """
    if clean.kind != "passed":
        return False
    return (
        session.caught
        and sibling.caught
        and "lost accounting:" in session.output
        and "lost accounting:" in sibling.output
        and "accepted replay:" not in session.output
        and "accepted replay:" not in sibling.output
    )


def strip_ansi(text):
    return _ANSI.sub("", text or "")


def evidence(output, limit=40):
    keys = (
        " ... ok",
        " ... FAILED",
        "accepted replay:",
        "lost accounting:",
        "without a refused replay",
        "could not compile",
        "error[E",
        "running 0 tests",
        "test result:",
        "panicked at",
    )
    lines = [line for line in strip_ansi(output).splitlines() if any(key in line for key in keys)]
    if len(lines) > limit:
        lines = lines[:limit]
    return "\n".join(lines)


def tail(text, limit=2000):
    body = (text or "").strip()
    if len(body) <= limit:
        return body
    return body[-limit:]


def assert_outside(path):
    resolved = Path(path).resolve()
    root = REPO.resolve()
    if resolved == root or resolved.is_relative_to(root):
        raise ProbeError(f"{resolved} is inside the repo")


def ignore_crate(_directory, names):
    skipped = {name for name in names if name == "target"}
    if Path(_directory).name == "src" and "plant.rs" in names:
        skipped.add("plant.rs")
    return skipped


def copy_crate(dest):
    dest = Path(dest)
    if dest.exists():
        raise ProbeError(f"{dest} already exists")
    assert_outside(dest)
    shutil.copytree(CRATE, dest, ignore=ignore_crate)
    if (dest / "target").exists() or (dest / "src" / "plant.rs").exists():
        raise ProbeError("the copy includes target/ or src/plant.rs")
    return dest


def apply_once(root, relative, old, new):
    root = Path(root).resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ProbeError(f"{relative} escapes the copy")
    if path.is_relative_to(CRATE.resolve()):
        raise ProbeError(f"plant would edit the owner tree: {path}")
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        raise ProbeError(f"{relative} holds {count} copies of the anchor, not one")
    path.write_text(text.replace(old, new, 1))


def write_probe(pkg, crate):
    pkg = Path(pkg)
    assert_outside(pkg)
    (pkg / "src").mkdir(parents=True)
    (pkg / "tests").mkdir()
    (pkg / "src" / "lib.rs").write_text("//! External probe package. The tests call grant-binding.\n")
    (pkg / "tests" / "replay.rs").write_text(REPLAY_RS)
    manifest = (
        "[package]\n"
        "name = \"grant-replay-probe\"\n"
        "version = \"0.0.0\"\n"
        "edition = \"2021\"\n"
        "publish = false\n"
        "\n"
        "[workspace]\n"
        "\n"
        "[dependencies]\n"
        f"grant-binding = {{ path = {json.dumps(str(Path(crate).resolve()))} }}\n"
    )
    (pkg / "Cargo.toml").write_text(manifest)
    if (REPO / "lab" / "redteam" / "Cargo.toml").exists():
        raise ProbeError("lab/redteam/Cargo.toml appeared")
    return pkg


def cargo(pkg, args, target):
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(Path(target).resolve())
    env["CARGO_NET_OFFLINE"] = "true"
    env["CARGO_TERM_COLOR"] = "never"
    env["CARGO_INCREMENTAL"] = "0"
    env["RUST_TEST_THREADS"] = "2"
    env["RUSTUP_AUTO_INSTALL"] = "0"
    argv = ["cargo", *args]
    try:
        proc = subprocess.Popen(
            argv,
            cwd=str(pkg),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            start_new_session=True,
        )
    except OSError as error:
        raise ProbeError(f"cannot run cargo: {error}") from None
    try:
        out, err = proc.communicate(timeout=TIMEOUT_S)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()
        raise ProbeError(f"{shlex.join(argv)} timed out after {TIMEOUT_S}s") from None
    output = strip_ansi((out or "") + "\n" + (err or ""))
    return proc.returncode, output


def outcome_for(name, code, output):
    """Classify ``name`` inside one cargo test transcript.

    A catch is a result line that ends in FAILED. A compile error and a
    filter that runs zero tests are errors, including when cargo exits 0.
    """
    prefix = f"test {name} ... "
    lines = [line.strip() for line in output.splitlines() if line.strip().startswith(prefix)]
    if len(lines) > 1:
        return Outcome("error", f"{name} reported {len(lines)} results", output)
    if len(lines) == 1:
        line = lines[0]
        if line.endswith(" FAILED"):
            if code == 0:
                return Outcome("error", "FAILED line but cargo exited 0", output)
            return Outcome("failed", line, output)
        if line.endswith(" ok"):
            return Outcome("passed", line, output)
        return Outcome("error", f"unreadable result {line}", output)
    if _COMPILE.search(output):
        return Outcome("error", "compile error", output)
    if code == 0 and "running 0 tests" in output:
        return Outcome("error", "0 tests ran", output)
    return Outcome("error", f"cargo exited {code} with no test result", output)


def run_suite(pkg, crate, target, harness_args):
    write_probe(pkg, crate)
    code, output = cargo(
        pkg,
        ["generate-lockfile", "--offline", "--manifest-path", str(pkg / "Cargo.toml")],
        target,
    )
    if code != 0 or not (pkg / "Cargo.lock").is_file():
        raise ProbeError(
            f"cargo generate-lockfile exited {code}\n{tail(output)}"
        )
    code, output = cargo(
        pkg,
        [
            "test", "--offline", "--locked",
            "--manifest-path", str(pkg / "Cargo.toml"),
            "--", *harness_args,
        ],
        target,
    )
    by_name = {name: outcome_for(name, code, output) for name in PROBE_NAMES}
    return Suite(code, output, by_name)


def raise_if_cargo_error(name, real, real_error):
    """A cargo error is raised here so a caller can use it from ``setUp``.

    ``expectedFailure`` hides every exception in the test body. ``setUp``
    runs before that flag, so a compile error stays an error.
    """
    if real_error is not None:
        raise real_error
    if real is None:
        raise ProbeError(f"{name} did not run")
    outcome = real.by_name[name]
    if outcome.kind == "error":
        shown = evidence(outcome.output) or outcome.detail
        raise ProbeError(f"{name}: {outcome.detail}\n{shown}")


def run_case(case_cls):
    case_cls.__module__ = "grant_replay_fixture"
    result = unittest.TestResult()
    unittest.TestLoader().loadTestsFromTestCase(case_cls).run(result)
    return result


class GrantReplayProbe(unittest.TestCase):
    """The stale-call probe and the plants that must turn it red."""

    skip_reason = None
    work = None
    target = None
    real_pkg = None
    real = None
    real_error = None
    head = ""
    pin_line = ""
    lib_sha = None
    ledger_sha = None

    @classmethod
    def setUpClass(cls):
        cls.skip_reason = toolchain_reason()
        if cls.skip_reason:
            return
        cls.lib_sha = sha256_file(LIB)
        cls.ledger_sha = sha256_file(LEDGER)
        cls.head = verify_pins()
        cls.pin_line = pin_line()
        cls.work = Path(tempfile.mkdtemp(prefix="redteam-009-")).resolve()
        cls.target = cls.work / "target"
        cls.target.mkdir()
        cls.real_pkg = cls.work / "probe-real"
        try:
            cls.real = run_suite(cls.real_pkg, CRATE, cls.target, [])
            cls.real_error = None
        except ProbeError as exc:
            cls.real = None
            cls.real_error = exc

    def setUp(self):
        if self._testMethodName == "test_toolchain_present_or_skip":
            return
        if self.skip_reason:
            self.skipTest(self.skip_reason)
        if self._testMethodName in PROBE_NAMES:
            raise_if_cargo_error(self._testMethodName, self.real, self.real_error)

    def test_toolchain_present_or_skip(self):
        """Skip when cargo or rustc is missing. When both exist, the later tests run."""
        reason = toolchain_reason()
        if reason:
            self.skipTest(reason)
        self.assertIsNotNone(shutil.which("cargo"))
        self.assertIsNotNone(shutil.which("rustc"))
        self.assertFalse((REPO / "lab" / "redteam" / "Cargo.toml").is_file())
        self.assertTrue(self.target.resolve().is_relative_to(self.work.resolve()))
        self.assertFalse(self.work.resolve().is_relative_to(REPO.resolve()))

    def test_run_hashes_the_bytes_it_reads(self):
        """HEAD and the sha256 of the bytes this run read. A different digest is a probe edit."""
        self.assertEqual(verify_pins(), self.head)
        self.assertEqual(self.lib_sha, sha256_file(LIB))
        self.assertEqual(self.ledger_sha, sha256_file(LEDGER))
        rel = "lab/grant-binding/src/lib.rs"
        changed_target(rel, self.lib_sha, self.lib_sha)
        with self.assertRaises(ProbeError) as changed:
            changed_target(rel, self.lib_sha, "0" * 64)
        self.assertEqual(str(changed.exception), f"the probe changed {rel}")

        saved = git_text

        def fake(value):
            def run(*args):
                if args == ("rev-parse", "HEAD"):
                    return value
                return saved(*args)
            return run

        try:
            globals()["git_text"] = fake("abc")
            with self.assertRaises(ProbeError) as short:
                verify_pins()
            self.assertEqual(str(short.exception), "HEAD is not a full sha: abc")
            odd = "g" * 40
            globals()["git_text"] = fake(odd)
            with self.assertRaises(ProbeError) as bad:
                verify_pins()
            self.assertEqual(str(bad.exception), f"HEAD is not a full sha: {odd}")
        finally:
            globals()["git_text"] = saved

    def test_missing_anchor_names_its_reason(self):
        """One copy of an anchor is covered. Zero or two copies skip this run."""
        rel = "lab/grant-binding/src/lib.rs"
        self.assertIsNone(anchor_reason(rel, 1, "session", self.head))
        for count in (0, 2):
            reason = anchor_reason(rel, count, "session", self.head)
            self.assertEqual(
                reason,
                f"{rel} on {self.head} holds {count} copies of the session anchor, "
                "not one. This run does not cover that plant.",
            )
            self.assertIn("does not cover that plant", reason)

    def check_real(self, name):
        outcome = self.real.by_name[name]
        kind = gate_kind(outcome, name, recorded_probes())
        shown = evidence(self.real.output) or tail(self.real.output)
        if kind == "expected":
            self.fail(f"{FINDING_ID} still reproduces:\n{shown}")
        if kind == "fail":
            self.fail(f"unrecorded failure of {name}:\n{shown}")
        self.assertEqual(kind, "pass", shown)

    def test_stale_call_session_replay_is_refused(self):
        """The call opened before host_set_session is refused, and the refusal spends nothing."""
        self.check_real(SESSION_NAME)

    def test_stale_call_sibling_instance_replay_is_refused(self):
        """The owner's call is opened first. The sibling call is refused and spends nothing."""
        self.check_real(SIBLING_NAME)

    def test_stale_call_use_path_is_refused(self):
        """A child path on the call opened before the session change is refused after it."""
        self.check_real(PATH_NAME)

    def plant(self, name, relative, old, new):
        dest = copy_crate(self.work / f"crate-{name}")
        self.assertFalse((dest / "target").exists())
        self.assertFalse((dest / "src" / "plant.rs").exists())
        apply_once(dest, relative, old, new)
        suite = run_suite(self.work / f"probe-{name}", dest, self.target, [])
        changed_target("lab/grant-binding/src/lib.rs", self.lib_sha, sha256_file(LIB))
        changed_target("lab/grant-binding/src/ledger.rs", self.ledger_sha, sha256_file(LEDGER))
        print(f"\n[{name}]\n{evidence(suite.output)}", file=sys.stderr, flush=True)
        return suite

    def test_clean_full_ceiling_reserve_succeeds(self):
        """A full-ceiling reserve passes. A double charge that fails it is not a stale-call catch."""
        self.check_real(CLEAN_NAME)
        suite = self.plant("double-charge", "src/ledger.rs", RESERVE_OLD, DOUBLE_NEW)
        session = suite.by_name[SESSION_NAME]
        sibling = suite.by_name[SIBLING_NAME]
        clean = suite.by_name[CLEAN_NAME]
        path = suite.by_name[PATH_NAME]
        self.assertEqual(path.kind, "passed", evidence(suite.output) or tail(suite.output))
        self.assertEqual(clean.kind, "failed", evidence(suite.output) or tail(suite.output))
        self.assertIn("without a refused replay", clean.output)
        self.assertNotEqual(clean.kind, "error")
        naive = (
            session.caught
            and sibling.caught
            and "lost accounting:" in session.output
            and "lost accounting:" in sibling.output
        )
        self.assertTrue(naive, evidence(suite.output) or tail(suite.output))
        self.assertFalse(accounting_plant_caught(session, sibling, clean))
        self.assertFalse(self._expecting("test_clean_full_ceiling_reserve_succeeds"))

    def require_one_anchor(self, relative, old, name):
        """Skip this plant when the live file does not hold that anchor once."""
        count = (REPO / relative).read_text().count(old)
        reason = anchor_reason(relative, count, name, self.head)
        if reason is not None:
            self.skipTest(reason)

    def test_deleted_session_comparison_is_caught(self):
        """Deleting the live session comparison makes the session replay and the stale use_path fail."""
        self.require_one_anchor("lab/grant-binding/src/lib.rs", SESSION_OLD, "session")
        suite = self.plant("drop-session", "src/lib.rs", SESSION_OLD, "")
        session = suite.by_name[SESSION_NAME]
        path = suite.by_name[PATH_NAME]
        self.assertTrue(session.caught, evidence(suite.output) or tail(suite.output))
        self.assertIn("accepted replay:", session.output)
        self.assertNotIn("lost accounting:", session.output)
        self.assertTrue(path.caught, evidence(suite.output) or tail(suite.output))
        self.assertIn("accepted replay: use_path returned Ok", path.output)
        self.assertNotIn("lost accounting:", path.output)
        self.assertEqual(suite.by_name[SIBLING_NAME].kind, "passed", evidence(suite.output))
        self.assertEqual(suite.by_name[CLEAN_NAME].kind, "passed", evidence(suite.output))

    def test_deleted_instance_comparison_is_caught(self):
        """Deleting the live instance comparison makes the sibling replay test fail."""
        self.require_one_anchor("lab/grant-binding/src/lib.rs", INSTANCE_OLD, "instance")
        suite = self.plant("drop-instance", "src/lib.rs", INSTANCE_OLD, "")
        sibling = suite.by_name[SIBLING_NAME]
        self.assertTrue(sibling.caught, evidence(suite.output) or tail(suite.output))
        self.assertIn("accepted replay:", sibling.output)
        self.assertNotIn("lost accounting:", sibling.output)
        self.assertEqual(suite.by_name[SESSION_NAME].kind, "passed", evidence(suite.output))
        self.assertEqual(suite.by_name[PATH_NAME].kind, "passed", evidence(suite.output))
        self.assertEqual(suite.by_name[CLEAN_NAME].kind, "passed", evidence(suite.output))

    def test_early_reserve_charge_is_caught(self):
        """A charge kept after a binding refusal fails both stale tests. A valid reserve is charged once."""
        self.require_one_anchor("lab/grant-binding/src/ledger.rs", RESERVE_OLD, "reserve")
        suite = self.plant("early-charge", "src/ledger.rs", RESERVE_OLD, ACCOUNTING_NEW)
        session = suite.by_name[SESSION_NAME]
        sibling = suite.by_name[SIBLING_NAME]
        clean = suite.by_name[CLEAN_NAME]
        self.assertTrue(accounting_plant_caught(session, sibling, clean), evidence(suite.output) or tail(suite.output))
        self.assertEqual(clean.kind, "passed", evidence(suite.output) or tail(suite.output))
        self.assertEqual(suite.by_name[PATH_NAME].kind, "passed", evidence(suite.output) or tail(suite.output))

    def test_compile_error_is_error(self):
        """Invalid Rust is an error. It is not a caught plant and not an expected failure."""
        self.require_one_anchor("lab/grant-binding/src/lib.rs", COMPILE_OLD, "compile")
        suite = self.plant("compile-error", "src/lib.rs", COMPILE_OLD, COMPILE_NEW)
        self.assertNotEqual(suite.code, 0)
        self.assertRegex(suite.output, r"could not compile|error\[E\d+\]")
        self.assertNotIn(" ... FAILED", suite.output)
        recorded = {SESSION_NAME, SIBLING_NAME}
        for name in PROBE_NAMES:
            outcome = suite.by_name[name]
            self.assertEqual(outcome.kind, "error", evidence(suite.output) or tail(suite.output))
            self.assertFalse(outcome.caught)
            self.assertEqual(gate_kind(outcome, name, recorded), "error")
        self.assertFalse(self._expecting("test_compile_error_is_error"))

    def test_zero_tests_is_error(self):
        """An unmatched test filter runs zero tests. Exit 0 is not a pass and not a catch."""
        if self.real_error is not None:
            raise self.real_error
        code, output = cargo(
            self.real_pkg,
            [
                "test", "--offline", "--locked",
                "--manifest-path", str(self.real_pkg / "Cargo.toml"),
                "--", "--exact", "test_no_such_grant_replay",
            ],
            self.target,
        )
        self.assertEqual(code, 0, tail(output))
        self.assertIn("running 0 tests", output)
        self.assertNotIn(" ... FAILED", output)
        outcome = outcome_for(SESSION_NAME, code, output)
        self.assertEqual(outcome.kind, "error", evidence(output) or tail(output))
        self.assertIn("0 tests", outcome.detail)
        self.assertFalse(outcome.caught)
        self.assertNotEqual(outcome.kind, "passed")
        self.assertEqual(gate_kind(outcome, SESSION_NAME, {SESSION_NAME}), "error")
        self.assertFalse(self._expecting("test_zero_tests_is_error"))
        self.assertTrue(code == 0 and outcome.kind != "passed")

    def test_unrecorded_failure_still_fails_the_gate(self):
        """One recorded probe is an expected failure. The other failure, and a compile error, are not."""
        text = pin_line() + (
            "\nprobe: " + SESSION_NAME + "\n"
            "call: open_call, use_grant, host_set_session, use_grant\n"
            "observed: Ok\n"
        )
        self.assertEqual(recorded_from(text), {SESSION_NAME})
        path_only = pin_line() + (
            "\nprobe: " + PATH_NAME + "\n"
            "call: open_call, use_path, host_set_session, use_path\n"
            "observed: Ok\n"
        )
        self.assertEqual(recorded_from(path_only), {PATH_NAME})
        both = pin_line() + (
            "\nprobe: " + SESSION_NAME + "\n"
            "probe: " + SIBLING_NAME + "\n"
            "call: reserve of 5 returned Binding, then reserve of 5\n"
            "observed: OverCeiling\n"
        )
        self.assertEqual(recorded_from(both), set(STALE_NAMES))
        with self.assertRaises(ProbeError):
            recorded_from(FINDING_ID + "\nprobe: " + SESSION_NAME + "\nobserved: Ok\n")
        with self.assertRaises(ProbeError):
            recorded_from(pin_line() + "\nprobe: " + CLEAN_NAME + "\nobserved: Ok\n")
        with self.assertRaises(ProbeError):
            recorded_from(pin_line() + "\nprobe: test_compile_error_is_error\nobserved: Ok\n")
        with self.assertRaises(ProbeError):
            recorded_from(pin_line() + "\nprobe: " + SESSION_NAME + "\n")

        failed = Outcome("failed", "failed", "lost accounting: binding refusal was followed by OverCeiling")
        compile = Outcome("error", "compile error", "could not compile")
        zero = Outcome("error", "0 tests ran", "running 0 tests")
        recorded = {SESSION_NAME}
        self.assertEqual(gate_kind(failed, SESSION_NAME, recorded), "expected")
        self.assertEqual(gate_kind(failed, SIBLING_NAME, recorded), "fail")
        self.assertEqual(gate_kind(compile, SESSION_NAME, recorded), "error")
        self.assertEqual(gate_kind(zero, SESSION_NAME, recorded), "error")

        class Gate(unittest.TestCase):
            def test_stale_call_session_replay_is_refused(self):
                self.fail("accepted replay: use_grant returned Ok")

            def test_stale_call_sibling_instance_replay_is_refused(self):
                self.fail("lost accounting: binding refusal was followed by OverCeiling")

            def test_compile_error_is_error(self):
                raise ProbeError("could not compile")

        expect_recorded(Gate, recorded)
        result = run_case(Gate)
        self.assertEqual(len(result.expectedFailures), 1)
        self.assertEqual(len(result.failures), 1)
        self.assertIn("lost accounting", result.failures[0][1])
        self.assertEqual(result.unexpectedSuccesses, [])
        self.assertEqual(len(result.errors), 1)
        self.assertIn("could not compile", result.errors[0][1])

        class Hidden(unittest.TestCase):
            """A test-body exception under expectedFailure is hidden. This probe does not do that."""

            @unittest.expectedFailure
            def test_compile_error_is_error(self):
                raise ProbeError("could not compile")

        hidden = run_case(Hidden)
        self.assertEqual(len(hidden.expectedFailures), 1)
        self.assertEqual(hidden.errors, [])
        self.assertFalse(self._expecting("test_compile_error_is_error"))
        self.assertFalse(self._expecting("test_zero_tests_is_error"))

        class Setup(unittest.TestCase):
            def setUp(self):
                real = Suite(101, "could not compile `grant-binding`\n", {
                    SESSION_NAME: Outcome("error", "compile error", "could not compile `grant-binding`"),
                })
                raise_if_cargo_error(SESSION_NAME, real, None)

            def test_stale_call_session_replay_is_refused(self):
                self.fail("body ran after a compile error")

        expect_recorded(Setup, {SESSION_NAME})
        setup = run_case(Setup)
        self.assertEqual(setup.expectedFailures, [])
        self.assertEqual(setup.failures, [])
        self.assertEqual(len(setup.errors), 1)
        self.assertIn("compile error", setup.errors[0][1])

        marked = {
            name for name in dir(GrantReplayProbe)
            if name.startswith("test_") and getattr(
                getattr(GrantReplayProbe, name), "__unittest_expecting_failure__", False
            )
        }
        self.assertEqual(marked, recorded_probes())

    def _expecting(self, name):
        return getattr(getattr(GrantReplayProbe, name), "__unittest_expecting_failure__", False)


expect_recorded(GrantReplayProbe, recorded_probes())


def tearDownModule():
    work = GrantReplayProbe.work
    real = GrantReplayProbe.real
    skip = GrantReplayProbe.skip_reason
    head = GrantReplayProbe.head
    pins = GrantReplayProbe.pin_line
    lib_sha = GrantReplayProbe.lib_sha
    ledger_sha = GrantReplayProbe.ledger_sha
    if work is not None:
        shutil.rmtree(work, ignore_errors=True)
        GrantReplayProbe.work = None
    if lib_sha is not None:
        changed_target("lab/grant-binding/src/lib.rs", lib_sha, sha256_file(LIB))
    if ledger_sha is not None:
        changed_target("lab/grant-binding/src/ledger.rs", ledger_sha, sha256_file(LEDGER))
    if (REPO / "lab" / "redteam" / "Cargo.toml").exists():
        raise ProbeError("lab/redteam/Cargo.toml appeared")
    if skip:
        print(f"SKIPPED: {skip}", file=sys.stderr)
        return
    if real is None or FINDING.is_file():
        return
    if all(real.by_name[name].kind == "passed" for name in PROBE_NAMES):
        print(CLEAN.format(commit=head), file=sys.stderr)
        print(pins, file=sys.stderr)
        for name in PROBE_NAMES:
            print(real.by_name[name].detail, file=sys.stderr)
