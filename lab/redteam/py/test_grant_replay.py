"""Red-team probe 009: a grant call opened before the session or instance changes.

Target (owner lane grant-binding), read only. The run records ``git rev-parse
HEAD`` and the sha256 of the bytes it read from ``lab/grant-binding/src/lib.rs``
and ``lab/grant-binding/src/ledger.rs``. A later commit on those files still
passes while the probed property holds.

The owner's session and instance tests open the call after the registry
change. This probe opens it first. The same call must then be refused, and
the refused reserve must not spend the ceiling. The same call's child path
is refused after the session change. A grant succeeds, the identity changes,
and the same call is refused. ``ledger.held`` stays inside
the crate. The probe watches the ceiling: a refused reserve of 5, then a
reserve of 5 that must succeed, then a reserve of 1 that must be over the
ceiling.

One driver. A temp package outside this repo path-depends on the crate and
runs ``cargo test --offline --locked``. Plants edit a temp copy that omits
``target/`` and ``src/plant.rs``. The probe does not run the owner's tests.

The link guard is ``grant_binding::link::cargo_toml_path_depends_on_grant_binding``.
This driver does not decide a link. ``tearDownModule`` used ``exists`` and
``test_toolchain_present_or_skip`` used ``is_file`` on ``lab/redteam/Cargo.toml``.
Both checks are removed. No existence check replaces either one.

A replay the real crate accepts, or a binding refusal followed by
``OverCeiling``, is ``findings/grant-binding-001.md``. Only a probe named
there is an expected failure. A compile error, a run of zero tests, and a
second unrecorded failure stay failures.

A path dependency Cargo resolves through a TOML escape, while the link test
still passes, is ``findings/grant-binding-002.md``. ``record_escaped_link``
is the only writer for that file.

An immediate ``timeout_hold`` after ``SettleOutcome::Unknown`` is refused.
No ledger call sits between that settle and the timeout. An ``Ok`` from the
live call is ``findings/grant-binding-003.md``. That writer reads the live
ledger file. It is not ``record_escaped_link``.
"""

from __future__ import annotations

import hashlib
import inspect
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
LINK_FINDING = REPO / "lab" / "redteam" / "findings" / "grant-binding-002.md"

FINDING_ID = "grant-binding-001"

SESSION_NAME = "test_stale_call_session_replay_is_refused"
SIBLING_NAME = "test_stale_call_sibling_instance_replay_is_refused"
CLEAN_NAME = "test_clean_full_ceiling_reserve_succeeds"
PATH_NAME = "test_stale_call_use_path_is_refused"
IDENTITY_NAME = "test_stale_call_identity_replay_is_refused"
LINK_NAME = "redteam_manifest_is_not_a_grant_link"
TIMEOUT_NAME = "test_immediate_timeout_after_unknown_is_refused"
TIMEOUT_FINDING = REPO / "lab" / "redteam" / "findings" / "grant-binding-003.md"
TIMEOUT_LEDGER = "lab/grant-binding/src/ledger.rs"
TIMEOUT_OK_PANIC = "immediate timeout returned Ok"
TIMEOUT_FREED_PANIC = "immediate timeout freed the hold"
TIMEOUT_OK_OBSERVED = "timeout_hold returned Ok"
TIMEOUT_FREED_OBSERVED = "timeout_hold freed the hold"
PROBE_NAMES = (SESSION_NAME, SIBLING_NAME, CLEAN_NAME, PATH_NAME, IDENTITY_NAME)
STALE_NAMES = (SESSION_NAME, SIBLING_NAME)
REPO_MARKER = "@@REDTEAM_REPO@@"
# Manifest texts the link plant hands to the owner's detector.
NAME_ONLY_MANIFEST = 'name = "grant-binding"'
AUDIT_SHAPED_MANIFEST = 'audit = { path = "../wasm-capsule/audit" }'
PATH_MANIFEST = 'grant-binding = { path = "lab/grant-binding" }'
# Cargo decodes \\u0069. The raw bytes do not contain grant-binding.
ESCAPED_MANIFEST = """\
[package]
name = "escape-probe"
version = "0.0.0"
edition = "2021"

[dependencies]
gb = { path = "../grant-bind\\u0069ng", package = "grant-bind\\u0069ng" }
"""

TIMEOUT_S = 240
CLEAN = "these two stale calls were refused and did not spend the ceiling, and the same call's child path was refused, and the same call was refused after the identity change, on {commit}"

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_COMPILE = re.compile(r"could not compile|error\[E\d+\]")

IDENTITY_OLD = (
    "        if live.identity != grant.identity {\n"
    "            return Err(Refuse::Identity);\n"
    "        }\n"
)
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

use grant_binding::ledger::{ReserveRefuse, SettleOutcome, SettleRefuse};
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

#[test]
fn test_stale_call_identity_replay_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let request = guest(handle);
    let call = verifier.open_call(instance);
    let decision = verifier
        .use_grant(call, &request)
        .expect("grant before the identity change");
    assert_eq!(decision.identity, "agent-1");
    verifier
        .host_set_identity(instance, "agent-2")
        .expect("set identity");
    match verifier.use_grant(call, &request) {
        Err(refusal) => {
            assert_eq!(refusal, Refuse::Identity);
            assert_eq!(refusal.to_string(), "identity does not match the grant");
        }
        Ok(decision) => panic!("accepted replay: use_grant returned Ok({decision:?})"),
    }
}

#[test]
fn test_immediate_timeout_after_unknown_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("bind");
    let request = guest(handle);
    let call = verifier.open_call(instance);
    verifier.admit(4);
    let reservation = verifier.reserve(&call, &request, 4).expect("reserve");
    let unknown = verifier
        .settle(&call, &request, reservation, SettleOutcome::Unknown)
        .expect_err("unknown outcome");
    assert_eq!(unknown, SettleRefuse::UnknownOutcome);
    assert_eq!(unknown.to_string(), "unknown outcome keeps the hold");
    match verifier.timeout_hold(&call, &request, reservation) {
        Ok(()) => panic!("immediate timeout returned Ok"),
        Err(refusal) => assert!(!refusal.to_string().is_empty()),
    }
    match verifier.reserve(&call, &request, 1) {
        Err(ReserveRefuse::OverCeiling { .. }) => {}
        other => panic!("immediate timeout freed the hold: {other:?}"),
    }
}

#[test]
fn redteam_manifest_is_not_a_grant_link() {
    let repo = "@@REDTEAM_REPO@@";
    let baked = format!("{repo}/lab/redteam/Cargo.toml");
    let chosen = std::env::var("REDTEAM_MANIFEST").unwrap_or(baked);
    let path = std::path::Path::new(&chosen);
    if !path.is_file() {
        return;
    }
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    assert!(
        !grant_binding::link::cargo_toml_path_depends_on_grant_binding(&text),
        "lab/redteam/Cargo.toml has a path dependency on grant-binding"
    );
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

    def __init__(self, code, output, by_name, link=None):
        self.code = code
        self.output = output
        self.by_name = by_name
        self.link = link


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


def link_pin_line():
    """The link finding's first line, from the live detector file."""
    rel = "lab/grant-binding/src/link.rs"
    commit = git_text("log", "-1", "--format=%H", "HEAD", "--", rel)
    digest = sha256_file(REPO / rel)
    return f"grant-binding-002 {rel} {commit} sha256 {digest}"


def live_escaped_document():
    """Finding text from the live detector file. The writer does not call this."""
    rel = "lab/grant-binding/src/link.rs"
    commit = git_text("log", "-1", "--format=%H", "HEAD", "--", rel)
    digest = sha256_file(REPO / rel)
    return (
        f"grant-binding-002 {rel} {commit} sha256 {digest}\n"
        "\n"
        "probe: test_escaped_path_dependency_matches_cargo\n"
        "observed: detector returned false\n"
        "cargo metadata package: grant-binding\n"
    )


def record_escaped_link(outcome, metadata_code, metadata_output, finding):
    """Write grant-binding-002, or raise without writing.

    A metadata failure or a link error writes nothing. A caught failure
    returns the package names and writes nothing. A pass writes the live
    pin and the three probe lines and returns that text.
    """
    if metadata_code != 0:
        raise ProbeError(f"cargo metadata exited {metadata_code}")
    start = metadata_output.find("{")
    if start < 0:
        raise ProbeError("cargo metadata output has no JSON object")
    try:
        document, _end = json.JSONDecoder().raw_decode(metadata_output, start)
    except json.JSONDecodeError:
        raise ProbeError("cargo metadata JSON is invalid") from None
    packages = document.get("packages") if isinstance(document, dict) else None
    names = []
    if isinstance(packages, list):
        for package in packages:
            if isinstance(package, dict) and isinstance(package.get("name"), str):
                names.append(package["name"])
    if "grant-binding" not in names:
        raise ProbeError("cargo metadata names no grant-binding package")
    if outcome.kind == "error":
        raise ProbeError(f"link outcome was error: {outcome.detail}")
    if outcome.kind == "failed" and outcome.caught:
        return names
    if outcome.kind != "passed":
        raise ProbeError(f"link outcome was {outcome.kind}")
    text = (
        link_pin_line()
        + "\n\n"
        + "probe: test_escaped_path_dependency_matches_cargo\n"
        + "observed: detector returned false\n"
        + "cargo metadata package: grant-binding\n"
    )
    Path(finding).write_text(text)
    return text


def timeout_pin_line():
    """The first line of grant-binding-003, from the live ledger file.

    The commit is ``git log -1`` of that file at HEAD. The digest is the
    sha256 of the bytes this process reads.
    """
    commit = git_text("log", "-1", "--format=%H", "HEAD", "--", TIMEOUT_LEDGER)
    digest = sha256_file(REPO / TIMEOUT_LEDGER)
    return f"grant-binding-003 {TIMEOUT_LEDGER} {commit} sha256 {digest}"


def timeout_finding_text(observed):
    """grant-binding-003 from the live ledger file and one observed line."""
    if observed not in (TIMEOUT_OK_OBSERVED, TIMEOUT_FREED_OBSERVED):
        raise ProbeError(f"timeout observed line is {observed}")
    return (
        timeout_pin_line()
        + "\n\n"
        + f"probe: {TIMEOUT_NAME}\n"
        + f"observed: {observed}\n"
    )


def write_timeout_finding(observed, finding):
    """Write grant-binding-003 from the live ledger bytes."""
    text = timeout_finding_text(observed)
    Path(finding).write_text(text)
    return text


def handle_timeout(real_error, outcome, finding):
    """Classify one immediate-timeout result.

    A set ``real_error`` is raised and writes nothing. A pass deletes a
    stale finding. An Ok panic writes ``timeout_hold returned Ok``. A freed
    hold writes ``timeout_hold freed the hold``. Both panics, any other
    failure, and an error raise and leave the destination unchanged.
    """
    if real_error is not None:
        raise real_error
    if outcome is None:
        raise ProbeError("timeout probe did not run")
    if outcome.kind == "error":
        raise ProbeError(f"timeout outcome was error: {outcome.detail}")
    path = Path(finding)
    if outcome.kind == "passed":
        if path.is_file():
            path.unlink()
        return "refused", None
    if outcome.kind != "failed":
        raise ProbeError(f"timeout outcome was {outcome.kind}")
    ok = TIMEOUT_OK_PANIC in outcome.output
    freed = TIMEOUT_FREED_PANIC in outcome.output
    if ok and freed:
        raise ProbeError("timeout outcome names both panics")
    if ok:
        return "finding", write_timeout_finding(TIMEOUT_OK_OBSERVED, path)
    if freed:
        return "finding", write_timeout_finding(TIMEOUT_FREED_OBSERVED, path)
    raise ProbeError("timeout outcome was an unrelated failure")


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

    A finding may name a stale probe, the use_path probe, or the identity
    probe. The clean reserve and a compile-error name stay unknown.
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
            if name not in STALE_NAMES and name != PATH_NAME and name != IDENTITY_NAME:
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
        "has a path dependency on grant-binding",
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


def render_replay(source, repo):
    """Substitute the one repo marker into the replay source.

    Any other marker count is a probe error. A quote or a backslash in the
    repo path is a probe error: that character would sit inside the Rust string.
    """
    repo = str(repo)
    count = source.count(REPO_MARKER)
    if count != 1:
        raise ProbeError(
            f"replay.rs holds {count} copies of {REPO_MARKER}, not one"
        )
    if '"' in repo or "\\" in repo:
        raise ProbeError("repo path contains a quote or a backslash")
    return source.replace(REPO_MARKER, repo, 1)


def set_manifest(value):
    """Set ``REDTEAM_MANIFEST``, or remove it when ``value`` is None.

    Returns the previous value so the caller can restore it in ``finally``.
    """
    previous = os.environ.get("REDTEAM_MANIFEST")
    if value is None:
        os.environ.pop("REDTEAM_MANIFEST", None)
    else:
        os.environ["REDTEAM_MANIFEST"] = str(value)
    return previous


def require_suite_manifest_unset():
    """A full suite reads the baked manifest path. The link plant sets the variable."""
    if os.environ.get("REDTEAM_MANIFEST") is not None:
        raise ProbeError("REDTEAM_MANIFEST is set for the suite")


def write_link_manifest(work, package, text):
    """Write a temp manifest for the link plant.

    The file is neither ``lab/redteam/Cargo.toml`` nor the package manifest.
    """
    fd, name = tempfile.mkstemp(prefix="link-manifest-", suffix=".toml", dir=work)
    os.close(fd)
    path = Path(name).resolve()
    assert_outside(path)
    package_manifest = (Path(package) / "Cargo.toml").resolve()
    redteam_manifest = (REPO / "lab" / "redteam" / "Cargo.toml").resolve()
    if path == package_manifest or path == redteam_manifest:
        raise ProbeError("link plant manifest is not a temp file")
    path.write_text(text)
    return path


def write_probe(pkg, crate):
    pkg = Path(pkg)
    assert_outside(pkg)
    (pkg / "src").mkdir(parents=True)
    (pkg / "tests").mkdir()
    (pkg / "src" / "lib.rs").write_text("//! External probe package. The tests call grant-binding.\n")
    (pkg / "tests" / "replay.rs").write_text(render_replay(REPLAY_RS, REPO))
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
    require_suite_manifest_unset()
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
    link = outcome_for(LINK_NAME, code, output)
    return Suite(code, output, by_name, link)


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
    _saved_manifest = None
    _manifest_saved = False

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
        cls._saved_manifest = set_manifest(None)
        cls._manifest_saved = True
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

    def test_stale_call_identity_replay_is_refused(self):
        """A grant on the call opened before the identity change is refused after it."""
        self.check_real(IDENTITY_NAME)

    def test_immediate_timeout_after_unknown_is_refused(self):
        """Reserve, settle Unknown, then timeout_hold with nothing between them.

        A refusal leaves no finding. An Ok panic records grant-binding-003.
        ``setUp`` raises ``real_error`` only for ``PROBE_NAMES``, so this
        method raises it itself. This method does not start cargo.
        """
        source = inspect.getsource(GrantReplayProbe.test_immediate_timeout_after_unknown_is_refused)
        self.assertNotIn("check" + "_real", source)
        self.assertNotIn("run" + "_suite", source)
        self.assertNotIn(".pl" + "ant(", source)
        self.assertNotIn("carg" + "o(", source)
        self.assertIn(
            "outcome_for(TIMEOUT_NAME, self.real.code, self.real.output)",
            source,
        )
        self.assertNotIn(TIMEOUT_NAME, PROBE_NAMES)
        self.assertNotIn(TIMEOUT_NAME, STALE_NAMES)
        self.assertNotIn(TIMEOUT_NAME, CLEAN)
        if self.real_error is not None:
            handle_timeout(self.real_error, None, TIMEOUT_FINDING)
        outcome = outcome_for(TIMEOUT_NAME, self.real.code, self.real.output)
        status, text = handle_timeout(None, outcome, TIMEOUT_FINDING)
        for name in PROBE_NAMES:
            self.assertEqual(
                self.real.by_name[name].kind,
                "passed",
                evidence(self.real.output),
            )
        if status == "refused":
            self.assertFalse(TIMEOUT_FINDING.exists())
            self.assertIsNone(text)
            print("immediate timeout: refused", file=sys.stderr, flush=True)
            return
        self.assertEqual(status, "finding")
        self.assertEqual(TIMEOUT_FINDING.read_text(), text)
        self.assertEqual(text.splitlines()[0], timeout_pin_line())
        observed = text.splitlines()[3]
        if TIMEOUT_OK_PANIC in outcome.output:
            self.assertEqual(observed, "observed: " + TIMEOUT_OK_OBSERVED)
        if TIMEOUT_FREED_PANIC in outcome.output:
            self.assertEqual(observed, "observed: " + TIMEOUT_FREED_OBSERVED)
        print("immediate timeout: finding", file=sys.stderr, flush=True)

    def test_timeout_probe_calls_settle_before_timeout(self):
        """Unknown settle, then one timeout_hold, then reserve again.

        ``release`` does not occur. This test launches nothing and does not
        read the ledger for a deadline.
        """
        source = inspect.getsource(
            GrantReplayProbe.test_timeout_probe_calls_settle_before_timeout
        )
        self.assertNotIn("carg" + "o(", source)
        self.assertNotIn("run" + "_suite", source)
        self.assertNotIn(".pl" + "ant(", source)
        self.assertNotIn("ledger" + ".rs", source)
        start = REPLAY_RS.find("fn test_immediate_timeout_after_unknown_is_refused")
        identity = REPLAY_RS.find("fn test_stale_call_identity_replay_is_refused")
        self.assertGreater(start, identity)
        end = REPLAY_RS.find("fn redteam_manifest_is_not_a_grant_link", start)
        self.assertGreater(end, start)
        body = REPLAY_RS[start:end]
        self.assertNotIn("\nfn ", body)
        reserve = body.find("reserve")
        unknown = body.find("SettleOutcome::Unknown")
        timeout = body.find("timeout_hold")
        again = body.find("reserve", timeout + 1)
        self.assertGreaterEqual(reserve, 0)
        self.assertLess(reserve, unknown)
        self.assertLess(unknown, timeout)
        self.assertEqual(body.count("timeout_hold"), 1)
        self.assertEqual(body.count("SettleOutcome::Unknown"), 1)
        self.assertEqual(body.count(".reserve("), 2)
        self.assertLess(timeout, again)
        self.assertNotIn("release", body)
        self.assertNotIn("reserve", body[unknown:timeout])
        self.assertIn(
            "use grant_binding::ledger::{ReserveRefuse, SettleOutcome, SettleRefuse};",
            REPLAY_RS,
        )
        self.assertIn(
            "use grant_binding::{GuestRequest, Handle, Refuse, Rights, Verifier};",
            REPLAY_RS,
        )

    def test_timeout_probe_errors_write_nothing(self):
        """Each timeout error is its own ProbeError and writes nothing.

        A real_error, an error outcome, both panic markers, and an unrelated
        failure each raise. A handler that writes or deletes a finding fails
        that case. The reasons stay distinct.
        """
        boom = ProbeError("real suite failed")
        both = TIMEOUT_OK_PANIC + "\n" + TIMEOUT_FREED_PANIC + "\n"
        cases = (
            (
                "real_error",
                boom,
                Outcome("failed", "failed", TIMEOUT_OK_PANIC),
                boom,
                True,
            ),
            (
                "error",
                None,
                Outcome(
                    "error",
                    "compile error",
                    "could not compile\n" + TIMEOUT_OK_PANIC + "\n",
                ),
                "timeout outcome was error: compile error",
                False,
            ),
            (
                "both panics",
                None,
                Outcome("failed", "failed", both),
                "timeout outcome names both panics",
                False,
            ),
            (
                "unrelated",
                None,
                Outcome("failed", "failed", "assertion failed: ceiling"),
                "timeout outcome was an unrelated failure",
                False,
            ),
            (
                "other kind",
                None,
                Outcome("skipped", "skipped", TIMEOUT_FREED_PANIC),
                "timeout outcome was skipped",
                False,
            ),
        )
        reasons = []
        root = self.work / "timeout-errors"
        root.mkdir(parents=True, exist_ok=True)
        findings = REPO / "lab" / "redteam" / "findings"
        before = {
            path.name: path.read_bytes()
            for path in findings.iterdir()
            if path.is_file()
        }
        saved_error = self.real_error
        try:
            for index, (name, real_error, outcome, reason, same) in enumerate(cases):
                with self.subTest(name):
                    dest = root / f"{index}.md"
                    dest.write_bytes(b"keep\n")
                    with self.assertRaises(ProbeError) as caught:
                        handle_timeout(real_error, outcome, dest)
                    if same:
                        self.assertIs(caught.exception, boom)
                    else:
                        self.assertEqual(str(caught.exception), reason)
                    self.assertEqual(dest.read_bytes(), b"keep\n")
                    reasons.append(str(caught.exception))
            self.assertEqual(len(reasons), len(set(reasons)))
            self.real_error = boom
            with self.assertRaises(ProbeError) as caught:
                self.test_immediate_timeout_after_unknown_is_refused()
            self.assertIs(caught.exception, boom)
        finally:
            self.real_error = saved_error
        after = {
            path.name: path.read_bytes()
            for path in findings.iterdir()
            if path.is_file()
        }
        self.assertEqual(after, before)

    def test_timeout_finding_contract(self):
        """A pass deletes a stale finding. Each panic writes its own line and the live pin.

        No cargo run. A leftover finding, a swapped observed line, or a wrong
        commit or digest fails.
        """
        self.assertNotIn("record_escaped_link", inspect.getsource(write_timeout_finding))
        self.assertNotIn("record_escaped_link", inspect.getsource(handle_timeout))
        self.assertNotIn("introducing_merge", inspect.getsource(timeout_pin_line))
        self.assertNotIn("introducing_merge", inspect.getsource(write_timeout_finding))
        self.assertIn("write_timeout_finding", inspect.getsource(handle_timeout))
        commit = git_text("log", "-1", "--format=%H", "HEAD", "--", TIMEOUT_LEDGER)
        digest = hashlib.sha256((REPO / TIMEOUT_LEDGER).read_bytes()).hexdigest()
        self.assertRegex(commit, r"^[0-9a-f]{40}$")
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(timeout_pin_line(), f"grant-binding-003 {TIMEOUT_LEDGER} {commit} sha256 {digest}")
        pin = f"grant-binding-003 {TIMEOUT_LEDGER} {commit} sha256 {digest}"
        stale_commit = "0" * 40
        stale_digest = "ab" * 32
        self.assertNotEqual(stale_commit, commit)
        self.assertNotEqual(stale_digest, digest)

        def stale(observed):
            return (
                f"grant-binding-003 {TIMEOUT_LEDGER} {stale_commit} sha256 {stale_digest}\n"
                "\n"
                f"probe: {TIMEOUT_NAME}\n"
                f"observed: {observed}\n"
            )

        def expect(observed):
            return (
                pin
                + "\n\n"
                + f"probe: {TIMEOUT_NAME}\n"
                + f"observed: {observed}\n"
            )

        calls = []
        real_cargo = cargo

        def wrapped(*args, **kwargs):
            calls.append(args)
            raise ProbeError("cargo ran")

        findings = REPO / "lab" / "redteam" / "findings"
        before = {
            path.name: path.read_bytes()
            for path in findings.iterdir()
            if path.is_file()
        }
        root = self.work / "timeout-contract"
        root.mkdir(parents=True, exist_ok=True)
        try:
            globals()["cargo"] = wrapped
            passed = root / "passed.md"
            passed.write_text(stale(TIMEOUT_OK_OBSERVED))
            status, text = handle_timeout(
                None,
                Outcome("passed", f"test {TIMEOUT_NAME} ... ok", ""),
                passed,
            )
            self.assertEqual(status, "refused")
            self.assertIsNone(text)
            self.assertFalse(passed.exists())

            ok_path = root / "ok.md"
            ok_path.write_text(stale(TIMEOUT_FREED_OBSERVED))
            status, text = handle_timeout(
                None,
                Outcome("failed", f"test {TIMEOUT_NAME} ... FAILED", TIMEOUT_OK_PANIC),
                ok_path,
            )
            self.assertEqual(status, "finding")
            self.assertEqual(text, expect(TIMEOUT_OK_OBSERVED))
            self.assertEqual(ok_path.read_text(), text)
            self.assertEqual(text.splitlines()[0].split(" "), [
                "grant-binding-003",
                TIMEOUT_LEDGER,
                commit,
                "sha256",
                digest,
            ])
            self.assertEqual(text.splitlines()[1], "")
            self.assertEqual(text.splitlines()[2], f"probe: {TIMEOUT_NAME}")
            self.assertEqual(text.splitlines()[3], "observed: " + TIMEOUT_OK_OBSERVED)
            self.assertNotIn(TIMEOUT_FREED_OBSERVED, text)
            self.assertNotIn(stale_commit, text)
            self.assertNotIn(stale_digest, text)
            self.assertNotIn(TIMEOUT_OK_PANIC, text)

            freed_path = root / "freed.md"
            freed_path.write_text(stale(TIMEOUT_OK_OBSERVED))
            status, text = handle_timeout(
                None,
                Outcome(
                    "failed",
                    f"test {TIMEOUT_NAME} ... FAILED",
                    TIMEOUT_FREED_PANIC + ": Ok(())",
                ),
                freed_path,
            )
            self.assertEqual(status, "finding")
            self.assertEqual(text, expect(TIMEOUT_FREED_OBSERVED))
            self.assertEqual(freed_path.read_text(), text)
            self.assertEqual(text.splitlines()[3], "observed: " + TIMEOUT_FREED_OBSERVED)
            self.assertNotIn(TIMEOUT_OK_OBSERVED, text)
            self.assertNotIn(TIMEOUT_FREED_PANIC, text)
            self.assertNotIn(stale_commit, text)
            self.assertEqual(calls, [])
        finally:
            globals()["cargo"] = real_cargo
        after = {
            path.name: path.read_bytes()
            for path in findings.iterdir()
            if path.is_file()
        }
        self.assertEqual(after, before)

    def test_renamed_identity_method_turns_compile_error_into_failure(self):
        """The identity method name is ``IDENTITY_NAME``. ``setUp`` and ``expect_recorded`` look up that name.

        A compile error on that method is an error, including when a finding
        records it. Renaming the method leaves it outside ``PROBE_NAMES``, so
        ``setUp`` does not raise. The body fails, and the result is a failure.
        The finding's name does not mark the renamed method as an expected failure.
        """
        compile = Suite(
            101,
            "could not compile `grant-binding`\n",
            {
                name: Outcome("error", "compile error", "could not compile `grant-binding`")
                for name in PROBE_NAMES
            },
        )
        self.assertTrue(callable(getattr(GrantReplayProbe, IDENTITY_NAME)))

        class Named(unittest.TestCase):
            skip_reason = None
            real = compile
            real_error = None

            def setUp(self):
                GrantReplayProbe.setUp(self)

            def test_stale_call_identity_replay_is_refused(self):
                self.fail("body ran after a compile error")

        expect_recorded(Named, {IDENTITY_NAME})
        self.assertTrue(getattr(Named, IDENTITY_NAME).__unittest_expecting_failure__)
        named = run_case(Named)
        self.assertEqual(named.expectedFailures, [])
        self.assertEqual(named.failures, [])
        self.assertEqual(len(named.errors), 1)
        self.assertIn("compile error", named.errors[0][1])

        class Renamed(unittest.TestCase):
            skip_reason = None
            real = compile
            real_error = None

            def setUp(self):
                GrantReplayProbe.setUp(self)

            def test_identity_replay_under_another_name(self):
                outcome = self.real.by_name[IDENTITY_NAME]
                kind = gate_kind(outcome, IDENTITY_NAME, {IDENTITY_NAME})
                self.assertEqual(kind, "pass")

        expect_recorded(Renamed, {IDENTITY_NAME})
        renamed_method = Renamed.test_identity_replay_under_another_name
        self.assertFalse(getattr(renamed_method, "__unittest_expecting_failure__", False))
        renamed = run_case(Renamed)
        self.assertEqual(renamed.errors, [])
        self.assertEqual(renamed.expectedFailures, [])
        self.assertEqual(len(renamed.failures), 1)
        self.assertIn("'error' != 'pass'", renamed.failures[0][1])

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
        self.require_one_anchor("lab/grant-binding/src/ledger.rs", RESERVE_OLD, "reserve")
        suite = self.plant("double-charge", "src/ledger.rs", RESERVE_OLD, DOUBLE_NEW)
        session = suite.by_name[SESSION_NAME]
        sibling = suite.by_name[SIBLING_NAME]
        clean = suite.by_name[CLEAN_NAME]
        path = suite.by_name[PATH_NAME]
        identity = suite.by_name[IDENTITY_NAME]
        self.assertEqual(path.kind, "passed", evidence(suite.output) or tail(suite.output))
        self.assertEqual(identity.kind, "passed", evidence(suite.output) or tail(suite.output))
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

    def test_clean_plant_skips_a_missing_anchor(self):
        """The clean plant skips a missing reserve anchor. It does not plant or start cargo.

        Count one is covered. A clean method that plants first, or a
        ``require_one_anchor`` that does not skip, fails this test.
        """
        ledger = "lab/grant-binding/src/ledger.rs"
        reason = anchor_reason(ledger, 0, "reserve", self.head)
        self.assertIn("does not cover that plant", reason)
        self.assertIsNone(anchor_reason(ledger, 1, "reserve", self.head))
        source = inspect.getsource(GrantReplayProbe.test_clean_full_ceiling_reserve_succeeds)
        live_at = source.find("self.check_real(CLEAN_NAME)")
        anchor_at = source.find("require_one_anchor")
        plant_at = source.find("self.plant(")
        self.assertGreaterEqual(live_at, 0)
        self.assertGreaterEqual(anchor_at, 0)
        self.assertGreaterEqual(plant_at, 0)
        self.assertLess(live_at, anchor_at)
        self.assertLess(anchor_at, plant_at)
        self.assertIn("RESERVE_OLD", source)
        self.assertIn('"reserve"', source)
        self.assertIn(
            'require_one_anchor("lab/grant-binding/src/ledger.rs", RESERVE_OLD, "reserve")',
            source,
        )
        guard = inspect.getsource(GrantReplayProbe.require_one_anchor)
        self.assertIn("self.skipTest(reason)", guard)

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
        self.assertEqual(suite.by_name[IDENTITY_NAME].kind, "passed", evidence(suite.output))
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
        self.assertEqual(suite.by_name[IDENTITY_NAME].kind, "passed", evidence(suite.output))
        self.assertEqual(suite.by_name[CLEAN_NAME].kind, "passed", evidence(suite.output))

    def test_deleted_identity_comparison_is_caught(self):
        """Deleting the live identity comparison accepts the same call after the identity change."""
        self.require_one_anchor("lab/grant-binding/src/lib.rs", IDENTITY_OLD, "identity")
        suite = self.plant("drop-identity", "src/lib.rs", IDENTITY_OLD, "")
        identity = suite.by_name[IDENTITY_NAME]
        self.assertTrue(identity.caught, evidence(suite.output) or tail(suite.output))
        self.assertIn("accepted replay: use_grant returned Ok", identity.output)
        self.assertNotIn("lost accounting:", identity.output)
        self.assertEqual(suite.by_name[SESSION_NAME].kind, "passed", evidence(suite.output))
        self.assertEqual(suite.by_name[SIBLING_NAME].kind, "passed", evidence(suite.output))
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
        self.assertEqual(suite.by_name[IDENTITY_NAME].kind, "passed", evidence(suite.output) or tail(suite.output))

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
        identity_only = pin_line() + (
            "\nprobe: " + IDENTITY_NAME + "\n"
            "call: open_call, use_grant, host_set_identity, use_grant\n"
            "observed: Ok\n"
        )
        self.assertEqual(recorded_from(identity_only), {IDENTITY_NAME})
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

    def test_replay_marker_count_is_refused(self):
        """The replay source holds the repo marker once. Zero or two is a probe error.

        Dropping the count check accepts a source that does not bind this repo.
        """
        self.assertEqual(REPLAY_RS.count(REPO_MARKER), 1)
        samples = (
            (0, "fn unused() {}\n"),
            (2, REPO_MARKER + "\n" + REPO_MARKER + "\n"),
        )
        for count, source in samples:
            with self.assertRaises(ProbeError) as caught:
                render_replay(source, "/tmp/redteam-repo")
            self.assertEqual(
                str(caught.exception),
                f"replay.rs holds {count} copies of {REPO_MARKER}, not one",
            )
        rendered = render_replay(REPLAY_RS, "/tmp/redteam-repo")
        self.assertNotIn(REPO_MARKER, rendered)
        self.assertIn('let repo = "/tmp/redteam-repo";', rendered)

    def test_replay_repo_quote_or_backslash_is_refused(self):
        """A quote or a backslash in the repo path is a probe error.

        Dropping the check writes that character into the Rust string.
        """
        for repo in ('/tmp/a"b', "/tmp/a\\b"):
            with self.assertRaises(ProbeError) as caught:
                render_replay(REPLAY_RS, repo)
            self.assertEqual(
                str(caught.exception),
                "repo path contains a quote or a backslash",
            )
        rendered = render_replay(REPLAY_RS, "/tmp/redteam-repo")
        self.assertNotIn(REPO_MARKER, rendered)
        self.assertIn('let repo = "/tmp/redteam-repo";', rendered)

    def test_suite_refuses_a_set_manifest_variable(self):
        """A full suite with REDTEAM_MANIFEST set is a probe error, before cargo runs.

        Dropping the check in ``run_suite`` launches cargo against that path.
        """
        previous = set_manifest(self.work / "not-used.toml")
        calls = []
        real_cargo = cargo

        def wrapped(*args, **kwargs):
            calls.append(args)
            raise ProbeError("cargo ran")

        try:
            globals()["cargo"] = wrapped
            with self.assertRaises(ProbeError) as caught:
                run_suite(self.work / "probe-env-refuse", CRATE, self.target, [])
            self.assertEqual(
                str(caught.exception),
                "REDTEAM_MANIFEST is set for the suite",
            )
            self.assertEqual(calls, [])
        finally:
            globals()["cargo"] = real_cargo
            set_manifest(previous)

    def test_link_outcome_other_than_passed_blocks_the_clean_line(self):
        """A failed or error link raises, so the clean line is not printed.

        A toolchain skip stays a skip. Treating every link outcome as passed
        prints the clean line after a grant link: that is the break.
        """
        by_name = {
            name: Outcome("passed", f"test {name} ... ok", "")
            for name in PROBE_NAMES
        }
        for kind in ("failed", "error"):
            suite = Suite(
                1, "", by_name, Outcome(kind, kind, "has a path dependency on grant-binding"),
            )
            with self.assertRaises(ProbeError) as caught:
                probe_report(suite, None, False, self.head, self.pin_line)
            self.assertEqual(str(caught.exception), f"link outcome was {kind}")
            self.assertNotIn("were refused", str(caught.exception))
            with self.assertRaises(ProbeError) as recorded:
                probe_report(suite, None, True, self.head, self.pin_line)
            self.assertEqual(str(recorded.exception), f"link outcome was {kind}")
        missing = Suite(1, "", by_name, None)
        with self.assertRaises(ProbeError) as bare:
            probe_report(missing, None, False, self.head, self.pin_line)
        self.assertEqual(str(bare.exception), "link outcome was missing")
        ok = Suite(
            0, "", by_name,
            Outcome("passed", f"test {LINK_NAME} ... ok", ""),
        )
        lines = probe_report(ok, None, False, self.head, self.pin_line)
        self.assertEqual(lines[0], CLEAN.format(commit=self.head))
        self.assertEqual(
            lines[0],
            "these two stale calls were refused and did not spend the ceiling, "
            "and the same call's child path was refused, "
            "and the same call was refused after the identity change, on " + self.head,
        )
        self.assertEqual(lines[1], self.pin_line)
        self.assertEqual(probe_report(ok, None, True, self.head, self.pin_line), [])
        self.assertEqual(probe_report(None, None, False, self.head, self.pin_line), [])
        skipped = probe_report(
            Suite(1, "", by_name, Outcome("failed", "failed", "")),
            "cargo is missing",
            False,
            self.head,
            self.pin_line,
        )
        self.assertEqual(skipped, ["SKIPPED: cargo is missing"])
        self.assertNotIn("appeared", skipped[0])

    def test_link_plant_raises_the_real_suite_error(self):
        """``LINK_NAME`` is outside ``PROBE_NAMES``, so ``setUp`` does not raise. The plant does.

        Dropping the raise runs cargo after the real suite failed.
        """
        self.assertNotIn(LINK_NAME, PROBE_NAMES)
        self.assertNotIn(LINK_NAME, STALE_NAMES)
        self.assertIn(PATH_NAME, PROBE_NAMES)
        self.assertNotIn(PATH_NAME, STALE_NAMES)
        self.assertIn(IDENTITY_NAME, PROBE_NAMES)
        self.assertNotIn(IDENTITY_NAME, STALE_NAMES)
        boom = ProbeError("real suite failed")
        saved_error = self.real_error
        calls = []
        real_cargo = cargo

        def wrapped(*args, **kwargs):
            calls.append(args)
            raise ProbeError("cargo ran")

        self.real_error = boom
        try:
            globals()["cargo"] = wrapped
            with self.assertRaises(ProbeError) as caught:
                self.run_link_manifest("unused")
            self.assertIs(caught.exception, boom)
            self.assertEqual(calls, [])
        finally:
            globals()["cargo"] = real_cargo
            self.real_error = saved_error

    def test_generated_replay_replaces_the_one_marker(self):
        """The generated replay binds this repo. The marker is replaced."""
        if self.real_error is not None:
            raise self.real_error
        text = (self.real_pkg / "tests" / "replay.rs").read_text()
        self.assertEqual(text, render_replay(REPLAY_RS, REPO))
        self.assertNotIn(REPO_MARKER, text)
        self.assertIn(str(REPO), text)
        self.assertIn(
            "grant_binding::link::cargo_toml_path_depends_on_grant_binding",
            text,
        )
        self.assertIn(LINK_NAME, text)

    def test_real_suite_link_passes_with_manifest_unset(self):
        """The real suite's link test passes with ``REDTEAM_MANIFEST`` unset."""
        if self.real_error is not None:
            raise self.real_error
        self.assertIsNone(os.environ.get("REDTEAM_MANIFEST"))
        self.assertEqual(self.real.link.kind, "passed", evidence(self.real.output) or tail(self.real.output))
        self.assertNotEqual(self.real.link.kind, "error")
        self.assertTrue(self.real.link.detail.endswith(" ok"))

    def _link_outcome(self, text):
        code, output, manifest = self.run_link_manifest(text)
        self.assertEqual(manifest.read_text(), text)
        self.assertNotEqual(manifest, (self.real_pkg / "Cargo.toml").resolve())
        self.assertNotEqual(
            manifest,
            (REPO / "lab" / "redteam" / "Cargo.toml").resolve(),
        )
        self.assertIsNone(os.environ.get("REDTEAM_MANIFEST"))
        return code, output, outcome_for(LINK_NAME, code, output)

    def test_name_only_manifest_is_not_a_grant_link(self):
        """A manifest that only names the crate is not a path dependency.

        The owner's detector decides. A guard that panics because the file
        exists fails this test.
        """
        code, output, outcome = self._link_outcome(NAME_ONLY_MANIFEST)
        shown = evidence(output) or tail(output)
        self.assertEqual(code, 0, shown)
        self.assertEqual(outcome.kind, "passed", shown)
        self.assertNotEqual(outcome.kind, "error")

    def test_audit_shaped_manifest_is_not_a_grant_link(self):
        """A path dependency on the audit crate is not a grant-binding link.

        The owner's detector decides. A guard that panics because the file
        exists fails this test.
        """
        code, output, outcome = self._link_outcome(AUDIT_SHAPED_MANIFEST)
        shown = evidence(output) or tail(output)
        self.assertEqual(code, 0, shown)
        self.assertEqual(outcome.kind, "passed", shown)
        self.assertNotEqual(outcome.kind, "error")

    def test_path_manifest_is_caught(self):
        """A path dependency on grant-binding fails the link test.

        Exit 0 is not a catch. Dropping the negation in the assertion lets
        this manifest pass, and the name-only and audit-shaped tests fail.
        """
        code, output, outcome = self._link_outcome(PATH_MANIFEST)
        shown = evidence(output) or tail(output)
        self.assertNotEqual(code, 0, shown)
        self.assertEqual(outcome.kind, "failed", shown)
        self.assertTrue(outcome.caught)
        self.assertNotEqual(outcome.kind, "error")
        self.assertIn("has a path dependency on grant-binding", outcome.output)

    def lay_escaped_probe(self):
        """Lay the dependency at grant-binding and the probe whose path decodes to it."""
        dependency = self.work / "grant-binding"
        probe = self.work / "escaped-probe"
        self._lay_crate(
            dependency,
            "[package]\n"
            'name = "grant-binding"\n'
            'version = "0.0.0"\n'
            'edition = "2021"\n',
            "pub fn f() {}\n",
        )
        self._lay_crate(probe, ESCAPED_MANIFEST, "pub fn g() {}\n")
        return probe

    def _lay_crate(self, root, manifest, lib):
        source = Path(root) / "src"
        source.mkdir(parents=True, exist_ok=True)
        (Path(root) / "Cargo.toml").write_text(manifest)
        (source / "lib.rs").write_text(lib)

    def test_escaped_path_dependency_matches_cargo(self):
        """Cargo resolves the escaped path. The raw text does not name the crate.

        The owner's detector reads that raw text. A pass writes
        grant-binding-002. A caught failure writes nothing to
        caught-escape.md, leaves grant-binding-002.md unchanged, and says
        the detector returned true. An error propagates. A false detector
        result is not a skip.
        """
        self.assertNotIn(self._testMethodName, PROBE_NAMES)
        self.assertNotIn(self._testMethodName, STALE_NAMES)
        encoded = ESCAPED_MANIFEST.encode()
        self.assertIn(b"\\u0069", encoded)
        self.assertNotIn(b"grant-binding", encoded)
        _code, _output, outcome = self._link_outcome(ESCAPED_MANIFEST)
        probe = self.lay_escaped_probe()
        self.assertEqual((probe / "Cargo.toml").read_bytes(), encoded)
        manifest_path = str(probe / "Cargo.toml")
        meta_code, meta_output = cargo(
            probe,
            [
                "metadata",
                "--offline",
                "--format-version",
                "1",
                "--manifest-path",
                manifest_path,
            ],
            self.target,
        )
        print(f"escaped link outcome: {outcome.kind}", file=sys.stderr, flush=True)
        self.assertTrue(LINK_FINDING.is_file(), "grant-binding-002.md is absent")
        tracked = LINK_FINDING.read_bytes()
        caught_escape = self.work / "caught-escape.md"
        if outcome.kind == "failed" and outcome.caught:
            self.assertFalse(caught_escape.exists())
            destination = caught_escape
        else:
            destination = LINK_FINDING
        returned = record_escaped_link(outcome, meta_code, meta_output, destination)
        start = meta_output.find("{")
        parsed, _end = json.JSONDecoder().raw_decode(meta_output, start)
        names = [package["name"] for package in parsed["packages"]]
        print(
            f"escaped metadata packages: {', '.join(names)}",
            file=sys.stderr,
            flush=True,
        )
        grant_dir = next(
            Path(package["manifest_path"]).resolve().parent
            for package in parsed["packages"]
            if package["name"] == "grant-binding"
        )
        self.assertEqual(grant_dir, (self.work / "grant-binding").resolve())
        self.assertIn("grant-binding", names)
        self.assertFalse(FINDING.is_file())
        if outcome.kind == "passed":
            document = live_escaped_document()
            self.assertEqual(link_pin_line(), document.splitlines()[0])
            self.assertEqual(returned, document)
            self.assertEqual(LINK_FINDING.read_text(), returned)
            self.assertEqual(LINK_FINDING.read_text().splitlines()[0], link_pin_line())
            self.assertEqual(
                LINK_FINDING.read_text().splitlines()[2:],
                [
                    "probe: test_escaped_path_dependency_matches_cargo",
                    "observed: detector returned false",
                    "cargo metadata package: grant-binding",
                ],
            )
        elif outcome.kind == "failed" and outcome.caught:
            self.assertEqual(destination, self.work / "caught-escape.md")
            self.assertFalse(destination.exists())
            self.assertEqual(returned, names)
            self.assertTrue(LINK_FINDING.is_file(), "grant-binding-002.md is absent")
            self.assertEqual(LINK_FINDING.read_bytes(), tracked)
            print("detector returned true", file=sys.stderr, flush=True)
        else:
            self.fail(f"escaped link outcome: {outcome.kind}")

    def test_escaped_probe_errors_are_probe_errors(self):
        """Each metadata or link error is its own ProbeError and writes nothing.

        Removing that reason's raise makes that subTest fail.
        """
        valid = '{"packages":[{"name":"grant-binding"}]}'
        passed = Outcome("passed", "ok", "")
        cases = (
            (
                "cargo metadata exited",
                1,
                valid,
                passed,
                "cargo metadata exited 1",
            ),
            (
                "cargo metadata output has no JSON object",
                0,
                "cargo metadata produced no object",
                passed,
                "cargo metadata output has no JSON object",
            ),
            (
                "cargo metadata JSON is invalid",
                0,
                "{not json",
                passed,
                "cargo metadata JSON is invalid",
            ),
            (
                "cargo metadata names no grant-binding package",
                0,
                '{"packages":[{"name":"escape-probe"}]}',
                passed,
                "cargo metadata names no grant-binding package",
            ),
            (
                "link outcome was error",
                0,
                valid,
                Outcome("error", "compile error", "could not compile"),
                "link outcome was error: compile error",
            ),
        )
        findings = REPO / "lab" / "redteam" / "findings"
        before_names = sorted(path.name for path in findings.iterdir())
        before_link = LINK_FINDING.read_bytes() if LINK_FINDING.is_file() else None
        for index, (name, code, output, outcome, reason) in enumerate(cases):
            with self.subTest(name):
                dest = self.work / "escaped-errors" / f"{index}.md"
                dest.parent.mkdir(parents=True, exist_ok=True)
                self.assertFalse(dest.is_file())
                with self.assertRaises(ProbeError) as caught:
                    record_escaped_link(outcome, code, output, dest)
                self.assertEqual(str(caught.exception), reason)
                self.assertFalse(dest.is_file())
                self.assertEqual(
                    sorted(path.name for path in findings.iterdir()),
                    before_names,
                )
                after_link = LINK_FINDING.read_bytes() if LINK_FINDING.is_file() else None
                self.assertEqual(after_link, before_link)

    def test_escaped_finding_contract(self):
        """A pass writes the live document. A caught failure leaves the destination absent.

        The two calls share one cargo metadata result. The outcome the live
        link did not return is built here. A wrong pin or a wrong body fails
        the pass. A finding left behind fails the failure.
        """
        _code, _output, live = self._link_outcome(ESCAPED_MANIFEST)
        probe = self.lay_escaped_probe()
        meta_code, meta_output = cargo(
            probe,
            [
                "metadata",
                "--offline",
                "--format-version",
                "1",
                "--manifest-path",
                str(probe / "Cargo.toml"),
            ],
            self.target,
        )
        if live.kind == "passed":
            other = Outcome(
                "failed",
                "test redteam_manifest_is_not_a_grant_link ... FAILED",
                live.output,
            )
        elif live.kind == "failed" and live.caught:
            other = Outcome(
                "passed",
                "test redteam_manifest_is_not_a_grant_link ... ok",
                live.output,
            )
        else:
            record_escaped_link(
                live, meta_code, meta_output, self.work / "escaped-link-error.md",
            )
            self.fail(f"link outcome was {live.kind}")
        document = live_escaped_document()
        self.assertEqual(link_pin_line(), document.splitlines()[0])
        names = None
        for item in (live, other):
            dest = self.work / f"link-contract-{item.kind}.md"
            self.assertFalse(dest.exists())
            returned = record_escaped_link(item, meta_code, meta_output, dest)
            if names is None:
                start = meta_output.find("{")
                parsed, _end = json.JSONDecoder().raw_decode(meta_output, start)
                names = [package["name"] for package in parsed["packages"]]
            if item.kind == "passed":
                self.assertTrue(dest.is_file())
                self.assertEqual(dest.read_text(), document)
                self.assertEqual(returned, document)
                self.assertEqual(dest.read_text().splitlines()[0], link_pin_line())
            else:
                self.assertTrue(item.caught)
                self.assertFalse(dest.exists())
                self.assertEqual(returned, names)

    def run_link_manifest(self, text):
        """Run the one link test in the real package against a temp manifest.

        ``setUp`` raises ``real_error`` only for ``PROBE_NAMES``. ``LINK_NAME``
        stays out of that tuple, so this plant raises ``real_error`` itself.
        ``--exact`` filters that package. The variable is set only around
        ``cargo`` and removed in ``finally``.
        """
        if self.real_error is not None:
            raise self.real_error
        if self.real is None or self.real_pkg is None:
            raise ProbeError("link plant did not run")
        manifest = write_link_manifest(self.work, self.real_pkg, text)
        previous = set_manifest(manifest)
        try:
            code, output = cargo(
                self.real_pkg,
                [
                    "test", "--offline", "--locked",
                    "--manifest-path", str(self.real_pkg / "Cargo.toml"),
                    "--", "--exact", LINK_NAME,
                ],
                self.target,
            )
        finally:
            set_manifest(previous)
        return code, output, manifest

    def _expecting(self, name):
        return getattr(getattr(GrantReplayProbe, name), "__unittest_expecting_failure__", False)


expect_recorded(GrantReplayProbe, recorded_probes())


def probe_report(real, skip, finding_present, head, pins):
    """Lines for stderr after the suite.

    A toolchain skip is ``SKIPPED`` and does not treat a manifest as a failure.
    When the suite ran, a link outcome other than ``passed`` raises, so the
    caller does not print the clean line. Dropping that refusal prints the
    clean line after a grant link.
    """
    if skip:
        return [f"SKIPPED: {skip}"]
    if real is not None:
        kind = real.link.kind if real.link is not None else "missing"
        if kind != "passed":
            raise ProbeError(f"link outcome was {kind}")
    if real is None or finding_present:
        return []
    if all(real.by_name[name].kind == "passed" for name in PROBE_NAMES):
        lines = [CLEAN.format(commit=head), pins]
        lines.extend(real.by_name[name].detail for name in PROBE_NAMES)
        return lines
    return []


def tearDownModule():
    saved = GrantReplayProbe._saved_manifest
    restore = GrantReplayProbe._manifest_saved
    try:
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
        for line in probe_report(real, skip, FINDING.is_file(), head, pins):
            print(line, file=sys.stderr)
    finally:
        if restore:
            set_manifest(saved)
            GrantReplayProbe._manifest_saved = False
