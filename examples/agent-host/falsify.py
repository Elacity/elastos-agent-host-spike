#!/usr/bin/env python3
"""Break each agent-host check, see its named tests fail, restore it.

Usage (from anywhere):
  python3 -I examples/agent-host/falsify.py              # every falsifier
  python3 -I examples/agent-host/falsify.py FS           # one prefix
  python3 -I examples/agent-host/falsify.py FS01 FS03    # some ids
  python3 -I examples/agent-host/falsify.py --list       # ids, commands, expectations
  python3 -I examples/agent-host/falsify.py --self-test  # the runner checks itself
  python3 -I examples/agent-host/falsify.py --self-test --with-repo  # and one real falsifier
  python3 -I examples/agent-host/falsify.py --self-test-case NAME  # one named case

The falsifiers are data, in falsifiers.json next to this file. Each one
replaces exact text (found exactly once) in a file and requires every named
test to FAIL. The verdict comes from exit codes: the mutated code is built
first (a build that fails is its own result); then each named test is listed
with `--exact` (exactly one test must match) and run alone with `--exact`.
A non-zero exit alone is not a catch: the harness evidence must be error-free
(a loader or Cargo error marker anywhere in the output, on either stream,
after terminal formatting is stripped, is NOT RUN and never a catch, and so
is a harness error marker anywhere outside a failed test's own captured
section), and a summary must say that test ran and failed. Every mode uses
this one proof, `survives` included: one named test that still passes means the
falsifier SURVIVED, and a survivor counts
only when at least one of its named tests ran and none reported failed. A
survivor whose named test did not run is NOT RUN. A named test that passes but
prints a line starting `SKIP ` did not run its check, so it is NOT RUN, never
a pass or a catch.

Before the first edit, every chosen named test runs once on the unmutated
tree. A test that fails or cannot run there proves nothing: its entry is NOT
RUN with that reason, and a command whose unmutated build fails makes every
chosen entry of that command NOT RUN.

The original file's bytes are kept as a hard link while the mutated copy is
in place, and the restore is a rename, so it needs no free space. The restore
runs on error, Ctrl-C and SIGTERM, and signals stay blocked until every
original is back, so an interrupt during the edit leaves the source unchanged
before the error propagates. A backup left by a killed run is put back before
anything else. The runner stops when the disk has less than 2 GiB free or a
command reports a full disk.

Exit status: 0 when every falsifier did what it expects, 1 otherwise, 2 for a
usage or data error, 3 when it stopped for a full disk.
"""
from collections import namedtuple
import contextlib
import io
import json
import inspect
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
DATA = HERE / "falsifiers.json"
# Each provider crate is its own workspace with its own lockfile.
PROVIDER_MANIFEST = REPO / "capsules" / "model-provider" / "Cargo.toml"
# One table for the three provider crates, the lab's capsule-identity crate,
# the lab's agent-conformance crate and the lab's wasm-capsule workspace.
# Each row is a crate's manifest plus the optional Cargo arguments its command
# adds; each entry is its own workspace with its own lockfile, and its command
# exists only with that manifest and those arguments: a second branch per
# crate would be a second copy of the same rule (P10). The lab workspace needs
# `--workspace`, because its root package `capsule` is the default selection
# and its audit member's tests live behind that flag. The agent-conformance
# crate needs no argument: its `default-members` already select its `probe`
# member.
PROVIDER_CRATES = {
    "provider": (PROVIDER_MANIFEST, ()),
    "did": (REPO / "capsules" / "did-provider" / "Cargo.toml", ()),
    "wallet": (REPO / "capsules" / "wallet-provider" / "Cargo.toml", ()),
    "capsule-identity": (REPO / "lab" / "capsule-identity" / "Cargo.toml", ()),
    "agent-conformance": (REPO / "lab" / "agent-conformance" / "Cargo.toml", ()),
    "lab": (REPO / "lab" / "wasm-capsule" / "Cargo.toml", ("--workspace",)),
}
BACKUP_SUFFIX = ".falsify-original"
# Capture ancestor ownership once. The environment then publishes that set
# plus this process's live backups to children; it is not a local ownership
# source after publication. Each live mutation restores its own backup.
OWNED_BACKUPS_ENV = "FALSIFY_OWNED_BACKUPS"
INHERITED_BACKUPS = frozenset(
    pathlib.Path(name).resolve()
    for name in os.environ.get(OWNED_BACKUPS_ENV, "").split(os.pathsep) if name)
OWNED_BACKUPS = set()
MIN_FREE_BYTES = int(os.environ.get("FALSIFY_MIN_FREE_BYTES", 2 * 1024**3))
COMMANDS = ("host", *PROVIDER_CRATES, "e2e", "selftest")
# Self-test scratch stays in this lane's report directory, so a run writes
# only below a path the lane owns.
SELF_TEST_DIR = HERE / "handoff" / "reports" / ".falsify-selftest"
DISK_FULL = ("No space left on device", "ENOSPC", "Disk quota exceeded")
# The test harness prints this line after every run of the binary. A panic in
# a test body can print anything, including a fake FAILED line, before it.
TEST_RESULT = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed;", re.MULTILINE)
# Terminal formatting is not evidence: a colored label reads as its plain
# text, so a marker cannot hide behind a color escape.
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# A harness error marker is the `error:` label with a message after it, and it
# counts anywhere on a line: a prefixed message such as
# `test-bin: error: ...` carries the same marker. Identifiers such as
# `BusError::Denied` do not match: no word boundary precedes `error` inside a
# longer word, and a space must follow the colon.
HARNESS_ERROR = re.compile(
    r"\b(?:error|Error)(?:\[[^\]]*\])?:\s|Traceback \(most recent call last\)")
# A loader reports these with a prefix, for example `/test-bin: error while
# loading shared libraries: ...` or `dyld[1234]: Library not loaded: ...`, so
# the line start does not carry the marker and the phrase counts anywhere.
LOADER_ERROR = re.compile(
    r"dyld(?:\[[^\]]*\])?: |error while loading shared libraries|Library not loaded:")
# Cargo says the test process never started, or died abnormally: that report
# is not a failed test, and it stays evidence when the ordinary failure footer
# is removed.
CARGO_FAILURE = re.compile(
    r"could not execute process|never executed"
    r"|process didn't exit successfully|\(signal: \d+, SIG[A-Z0-9]+\)")
# Cargo prints this footer after an ordinary failing test: the harness ran the
# test and the test failed, so the footer itself is not a harness error. Only
# the footer text is removed; anything after it on the same line is checked.
TEST_FAILED = re.compile(r"^[ \t]*error: test failed, to rerun pass", re.MULTILINE)
# A failed test's own captured section starts at a line that is exactly
# `---- NAME stdout ----` and ends at the next line that is exactly
# `failures:`. The harness prints that section only after the test ran, so the
# text in it belongs to the test: a test may quote a child's standard error on
# purpose to give its reason (P11), and that quote is not a harness error. The
# runner joins both streams before this removal, so a section printed on
# stderr is removed the same way. A section with no later `failures:` line is
# not the harness's framing and stays checked, and the removal never reaches
# past that line. The loader and Cargo checks read the output before the
# removal, so their markers count inside a section too.
OWN_FAILURE_TEXT = re.compile(
    r"^---- .+ stdout ----\n(?:.*\n)*?^failures:$\n?", re.MULTILINE)
# A passing test that printed a line starting `SKIP ` did not run its check:
# it reported a host or fixture the check cannot use. libtest prints that line
# only with --show-output, and the line counts anywhere in the test's own
# output, so a skip is never a pass and never a catch.
SKIPPED_TEST = re.compile(r"^SKIP ", re.MULTILINE)
# A named self-test case runs in its own process. A non-zero exit alone does
# not say the case ran: a loading error also exits non-zero. The child prints
# one marker line only after the case returns, and the runner requires both.
CASE_PASSED = 0
CASE_FAILED = 1
CASE_USAGE = 2
CASE_ERROR = 3


def case_marker(name, word):
    return f"self-test case {name!r}: {word}"


ParsedArgv = namedtuple(
    "ParsedArgv", "path mode name filters keep_backups with_repo")


def refuse(reason):
    """Stop before any work: an unsupported option is never a selection."""
    print(f"usage: {reason}", file=sys.stderr)
    raise SystemExit(CASE_USAGE)


def parse_argv(argv):
    """The data file and the mode, from the arguments alone.

    This is the front door: it reads no file, runs no test and changes
    nothing. An option it does not know stops the run here with status 2 and
    its own reason, so a typo can never select work.
    """
    path = DATA
    from_selected = False
    filters = []
    keep_backups = False
    with_repo = False
    want_list = False
    want_cases = False
    want_self_test = False
    case_name = None
    at = 0
    while at < len(argv):
        token = argv[at]
        if token == "--from":
            if at + 1 >= len(argv) or argv[at + 1].startswith("-"):
                refuse("--from needs a path, not an option")
            at += 1
            path = pathlib.Path(argv[at])
            from_selected = True
        elif token.startswith("--from="):
            refuse("--from=PATH is not supported; use --from PATH")
        elif token == "--list":
            want_list = True
        elif token == "--keep-backups":
            keep_backups = True
        elif token == "--with-repo":
            with_repo = True
        elif token == "--self-test-cases":
            want_cases = True
        elif token == "--self-test":
            want_self_test = True
        elif token == "--self-test-case":
            if at + 1 >= len(argv) or argv[at + 1].startswith("-"):
                refuse("--self-test-case needs a case name, not an option")
            at += 1
            case_name = argv[at]
        elif token.startswith("-"):
            refuse(f"unknown option {token}")
        else:
            filters.append(token)
        at += 1
    if want_list:
        mode = "list"
    elif want_cases:
        mode = "self-test-cases"
    elif case_name is not None:
        mode = "self-test-case"
    elif want_self_test:
        mode = "self-test"
    else:
        mode = "run"
    if mode == "run" and not filters and not from_selected and (keep_backups or with_repo):
        refuse("--keep-backups and --with-repo need a mode, --from PATH, or an id prefix")
    return ParsedArgv(path, mode, case_name, filters, keep_backups, with_repo)


class DiskFull(Exception):
    pass


def load_refuse(path, reason):
    """Stop on a data file that cannot load: status 2 and one clear reason. A
    refusal never selects work and never counts as zero falsifiers run."""
    print(f"{path}: {reason}", file=sys.stderr)
    raise SystemExit(CASE_USAGE)


def load(path=DATA):
    """The entries, or a refusal with status 2 when the data file is missing,
    is not JSON, or has the wrong document shape."""
    try:
        if not path.is_file():
            load_refuse(path, "the data file does not exist")
        text = path.read_text(encoding="utf-8")
    except OSError:
        load_refuse(path, "the data file cannot be read")
    except UnicodeDecodeError:
        load_refuse(path, "the data file is not JSON")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        load_refuse(path, "the data file is not JSON")
    if not isinstance(doc, dict):
        load_refuse(path, "the document is not an object")
    if "falsifiers" not in doc:
        load_refuse(path, "the document has no falsifiers list")
    entries = doc["falsifiers"]
    if not isinstance(entries, list):
        load_refuse(path, "falsifiers is not a list")
    ids = [entry["id"] for entry in entries]
    if len(ids) != len(set(ids)):
        load_refuse(path, "an id is used twice")
    for entry in entries:
        if entry["command"] not in COMMANDS:
            load_refuse(path, f"{entry['id']}: unknown command {entry['command']!r}")
        if entry["expect"] not in ("caught", "compile_error", "survives"):
            load_refuse(path, f"{entry['id']}: unknown expect {entry['expect']!r}")
        if entry["expect"] in ("caught", "survives") and not entry["tests"]:
            load_refuse(path, f"{entry['id']}: no named tests")
    return entries


# The files the lists this runner loads mutate, relative to REPO. Each exact
# target is restored on startup; a file under examples/agent-host is already
# covered by this runner's own search. The lists and their targets:
# - capsules/model-provider/falsifiers.json: the model provider's
#   src/local_memory.rs, src/journal.rs, src/contract.rs, src/state.rs,
#   src/local_llama.rs and src/adapters.rs. Its `selftest` entries edit
#   falsify.py, which recovery finds under examples/agent-host.
# - capsules/model-provider/confine-falsifiers.json: the model `confine.sb`
#   and tests/confine/main.rs.
# - capsules/did-provider/falsifiers.json: did's src/main.rs, did's
#   confine.sb and did's tests/confine.rs.
# - capsules/wallet-provider/falsifiers.json: wallet's src/main.rs, wallet's
#   confine.sb, wallet's tests/confine.rs and src/tests/falsifiers.rs, and
#   did's confine.sb.
# - lab/capsule-identity/falsifiers.json: capsule-identity's .gitignore,
#   README.md, src/lib.rs, tests/common/mod.rs and
#   fixtures/wc001-core/capsule.json.
# - lab/wasm-capsule/falsifiers.json and lab/wasm-capsule/audit/falsifiers.json:
#   the lab capsule's .gitignore, README.md, capsule/capsule.json,
#   capsule/src/lib.rs, tests/common/build.rs, tests/lab_cid.rs,
#   tests/verify.rs, tools/build, tools/src/bin/bundle.rs,
#   tools/src/bundle.rs, tools/src/lib.rs, tools/src/receipt.rs,
#   tools/src/run.rs and tools/src/verify.rs, the lab's run log LOG.md, and
#   the audit crate's Cargo.toml, INTERFACE.md and src/lib.rs.
#   tests/lab_cid.rs is named here ahead of the wasm lab's planned entry that
#   edits it; no list edits it at this base. tools/src/lab_name.rs is gone
#   from the tree and keeps its line because two entries of the model list
#   anchor on it.
# - examples/agent-host/falsifiers.json: asks.json, falsify.py and src/lib.rs,
#   all under examples/agent-host, which this runner's own search restores, so
#   the tuple needs no line for it.
# - lab/agent-conformance/falsifiers.json: the 19 files its entries edit,
#   named relative to its own folder: fixtures/granted-bytes.txt,
#   fixtures/grants.json, fixtures/home-source.txt, fixtures/host-key-read.txt,
#   fixtures/instance-grants.json, fixtures/operator-api-host.txt,
#   fixtures/parallel-tasks.txt, probe/capsule.json, probe/src/lib.rs,
#   src/census.rs, src/harness.rs, src/report.rs, tests/artifact.rs,
#   tests/common/grants.rs, tests/common/mod.rs, tests/common/operator.rs,
#   tests/common/probe.rs, tests/effects.rs and tests/runtime.rs. The list
#   still uses the old paths until its owning lane rewrites it to this
#   runner's rule. Its F-ac2c entry edits fixtures/no-policy.json, which does
#   not exist, so it gets no line: the runner refuses an edit to a missing
#   file, and recutting that entry is that lane's job.
# A killed run therefore restores an exact file instead of leaving a weakened
# confinement test, profile or fixture behind.
PROVIDER_TARGETS = (
    "capsules/model-provider/src/local_memory.rs",
    "capsules/model-provider/src/journal.rs",
    "capsules/model-provider/src/contract.rs",
    "capsules/model-provider/confine.sb",
    "capsules/model-provider/tests/confine/main.rs",
    "capsules/did-provider/src/main.rs",
    "capsules/did-provider/confine.sb",
    "capsules/did-provider/tests/confine.rs",
    "capsules/wallet-provider/src/main.rs",
    "capsules/wallet-provider/confine.sb",
    "capsules/wallet-provider/tests/confine.rs",
    "capsules/wallet-provider/src/tests/falsifiers.rs",
    "lab/capsule-identity/src/lib.rs",
    "lab/capsule-identity/tests/common/mod.rs",
    "lab/capsule-identity/fixtures/wc001-core/capsule.json",
    "lab/wasm-capsule/capsule/src/lib.rs",
    "lab/wasm-capsule/tools/build",
    "lab/wasm-capsule/tools/src/lab_name.rs",
    "lab/wasm-capsule/audit/Cargo.toml",
    "lab/wasm-capsule/audit/INTERFACE.md",
    "lab/wasm-capsule/audit/src/lib.rs",
    "lab/wasm-capsule/.gitignore",
    "lab/wasm-capsule/README.md",
    "lab/wasm-capsule/capsule/capsule.json",
    "lab/wasm-capsule/tests/common/build.rs",
    "lab/wasm-capsule/tests/verify.rs",
    "lab/wasm-capsule/tools/src/bin/bundle.rs",
    "lab/wasm-capsule/tools/src/bundle.rs",
    "lab/wasm-capsule/tools/src/lib.rs",
    "lab/wasm-capsule/tools/src/verify.rs",
    "lab/wasm-capsule/LOG.md",
    "lab/capsule-identity/.gitignore",
    "lab/capsule-identity/README.md",
    "lab/wasm-capsule/tools/src/run.rs",
    "lab/wasm-capsule/tools/src/receipt.rs",
    "lab/wasm-capsule/tests/lab_cid.rs",
    "capsules/model-provider/src/state.rs",
    "capsules/model-provider/src/local_llama.rs",
    "capsules/model-provider/src/adapters.rs",
    "lab/agent-conformance/fixtures/granted-bytes.txt",
    "lab/agent-conformance/fixtures/grants.json",
    "lab/agent-conformance/fixtures/home-source.txt",
    "lab/agent-conformance/fixtures/host-key-read.txt",
    "lab/agent-conformance/fixtures/instance-grants.json",
    "lab/agent-conformance/fixtures/operator-api-host.txt",
    "lab/agent-conformance/fixtures/parallel-tasks.txt",
    "lab/agent-conformance/probe/capsule.json",
    "lab/agent-conformance/probe/src/lib.rs",
    "lab/agent-conformance/src/census.rs",
    "lab/agent-conformance/src/harness.rs",
    "lab/agent-conformance/src/report.rs",
    "lab/agent-conformance/tests/artifact.rs",
    "lab/agent-conformance/tests/common/grants.rs",
    "lab/agent-conformance/tests/common/mod.rs",
    "lab/agent-conformance/tests/common/operator.rs",
    "lab/agent-conformance/tests/common/probe.rs",
    "lab/agent-conformance/tests/effects.rs",
    "lab/agent-conformance/tests/runtime.rs",
)


def owned_backups():
    """The backup paths held by this process or handed down by a caller. The
    environment carries them into nested runs, so each one knows which
    backups belong to a live mutation instead of a killed run."""
    return OWNED_BACKUPS | INHERITED_BACKUPS


def publish_owned_backups():
    names = sorted(str(path) for path in owned_backups())
    if names:
        os.environ[OWNED_BACKUPS_ENV] = os.pathsep.join(names)
    else:
        os.environ.pop(OWNED_BACKUPS_ENV, None)


def own_backup(backup):
    OWNED_BACKUPS.add(backup.resolve())
    publish_owned_backups()


def disown_backup(backup):
    OWNED_BACKUPS.discard(backup.resolve())
    publish_owned_backups()


def recover_backups():
    """Restore this runner's originals: agent-host files and the exact files
    named in PROVIDER_TARGETS, which include other lanes' edit files and not
    only provider files. Other files stay with their owning runners.
    Recovery is independent of the data file selected for the next run, and it
    never touches a backup a caller still owns."""
    owned = owned_backups()
    backups = set(HERE.rglob("*" + BACKUP_SUFFIX))
    for name in PROVIDER_TARGETS:
        target = REPO / name
        backups.update(target.parent.glob(target.name + BACKUP_SUFFIX))
    for backup in sorted(backups):
        if backup.resolve() in owned:
            continue
        target = backup.with_name(backup.name[: -len(BACKUP_SUFFIX)])
        os.replace(backup, target)
        os.utime(target)
        print(f"recovered {target.relative_to(REPO)} from a killed run")


def check_disk():
    free = shutil.disk_usage(REPO).free
    if free < MIN_FREE_BYTES:
        raise DiskFull(f"only {free // 1024**2} MiB free")


def block_interruptions():
    """Ignore Ctrl-C and SIGTERM while the originals are put back. Returns
    (signal number, previous handler) pairs for restore_interruptions."""
    saved = []
    if threading.current_thread() is threading.main_thread():
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            saved.append((number, signal.getsignal(number)))
            signal.signal(number, signal.SIG_IGN)
    return saved


def restore_interruptions(saved):
    for number, handler in saved:
        signal.signal(number, handler)


class BackupCollision(Exception):
    """A backup or temporary file this run did not create is already there.
    The name decides ownership: this run stops before it touches the caller's
    bytes."""


def remove_own_tmp(tmp):
    """Remove the temporary file this run created, and only that file: a name
    this run did not create is never removed (task 029)."""
    if tmp is not None and tmp.exists():
        tmp.unlink()


class Mutation:
    """Apply one falsifier's edits; undo them on exit, whatever happened."""

    def __init__(self, entry, base=HERE):
        self.entry = entry
        self.base = base
        self.applied = []  # (path, backup, original bytes)

    def __enter__(self):
        by_file = {}
        for edit in self.entry["edits"]:
            by_file.setdefault(edit["file"], []).append(edit)
        texts = {}
        for name, edits in by_file.items():
            path = self.base / name
            # One path rule: an edit names a file under examples/agent-host,
            # and this decides on the tree as it stands when the entry starts.
            # An absolute name, a folder that resolves outside REPO and a
            # symbolic link each get a reason before any link or write (P11).
            # A tree changed during the run is not guarded here (BACKLOG item
            # 16), and a file already planted at the temporary-file name is
            # task 029.
            if pathlib.Path(name).is_absolute():
                raise LookupError(
                    f"{name}: the path is absolute; "
                    "edit paths are relative to examples/agent-host")
            folder = path.parent.resolve()
            repository = REPO.resolve()
            if folder != repository and repository not in folder.parents:
                raise LookupError(
                    f"{name}: the path leaves the repository; "
                    "edit paths are relative to examples/agent-host")
            if path.is_symlink():
                raise LookupError(
                    f"{name}: the file is a symbolic link; "
                    "an edit names the file itself")
            # A missing file is a refusal with its reason, not a read error,
            # and it is decided before any link or write (P11).
            if not path.is_file():
                raise LookupError(
                    f"{name}: the file does not exist; "
                    "edit paths are relative to examples/agent-host")
            text = path.read_text(encoding="utf-8")
            for edit in edits:
                count = text.count(edit["old"])
                if count != 1:
                    raise LookupError(f"{name}: the original text is found {count} times, not once")
                text = text.replace(edit["old"], edit["new"])
            texts[path] = text
        owned_tmp = None
        try:
            for path, text in texts.items():
                original = path.read_bytes()
                backup = path.with_name(path.name + BACKUP_SUFFIX)
                tmp = path.with_name(path.name + ".falsify-tmp")
                # Ownership of the temporary file comes from its exclusive
                # create, and that decision comes before the backup link: a
                # name that already exists belongs to another run or to a
                # killed run's leftover, and writing through it would change
                # a file this run does not own (P11).
                try:
                    try:
                        descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
                    except FileExistsError as error:
                        raise BackupCollision(
                            f"{tmp}: a temporary file this run did not create; "
                            "the edit is not applied") from error
                    owned_tmp = tmp
                    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                        stream.write(text)
                except BaseException:
                    remove_own_tmp(owned_tmp)
                    owned_tmp = None
                    raise
                # The link decides ownership: a backup that already exists
                # belongs to another run, and consuming it would put that
                # run's original back. Signals stay off across the link and
                # the record, so a kill cannot leave an owned backup
                # unrecorded.
                saved = block_interruptions()
                try:
                    try:
                        os.link(path, backup)
                    except FileExistsError as error:
                        raise BackupCollision(
                            f"{backup} is a backup this run did not create; "
                            "the edit is not applied") from error
                    self.applied.append((path, backup, original))
                    own_backup(backup)
                except BaseException:
                    remove_own_tmp(owned_tmp)
                    owned_tmp = None
                    raise
                finally:
                    restore_interruptions(saved)
                try:
                    os.replace(tmp, path)
                finally:
                    remove_own_tmp(owned_tmp)
                    owned_tmp = None
            # Inside the try: an interrupt after the last replacement but
            # before __enter__ returns must still restore (task 004).
            return self
        except BaseException as error:
            # Python does not call __exit__ when __enter__ raises, and a
            # Ctrl-C or SIGTERM can arrive just after a replacement. Put every
            # original back before the interruption goes on.
            self.restore()
            if isinstance(error, OSError) and "No space" in str(error):
                raise DiskFull(str(error)) from error
            raise

    def restore(self):
        saved = block_interruptions()
        try:
            for path, backup, original in reversed(self.applied):
                if backup.exists():
                    os.replace(backup, path)
                    # The rename brings back the original's old mtime; touch
                    # it, so cargo does not take the mutated build for a fresh
                    # one.
                    os.utime(path)
                    if path.read_bytes() != original:
                        raise SystemExit(
                            f"{path}: restored bytes differ from the saved original; stop")
                disown_backup(backup)
            self.applied = []
        finally:
            restore_interruptions(saved)

    def __exit__(self, *_):
        self.restore()
        return False


def spec(command, manifest=None, cargo_flags=("--locked",)):
    """How to build and run one named test, for a command."""
    if command == "host":
        cargo = ["cargo", "test", *cargo_flags, "--manifest-path", str(manifest or HERE / "Cargo.toml")]
        return {
            "build": [(cargo + ["--no-run"], REPO)],
            "one": (cargo + ["--"], REPO, []),
        }
    if command in PROVIDER_CRATES:
        # Each crate in the table is its own workspace with its own lockfile,
        # so its test command names --locked and that crate's manifest
        # directly. A row's optional Cargo arguments follow the manifest and
        # stay before the libtest separator: the lab workspace's --workspace
        # selects its audit member, and an existing row adds none.
        crate_manifest, cargo_args = PROVIDER_CRATES[command]
        cargo = ["cargo", "test", "--locked",
                 "--manifest-path", str(manifest or crate_manifest)]
        return {
            "build": [(cargo + list(cargo_args) + ["--no-run"], REPO)],
            "one": (cargo + list(cargo_args) + ["--"], REPO, []),
        }
    if command == "selftest":
        # A change to this runner is checked by its own self-test. A fresh
        # process reads the mutated file; --keep-backups stops it from taking
        # this run's backup of falsify.py for a killed run's leftover. Each
        # named case runs in its own process, as each named test does.
        base = ["python3", "-I", str(HERE / "falsify.py"), "--keep-backups"]
        return {"build": [], "one": (base, REPO, [])}
    cargo = ["cargo", "test", "-p", "elastos-server", "--lib"]
    return {
        "build": [(["bash", str(HERE / "build.sh")], REPO), (cargo + ["--no-run"], REPO / "elastos")],
        "one": (cargo + ["--"], REPO / "elastos", ["--ignored"]),
    }


def run(argv, cwd):
    """Run a command; return its exit code and its output. The output is read
    only to stop on a full disk and to see the harness's own summary line,
    never to decide that a test passed."""
    env = dict(os.environ, RUST_TEST_THREADS=os.environ.get("RUST_TEST_THREADS", "2"))
    done = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)
    # Keep each stream's line structure: a marker at the start of stderr is
    # still at the start of a line when stdout ends without a newline. Joining
    # the bytes directly would fuse the last stdout line with the first stderr
    # line and hide the marker. Terminal formatting is stripped here, once,
    # so every reader sees the plain text.
    output = ANSI.sub("", done.stdout + "\n" + done.stderr)
    if any(word in output for word in DISK_FULL):
        raise DiskFull("a command reported a full disk")
    return done.returncode, output


def harness_results(output):
    return [(status, int(passed), int(failed))
            for status, passed, failed in TEST_RESULT.findall(output)]


def harness_is_error_free(output):
    """True only when the output holds no loader or Cargo error marker, and
    no harness error marker outside a failed test's own captured section. A
    test body can print a fake FAILED summary, and a harness that fails to
    load the test prints no summary of its own, so any error marker makes
    every summary in that output untrustworthy. The text keeps its separators:
    a marker may end at a line break, and only the Cargo footer text and each
    failed test's own captured section are removed."""
    if LOADER_ERROR.search(output) or CARGO_FAILURE.search(output):
        return False
    output = OWN_FAILURE_TEXT.sub("", output)
    return not HARNESS_ERROR.search(TEST_FAILED.sub("", output))


def ran_and_failed(output):
    """True only when the harness evidence is error-free and a summary says
    one test ran and failed, with no other summary saying a test ran and
    passed. A test body can print a fake summary; the harness prints the real
    one after it, and a harness or loader error is never a catch."""
    results = harness_results(output)
    failed = any(status == "FAILED" and failed >= 1 and passed == 0
                 for status, passed, failed in results)
    returned = any(passed >= 1 for _status, passed, _failed in results)
    return failed and not returned and harness_is_error_free(output)


def evaluate(entry, how):
    """(build_failed, outcomes), from exit codes only. outcomes maps each named
    test to "failed", "passed" or "not run". Every expect mode, `survives`
    included, is proved by this same per-named-test rule; no mode reads the
    whole suite's exit code."""
    for argv, cwd in how["build"]:
        if run(argv, cwd)[0] != 0:
            return True, {}
    argv, cwd, extra = how["one"]
    outcomes = {}
    for name in entry["tests"]:
        if entry.get("command") == "selftest":
            # Each named case is its own process, so one case cannot carry a
            # verdict for another. The case counts only when the child exits
            # with its result AND prints the marker it writes after the case
            # returns. A loading error, an unknown name, or a signal is not run.
            code, output = run(argv + extra + ["--self-test-case", name], cwd)
            lines = output.splitlines()
            if code == CASE_PASSED and case_marker(name, "OK") in lines:
                outcomes[name] = "passed"
            elif code == CASE_FAILED and case_marker(name, "FAILED") in lines:
                outcomes[name] = "failed"
            else:
                outcomes[name] = "not run"
            continue
        # Exactly one test must answer to the name; the list is read for that
        # count only (a list run prints no test output).
        _, listed = run(argv + extra + ["--exact", name, "--list"], cwd)
        if [line for line in listed.splitlines() if line == f"{name}: test"] != [f"{name}: test"]:
            outcomes[name] = "not run"
            continue
        code, output = run(argv + extra + ["--exact", name, "--show-output"], cwd)
        if code == 0:
            ran = any(passed >= 1 for _status, passed, _failed in harness_results(output))
            outcomes[name] = "passed" if ran else "not run"
        elif ran_and_failed(output):
            outcomes[name] = "failed"
        else:
            outcomes[name] = "not run"
        if outcomes[name] == "passed" and SKIPPED_TEST.search(output):
            outcomes[name] = "not run"
    return False, outcomes


def verdict(entry, build_failed, outcomes):
    """(ok, word, detail): ok is whether the falsifier did what it expects."""
    expect = entry["expect"]
    if expect == "compile_error":
        return (True, "CAUGHT (does not build)", "") if build_failed else (False, "SURVIVED", "it builds")
    if build_failed:
        return False, "BUILD FAILED", "the mutation must build so its tests can fail"
    missing = [name for name in entry["tests"] if outcomes.get(name, "not run") == "not run"]
    if missing:
        return False, "NOT RUN", "did not run: " + ", ".join(missing)
    if not entry["tests"]:
        return False, "NOT RUN", "no named tests"
    failed = [name for name in entry["tests"] if outcomes.get(name) == "failed"]
    passed = [name for name in entry["tests"] if outcomes.get(name) == "passed"]
    if expect == "survives":
        if failed and passed:
            return (False, "NOT A SURVIVOR",
                    "failed: " + ", ".join(failed) + "; still pass: " + ", ".join(passed))
        if failed:
            return True, "CAUGHT (listed as a survivor)", ""
        return True, "SURVIVED (expected, by design)", ""
    if passed:
        return False, "SURVIVED", "still pass: " + ", ".join(passed)
    return True, "CAUGHT", ""


def falsify(entry, how=None):
    check_disk()
    with Mutation(entry):
        result = evaluate(entry, how or spec(entry["command"]))
    return verdict(entry, *result)


def reported(entry, how=None):
    """One falsifier's result. A data mismatch and a backup this run does not
    own each keep their own word and reason, so neither reads as a catch."""
    try:
        return falsify(entry, how)
    except LookupError as error:
        return False, "NO MATCH", str(error)
    except BackupCollision as error:
        return False, "BACKUP TAKEN", str(error)


def baseline(chosen, how_for):
    """(command -> (build_failed, outcomes)) from the unmutated tree, before
    any edit. Each chosen command is built once and each distinct named test
    runs once through evaluate(), the one per-named-test rule. A compile_error
    entry adds only its command's build."""
    check_disk()
    tests = {}
    for entry in chosen:
        names = tests.setdefault(entry["command"], set())
        if entry["expect"] in ("caught", "survives"):
            names.update(entry["tests"])
    return {command: evaluate({"command": command, "tests": sorted(names)},
                              how_for(command))
            for command, names in tests.items()}


def baseline_line(base, chosen):
    """One line for the run: how many distinct named-test pairs pass without
    an edit, and how many do not. A compile_error entry has no named test."""
    passed = not_passed = 0
    seen = set()
    for entry in chosen:
        if entry["expect"] not in ("caught", "survives"):
            continue
        build_failed, outcomes = base.get(entry["command"], (False, {}))
        for name in entry["tests"]:
            if (entry["command"], name) in seen:
                continue
            seen.add((entry["command"], name))
            if not build_failed and outcomes.get(name) == "passed":
                passed += 1
            else:
                not_passed += 1
    return f"baseline: {passed} named tests pass without an edit, {not_passed} do not"


def judged(entry, base, how_for):
    """One entry's result, held to the unmutated baseline first. An edit is
    evidence for a test only when that test passes without it: a test that
    fails, or cannot run, without the edit proves nothing (P11). The reason
    names each kind a named test showed; when both are present it names
    both. A command whose unmutated build fails proves nothing for any entry
    of it, compile_error included."""
    build_failed, outcomes = base.get(entry["command"], (False, {}))
    if build_failed:
        return False, "NOT RUN", "the unmutated build fails"
    if entry["expect"] != "compile_error":
        failed = [name for name in entry["tests"] if outcomes.get(name) == "failed"]
        missing = [name for name in entry["tests"]
                   if outcomes.get(name, "not run") == "not run"]
        reasons = []
        if failed:
            reasons.append("fails without the edit: " + ", ".join(failed))
        if missing:
            reasons.append("did not run without the edit: " + ", ".join(missing))
        if reasons:
            return False, "NOT RUN", "; ".join(reasons)
    return reported(entry, how_for(entry["command"]))


def judged_entries(chosen, base, how_for):
    """Yield each judgment lazily so run_chosen() can time its execution."""
    for entry in chosen:
        yield entry, judged(entry, base, how_for)


def run_chosen(chosen, how_for=None, on_baseline=None):
    """The one order for a run: the unmutated baseline for the chosen
    commands, then each entry's result. main() and the self-test cases use
    this same function, so a case never rebuilds the order by hand. The
    baseline finishes before the first edit, and on_baseline(line) runs
    between them. Yield each entry, result and execution duration; baseline
    work and time spent by the caller between entries have separate costs."""
    how_for = how_for or spec
    base = baseline(chosen, how_for)
    if on_baseline is not None:
        on_baseline(baseline_line(base, chosen))
    pending = judged_entries(chosen, base, how_for)
    for _ in chosen:
        start = time.monotonic()
        entry, result = next(pending)
        yield entry, result, time.monotonic() - start


REAL_CRATE = {
    "Cargo.toml": """[package]
name = "falsify_selftest"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]
""",
    "src/lib.rs": """#[cfg(test)]
mod tests {
    #[test]
    fn genuinely_passing() {
        println!("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out");
    }

    #[test]
    fn fails_with_a_fake_line() {
        panic!("\\ntest tests::genuinely_passing ... FAILED");
    }

    #[test]
    fn fails_plainly() {
        assert!(false, "planted failure");
    }
}
""",
}

# A test that fails with did's message shape: the panic quote carries a child's
# standard error on purpose, so the test names its own reason (P11).
PROVIDER_FAILURE_LIB_RS = """#[cfg(test)]
mod tests {
    #[test]
    fn fails_naming_standard_error() {
        panic!("provider did not answer request 7 (closed); child exit status: 1; standard error: planted-child: error: denied");
    }
}
"""

# A crate that cannot build: the baseline must refuse every entry of its
# command instead of crediting an edit that leaves it broken.
BROKEN_LIB_RS = "this is not Rust\n"

STUB_LIST_MISSING = """import sys
print("tests::some_other_test: test")
raise SystemExit(0)
"""

# The named test exists only after the edit: the baseline could not run it,
# while an accepted baseline would let the edited run report a failure.
STUB_LISTS_ONLY_WHEN_MUTATED = """import pathlib
import sys
mutated = pathlib.Path(__file__).with_name("mutable.txt").read_text(
    encoding="utf-8") == "mutated bytes\\n"
if "--list" in sys.argv:
    if mutated:
        print("tests::planted_check: test")
    raise SystemExit(0)
if mutated:
    print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
raise SystemExit(101 if mutated else 0)
"""

STUB_HARNESS_ERROR = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("error: could not load the test harness")
raise SystemExit(101)
"""

STUB_FILTERED_OUT = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out")
raise SystemExit(0)
"""

STUB_FAKE_SUMMARY_INDENTED_ERROR = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("  error: could not load the test harness")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_STDOUT_ERROR = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print("error: could not load the test harness")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_SPLIT_STREAMS = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
sys.stdout.write("partial output: ")
sys.stderr.write("error: could not load the test harness")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_DYLD_PID = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("dyld[1234]: Library not loaded: libmissing.dylib")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_PREFIXED_LOADER = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("/test-bin: error while loading shared libraries: libmissing.so: cannot open shared object file")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_PREFIXED_HARNESS = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("test-bin: error: could not load the test harness")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_COLORED_ERROR = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("\\x1b[31merror\\x1b[0m: could not load the test harness")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_FOOTER_THEN_ERROR = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("error: test failed, to rerun pass `--lib` error: could not load the test harness")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_SPLIT_ERROR = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("error:")
print("  could not load the test harness")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_CARGO_LAUNCH_FAILURE = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
sys.stderr.write(
    "error: test failed, to rerun pass `--lib`\\n\\n"
    "Caused by:\\n"
    "  could not execute process `test-bin` (never executed)\\n\\n"
    "Caused by:\\n"
    "    No such file or directory (os error 2)\\n")
raise SystemExit(101)
"""

STUB_FAKE_SUMMARY_CARGO_CRASH = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
sys.stderr.write(
    "error: test failed, to rerun pass `--lib`\\n\\n"
    "Caused by:\\n"
    "  process didn't exit successfully: `/tmp/test-bin` (signal: 11, SIGSEGV)\\n")
raise SystemExit(101)
"""

STUB_OWN_TEXT_THEN_HARNESS_ERROR = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print()
print("failures:")
print()
print("---- tests::planted_check stdout ----")
print("standard error: x")
print("failures:")
print("    tests::planted_check")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("error: could not load the test harness")
raise SystemExit(101)
"""

STUB_LOADER_ERROR_IN_SECTION = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print()
print("failures:")
print()
print("---- tests::planted_check stdout ----")
print("standard error: dyld[1]: Library not loaded: x")
print("failures:")
print("    tests::planted_check")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
raise SystemExit(101)
"""

STUB_CARGO_FAILURE_IN_SECTION = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print()
print("failures:")
print()
print("---- tests::planted_check stdout ----")
print("standard error: process didn't exit successfully: planted-child")
print("failures:")
print("    tests::planted_check")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
raise SystemExit(101)
"""

STUB_UNTERMINATED_SECTION = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
print("running 1 test")
print("test tests::planted_check ... FAILED")
print()
print("failures:")
print()
print("---- tests::planted_check stdout ----")
print("standard error: x")
raise SystemExit(101)
"""

STUB_INDENTED_SECTION = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print()
print("failures:")
print()
print("  ---- tests::planted_check stdout ----")
print("  standard error: x")
print("failures:")
print("    tests::planted_check")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
raise SystemExit(101)
"""

STUB_HEADER_TRAILING_TEXT = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print()
print("failures:")
print()
print("---- tests::planted_check stdout ---- extra")
print("standard error: x")
print("failures:")
print("    tests::planted_check")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
raise SystemExit(101)
"""

STUB_MIDLINE_DELIMITER = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print()
print("failures:")
print()
print("---- tests::planted_check stdout ----")
print("note: see failures:")
print("standard error: x")
print("failures:")
print("    tests::planted_check")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
raise SystemExit(101)
"""

STUB_TRAILING_TEXT_DELIMITER = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print()
print("failures:")
print()
print("---- tests::planted_check stdout ----")
print("failures: note")
print("standard error: x")
print("failures:")
print("    tests::planted_check")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
raise SystemExit(101)
"""

STUB_TWO_DELIMITERS = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print()
print("failures:")
print()
print("---- tests::planted_check stdout ----")
print("first line")
print("failures:")
print("error: could not load the test harness")
print("failures:")
print("    tests::planted_check")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
raise SystemExit(101)
"""

STUB_TWO_SECTIONS = """import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... FAILED")
print()
print("failures:")
print()
print("---- tests::planted_check stdout ----")
print("standard error: first")
print("failures:")
print("    tests::planted_check")
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out")
sys.stderr.write(
    "\\n---- tests::planted_check stdout ----\\n"
    "standard error: second\\n"
    "failures:\\n")
raise SystemExit(101)
"""

STUB_SURVIVOR_RAN = """import sys
if "--exact" in sys.argv:
    if "--list" in sys.argv:
        print("tests::planted_check: test")
        raise SystemExit(0)
    print("running 1 test")
    print("test tests::planted_check ... ok")
    print()
    print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out")
    raise SystemExit(0)
print("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out")
raise SystemExit(101)
"""

# A passing test that printed a `SKIP ` line did not run its check. libtest
# prints the test's own output only with --show-output, so the stub prints its
# success block only when that flag is present. skip.txt holds the line the
# test printed there, and an empty file is the same run with no skip line.
STUB_PASSING_SKIP = """import pathlib
import sys
if "--list" in sys.argv:
    print("tests::planted_check: test")
    raise SystemExit(0)
print("running 1 test")
print("test tests::planted_check ... ok")
print()
if "--show-output" in sys.argv:
    print("successes:")
    print("---- tests::planted_check stdout ----")
    skip = pathlib.Path(__file__).with_name("skip.txt")
    line = skip.read_text(encoding="utf-8").strip()
    if line:
        print(line)
    print()
    print("successes:")
    print("    tests::planted_check")
print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out")
raise SystemExit(0)
"""

STUB_SPLIT_STREAMS = """import sys
sys.stdout.write("partial output: ")
sys.stderr.write("error: could not load the test harness")
raise SystemExit(101)
"""

STUB_CASE_RAN_FAILED = """import sys
name = sys.argv[sys.argv.index('--self-test-case') + 1]
print(f"self-test case {name!r}: FAILED")
raise SystemExit(1)
"""

STUB_CASE_RAN_PASSED = """import sys
name = sys.argv[sys.argv.index('--self-test-case') + 1]
print(f"self-test case {name!r}: OK")
raise SystemExit(0)
"""

STUB_CASE_LOADING_ERROR = """import sys
print("Traceback (most recent call last):")
print("RuntimeError: the case module did not load")
raise SystemExit(1)
"""

STUB_CASE_SIGNAL = """import os
import signal
os.kill(os.getpid(), signal.SIGTERM)
"""

INTERRUPTION_ENTRY = {
    "id": "ST",
    "command": "host",
    "expect": "caught",
    "edits": [{"file": "interrupted.txt", "old": "original bytes", "new": "mutated bytes"}],
    "tests": [],
}


def verdict_cases():
    """The verdict logic truth table."""
    ok = True
    two = {"id": "ST", "expect": "caught", "tests": ["a", "b"]}
    cases = [
        ((two, False, {"a": "failed", "b": "passed"}), (False, "SURVIVED")),
        ((two, False, {"a": "failed", "b": "failed"}), (True, "CAUGHT")),
        ((two, False, {"a": "failed", "b": "not run"}), (False, "NOT RUN")),
        ((two, True, {}), (False, "BUILD FAILED")),
        (({"id": "ST", "expect": "survives", "tests": ["a"]}, False, {"a": "passed"}),
         (True, "SURVIVED (expected, by design)")),
        (({"id": "ST", "expect": "survives", "tests": ["a"]}, False, {"a": "not run"}),
         (False, "NOT RUN")),
        (({"id": "ST", "expect": "survives", "tests": ["a"]}, False, {"a": "failed"}),
         (True, "CAUGHT (listed as a survivor)")),
        (({"id": "ST", "expect": "survives", "tests": ["a", "b"]},
          False, {"a": "failed", "b": "passed"}), (False, "NOT A SURVIVOR")),
        (({"id": "ST", "expect": "survives", "tests": []}, False, {}), (False, "NOT RUN")),
        (({"id": "ST", "expect": "compile_error", "tests": []}, False, {}), (False, "SURVIVED")),
    ]
    for args, want in cases:
        got = verdict(*args)[:2]
        if got != want:
            print(f"self-test: verdict {args[1:]} -> {got}, want {want}")
            ok = False
    return ok


def a_named_test_that_does_not_run_is_not_a_catch():
    """Two planted failures: no test answers to the name, and a harness
    error exits non-zero without running one. Neither is a catch (task 004)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        entry = {"id": "ST", "command": "host", "expect": "caught", "tests": ["tests::planted_check"]}
        for title, text in (("name is not listed", STUB_LIST_MISSING),
                            ("harness error", STUB_HARNESS_ERROR),
                            ("exit 0 but no test ran", STUB_FILTERED_OUT),
                            ("fake summary with an indented error",
                             STUB_FAKE_SUMMARY_INDENTED_ERROR),
                            ("fake summary with an error on stdout",
                             STUB_FAKE_SUMMARY_STDOUT_ERROR),
                            ("fake summary then an error across the stream boundary",
                             STUB_FAKE_SUMMARY_SPLIT_STREAMS),
                            ("fake summary with a dyld process id error",
                             STUB_FAKE_SUMMARY_DYLD_PID),
                            ("fake summary with a prefixed loader error",
                             STUB_FAKE_SUMMARY_PREFIXED_LOADER),
                            ("fake summary with a prefixed harness error",
                             STUB_FAKE_SUMMARY_PREFIXED_HARNESS),
                            ("fake summary with a colored error label",
                             STUB_FAKE_SUMMARY_COLORED_ERROR),
                            ("fake summary with an error after the cargo footer",
                             STUB_FAKE_SUMMARY_FOOTER_THEN_ERROR),
                            ("fake summary with an error split after its colon",
                             STUB_FAKE_SUMMARY_SPLIT_ERROR),
                            ("fake summary with a cargo launch failure",
                             STUB_FAKE_SUMMARY_CARGO_LAUNCH_FAILURE),
                            ("fake summary with an abnormal test-process exit",
                             STUB_FAKE_SUMMARY_CARGO_CRASH),
                            ("a failure section then a harness error after it",
                             STUB_OWN_TEXT_THEN_HARNESS_ERROR)):
            stub = SELF_TEST_DIR / "stub.py"
            stub.write_text(text, encoding="utf-8")
            how = {"build": [], "one": (["python3", "-I", str(stub)], SELF_TEST_DIR, [])}
            got = verdict(entry, *evaluate(entry, how))
            print(f"self-test: {title}: {got[1]} ({got[2]})")
            if got[:2] != (False, "NOT RUN"):
                ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_passing_test_that_prints_a_skip_line_is_not_run():
    """A test that exits 0 with a passing summary but printed a `SKIP ` line
    did not run its check, so it is NOT RUN: never a pass and never a catch,
    and a `survives` entry cannot read as a survivor (task 050). The control
    is the same stub with no skip line, which still reads as passed."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        stub = SELF_TEST_DIR / "stub.py"
        stub.write_text(STUB_PASSING_SKIP, encoding="utf-8")
        how = {"build": [], "one": (["python3", "-I", str(stub)], SELF_TEST_DIR, [])}
        for title, skip_line, want in (
                ("a passing test with a skip line", "SKIP planted: off this host",
                 (False, "NOT RUN")),
                ("a passing test with no skip line", "", (False, "SURVIVED"))):
            (SELF_TEST_DIR / "skip.txt").write_text(skip_line, encoding="utf-8")
            entry = {"id": "ST", "command": "host", "expect": "caught",
                     "tests": ["tests::planted_check"]}
            build_failed, outcomes = evaluate(entry, how)
            got = verdict(entry, build_failed, outcomes)
            outcome = outcomes["tests::planted_check"]
            print(f"self-test: {title}: {outcome}, {got[1]} ({got[2]})")
            if outcome != ("not run" if skip_line else "passed") or got[:2] != want:
                ok = False
        (SELF_TEST_DIR / "skip.txt").write_text("SKIP planted: off this host",
                                                encoding="utf-8")
        entry = {"id": "ST", "command": "host", "expect": "survives",
                 "tests": ["tests::planted_check"]}
        got = verdict(entry, *evaluate(entry, how))
        print(f"self-test: a survivor over a skip line: {got[1]} ({got[2]})")
        if got[:2] != (False, "NOT RUN"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def stub_verdict(text):
    """The verdict for one stub's output, run as one named test. The stub
    answers --list with the name and then prints its planted output."""
    stub = SELF_TEST_DIR / "stub.py"
    stub.write_text(text, encoding="utf-8")
    entry = {"id": "ST", "command": "host", "expect": "caught",
             "tests": ["tests::planted_check"]}
    how = {"build": [], "one": (["python3", "-I", str(stub)], SELF_TEST_DIR, [])}
    return verdict(entry, *evaluate(entry, how))


def an_unterminated_failure_section_stays_checked():
    """A section with no later `failures:` line is not the harness's framing,
    so its text stays checked (task 019). The stub prints its summary before
    the section, so a removal that accepts the end of the output as a closing
    delimiter would hide that text and read CAUGHT."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        got = stub_verdict(STUB_UNTERMINATED_SECTION)
        print(f"self-test: an unterminated failure section: {got[1]} ({got[2]})")
        if got[:2] != (False, "NOT RUN"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def section_header_is_an_exact_line():
    """A section starts only at a line that is exactly
    `---- NAME stdout ----`. An indented line with those words, or a line
    with text after them, is the test's own text, so its `standard error:`
    stays checked (tasks 019 and 020)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        for title, text in (
                ("an indented section header", STUB_INDENTED_SECTION),
                ("trailing text after the section header",
                 STUB_HEADER_TRAILING_TEXT)):
            got = stub_verdict(text)
            print(f"self-test: {title}: {got[1]} ({got[2]})")
            if got[:2] != (False, "NOT RUN"):
                ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def closing_delimiter_is_an_exact_line():
    """A section ends only at a line that is exactly `failures:`. A line that
    merely contains or extends those words is the test's own text, so the
    section still runs to the exact line and its text is removed (task 019)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        for title, text in (
                ("a delimiter inside the section text", STUB_MIDLINE_DELIMITER),
                ("trailing text after the delimiter", STUB_TRAILING_TEXT_DELIMITER)):
            got = stub_verdict(text)
            print(f"self-test: {title}: {got[1]} ({got[2]})")
            if got[:2] != (True, "CAUGHT"):
                ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_section_stops_at_its_first_delimiter():
    """The section ends at the first `failures:` line after its header, so a
    later one cannot hide a harness error (task 019)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        got = stub_verdict(STUB_TWO_DELIMITERS)
        print(f"self-test: a section stops at its first delimiter: {got[1]} ({got[2]})")
        if got[:2] != (False, "NOT RUN"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def every_failure_section_is_removed():
    """Every failed test's captured section is removed, not only the first
    (task 019). libtest closes its own section with one `failures:` line; the
    stub adds a second section on stderr, which libtest does not capture and
    the runner joins after that line."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        got = stub_verdict(STUB_TWO_SECTIONS)
        print(f"self-test: every failure section: {got[1]} ({got[2]})")
        if got[:2] != (True, "CAUGHT"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_loader_error_inside_a_section_is_not_a_catch():
    """A loader error inside a failed test's own captured section is still a
    loader error: the loader check reads the output before the section is
    removed, so a child that failed to load is NOT RUN, never a catch
    (task 020)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        got = stub_verdict(STUB_LOADER_ERROR_IN_SECTION)
        print(f"self-test: a loader error inside a section: {got[1]} ({got[2]})")
        if got[:2] != (False, "NOT RUN"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_cargo_failure_inside_a_section_is_not_a_catch():
    """A Cargo failure inside a failed test's own captured section is still a
    Cargo failure: the Cargo check reads the output before the section is
    removed, so a test process that never ran is NOT RUN, never a catch
    (task 020)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        got = stub_verdict(STUB_CARGO_FAILURE_IN_SECTION)
        print(f"self-test: a cargo failure inside a section: {got[1]} ({got[2]})")
        if got[:2] != (False, "NOT RUN"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def interruption_restores():
    """Ctrl-C or SIGTERM right after a replacement: the original comes back
    before the interruption goes on (task 004)."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
    path = SELF_TEST_DIR / "interrupted.txt"
    original = "original bytes\n"
    path.write_text(original, encoding="utf-8")
    real_replace = os.replace
    replaced = []

    def replace_then_interrupt(src, dst):
        real_replace(src, dst)
        replaced.append(dst)
        if len(replaced) == 1:
            raise KeyboardInterrupt

    os.replace = replace_then_interrupt
    interrupted = False
    try:
        with Mutation(INTERRUPTION_ENTRY, SELF_TEST_DIR):
            pass
    except KeyboardInterrupt:
        interrupted = True
    finally:
        os.replace = real_replace
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    restored = path.read_text(encoding="utf-8") == original
    print(f"self-test: interruption during replacement: raised={interrupted}, "
          f"restored={restored}, backup left={backup.exists()}")
    return interrupted and restored and not backup.exists()


def real_catch_counts():
    """A real catch still counts when every named test runs and fails, and a
    passing test beside them is SURVIVED. A fake FAILED line in a panic does
    not change either verdict."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        for name, text in REAL_CRATE.items():
            path = SELF_TEST_DIR / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        how = spec("host", SELF_TEST_DIR / "Cargo.toml", ("--offline",))
        entry = {"id": "ST", "command": "host", "expect": "caught",
                 "tests": ["tests::fails_with_a_fake_line", "tests::fails_plainly"]}
        got = verdict(entry, *evaluate(entry, how))
        print(f"self-test: every named test runs and fails: {got[1]} ({got[2]})")
        if got[:2] != (True, "CAUGHT"):
            ok = False
        beside = {"id": "ST", "command": "host", "expect": "caught",
                  "tests": ["tests::genuinely_passing", "tests::fails_plainly"]}
        got = verdict(beside, *evaluate(beside, how))
        print(f"self-test: a passing test beside a failing one: {got[1]} ({got[2]})")
        if got[:2] != (False, "SURVIVED") or "tests::genuinely_passing" not in got[2]:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def provider_failure_with_stderr_counts():
    """A failed test whose own section quotes a child's standard error is a
    catch: the text in the section is the test's, not a harness error
    (task 019)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        (SELF_TEST_DIR / "src").mkdir(parents=True, exist_ok=True)
        (SELF_TEST_DIR / "Cargo.toml").write_text(REAL_CRATE["Cargo.toml"], encoding="utf-8")
        (SELF_TEST_DIR / "src" / "lib.rs").write_text(PROVIDER_FAILURE_LIB_RS, encoding="utf-8")
        how = spec("host", SELF_TEST_DIR / "Cargo.toml", ("--offline",))
        entry = {"id": "ST", "command": "host", "expect": "caught",
                 "tests": ["tests::fails_naming_standard_error"]}
        got = verdict(entry, *evaluate(entry, how))
        print(f"self-test: a provider failure with stderr counts: {got[1]} ({got[2]})")
        if got[:2] != (True, "CAUGHT"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def real_crate():
    """Write REAL_CRATE under SELF_TEST_DIR and return its host spec."""
    for name, text in REAL_CRATE.items():
        path = SELF_TEST_DIR / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return spec("host", SELF_TEST_DIR / "Cargo.toml", ("--offline",))


def a_test_that_fails_without_the_edit_is_not_a_catch():
    """A named test that already fails without the edit proves nothing: the
    entry reads NOT RUN with that reason and no edit is applied. Original
    bytes and an absent backup also hold after an applied and restored edit,
    so this case also asserts Mutation is never entered (task 024)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        how = real_crate()
        path = SELF_TEST_DIR / "harmless.txt"
        original = "original bytes\n"
        path.write_text(original, encoding="utf-8")
        entry = {"id": "ST", "command": "host", "expect": "caught",
                 "edits": [{"file": "harmless.txt", "old": "original bytes",
                            "new": "mutated bytes"}],
                 "tests": ["tests::fails_plainly"]}
        entered = []
        real_mutation = Mutation

        def recording_mutation(item, base=HERE):
            entered.append(item["id"])
            return real_mutation(item, base)

        with mock.patch.dict(globals(),
                             Mutation=lambda item: recording_mutation(item, SELF_TEST_DIR)):
            got = list(run_chosen([entry], how_for=lambda _command: how))[0][1]
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        kept = path.read_text(encoding="utf-8") == original
        print(f"self-test: a test that fails without the edit: {got[1]} ({got[2]}); "
              f"entered={entered}, bytes kept={kept}, backup left={backup.exists()}")
        reason = "fails without the edit: tests::fails_plainly"
        if got != (False, "NOT RUN", reason):
            ok = False
        if entered or not kept or backup.exists():
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_test_that_passes_without_the_edit_still_counts():
    """The edit makes a test that passes without it panic: that is a catch,
    and the baseline must not hide it (task 024)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        how = real_crate()
        entry = {"id": "ST", "command": "host", "expect": "caught",
                 "edits": [{
                     "file": "src/lib.rs",
                     "old": '        println!("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out");',
                     "new": '        panic!("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out");',
                 }],
                 "tests": ["tests::genuinely_passing"]}
        real_mutation = Mutation
        with mock.patch.dict(globals(),
                             Mutation=lambda item: real_mutation(item, SELF_TEST_DIR)):
            got = list(run_chosen([entry], how_for=lambda _command: how))[0][1]
        print(f"self-test: a test that passes without the edit: {got[1]} ({got[2]})")
        if got[:2] != (True, "CAUGHT"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def an_unmutated_build_failure_is_not_a_catch():
    """A command whose unmutated build fails is refused for every entry of
    it, compile_error included: an edit that leaves it broken is no catch
    (task 024)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        (SELF_TEST_DIR / "src").mkdir(parents=True, exist_ok=True)
        (SELF_TEST_DIR / "Cargo.toml").write_text(REAL_CRATE["Cargo.toml"], encoding="utf-8")
        (SELF_TEST_DIR / "src" / "lib.rs").write_text(BROKEN_LIB_RS, encoding="utf-8")
        entry = {"id": "ST", "command": "host", "expect": "compile_error",
                 "edits": [{"file": "src/lib.rs", "old": "this is not Rust",
                            "new": "this is still not Rust"}],
                 "tests": []}
        how = spec("host", SELF_TEST_DIR / "Cargo.toml", ("--offline",))
        real_mutation = Mutation
        with mock.patch.dict(globals(),
                             Mutation=lambda item: real_mutation(item, SELF_TEST_DIR)):
            got = list(run_chosen([entry], how_for=lambda _command: how))[0][1]
        print(f"self-test: an unmutated build failure: {got[1]} ({got[2]})")
        if got != (False, "NOT RUN", "the unmutated build fails"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_baseline_test_that_cannot_run_is_refused():
    """A named test the baseline could not run is not evidence: the entry
    reads NOT RUN with that reason, never a catch (task 024)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        (SELF_TEST_DIR / "mutable.txt").write_text("original bytes\n", encoding="utf-8")
        stub = SELF_TEST_DIR / "stub.py"
        stub.write_text(STUB_LISTS_ONLY_WHEN_MUTATED, encoding="utf-8")
        how = {"build": [], "one": (["python3", "-I", str(stub)], SELF_TEST_DIR, [])}
        entry = {"id": "ST", "command": "host", "expect": "caught",
                 "edits": [{"file": "mutable.txt", "old": "original bytes",
                            "new": "mutated bytes"}],
                 "tests": ["tests::planted_check"]}
        real_mutation = Mutation
        with mock.patch.dict(globals(),
                             Mutation=lambda item: real_mutation(item, SELF_TEST_DIR)):
            got = list(run_chosen([entry], how_for=lambda _command: how))[0][1]
        print(f"self-test: a baseline test that cannot run: {got[1]} ({got[2]})")
        if got != (False, "NOT RUN",
                   "did not run without the edit: tests::planted_check"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_survivor_requires_a_passing_baseline():
    """A survives entry needs the same passing baseline as a catch: a test
    that fails without the edit is NOT RUN, never CAUGHT, and one the baseline
    could not run is NOT RUN with that reason, never SURVIVED (task 024)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        how = real_crate()
        failed = {"id": "ST", "command": "host", "expect": "survives",
                  "edits": [], "tests": ["tests::fails_plainly"]}
        got = list(run_chosen([failed], how_for=lambda _command: how))[0][1]
        print(f"self-test: survivor with a failing baseline: {got[1]} ({got[2]})")
        if got != (False, "NOT RUN", "fails without the edit: tests::fails_plainly"):
            ok = False
        stub = SELF_TEST_DIR / "stub.py"
        stub.write_text(STUB_LIST_MISSING, encoding="utf-8")
        stub_how = {"build": [], "one": (["python3", "-I", str(stub)], SELF_TEST_DIR, [])}
        missing = {"id": "ST", "command": "host", "expect": "survives",
                   "edits": [], "tests": ["tests::planted_check"]}
        got = list(run_chosen([missing], how_for=lambda _command: stub_how))[0][1]
        print(f"self-test: survivor with a baseline that did not run: {got[1]} ({got[2]})")
        if got != (False, "NOT RUN",
                   "did not run without the edit: tests::planted_check"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def the_with_repo_check_holds_its_entries_to_the_baseline():
    """The with-repo check runs both of its entries through one run_chosen()
    call, so both share the unmutated baseline: a named test that already
    fails without the edit reads NOT RUN with that reason, never CAUGHT, and
    no edit is applied (task 047)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        how = real_crate()
        path = SELF_TEST_DIR / "harmless.txt"
        path.write_text("original bytes\n", encoding="utf-8")
        entry = {"id": "ST", "command": "host", "expect": "caught",
                 "edits": [{"file": "harmless.txt", "old": "original bytes",
                            "new": "mutated bytes"}],
                 "tests": ["tests::fails_plainly"]}
        entered = []
        printed = []
        calls = []
        results = []
        real_mutation = Mutation
        real_run_chosen = run_chosen

        def recording_mutation(item, base=HERE):
            entered.append(item["id"])
            return real_mutation(item, base)

        def recording_run_chosen(chosen, how_for=None, on_baseline=None):
            calls.append([list(item["tests"]) for item in chosen])
            for item in real_run_chosen(chosen, how_for=how_for, on_baseline=on_baseline):
                results.append(item)
                yield item

        with mock.patch.dict(globals(),
                             Mutation=lambda item: recording_mutation(item, SELF_TEST_DIR),
                             run_chosen=recording_run_chosen), \
             mock.patch("builtins.print", side_effect=printed.append):
            got_ok = with_repo_check([entry], still_passing="tests::genuinely_passing",
                                     how_for=lambda _command: how)
        listed = results[1][1] if len(results) == 2 else None
        print(f"self-test: the with-repo check: {printed[-1] if printed else 'no line'}"
              f"{f'; listed reason={listed[2]!r}' if listed else ''}; entered={entered}")
        if got_ok:
            ok = False
        if entered:
            ok = False
        if calls != [[["tests::fails_plainly", "tests::genuinely_passing"],
                      ["tests::fails_plainly"]]]:
            ok = False
        if listed != (False, "NOT RUN", "fails without the edit: tests::fails_plainly"):
            ok = False
        if printed != [
                "self-test: ST with tests::genuinely_passing added -> "
                "NOT RUN (fails without the edit: tests::fails_plainly)",
                "self-test: ST as listed -> NOT RUN"]:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_baseline_reason_names_failed_and_missing_tests():
    """When one named test fails without the edit and another cannot run
    there, the NOT RUN reason names both kinds (task 047)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        how = real_crate()
        entry = {"id": "ST", "command": "host", "expect": "caught", "edits": [],
                 "tests": ["tests::fails_plainly", "tests::absent_test"]}
        real_mutation = Mutation
        with mock.patch.dict(globals(),
                             Mutation=lambda item: real_mutation(item, SELF_TEST_DIR)):
            got = list(run_chosen([entry], how_for=lambda _command: how))[0][1]
        reason = ("fails without the edit: tests::fails_plainly; "
                  "did not run without the edit: tests::absent_test")
        print(f"self-test: a baseline reason with both kinds: {got[1]} ({got[2]})")
        if got != (False, "NOT RUN", reason):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def baseline_batches_chosen_pairs_before_edits():
    """The baseline runs each distinct (command, named test) pair once, one
    evaluate() call per command, and finishes before the first edit. A
    compile_error entry adds only its command (task 024)."""
    ok = True
    calls = []
    events = []
    mutated = []
    entries = [
        {"id": "ST1", "command": "one", "expect": "caught",
         "tests": ["x", "y"], "edits": []},
        {"id": "ST2", "command": "one", "expect": "survives",
         "tests": ["y", "z"], "edits": []},
        {"id": "ST3", "command": "two", "expect": "caught",
         "tests": ["x"], "edits": []},
        {"id": "ST4", "command": "one", "expect": "compile_error",
         "tests": [], "edits": []},
    ]

    class FakeMutation:
        def __init__(self, item, base=HERE):
            self.item = item

        def __enter__(self):
            mutated.append(self.item["id"])
            events.append("mutate " + self.item["id"])
            return self

        def __exit__(self, *_):
            events.append("restore " + self.item["id"])
            mutated.pop()
            return False

    def fake_evaluate(item, _how):
        if mutated:
            events.append("edited " + item["command"])
            if item.get("expect") == "compile_error":
                return True, {}
            return False, {name: "failed" for name in item["tests"]}
        events.append("baseline " + item["command"])
        calls.append((item["command"], list(item["tests"])))
        return False, {name: "passed" for name in item["tests"]}

    lines = []
    with mock.patch.dict(globals(), evaluate=fake_evaluate, Mutation=FakeMutation):
        results = list(run_chosen(
            entries, how_for=lambda _command: {"build": [], "one": ([], REPO, [])},
            on_baseline=lines.append))
    first_edit = next((at for at, event in enumerate(events)
                       if event.startswith("mutate")), len(events))
    last_baseline = max((at for at, event in enumerate(events)
                         if event.startswith("baseline")), default=-1)
    words = [got[1] for _entry, got, _duration in results]
    print(f"self-test: baseline batches chosen pairs: calls={calls}, lines={lines}, "
          f"baseline before edits={last_baseline < first_edit}, words={words}")
    if calls != [("one", ["x", "y", "z"]), ("two", ["x"])]:
        ok = False
    if lines != ["baseline: 4 named tests pass without an edit, 0 do not"]:
        ok = False
    if first_edit <= last_baseline:
        ok = False
    if words != ["CAUGHT", "CAUGHT (listed as a survivor)", "CAUGHT",
                 "CAUGHT (does not build)"]:
        ok = False
    return ok


def baseline_checks_free_space_before_building():
    """The baseline checks free space before it builds or runs anything
    (task 024)."""
    built = []

    def no_space():
        raise DiskFull("planted full disk")

    def fake_evaluate(item, _how):
        built.append(item["command"])
        return False, {}

    entry = {"id": "ST", "command": "host", "expect": "caught",
             "tests": ["tests::x"], "edits": []}
    raised = False
    with mock.patch.dict(globals(), check_disk=no_space, evaluate=fake_evaluate):
        try:
            list(run_chosen([entry]))
        except DiskFull:
            raised = True
    print(f"self-test: baseline disk check: raised={raised}, built={built}")
    return raised and not built


def entry_durations_include_execution():
    """Printed durations cover each entry's work, with baseline and output
    time excluded. A refused entry keeps its own duration too."""
    clock = [0.0]
    entries = [
        {"id": "ST1", "command": "host", "expect": "caught",
         "tests": ["ready"], "edits": [], "title": "first entry"},
        {"id": "ST2", "command": "host", "expect": "caught",
         "tests": ["ready"], "edits": [], "title": "second entry"},
        {"id": "ST3", "command": "host", "expect": "caught",
         "tests": ["blocked"], "edits": [], "title": "refused entry"},
    ]

    def fake_evaluate(_entry, _how):
        clock[0] += 11
        return False, {"ready": "passed", "blocked": "failed"}

    def fake_reported(entry, _how):
        clock[0] += {"ST1": 5, "ST2": 7}[entry["id"]]
        return True, "CAUGHT", ""

    class SlowOutput(io.StringIO):
        def write(self, text):
            clock[0] += 100
            return super().write(text)

    output = SlowOutput()
    with mock.patch.dict(globals(), load=lambda _path: entries,
                         evaluate=fake_evaluate, reported=fake_reported,
                         check_disk=lambda: None), \
            mock.patch.object(time, "monotonic", side_effect=lambda: clock[0]), \
            contextlib.redirect_stdout(output):
        code = main(["ST", "--keep-backups"])
    printed = output.getvalue()
    durations = re.findall(r"^(ST[123])\s+.+?\s+(\d+)s  ", printed, re.MULTILINE)
    print(f"self-test: entry durations include execution: {durations}")
    return (code == 1 and durations == [("ST1", "5"), ("ST2", "7"), ("ST3", "0")]
            and "summary: 2 CAUGHT, 1 NOT RUN of 3\n" in printed
            and "fails without the edit: blocked\n" in printed)


def interruption_at_the_end_of_the_edit():
    """An interrupt after the last replacement but before __enter__ returns:
    the original still comes back (task 004, review finding 2)."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
    path = SELF_TEST_DIR / "boundary.txt"
    original = "original bytes\n"
    path.write_text(original, encoding="utf-8")
    lines, start = inspect.getsourcelines(Mutation.__enter__)
    at = next(start + offset for offset, line in enumerate(lines) if line.strip() == "return self")
    entered = []

    def trace(frame, event, _arg):
        if frame.f_code is Mutation.__enter__.__code__:
            if event == "call":
                entered.append(frame)
            elif event == "line" and frame.f_lineno == at and len(entered) == 1:
                entered.append(frame)
                raise KeyboardInterrupt
        return trace

    entry = {"id": "ST", "command": "host", "expect": "caught",
             "edits": [{"file": "boundary.txt", "old": "original bytes", "new": "mutated bytes"}],
             "tests": []}
    interrupted = False
    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        with Mutation(entry, SELF_TEST_DIR):
            pass
    except KeyboardInterrupt:
        interrupted = True
    finally:
        sys.settrace(previous)
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    restored = path.read_text(encoding="utf-8") == original
    print(f"self-test: interruption at the end of the edit: raised={interrupted}, "
          f"restored={restored}, backup left={backup.exists()}")
    return interrupted and restored and not backup.exists()


def another_lanes_backup_is_not_recovered():
    """Recovery keeps foreign backups, including a neighbour of MP01's
    source file. The runner owns that exact provider target."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        repo = SELF_TEST_DIR / "lanes"
        here = repo / "examples" / "agent-host"
        here.mkdir(parents=True)
        data = here / "falsifiers.json"
        data.write_text('{"falsifiers": []}', encoding="utf-8")
        owned = here / "owned.txt"
        foreign = repo / "capsules" / "wallet-provider" / "src" / "lib.rs"
        foreign.parent.mkdir(parents=True)
        neighbour = repo / "capsules" / "model-provider" / "src" / "lib.rs"
        neighbour.parent.mkdir(parents=True)
        for target in (owned, foreign, neighbour):
            target.write_text("mutated bytes\n", encoding="utf-8")
            target.with_name(target.name + BACKUP_SUFFIX).write_text(
                "original bytes\n", encoding="utf-8")
        saved = HERE, REPO, DATA, SELF_TEST_DIR
        globals().update(HERE=here, REPO=repo, DATA=data,
                         SELF_TEST_DIR=repo / "self-test")
        try:
            code = main(["--from", str(data), "--list"])
        finally:
            globals().update(HERE=saved[0], REPO=saved[1], DATA=saved[2],
                             SELF_TEST_DIR=saved[3])
        owned_restored = (owned.read_text() == "original bytes\n"
                          and not owned.with_name(owned.name + BACKUP_SUFFIX).exists())
        foreign_kept = (foreign.read_text() == "mutated bytes\n"
                        and foreign.with_name(foreign.name + BACKUP_SUFFIX).exists())
        neighbour_kept = (neighbour.read_text() == "mutated bytes\n"
                          and neighbour.with_name(neighbour.name + BACKUP_SUFFIX).read_text()
                          == "original bytes\n")
        print(f"self-test: another lane's backup on restart: exit={code}, "
              f"owned restored={owned_restored}, foreign kept={foreign_kept}")
        if code != 0 or not owned_restored or not foreign_kept:
            ok = False
        if not neighbour_kept:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_killed_provider_edit_is_recovered():
    """Kill real and synthetic provider edits in an isolated tree, restart
    through main(), and repeat the edit. This lane's model-provider targets,
    the model provider's confinement test harness, the confine lane's five
    did/wallet targets plus its did confinement test harness and wallet's
    falsifier honesty test, capsule-identity's .gitignore, README.md,
    src/lib.rs, tests/common/mod.rs and fixtures/wc001-core/capsule.json, and
    the wasm lab's .gitignore, README.md, LOG.md, capsule/capsule.json,
    capsule/src/lib.rs, tests/common/build.rs, tests/lab_cid.rs,
    tests/verify.rs, tools/build, tools/src/bin/bundle.rs,
    tools/src/bundle.rs, tools/src/lib.rs, tools/src/receipt.rs,
    tools/src/run.rs, tools/src/verify.rs, tools/src/lab_name.rs and audit
    Cargo.toml, INTERFACE.md and src/lib.rs, and agent-conformance's 19 edit
    targets all come back in either startup mode. Foreign backups, including
    both providers' confinement documents, each harness's support neighbour,
    wallet's test support neighbour, the labs' adoption note, gap report and
    web-app fixture, the lab's tools manifest and a tools/src neighbour, stay
    with their owners."""
    owned = {entry["id"]: entry
             for entry in load(REPO / "capsules/model-provider/falsifiers.json")
             if entry["id"] in ("MP01", "MP02", "MP05", "MP12", "MP15", "MP16",
                                "MP23")}
    profile = "../../capsules/model-provider/confine.sb"
    # The did and wallet targets, both confinement test harnesses, wallet's
    # falsifier honesty test, capsule-identity's .gitignore, README.md,
    # src/lib.rs, tests/common/mod.rs and fixtures/wc001-core/capsule.json,
    # the wasm lab's edit and run-log files, and agent-conformance's 19 edit
    # targets are named here, not read from the table, so a target dropped
    # from PROVIDER_TARGETS is caught. Their original bytes are written in the
    # isolated tree, never read from the real lab or crates.
    synthetic = ("../../capsules/model-provider/tests/confine/main.rs",
                 "../../capsules/did-provider/src/main.rs",
                 "../../capsules/did-provider/confine.sb",
                 "../../capsules/did-provider/tests/confine.rs",
                 "../../capsules/wallet-provider/src/main.rs",
                 "../../capsules/wallet-provider/confine.sb",
                 "../../capsules/wallet-provider/tests/confine.rs",
                 "../../capsules/wallet-provider/src/tests/falsifiers.rs",
                 "../../lab/capsule-identity/src/lib.rs",
                 "../../lab/capsule-identity/tests/common/mod.rs",
                 "../../lab/capsule-identity/fixtures/wc001-core/capsule.json",
                 "../../lab/wasm-capsule/capsule/src/lib.rs",
                 "../../lab/wasm-capsule/tools/build",
                 "../../lab/wasm-capsule/tools/src/lab_name.rs",
                 "../../lab/wasm-capsule/audit/Cargo.toml",
                 "../../lab/wasm-capsule/audit/INTERFACE.md",
                 "../../lab/wasm-capsule/audit/src/lib.rs",
                 "../../lab/wasm-capsule/.gitignore",
                 "../../lab/wasm-capsule/README.md",
                 "../../lab/wasm-capsule/capsule/capsule.json",
                 "../../lab/wasm-capsule/tests/common/build.rs",
                 "../../lab/wasm-capsule/tests/verify.rs",
                 "../../lab/wasm-capsule/tools/src/bin/bundle.rs",
                 "../../lab/wasm-capsule/tools/src/bundle.rs",
                 "../../lab/wasm-capsule/tools/src/lib.rs",
                 "../../lab/wasm-capsule/tools/src/verify.rs",
                 "../../lab/wasm-capsule/LOG.md",
                 "../../lab/capsule-identity/.gitignore",
                 "../../lab/capsule-identity/README.md",
                 "../../lab/wasm-capsule/tools/src/run.rs",
                 "../../lab/wasm-capsule/tools/src/receipt.rs",
                 "../../lab/wasm-capsule/tests/lab_cid.rs",
                 "../../lab/agent-conformance/fixtures/granted-bytes.txt",
                 "../../lab/agent-conformance/fixtures/grants.json",
                 "../../lab/agent-conformance/fixtures/home-source.txt",
                 "../../lab/agent-conformance/fixtures/host-key-read.txt",
                 "../../lab/agent-conformance/fixtures/instance-grants.json",
                 "../../lab/agent-conformance/fixtures/operator-api-host.txt",
                 "../../lab/agent-conformance/fixtures/parallel-tasks.txt",
                 "../../lab/agent-conformance/probe/capsule.json",
                 "../../lab/agent-conformance/probe/src/lib.rs",
                 "../../lab/agent-conformance/src/census.rs",
                 "../../lab/agent-conformance/src/harness.rs",
                 "../../lab/agent-conformance/src/report.rs",
                 "../../lab/agent-conformance/tests/artifact.rs",
                 "../../lab/agent-conformance/tests/common/grants.rs",
                 "../../lab/agent-conformance/tests/common/mod.rs",
                 "../../lab/agent-conformance/tests/common/operator.rs",
                 "../../lab/agent-conformance/tests/common/probe.rs",
                 "../../lab/agent-conformance/tests/effects.rs",
                 "../../lab/agent-conformance/tests/runtime.rs")
    entry = {"id": "MP01+MP02+MP05+MP12+MP15+MP16+MP23",
             "edits": [edit for owned_entry in owned.values() for edit in owned_entry["edits"]]
             + [{"file": "owned.txt", "old": "original bytes", "new": "mutated bytes"},
                {"file": profile, "old": "original bytes", "new": "mutated bytes"}]
             + [{"file": name, "old": "original bytes", "new": "mutated bytes"}
                for name in synthetic]}
    originals = {edit["file"]: (HERE / edit["file"]).read_bytes()
                 for owned_entry in owned.values() for edit in owned_entry["edits"]}
    originals["owned.txt"] = b"original bytes\n"
    originals[profile] = b"original bytes\n"
    for name in synthetic:
        originals[name] = b"original bytes\n"
    child = """import json, os, pathlib, runpy, signal, sys
runner = runpy.run_path(sys.argv[1])
runner['Mutation'](json.loads(sys.argv[2]), pathlib.Path(sys.argv[3])).__enter__()
os.kill(os.getpid(), signal.SIGKILL)
"""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        for mode in ("provider", "default"):
            repo = SELF_TEST_DIR / mode
            here = repo / "examples/agent-host"
            here.mkdir(parents=True)
            data = here / "falsifiers.json"
            data.write_text('{"falsifiers": []}', encoding="utf-8")
            provider_data = repo / "capsules/model-provider/falsifiers.json"
            provider_data.parent.mkdir(parents=True)
            provider_data.write_text(json.dumps({"falsifiers": list(owned.values())}),
                                     encoding="utf-8")
            for name, original in originals.items():
                target = here / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(original)
                os.utime(target, (1, 1))
            foreign_targets = [repo / "capsules/wallet-provider/src/local_memory.rs",
                               repo / "capsules/model-provider/src/lib.rs",
                               repo / "capsules/model-provider/CONFINEMENT.md",
                               repo / "capsules/did-provider/CONFINEMENT.md",
                               repo / "capsules/model-provider/tests/confine/support.rs",
                               repo / "capsules/did-provider/tests/support.rs",
                               repo / "capsules/wallet-provider/src/tests/support.rs",
                               repo / "lab/capsule-identity/GAP-REPORT.md",
                               repo / "lab/capsule-identity/fixtures/web-app/capsule.json",
                               repo / "lab/wasm-capsule/ADOPTION.md",
                               repo / "lab/wasm-capsule/tools/Cargo.toml",
                               repo / "lab/wasm-capsule/tools/src/other.rs"]
            for target in foreign_targets:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"foreign mutation\n")
                target.with_name(target.name + BACKUP_SUFFIX).write_bytes(b"foreign original\n")
            killed = subprocess.run(
                [sys.executable, "-I", "-B", "-c", child, str(HERE / "falsify.py"),
                 json.dumps(entry), str(here)], capture_output=True, text=True, timeout=10)
            planted = all(
                (here / name).read_bytes() != original
                and (here / name).with_name(pathlib.Path(name).name + BACKUP_SUFFIX).read_bytes()
                == original for name, original in originals.items())
            if killed.returncode != -signal.SIGKILL or not planted:
                print(f"self-test: provider kill: exit={killed.returncode}, planted={planted}")
                return False
            argv = ["--from", str(provider_data), "--list"] if mode == "provider" else ["--list"]
            with mock.patch.dict(globals(), HERE=here, REPO=repo, DATA=data):
                code = main(argv)
            restored = all(
                (here / name).read_bytes() == original
                and not (here / name).with_name(pathlib.Path(name).name + BACKUP_SUFFIX).exists()
                and (here / name).stat().st_mtime_ns > 1_000_000_000
                for name, original in originals.items())
            foreign_kept = all(
                target.read_bytes() == b"foreign mutation\n"
                and target.with_name(target.name + BACKUP_SUFFIX).read_bytes() == b"foreign original\n"
                for target in foreign_targets)
            print(f"self-test: provider {mode} restart: exit={code}, restored={restored}, "
                  f"foreign kept={foreign_kept}")
            if code != 0 or not restored or not foreign_kept:
                ok = False
                continue
            with Mutation(entry, here):
                if any((here / name).read_bytes() == original
                       for name, original in originals.items()):
                    ok = False
            if any((here / name).read_bytes() != original
                   or (here / name).with_name(pathlib.Path(name).name + BACKUP_SUFFIX).exists()
                   for name, original in originals.items()):
                ok = False
    except Exception as error:
        print(f"self-test: provider restart raised {type(error).__name__}: {error}")
        return False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_runner_killed_in_its_test_step_is_recovered():
    """Kill this runner through its own main() after the baseline, restart it
    through main(), and read the recovered bytes. A synthetic provider entry
    edits one PROVIDER_TARGETS file in an isolated tree; a stub for run()
    answers the baseline on the original bytes and kills the child on the
    mutated ones in the named test's run. In both startup modes the next run
    puts the original bytes back and leaves no backup or temporary file beside
    the target."""
    target_name = "../../capsules/model-provider/src/local_llama.rs"
    original_text = "synthetic local_llama original bytes\n"
    mutated_text = "synthetic local_llama mutated bytes\n"
    original = original_text.encode("utf-8")
    mutated = mutated_text.encode("utf-8")
    entry = {"id": "MP01",
             "title": "a synthetic local_llama edit",
             "command": "provider",
             "expect": "caught",
             "edits": [{"file": target_name,
                        "old": original_text.rstrip("\n"),
                        "new": mutated_text.rstrip("\n")}],
             "tests": ["tests::the_stub_answers"]}
    child = """import os, pathlib, runpy, signal, sys
runner = runpy.run_path(sys.argv[1])
here = pathlib.Path(sys.argv[2])
list_path = sys.argv[3]
target = here / sys.argv[4]
test_name = sys.argv[5]
call_log = pathlib.Path(sys.argv[6])
original = ORIGINAL

def stub(argv, cwd):
    word = "original" if target.read_bytes() == original else "mutated"
    step = "build" if "--no-run" in argv else "list" if "--list" in argv else "test"
    with open(call_log, "a", encoding="utf-8") as stream:
        stream.write(word + ":" + step + "\\n")
    if step == "build":
        return 0, ""
    if step == "list":
        return 0, test_name + ": test\\n"
    if word == "mutated":
        os.kill(os.getpid(), signal.SIGKILL)
    return 0, "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\\n"

namespace = runner['main'].__globals__
namespace.update(HERE=here, REPO=here.parent.parent, DATA=here / "falsifiers.json", run=stub)
# Mutation's default base is bound when the class is defined, and the runner's
# own falsify() applies each edit at that default. Point it at the tree too,
# so main() edits the tree's file.
runner['Mutation'].__init__.__defaults__ = (here,)
raise SystemExit(runner['main'](["--from", str(list_path), "MP01"]))
""".replace("ORIGINAL", repr(original))
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        for mode in ("provider", "default"):
            repo = SELF_TEST_DIR / mode
            here = repo / "examples/agent-host"
            here.mkdir(parents=True)
            data = here / "falsifiers.json"
            data.write_text('{"falsifiers": []}', encoding="utf-8")
            list_path = repo / "capsules/model-provider/falsifiers.json"
            list_path.parent.mkdir(parents=True)
            list_path.write_text(json.dumps({"falsifiers": [entry]}), encoding="utf-8")
            target = here / target_name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(original)
            backup = target.with_name(target.name + BACKUP_SUFFIX)
            call_log = repo / "stub-calls.txt"
            killed = subprocess.run(
                [sys.executable, "-I", "-B", "-c", child, str(HERE / "falsify.py"),
                 str(here), str(list_path), target_name, entry["tests"][0],
                 str(call_log)], capture_output=True, text=True, timeout=30)
            calls = call_log.read_text(encoding="utf-8").splitlines()
            planted = (target.read_bytes() == mutated
                       and backup.is_file() and backup.read_bytes() == original)
            argv = ["--from", str(list_path), "--list"] if mode == "provider" else ["--list"]
            with mock.patch.dict(globals(), HERE=here, REPO=repo, DATA=data):
                code = main(argv)
            restored = target.read_bytes() == original
            leftovers = [path.name for path in
                         (backup, target.with_name(target.name + ".falsify-tmp"))
                         if path.exists()]
            # The kill must land in the mutated test run: the original test run
            # answered before the first mutated call, and the last call is the
            # mutated test run itself, not a build or list step.
            first_mutated = next((index for index, call in enumerate(calls)
                                  if call.startswith("mutated")), len(calls))
            order = ("original:test" in calls[:first_mutated]
                     and calls[-1:] == ["mutated:test"])
            print(f"self-test: runner kill {mode}: exit={killed.returncode}, "
                  f"calls={','.join(calls)}, planted={planted}, restart={code}, "
                  f"restored={restored}, leftovers={leftovers}")
            if (killed.returncode != -signal.SIGKILL or not order or not planted
                    or code != 0 or not restored or leftovers):
                ok = False
    except Exception as error:
        print(f"self-test: runner kill raised {type(error).__name__}: {error}")
        return False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def an_edit_of_a_missing_file_is_refused():
    """An edit whose file does not exist is refused by Mutation before any
    link or write, with the one path-rule reason; reported() returns it as
    NO MATCH, so a missing file is never a catch (task 014). An exception
    escaping reported() fails this case instead of erroring it out."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        name = "missing.txt"
        entry = {"id": "ST", "command": "host", "expect": "caught",
                 "edits": [{"file": name, "old": "original bytes",
                            "new": "mutated bytes"}],
                 "tests": ["tests::planted_check"]}
        reason = (f"{name}: the file does not exist; "
                  "edit paths are relative to examples/agent-host")
        path = SELF_TEST_DIR / name
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        real_mutation = Mutation
        got = None
        with mock.patch.dict(globals(),
                             Mutation=lambda item: real_mutation(item, SELF_TEST_DIR)):
            try:
                got = reported(entry)
            except BaseException as error:
                print(f"self-test: missing file raised {type(error).__name__}: {error}")
                ok = False
        created = path.exists() or backup.exists()
        print(f"self-test: edit of a missing file: {got}, created={created}")
        if got != (False, "NO MATCH", reason):
            ok = False
        if created:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def refusal_tree():
    """A repository folder under SELF_TEST_DIR with an outside.txt and an
    outside-dir/victim.txt beside it that no edit may touch (task 028)."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    tree = SELF_TEST_DIR / "repo"
    tree.mkdir(parents=True)
    (SELF_TEST_DIR / "outside.txt").write_bytes(b"outside original\n")
    victim = SELF_TEST_DIR / "outside-dir" / "victim.txt"
    victim.parent.mkdir()
    victim.write_bytes(b"outside original\n")
    return tree


def edit_entry(name, old="outside original"):
    """One edit entry for one name, so a path that is not refused would
    change that file."""
    return {"id": "ST", "command": "host", "expect": "caught",
            "edits": [{"file": name, "old": old, "new": "mutated bytes"}],
            "tests": ["tests::planted_check"]}


def refused_edit(entry, tree):
    """One entry's reported() result against the test tree, which is both
    REPO and the edit base. The cheap command runs only when the edit is not
    refused, so a refusal is checked without a build. An exception escaping
    reported() fails the case instead of erroring it out."""
    real_mutation = Mutation
    how = {"build": [], "one": (["false"], tree, [])}
    with mock.patch.dict(globals(), REPO=tree,
                         Mutation=lambda item: real_mutation(item, tree)):
        try:
            return reported(entry, how)
        except BaseException as error:
            return False, f"raised {type(error).__name__}", str(error)


def tree_state(root):
    """Every name under root as a link's target or a file's bytes, so a case
    proves a refusal changed nothing inside or outside the repository."""
    state = {}
    for folder, folders, names in os.walk(root):
        for name in folders + names:
            path = pathlib.Path(folder) / name
            if path.is_symlink():
                state[path] = ("link", os.readlink(path))
            elif path.is_file():
                state[path] = ("file", path.read_bytes())
            else:
                state[path] = ("folder", None)
    return state


def an_absolute_edit_path_is_refused():
    """An absolute edit path is refused with its own reason before any link,
    whether it names a file inside the tree's repository or outside it. Only
    the absolute check refuses the inside file (task 028)."""
    ok = True
    try:
        tree = refusal_tree()
        inside = tree / "inside.txt"
        inside.write_bytes(b"inside original\n")
        before = tree_state(SELF_TEST_DIR)
        results = {}
        for name, old in ((str(inside), "inside original"),
                          (str(SELF_TEST_DIR / "outside.txt"), "outside original")):
            want = (f"{name}: the path is absolute; "
                    "edit paths are relative to examples/agent-host")
            results[name] = refused_edit(edit_entry(name, old), tree)
            if results[name] != (False, "NO MATCH", want):
                ok = False
        kept = tree_state(SELF_TEST_DIR) == before
        print(f"self-test: an absolute edit path is refused: "
              + ", ".join(f"{got[1]}" for got in results.values())
              + f", kept={kept}")
        if not kept:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def an_edit_path_that_climbs_out_is_refused():
    """A relative edit path with enough `..` parts resolves outside the
    tree's repository and is refused with the containment reason before any
    link or write (task 028)."""
    ok = True
    try:
        tree = refusal_tree()
        before = tree_state(SELF_TEST_DIR)
        results = {}
        for name in ("../outside.txt", "nested/../../outside.txt"):
            want = (f"{name}: the path leaves the repository; "
                    "edit paths are relative to examples/agent-host")
            results[name] = refused_edit(edit_entry(name), tree)
            if results[name] != (False, "NO MATCH", want):
                ok = False
        kept = tree_state(SELF_TEST_DIR) == before
        print(f"self-test: an edit path that climbs out is refused: "
              + ", ".join(f"{got[1]}" for got in results.values())
              + f", kept={kept}")
        if not kept:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def an_absent_outside_edit_path_gets_the_containment_reason():
    """A `..` path to a file that does not exist is refused for leaving the
    repository, not for being missing: the containment check runs before the
    missing-file check (task 028)."""
    ok = True
    try:
        tree = refusal_tree()
        before = tree_state(SELF_TEST_DIR)
        name = "../absent.txt"
        want = (f"{name}: the path leaves the repository; "
                "edit paths are relative to examples/agent-host")
        got = refused_edit(edit_entry(name), tree)
        kept = tree_state(SELF_TEST_DIR) == before
        print(f"self-test: an absent outside edit path gets the containment "
              f"reason: {got[1]} ({got[2]}), kept={kept}")
        if got != (False, "NO MATCH", want) or not kept:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def an_edit_through_a_symbolic_link_is_refused():
    """A file reached through a folder link gets the containment reason, and
    a link to outside.txt, a link to an inside file and a dangling link each
    get the link reason. Every link stays a link and every file keeps its
    bytes (task 028)."""
    ok = True
    try:
        tree = refusal_tree()
        inside = tree / "inside.txt"
        inside.write_bytes(b"inside original\n")
        outside_dir = SELF_TEST_DIR / "outside-dir"
        (tree / "portal").symlink_to(outside_dir)
        (tree / "link.txt").symlink_to(SELF_TEST_DIR / "outside.txt")
        (tree / "inside-link.txt").symlink_to(inside)
        (tree / "dangling.txt").symlink_to(tree / "gone.txt")
        before = tree_state(SELF_TEST_DIR)
        edits = {
            "portal/victim.txt": ("outside original",
                                  "the path leaves the repository; "
                                  "edit paths are relative to examples/agent-host"),
            "link.txt": ("outside original",
                         "the file is a symbolic link; an edit names the file itself"),
            "inside-link.txt": ("inside original",
                                "the file is a symbolic link; an edit names the file itself"),
            "dangling.txt": ("outside original",
                             "the file is a symbolic link; an edit names the file itself"),
        }
        results = {}
        for name, (old, reason) in edits.items():
            want = (False, "NO MATCH", f"{name}: {reason}")
            results[name] = refused_edit(edit_entry(name, old), tree)
            if results[name] != want:
                ok = False
        kept = tree_state(SELF_TEST_DIR) == before
        print(f"self-test: an edit through a symbolic link is refused: "
              + ", ".join(f"{name}={got[1]}" for name, got in results.items())
              + f", kept={kept}")
        if not kept:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def an_entry_with_one_outside_edit_changes_no_file():
    """An entry whose inside edit comes first and whose second path climbs
    out makes no link, no write and no replacement: every name is checked
    before the first edit is applied, so restored final bytes alone do not
    prove the refusal came first (task 028)."""
    ok = True
    try:
        tree = refusal_tree()
        inside = tree / "inside.txt"
        inside.write_bytes(b"inside original\n")
        before = tree_state(SELF_TEST_DIR)
        name = "../outside.txt"
        entry = edit_entry("inside.txt", "inside original")
        entry["edits"].extend(edit_entry(name)["edits"])
        want = (False, "NO MATCH", f"{name}: the path leaves the repository; "
                "edit paths are relative to examples/agent-host")
        real_write_text = pathlib.Path.write_text
        writes = []

        def count_write_text(path, *args, **kwargs):
            writes.append(path)
            return real_write_text(path, *args, **kwargs)

        with mock.patch.object(pathlib.Path, "write_text", count_write_text), \
                mock.patch.object(os, "link", wraps=os.link) as links, \
                mock.patch.object(os, "replace", wraps=os.replace) as replaces:
            got = refused_edit(entry, tree)
        calls = (links.call_count, len(writes), replaces.call_count)
        kept = tree_state(SELF_TEST_DIR) == before
        print(f"self-test: an entry with one outside edit changes no file: "
              f"{got[1]}, links={calls[0]}, writes={calls[1]}, "
              f"replacements={calls[2]}, kept={kept}")
        if got != want or calls != (0, 0, 0) or not kept:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def the_streams_keep_their_own_lines():
    """stdout and stderr are joined at a line boundary, so a marker at the
    start of stderr is still at the start of a line when stdout ends without
    a newline (task 010 review finding 1)."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        stub = SELF_TEST_DIR / "stub.py"
        stub.write_text(STUB_SPLIT_STREAMS, encoding="utf-8")
        _, output = run(["python3", "-I", str(stub)], SELF_TEST_DIR)
        kept = "error: could not load the test harness" in output.splitlines()
        print(f"self-test: the streams keep their own lines: kept={kept}")
        return kept
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)


def a_self_test_case_counts_only_when_it_ran():
    """The named case ran and failed -> a catch. A loading error that exits
    non-zero, or a signal, is not run and not a catch (review finding 1)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        entry = {"id": "ST", "command": "selftest", "expect": "caught",
                 "tests": ["planted case"]}
        cases = (
            ("ran and failed", STUB_CASE_RAN_FAILED, (True, "CAUGHT")),
            ("ran and passed", STUB_CASE_RAN_PASSED, (False, "SURVIVED")),
            ("loading error", STUB_CASE_LOADING_ERROR, (False, "NOT RUN")),
            ("signal", STUB_CASE_SIGNAL, (False, "NOT RUN")),
        )
        for title, text, want in cases:
            stub = SELF_TEST_DIR / "stub.py"
            stub.write_text(text, encoding="utf-8")
            how = {"build": [], "one": (["python3", "-I", str(stub)], SELF_TEST_DIR, [])}
            got = verdict(entry, *evaluate(entry, how))
            print(f"self-test: self-test case {title}: {got[1]} ({got[2]})")
            if got[:2] != want:
                ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def load_refused(path, reason):
    """True only when load(path) stops with status 2 and exactly `reason`.
    A bypass that lets a read, JSON or shape exception escape fails the case,
    so that falsifier is caught instead of the case erroring out."""
    message = io.StringIO()
    try:
        with contextlib.redirect_stderr(message):
            load(path)
    except SystemExit as stop:
        code = stop.code
    except Exception as error:
        print(f"self-test: load({path}) raised {type(error).__name__}: {error}")
        return False
    else:
        print(f"self-test: load({path}) returned without a refusal")
        return False
    print(f"self-test: load({path}) -> exit {code}: {message.getvalue().strip()}")
    return code == CASE_USAGE and message.getvalue() == f"{path}: {reason}\n"


def a_data_file_refusal(name, text, reason):
    """One crafted data file under the self-test dir: load() stops with status
    2 and exactly reason. No file is written when text is None."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        path = SELF_TEST_DIR / name
        if text is not None:
            SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
            if isinstance(text, bytes):
                path.write_bytes(text)
            else:
                path.write_text(text, encoding="utf-8")
        return load_refused(path, reason)
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)


def a_missing_data_file_is_refused():
    """A path with no file is a refusal, not an empty run."""
    return a_data_file_refusal("missing.json", None, "the data file does not exist")


def an_unreadable_data_file_is_refused():
    """An existing file whose read fails gives the exact read refusal."""
    with mock.patch.object(pathlib.Path, "read_text", side_effect=PermissionError("denied")):
        return a_data_file_refusal("unreadable.json", '{"falsifiers": []}',
                                   "the data file cannot be read")


def an_unreadable_data_path_is_refused():
    """An inaccessible parent makes the initial stat fail: the shared OSError
    refusal gives exit 2 and the read reason, not a traceback."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        path = SELF_TEST_DIR / "stat-denied.json"
        path.write_text('{"falsifiers": []}', encoding="utf-8")
        with mock.patch.object(pathlib.Path, "stat",
                               side_effect=PermissionError("denied")):
            return load_refused(path, "the data file cannot be read")
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)


def an_invalid_utf8_data_file_is_refused():
    """Invalid UTF-8 reaches the decode refusal before JSON parsing."""
    return a_data_file_refusal("invalid-utf8.json", b'{"falsifiers": []}\xff',
                               "the data file is not JSON")


def a_non_json_data_file_is_refused():
    """Text that is not JSON is a refusal, not an empty run."""
    return a_data_file_refusal("not-json.json", "this is not JSON\n",
                               "the data file is not JSON")


def a_data_document_must_be_an_object():
    """A JSON body that is not an object is a refusal with its own reason."""
    return a_data_file_refusal("root-list.json", json.dumps(["falsifiers"]),
                               "the document is not an object")


def a_data_document_needs_a_falsifiers_list():
    """An object without a falsifiers key is a refusal with its own reason."""
    return a_data_file_refusal("no-falsifiers.json", json.dumps({"entries": []}),
                               "the document has no falsifiers list")


def falsifiers_must_be_a_list():
    """A falsifiers value that is not a list is a refusal with its own reason."""
    return a_data_file_refusal("falsifiers-object.json",
                               json.dumps({"falsifiers": {}}),
                               "falsifiers is not a list")


def a_duplicate_id_is_refused():
    """Two entries with one id are a refusal with status 2."""
    entry = {"id": "ST", "command": "host", "expect": "caught", "tests": ["tests::x"]}
    return a_data_file_refusal("duplicate.json",
                               json.dumps({"falsifiers": [entry, dict(entry)]}),
                               "an id is used twice")


def an_unknown_command_is_refused():
    """A command outside COMMANDS is a refusal with its own reason."""
    entry = {"id": "ST", "command": "bogus", "expect": "caught", "tests": ["tests::x"]}
    return a_data_file_refusal("unknown-command.json",
                               json.dumps({"falsifiers": [entry]}),
                               "ST: unknown command 'bogus'")


def an_unknown_expect_is_refused():
    """An expect outside the known values is a refusal with its own reason."""
    entry = {"id": "ST", "command": "host", "expect": "bogus", "tests": ["tests::x"]}
    return a_data_file_refusal("unknown-expect.json",
                               json.dumps({"falsifiers": [entry]}),
                               "ST: unknown expect 'bogus'")


def a_survivor_needs_its_named_test_to_run():
    """A survives entry whose named test did not run is NOT RUN, never a
    survivor. load() refuses a survives entry with no named test, the same as
    a caught entry (task 005)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        data = SELF_TEST_DIR / "falsifiers.json"
        data.write_text(json.dumps({"falsifiers": [
            {"id": "ST", "title": "no test", "command": "host",
             "expect": "survives", "edits": [], "tests": []}]}), encoding="utf-8")
        if not load_refused(data, "ST: no named tests"):
            ok = False
        entry = {"id": "ST", "command": "host", "expect": "survives",
                 "tests": ["tests::planted_check"]}
        stub = SELF_TEST_DIR / "stub.py"
        stub.write_text(STUB_HARNESS_ERROR, encoding="utf-8")
        how = {"build": [], "one": (["python3", "-I", str(stub)], SELF_TEST_DIR, [])}
        got = verdict(entry, *evaluate(entry, how))
        print(f"self-test: survivor whose named test did not run: {got[1]} ({got[2]})")
        if got[:2] != (False, "NOT RUN"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_survivor_is_proved_by_its_named_tests():
    """A genuine survivor counts only when its named test ran and passed under
    the mutation. The stub's whole suite fails, which used to be read as "the
    mutation is caught": only the named test proves it (task 005)."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        entry = {"id": "ST", "command": "host", "expect": "survives",
                 "tests": ["tests::planted_check"]}
        stub = SELF_TEST_DIR / "stub.py"
        stub.write_text(STUB_SURVIVOR_RAN, encoding="utf-8")
        how = {"build": [], "one": (["python3", "-I", str(stub)], SELF_TEST_DIR, [])}
        got = verdict(entry, *evaluate(entry, how))
        print(f"self-test: survivor whose named test ran and passed: {got[1]} ({got[2]})")
        if got[:2] != (True, "SURVIVED (expected, by design)"):
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def refusal(argv):
    """(exit code, reason) from parse_argv, with its message captured."""
    message = io.StringIO()
    with contextlib.redirect_stderr(message):
        try:
            parse_argv(argv)
        except SystemExit as stop:
            return stop.code, message.getvalue()
    return None, message.getvalue()


def from_option_selects_path():
    """--from names the data file; without it the path is the default."""
    ok = True
    default = parse_argv([])
    print(f"self-test: default path: {default.path}, mode {default.mode}")
    if default.path != DATA or default.mode != "run":
        ok = False
    chosen = pathlib.Path("capsules/model-provider/falsifiers.json")
    picked = parse_argv(["--from", str(chosen)])
    print(f"self-test: --from path: {picked.path}")
    if picked.path != chosen:
        ok = False
    return ok


def unknown_option_is_refused():
    """Every unsupported option stops at the front door with status 2 and a
    reason that names it, even beside --list or after --from PATH."""
    ok = True
    for argv, option in (
        (["--help"], "--help"),
        (["--typo"], "--typo"),
        (["--list", "--typo"], "--typo"),
        (["--from", str(DATA), "--typo"], "--typo"),
        (["FS01", "--bogus"], "--bogus"),
    ):
        code, reason = refusal(argv)
        print(f"self-test: {' '.join(argv)} -> exit {code}: {reason.strip()}")
        if code != 2 or option not in reason:
            ok = False
        if reason != f"usage: unknown option {option}\n":
            ok = False
    return ok


def equals_form_is_refused():
    """The equals form is refused and names the separated form to use."""
    ok = True
    for argv in (["--from=capsules/model-provider/falsifiers.json"], ["--from="]):
        code, reason = refusal(argv)
        print(f"self-test: {argv[0]} -> exit {code}: {reason.strip()}")
        if code != 2 or "use --from PATH" not in reason:
            ok = False
        if reason != "usage: --from=PATH is not supported; use --from PATH\n":
            ok = False
    return ok


def from_without_a_path_is_refused():
    """--from needs a path, not a missing value and not another option."""
    ok = True
    for argv in (["--from"], ["--from", "--typo"]):
        code, reason = refusal(argv)
        print(f"self-test: {' '.join(argv)} -> exit {code}: {reason.strip()}")
        if code != 2 or "--from needs a path" not in reason:
            ok = False
        if reason != "usage: --from needs a path, not an option\n":
            ok = False
    return ok


def modifier_only_invocation_is_refused():
    """Modifiers need an explicit mode, data file, or id prefix."""
    ok = True
    for argv in (["--with-repo"], ["--keep-backups"],
                 ["--with-repo", "--keep-backups"],
                 ["--keep-backups", "--with-repo"],
                 ["--with-repo", "--with-repo"],
                 ["--keep-backups", "--keep-backups"]):
        code, reason = refusal(argv)
        print(f"self-test: {' '.join(argv)} -> exit {code}: {reason.strip()}")
        if (code != 2 or reason != "usage: --keep-backups and --with-repo need a mode, "
                "--from PATH, or an id prefix\n"):
            ok = False
    return ok


def modifiers_preserve_explicit_selection():
    """Each modifier remains available beside an explicit selection."""
    ok = True
    for modifiers in (["--with-repo"], ["--keep-backups"],
                      ["--keep-backups", "--with-repo"]):
        for selection, mode, name, filters in (
            (["--from", str(DATA)], "run", None, []),
            (["FS01"], "run", None, ["FS01"]),
            (["--list"], "list", None, []),
            (["--self-test-cases"], "self-test-cases", None, []),
            (["--self-test"], "self-test", None, []),
            (["--self-test-case", "from option selects path"],
             "self-test-case", "from option selects path", []),
        ):
            for argv in (modifiers + selection, selection + modifiers):
                try:
                    parsed = parse_argv(argv)
                except SystemExit as stop:
                    print(f"self-test: {argv} -> unexpected exit {stop.code}")
                    ok = False
                    continue
                if parsed != ParsedArgv(DATA, mode, name, filters,
                                        "--keep-backups" in modifiers,
                                        "--with-repo" in modifiers):
                    print(f"self-test: {argv} -> {parsed}")
                    ok = False
    return ok


def self_test_case_without_a_name_is_refused():
    """A named case requires a value; another option cannot supply it."""
    ok = True
    for argv in (["--self-test-case"], ["--self-test-case", "--typo"],
                 ["--self-test-case", "--list"],
                 ["--list", "--self-test-case"],
                 ["--list", "--self-test-case", "--self-test"]):
        code, reason = refusal(argv)
        print(f"self-test: {' '.join(argv)} -> exit {code}: {reason.strip()}")
        if (code != 2 or reason != "usage: --self-test-case needs a case name, not an option\n"):
            ok = False
    return ok


def argv_refusal_precedes_work():
    """main() refuses an unsupported option before recovery or loading. Both
    are stubbed, so this case reads no file and touches no backup."""
    ok = True
    touched = []
    saved = recover_backups, load

    def stub_recover():
        touched.append("recover_backups")

    def stub_load(*_args, **_kwargs):
        touched.append("load")
        return []

    globals()["recover_backups"] = stub_recover
    globals()["load"] = stub_load
    try:
        for argv, reason in (
            (["--typo"], "unknown option --typo"),
            (["--list", "--typo"], "unknown option --typo"),
            (["--from=path"], "--from=PATH is not supported; use --from PATH"),
            (["--from"], "--from needs a path, not an option"),
            (["--from", "--list"], "--from needs a path, not an option"),
            (["--self-test-case"], "--self-test-case needs a case name, not an option"),
            (["--self-test-case", "--list"], "--self-test-case needs a case name, not an option"),
            (["--with-repo"], "--keep-backups and --with-repo need a mode, --from PATH, or an id prefix"),
            (["--keep-backups"], "--keep-backups and --with-repo need a mode, --from PATH, or an id prefix"),
            (["--with-repo", "--keep-backups"],
             "--keep-backups and --with-repo need a mode, --from PATH, or an id prefix"),
        ):
            touched.clear()
            code = None
            message = io.StringIO()
            with contextlib.redirect_stderr(message):
                try:
                    main(argv)
                except SystemExit as stop:
                    code = stop.code
            print(f"self-test: main {' '.join(argv)} -> exit {code}, touched={touched}")
            if code != 2 or touched:
                ok = False
            if message.getvalue() != f"usage: {reason}\n":
                ok = False
    finally:
        globals()["recover_backups"], globals()["load"] = saved
    return ok


def provider_spec_uses_locked_manifest():
    """Every crate in the table — the three provider crates, the lab's
    capsule-identity crate, the lab's agent-conformance crate and the lab's
    wasm-capsule workspace — is a registered command, and both its build and
    run argv name --locked and the manifest that follows --manifest-path. The
    lab workspace adds --workspace before the libtest separator; every other
    row, agent-conformance included, adds no argument. The expected manifests
    and arguments are written here, so a table that maps one crate to another
    crate's manifest is caught (PV43, PV50, PV118); lab registration, its
    manifest, its omitted workspace flag and a flag that leaks into a provider
    row are caught (PV65-PV68); an absent agent-conformance row is caught
    (PV117)."""
    ok = True
    expected = {
        "provider": (str(REPO / "capsules" / "model-provider" / "Cargo.toml"), ()),
        "did": (str(REPO / "capsules" / "did-provider" / "Cargo.toml"), ()),
        "wallet": (str(REPO / "capsules" / "wallet-provider" / "Cargo.toml"), ()),
        "capsule-identity": (str(REPO / "lab" / "capsule-identity" / "Cargo.toml"), ()),
        "agent-conformance": (str(REPO / "lab" / "agent-conformance" / "Cargo.toml"), ()),
        "lab": (str(REPO / "lab" / "wasm-capsule" / "Cargo.toml"), ("--workspace",)),
    }
    for command, (manifest, extra) in expected.items():
        if command not in COMMANDS:
            print(f"self-test: {command} is not a registered command")
            ok = False
            continue
        how = spec(command)
        build = how["build"]
        one, cwd, _extra = how["one"]
        print(f"self-test: {command} build {[argv for argv, _cwd in build]}")
        print(f"self-test: {command} run {one}")
        base = ["cargo", "test", "--locked", "--manifest-path", manifest]
        if cwd != REPO or len(build) != 1 or build[0][1] != REPO:
            ok = False
        elif build[0][0] != base + list(extra) + ["--no-run"]:
            ok = False
        if one != base + list(extra) + ["--"]:
            ok = False
    return ok


def an_agent_conformance_entry_loads_and_runs_its_crate():
    """A list entry whose command is agent-conformance loads, and that
    command builds and runs the crate through its own manifest with --locked
    and no extra Cargo argument. The crate's default members already select
    its probe member, so the row adds none. No cargo runs here."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        path = SELF_TEST_DIR / "agent-conformance.json"
        entry = {"id": "AC1", "command": "agent-conformance",
                 "expect": "caught", "tests": ["tests::x"]}
        path.write_text(json.dumps({"falsifiers": [entry]}), encoding="utf-8")
        try:
            loaded = load(path)
        except SystemExit:
            print("self-test: an agent-conformance entry does not load")
            return False
        print(f"self-test: an agent-conformance entry loads: {loaded == [entry]}")
        if loaded != [entry]:
            ok = False
        manifest = str(REPO / "lab" / "agent-conformance" / "Cargo.toml")
        how = spec("agent-conformance")
        build = how["build"]
        one, cwd, extra = how["one"]
        base = ["cargo", "test", "--locked", "--manifest-path", manifest]
        print(f"self-test: agent-conformance build {[argv for argv, _cwd in build]}")
        print(f"self-test: agent-conformance run {one}")
        if cwd != REPO or extra or len(build) != 1 or build[0][1] != REPO:
            ok = False
        elif build[0][0] != base + ["--no-run"]:
            ok = False
        if one != base + ["--"]:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def list_mode_displays():
    """--list displays the loaded entries. It never selects work, and it may
    name the file it displays."""
    ok = True
    chosen = pathlib.Path("capsules/model-provider/falsifiers.json")
    for argv, want_path in ((["--list"], DATA), (["--list", "--from", str(chosen)], chosen)):
        parsed = parse_argv(argv)
        print(f"self-test: {' '.join(argv)} -> mode {parsed.mode}, path {parsed.path}")
        if parsed.mode != "list" or parsed.path != want_path:
            ok = False
    return ok


def prefix_token_still_selects():
    """A bare token still filters by id prefix, with or without --from."""
    ok = True
    chosen = pathlib.Path("capsules/model-provider/falsifiers.json")
    for argv, want in ((["FS01", "FS03"], ["FS01", "FS03"]),
                       (["--from", str(chosen), "FS01"], ["FS01"])):
        parsed = parse_argv(argv)
        print(f"self-test: {' '.join(argv)} -> mode {parsed.mode}, filters {parsed.filters}")
        if parsed.mode != "run" or parsed.filters != want:
            ok = False
    return ok


def a_nested_list_is_listed():
    """A nested main() against a crafted list displays it. This is the first
    step of the cross-process case below: the nested run must leave a
    caller's backup alone."""
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        data = SELF_TEST_DIR / "nested-list.json"
        data.write_text(json.dumps({"falsifiers": [
            {"id": "ST", "title": "nested entry", "command": "host",
             "expect": "caught", "edits": [], "tests": ["tests::x"]}]}),
            encoding="utf-8")
        listed = io.StringIO()
        with contextlib.redirect_stdout(listed):
            code = main(["--from", str(data), "--list"])
        text = listed.getvalue()
        print(f"self-test: nested list -> exit {code}: {text.strip()}")
        return code == 0 and "nested entry" in text
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)


def a_nested_run_keeps_the_callers_backup():
    """Cross-process: an outer `survives` mutation of the non-JSON refusal is
    active on a copy of this runner. A first case runs a nested main()
    without --keep-backups, then PV20's case still sees the mutation, so the
    verdict is NOT A SURVIVOR. The caller's backup keeps the original bytes,
    and --keep-backups keeps a backup this process does not own."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        runner = SELF_TEST_DIR / "falsify.py"
        source = (HERE / "falsify.py").read_bytes()
        runner.write_bytes(source)
        (SELF_TEST_DIR / "falsifiers.json").write_text(
            '{"falsifiers": []}', encoding="utf-8")
        pv20 = next(entry for entry in load(REPO / "capsules/model-provider/falsifiers.json")
                    if entry["id"] == "PV20")
        entry = {"id": "ST", "command": "selftest", "expect": "survives",
                 "tests": ["a nested list is listed",
                           "a non-json data file is refused"]}
        how = {"build": [], "one": (["python3", "-I", str(runner), "--keep-backups"],
                                    HERE, [])}
        backup = runner.with_name(runner.name + BACKUP_SUFFIX)
        with Mutation(pv20, SELF_TEST_DIR):
            got = verdict(entry, *evaluate(entry, how))
            mutated = str(pv20["edits"][0]["new"]) in runner.read_text(encoding="utf-8")
            kept = backup.exists() and backup.read_bytes() == source
            print(f"self-test: nested ownership: {got[1]} ({got[2]}), "
                  f"mutated={mutated}, caller backup kept={kept}")
            if got[:2] != (False, "NOT A SURVIVOR"):
                ok = False
            if "a non-json data file is refused" not in got[2]:
                ok = False
            if not mutated or not kept:
                ok = False
        stale = SELF_TEST_DIR / "stale.txt"
        stale.write_text("mutated bytes\n", encoding="utf-8")
        stale_backup = stale.with_name(stale.name + BACKUP_SUFFIX)
        stale_backup.write_text("caller original\n", encoding="utf-8")
        code, _output = run(["python3", "-I", str(runner), "--keep-backups", "--list"], HERE)
        stale_kept = (code == 0 and stale.read_text(encoding="utf-8") == "mutated bytes\n"
                      and stale_backup.read_text(encoding="utf-8") == "caller original\n")
        print(f"self-test: --keep-backups keeps an unowned backup: exit={code}, "
              f"kept={stale_kept}")
        if not stale_kept:
            ok = False
        if runner.read_bytes() != source or backup.exists():
            print("self-test: nested ownership: the caller's copy was not restored")
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def released_backups_are_recovered_again():
    """Two killed-edit recoveries run in one child interpreter. Local
    ownership ends after restore, while the child's recovery and subsequent
    ownership publications keep the active ancestor's backup protected."""
    ok = True
    before = owned_backups()
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        path = SELF_TEST_DIR / "ancestor.txt"
        original = b"ancestor original\n"
        path.write_bytes(original)
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        entry = {"edits": [{"file": path.name, "old": "ancestor original",
                            "new": "ancestor mutation"}]}
        child = """import os, pathlib, runpy, sys
from unittest import mock
runner = runpy.run_path(sys.argv[1])
state = runner['main'].__globals__
root = pathlib.Path(sys.argv[2])
state['SELF_TEST_DIR'] = root / 'recovery'
inherited = runner['owned_backups']()
ok = True
for attempt in range(2):
    recovered = runner['a_killed_provider_edit_is_recovered']()
    published = {pathlib.Path(name).resolve()
                 for name in os.environ.get(runner['OWNED_BACKUPS_ENV'], '').split(os.pathsep)
                 if name}
    released = runner['owned_backups']() == inherited and published == inherited
    with mock.patch.dict(state, HERE=root, REPO=root):
        runner['recover_backups']()
    print(f'self-test: recovery cycle {attempt + 1}: recovered={recovered}, released={released}')
    if not recovered or not released:
        ok = False
sys.exit(0 if ok else 1)
"""
        with Mutation(entry, SELF_TEST_DIR):
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-c", child, str(HERE / "falsify.py"),
                 str(SELF_TEST_DIR)], capture_output=True, text=True, timeout=30)
            kept = (path.read_bytes() == b"ancestor mutation\n"
                    and backup.exists() and backup.read_bytes() == original)
            print(result.stdout, end="")
            print(f"self-test: repeated recovery: exit={result.returncode}, "
                  f"ancestor kept={kept}")
            if result.returncode != 0 or not kept:
                print(result.stderr, end="")
                ok = False
        if path.read_bytes() != original or backup.exists() or owned_backups() != before:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_backup_this_run_did_not_make_is_refused():
    """A competing backup appears inside os.link(). The link decides
    ownership: the edit stops with its own reason and result, the caller's
    file and backup keep their bytes, and no backup is recorded for restore.
    A backup that is already there at the start gets the same refusal."""
    ok = True
    shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    try:
        SELF_TEST_DIR.mkdir(parents=True, exist_ok=True)
        path = SELF_TEST_DIR / "planted.txt"
        original = "original bytes\n"
        caller_backup = "a caller's backup\n"
        path.write_text(original, encoding="utf-8")
        backup = path.with_name(path.name + BACKUP_SUFFIX)
        entry = {"id": "ST", "command": "selftest", "expect": "caught",
                 "edits": [{"file": path.name, "old": "original bytes",
                            "new": "mutated bytes"}],
                 "tests": ["a nested list is listed"]}
        reason = f"{backup} is a backup this run did not create; the edit is not applied"

        def bytes_or_none(target):
            return target.read_bytes() if target.exists() else None

        # A backup the caller made is already there.
        backup.write_text(caller_backup, encoding="utf-8")
        real_mutation = Mutation
        with mock.patch.dict(globals(),
                             Mutation=lambda item: real_mutation(item, SELF_TEST_DIR)):
            try:
                got = reported(entry)
            except BaseException as error:
                print(f"self-test: reported collision raised {type(error).__name__}: {error}")
                got = None
        unchanged = bytes_or_none(path) == original.encode("utf-8")
        backup_kept = bytes_or_none(backup) == caller_backup.encode("utf-8")
        print(f"self-test: backup collision: {got}, unchanged={unchanged}, "
              f"backup kept={backup_kept}")
        if got != (False, "BACKUP TAKEN", reason):
            ok = False
        if not unchanged or not backup_kept:
            ok = False
        backup.unlink(missing_ok=True)

        # The same refusal when the competing backup appears inside our link.
        real_link = os.link

        def competing_link(src, dst, *args, **kwargs):
            pathlib.Path(dst).write_text(caller_backup, encoding="utf-8")
            return real_link(src, dst, *args, **kwargs)

        mutation = Mutation(entry, SELF_TEST_DIR)
        got_class = got_reason = None
        with mock.patch.object(os, "link", competing_link):
            try:
                with mutation:
                    pass
            except BackupCollision as error:
                got_class = type(error).__name__
                got_reason = str(error)
            except BaseException as error:
                print(f"self-test: collision raised {type(error).__name__}: {error}")
                ok = False
        unchanged = bytes_or_none(path) == original.encode("utf-8")
        backup_kept = bytes_or_none(backup) == caller_backup.encode("utf-8")
        unrecorded = mutation.applied == []
        print(f"self-test: link collision: class={got_class}, unchanged={unchanged}, "
              f"backup kept={backup_kept}, unrecorded={unrecorded}")
        if got_class != "BackupCollision" or got_reason != reason:
            print(f"self-test: link collision reason: {got_reason!r}")
            ok = False
        if not unchanged or not backup_kept or not unrecorded:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_temporary_file_this_run_did_not_create_is_refused():
    """A name planted at the temporary-file name, here a hard link to a file
    beside the repository, is refused with its own reason before the backup
    link: neither file changes, the plant keeps its inode and no backup
    appears (task 029)."""
    ok = True
    try:
        tree = refusal_tree()
        inside = tree / "inside.txt"
        inside.write_bytes(b"inside original\n")
        outside = SELF_TEST_DIR / "outside.txt"
        tmp = inside.with_name(inside.name + ".falsify-tmp")
        os.link(outside, tmp)
        planted = os.stat(tmp).st_ino
        before = tree_state(SELF_TEST_DIR)
        want = (False, "BACKUP TAKEN",
                f"{tmp}: a temporary file this run did not create; "
                "the edit is not applied")
        got = refused_edit(edit_entry("inside.txt", "inside original"), tree)
        backup = inside.with_name(inside.name + BACKUP_SUFFIX)
        kept = (tree_state(SELF_TEST_DIR) == before
                and tmp.exists() and os.stat(tmp).st_ino == planted
                and os.path.samefile(tmp, outside))
        print(f"self-test: a temporary file this run did not create is refused: "
              f"{got[1]} ({got[2]}), kept={kept}, backup left={backup.exists()}")
        if got != want or not kept or backup.exists():
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


def a_backup_refusal_removes_this_runs_temporary_file():
    """A backup planted before the edit makes the link refuse after this run
    created its temporary file: that file is removed and the caller's backup
    keeps its bytes (task 029)."""
    ok = True
    try:
        tree = refusal_tree()
        inside = tree / "inside.txt"
        inside.write_bytes(b"inside original\n")
        backup = inside.with_name(inside.name + BACKUP_SUFFIX)
        tmp = inside.with_name(inside.name + ".falsify-tmp")
        backup.write_bytes(b"a caller's backup\n")
        want = (False, "BACKUP TAKEN",
                f"{backup} is a backup this run did not create; "
                "the edit is not applied")
        got = refused_edit(edit_entry("inside.txt", "inside original"), tree)
        kept = (inside.read_bytes() == b"inside original\n"
                and backup.read_bytes() == b"a caller's backup\n")
        left = tmp.exists()
        print(f"self-test: a backup refusal removes this run's temporary file: "
              f"{got[1]} ({got[2]}), kept={kept}, temporary left={left}")
        if got != want or not kept or left:
            ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    return ok


# Each self-test case is named, so a falsifier names one and the runner runs
# it on its own. A name not listed here is not a case: the runner reports it
# as not run, never as caught.
SELF_TEST_CASES = {
    "verdict cases": verdict_cases,
    "a named test that does not run is not a catch": a_named_test_that_does_not_run_is_not_a_catch,
    "a passing test that prints a skip line is not run":
        a_passing_test_that_prints_a_skip_line_is_not_run,
    "an interrupted edit is restored": interruption_restores,
    "another lane's backup is not recovered": another_lanes_backup_is_not_recovered,
    "a killed provider edit is recovered": a_killed_provider_edit_is_recovered,
    "a runner killed in its test step is recovered":
        a_runner_killed_in_its_test_step_is_recovered,
    "an edit of a missing file is refused": an_edit_of_a_missing_file_is_refused,
    "an absolute edit path is refused": an_absolute_edit_path_is_refused,
    "an edit path that climbs out is refused": an_edit_path_that_climbs_out_is_refused,
    "an absent outside edit path gets the containment reason":
        an_absent_outside_edit_path_gets_the_containment_reason,
    "an edit through a symbolic link is refused": an_edit_through_a_symbolic_link_is_refused,
    "an entry with one outside edit changes no file":
        an_entry_with_one_outside_edit_changes_no_file,
    "a missing data file is refused": a_missing_data_file_is_refused,
    "an unreadable data file is refused": an_unreadable_data_file_is_refused,
    "an unreadable data path is refused": an_unreadable_data_path_is_refused,
    "an invalid utf8 data file is refused": an_invalid_utf8_data_file_is_refused,
    "a non-json data file is refused": a_non_json_data_file_is_refused,
    "a data document must be an object": a_data_document_must_be_an_object,
    "a data document needs a falsifiers list": a_data_document_needs_a_falsifiers_list,
    "falsifiers must be a list": falsifiers_must_be_a_list,
    "a duplicate id is refused": a_duplicate_id_is_refused,
    "an unknown command is refused": an_unknown_command_is_refused,
    "an unknown expect is refused": an_unknown_expect_is_refused,
    "an interrupt at the end of the edit is restored": interruption_at_the_end_of_the_edit,
    "the streams keep their own lines": the_streams_keep_their_own_lines,
    "a real catch counts": real_catch_counts,
    "a provider failure with stderr counts": provider_failure_with_stderr_counts,
    "a test that fails without the edit is not a catch":
        a_test_that_fails_without_the_edit_is_not_a_catch,
    "a test that passes without the edit still counts":
        a_test_that_passes_without_the_edit_still_counts,
    "an unmutated build failure is not a catch": an_unmutated_build_failure_is_not_a_catch,
    "a baseline test that cannot run is refused": a_baseline_test_that_cannot_run_is_refused,
    "a survivor requires a passing baseline": a_survivor_requires_a_passing_baseline,
    "the with-repo check holds its entries to the baseline":
        the_with_repo_check_holds_its_entries_to_the_baseline,
    "a baseline reason names failed and missing tests":
        a_baseline_reason_names_failed_and_missing_tests,
    "baseline batches chosen pairs before edits": baseline_batches_chosen_pairs_before_edits,
    "baseline checks free space before building": baseline_checks_free_space_before_building,
    "entry durations include execution": entry_durations_include_execution,
    "an unterminated failure section stays checked": an_unterminated_failure_section_stays_checked,
    "the section header is an exact line": section_header_is_an_exact_line,
    "the closing delimiter is an exact line": closing_delimiter_is_an_exact_line,
    "a section stops at its first delimiter": a_section_stops_at_its_first_delimiter,
    "every failure section is removed": every_failure_section_is_removed,
    "a loader error inside a section is not a catch":
        a_loader_error_inside_a_section_is_not_a_catch,
    "a cargo failure inside a section is not a catch":
        a_cargo_failure_inside_a_section_is_not_a_catch,
    "a self-test case counts only when it ran": a_self_test_case_counts_only_when_it_ran,
    "a survivor needs its named test to run": a_survivor_needs_its_named_test_to_run,
    "a survivor is proved by its named tests": a_survivor_is_proved_by_its_named_tests,
    "from option selects path": from_option_selects_path,
    "unknown option is refused": unknown_option_is_refused,
    "equals form is refused": equals_form_is_refused,
    "from without a path is refused": from_without_a_path_is_refused,
    "modifier only invocation is refused": modifier_only_invocation_is_refused,
    "modifiers preserve explicit selection": modifiers_preserve_explicit_selection,
    "self-test case without a name is refused": self_test_case_without_a_name_is_refused,
    "argv refusal precedes work": argv_refusal_precedes_work,
    "provider spec uses locked manifest": provider_spec_uses_locked_manifest,
    "an agent-conformance entry loads and runs its crate":
        an_agent_conformance_entry_loads_and_runs_its_crate,
    "list mode displays": list_mode_displays,
    "prefix token still selects": prefix_token_still_selects,
    "a nested list is listed": a_nested_list_is_listed,
    "a nested run keeps the caller's backup": a_nested_run_keeps_the_callers_backup,
    "released backups are recovered again": released_backups_are_recovered_again,
    "a backup this run did not make is refused": a_backup_this_run_did_not_make_is_refused,
    "a temporary file this run did not create is refused":
        a_temporary_file_this_run_did_not_create_is_refused,
    "a backup refusal removes this run's temporary file":
        a_backup_refusal_removes_this_runs_temporary_file,
}


def with_repo_check(entries, still_passing="tests::compaction_keeps_a_skill_node",
                    how_for=None):
    """The with-repo check: one real host entry run with a passing test added
    and as listed. Both entries go through one run_chosen() call, so both
    share the unmutated baseline (P11): a named test that already fails
    without the edit reads NOT RUN, never CAUGHT. Returns whether both
    checks hold."""
    real = next(entry for entry in entries
                if entry["command"] == "host" and entry["expect"] == "caught")
    added = dict(real, tests=real["tests"] + [still_passing])
    got_added, got_listed = [result for _entry, result, _duration
                             in run_chosen([added, real], how_for=how_for)]
    print(f"self-test: {real['id']} with {still_passing} added -> {got_added[1]} ({got_added[2]})")
    print(f"self-test: {real['id']} as listed -> {got_listed[1]}")
    ok = got_added[:2] == (False, "SURVIVED") and still_passing in got_added[2]
    return ok and got_listed[:2] == (True, "CAUGHT")


def self_test(entries, with_repo, only=None):
    """Run the named self-test cases, or only `only`; with the repo, also one
    real falsifier with a passing name added and as listed."""
    ok = True
    try:
        for name, case in SELF_TEST_CASES.items():
            if only is not None and name != only:
                continue
            if not case():
                print(f"self-test: {name}: FAILED")
                ok = False
    finally:
        shutil.rmtree(SELF_TEST_DIR, ignore_errors=True)
    if with_repo and only is None:
        if not with_repo_check(entries):
            ok = False
    if only is not None:
        print(case_marker(only, "OK" if ok else "FAILED"))
        return ok
    print("self-test:", "OK" if ok else "FAILED")
    return ok


def stop_on_term(*_):
    raise KeyboardInterrupt


def main(argv):
    signal.signal(signal.SIGTERM, stop_on_term)
    parsed = parse_argv(argv)
    # --keep-backups is for a self-test that runs on a mutated copy of this
    # file: the backup belongs to the caller's mutation, not to a killed run.
    if not parsed.keep_backups:
        recover_backups()
    entries = load(parsed.path)
    if parsed.mode == "list":
        for entry in entries:
            print(f"{entry['id']:6} {entry['command']:8} {entry['expect']:13} {entry['title']}")
        return 0
    if parsed.mode == "self-test-cases":
        for name in SELF_TEST_CASES:
            print(name)
        return 0
    if parsed.mode == "self-test-case":
        name = parsed.name
        if name not in SELF_TEST_CASES:
            print(f"no self-test case named {name}")
            return CASE_USAGE
        try:
            ok = self_test(entries, False, only=name)
        except BaseException as error:
            # The case did not complete, so its name must not carry a verdict.
            print(f"self-test case {name!r}: ERROR: {type(error).__name__}: {error}")
            return CASE_ERROR
        return CASE_PASSED if ok else CASE_FAILED
    if parsed.mode == "self-test":
        return 0 if self_test(entries, parsed.with_repo) else 1
    chosen = [entry for entry in entries if not parsed.filters or any(
        entry["id"] == arg or entry["id"].startswith(arg) for arg in parsed.filters)]
    if not chosen:
        print("no falsifier matches", " ".join(parsed.filters))
        return 2
    counts = {}
    bad = []
    ran_e2e = False
    stopped_for_disk = False
    try:
        for entry, (ok, word, detail), duration in run_chosen(chosen, on_baseline=print):
            ran_e2e |= entry["command"] == "e2e"
            counts[word] = counts.get(word, 0) + 1
            if not ok:
                bad.append(entry["id"])
            print(f"{entry['id']:6} {word:30} {duration:5.0f}s  {entry['title']}"
                  + (f"\n       {detail}" if detail else ""), flush=True)
    except DiskFull as error:
        stopped_for_disk = True
        print(f"stopped: disk full ({error}); every file is restored")
        if ran_e2e:
            print("the guest rebuild is deferred until there is free space; "
                  "the next e2e run builds before its tests")
        return 3
    except KeyboardInterrupt:
        print("stopped: interrupted; every file is restored")
        return 1
    finally:
        if ran_e2e and not stopped_for_disk:
            # run-e2e.sh rebuilt the guest from a mutated source; build it again.
            # A full disk cannot build, so that rebuild waits for free space.
            subprocess.run(["bash", str(HERE / "build.sh")], cwd=REPO, capture_output=True)
    print("summary:", ", ".join(f"{count} {word}" for word, count in sorted(counts.items())),
          f"of {len(chosen)}")
    if bad:
        print("not as expected:", " ".join(bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
