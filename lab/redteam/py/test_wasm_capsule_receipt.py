"""Red-team probe 003: does the wasm-capsule receipt honestly bind its artifact?

Target (owner lane wasm-capsule-lab): the wc-001 claim in
lab/wasm-capsule/README.md that `tools/build` rebuilds the capsule byte for byte
on this Mac, in different paths, and writes a receipt that names `capsule.wasm`
and `Cargo.lock` by SHA-256. That claim is the ground for "named by hash" and
for the later sign/offline-verify grade (wc-004).

Pinned when written (guard a), from `git log -1 --format='%H %s' HEAD -- <path>`
on HEAD 745fd6b27026beef6847f8f4facb95252b4a603b:
  tools/build                    5fc603e0fc8f5e29349c09c097d28738218f6ab5  PR #74 (wasm-capsule-lab/001)
  capsule/, rust-toolchain.toml  b719134ac2b5e40d653ed5efb6e7b1be40f6cf9a  PR #74
  Cargo.toml, Cargo.lock         938bc0c12f3cddceaa5fc35f73a886865df0f5a6  PR #105 (wasm-capsule-lab/007)
A failing check prints the commit it ran on, the sha256 of the tested bytes and
the exact commands, so its message is the finding's evidence.

Independent of the lane: it neither runs nor trusts the lane's Rust tests. It
drives only the committed `tools/build`, hashes with Python's hashlib and
compares the bytes itself. Each build runs from its own copy of the lane
source, at two different paths, into its own temp OUT_DIR, so a build path the
artifact embeds shows up as a byte difference. No build output is written under
lab/redteam/ or any owner tree.

Task 008 places every copy at <prefix>/lab/wasm-capsule and links
lab/capsule-identity and elastos beside it, so the lane's path dependencies
resolve. Those two trees are symlinks, not copies. A plant is refused when
its path resolves outside the wasm-capsule copy.

The lane's guards a-e live in its BACKLOG (and in lab/redteam/README.md once
task 005 lands it). The ones this probe touches:
(a) a finding pins the merged commit, the PR and the sha256 of the tested bytes;
(b) a finding goes only in lab/redteam/findings/wasm-capsule-lab-001.md, and a
    reproduced defect stays here as a test marked @unittest.expectedFailure
    naming that id, never deleted. No owner tree is edited;
(d) a SKIP is never a PASS: without rustc 1.91.0 and the wasm32 target every
    test SKIPs with the reason, and an all-skipped run is reported SKIPPED;
(e) no network (Cargo runs offline and rustup may not download a toolchain), no
    secrets, Mac toolchain only.
"""

import hashlib
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
LANE_DIR = REPO_ROOT / "lab" / "wasm-capsule"
TOOLS_BUILD = LANE_DIR / "tools" / "build"
LOCKFILE = LANE_DIR / "Cargo.lock"

FINDING_ID = "wasm-capsule-lab-001"
PINNED = "tools/build 5fc603e0fc8f5e29349c09c097d28738218f6ab5, PR #74 (wasm-capsule-lab/001)"

RUSTC_RELEASE = "rustc 1.91.0 "
TARGET = "wasm32-unknown-unknown"
QUERY_TIMEOUT_S = 120
BUILD_TIMEOUT_S = 900

# Guard e: Cargo stays offline, and rustup may not download a toolchain that the
# lane's rust-toolchain.toml names but this Mac lacks.
NO_NETWORK = {"CARGO_NET_OFFLINE": "true", "RUSTUP_AUTO_INSTALL": "0"}

# The build outputs the lane's own .gitignore names: never copied as source.
BUILD_OUTPUTS = ("target", "capsule.wasm", "receipt.txt")

# Where each copy of the lane sits in its own temp dir: <prefix>/lab/wasm-capsule.
# The prefixes differ in depth, length and a space (`a`, and `copy b/with a
# space`), so an absolute build path embedded in the artifact makes the two
# builds differ (the owner's own falsifier F-WC1 is such a bug). build_copy
# links lab/capsule-identity and elastos beside the copy; it does not copy them.
COPY_PATHS = (
    "a/lab/wasm-capsule",
    "copy b/with a space/lab/wasm-capsule",
)

# git status --porcelain of these three trees must stay empty: a plant and a
# real-tree build write only under a temp root.
REAL_TREES = ("lab/wasm-capsule", "lab/capsule-identity", "elastos")

# Edit.apply refuses a path that resolves outside the wasm-capsule copy.
# Traversal and a symlink that leaves the copy share this one reason.
PLANT_ESCAPE = "refused: plant escapes the wasm-capsule copy"

RECEIPT_SCHEMA = "wc-001.receipt/v1"
RECEIPT_KEYS = (
    "schema",
    "artifact",
    "artifact_sha256",
    "rustc_version",
    "target",
    "lockfile_sha256",
    "source_date_epoch",
)
WASM_HEADER = b"\0asm\x01\0\0\0"


def sha256_file(path):
    """The lowercase hex SHA-256 of a file, by Python's hashlib (no system tool, no Rust)."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build_env():
    return dict(os.environ, **NO_NETWORK)


def decoded(output):
    """Captured process output as text. A timeout hands it back as bytes."""
    if isinstance(output, bytes):
        return output.decode(errors="replace")
    return output or ""


class ToolchainAbsent(Exception):
    """rustc 1.91.0 or the wasm32 target is missing: every test SKIPs with this reason."""


def query_rustc(rustc, *args, absent):
    """One rustc query, run where tools/build runs it: from the lane root, so the
    lane's rust-toolchain.toml picks the compiler."""
    argv = [rustc, *args]
    try:
        proc = subprocess.run(
            argv,
            cwd=LANE_DIR,
            env=build_env(),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=QUERY_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ToolchainAbsent(f"{absent} is absent: {shlex.join(argv)} failed: {error}") from None
    if proc.returncode != 0:
        raise ToolchainAbsent(
            f"{absent} is absent: {shlex.join(argv)} exited {proc.returncode}: {proc.stderr.strip()}"
        )
    return proc.stdout.strip()


def detect_toolchain():
    """The `rustc --version` line tools/build will record, or ToolchainAbsent naming
    what is missing. tools/build compiles with `${RUSTC:-rustc}`, so ask that one.
    A missing tools/build is the probe's own error, never a SKIP."""
    if not TOOLS_BUILD.is_file():
        raise FileNotFoundError(f"no {TOOLS_BUILD}: the probe has nothing to build")
    rustc = os.environ.get("RUSTC", "rustc")
    version = query_rustc(rustc, "--version", absent="rustc 1.91.0")
    if not version.startswith(RUSTC_RELEASE):
        raise ToolchainAbsent(f"rustc 1.91.0 is absent: {rustc} is {version!r}")
    sysroot = query_rustc(rustc, "--print", "sysroot", absent=f"the {TARGET} target")
    target_lib = Path(sysroot, "lib", "rustlib", TARGET, "lib")
    if not target_lib.is_dir():
        raise ToolchainAbsent(f"the {TARGET} target is absent: no {target_lib} for {version}")
    return version


@dataclass(frozen=True)
class Edit:
    """One planted change to a file of a lane copy, never of the owner tree."""

    file: str
    old: str
    new: str

    def apply(self, lane):
        """Replace `old` with `new` in one file inside `lane`.

        The file must resolve inside `lane`. `..` and a symlink that leaves
        the copy both resolve outside it, and both are refused with
        PLANT_ESCAPE before any read or write.
        """
        root = Path(lane).resolve()
        # One check: the resolved path, after `..` and symlinks, stays inside
        # the copy. An absolute path replaces `root` on join, so it fails here too.
        resolved = (root / self.file).resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            raise ValueError(f"{PLANT_ESCAPE}: {self.file} resolves outside {root}") from None
        text = resolved.read_text()
        if text.count(self.old) != 1:
            raise ValueError(
                f"stale plant: {self.file} holds {text.count(self.old)} copies of "
                f"{self.old!r}, not exactly one"
            )
        resolved.write_text(text.replace(self.old, self.new))


@dataclass(frozen=True)
class Build:
    """One finished run of a lane copy's tools/build."""

    source: Path  # the copy's lane root
    out: Path  # the OUT_DIR given to tools/build
    command: str  # the exact command, for a finding

    @property
    def wasm(self):
        return self.out / "capsule.wasm"

    @property
    def receipt(self):
        return self.out / "receipt.txt"


class BuildFailed(Exception):
    """tools/build exited non-zero or timed out. It is raised from setUpClass, so
    it is an ERROR of the run: never a SKIP, and never absorbed by an
    expectedFailure marker on a probe test."""


def linked_deps(source):
    """Validate the copy layout and return its capsule-identity and elastos paths."""
    source = Path(source)
    if source.name != "wasm-capsule" or source.parent.name != "lab":
        raise ValueError(f"copy path must end in lab/wasm-capsule: {source}")
    prefix = source.parent.parent
    return prefix / "lab" / "capsule-identity", prefix / "elastos"


def assert_linked_layout(test, source):
    """The wasm-capsule tree is a real copy; the two path deps are symlinks."""
    identity, elastos = linked_deps(source)
    test.assertFalse(source.is_symlink(), f"{source} must be a real copy, not a link")
    for link, target in (
        (identity, REPO_ROOT / "lab" / "capsule-identity"),
        (elastos, REPO_ROOT / "elastos"),
    ):
        test.assertTrue(link.is_symlink(), f"{link} must be a symlink, not a copy")
        test.assertEqual(link.resolve(), target.resolve(), link)


def _run_tools_build(root, source):
    """The one tools/build driver. Output goes to root/out, never the lane tree."""
    out = root / "out"
    argv = [str(source / "tools" / "build"), str(out)]
    command = shlex.join(["env", *(f"{key}={value}" for key, value in NO_NETWORK.items()), *argv])
    try:
        proc = subprocess.run(
            argv,
            cwd=root,
            env=build_env(),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=BUILD_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as error:
        raise BuildFailed(
            f"{command}\ntimed out after {BUILD_TIMEOUT_S} s\n--- stderr ---\n{decoded(error.stderr)}"
        ) from None
    if proc.returncode != 0:
        detail = proc.stderr or ""
        if proc.stdout:
            detail = f"{detail}\n--- stdout ---\n{proc.stdout}"
        raise BuildFailed(f"{command}\nexited {proc.returncode}\n--- stderr ---\n{detail}")
    return Build(source, out, command)


def build_copy(root, copy_path, plant, *, links=True, copy=True):
    """Copy the lane to root/copy_path, link its path deps, plant, and build.

    The copy is <root>/<prefix>/lab/wasm-capsule. <prefix> is everything in
    copy_path before `lab/wasm-capsule` (`a`, or `copy b/with a space`).
    <root>/<prefix>/lab/capsule-identity and <root>/<prefix>/elastos are
    symlinks to the repo trees. `links=False` omits both symlinks, so
    tools/build fails closed. `copy=False` builds the real lane with this
    same driver and applies no plant.
    """
    if not copy:
        if plant:
            raise ValueError("plants write only inside a wasm-capsule copy")
        if not links:
            raise ValueError("omitting links applies to a copy, not the real lane")
        return _run_tools_build(root, LANE_DIR)

    relative = Path(copy_path)
    if relative.is_absolute():
        raise ValueError(f"copy path must be relative: {copy_path}")
    source = root / relative
    identity, elastos = linked_deps(source)
    shutil.copytree(LANE_DIR, source, ignore=shutil.ignore_patterns(*BUILD_OUTPUTS))
    if links:
        identity.symlink_to(
            (REPO_ROOT / "lab" / "capsule-identity").resolve(), target_is_directory=True
        )
        elastos.symlink_to((REPO_ROOT / "elastos").resolve(), target_is_directory=True)
    for edit in plant:
        edit.apply(source)
    return _run_tools_build(root, source)


def parse_receipt(text):
    """The receipt's fields. Refuses anything but one `key: value` per line, each
    key once, exactly the wc-001.receipt/v1 keys, under that schema."""
    fields = {}
    for number, line in enumerate(text.splitlines(), start=1):
        key, sep, value = line.partition(": ")
        if not (key and sep and value):
            raise ValueError(f"line {number} is not `key: value`: {line!r}")
        if key in fields:
            raise ValueError(f"line {number} repeats {key!r}")
        fields[key] = value
    missing = [key for key in RECEIPT_KEYS if key not in fields]
    unknown = [key for key in fields if key not in RECEIPT_KEYS]
    if missing or unknown:
        raise ValueError(f"missing keys {missing}, unknown keys {unknown}")
    if fields["schema"] != RECEIPT_SCHEMA:
        raise ValueError(f"schema is {fields['schema']!r}, not {RECEIPT_SCHEMA!r}")
    return fields


def git(*args):
    """One line of git output from this repo, or why it is unknown."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(REPO_ROOT), *args],
            capture_output=True,
            text=True,
            timeout=QUERY_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"unknown ({error})"
    if proc.returncode != 0:
        return f"unknown ({proc.stderr.strip()})"
    return proc.stdout.strip()


def evidence(builds):
    """What turns a failed check into finding wasm-capsule-lab-001 (guards a, b)."""
    lines = [
        f"finding {FINDING_ID} (owner lane wasm-capsule-lab); an integrity finding, not CRITICAL",
        f"probe ran on HEAD {git('rev-parse', 'HEAD')}",
        "tools/build last changed in "
        + git("log", "-1", "--format=%H %s", "HEAD", "--", "lab/wasm-capsule/tools/build"),
        f"pinned when the probe was written: {PINNED}",
        "local changes under lab/wasm-capsule: "
        + (git("status", "--porcelain", "--", "lab/wasm-capsule") or "none"),
        f"tested bytes: tools/build sha256 {sha256_file(TOOLS_BUILD)}, "
        f"Cargo.lock sha256 {sha256_file(LOCKFILE)}",
        "each build ran from a copy of lab/wasm-capsule without its build outputs:",
    ]
    lines += [f"  {build.command}" for build in builds]
    return "\n".join(lines)


class WasmCapsuleReceiptProbe(unittest.TestCase):
    """Builds the committed lane twice, from copies at two paths, and checks the
    receipt and the bytes with nothing from the lane but tools/build."""

    # Edits planted in both copies before they build. Always empty for the
    # probe, which builds the lane as committed; run_probe() sets it only for the
    # falsifiers and the forced build failure.
    plant = ()

    @classmethod
    def setUpClass(cls):
        cls.builds = ()
        try:
            cls.rustc_version = detect_toolchain()
        except ToolchainAbsent as absent:
            cls.skip_reason = str(absent)
            return
        cls.skip_reason = None
        builds = []
        for copy_path in COPY_PATHS:
            root = Path(tempfile.mkdtemp(prefix="redteam-003-"))
            cls.addClassCleanup(shutil.rmtree, root, ignore_errors=True)
            builds.append(build_copy(root, copy_path, cls.plant))
        cls.builds = tuple(builds)

    def setUp(self):
        if self.skip_reason:
            self.skipTest(self.skip_reason)
        # Without both builds every loop below would pass on nothing.
        self.assertEqual(len(self.builds), 2, "both builds must exist")

    def read_receipt(self, build):
        try:
            return parse_receipt(build.receipt.read_text())
        except ValueError as error:
            self.fail(
                f"{build.receipt} is not a {RECEIPT_SCHEMA} receipt: {error}\n{evidence(self.builds)}"
            )

    def test_toolchain_present_or_skip(self):
        # setUp has SKIPped this and every other test if the toolchain is absent.
        # Present: the receipts name the very compiler the check found, so the
        # SKIP decision looks at the compiler tools/build really uses.
        self.assertTrue(self.rustc_version.startswith(RUSTC_RELEASE), self.rustc_version)
        for build in self.builds:
            self.assertEqual(
                self.read_receipt(build)["rustc_version"],
                self.rustc_version,
                f"{build.command}: the receipt names another compiler",
            )

    def test_build_produces_capsule_and_receipt(self):
        # The control. tools/build exited 0: setUpClass raises BuildFailed, with
        # the captured stderr, on any other exit.
        committed = sha256_file(TOOLS_BUILD)
        for build in self.builds:
            self.assertEqual(
                sha256_file(build.source / "tools" / "build"),
                committed,
                f"{build.command}: the copy must run the committed tools/build unchanged",
            )
            self.assertTrue(build.receipt.is_file(), f"{build.command} wrote no receipt.txt")
            self.assertTrue(build.wasm.is_file(), f"{build.command} wrote no capsule.wasm")
            self.assertEqual(
                build.wasm.read_bytes()[: len(WASM_HEADER)],
                WASM_HEADER,
                f"{build.command}: capsule.wasm is not a core wasm module",
            )

    def test_receipt_artifact_sha256_matches_independent_sha256(self):
        for build in self.builds:
            receipt = self.read_receipt(build)
            self.assertEqual(
                receipt["artifact"], "capsule.wasm", f"{build.receipt} names another artifact"
            )
            observed = sha256_file(build.wasm)
            if observed != receipt["artifact_sha256"]:
                self.fail(
                    "the receipt does not name the bytes it ships ('named by hash' is broken)\n"
                    f"  claimed  artifact_sha256 {receipt['artifact_sha256']} in {build.receipt}\n"
                    f"  observed sha256          {observed} of {build.wasm}\n"
                    f"{evidence(self.builds)}"
                )

    def test_receipt_lockfile_sha256_matches_independent_sha256(self):
        observed = sha256_file(LOCKFILE)
        for build in self.builds:
            claimed = self.read_receipt(build)["lockfile_sha256"]
            if observed != claimed:
                self.fail(
                    "the receipt does not name the committed lockfile\n"
                    f"  claimed  lockfile_sha256 {claimed} in {build.receipt}\n"
                    f"  observed sha256          {observed} of {LOCKFILE}\n"
                    f"{evidence(self.builds)}"
                )

    def test_two_builds_in_different_paths_are_byte_identical(self):
        first, second = self.builds
        self.assertNotEqual(first.source, second.source, "the two copies must sit at different paths")
        a, b = first.wasm.read_bytes(), second.wasm.read_bytes()
        if a != b:
            at = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
            self.fail(
                "two builds in different paths differ (the build did not reproduce)\n"
                f"  {first.wasm}: sha256 {hashlib.sha256(a).hexdigest()}, {len(a)} bytes\n"
                f"  {second.wasm}: sha256 {hashlib.sha256(b).hexdigest()}, {len(b)} bytes\n"
                f"  first difference at byte {at}\n"
                f"{evidence(self.builds)}"
            )

    def test_linked_copy_matches_a_build_of_the_real_tree(self):
        # The linked layout must not change the artifact. One tools/build of the
        # real lane, into a temp OUT_DIR, matches the first linked copy byte
        # for byte. A mismatch means the layout changed the capsule.
        for build in self.builds:
            assert_linked_layout(self, build.source)
        lane_root = LANE_DIR.resolve()
        side_effects = _lane_side_effects()
        root = Path(tempfile.mkdtemp(prefix="redteam-008-real-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        real = build_copy(root, COPY_PATHS[0], (), copy=False)
        self.assertEqual(real.source.resolve(), lane_root)
        try:
            real.out.resolve().relative_to(lane_root)
        except ValueError:
            wrote_into_lane = False
        else:
            wrote_into_lane = True
        self.assertFalse(wrote_into_lane, f"{real.out} is inside {lane_root}")
        self.assertEqual(_lane_side_effects(), side_effects)
        self.assertEqual(git("status", "--porcelain", "--", *REAL_TREES), "")
        first = self.builds[0]
        a, b = first.wasm.read_bytes(), real.wasm.read_bytes()
        if a != b:
            at = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
            self.fail(
                "the linked copy does not match a build of the real tree "
                "(the layout changed the artifact)\n"
                f"  copy {first.wasm}: sha256 {hashlib.sha256(a).hexdigest()}, {len(a)} bytes\n"
                f"  real {real.wasm}: sha256 {hashlib.sha256(b).hexdigest()}, {len(b)} bytes\n"
                f"  first difference at byte {at}\n"
                f"  copy command: {first.command}\n"
                f"  real command: {real.command}\n"
                f"probe ran on HEAD {git('rev-parse', 'HEAD')}\n"
                "local changes under the real trees: "
                + (git("status", "--porcelain", "--", *REAL_TREES) or "none")
            )


def _lane_side_effects():
    """Bytes of the lane outputs tools/build would write if OUT_DIR were the lane."""
    found = {}
    for name in ("capsule.wasm", "receipt.txt"):
        path = LANE_DIR / name
        found[name] = path.read_bytes() if path.is_file() else None
    found["target"] = (LANE_DIR / "target").exists()
    return found


# Every probe test, and the three whose failure would be a finding.
PROBE_TESTS = tuple(unittest.TestLoader().getTestCaseNames(WasmCapsuleReceiptProbe))
INTEGRITY_TESTS = (
    "test_receipt_artifact_sha256_matches_independent_sha256",
    "test_receipt_lockfile_sha256_matches_independent_sha256",
    "test_two_builds_in_different_paths_are_byte_identical",
)


@dataclass(frozen=True)
class Falsifier:
    """A planted bug, applied to both copies. Caught only when every named probe
    test fails at the assertion that names the broken claim (`reason`): a build
    error, a skip or a failure for another reason is not a catch."""

    id: str
    title: str
    plant: tuple
    tests: tuple
    reason: str


F_ARTIFACT_HASH = Falsifier(
    "F-RT003-ARTIFACT-HASH",
    "tools/build records the lockfile hash in place of the artifact hash",
    (
        Edit(
            "tools/build",
            'ARTIFACT_SHA="$(sha256 "$OUT_DIR/capsule.wasm")"',
            'ARTIFACT_SHA="$(sha256 "$LANE_DIR/Cargo.lock")"',
        ),
    ),
    ("test_receipt_artifact_sha256_matches_independent_sha256",),
    "the receipt does not name the bytes it ships",
)
F_LOCK_HASH = Falsifier(
    "F-RT003-LOCK-HASH",
    "tools/build records the artifact hash in place of the lockfile hash",
    (
        Edit(
            "tools/build",
            'LOCK_SHA="$(sha256 "$LANE_DIR/Cargo.lock")"',
            'LOCK_SHA="$(sha256 "$OUT_DIR/capsule.wasm")"',
        ),
    ),
    ("test_receipt_lockfile_sha256_matches_independent_sha256",),
    "the receipt does not name the committed lockfile",
)
NO_STD = '#![cfg_attr(target_arch = "wasm32", no_std)]\n'
F_BUILD_PATH = Falsifier(
    "F-RT003-BUILD-PATH",
    "the capsule embeds its absolute source path (the bug the owner's F-WC1 plants)",
    (
        Edit(
            "capsule/src/lib.rs",
            NO_STD,
            NO_STD + '\n#[cfg(target_arch = "wasm32")]\n#[used]\n'
            'static BUILD_DIR: &str = env!("CARGO_MANIFEST_DIR");\n',
        ),
    ),
    ("test_two_builds_in_different_paths_are_byte_identical",),
    "two builds in different paths differ",
)
F_REAL_TREE = Falsifier(
    "F-RT008-REAL-TREE",
    "a source plant makes the linked copy differ from the real tree",
    F_BUILD_PATH.plant,
    ("test_linked_copy_matches_a_build_of_the_real_tree",),
    "the linked copy does not match a build of the real tree",
)

FORCED_EXIT = "planted: tools/build exits 3 before it builds"
BUILD_FAILS = (
    Edit(
        "tools/build",
        "set -euo pipefail\n",
        f"set -euo pipefail\necho '{FORCED_EXIT}' >&2\nexit 3\n",
    ),
)


def as_recorded_finding(test):
    """A copy of a probe test marked the way guard b keeps a reproduced defect.
    A copy, so the probe's own test is never marked."""

    def marked(self):
        return test(self)

    return unittest.expectedFailure(marked)


def run_probe(tests, plant=(), recorded=()):
    """Run the named probe tests the way the gate's runner does, in a fresh
    subclass whose two copies carry `plant`. Tests named in `recorded` are marked
    @unittest.expectedFailure, as a recorded finding would be."""
    attrs = {"plant": tuple(plant)}
    for name in recorded:
        attrs[name] = as_recorded_finding(getattr(WasmCapsuleReceiptProbe, name))
    probe = type("PlantedProbe", (WasmCapsuleReceiptProbe,), attrs)
    result = unittest.TestResult()
    unittest.TestSuite(probe(name) for name in tests).run(result)
    return probe, result


def fake_rustc(path, version, sysroot):
    """A stand-in rustc that reports `version` and `sysroot` and builds nothing."""
    path.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        f"  --version) echo '{version}' ;;\n"
        f"  --print) echo '{sysroot}' ;;\n"
        "  *) echo 'this fake rustc builds nothing' >&2; exit 1 ;;\n"
        "esac\n"
    )
    path.chmod(0o755)
    return path


class WasmCapsuleReceiptProbeChecks(unittest.TestCase):
    """The probe's own falsifiers and fail-closed checks."""

    @classmethod
    def setUpClass(cls):
        try:
            detect_toolchain()
        except ToolchainAbsent as absent:
            cls.skip_reason = str(absent)
        else:
            cls.skip_reason = None

    def setUp(self):
        # The link falsifier and the plant boundary do not need a finished
        # wasm artifact. Skipping either one would hide a broken layout.
        if self.skip_reason and self._testMethodName not in (
            "test_falsifier_missing_links_is_caught",
            "test_plant_does_not_write_the_real_trees",
            "test_invalid_copy_paths_are_refused_before_copying",
        ):
            self.skipTest(self.skip_reason)

    def assert_caught(self, falsifier):
        _, result = run_probe(falsifier.tests, plant=falsifier.plant)
        label = f"{falsifier.id} ({falsifier.title})"
        self.assertEqual(result.errors, [], f"{label}: a build error is not a catch")
        self.assertEqual(result.skipped, [], f"{label}: a skip is not a catch")
        self.assertEqual(result.expectedFailures + result.unexpectedSuccesses, [], label)
        failed = sorted({test._testMethodName for test, _ in result.failures})
        self.assertEqual(failed, sorted(falsifier.tests), f"{label}: every named test must fail")
        for test, text in result.failures:
            self.assertIn(
                falsifier.reason, text, f"{label}: {test._testMethodName} failed for another reason"
            )
        self.assertEqual(result.testsRun, len(falsifier.tests), label)

    def test_falsifier_artifact_hash_is_caught(self):
        self.assert_caught(F_ARTIFACT_HASH)

    def test_falsifier_lockfile_hash_is_caught(self):
        self.assert_caught(F_LOCK_HASH)

    def test_falsifier_build_path_is_caught(self):
        self.assert_caught(F_BUILD_PATH)

    def test_falsifier_real_tree_match_is_caught_then_restored(self):
        # Reuse the existing source plant, but require the real-tree comparison
        # itself to fail. Fresh unplanted copies must then pass that same test.
        self.assert_caught(F_REAL_TREE)
        _, restored = run_probe(F_REAL_TREE.tests)
        self.assertEqual(restored.testsRun, len(F_REAL_TREE.tests))
        self.assertEqual(restored.errors + restored.failures, [])
        self.assertEqual(restored.skipped, [], "the restored comparison must run")
        self.assertEqual(restored.expectedFailures + restored.unexpectedSuccesses, [])
        self.assertTrue(restored.wasSuccessful())

    def test_invalid_copy_paths_are_refused_before_copying(self):
        root = Path("/review")
        module = sys.modules[__name__]
        with mock.patch.object(shutil, "copytree") as copier, mock.patch.object(
            module, "_run_tools_build"
        ) as builder:
            for relative in (
                "", "lab/wrong", "wrong/wasm-capsule", "wasm-capsule",
                "lab/wasm-capsule/extra",
            ):
                source = root / relative
                reason = f"copy path must end in lab/wasm-capsule: {source}"
                with self.subTest(entry="linked_deps", path=relative):
                    with self.assertRaises(ValueError) as caught:
                        linked_deps(source)
                    self.assertEqual(str(caught.exception), reason)
                for links in (True, False):
                    with self.subTest(entry="build_copy", path=relative, links=links):
                        with self.assertRaises(ValueError) as caught:
                            build_copy(root, relative, (), links=links)
                        self.assertEqual(str(caught.exception), reason)
            for links in (True, False):
                with self.subTest(path="absolute", links=links):
                    with self.assertRaises(ValueError) as caught:
                        build_copy(root, "/review/lab/wasm-capsule", (), links=links)
                    self.assertEqual(
                        str(caught.exception),
                        "copy path must be relative: /review/lab/wasm-capsule",
                    )
            copier.assert_not_called()
            builder.assert_not_called()

    def test_build_failure_remains_failure(self):
        # Every integrity test is marked as a recorded finding, and still a build
        # that exits 3 is one ERROR carrying its stderr: no accepted finding, no
        # skip, no pass.
        _, result = run_probe(PROBE_TESTS, plant=BUILD_FAILS, recorded=INTEGRITY_TESTS)
        self.assertEqual(result.testsRun, 0, "no probe test may run on a failed build")
        self.assertEqual(result.expectedFailures, [], "a build error must not count as a finding")
        self.assertEqual(result.skipped, [], "a build error must not count as a skip")
        self.assertEqual(result.failures + result.unexpectedSuccesses, [])
        self.assertEqual(len(result.errors), 1, result.errors)
        where, text = result.errors[0]
        self.assertIn("setUpClass", str(where))
        self.assertIn("tools/build", text)
        self.assertIn("exited 3", text)
        self.assertIn(FORCED_EXIT, text, "the error must carry the captured stderr")
        self.assertFalse(result.wasSuccessful())

    def test_missing_toolchain_skips_every_probe_test(self):
        with tempfile.TemporaryDirectory(prefix="redteam-003-rustc-") as tmp:
            tmp = Path(tmp)
            cases = (
                (tmp / "no-such-rustc", "rustc 1.91.0 is absent"),
                (
                    fake_rustc(tmp / "rustc-1.90", "rustc 1.90.0 (fake 2025-09-14)", tmp),
                    "rustc 1.91.0 is absent",
                ),
                (
                    fake_rustc(tmp / "rustc-no-wasm32", "rustc 1.91.0 (fake 2025-10-28)", tmp),
                    f"the {TARGET} target is absent",
                ),
            )
            for rustc, absent in cases:
                with self.subTest(rustc=rustc.name):
                    with mock.patch.dict(os.environ, {"RUSTC": str(rustc)}):
                        probe, result = run_probe(PROBE_TESTS)
                    reasons = [reason for _, reason in result.skipped]
                    self.assertEqual(result.testsRun, len(PROBE_TESTS))
                    self.assertEqual(len(reasons), len(PROBE_TESTS), "every probe test must SKIP")
                    self.assertEqual(len(set(reasons)), 1, reasons)
                    self.assertIn(absent, reasons[0])
                    self.assertEqual(result.failures + result.errors, [])
                    self.assertEqual(result.expectedFailures + result.unexpectedSuccesses, [])
                    self.assertEqual(probe.builds, (), "nothing may build without the toolchain")

    def test_missing_target_is_an_error_not_a_skip(self):
        # Without lab/wasm-capsule the probe has nothing to build. That is one
        # ERROR naming the missing file, never a SKIP that blames the toolchain.
        lane = REPO_ROOT / "lab" / "no-such-wasm-capsule"
        module = sys.modules[__name__]
        with mock.patch.object(module, "LANE_DIR", lane), mock.patch.object(
            module, "TOOLS_BUILD", lane / "tools" / "build"
        ):
            _, result = run_probe(PROBE_TESTS)
        self.assertEqual(result.testsRun, 0)
        self.assertEqual(result.skipped, [], "a missing target must not count as a skip")
        self.assertEqual(len(result.errors), 1, result.errors)
        self.assertIn(str(lane / "tools" / "build"), result.errors[0][1])

    def test_falsifier_missing_links_is_caught(self):
        # The same build_copy, with the two links omitted. tools/build must
        # fail, and BuildFailed must name the missing path. A skip, a pass,
        # or an expectedFailure on that build is not a catch.
        method = getattr(type(self), "test_falsifier_missing_links_is_caught")
        self.assertFalse(getattr(method, "__unittest_expecting_failure__", False))
        root = Path(tempfile.mkdtemp(prefix="redteam-008-nolink-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        source = root / COPY_PATHS[0]
        identity, elastos = linked_deps(source)
        missing = identity / "Cargo.toml"
        try:
            build_copy(root, COPY_PATHS[0], (), links=False)
        except BuildFailed as error:
            message = str(error)
        else:
            self.fail("tools/build passed without the path links; the falsifier was not caught")
        self.assertTrue(source.joinpath("tools", "build").is_file(), "the copy must still be laid out")
        self.assertFalse(identity.exists(), identity)
        self.assertFalse(elastos.exists(), elastos)
        self.assertFalse(identity.is_symlink(), identity)
        self.assertFalse(elastos.is_symlink(), elastos)
        canonical = identity.parent.resolve() / identity.name / "Cargo.toml"
        named = [str(missing), str(canonical)]
        self.assertTrue(
            any(path in message for path in named),
            f"BuildFailed must name the missing path ({named}):\n{message}",
        )

    def test_plant_does_not_write_the_real_trees(self):
        # An ordinary plant edits a file inside the copy. Traversal and a
        # symlink that leave the copy are refused, and their sentinel bytes
        # stay put. The real lane, capsule-identity and elastos stay clean.
        self.assertEqual(git("status", "--porcelain", "--", *REAL_TREES), "")
        watched = (
            LANE_DIR / "tools" / "build",
            REPO_ROOT / "lab" / "capsule-identity" / "Cargo.toml",
            REPO_ROOT / "elastos" / "Cargo.toml",
        )
        before = {path: path.read_bytes() for path in watched}
        root = Path(tempfile.mkdtemp(prefix="redteam-008-plant-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        source = root / COPY_PATHS[0]
        with self.assertRaises(BuildFailed) as caught:
            build_copy(root, COPY_PATHS[0], BUILD_FAILS)
        self.assertIn(FORCED_EXIT, str(caught.exception))
        self.assertIn(FORCED_EXIT, (source / "tools" / "build").read_text())
        self.assertNotIn(FORCED_EXIT, before[LANE_DIR / "tools" / "build"].decode())
        assert_linked_layout(self, source)
        for path, original in before.items():
            self.assertEqual(path.read_bytes(), original, path)

        self._assert_escape_refused(source, root / "traversal-sentinel.txt", traversal=True)
        self._assert_escape_refused(source, root / "symlink-sentinel.txt", traversal=False)
        outside = root / "outside-dir"
        outside.mkdir()
        nested = outside / "sentinel.txt"
        nested.write_bytes(b"disposable-sentinel\n")
        (source / "out-link").symlink_to(outside)
        with self.subTest(escape="directory symlink"):
            self._refuse(source, "out-link/sentinel.txt", nested)

        for path, original in before.items():
            self.assertEqual(path.read_bytes(), original, path)
        status = git("status", "--porcelain", "--", *REAL_TREES)
        self.assertEqual(status, "", status)

    def _assert_escape_refused(self, source, sentinel, *, traversal):
        sentinel.write_bytes(b"disposable-sentinel\n")
        if traversal:
            relative = os.path.relpath(sentinel, source)
            self.assertIn("..", Path(relative).parts, relative)
            label = "traversal"
        else:
            link = source / "sentinel-link"
            link.symlink_to(sentinel)
            relative = "sentinel-link"
            self.assertTrue(link.is_symlink())
            label = "symlink"
        with self.subTest(escape=label):
            self._refuse(source, relative, sentinel)

    def _refuse(self, lane, relative, sentinel):
        original = sentinel.read_bytes()
        message = ""
        try:
            Edit(relative, "disposable-sentinel", "CHANGED-SENTINEL").apply(lane)
        except ValueError as error:
            message = str(error)
        self.assertEqual(sentinel.read_bytes(), original, relative)
        self.assertTrue(
            message.startswith(PLANT_ESCAPE + ":"),
            message or f"plant was not refused: {relative}",
        )


if __name__ == "__main__":
    unittest.main()
