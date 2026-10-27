"""Red-team probe 016: verify_bundle refuses a module swapped after signing.

Target (owner lane wasm-capsule-lab): the wc-004 sign and offline-verify
claim. Tasks 003 and 007 check that tools/build writes a receipt whose
artifact hash matches the module it just built. They never call verify_bundle.
This probe calls that public function from a test that exists only in a temp
copy, so a pass here is not a re-run of the owner's suite.

The temp copy is laid out by lay_copy. The probe does not build the guest and
does not define another verifier. Cargo runs offline. The test key is
SigningKey::generate with OsRng inside the temp test. Nothing prints the key
or the signature, and nothing writes a key file.

Pinned from this checkout (guard a), with
`git log -1 --format='%H %s' HEAD -- lab/wasm-capsule/tools/src/verify.rs`,
`shasum -a 256` of that file, and the merge commit of PR #279:
  verify.rs   c0a80c0378f3ec38bf109760d54e73471679e11a
  PR #279     b8c1dcedbbbec3731cbb5008b0798995dfb854a9
  sha256      888878b2573de0135c3571ef485a590873e50f04d00c56d7eaf57104a40a3aaa
The clean line names the HEAD this process reads. A missing rustc 1.91.0
prints SKIPPED and skips the cargo tests. Any other stop of the unplanted
test is an ERROR. An accepted swap on the pinned file is a finding at
lab/redteam/findings/wasm-capsule-lab-003.md. With no accept, that file is
not written.

Guards this probe touches:
(a) the pin above, and the finding's first line carries the same commit,
    PR #279 and sha256;
(b) a finding goes only in that file. expectedFailure is only for a recorded
    accept whose docstring names the file;
(d) a SKIP is never a PASS. The skip line is `SKIPPED:`;
(e) no network, no secrets, Mac toolchain only.
"""

import os
import shlex
import signal
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from test_wasm_capsule_receipt import (
    REAL_TREES,
    RUSTC_RELEASE,
    Edit,
    ToolchainAbsent,
    assert_linked_layout,
    build_env,
    git,
    lay_copy,
    query_rustc,
    report_skip,
    sha256_file,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
VERIFY_REL = "lab/wasm-capsule/tools/src/verify.rs"
VERIFY_RS = REPO_ROOT / VERIFY_REL
FINDING_ID = "wasm-capsule-lab-003"
FINDING = REPO_ROOT / "lab" / "redteam" / "findings" / f"{FINDING_ID}.md"

# Measured on this checkout. A different digest fails test_pin_matches_verify_rs.
PINNED_VERIFY_COMMIT = "c0a80c0378f3ec38bf109760d54e73471679e11a"
PINNED_PR_MERGE = "b8c1dcedbbbec3731cbb5008b0798995dfb854a9"
PINNED_VERIFY_SHA256 = "888878b2573de0135c3571ef485a590873e50f04d00c56d7eaf57104a40a3aaa"

COPY_PATH = "swap/lab/wasm-capsule"
VERIFY_LEAF = "tools/src/verify.rs"
CARGO_TIMEOUT_S = 900

# F-WC4a, the one line in tools/src/verify.rs. Applied only in the temp copy.
SIGNATURE_LINE = (
    "    verify_checked_signature(&checked, signature, accepted)"
    ".map_err(VerifyRefusal::Identity)?;\n"
)
TRUSTED_LINE = "    let _trusted_name = &signature.name;\n"
F_WC4A = Edit(VERIFY_LEAF, SIGNATURE_LINE, TRUSTED_LINE)

# --show-output is what puts a passing test's refusal line on cargo's stdout.
# The other arguments are the probe's cargo invocation.

SWAP_RS = """\
//! Temp probe. Calls wasm_capsule_tools::verify::verify_bundle on a module
//! swapped after signing. It does not define a verifier and it does not call
//! audit. The key and the signature stay in memory.

use capsule_identity::{sign_bundle, NameSignature};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;
use std::path::{Path, PathBuf};
use wasm_capsule_tools::verify::{verify_bundle, DeclaredImport};
use wasm_capsule_tools::CAPSULE_MANIFEST;

/// The eight bytes `00 61 73 6d 01 00 00 00`.
const MODULE: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

/// The same module plus a custom section named `n` whose data is `hi`.
const SWAPPED: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x6e, 0x68, 0x69,
];

struct RemoveDir(PathBuf);

impl Drop for RemoveDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl RemoveDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

fn prepare() -> RemoveDir {
    let dir = match std::env::var_os("REDTEAM_BUNDLE_DIR") {
        Some(value) => PathBuf::from(value),
        None => std::env::temp_dir().join(format!("redteam-016-{}", std::process::id())),
    };
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap_or_else(|error| {
        panic!("could not create the bundle directory: {error}");
    });
    fs::write(dir.join("capsule.json"), CAPSULE_MANIFEST).expect("write capsule.json");
    fs::write(dir.join("capsule.wasm"), MODULE).expect("write capsule.wasm");
    RemoveDir(dir)
}

fn sign(dir: &Path) -> NameSignature {
    let key = SigningKey::generate(&mut OsRng);
    sign_bundle(&key, dir).unwrap_or_else(|refusal| panic!("sign_bundle refused: {refusal}"))
}

fn no_grants() -> &'static [DeclaredImport] {
    &[]
}

fn assert_names_differ(text: &str) {
    assert!(
        text.contains("bundle bytes name "),
        "refusal display: {text}"
    );
    assert!(text.contains("; the claim is "), "refusal display: {text}");
    let (_, rest) = text
        .split_once("bundle bytes name ")
        .expect("bundle bytes name");
    let (actual, claimed) = rest.split_once("; the claim is ").expect("the claim is");
    assert_ne!(actual, claimed, "{text}");
    assert!(!actual.is_empty() && !claimed.is_empty(), "{text}");
}

#[test]
fn swapped_module_is_refused() {
    assert_eq!(MODULE.len(), 8);
    assert!(SWAPPED.starts_with(MODULE));
    assert!(SWAPPED.len() > MODULE.len());

    let bundle = prepare();
    let signature = sign(bundle.path());
    let accepted = [signature.signer_did.clone()];
    let granted = no_grants();
    let verified = verify_bundle(bundle.path(), Some(&signature), &accepted, granted)
        .unwrap_or_else(|refusal| panic!("the signed bundle was refused: {refusal}"));
    assert_eq!(verified.entrypoint().content.as_slice(), MODULE);

    fs::write(bundle.path().join("capsule.wasm"), SWAPPED).expect("replace capsule.wasm");
    assert_eq!(
        fs::read(bundle.path().join("capsule.wasm")).expect("read capsule.wasm"),
        SWAPPED
    );
    match verify_bundle(bundle.path(), Some(&signature), &accepted, granted) {
        Ok(_) => panic!("accepted swap: verify_bundle returned Ok"),
        Err(refusal) => {
            let text = refusal.to_string();
            assert_names_differ(&text);
            println!("refused the swapped module");
            println!("{text}");
        }
    }
}
"""


class ProbeError(Exception):
    """The unplanted cargo test stopped for a reason other than an accepted swap.

    unittest counts this as an ERROR. A skip is only a missing rustc 1.91.0.
    """


@dataclass(frozen=True)
class CargoResult:
    returncode: int
    output: str
    command: str


def host_rustc_skip_reason():
    """None when rustc 1.91.0 starts. Otherwise the SKIPPED reason."""
    rustc = os.environ.get("RUSTC", "rustc")
    try:
        version = query_rustc(rustc, "--version", absent="rustc 1.91.0")
    except ToolchainAbsent as absent:
        return str(absent)
    if not version.startswith(RUSTC_RELEASE):
        return f"rustc 1.91.0 cannot be started: {rustc} is {version!r}"
    return None


def clean_line():
    """The one clean-run sentence. HEAD is read once here."""
    head = git("rev-parse", "HEAD")
    if len(head) != 40 or any(char not in "0123456789abcdef" for char in head):
        raise ProbeError(f"HEAD is not a commit: {head}")
    return f"verify_bundle refused the swapped module, on {head}"


def harness_text(output):
    """The test harness's own report, after cargo's compile log."""
    marker = "running 1 test"
    index = output.rfind(marker)
    if index == -1:
        return output[-2500:]
    report = output[index:]
    end = report.find("\nerror:")
    if end != -1:
        report = report[:end]
    return report.rstrip()


def show_cargo(label, result):
    """Print one cargo result. The compile log stays in `result` for assertions."""
    print(
        f"--- cargo {label} exit {result.returncode} ---\n{result.command}\n{harness_text(result.output)}",
        file=sys.stderr,
        flush=True,
    )


def identity_names(output):
    """The two names in the identity refusal, from cargo's output."""
    found = []
    for line in output.splitlines():
        if "bundle bytes name " not in line or "; the claim is " not in line:
            continue
        rest = line.split("bundle bytes name ", 1)[1]
        actual, claimed = rest.split("; the claim is ", 1)
        found.append((actual.strip(), claimed.strip()))
    if not found:
        raise AssertionError("cargo output has no identity display\n" + harness_text(output))
    return found[0]


def cargo_env(root):
    env = build_env()
    env["CARGO_TARGET_DIR"] = str(root / "target")
    env["CARGO_BUILD_BUILD_DIR"] = str(root / "build")
    env["CARGO_TERM_COLOR"] = "never"
    env["CARGO_INCREMENTAL"] = "0"
    env["RUST_TEST_THREADS"] = "2"
    env["RUST_BACKTRACE"] = "0"
    env["REDTEAM_BUNDLE_DIR"] = str(root / "bundle")
    return env


def run_cargo(source, root):
    """One offline cargo test of swapped_module_is_refused in the temp copy."""
    argv = [
        "cargo",
        "test",
        "--offline",
        "--locked",
        "--manifest-path",
        str(source / "Cargo.toml"),
        "--test",
        "redteam_swap",
        "--",
        "--exact",
        "swapped_module_is_refused",
        "--show-output",
    ]
    command = shlex.join(argv)
    env = cargo_env(root)
    try:
        proc = subprocess.Popen(
            argv,
            cwd=source,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            start_new_session=True,
        )
    except OSError as error:
        raise ProbeError(f"cargo cannot be started: {error}") from None
    try:
        out, err = proc.communicate(timeout=CARGO_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
        raise ProbeError(
            f"{command}\ntimed out after {CARGO_TIMEOUT_S} s\n--- stderr ---\n{err or ''}"
        ) from None
    # Cargo's compile log is stderr. The harness report is stdout. Keep that
    # order so the report is the tail a reader pastes.
    output = f"{err or ''}\n{out or ''}"
    return CargoResult(proc.returncode, output, command)


def assert_binary_stays_in_temp(result, root, source):
    """The redteam_swap binary cargo ran is under this temp root.

    Cargo 1.91 places that binary in ``CARGO_BUILD_BUILD_DIR`` when the
    variable is set, and in ``CARGO_TARGET_DIR`` otherwise. Both are under
    the temp root. A path inside the repo is a miss.
    """
    temp_root = root.resolve()
    repo = REPO_ROOT.resolve()
    found = []
    for line in result.output.splitlines():
        if "Running " not in line or "redteam_swap" not in line:
            continue
        if "(" not in line or ")" not in line:
            continue
        raw = line[line.rfind("(") + 1 : line.rfind(")")]
        path = Path(raw)
        if not path.is_absolute():
            path = source / path
        found.append(path.resolve())
    if not found:
        raise ProbeError("cargo did not report the redteam_swap binary\n" + harness_text(result.output))
    for path in found:
        try:
            path.relative_to(temp_root)
        except ValueError:
            raise ProbeError(f"cargo ran {path}, outside {temp_root}") from None
        try:
            path.relative_to(repo)
        except ValueError:
            pass
        else:
            raise ProbeError(f"cargo ran {path}, inside the repo")


def write_accept_finding():
    """The recorded accept. The first line pins the file this probe called."""
    FINDING.parent.mkdir(parents=True, exist_ok=True)
    FINDING.write_text(
        "\n".join(
            (
                f"{FINDING_ID} commit {PINNED_VERIFY_COMMIT} "
                f"PR #279 sha256 {PINNED_VERIFY_SHA256}",
                "",
                "call sequence:",
                "1. Write capsule.json from CAPSULE_MANIFEST and capsule.wasm as "
                "the eight bytes 00 61 73 6d 01 00 00 00.",
                "2. Sign that directory with SigningKey::generate and OsRng. "
                "The key and the signature stay in memory.",
                "3. verify_bundle of that directory, with that signature and a "
                "one-element accepted list of the signer's did:key, and with "
                "granted imports empty, returns Ok. entrypoint() bytes are those eight.",
                "4. Replace capsule.wasm with "
                "00 61 73 6d 01 00 00 00 00 04 01 6e 68 69.",
                "5. verify_bundle with the original signature, the same accepted "
                "list, and empty grants.",
                "",
                "observed: Ok",
                "",
            )
        )
    )


class WasmVerifySwapProbe(unittest.TestCase):
    """One temp copy, one generated test, the pinned verify.rs."""

    skip_reason = None
    root = None
    source = None
    _hold = None

    @classmethod
    def setUpClass(cls):
        cls.skip_reason = host_rustc_skip_reason()
        cls.root = None
        cls.source = None
        cls._hold = None
        if cls.skip_reason:
            report_skip(cls.skip_reason)

    @classmethod
    def tearDownClass(cls):
        hold = cls._hold
        if hold is not None:
            hold.cleanup()
            cls._hold = None

    def require_toolchain(self):
        if type(self).skip_reason:
            self.skipTest(type(self).skip_reason)

    def copy(self):
        """The one temp wasm-capsule tree, with the generated test written into it."""
        self.require_toolchain()
        cls = type(self)
        if cls.source is None:
            cls._hold = tempfile.TemporaryDirectory(prefix="redteam-016-")
            cls.root = Path(cls._hold.name)
            cls.source = lay_copy(cls.root, COPY_PATH)
            (cls.source / "tests" / "redteam_swap.rs").write_text(SWAP_RS)
            assert_linked_layout(self, cls.source)
        return cls.root, cls.source

    def assert_trees_clean(self):
        status = git("status", "--porcelain", "--", *REAL_TREES)
        self.assertEqual(status, "", status)

    def assert_copy_is_pinned(self, source):
        copy = (source / VERIFY_LEAF).read_bytes()
        real = VERIFY_RS.read_bytes()
        if copy != real:
            raise ProbeError("temp verify.rs is not the pinned file")
        if sha256_file(source / VERIFY_LEAF) != PINNED_VERIFY_SHA256:
            raise ProbeError("temp verify.rs sha256 does not match the pin")

    def assert_ran_under_temp(self, result, root, source):
        repo_target = str((REPO_ROOT / "lab" / "wasm-capsule" / "target").resolve())
        if repo_target in result.output:
            raise ProbeError(f"cargo used the owner target dir {repo_target}")
        assert_binary_stays_in_temp(result, root, source)

    def assert_refused(self, result, root, source, *, announce, record):
        """Exit 0, the refusal line, and two different names in the display."""
        if result.returncode != 0:
            show_cargo("unplanted", result)
            if "accepted swap:" in result.output:
                if record:
                    write_accept_finding()
                self.fail(
                    "accepted swap: verify_bundle returned Ok\n" + harness_text(result.output)
                )
            raise ProbeError(
                f"{result.command}\nexited {result.returncode}\n" + harness_text(result.output)
            )
        self.assert_ran_under_temp(result, root, source)
        shown = harness_text(result.output)
        self.assertIn("refused the swapped module", result.output, shown)
        self.assertIn("bundle bytes name ", result.output, shown)
        self.assertIn("; the claim is ", result.output, shown)
        actual, claimed = identity_names(result.output)
        self.assertNotEqual(actual, claimed, result.output)
        self.assertTrue(actual, result.output)
        self.assertTrue(claimed, result.output)
        self.assertNotIn("accepted swap:", result.output)
        if announce:
            self.assertFalse(FINDING.is_file(), f"a clean refusal wrote {FINDING}")
            print(clean_line(), file=sys.stderr, flush=True)
        show_cargo("unplanted", result)

    def test_pin_matches_verify_rs(self):
        """The sha256 of verify.rs is the digest this probe records."""
        observed = sha256_file(VERIFY_RS)
        self.assertEqual(observed, PINNED_VERIFY_SHA256)
        last = git("log", "-1", "--format=%H", "HEAD", "--", VERIFY_REL)
        self.assertEqual(last, PINNED_VERIFY_COMMIT)
        ancestor = git("merge-base", "--is-ancestor", PINNED_PR_MERGE, "HEAD")
        self.assertEqual(ancestor, "", ancestor)
        self.assertFalse(
            (REPO_ROOT / "lab" / "redteam" / "Cargo.toml").exists(),
            "this probe adds no lab/redteam/Cargo.toml",
        )

    def test_skipped_signature_is_caught(self):
        """F-WC4a in the temp copy: the same cargo test fails with `accepted swap:`.

        Restoring the line makes the unplanted test pass again.
        """
        root, source = self.copy()
        path = source / VERIFY_LEAF
        original = path.read_bytes()
        self.assertEqual(original, VERIFY_RS.read_bytes())
        planted = None
        try:
            F_WC4A.apply(source)
            planted_text = path.read_text()
            self.assertEqual(planted_text.count(TRUSTED_LINE), 1)
            self.assertNotIn(SIGNATURE_LINE, planted_text)
            planted = run_cargo(source, root)
        finally:
            path.write_bytes(original)
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(path.read_bytes(), VERIFY_RS.read_bytes())
        self.assertIsNotNone(planted)
        show_cargo("planted", planted)
        self.assertNotEqual(
            planted.returncode,
            0,
            "the planted verifier refused the swap; F-WC4a was not caught\n"
            + harness_text(planted.output),
        )
        self.assertIn("accepted swap:", planted.output)
        self.assert_copy_is_pinned(source)
        restored = run_cargo(source, root)
        self.assert_refused(restored, root, source, announce=False, record=False)
        self.assert_trees_clean()

    def test_swapped_module_is_refused(self):
        """The unplanted verifier refuses a module swapped after signing."""
        root, source = self.copy()
        self.assert_copy_is_pinned(source)
        self.assert_trees_clean()
        owner_test = REPO_ROOT / "lab" / "wasm-capsule" / "tests" / "redteam_swap.rs"
        self.assertFalse(owner_test.exists(), owner_test)
        result = run_cargo(source, root)
        self.assert_refused(result, root, source, announce=True, record=True)
        self.assert_trees_clean()
        self.assertFalse(owner_test.exists(), owner_test)


if __name__ == "__main__":
    unittest.main()
