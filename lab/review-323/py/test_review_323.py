"""Adversarial review of draft PR #323 against its live checkers.

HOLDS tests assert a refusal #323 already makes. FALSIFIED tests assert a
refusal the contract still needs; they fail on #323 today. WEAK tests record
a narrower gap that is not a silent pass of the claimed #294 cases.

The probe is the extracted #323 functions, not a second implementation.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REVIEW = ROOT / "lab/review-323"
PROBE_BIN = REVIEW / "probe/target/debug/review323-probe"
WALLET_CONFINE = ROOT / "capsules/wallet-provider/tests/confine.rs"
MODEL_CONFINE = ROOT / "capsules/model-provider/tests/confine/main.rs"
DID_CONFINE = ROOT / "capsules/did-provider/tests/confine.rs"

if str(REVIEW) not in sys.path:
    sys.path.insert(0, str(REVIEW))
import extract  # noqa: E402


def _build_probe() -> None:
    extract.build(REVIEW / "probe")
    subprocess.run(
        ["cargo", "build", "--quiet"],
        cwd=REVIEW / "probe",
        check=True,
    )


def probe(req: dict) -> dict:
    proc = subprocess.run(
        [str(PROBE_BIN)],
        input=json.dumps(req),
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        return {
            "ok": False,
            "panic": True,
            "stderr": proc.stderr,
        }
    return json.loads(proc.stdout)


def fixture_profile() -> str:
    return probe({"op": "fixture"})["profile"]


def declared_for(
    extra_storage_rule: str | None = None,
    justification: str | None = None,
    extra_profile_line: str | None = None,
) -> tuple[str, dict]:
    fix = fixture_profile()
    rules = probe({"op": "shared_rules"})["rules"]
    startup = probe({"op": "startup_rules"})["rules"]
    just_root = justification or probe(
        {"op": "justification", "name": "did-provider", "id": "startup-root-directory"}
    )["text"]
    just_sys = probe(
        {"op": "justification", "name": "did-provider", "id": "startup-sysctl"}
    )["text"]
    storage = [rules[1], rules[2]]
    profile = fix + startup[0] + "\n" + startup[1] + "\n"
    if extra_storage_rule:
        storage.append(extra_storage_rule)
        profile += extra_storage_rule + "\n"
    if extra_profile_line:
        profile += extra_profile_line + "\n"
    declared = {
        "role": "lab stand-in for the Runtime generator's input, not a manifest field",
        "provider": "did-provider",
        "rights": [
            {"id": "storage", "rules": storage},
            {"id": "bound-executable", "rules": [rules[0]]},
        ],
        "platform_baseline": {
            "status": (
                "Runtime platform baseline for the did-provider executable "
                "on macOS, not approved rights"
            ),
            "rules": [
                {
                    "id": "startup-root-directory",
                    "justification": just_root,
                    "rules": [startup[0]],
                },
                {
                    "id": "startup-sysctl",
                    "justification": just_sys,
                    "rules": [startup[1]],
                },
            ],
        },
    }
    return profile, declared


def cite(source: str) -> list:
    tmp = tempfile.mkdtemp()
    tests = Path(tmp) / "tests"
    tests.mkdir()
    (tests / "confine.rs").write_text(source)
    doc = (
        "## Operations and the rights they need\n\n"
        "| `tests/confine.rs::present_case` |\n\n"
        "## Host-OS status\n"
    )
    return probe({"op": "cite", "dir": tmp, "document": doc})["problems"]


def setUpModule() -> None:
    _build_probe()
    assert PROBE_BIN.is_file(), PROBE_BIN


class HoldsClaimedRefusals(unittest.TestCase):
    """#323's own #294 cases still refuse."""

    def test_holds_nested_allow_default(self) -> None:
        profile = fixture_profile() + "(if #t (allow default))\n"
        got = probe({"op": "contract", "profile": profile})
        self.assertFalse(got["ok"], got)
        self.assertIn("must reject (allow default)", got["reason"])

    def test_holds_split_allow_default(self) -> None:
        profile = fixture_profile() + "(if #t (allow\n    default))\n"
        got = probe({"op": "contract", "profile": profile})
        self.assertFalse(got["ok"], got)
        self.assertIn("must reject (allow default)", got["reason"])

    def test_holds_nested_network(self) -> None:
        profile = fixture_profile() + "(begin (allow network*))\n"
        got = probe({"op": "contract", "profile": profile})
        self.assertFalse(got["ok"], got)
        self.assertIn("network allow is refused", got["reason"])

    def test_holds_nested_import(self) -> None:
        profile = fixture_profile() + '(if #t (import "bsd.sb"))\n'
        got = probe({"op": "contract", "profile": profile})
        self.assertFalse(got["ok"], got)
        self.assertIn("import", got["reason"])

    def test_holds_exact_subpath_root_as_storage(self) -> None:
        profile, declared = declared_for('(allow file-read* (subpath "/"))')
        got = probe(
            {
                "op": "rights",
                "name": "did-provider",
                "profile": profile,
                "declared": declared,
            }
        )
        self.assertFalse(got["ok"], got)
        self.assertIn("root-wide", got["reason"])

    def test_holds_prefix_plus_x_justification(self) -> None:
        junk = (
            "macOS did-provider executable bound as PROVIDER_EXECUTABLE: x"
        )
        profile, declared = declared_for(justification=junk)
        got = probe(
            {
                "op": "rights",
                "name": "did-provider",
                "profile": profile,
                "declared": declared,
            }
        )
        self.assertFalse(got["ok"], got)
        self.assertIn("must be", got["reason"])
        self.assertNotIn(' must start with "x"', got["reason"])

    def test_holds_line_comment_is_not_a_citation(self) -> None:
        problems = cite("// fn present_case()\nfn other_case() {}\n")
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("does not hold", problems[0])

    def test_holds_model_walk_sees_nested_allow(self) -> None:
        forms = probe(
            {
                "op": "model_allow_forms",
                "profile": "(version 1)\n(deny default)\n(if #t (allow default))\n",
            }
        )["forms"]
        self.assertIn("(allow default)", forms)

    def test_holds_model_comment_strip_matches_wallet(self) -> None:
        wallet = extract.extract_named(
            WALLET_CONFINE.read_text(), "fn", "rust_source_without_comments"
        )
        model = extract.extract_named(
            MODEL_CONFINE.read_text(), "fn", "rust_source_without_comments"
        )
        self.assertEqual(
            wallet.replace("pub fn ", "fn ", 1),
            model.replace("pub fn ", "fn ", 1),
        )


class FalsifiedRootWideStorage(unittest.TestCase):
    """A storage right may still claim a host-wide read that is not the
    exact `(subpath "/")` / `(literal "/")` spelling.
    """

    def test_falsified_unfiltered_file_read_as_storage(self) -> None:
        # capsules/wallet-provider/tests/confine.rs:1569 is_root_wide_read
        # and :2101 storage refusal only match those two path spellings.
        profile, declared = declared_for("(allow file-read*)")
        got = probe(
            {
                "op": "rights",
                "name": "did-provider",
                "profile": profile,
                "declared": declared,
            }
        )
        self.assertFalse(
            got["ok"],
            "storage must not claim an unfiltered file-read* "
            f"(wider than a root-wide read); checker returned {got}",
        )

    def test_falsified_regex_root_as_storage(self) -> None:
        profile, declared = declared_for('(allow file-read* (regex "^/"))')
        got = probe(
            {
                "op": "rights",
                "name": "did-provider",
                "profile": profile,
                "declared": declared,
            }
        )
        self.assertFalse(
            got["ok"],
            "storage must not claim a regex root read; "
            f"checker returned {got}",
        )

    def test_falsified_spaced_literal_root_as_storage(self) -> None:
        profile, declared = declared_for('(allow file-read* (literal "/" ))')
        got = probe(
            {
                "op": "rights",
                "name": "did-provider",
                "profile": profile,
                "declared": declared,
            }
        )
        self.assertFalse(
            got["ok"],
            "storage must not claim (literal \"/\" ) with extra space; "
            f"checker returned {got}",
        )

    def test_falsified_dot_subpath_root_as_storage(self) -> None:
        profile, declared = declared_for('(allow file-read* (subpath "/."))')
        got = probe(
            {
                "op": "rights",
                "name": "did-provider",
                "profile": profile,
                "declared": declared,
            }
        )
        self.assertFalse(
            got["ok"],
            "storage must not claim (subpath \"/.\"), which is the host root; "
            f"checker returned {got}",
        )


class FalsifiedCitationJunk(unittest.TestCase):
    """A citation may still name a string or a nested block comment."""

    def test_falsified_string_literal_is_not_a_function(self) -> None:
        # rust_source_without_comments keeps string text
        # (capsules/wallet-provider/tests/confine.rs:1604).
        problems = cite('const S: &str = "fn present_case(";\n')
        self.assertTrue(
            problems,
            "a string that holds fn present_case( must not satisfy a citation; "
            f"problems={problems}",
        )

    def test_falsified_nested_block_comment_is_not_a_function(self) -> None:
        # The stripper does not nest /* */, so the inner */ ends the comment
        # and `fn present_case(` remains. Real Rust keeps the fn in comment.
        problems = cite("/* /* */ fn present_case() {} */\n")
        self.assertTrue(
            problems,
            "a nested block comment must not satisfy a citation; "
            f"problems={problems}",
        )


class FalsifiedSkipStillCounts(unittest.TestCase):
    """#[ignore] hides the skip from default cargo test. --ignored still
    returns ok on Linux for wallet and did sandbox tests.
    """

    def test_falsified_ignored_wallet_sandbox_test_still_passes(self) -> None:
        # confined_outside_write_is_denied:732 returns after sandbox_available.
        proc = subprocess.run(
            [
                "cargo",
                "test",
                "--test",
                "confine",
                "confined_outside_write_is_denied",
                "--",
                "--ignored",
                "--test-threads=1",
            ],
            cwd=ROOT / "capsules/wallet-provider",
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(
            proc.returncode,
            0,
            "a sandbox test with no sandbox-exec must not pass under "
            "--ignored; stdout follows\n" + proc.stdout[-800:],
        )


class FalsifiedCaseAndNetworkOps(unittest.TestCase):
    """The contract check is a lowercase substring scan."""

    def test_falsified_allow_default_uppercase(self) -> None:
        # is_default_allow:1555 requires `(allow ` and token `default`.
        profile = fixture_profile() + "(ALLOW DEFAULT)\n"
        got = probe({"op": "contract", "profile": profile})
        self.assertFalse(
            got["ok"],
            "the contract must refuse (ALLOW DEFAULT); "
            f"checker returned {got}",
        )

    def test_falsified_allow_default_titlecase(self) -> None:
        profile = fixture_profile() + "(allow Default)\n"
        got = probe({"op": "contract", "profile": profile})
        self.assertFalse(
            got["ok"],
            "the contract must refuse (allow Default); "
            f"checker returned {got}",
        )

    def test_falsified_system_socket_is_a_network_grant(self) -> None:
        # is_network_allow:1548 is form.contains("network").
        # SBPL system-socket creates sockets without that word.
        profile = fixture_profile() + "(allow system-socket)\n"
        got = probe({"op": "contract", "profile": profile})
        self.assertFalse(
            got["ok"],
            "the contract must refuse a system-socket grant; "
            f"checker returned {got}",
        )


class WeakRemainingGaps(unittest.TestCase):
    """Gaps that do not reopen the exact #294 cases."""

    def test_weak_include_is_not_treated_as_import(self) -> None:
        profile = fixture_profile() + '(include "bsd.sb")\n'
        got = probe({"op": "contract", "profile": profile})
        self.assertFalse(
            got["ok"],
            "include is an inclusion form and must be refused; "
            f"checker returned {got}",
        )
        self.assertIn("import", got.get("reason", ""))

    def test_weak_did_parser_still_cuts_at_every_semicolon(self) -> None:
        got = probe(
            {
                "op": "did_forms",
                "profile": '(deny file-read* (literal "/x;")) (allow default)\n',
            }
        )
        self.assertFalse(
            got.get("panic"),
            "did profile_forms must keep a semicolon inside a string; "
            f"checker returned {got}",
        )
        forms = got.get("forms") or []
        self.assertTrue(
            any(form == "(allow default)" for form in forms),
            f"the allow after a string semicolon must stay visible: {forms}",
        )

    def test_weak_flush_head_default_is_not_seen(self) -> None:
        got = probe({"op": "default_allow", "form": "(allow(default))"})
        self.assertTrue(
            got.get("default_allow"),
            "the contract must see (allow(default)); "
            f"checker returned {got}",
        )

    def test_weak_process_fork_is_not_an_exec_allow(self) -> None:
        profile = fixture_profile() + "(allow process-fork)\n"
        got = probe({"op": "contract", "profile": profile})
        self.assertFalse(
            got["ok"],
            "an extra process-fork is a second exec allow; "
            f"checker returned {got}",
        )

    def test_weak_citation_does_not_require_a_test_attribute(self) -> None:
        problems = cite("fn present_case() {}\n")
        self.assertTrue(
            problems,
            "a citation must name a #[test] function; "
            f"problems={problems}",
        )


if __name__ == "__main__":
    unittest.main()
