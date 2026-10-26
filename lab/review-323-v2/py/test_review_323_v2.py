"""Second adversarial review of draft PR #323.

HOLDS tests assert a refusal #323 now claims. FALSIFIED tests assert a
refusal the contract still needs; they fail on #323 today. WEAK tests
record a narrower gap.

The probe is the extracted #323 functions, not a second walk. Every
bypass here is a spelling #346 did not plant.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REVIEW = ROOT / "lab/review-323-v2"
PROBE_BIN = REVIEW / "probe/target/debug/review323v2-probe"
WALLET_CONFINE = ROOT / "capsules/wallet-provider/tests/confine.rs"
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
        return {"ok": False, "panic": True, "stderr": proc.stderr}
    return json.loads(proc.stdout)


def fixture_profile() -> str:
    return probe({"op": "fixture"})["profile"]


def declared_for(
    extra_storage_rule: str | None = None,
    extra_profile_line: str | None = None,
    extra_storage_only: bool = False,
) -> tuple[str, dict]:
    fix = fixture_profile()
    rules = probe({"op": "shared_rules"})["rules"]
    startup = probe({"op": "startup_rules"})["rules"]
    just_root = probe(
        {"op": "justification", "name": "did-provider", "id": "startup-root-directory"}
    )["text"]
    just_sys = probe(
        {"op": "justification", "name": "did-provider", "id": "startup-sysctl"}
    )["text"]
    storage = [rules[1], rules[2]]
    profile = fix + startup[0] + "\n" + startup[1] + "\n"
    if extra_storage_rule:
        storage.append(extra_storage_rule)
        if not extra_storage_only:
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


def rights(extra_storage_rule: str) -> dict:
    profile, declared = declared_for(extra_storage_rule)
    return probe(
        {
            "op": "rights",
            "name": "did-provider",
            "profile": profile,
            "declared": declared,
        }
    )


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


class HoldsClaimedFixes(unittest.TestCase):
    """#346 F1-F9 and the named WEAK items #323 says it closed."""

    def test_holds_unfiltered_file_read_as_storage(self) -> None:
        got = rights("(allow file-read*)")
        self.assertFalse(got["ok"], got)
        self.assertIn("root-wide", got["reason"])

    def test_holds_regex_caret_slash_as_storage(self) -> None:
        got = rights('(allow file-read* (regex "^/"))')
        self.assertFalse(got["ok"], got)
        self.assertIn("root-wide", got["reason"])

    def test_holds_spaced_literal_root_as_storage(self) -> None:
        got = rights('(allow file-read* (literal "/" ))')
        self.assertFalse(got["ok"], got)
        self.assertIn("root-wide", got["reason"])

    def test_holds_dot_subpath_root_as_storage(self) -> None:
        got = rights('(allow file-read* (subpath "/."))')
        self.assertFalse(got["ok"], got)
        self.assertIn("root-wide", got["reason"])

    def test_holds_parent_subpath_normalises_to_root(self) -> None:
        got = rights('(allow file-read* (subpath "/../"))')
        self.assertFalse(got["ok"], got)
        self.assertIn("root-wide", got["reason"])

    def test_holds_regex_caret_slash_dot_star(self) -> None:
        got = rights('(allow file-read* (regex "^/.*"))')
        self.assertFalse(got["ok"], got)
        self.assertIn("root-wide", got["reason"])

    def test_holds_unfiltered_file_read_data_as_storage(self) -> None:
        got = rights("(allow file-read-data)")
        self.assertFalse(got["ok"], got)
        self.assertIn("root-wide", got["reason"])

    def test_holds_string_literal_is_not_a_citation(self) -> None:
        problems = cite('const S: &str = "fn present_case(";\n')
        self.assertTrue(problems, problems)

    def test_holds_nested_block_comment_is_not_a_citation(self) -> None:
        problems = cite("/* /* */ #[test] fn present_case() {} */\n")
        self.assertTrue(problems, problems)

    def test_holds_plain_fn_is_not_a_citation(self) -> None:
        problems = cite("fn present_case() {}\n")
        self.assertTrue(problems, problems)

    def test_holds_allow_default_uppercase(self) -> None:
        got = probe({"op": "contract", "profile": fixture_profile() + "(ALLOW DEFAULT)\n"})
        self.assertFalse(got["ok"], got)

    def test_holds_system_socket_is_a_network_grant(self) -> None:
        got = probe({"op": "contract", "profile": fixture_profile() + "(allow system-socket)\n"})
        self.assertFalse(got["ok"], got)
        self.assertIn("network", got["reason"])

    def test_holds_network_outbound(self) -> None:
        got = probe(
            {"op": "contract", "profile": fixture_profile() + "(allow network-outbound)\n"}
        )
        self.assertFalse(got["ok"], got)
        self.assertIn("network", got["reason"])

    def test_holds_network_bind(self) -> None:
        got = probe({"op": "contract", "profile": fixture_profile() + "(allow network-bind)\n"})
        self.assertFalse(got["ok"], got)
        self.assertIn("network", got["reason"])

    def test_holds_include_load_require(self) -> None:
        for form in ('(include "bsd.sb")', '(load "bsd.sb")', '(require "bsd.sb")'):
            got = probe({"op": "contract", "profile": fixture_profile() + form + "\n"})
            self.assertFalse(got["ok"], (form, got))

    def test_holds_process_fork_is_second_exec(self) -> None:
        got = probe({"op": "contract", "profile": fixture_profile() + "(allow process-fork)\n"})
        self.assertFalse(got["ok"], got)

    def test_holds_did_reader_keeps_semicolon_in_string(self) -> None:
        got = probe(
            {
                "op": "did_forms",
                "profile": '(deny file-read* (literal "/x;")) (allow default)\n',
            }
        )
        self.assertFalse(got.get("panic"), got)
        forms = got.get("forms") or []
        self.assertTrue(any(form == "(allow default)" for form in forms), forms)

    def test_holds_ignored_wallet_sandbox_test_panics(self) -> None:
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
        self.assertNotEqual(proc.returncode, 0, proc.stdout[-800:])
        self.assertIn("NOT RUN", proc.stdout + proc.stderr)


class FalsifiedNewBypasses(unittest.TestCase):
    """New spellings #346 did not plant. Each test asks for a refusal."""

    def test_falsified_empty_prefix_as_storage(self) -> None:
        got = rights('(allow file-read* (prefix ""))')
        self.assertFalse(
            got["ok"],
            "storage must not claim (prefix \"\"), which matches every path; "
            f"checker returned {got}",
        )

    def test_falsified_regex_dot_star_as_storage(self) -> None:
        got = rights('(allow file-read* (regex ".*"))')
        self.assertFalse(
            got["ok"],
            "storage must not claim (regex \".*\"), which matches every path; "
            f"checker returned {got}",
        )

    def test_falsified_regex_class_slash_as_storage(self) -> None:
        got = rights('(allow file-read* (regex "^[/].*"))')
        self.assertFalse(
            got["ok"],
            f"storage must not claim (regex \"^[/].*\"); checker returned {got}",
        )

    def test_falsified_string_append_root_as_storage(self) -> None:
        got = rights('(allow file-read* (subpath (string-append "/" "")))')
        self.assertFalse(
            got["ok"],
            "storage must not claim a string-append root; "
            f"checker returned {got}",
        )

    def test_falsified_unfiltered_file_star_as_storage(self) -> None:
        got = rights("(allow file*)")
        self.assertFalse(
            got["ok"],
            "storage must not claim unfiltered file* (every file op); "
            f"checker returned {got}",
        )

    def test_falsified_unfiltered_file_write_as_storage(self) -> None:
        got = rights("(allow file-write*)")
        self.assertFalse(
            got["ok"],
            "storage must not claim unfiltered file-write*; "
            f"checker returned {got}",
        )

    def test_falsified_require_any_root_as_storage(self) -> None:
        got = rights('(allow file-read* (require-any (subpath "/")))')
        self.assertFalse(
            got["ok"],
            "storage must not claim require-any of the host root; "
            f"checker returned {got}",
        )

    def test_falsified_vnode_type_only_as_storage(self) -> None:
        got = rights("(allow file-read* (vnode-type REGULAR-FILE))")
        self.assertFalse(
            got["ok"],
            "a pathless vnode-type filter is still a host-wide read; "
            f"checker returned {got}",
        )

    def test_falsified_multiple_filters_regex_dot_star(self) -> None:
        got = rights('(allow file-read* (subpath "/var") (regex ".*"))')
        self.assertFalse(
            got["ok"],
            "a second regex .* filter is still host-wide; "
            f"checker returned {got}",
        )

    def test_falsified_uppercase_allow_invisible_to_allow_forms(self) -> None:
        profile, declared = declared_for(extra_profile_line="(ALLOW file-read*)")
        seen = probe({"op": "allow_forms", "profile": profile})["forms"]
        self.assertNotIn(
            "(ALLOW file-read*)",
            seen,
            "setup: allow_forms must miss the uppercase extra grant for this "
            f"to be the hole; forms={seen}",
        )
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
            "an extra (ALLOW file-read*) in the profile is a host-wide read "
            f"and must be refused; checker returned {got}",
        )

    def test_falsified_flush_head_file_read_invisible(self) -> None:
        profile, declared = declared_for(extra_profile_line="(allow(file-read*))")
        seen = probe({"op": "allow_forms", "profile": profile})["forms"]
        self.assertFalse(
            any(form == "(allow(file-read*))" for form in seen),
            f"setup: allow_forms must miss the flush-head grant; forms={seen}",
        )
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
            "an extra (allow(file-read*)) is an unfiltered host-wide read; "
            f"checker returned {got}",
        )

    def test_falsified_mach_lookup_is_ambient_ipc(self) -> None:
        got = probe({"op": "contract", "profile": fixture_profile() + "(allow mach-lookup)\n"})
        self.assertFalse(
            got["ok"],
            "a bare mach-lookup grant is ambient IPC; "
            f"checker returned {got}",
        )

    def test_falsified_ipc_posix_is_ambient_ipc(self) -> None:
        got = probe({"op": "contract", "profile": fixture_profile() + "(allow ipc-posix*)\n"})
        self.assertFalse(
            got["ok"],
            "a bare ipc-posix* grant is ambient IPC; "
            f"checker returned {got}",
        )

    def test_falsified_cfg_any_module_is_not_a_citation(self) -> None:
        source = (
            "#[cfg(any())]\n"
            "mod unused {\n"
            "    #[test]\n"
            "    fn present_case() {}\n"
            "}\n"
        )
        problems = cite(source)
        self.assertTrue(
            problems,
            "a #[test] under #[cfg(any())] never runs and must not cite; "
            f"problems={problems}",
        )

    def test_falsified_unused_macro_is_not_a_citation(self) -> None:
        source = (
            "macro_rules! planted {\n"
            "    () => {\n"
            "        #[test]\n"
            "        fn present_case() {}\n"
            "    };\n"
            "}\n"
        )
        problems = cite(source)
        self.assertTrue(
            problems,
            "an unused macro_rules body must not satisfy a citation; "
            f"problems={problems}",
        )

    def test_falsified_did_gate_misses_uppercase_default(self) -> None:
        got = probe({"op": "did_denies", "profile": fixture_profile() + "(ALLOW DEFAULT)\n"})
        self.assertFalse(
            got["ok"],
            "did profile_denies_network still uses starts_with(\"(allow \") "
            f"and misses (ALLOW DEFAULT); checker returned {got}",
        )

    def test_falsified_did_gate_misses_system_socket(self) -> None:
        got = probe(
            {"op": "did_denies", "profile": fixture_profile() + "(allow system-socket)\n"}
        )
        self.assertFalse(
            got["ok"],
            "did profile_denies_network still uses contains(\"network\") "
            f"and misses system-socket; checker returned {got}",
        )


class WeakRemainingGaps(unittest.TestCase):
    """Narrower gaps. These pass as documentation."""

    def test_weak_zero_width_path_is_not_normalised(self) -> None:
        form = '(allow file-read* (literal "/\u200b"))'
        got = probe({"op": "root_wide", "form": form})
        self.assertFalse(
            got.get("root_wide"),
            "setup: the live checker must still miss U+200B after /; "
            f"checker returned {got}",
        )

    def test_weak_deny_then_allow_root_still_seen_as_root(self) -> None:
        profile, declared = declared_for(
            extra_storage_rule='(allow file-read* (subpath "/"))',
            extra_profile_line='(deny file-read* (subpath "/"))\n'
            '(allow file-read* (subpath "/"))',
            extra_storage_only=True,
        )
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

    def test_weak_model_copy_misses_empty_prefix(self) -> None:
        got = probe({"op": "model_root_wide", "form": '(allow file-read* (prefix ""))'})
        self.assertTrue(
            got.get("root_wide"),
            "the model copy must catch an empty prefix; "
            f"checker returned {got}",
        )

    def test_weak_did_source_still_has_old_predicates(self) -> None:
        text = DID_CONFINE.read_text()
        start = text.find("fn profile_network_denied(")
        self.assertGreater(start, 0, "did profile_network_denied must exist")
        body = text[start : start + 2200]
        self.assertIn("did_is_permitted_profile_form", body)
        self.assertIn("did_allow_head", body)
        self.assertNotIn('contains("network")', body)
        self.assertNotIn('starts_with("(import")', body)
        self.assertIn("capsules/did-provider/tests/confine.rs", str(DID_CONFINE))
        self.assertTrue(WALLET_CONFINE.is_file())


if __name__ == "__main__":
    unittest.main()
