"""Adversarial review tests for draft PR #343.

HOLDS and WEAK classes pass. FALSIFIED classes assert the property the
M1 check still needs; they fail on this #343 head.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

from mutants import classify, run_named_tests, subject_sources

REVIEW = Path(__file__).resolve().parents[1]
REPO = REVIEW.parents[1]
SUBJECT = REVIEW / "subject"
HEAD = "011d01f283a3f4ed4717383ecedf55622d451b4d"

A6_JOURNEY = [
    "tests::a6_owner_may_use_own_session_token",
    "tests::a6_sibling_presenting_owner_token_is_refused",
]
A12_LIST_AND_PLANT = [
    "tests::a12_census_lists_runtime_storage",
    "tests::a12_planted_storage_file_is_caught",
]


def _git_show(path: str, rev: str = HEAD) -> str:
    result = subprocess.run(
        ["git", "show", f"{rev}:{path}"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def _line(path: str, number: int, rev: str = HEAD) -> str:
    lines = _git_show(path, rev).splitlines()
    return lines[number - 1]


class HoldsCitations(unittest.TestCase):
    def test_cited_lines_exist_on_reviewed_head(self) -> None:
        self.assertIn(
            "pub fn cleanup(",
            _line("lab/agent-conformance/src/census.rs", 79),
        )
        self.assertIn("home.temp()", _line("lab/agent-conformance/src/census.rs", 100))
        self.assertIn(
            "outside-root:BLOCKED(AC-006-STORAGE)",
            _line("lab/agent-conformance/src/census.rs", 124),
        )
        self.assertIn(
            "fn cleanup_census_refuses_each_leftover",
            _line("lab/agent-conformance/tests/runtime.rs", 324),
        )
        self.assertIn(
            'home.temp().join("planted")',
            _line("lab/agent-conformance/tests/runtime.rs", 340),
        )
        self.assertIn(
            "fn two_instances_overlap_with_separate_grants",
            _line("lab/agent-conformance/tests/effects.rs", 657),
        )
        self.assertIn(
            "fn instance_grant_does_not_authorise_sibling",
            _line("lab/agent-conformance/tests/effects.rs", 662),
        )
        self.assertIn(
            "For now, all requests go to pending",
            _line(
                "elastos/crates/elastos-server/src/api/handlers/capability.rs",
                119,
            ),
        )
        self.assertIn(
            "if token.capsule != caller_capsule_id",
            _line(
                "elastos/crates/elastos-runtime/src/capability/manager.rs",
                409,
            ),
        )
        self.assertIn(
            '"wrong_capsule"',
            _line(
                "elastos/crates/elastos-runtime/src/capability/manager.rs",
                410,
            ),
        )
        self.assertIn(
            "ValidationError::WrongCapsule",
            _line(
                "elastos/crates/elastos-runtime/src/capability/manager.rs",
                411,
            ),
        )
        self.assertIn(
            'throwaway Homes require macOS',
            _line("lab/agent-conformance/src/harness.rs", 18),
        )

    def test_named_lib_tests_exist_in_subject_lib(self) -> None:
        lib = (SUBJECT / "lib.rs").read_text()
        for name in [
            "a6_owner_may_use_own_session_token",
            "a6_sibling_presenting_owner_token_is_refused",
            "a6_runtime_session_token_check_is_present",
            "a6_absent_runtime_session_token_check_is_caught",
            "a12_census_lists_runtime_storage",
            "a12_planted_storage_file_is_caught",
            "a12_empty_root_is_leftover",
            "combined_cleanup_invokes_existing_census_by_name",
            "planted_bugs_are_caught",
        ]:
            self.assertIn(f"fn {name}(", lib)


class HoldsTheirFalsifiers(unittest.TestCase):
    def test_f_a6_no_token_check_is_caught(self) -> None:
        a6, a12 = subject_sources()
        mutated = a6.replace(
            "    if token_capsule != caller_capsule {",
            "    if false && token_capsule != caller_capsule {",
            1,
        )
        self.assertNotEqual(mutated, a6)
        output = run_named_tests(
            mutated, a12, ["tests::a6_sibling_presenting_owner_token_is_refused"]
        )
        self.assertEqual(classify(output, ["tests::a6_sibling_presenting_owner_token_is_refused"]), "CAUGHT", output)

    def test_f_a12_drop_roots_is_caught(self) -> None:
        a6, a12 = subject_sources()
        mutated = a12.replace(
            'pub const RUNTIME_TEMP_ROOTS: &[&str] = &["/tmp/elastos/storage", "/tmp/elastos"];',
            'pub const RUNTIME_TEMP_ROOTS: &[&str] = &[];',
            1,
        )
        self.assertNotEqual(mutated, a12)
        output = run_named_tests(a6, mutated, A12_LIST_AND_PLANT)
        self.assertEqual(classify(output, A12_LIST_AND_PLANT), "CAUGHT", output)

    def test_generic_denied_reason_is_caught(self) -> None:
        a6, a12 = subject_sources()
        mutated = a6.replace(
            '            "wrong_capsule expected:{token_capsule} got:{caller_capsule}"',
            '            "denied"',
            1,
        )
        self.assertNotEqual(mutated, a6)
        output = run_named_tests(
            mutated, a12, ["tests::a6_sibling_presenting_owner_token_is_refused"]
        )
        self.assertEqual(
            classify(output, ["tests::a6_sibling_presenting_owner_token_is_refused"]),
            "CAUGHT",
            output,
        )


class WeakSurvivingMutants(unittest.TestCase):
    def test_prefix_bind_survives_named_a6_journeys(self) -> None:
        a6, a12 = subject_sources()
        mutated = a6.replace(
            "    if token_capsule != caller_capsule {",
            "    if !caller_capsule.starts_with(token_capsule) {",
            1,
        )
        self.assertNotEqual(mutated, a6)
        output = run_named_tests(mutated, a12, A6_JOURNEY)
        self.assertEqual(classify(output, A6_JOURNEY), "SURVIVED", output)

    def test_empty_token_survives_named_a6_journeys(self) -> None:
        a6, a12 = subject_sources()
        mutated = a6.replace(
            "    if token_capsule != caller_capsule {",
            "    if !token_capsule.is_empty() && token_capsule != caller_capsule {",
            1,
        )
        self.assertNotEqual(mutated, a6)
        output = run_named_tests(mutated, a12, A6_JOURNEY)
        self.assertEqual(classify(output, A6_JOURNEY), "SURVIVED", output)

    def test_hardcoded_runtime_temp_fail_survives_list_and_plant(self) -> None:
        a6, a12 = subject_sources()
        old = """pub fn runtime_temp_census() -> Result<String, String> {
    runtime_temp_census_at(&runtime_owned_temp_roots())
}"""
        new = """pub fn runtime_temp_census() -> Result<String, String> {
    Err("runtime-temp census: FAIL leftovers:3 paths:[\\"/tmp/elastos\\", \\"/tmp/elastos/storage\\", \\"/tmp/elastos/storage/a6-a12-evidence-fix-planted\\"]".into())
}"""
        mutated = a12.replace(old, new, 1)
        self.assertNotEqual(mutated, a12)
        output = run_named_tests(a6, mutated, A12_LIST_AND_PLANT)
        self.assertEqual(classify(output, A12_LIST_AND_PLANT), "SURVIVED", output)

    def test_owner_census_still_blocks_storage(self) -> None:
        census = (REPO / "lab/agent-conformance/src/census.rs").read_text()
        self.assertIn("outside-root:BLOCKED(AC-006-STORAGE)", census)
        self.assertNotIn("/tmp/elastos/storage", census)


class FalsifiedA6Journey(unittest.TestCase):
    """These fail: #343 never presents a token to Runtime validate."""

    def test_a6_source_is_a_capability_token_journey(self) -> None:
        src = (SUBJECT / "a6.rs").read_text()
        self.assertIn("CapabilityToken", src)

    def test_a6_source_calls_runtime_validate(self) -> None:
        src = (SUBJECT / "a6.rs").read_text()
        self.assertTrue(
            re.search(r"\bvalidate\s*\(", src),
            "A6 must call Runtime validate, not a local string compare",
        )

    def test_named_a6_tests_catch_a_prefix_sibling(self) -> None:
        a6, a12 = subject_sources()
        mutated = a6.replace(
            "    if token_capsule != caller_capsule {",
            "    if !caller_capsule.starts_with(token_capsule) {",
            1,
        )
        output = run_named_tests(mutated, a12, A6_JOURNEY)
        self.assertEqual(
            classify(output, A6_JOURNEY),
            "CAUGHT",
            "prefix sibling must fail the named A6 tests",
        )


class FalsifiedA12Wiring(unittest.TestCase):
    """These fail: #343 does not invoke the owner census or see hidden trees."""

    def test_a12_calls_owner_cleanup(self) -> None:
        src = (SUBJECT / "a12.rs").read_text()
        self.assertIn("agent_conformance::census::cleanup(", src)

    def test_a12_constructs_a_throwaway_home(self) -> None:
        src = (SUBJECT / "a12.rs").read_text()
        self.assertIn("ThrowawayHome::new", src)

    def test_walk_reports_files_behind_a_symlink_root(self) -> None:
        # Needed property: a census of /tmp/elastos/storage still sees files
        # when that name is a symlink. The subject walk stops at the symlink.
        src = (SUBJECT / "a12.rs").read_text()
        self.assertNotIn(
            "if meta.file_type().is_symlink() || !meta.is_dir() {\n        return Ok(());\n    }",
            src,
        )

    def test_subject_has_a_clean_tmp_pass_test(self) -> None:
        lib = (SUBJECT / "lib.rs").read_text()
        self.assertIn("runtime-temp census: PASS", lib)


class FalsifiedCombinedInvoke(unittest.TestCase):
    def test_combined_cleanup_does_not_hardcode_the_existing_pass_line(self) -> None:
        lib = (SUBJECT / "lib.rs").read_text()
        self.assertNotIn(
            "outside-root:BLOCKED(AC-006-STORAGE)",
            lib,
        )


if __name__ == "__main__":
    unittest.main()
