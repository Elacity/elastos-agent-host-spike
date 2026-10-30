"""Apply mutants to a copy of the #343 crate and run named lib tests."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

REVIEW = Path(__file__).resolve().parents[1]
SUBJECT = REVIEW / "subject"

TEST_BODIES = {
    "tests::a6_owner_may_use_own_session_token": """
    #[test]
    fn a6_owner_may_use_own_session_token() {
        let line = a6::owner_may_use_own_token().expect("A6 owner journey");
        assert!(line.contains("instance-1"), "{line}");
    }
""",
    "tests::a6_sibling_presenting_owner_token_is_refused": """
    #[test]
    fn a6_sibling_presenting_owner_token_is_refused() {
        let line = a6::sibling_presenting_owner_token_is_refused().expect("A6 sibling refusal");
        assert!(line.contains("wrong_capsule"), "{line}");
        assert!(line.contains("expected:instance-1"), "{line}");
        assert!(line.contains("got:instance-2"), "{line}");
    }
""",
    "tests::a12_census_lists_runtime_storage": """
    #[test]
    fn a12_census_lists_runtime_storage() {
        let roots = a12::runtime_owned_temp_roots();
        assert!(
            roots.iter().any(|root| root == std::path::Path::new("/tmp/elastos/storage")),
            "{roots:?}"
        );
        assert!(
            roots.iter().any(|root| root == std::path::Path::new("/tmp/elastos")),
            "{roots:?}"
        );
    }
""",
    "tests::a12_planted_storage_file_is_caught": """
    #[test]
    fn a12_planted_storage_file_is_caught() {
        let plant = a12::StoragePlant::place().expect("plant");
        let err = a12::runtime_temp_census().expect_err("planted leftover must fail");
        assert!(err.contains(plant.path().to_str().unwrap()), "{err}");
        assert!(err.contains("runtime-temp census: FAIL"), "{err}");
        drop(plant);
    }
""",
    "tests::a12_empty_root_is_leftover": """
    #[test]
    fn a12_empty_root_is_leftover() {
        let dir = a12::isolated_dir("empty-root");
        let leftovers = a12::leftovers_under(&[dir.clone()]).expect("walk");
        assert_eq!(leftovers, vec![dir.clone()], "{leftovers:?}");
        a12::remove_isolated(&dir);
    }
""",
}


def slim_lib(tests: list[str]) -> str:
    missing = [name for name in tests if name not in TEST_BODIES]
    if missing:
        raise KeyError(f"no slim body for {missing}")
    bodies = "\n".join(TEST_BODIES[name] for name in tests)
    return f"""pub mod a6;
pub mod a12;

#[cfg(test)]
mod tests {{
    use super::*;
{bodies}
}}
"""


def _write_probe(root: Path, a6: str, a12: str, tests: list[str]) -> None:
    src = root / "src"
    src.mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        "[package]\n"
        'name = "a6-a12-evidence-fix"\n'
        'version = "0.0.0"\n'
        'edition = "2021"\n'
        "publish = false\n\n"
        "[workspace]\n"
    )
    (src / "a6.rs").write_text(a6)
    (src / "a12.rs").write_text(a12)
    (src / "lib.rs").write_text(slim_lib(tests))


def run_named_tests(a6: str, a12: str, tests: list[str], timeout: int = 120) -> str:
    tmp = Path(tempfile.mkdtemp(prefix="review-343-mutant-"))
    try:
        _write_probe(tmp, a6, a12, tests)
        env = os.environ.copy()
        env["CARGO_NET_OFFLINE"] = "true"
        env["CARGO_INCREMENTAL"] = "0"
        env["RUST_TEST_THREADS"] = "2"
        env["CARGO_TARGET_DIR"] = str(tmp / "target")
        result = subprocess.run(
            [
                "cargo",
                "test",
                "--offline",
                "--manifest-path",
                str(tmp / "Cargo.toml"),
                "--lib",
                "--",
                "--nocapture",
            ],
            cwd=tmp,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout + result.stderr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def classify(output: str, tests: list[str]) -> str:
    failed = []
    passed = []
    short = [name.split("::")[-1] for name in tests]
    for name, short_name in zip(tests, short):
        ok = f"test tests::{short_name} ... ok" in output
        bad = f"test tests::{short_name} ... FAILED" in output
        if bad:
            failed.append(name)
        elif ok:
            passed.append(name)
    if failed:
        return "CAUGHT"
    if len(passed) == len(tests):
        return "SURVIVED"
    return f"INCONCLUSIVE\n{output}"


def subject_sources() -> tuple[str, str]:
    return (SUBJECT / "a6.rs").read_text(), (SUBJECT / "a12.rs").read_text()
