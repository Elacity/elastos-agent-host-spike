#!/usr/bin/env python3
"""This test code stands in for the Runtime's launch by CID, which does not exist yet.

Compile each stand-in mutant and run only its named host test with --exact.
Use --check to confirm each anchor occurs once, without building or running.
"""
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "capsule-kit" / "falsify"))
import falsify_kit as kit  # noqa: E402

SUPPORT = HERE / "host-test/tests/support/ph6_stand_in.rs"
CASES = [
    (
        "F19 stand-in success without running the core",
        SUPPORT,
        [(
            "let (result, bridge) = capsule_v1_host_test::run(dependencies.core.path.as_path(), manifest, bridge).await;",
            "let (result, bridge) = (Ok(()), bridge);",
        )],
        ["stand_in_opens_content_cid_and_writes_checked_playlist"],
    ),
    (
        "F21 stand-in runs the removed source core",
        SUPPORT,
        [("dependencies.core.path.as_path()", "source_core")],
        ["stand_in_runs_the_staged_core"],
    ),
    (
        "F22 stand-in grants the deliberately denied image",
        SUPPORT,
        [('bridge.deny(denied_read, "read");', "let _ = denied_read;")],
        ["stand_in_preserves_content_skip_and_authority_stop"],
    ),
]


def compile_stand_in():
    kit.cargo_compiles(HERE / "host-test", ["--test", "ph6_stand_in"])


def stand_in_test_fails(name):
    return kit.cargo_test_fails(HERE / "host-test", ["--test", "ph6_stand_in"], name)


if __name__ == "__main__":
    kit.main(
        [(CASES, compile_stand_in, stand_in_test_fails, None, True)],
        done="all 3 stand-in launch falsifiers caught",
    )
