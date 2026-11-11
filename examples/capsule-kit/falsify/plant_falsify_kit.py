"""Plants for the mutation runner's own rules.

Each plant breaks one rule of falsify_kit.py in a temporary copy (this
folder is not touched), runs test_falsify_kit.py against the copy, and
requires the named test to FAIL at an assertion. A test that ends in an
error (an exception that is not a failed assertion) does not count: a plant
that only breaks the file proves nothing about the rule.

Run: python3 -I examples/capsule-kit/falsify/plant_falsify_kit.py
"""
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
CLOCK = "test_a_file_restored_after_the_clock_stepped_back_is_newer_than_the_build_before_it"
OTHER_CRATE = "test_a_build_that_compiled_only_another_crate_did_not_compile_the_mutant"
ONCE = "test_a_mutant_is_built_once_and_its_restore_once_and_cargo_is_not_told_to_be_quiet"
OWN_LINE = "test_a_named_test_failed_only_if_its_own_line_says_failed"
NOT_COMPILED = '        if result.returncode == 0 and _not_compiled(result.stderr):\n            names'

# (what the plant removes, exact old text, new text, the test that must fail)
PLANTS = [
    ("the time after a command is not noted",
     "    result = subprocess.run(cmd, cwd=cwd, env=env(), capture_output=True, text=True)\n    _note_time()\n",
     "    result = subprocess.run(cmd, cwd=cwd, env=env(), capture_output=True, text=True)\n",
     CLOCK),
    ("time that really passed is ignored",
     "    _latest_seen = max(_latest_seen, time.time(), _started[0] + passed)\n",
     "    _latest_seen = max(_latest_seen, time.time(), passed * 0)\n",
     "test_time_that_really_passed_counts_when_the_clock_stepped_back_during_a_command"),
    ("a restored file is stamped at the clock, not after the latest time seen",
     "    paths = [pathlib.Path(path) for path in paths]\n    _stamp_after_latest(paths, 1)\n",
     "    paths = [pathlib.Path(path) for path in paths]\n    [os.utime(each, (time.time(), time.time())) for each in paths]\n",
     CLOCK),
    ("a mutant is left at the time the clock gave it",
     "    _compiled = False\n    _stamp_after_latest(_planted, 1)\n",
     "    _compiled = False\n",
     CLOCK),
    ("the runner does not say a mutant was planted",
     "            planted(touched)\n",
     "",
     "test_a_mutant_no_build_compiled_stops_the_run_and_is_not_scored"),
    ("the runner does not say a mutant was restored",
     "            restored(saved)\n",
     "",
     CLOCK),
    ("a build that compiled nothing is not tried again",
     "        _stamp_after_latest(_planted, 60)\n        result = run(cmd, cwd)\n" + NOT_COMPILED,
     NOT_COMPILED,
     "test_a_mutant_cargo_did_not_rebuild_is_stamped_ahead_and_built_again"),
    ("a second build that compiled nothing is accepted",
     NOT_COMPILED,
     "        if False:\n            names",
     "test_a_mutant_no_build_compiled_stops_the_run_and_is_not_scored"),
    ("a build that had to be made again does not say so",
     '            f"built again, stamped ahead: the first build did not compile',
     '            f"',
     "test_a_build_that_had_to_be_made_again_says_so"),
    ("the restore is not followed by a checked build",
     "        if again is not None:\n            _planted[:] = paths\n            build(*again)\n",
     "        if again is not None:\n            pass\n",
     "test_a_restored_file_cargo_did_not_rebuild_stops_the_run"),
    ("a named test runs without a checked build",
     '    if not _compiled and any(str(path).endswith(".rs") for path in _planted):\n',
     "    if False:\n",
     "test_a_named_test_is_not_run_before_a_build_compiled_the_mutant"),
    ("a checked build is not remembered",
     "    _compiled = bool(_planted)\n",
     "    _compiled = False\n",
     "test_a_named_test_is_not_run_before_a_build_compiled_the_mutant"),
    ("a mutant in a file that is not Rust passes a build unchecked",
     "    if other:\n",
     "    if False:\n",
     "test_a_mutant_in_a_file_that_is_not_rust_cannot_be_built_and_scored"),
    ("any crate's Compiling line counts",
     '    return [crate for crate in crates if not re.search(rf"^\\s*Compiling {re.escape(crate)} v", stderr, re.M)]\n',
     '    return [crate for crate in crates if "Compiling" not in stderr]\n',
     OTHER_CRATE),
    ("a crate name is matched as a prefix of another",
     're.search(rf"^\\s*Compiling {re.escape(crate)} v", stderr, re.M)',
     're.search(rf"^\\s*Compiling {re.escape(crate)}", stderr, re.M)',
     OTHER_CRATE),
    ("the crate is the first name in the manifest, whatever its table",
     "            if in_package and name:\n",
     "            if name:\n",
     ONCE),
    ("cargo is left quiet for the build",
     '    loud = [arg for arg in args if arg not in ("-q", "--quiet")]\n    build(',
     "    loud = list(args)\n    build(",
     ONCE),
    ("cargo is left quiet for the named test",
     '    loud = [arg for arg in args if arg not in ("-q", "--quiet")]\n    result = run(',
     "    loud = list(args)\n    result = run(",
     "test_a_named_test_is_run_without_q_so_that_its_line_is_printed"),
    ("a build with no mutant in place must also compile something",
     '    crates = sorted({_crate(path) for path in _planted if str(path).endswith(".rs")})\n',
     '    crates = sorted({_crate(path) for path in _planted if str(path).endswith(".rs")} | {"something"})\n',
     "test_a_build_with_no_mutant_in_place_only_has_to_pass"),
    ("a named test is scored from Cargo's exit code",
     '    failed = marks[0] == "FAILED"\n',
     "    failed = result.returncode != 0\n",
     OWN_LINE),
    ("a named test's line is matched as a prefix",
     r'(?: - should panic)? \.\.\. (ok|FAILED)$", line)',
     r'.*(ok|FAILED)$", line)',
     OWN_LINE),
    ("a named test may have run more than once",
     "    if len(marks) != 1:\n",
     "    if len(marks) < 1:\n",
     OWN_LINE),
    ("the binary's summary need not agree with the test's line",
     '    if not any(line.startswith("test result:") and summary in line for line in lines):\n',
     "    if False:\n",
     OWN_LINE),
]


def main():
    bad = 0
    for what, old, new, test in PLANTS:
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("falsify_kit.py", "test_falsify_kit.py"):
                shutil.copy(HERE / name, tmp)
            kit = pathlib.Path(tmp) / "falsify_kit.py"
            text = kit.read_text()
            if text.count(old) != 1:
                raise SystemExit(f"plant '{what}': the text to replace occurs {text.count(old)} times")
            kit.write_text(text.replace(old, new))
            run = subprocess.run(
                [sys.executable, "-I", str(pathlib.Path(tmp) / "test_falsify_kit.py")],
                capture_output=True,
                text=True,
            )
        failed = f"FAIL: {test} " in run.stderr
        errored = f"ERROR: {test} " in run.stderr
        state = "RED" if failed else ("NOT RED (the test ended in an error, not a failed assertion)" if errored else "NOT RED")
        print(f"{state}: {what} -> {test}", flush=True)
        bad += 0 if failed else 1
    if bad:
        raise SystemExit(f"{bad} plant(s) on the runner's own rules did not turn their test red")
    print(f"all {len(PLANTS)} plants on the runner's own rules are red at their named test")


if __name__ == "__main__":
    main()
