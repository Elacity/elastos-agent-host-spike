#!/usr/bin/env python3
"""Plant one bug at a time in a copy of this pack. The named test must fail."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

ENTRIES = (
    {
        "id": "F-ME-EVIDENCE",
        "file": "grade.py",
        "old": "    if evidence_path is None or not evidence_path.is_file():\n"
        "        return Verdict(\n"
        '            "FAIL",\n'
        '            f"exit {exit_code} with no evidence file",\n'
        "            evidence,\n"
        "        )",
        "new": "    if evidence_path is None or not evidence_path.is_file():\n"
        "        if exit_code == 0:\n"
        '            return Verdict("PASS", "exit 0", evidence)\n'
        "        return Verdict(\n"
        '            "FAIL",\n'
        '            f"exit {exit_code} with no evidence file",\n'
        "            evidence,\n"
        "        )",
        "test": "test_exit_zero_without_evidence_is_fail",
    },
    {
        "id": "F-ME-ROSETTA",
        "file": "preflight.py",
        "old": '    if facts.translated == "1":\n'
        "        out.append(\n"
        '            "this shell is Rosetta (sysctl.proc_translated=1); open a native arm64 Terminal"\n'
        "        )",
        "new": '    if facts.translated == "1" and False:\n'
        "        out.append(\n"
        '            "this shell is Rosetta (sysctl.proc_translated=1); open a native arm64 Terminal"\n'
        "        )",
        "test": "test_rosetta_fixture_is_refused",
    },
    {
        "id": "F-ME-ROOT",
        "file": "preflight.py",
        "old": "    if facts.uid == 0:\n"
        '        out.append("refuses to run as uid 0")',
        "new": "    if facts.uid == 0 and False:\n"
        '        out.append("refuses to run as uid 0")',
        "test": "test_root_fixture_is_refused",
    },
    {
        "id": "F-ME-SPACE",
        "file": "preflight.py",
        "old": "        if path:\n"
        "            hit = has_space(label, path)\n"
        "            if hit:\n"
        "                out.append(hit)",
        "new": "        if path and False:\n"
        "            hit = has_space(label, path)\n"
        "            if hit:\n"
        "                out.append(hit)",
        "test": "test_spaced_path_fixture_is_refused",
    },
    {
        "id": "F-ME-OUTSIDE",
        "file": "paths.py",
        "old": "    return inner == outer or outer in inner.parents",
        "new": "    return True",
        "test": "test_refuses_delete_outside_work_dir",
    },
    {
        "id": "F-ME-A14",
        "file": "catalog.py",
        "old": '        [["sh", "lab/demo-a14/preflight.sh"]],',
        "new": '        [["bash", "lab/demo-a14/install.sh", "--sign"]],',
        "test": "test_a14_does_not_run_the_demo",
    },
    {
        "id": "F-ME-SUMMARY",
        "file": "pack.py",
        "old": '    path = work / "summary.txt"\n',
        "new": '    path = work / "summary.skipped.txt"\n',
        "test": "test_summary_written_after_crash",
    },
    {
        "id": "F-ME-FOREIGN-CLONE",
        "file": "pins.py",
        "old": "    try:\n"
        "        return path.is_file() and path.read_text(encoding=\"utf-8\") == MARKER_TEXT\n"
        "    except OSError:\n"
        "        return False",
        "new": "    try:\n"
        "        return True\n"
        "    except OSError:\n"
        "        return False",
        "test": "test_refuses_existing_non_pack_clone_path",
    },
    {
        "id": "F-ME-PIN-REPIN",
        "file": "pins.py",
        "old": '    if status == "NEEDS_REPIN":\n'
        '        detail = pin.reason or "pin is marked NEEDS_REPIN"\n'
        '        return f"PIN_NEEDS_REPIN: {detail}"',
        "new": '    if status == "NEEDS_REPIN":\n'
        "        return None",
        "test": "test_needs_repin_row_is_fail_not_pass",
    },
    {
        "id": "F-ME-PIN-MISSING",
        "file": "pins.py",
        "old": '    if status == "MISSING" or not pin.sha:\n'
        '        return f"PIN_MISSING: row {pin.id} has no usable SHA"\n'
        "    if len(pin.sha) != 40 or any(ch not in \"0123456789abcdef\" for ch in pin.sha.lower()):\n"
        '        return f"PIN_MISSING: row {pin.id} SHA is not a full commit"',
        "new": '    if status == "MISSING" or not pin.sha:\n'
        "        return None\n"
        "    if len(pin.sha) != 40 or any(ch not in \"0123456789abcdef\" for ch in pin.sha.lower()):\n"
        "        return None",
        "test": "test_missing_pin_is_fail",
    },
    {
        "id": "F-ME-PIN-SUPERSEDED",
        "file": "pins.py",
        "old": '    if status == "SUPERSEDED":\n'
        '        detail = pin.reason or "pin is marked superseded"\n'
        '        return f"PIN_SUPERSEDED: {detail}"',
        "new": '    if status == "SUPERSEDED":\n'
        "        return None",
        "test": "test_superseded_pin_is_fail",
    },
    {
        "id": "F-ME-A12-TMP",
        "file": "isolate.py",
        "old": "    if _REDIRECT_RE.search(text):\n"
        "        return None\n"
        "    return UNREDIRECTABLE",
        "new": "    if _REDIRECT_RE.search(text):\n"
        "        return None\n"
        "    return None",
        "test": "test_a12_unredirectable_is_fail_named_reason",
    },
    {
        "id": "F-ME-ABORT-SUMMARY",
        "file": "pack.py",
        "old": "    dest.mkdir(parents=True, exist_ok=True)\n"
        "    write_summary(\n"
        "        dest,\n"
        "        facts=None,\n"
        "        gaps=[],\n"
        "        results=abort_results(reason),\n"
        "        dry_run=dry_run,\n"
        "        abort=reason,\n"
        "    )\n"
        "    return dest",
        "new": "    dest.mkdir(parents=True, exist_ok=True)\n"
        "    return dest",
        "test": "test_foreign_pack_clone_writes_summary_and_refuses",
    },
)


def _copy_pack(dest: Path) -> None:
    dest.mkdir(parents=True)
    for name in (
        "catalog.py",
        "checkout.py",
        "grade.py",
        "isolate.py",
        "pack.py",
        "paths.py",
        "pins.ini",
        "pins.py",
        "preflight.py",
        "morning.sh",
        "run.sh",
        "README.md",
        "fixtures",
        "tests",
    ):
        src = HERE / name
        if src.is_dir():
            shutil.copytree(src, dest / name)
        else:
            shutil.copy2(src, dest / name)


def _plant(dest: Path, entry: dict) -> None:
    path = dest / entry["file"]
    text = path.read_text(encoding="utf-8")
    if text.count(entry["old"]) != 1:
        raise SystemExit(
            f"{entry['id']}: anchor count {text.count(entry['old'])} in {entry['file']}"
        )
    path.write_text(text.replace(entry["old"], entry["new"], 1), encoding="utf-8")


def _discover_module(name: str) -> str:
    mapping = {
        "test_exit_zero_without_evidence_is_fail": "tests.test_grade.GradeTests",
        "test_rosetta_fixture_is_refused": "tests.test_preflight.PreflightTests",
        "test_root_fixture_is_refused": "tests.test_preflight.PreflightTests",
        "test_spaced_path_fixture_is_refused": "tests.test_preflight.PreflightTests",
        "test_refuses_delete_outside_work_dir": "tests.test_paths.PathTests",
        "test_a14_does_not_run_the_demo": "tests.test_catalog.CatalogTests",
        "test_summary_written_after_crash": "tests.test_pack.PackTests",
        "test_refuses_existing_non_pack_clone_path": "tests.test_checkout.CheckoutTests",
        "test_needs_repin_row_is_fail_not_pass": "tests.test_pins.PinTests",
        "test_missing_pin_is_fail": "tests.test_pins.PinTests",
        "test_superseded_pin_is_fail": "tests.test_pins.PinTests",
        "test_a12_unredirectable_is_fail_named_reason": "tests.test_isolate.IsolateTests",
        "test_foreign_pack_clone_writes_summary_and_refuses": "tests.test_pack.PackTests",
    }
    return f"{mapping[name]}.{name}"


def main() -> int:
    caught = 0
    with tempfile.TemporaryDirectory() as tmp:
        for entry in ENTRIES:
            dest = Path(tmp) / entry["id"]
            _copy_pack(dest)
            _plant(dest, entry)
            target = _discover_module(entry["test"])
            result = subprocess.run(
                [sys.executable, "-m", "unittest", target],
                cwd=dest,
                text=True,
                capture_output=True,
                check=False,
            )
            output = result.stdout + result.stderr
            failed = result.returncode != 0 and (
                "FAIL:" in output
                or "ERROR:" in output
                or "AssertionError" in output
            )
            if failed:
                print(f"{entry['id']} CAUGHT by {entry['test']}")
                caught += 1
            else:
                print(f"{entry['id']} SURVIVED rc={result.returncode}")
                print(output)
                return 1
    print(f"falsifiers: {caught} CAUGHT of {len(ENTRIES)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
