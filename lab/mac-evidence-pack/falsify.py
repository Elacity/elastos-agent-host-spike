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
        "old": '            work / "summary.txt",\n',
        "new": '            work / "summary.skipped.txt",\n',
        "test": "test_summary_written_after_crash",
    },
)


def _copy_pack(dest: Path) -> None:
    dest.mkdir(parents=True)
    for name in (
        "catalog.py",
        "checkout.py",
        "grade.py",
        "pack.py",
        "paths.py",
        "preflight.py",
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
