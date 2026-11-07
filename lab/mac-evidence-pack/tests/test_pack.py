import os
import tempfile
import unittest
from pathlib import Path

import common  # noqa: F401
from common import PACK

import pack
from catalog import ROWS
from preflight import load_facts


class PackTests(unittest.TestCase):
    def test_plan_names_every_pin(self):
        text = pack.format_plan()
        self.assertIn("cursor/a1-a8-hardening-85ce", text)
        self.assertIn("1a82d25bdd00d3a383433de84e97c39a4184d107", text)
        self.assertIn("cursor/redteam-fix-4bfb", text)
        self.assertIn("fa1841f35d32e7bea98e124fd406231d0088fd4e", text)
        self.assertIn("cursor/a6-a12-evidence-fix-6e3b", text)
        self.assertIn("011d01f283a3f4ed4717383ecedf55622d451b4d", text)
        self.assertIn("cursor/demo-a14-installed-demo-83e1", text)
        self.assertIn("39b4b47edc64d8705a0294c978e6171819cea9fc", text)
        self.assertIn("pin:NEEDS_REPIN", text)
        self.assertIn("A14  sh lab/demo-a14/preflight.sh", text)
        command_lines = [
            line
            for line in text.splitlines()
            if line.startswith("  A14  ") and "pointer:" not in line
        ]
        self.assertEqual(command_lines, ["  A14  sh lab/demo-a14/preflight.sh"])

    def test_dry_run_writes_summary_and_marks_rows_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            work = home / "mac-evidence-pack" / "dry"
            previous_home = os.environ.get("HOME")
            os.environ["HOME"] = str(home)
            try:
                results = pack.run(
                    work=work,
                    pack_clone=None,
                    dry_run=True,
                    facts=load_facts(PACK / "fixtures" / "linux-x64.json"),
                )
            finally:
                if previous_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = previous_home
            summary = (work / "summary.txt").read_text(encoding="utf-8")
            plan = (work / "plan.txt").read_text(encoding="utf-8")
            fixtures = (work / "fixture-preflight.txt").read_text(encoding="utf-8")
        self.assertEqual(len(results), len(ROWS))
        self.assertTrue(all(item.verdict.status == "NOT RUN" for item in results))
        self.assertIn("NOT RUN", summary)
        self.assertIn("A8", summary)
        self.assertIn("A14", summary)
        self.assertIn("1a82d25bdd00d3a383433de84e97c39a4184d107", plan)
        self.assertIn("pin:NEEDS_REPIN", plan)
        self.assertIn("fa1841f35d32e7bea98e124fd406231d0088fd4e", summary)
        self.assertIn("rosetta: REFUSED", fixtures)
        self.assertIn("darwin-arm64: PASS", fixtures)
        self.assertIn("pointer", summary)

    def test_summary_written_after_crash(self):
        def boom(*_args, **_kwargs):
            raise RuntimeError("planted crash")

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            work = home / "mac-evidence-pack" / "crash"
            previous_home = os.environ.get("HOME")
            os.environ["HOME"] = str(home)
            try:
                results = pack.run(
                    work=work,
                    pack_clone=None,
                    dry_run=True,
                    facts=load_facts(PACK / "fixtures" / "darwin-arm64.json"),
                    run_row_fn=boom,
                )
            finally:
                if previous_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = previous_home
            summary = work / "summary.txt"
            self.assertTrue(summary.is_file())
            text = summary.read_text(encoding="utf-8")
        self.assertTrue(any(item.verdict.status == "FAIL" for item in results))
        self.assertIn("planted crash", text)

    def test_preflight_refusal_marks_rows_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            work = home / "mac-evidence-pack" / "refused"
            results = pack.run(
                work=work,
                pack_clone=None,
                dry_run=False,
                facts=load_facts(PACK / "fixtures" / "rosetta.json"),
            )
            summary = (work / "summary.txt").read_text(encoding="utf-8")
        self.assertTrue(all(item.verdict.status == "NOT RUN" for item in results))
        self.assertIn("Rosetta", summary)
        self.assertIn("preflight: FAIL", summary)

    def test_main_refuses_work_dir_outside_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            outside = Path(tmp) / "outside"
            previous_home = os.environ.get("HOME")
            os.environ["HOME"] = str(home)
            try:
                status = pack.main(
                    ["--dry-run", "--work-dir", str(outside)]
                )
            finally:
                if previous_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = previous_home
            self.assertEqual(status, 2)
            summaries = list(home.glob("mac-evidence-pack/*/summary.txt"))
            self.assertTrue(summaries, "refused run must still write summary.txt")
            text = summaries[0].read_text(encoding="utf-8")
            self.assertIn("abort:", text)
            self.assertIn("outside HOME", text)

    def test_foreign_pack_clone_writes_summary_and_refuses(self):
        from common import init_repo

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            foreign = Path(tmp) / "sash-spike"
            init_repo(foreign)
            work = home / "mac-evidence-pack" / "foreign"
            previous_home = os.environ.get("HOME")
            os.environ["HOME"] = str(home)
            try:
                status = pack.main(
                    [
                        "--dry-run",
                        "--work-dir",
                        str(work),
                        "--pack-clone",
                        str(foreign),
                    ]
                )
            finally:
                if previous_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = previous_home
            summary = work / "summary.txt"
            self.assertEqual(status, 2)
            self.assertTrue(summary.is_file())
            text = summary.read_text(encoding="utf-8")
        self.assertIn("FOREIGN_CLONE", text)
        self.assertIn("abort:", text)
        self.assertIn("fa1841f35d32e7bea98e124fd406231d0088fd4e", text)
