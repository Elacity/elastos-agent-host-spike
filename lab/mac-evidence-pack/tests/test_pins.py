import tempfile
import unittest
from pathlib import Path

import common  # noqa: F401
from common import PACK, init_repo, write_owned_marker

from catalog import PIN_BY_ID, ROWS, row_by_id
from grade import grade
from pack import run_one_row
from pins import Pin, load_pin_file, pin_block_reason
from preflight import load_facts


class PinTests(unittest.TestCase):
    def test_pin_file_lists_every_row(self):
        _pack, pins = load_pin_file()
        self.assertEqual(set(pins), {row.id for row in ROWS})
        for row in ROWS:
            pin = pins[row.id]
            self.assertEqual(row.branch, pin.branch)
            self.assertEqual(row.commit, pin.sha)
            self.assertEqual(row.pr, pin.pr)
            self.assertEqual(row.pin_status, pin.status)

    def test_c_series_is_needs_repin_not_a_guessed_sha(self):
        recorded = "fa1841f35d32e7bea98e124fd406231d0088fd4e"
        for row_id in ("C1", "C2", "C3", "C4", "C5", "C6", "C7"):
            pin = PIN_BY_ID[row_id]
            self.assertEqual(pin.status, "NEEDS_REPIN")
            self.assertEqual(pin.sha, recorded)
            reason = pin_block_reason(pin)
            self.assertIsNotNone(reason)
            self.assertTrue(reason.startswith("PIN_NEEDS_REPIN"))
            self.assertIn("#352", reason)

    def test_needs_repin_row_is_fail_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "work"
            work.mkdir()
            item = run_one_row(
                row_by_id("C1"),
                work=work,
                pack_clone=None,
                dry_run=False,
                skip_reason=None,
            )
        self.assertEqual(item.verdict.status, "FAIL")
        self.assertTrue(item.verdict.reason.startswith("PIN_NEEDS_REPIN"))
        self.assertEqual(item.commit_used, PIN_BY_ID["C1"].sha)

    def test_missing_pin_is_fail(self):
        pin = Pin(
            id="A8",
            branch="cursor/a1-a8-hardening-85ce",
            sha="",
            pr=301,
            status="ok",
        )
        reason = pin_block_reason(pin)
        self.assertIsNotNone(reason)
        self.assertTrue(reason.startswith("PIN_MISSING"))

    def test_superseded_pin_is_fail(self):
        pin = Pin(
            id="A8",
            branch="cursor/old",
            sha="1a82d25bdd00d3a383433de84e97c39a4184d107",
            pr=301,
            status="superseded",
            reason="replaced by a later draft",
        )
        reason = pin_block_reason(pin)
        self.assertIsNotNone(reason)
        self.assertTrue(reason.startswith("PIN_SUPERSEDED"))
        verdict = grade(
            row_by_id("A8"),
            exit_code=0,
            evidence_path=None,
            blocked=reason,
        )
        self.assertEqual(verdict.status, "FAIL")
        self.assertIn("PIN_SUPERSEDED", verdict.reason)

    def test_ok_pin_with_full_sha_is_runnable(self):
        self.assertIsNone(pin_block_reason(PIN_BY_ID["A8"]))
        self.assertIsNone(pin_block_reason(PIN_BY_ID["A6"]))
        self.assertIsNone(pin_block_reason(PIN_BY_ID["A14"]))

    def test_missing_sha_in_owned_clone_is_pin_missing(self):
        import pack

        with tempfile.TemporaryDirectory() as tmp:
            clone = Path(tmp) / "pack-clone"
            init_repo(clone)
            write_owned_marker(clone)
            work = Path(tmp) / "work"
            work.mkdir()

            original = pack.checkout_commit

            def boom(*_args, **_kwargs):
                raise pack.CheckoutError(
                    "PIN_MISSING: commit "
                    "1a82d25bdd00d3a383433de84e97c39a4184d107 "
                    "is not in the pack clone after git fetch origin "
                    "cursor/a1-a8-hardening-85ce"
                )

            pack.checkout_commit = boom
            try:
                item = run_one_row(
                    row_by_id("A8"),
                    work=work,
                    pack_clone=clone,
                    dry_run=False,
                    skip_reason=None,
                )
            finally:
                pack.checkout_commit = original
        self.assertEqual(item.verdict.status, "FAIL")
        self.assertTrue(item.verdict.reason.startswith("PIN_MISSING"))

    def test_linux_preflight_keeps_repin_rows_not_run(self):
        import pack
        from catalog import ROWS as rows

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            work = home / "mac-evidence-pack" / "linux"
            results = pack.run(
                work=work,
                pack_clone=None,
                dry_run=False,
                facts=load_facts(PACK / "fixtures" / "linux-x64.json"),
            )
            summary = (work / "summary.txt").read_text(encoding="utf-8")
        self.assertEqual(len(results), len(rows))
        self.assertTrue(all(item.verdict.status == "NOT RUN" for item in results))
        self.assertIn("pin:NEEDS_REPIN", summary)
        self.assertIn("fa1841f35d32e7bea98e124fd406231d0088fd4e", summary)
        self.assertIn("NOT RUN", summary)
        self.assertNotIn("\tPASS\t", summary)
