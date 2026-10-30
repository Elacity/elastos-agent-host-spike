import tempfile
import unittest
from pathlib import Path

import common  # noqa: F401
from common import init_repo, write_owned_marker

from catalog import row_by_id
from isolate import (
    UNREDIRECTABLE,
    inspect_runner,
    isolation_env,
    redirect_reason_from_text,
    row_needs_isolation,
)
from pack import run_one_row


class IsolateTests(unittest.TestCase):
    def test_hardcoded_shared_tmp_is_unredirectable(self):
        text = 'pub const ROOTS: &[&str] = &["/tmp/elastos/storage", "/tmp/elastos"];\n'
        self.assertEqual(redirect_reason_from_text(text), UNREDIRECTABLE)

    def test_env_redirectable_runner_is_accepted(self):
        text = (
            'let root = std::env::var("ELASTOS_TMP_ROOT")'
            '.unwrap_or_else(|_| "/tmp/elastos/storage".into());\n'
        )
        self.assertIsNone(redirect_reason_from_text(text))

    def test_no_shared_path_needs_no_redirect(self):
        self.assertIsNone(redirect_reason_from_text("fn leftover() {}\n"))

    def test_a6_and_a12_need_isolation(self):
        self.assertTrue(row_needs_isolation(row_by_id("A6")))
        self.assertTrue(row_needs_isolation(row_by_id("A12")))
        self.assertFalse(row_needs_isolation(row_by_id("A8")))
        self.assertFalse(row_needs_isolation(row_by_id("A14")))

    def test_inspect_runner_reads_checkout_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "co"
            src = checkout / "lab" / "a6-a12-evidence-fix" / "src"
            src.mkdir(parents=True)
            (src / "a12.rs").write_text(
                'PathBuf::from("/tmp/elastos/storage")\n',
                encoding="utf-8",
            )
            self.assertEqual(inspect_runner(checkout), UNREDIRECTABLE)

    def test_a12_unredirectable_is_fail_named_reason(self):
        import pack

        with tempfile.TemporaryDirectory() as tmp:
            clone = Path(tmp) / "pack-clone"
            init_repo(clone)
            write_owned_marker(clone)
            work = Path(tmp) / "work"
            work.mkdir()
            checkout = Path(tmp) / "co"
            src = checkout / "lab" / "a6-a12-evidence-fix" / "src"
            src.mkdir(parents=True)
            (src / "a12.rs").write_text(
                'pub const RUNTIME_TEMP_ROOTS: &[&str] = &["/tmp/elastos/storage"];\n',
                encoding="utf-8",
            )

            def fake_checkout(_work, _clone, _branch, commit):
                return checkout

            original = pack.checkout_commit
            pack.checkout_commit = fake_checkout
            try:
                item = run_one_row(
                    row_by_id("A12"),
                    work=work,
                    pack_clone=clone,
                    dry_run=False,
                    skip_reason=None,
                )
                evidence = (work / "rows" / "A12" / "evidence.txt").read_text(
                    encoding="utf-8"
                )
            finally:
                pack.checkout_commit = original
        self.assertEqual(item.verdict.status, "FAIL")
        self.assertTrue(item.verdict.reason.startswith("A12_SHARED_TMP_UNREDIRECTABLE"))
        self.assertIn("/tmp/elastos/storage", item.verdict.reason)
        self.assertIn("A12_SHARED_TMP_UNREDIRECTABLE", evidence)

    def test_isolation_env_stays_inside_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "work"
            work.mkdir()
            env = isolation_env(work)
        for value in env.values():
            self.assertTrue(value.startswith(str(work)))
            self.assertNotEqual(value, "/tmp/elastos/storage")
            self.assertNotIn("/tmp/elastos/storage", value)
