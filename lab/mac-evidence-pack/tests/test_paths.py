import tempfile
import unittest
from pathlib import Path

import common  # noqa: F401

from paths import PathRefusal, is_inside, remove_inside, require_under_home


class PathTests(unittest.TestCase):
    def test_work_dir_must_be_under_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            outside = Path(tmp) / "outside"
            outside.mkdir()
            with self.assertRaises(PathRefusal):
                require_under_home(outside, home, "the work dir")

    def test_refuses_delete_outside_work_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "work"
            work.mkdir()
            planted = Path(tmp) / "outside.txt"
            planted.write_text("keep\n", encoding="utf-8")
            with self.assertRaises(PathRefusal):
                remove_inside(planted, work)
            self.assertEqual(planted.read_text(encoding="utf-8"), "keep\n")

    def test_deletes_only_inside_work_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "work"
            inner = work / "rows" / "A8"
            inner.mkdir(parents=True)
            (inner / "old.txt").write_text("x\n", encoding="utf-8")
            remove_inside(inner, work)
            self.assertFalse(inner.exists())
            self.assertTrue(work.exists())

    def test_inside_rejects_sibling_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "work"
            work.mkdir()
            sibling = Path(tmp) / "work-extra"
            sibling.mkdir()
            self.assertFalse(is_inside(sibling, work))
