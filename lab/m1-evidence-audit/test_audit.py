"""Catalog resolve, then the row-removal falsifier."""

from __future__ import annotations

import unittest
from pathlib import Path

import audit
import falsify

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


class CatalogTests(unittest.TestCase):
    def test_catalog_rows_resolve(self):
        catalog = audit.load_catalog(HERE / "evidence.json")
        problems = audit.audit(catalog, ROOT)
        self.assertEqual(problems, [])

    def test_removing_a_cited_row_is_caught(self):
        self.assertEqual(falsify.falsify_row(ROOT), 0)


if __name__ == "__main__":
    unittest.main()
