#!/usr/bin/env python3
"""Pin the kit's client-owner reports and falsify them without starting Cargo."""
import pathlib
import re
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
KIT = HERE.parent / "capsule-kit"
sys.path.insert(0, str(KIT / "falsify"))
import falsify_kit as kit  # noqa: E402

OWNER_SENTENCE = "page-client.js is the one owner of launchToken and pageClient."
OWNER_PATH = "`surface/page-client.js`"
DOCS_SENTENCE = "The docs page ships the kit `page-client.js`."
TEST = "ClientOwnerReportTests.test_the_kit_reports_name_the_docs_client_owner"


class ClientOwnerReportTests(unittest.TestCase):
    def test_the_kit_reports_name_the_docs_client_owner(self):
        """the kit reports name the docs client owner"""
        source = (KIT / "KIT-REPORT.md").read_text()
        heading = "\n### A5 delivered: one owner, verified copies\n"
        self.assertEqual(source.count(heading), 1)
        section = source.split(heading, 1)[1].split("\n## ", 1)[0]
        self.assertEqual(section.count(OWNER_SENTENCE), 1)
        self.assertEqual(source.count(OWNER_SENTENCE), 1)

        source = (KIT / "README.md").read_text()
        rows = re.findall(r"^\| A5 page kit \|.*$", source, re.M)
        self.assertEqual(len(rows), 1)
        self.assertIn(f"{OWNER_PATH} (the one owner of `launchToken` and `pageClient`)", rows[0])

        source = (KIT / "CRATE-REPORT.md").read_text()
        bullets = re.findall(r"^- \*\*Page code\*\*[^\n]*(?:\n[ \t]+[^\n]+)*", source, re.M)
        self.assertEqual(len(bullets), 1)
        self.assertEqual(" ".join(bullets[0].split()).count(DOCS_SENTENCE), 1)


def failing_tests(*names):
    result = kit.run([sys.executable, "-I", __file__, "-v", *names], HERE)
    output = result.stderr
    if "Ran 1 test in " not in output or "ERROR:" in output:
        raise SystemExit(f"the client-owner report test did not run cleanly:\n{output}")
    failed = set(re.findall(r"^FAIL: (\w+) \(__main__\.(\w+)(?:\.\w+)?\)$", output, re.M))
    if result.returncode != (1 if failed else 0):
        raise SystemExit(f"the client-owner report test did not report its failures:\n{output}")
    return {f"{group}.{name}" for name, group in failed}


def test_fails(name):
    return failing_tests(name) == {name}


if __name__ == "__main__":
    if "--falsify" in sys.argv[1:]:
        cases = [
            (
                "KIT-REPORT omits the client owner sentence",
                KIT / "KIT-REPORT.md",
                [(OWNER_SENTENCE, "")],
                [TEST],
            ),
            (
                "README A5 omits the client owner path",
                KIT / "README.md",
                [(OWNER_PATH, "")],
                [TEST],
            ),
            (
                "CRATE-REPORT omits the docs client statement",
                KIT / "CRATE-REPORT.md",
                [(DOCS_SENTENCE, "")],
                [TEST],
            ),
        ]
        kit.main([(cases, None, test_fails, None, True, failing_tests)], args=[],
                 done="all 3 client-owner report falsifiers caught")
    else:
        unittest.main(verbosity=2)
