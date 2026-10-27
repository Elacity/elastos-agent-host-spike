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
ARCHIVE_BUILD_SENTENCE = "The archive build copies `page-client.js` to `surface/browser/page-client.js`."
ARCHIVE_COPY_PHRASE = "The archive build copies `page-client.js`"
ARCHIVE_SENTENCE = "The archive page ships the kit `page-client.js`."
ARCHIVE_PARAGRAPH_SENTENCE = "The archive page ships the kit client."
ARCHIVE_OLD_SENTENCE = "The archive page still has its own client copy."
ARCHIVE_TEST = "ClientOwnerReportTests.test_the_kit_reports_name_the_archive_client_copy"


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

    def test_the_kit_reports_name_the_archive_client_copy(self):
        """the kit reports name the archive client copy"""
        source = (KIT / "KIT-REPORT.md").read_text()
        heading = "\n### A5 delivered: one owner, verified copies\n"
        self.assertEqual(source.count(heading), 1)
        section = source.split(heading, 1)[1].split("\n## ", 1)[0]
        self.assertEqual(section.count(ARCHIVE_BUILD_SENTENCE), 1)
        self.assertEqual(source.count(ARCHIVE_BUILD_SENTENCE), 1)
        self.assertNotIn("The archive page still has its own client copy.", " ".join(source.split()))

        source = (KIT / "README.md").read_text()
        rows = re.findall(r"^\| A5 page kit \|.*$", source, re.M)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].count(ARCHIVE_COPY_PHRASE), 1)

        source = (KIT / "CRATE-REPORT.md").read_text()
        bullets = re.findall(r"^- \*\*Page code\*\*[^\n]*(?:\n[ \t]+[^\n]+)*", source, re.M)
        self.assertEqual(len(bullets), 1)
        self.assertEqual(" ".join(bullets[0].split()).count(ARCHIVE_SENTENCE), 1)
        self.assertEqual(source.count(ARCHIVE_PARAGRAPH_SENTENCE), 1)
        self.assertNotIn(ARCHIVE_OLD_SENTENCE, " ".join(source.split()))
        heading = "\n## What is still copied, and why\n"
        self.assertEqual(source.count(heading), 1)
        section = source.split(heading, 1)[1].split("\n## Counts\n", 1)[0]
        paragraph = " ".join(section.strip().rsplit("\n\n", 1)[-1].split())
        self.assertEqual(paragraph.count(ARCHIVE_PARAGRAPH_SENTENCE), 1)
        self.assertIn(
            "The docs page ships verified copies of the kit's launch client and docs-model renderer.",
            paragraph,
        )
        self.assertIn(
            "The Photos page keeps its client copy until the Runtime's four-file gateway "
            "test allows a fifth file.",
            paragraph,
        )


def failing_tests(*names):
    result = kit.run([sys.executable, "-I", __file__, "-v", *names], HERE)
    output = result.stderr
    count = len(names) if names else 2
    summary = f"Ran {count} test{'s' if count != 1 else ''} in "
    if summary not in output or "ERROR:" in output:
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
            (
                "KIT-REPORT omits the archive client copy sentence",
                KIT / "KIT-REPORT.md",
                [(ARCHIVE_BUILD_SENTENCE, "")],
                [ARCHIVE_TEST],
            ),
            (
                "README A5 omits the archive client copy phrase",
                KIT / "README.md",
                [(ARCHIVE_COPY_PHRASE, "")],
                [ARCHIVE_TEST],
            ),
            (
                "CRATE-REPORT omits the archive client statement",
                KIT / "CRATE-REPORT.md",
                [(ARCHIVE_SENTENCE, "")],
                [ARCHIVE_TEST],
            ),
            (
                "CRATE-REPORT says the archive page has its own client copy",
                KIT / "CRATE-REPORT.md",
                [(ARCHIVE_PARAGRAPH_SENTENCE, ARCHIVE_OLD_SENTENCE)],
                [ARCHIVE_TEST],
            ),
        ]
        kit.main([(cases, None, test_fails, None, True, failing_tests)], args=[],
                 done="all 7 client-owner report falsifiers caught")
    else:
        unittest.main(verbosity=2)
