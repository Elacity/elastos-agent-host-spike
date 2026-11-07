"""M1 red team: the provider lane's reports (#251, #257). Both book no M1 check.

#257 states "All line numbers below are at" ce62fa9. Every explicit
`path:line` citation and every table row is checked at that commit.
#251 records "35 CAUGHT of 35" for PV75-PV109 at base f92fe859 on the Mac.
Those ids are runner self-tests, so the same command is replayed here at the
same base in a scratch clone.
"""

import re
import unittest

import rt

A4_REPORT = "examples/agent-host/handoff/reports/provider-a4-deepseek-turn-gaps.md"
A4_REV = "ce62fa9ce1eed4d7d33930604e72d077059740f6"
REPLAY_BASE = "f92fe85970ad0898be4f5247cf580b1f5eaf4bda"
REPLAY_IDS = ["PV%d" % n for n in range(75, 110)]


class ProviderA4ReportCitations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = rt.git_show(A4_REPORT)
        cls.cache = {}

    def lines(self, path):
        if path not in self.cache:
            try:
                self.cache[path] = rt.git_show(path, A4_REV).splitlines()
            except rt.SetupError:
                self.cache[path] = None
        return self.cache[path]

    def test_every_explicit_citation_is_in_range_at_its_commit(self):
        checked, problems = 0, []
        for m in re.finditer(r"`((?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\.[a-z]+):(\d+)(?:-(\d+))?`", self.report):
            lines = self.lines(m.group(1))
            checked += 1
            if lines is None or int(m.group(3) or m.group(2)) > len(lines):
                problems.append(m.group(0))
        print("#257: %d explicit citations at %s" % (checked, A4_REV[:9]))
        self.assertGreater(checked, 50)
        self.assertEqual(problems, [])

    def test_table_rows_name_the_cited_test_and_ignore_line(self):
        rows = re.findall(r"\| `([a-z0-9_]+)` \| `([^`:]+):(\d+)`(?: \(`#\[ignore\]` at `:(\d+)`\))?", self.report)
        self.assertEqual(len(rows), 5)
        for name, path, line, ignore in rows:
            lines = self.lines(path)
            self.assertIn("fn %s(" % name, lines[int(line) - 1])
            if ignore:
                self.assertTrue(lines[int(ignore) - 1].strip().startswith("#[ignore"), name)


class ProviderGateReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = rt.scratch_clone("provider-replay", rev=REPLAY_BASE)
        cls.code, cls.output = rt.run(
            ["python3", "-I", "examples/agent-host/falsify.py", "--from",
             "capsules/model-provider/falsifiers.json", *REPLAY_IDS],
            cwd=root, env={"RUST_TEST_THREADS": "2", "CARGO_INCREMENTAL": "0"}, timeout=3600)

    def test_replay_reads_35_caught_of_35(self):
        summary = re.findall(r"summary: .*", self.output)
        print("#251 replay on Linux at %s: %s" % (REPLAY_BASE[:9], summary))
        self.assertEqual(self.code, 0, self.output[-3000:])
        self.assertEqual(summary, ["summary: 35 CAUGHT of 35"])


if __name__ == "__main__":
    unittest.main()
