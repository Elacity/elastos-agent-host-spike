"""M1 red team: the core-calls citation check (#255).

`lab/bus-v2-proposal/check.py` says it refuses "a core-calls citation the
worktree does not support". It checks that a cited path exists, that a cited
line is in range and that `fn NAME(` or `def NAME(` appears after whitespace.
These tests call the merged `check.problems` on temporary drafts, the way the
lane's own tests do. The lane folder is read, never written.
"""

import sys
import tempfile
import unittest
from pathlib import Path

import rt

sys.path.insert(0, str(rt.REPO / "lab" / "bus-v2-proposal"))
import check  # noqa: E402


class CitationCheckScope(unittest.TestCase):
    def problems(self, body, files):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        draft = root / "lab" / "bus-v2-proposal" / "CORE-CALLS-PROPOSAL.md"
        draft.parent.mkdir(parents=True)
        draft.write_text(body, encoding="utf-8")
        for rel, data in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return check.problems(root)

    def test_control_line_past_the_end_is_refused(self):
        got = self.problems("Grants are strings (`wit/bus.wit:9`).\n",
                            {"wit/bus.wit": b"package elastos:bus@1.0.0;\n"})
        self.assertEqual(len(got), 1)

    @unittest.expectedFailure
    def test_fm_b1_a_line_that_does_not_support_the_sentence_is_refused(self):
        """REPORT.md row FM-B1: an in-range line that says something else."""
        got = self.problems(
            "Bus v1 passes the grant to the guest as a string (`wit/bus.wit:1`).\n",
            {"wit/bus.wit": b"package elastos:bus@1.0.0;\nrecord grant { id: string }\n"})
        self.assertNotEqual(got, [])

    @unittest.expectedFailure
    def test_fm_b1_a_function_named_only_in_a_comment_is_refused(self):
        """REPORT.md row FM-B1: `fn NAME(` inside a comment satisfies `::NAME`."""
        got = self.problems("The check is `pkg/one.rs::wanted`.\n",
                            {"pkg/one.rs": b"// fn wanted( was removed\nfn other() {}\n"})
        self.assertNotEqual(got, [])


if __name__ == "__main__":
    unittest.main()
