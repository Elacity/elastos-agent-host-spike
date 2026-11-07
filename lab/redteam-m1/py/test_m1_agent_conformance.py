"""M1 red team: agent-conformance A rows, static half.

A8 = #179, A6 = #201, A10 = #213, A11 = #219 and #249, A12 = the cleanup
census (#187, carried by #213, #219 and #249). These tests read the merged
sources, falsifier list and merge titles from git at HEAD, so they run on any
host. `test_m1_ac_linux.py` runs the same journeys on Linux.
"""

import json
import os
import re
import unittest

import rt

LANE = "lab/agent-conformance"
MERGE = {
    "A12": "f9d2b48f8160398e843e0d656d2771fefc4fef29",  # #187
    "A10": "c215763e92c1135421ce1926f8278751758e637a",  # #213
    "A11": "8beb8e56266a2403e2723d2024a58a07af078cfa",  # #219
}
ROWS = {
    "A6": {"two_instances_overlap_with_separate_grants", "instance_grant_does_not_authorise_sibling"},
    "A8": {"host_key_read_is_refused"},
    "A10": {"cancelled_instance_settles_with_reason_sibling_completes"},
    "A11": {"killed_worker_settlement_recorded_without_retry"},
    "A12": {"granted_read_succeeds"},
}


def lane(rel):
    return rt.git_show(LANE + "/" + rel)


def function_body(source, signature):
    """The text of the method that starts with SIGNATURE, to its closing brace
    at the same indentation."""
    start = source.find(signature)
    if start < 0:
        raise rt.SetupError("signature not found: " + signature)
    line_start = source.rfind("\n", 0, start) + 1
    indent = source[line_start:start]
    end = source.find("\n" + indent + "}\n", start)
    if end < 0:
        raise rt.SetupError("end of body not found: " + signature)
    return source[start:end]


class FalsifiersEditOnlyTheLab(unittest.TestCase):
    """FM-AX: every caught falsifier that names an A row edits lab files only."""

    @classmethod
    def setUpClass(cls):
        listed = json.loads(lane("falsifiers.json"))["falsifiers"]
        cls.by_row = {}
        for row, names in ROWS.items():
            entries = [e for e in listed if e.get("expect") == "caught" and names & set(e.get("tests", []))]
            files = sorted({os.path.normpath(os.path.join(LANE, edit["file"]))
                            for entry in entries for edit in entry["edits"]})
            cls.by_row[row] = ([e["id"] for e in entries], files)

    def test_control_every_row_has_caught_falsifiers(self):
        for row, (ids, files) in self.by_row.items():
            print("%s: %s edit %s" % (row, ", ".join(ids), ", ".join(files)))
            self.assertTrue(ids, row)

    @unittest.expectedFailure
    def test_fm_ax_some_falsifier_mutates_runtime_code(self):
        """REPORT.md row FM-AX."""
        for row, (_, files) in self.by_row.items():
            outside = [f for f in files if not f.startswith(LANE + "/")]
            self.assertTrue(outside, "%s: every falsifier edits only %s" % (row, LANE))


class CancelIsAFixtureDenial(unittest.TestCase):
    """FM-A10: the cancel is the fixture's ordinary deny of a pending request."""

    @classmethod
    def setUpClass(cls):
        grants = lane("tests/common/grants.rs")
        cls.poll = function_body(grants, "pub fn poll(&mut self, running: &mut RunningInstances<'_>)")
        cls.deny = function_body(grants, "fn deny(&mut self, request: &Value, reason: &str)")
        cls.cancellations = cls.poll[cls.poll.index("for request in cancellations {"):]
        cls.title = rt.commit_message(MERGE["A10"])
        cls.gaps = lane("GAPS.md")

    def test_control_claim_and_mechanism_are_found(self):
        self.assertIn("Cancel one instance mid-run; the sibling completes unaffected", self.title)
        self.assertIn('"/api/capability/deny"', self.deny)
        self.assertIn("self.deny(request, CANCEL_REASON)?;", self.cancellations)
        self.assertIn("self.deny(request, &reason)?;", self.poll)
        self.assertIn("Resident cancellation stays RT4", self.gaps)

    @unittest.expectedFailure
    def test_fm_a10_cancel_is_not_the_fixture_deny(self):
        """REPORT.md row FM-A10: a Runtime cancel or stop ends the instance."""
        self.assertNotIn("self.deny(request, CANCEL_REASON)", self.cancellations)


class KillSettlementIsFixtureOwned(unittest.TestCase):
    """FM-A11: the killed worker's pending request is settled by the fixture,
    and the only retry the row can catch is one the harness itself starts."""

    @classmethod
    def setUpClass(cls):
        grants = lane("tests/common/grants.rs")
        cls.settle = function_body(grants, "pub fn settle_orphan(&mut self, original: &Value, reason: &str)")
        cls.line = function_body(grants, "pub fn line(&self) -> String")
        cls.title = rt.commit_message(MERGE["A11"])
        listed = json.loads(lane("falsifiers.json"))["falsifiers"]
        retry = [e for e in listed if e["id"] == "F-kill-retry"]
        if len(retry) != 1:
            raise rt.SetupError("F-kill-retry must be listed once")
        cls.retry_files = [edit["file"] for edit in retry[0]["edits"]]
        cls.gaps = lane("GAPS.md")

    def test_control_claim_and_mechanism_are_found(self):
        self.assertIn("settlement recorded, no silent retry", self.title)
        self.assertIn("self.deny(request, reason)?;", self.settle)
        self.assertIn("settled by the fixture", self.line)
        self.assertIn("AC-027-ORPHAN", self.gaps)
        self.assertEqual(self.retry_files, ["tests/effects.rs"])

    @unittest.expectedFailure
    def test_fm_a11_runtime_settles_the_orphan(self):
        """REPORT.md row FM-A11."""
        self.assertNotIn("self.deny(request, reason)", self.settle)

    @unittest.expectedFailure
    def test_fm_a11_retry_falsifier_plants_a_runtime_retry(self):
        """REPORT.md row FM-A11: F-kill-retry starts the worker again from the
        lab harness; no falsifier plants a retry in the Runtime."""
        self.assertTrue(any(f.startswith("../../elastos") for f in self.retry_files))


class CensusScopeVersusTitle(unittest.TestCase):
    """FM-A12: #187's title names four leftovers; the census measures one."""

    @classmethod
    def setUpClass(cls):
        cls.title = rt.commit_message(MERGE["A12"])
        cls.gaps = " ".join(lane("GAPS.md").split())
        cls.effects = lane("tests/effects.rs")
        cls.census = lane("src/census.rs")

    def test_control_title_names_four_leftovers(self):
        self.assertIn("a run leaves no process, socket, temp file or grant", self.title)

    @unittest.expectedFailure
    def test_fm_a12_every_named_leftover_is_measured(self):
        """REPORT.md row FM-A12."""
        unmeasured = []
        if "Unix socket absence under the root remains unmeasured" in self.gaps:
            unmeasured.append("socket (Unix sockets under the root)")
        if re.search(r'#\[ignore = "blocked: AC-021-GRANTS"\]\s*fn run_leaves_no_live_grant', self.effects):
            unmeasured.append("grant (run_leaves_no_live_grant ignored, AC-021-GRANTS)")
        if "outside-root:BLOCKED(AC-006-STORAGE)" in self.census:
            unmeasured.append("temp file outside the root (/tmp/elastos/storage, AC-006-STORAGE)")
        print("unmeasured: " + "; ".join(unmeasured))
        self.assertEqual(unmeasured, [])


if __name__ == "__main__":
    unittest.main()
