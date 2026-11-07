"""M1 red team: the agent-conformance journeys, run on Linux.

The lane's harness refuses non-macOS hosts (`harness::data_dir`). Three
scratch-only shims let its own journeys run here, unchanged otherwise:

1. `src/harness.rs::data_dir`: Linux uses `<home>/.local/share/elastos`, the
   Runtime's `dirs::data_dir()` rule. It is three levels below Home, as the
   macOS rule is, so A8's fixed `../../../../` depth is unchanged.
2. `src/census.rs`: Linux `lsof` is `/usr/bin/lsof`. Its `-F` field output and
   its exit 1 for a `+D` selection match what the parser expects.
3. `tests/common/mod.rs::operator_platform`: `linux-amd64`, the key
   `components.json` uses.

Then each journey runs on the merged bytes, with one fixture edit, and with one
Runtime edit. Linux is not the lane's declared host: a Linux PASS is extra
evidence for a journey, and a Linux FAIL would need Mac confirmation.

The scratch clone keeps its ignored `target/` between runs (`scratch_reuse`),
so the Runtime is built once. Set RT_M1_AC_NAME to reuse a clone by name.
"""

import os
import re
import sys
import unittest
from pathlib import Path

import rt

LANE = "lab/agent-conformance"
NAME = os.environ.get("RT_M1_AC_NAME", "ac-linux")
STORAGE = Path("/tmp/elastos/storage")

SHIMS = [
    ("src/harness.rs",
     '    if !cfg!(target_os = "macos") {\n        return Err("throwaway Homes require macOS");\n    }\n',
     '    if cfg!(target_os = "linux") {\n        return Ok(home.join(".local/share/elastos"));\n    }\n'
     '    if !cfg!(target_os = "macos") {\n        return Err("throwaway Homes require macOS");\n    }\n'),
    ("src/census.rs",
     'Path::new("/usr/sbin/lsof")',
     'Path::new(if cfg!(target_os = "linux") { "/usr/bin/lsof" } else { "/usr/sbin/lsof" })'),
    ("tests/common/mod.rs",
     '        ("macos", "x86_64") => Ok("darwin-amd64"),\n',
     '        ("macos", "x86_64") => Ok("darwin-amd64"),\n        ("linux", "x86_64") => Ok("linux-amd64"),\n'),
]

# F-ac3b from the lane's own list: the fixture grants instance 2 the sibling read.
F_AC3B = ("fixtures/instance-grants.json", '  "grants": [\n',
          '  "grants": [\n    {\n      "resource": "localhost://Public/agent-conformance-grants/instance-1/own.txt",\n'
          '      "action": "read",\n      "reason": "agent conformance: instance-2 sibling",\n'
          '      "duration": "session"\n    },\n')

# The Runtime's per-session check: a token names the granting session, and the
# provider proxy validates it against the caller's session (step 4).
STEP_4 = ("elastos/crates/elastos-runtime/src/capability/manager.rs",
          "        if token.capsule != caller_capsule_id {\n",
          "        if false && token.capsule != caller_capsule_id {\n")

# An ordinary undeclared resource in place of the fake host key.
ORDINARY = "localhost://Public/an-ordinary-undeclared-file.txt\n"

A6 = "instance_grant_does_not_authorise_sibling"
A6_OVERLAP = "two_instances_overlap_with_separate_grants"
A8 = "host_key_read_is_refused"
A10 = "cancelled_instance_settles_with_reason_sibling_completes"
A11 = "killed_worker_settlement_recorded_without_retry"
A12 = "granted_read_succeeds"


def storage_state():
    if not STORAGE.exists():
        return None
    return sorted(str(p.relative_to(STORAGE)) for p in STORAGE.rglob("*"))


@unittest.skipUnless(sys.platform.startswith("linux"), "these shims port the journeys to Linux")
class LinuxJourneys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if STORAGE.exists():
            raise rt.SetupError(
                "%s exists before the run; FM-A12 measures whether a run creates it. "
                "Remove it by hand after checking it is an earlier run's empty leftover." % STORAGE)
        root = rt.scratch_reuse(NAME)
        lane = root / LANE
        for rel, old, new in SHIMS:
            rt.edit(lane, rel, old, new)
        env = {
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(lane / "target/host"),
            "CARGO_BUILD_BUILD_DIR": str(lane / "target/host-build"),
            "CARGO_INCREMENTAL": "0",
            "RUSTFLAGS": None,
            "CARGO_ENCODED_RUSTFLAGS": None,
        }
        cls.runs = {}
        cls.outputs = {}
        cls.runtime = {}

        def journey(key, name):
            _, output, results = rt.cargo_test(
                root, LANE + "/Cargo.toml", "unused", args=["--test", "effects"],
                filters=[name], nocapture=True, env=env, timeout=3 * 3600)
            cls.runs[key] = results[name]
            cls.outputs[key] = output
            # The lane prints the Runtime it built and launched for this run.
            hashes = set(re.findall(r'version identity: \{"kind":"native","role":"elastos","sha256":"([0-9a-f]{64})"\}', output))
            if len(hashes) != 1:
                raise rt.SetupError("%s: expected one elastos identity line, found %d" % (key, len(hashes)))
            cls.runtime[key] = hashes.pop()
            evidence = [line for line in output.splitlines()
                        if line.startswith(("cleanup census:", "cancel settlement:", "kill settlement:", "host key read:"))]
            print("%s: %s %s elastos:%s %s" % (key, name, results[name], cls.runtime[key][:12],
                                               " | ".join(evidence)), flush=True)

        # Merged bytes (plus the shims).
        cls.storage_before = storage_state()
        journey("a12_baseline", A12)
        cls.storage_after = storage_state()
        for key, name in (("a6_baseline", A6), ("a6_overlap_baseline", A6_OVERLAP),
                          ("a8_baseline", A8), ("a10_baseline", A10), ("a11_baseline", A11)):
            journey(key, name)

        # Fixture edits only.
        rt.edit(lane, "fixtures/host-key-read.txt", rt.git_show(LANE + "/fixtures/host-key-read.txt") + "\n", ORDINARY)
        journey("a8_ordinary_resource", A8)
        rt.reset(root, LANE + "/fixtures/host-key-read.txt")
        rt.edit(lane, *F_AC3B)
        journey("a6_fixture_grants_sibling", A6)
        rt.reset(root, LANE + "/fixtures/instance-grants.json")

        # Runtime edit last: the lane's runtime_under_test rebuilds it once.
        rt.edit(root, *STEP_4)
        journey("a6_runtime_without_session_check", A6)
        journey("a6_overlap_runtime_without_session_check", A6_OVERLAP)
        rt.reset(root, STEP_4[0])

    def test_precondition_mutated_journeys_ran_the_edited_runtime(self):
        baseline = {self.runtime[k] for k in self.runtime if "runtime_without" not in k}
        mutated = {self.runtime[k] for k in self.runtime if "runtime_without" in k}
        self.assertEqual(len(baseline), 1, "every baseline and fixture run used one Runtime")
        self.assertEqual(len(mutated), 1, "both mutated runs used one Runtime")
        self.assertNotEqual(baseline, mutated, "the edited Runtime was rebuilt and launched")

    # Independent Linux runs of the merged journeys.
    def test_merged_journeys_pass_on_linux(self):
        for key in ("a6_baseline", "a6_overlap_baseline", "a8_baseline", "a10_baseline",
                    "a11_baseline", "a12_baseline"):
            self.assertEqual(self.runs[key], "ok", key)

    def test_control_a6_row_catches_a_fixture_grant(self):
        self.assertEqual(self.runs["a6_fixture_grants_sibling"], "FAILED")

    @unittest.expectedFailure
    def test_fm_a6_rows_catch_a_runtime_without_its_session_check(self):
        """FM-A6: with the Runtime's per-session token check removed, both A6
        rows still pass. REPORT.md row FM-A6."""
        self.assertIn("FAILED", (self.runs["a6_runtime_without_session_check"],
                                 self.runs["a6_overlap_runtime_without_session_check"]))

    @unittest.expectedFailure
    def test_fm_a8_row_is_specific_to_a_host_file(self):
        """FM-A8: `host_key_read_is_refused` passes when the fake host key is
        replaced by an ordinary undeclared resource. REPORT.md row FM-A8."""
        self.assertEqual(self.runs["a8_ordinary_resource"], "FAILED")

    @unittest.expectedFailure
    def test_fm_a12_a_run_leaves_no_storage_outside_its_root(self):
        """FM-A12: the run leaves `/tmp/elastos/storage` outside the throwaway
        root while the census passes. REPORT.md row FM-A12."""
        print("/tmp/elastos/storage before: %s; after: %s"
              % (self.storage_before, self.storage_after))
        self.assertEqual(self.storage_after, self.storage_before)


if __name__ == "__main__":
    unittest.main()
