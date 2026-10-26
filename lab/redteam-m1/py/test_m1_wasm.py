"""M1 red team: the wasm-capsule lab memory cap (#254, #262, #269, #273).

FM-W1: the real-engine tests print "SKIPPED ... (no result, not a PASS)" and
return when an engine is absent, so libtest reports them as passed.
FM-W2: the two-engine runner starts wasmer with no memory cap and accepts the
run (Flint's C0 refusal, "refuse to start an engine that cannot apply the
capsule's declared memory cap, never run it uncapped", is not built).
The runner test is appended to a scratch clone of `tests/run.rs` so it can use
that file's own helpers; the lane folder never changes.
"""

import shutil
import unittest

import rt

LANE = "lab/wasm-capsule"
REAL_ENGINE_TESTS = [
    "each_engine_prints_the_fixed_output",
    "zero_grants_zero_imports_runs_on_both_real_engines",
    "real_receipt_names_both_installed_engines",
    "capsule_grows_within_the_declared_cap_on_wasmtime",
    "memory_grow_past_the_declared_cap_traps_on_wasmtime",
    "second_memory_cannot_double_the_declared_cap_on_wasmtime",
    "built_capsule_runs_under_the_declared_cap_on_wasmtime",
]
C0_TEST = "redteam_m1_run_never_starts_an_engine_without_the_declared_cap"
C0_SOURCE = r'''

/// M1 red team (lab/redteam-m1, FM-W2): Flint's C0 refusal. A bundle that
/// declares 64 MB must not reach an engine that is started without that cap.
#[test]
fn redteam_m1_run_never_starts_an_engine_without_the_declared_cap() {
    let tmp = TempDir::new("redteam-m1-c0");
    let root = canonical(&tmp);
    let signed = signed_bundle_declaring(&root, "bundle", &grow_module(GROW_PAST_THE_CAP), 64);
    let engines = work_root(&root, "engines");
    let wasmtime = marked(&engines, "wasmtime", "printf 'same\\n'\n");
    let wasmer = marked(&engines, "wasmer", "printf 'same\\n'\n");
    let work = work_root(&root, "work");
    let result = run(&signed.input(&wasmtime, &wasmer, &work));
    let wasmer_started = started(&engines, "wasmer");
    assert!(
        result.is_err() && !wasmer_started,
        "run accepted the bundle (ok: {}) and started wasmer with no memory cap (started: {wasmer_started})",
        result.is_ok()
    );
}
'''
CONTROL = "receipt_cap_line_matches_the_argv_the_engine_got"


class WasmMemoryCap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("wasmtime") or shutil.which("wasmer"):
            raise unittest.SkipTest("an engine is on PATH; FM-W1 needs a host without one")
        root = rt.scratch_clone("wasm")
        rt.append(root, LANE + "/tests/run.rs", C0_SOURCE)
        cls.results = {}
        cls.skipped = {}
        _, _, results = rt.cargo_test(root, LANE + "/Cargo.toml", "wasm", args=["--test", "run"],
                                      filters=[C0_TEST, CONTROL])
        cls.results.update(results)
        for name in REAL_ENGINE_TESTS:
            _, output, results = rt.cargo_test(root, LANE + "/Cargo.toml", "wasm", args=["--test", "run"],
                                               filters=[name], nocapture=True)
            cls.results[name] = results[name]
            cls.skipped[name] = "SKIPPED" in output

    def test_control_lane_shows_wasmer_gets_no_cap(self):
        self.assertEqual(self.results[CONTROL], "ok")

    @unittest.expectedFailure
    def test_fm_w1_a_skipped_real_engine_test_is_not_a_pass(self):
        """REPORT.md row FM-W1."""
        passed_by_skipping = [n for n in REAL_ENGINE_TESTS
                              if self.skipped[n] and self.results[n] == "ok"]
        print("reported ok after printing SKIPPED: %d of %d: %s"
              % (len(passed_by_skipping), len(REAL_ENGINE_TESTS), ", ".join(passed_by_skipping)))
        self.assertEqual(passed_by_skipping, [])

    @unittest.expectedFailure
    def test_fm_w2_run_refuses_an_uncapped_engine(self):
        """REPORT.md row FM-W2."""
        self.assertEqual(self.results[C0_TEST], "ok")


if __name__ == "__main__":
    unittest.main()
