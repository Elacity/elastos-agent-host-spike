"""M1 red team: the Runtime behaviour behind A6 (#201) and A8 (#179).

The agent-conformance journeys for A6 and A8 run only on macOS (their harness
refuses other hosts). These falsifiers ask the Runtime code those journeys
exercise the question the journeys rely on, through the Runtime's own handler
functions, in a scratch clone. The test modules in `rust/runtime_*_m1.rs` are
copied into that clone only.

The build is the heaviest step here (elastos-server, test profile). Set
RT_M1_TARGET to reuse an existing target root.
"""

import unittest

import rt

SERVER = "elastos/crates/elastos-server/src"
CAP = "api::handlers::capability::redteam_m1::"
BRIDGE = "resource_bridge::redteam_m1::"
NAMES = [
    CAP + "control_a_sibling_request_reaches_pending",
    CAP + "control_a_token_is_refused_for_another_session",
    CAP + "fm_a6_a_live_grant_changes_the_answer_for_its_own_session",
    BRIDGE + "control_the_manifest_bound_refuses_both_resources",
    BRIDGE + "control_a_parent_segment_under_the_declared_prefix_is_refused",
    BRIDGE + "fm_a8_the_asserted_refusal_is_specific_to_a_host_file",
]
# The agent-conformance lab builds the Runtime with these settings; matching
# them lets a shared target root reuse its dependencies.
ENV = {"CARGO_INCREMENTAL": "0", "CARGO_PROFILE_DEV_DEBUG": "0",
       "RUSTFLAGS": None, "CARGO_ENCODED_RUSTFLAGS": None}


class RuntimeObservations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = rt.scratch_clone("runtime")
        (root / SERVER / "api/handlers/redteam_m1_capability.rs").write_text(
            rt.rust_source("runtime_capability_m1.rs"), encoding="utf-8")
        rt.append(root, SERVER + "/api/handlers/capability.rs",
                  '\n#[cfg(test)]\n#[path = "redteam_m1_capability.rs"]\nmod redteam_m1;\n')
        (root / SERVER / "redteam_m1_bridge.rs").write_text(
            rt.rust_source("runtime_bridge_m1.rs"), encoding="utf-8")
        rt.append(root, SERVER + "/resource_bridge.rs",
                  '\n#[cfg(test)]\n#[path = "redteam_m1_bridge.rs"]\nmod redteam_m1;\n')
        _, cls.output, cls.results = rt.cargo_test(
            root, "elastos/Cargo.toml", "runtime", args=["-p", "elastos-server", "--lib"],
            filters=NAMES, env=ENV, timeout=4 * 3600)

    def result(self, name):
        return self.results[name]

    def test_controls_pass(self):
        for name in NAMES:
            if "::control_" in name:
                self.assertEqual(self.result(name), "ok", name)

    @unittest.expectedFailure
    def test_fm_a6_live_grant_changes_the_answer(self):
        """FM-A6: every request reaches pending, so the A6 sibling observation
        cannot show a grant staying with its session. REPORT.md row FM-A6."""
        self.assertEqual(self.result(CAP + "fm_a6_a_live_grant_changes_the_answer_for_its_own_session"), "ok")

    @unittest.expectedFailure
    def test_fm_a8_refusal_is_specific_to_host_files(self):
        """FM-A8: A8's required reason is the generic manifest bound. REPORT.md
        row FM-A8."""
        self.assertEqual(self.result(BRIDGE + "fm_a8_the_asserted_refusal_is_specific_to_a_host_file"), "ok")


if __name__ == "__main__":
    unittest.main()
