"""M1 red team: the grant-binding reference model (#263, #271, #274, #277).

The lane states that it counts toward no M1 check. These falsifiers test the
lane's own claims and the A5/A7 shape it models. The Rust module
`rust/grant_binding_m1.rs` is copied into a scratch clone of the crate; the lane
folder never changes (the crate refuses any other Cargo.toml that depends on it,
so a separate crate here would break the lane's own test).
"""

import unittest

import rt

CRATE = "lab/grant-binding"
MODULE = "redteam_m1"


class GrantBindingModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = rt.scratch_clone("grant-binding")
        (root / CRATE / "src" / (MODULE + ".rs")).write_text(
            rt.rust_source("grant_binding_m1.rs"), encoding="utf-8")
        rt.append(root, CRATE + "/src/lib.rs", "\n#[cfg(test)]\nmod %s;\n" % MODULE)
        names = [
            "control_root_under_another_agent_is_refused",
            "control_reserve_over_the_ceiling_is_refused_for_one_agent",
            "fm_gb1_one_agents_hold_does_not_spend_another_agents_allowance",
            "fm_gb2_a_real_symlink_with_a_plain_name_is_refused",
            "fm_gb3_a_case_variant_agent_root_is_refused",
        ]
        _, cls.output, results = rt.cargo_test(
            root, CRATE + "/Cargo.toml", "grant-binding", args=["--lib"],
            filters=["%s::%s" % (MODULE, n) for n in names])
        cls.results = {n: results["%s::%s" % (MODULE, n)] for n in names}

    def test_controls_pass(self):
        self.assertEqual(self.results["control_root_under_another_agent_is_refused"], "ok")
        self.assertEqual(self.results["control_reserve_over_the_ceiling_is_refused_for_one_agent"], "ok")

    @unittest.expectedFailure
    def test_fm_gb1_budget_is_per_agent(self):
        """FM-GB1: one global ceiling and one outstanding total. REPORT.md row FM-GB1."""
        self.assertEqual(self.results["fm_gb1_one_agents_hold_does_not_spend_another_agents_allowance"], "ok")

    @unittest.expectedFailure
    def test_fm_gb2_real_symlink_is_refused(self):
        """FM-GB2: the symlink refusal is a character-class check. REPORT.md row FM-GB2."""
        self.assertEqual(self.results["fm_gb2_a_real_symlink_with_a_plain_name_is_refused"], "ok")

    @unittest.expectedFailure
    def test_fm_gb3_case_variant_root_is_refused(self):
        """FM-GB3: case-variant agent roots are accepted as distinct. REPORT.md row FM-GB3."""
        self.assertEqual(self.results["fm_gb3_a_case_variant_agent_root_is_refused"], "ok")


if __name__ == "__main__":
    unittest.main()
