"""M1 red team: model-provider confinement checks (#250, #252, #260, #266, #268).

The model provider keeps its own copies of the trace check
(`allow_rules_trace_to_declared_rights`, #260) and of the operations-table
citation check (`operations_section_cites_existing_tests`, #266). The wallet
crate also reads the model profile with the shared check
(`model_declared_rights_read_on_the_did_and_wallet_template`, #275). Each
falsifier edits a scratch clone and runs the owner tests there.
"""

import unittest

import rt

MODEL = "capsules/model-provider/Cargo.toml"
WALLET = "capsules/wallet-provider/Cargo.toml"
PROFILE = "capsules/model-provider/confine.sb"
TESTS = "capsules/model-provider/tests/confine/main.rs"
MODEL_TRACE = "allow_rules_trace_to_declared_rights"
MODEL_CITES = "operations_section_cites_existing_tests"
SHARED_TRACE = "model_declared_rights_read_on_the_did_and_wallet_template"
# sandbox-exec reads forms, so this is `(allow file-read* (subpath "/"))`. A
# reader that keeps only lines starting with "(allow " does not see it.
MULTI_LINE_WIDE_READ = '(allow\n    file-read* (subpath "/"))\n'
SKIP = "SKIP model-provider"


def model(root, *names, **kw):
    return rt.cargo_test(root, MODEL, "model", args=["--test", "confine"], filters=names, **kw)


def wallet(root, *names):
    return rt.cargo_test(root, WALLET, "wallet", args=["--test", "confine"], filters=names)[2]


class ModelConfineChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = rt.scratch_clone("model-confine")
        cls.runs = {}
        cls.runs["baseline"] = dict(model(root, MODEL_TRACE, MODEL_CITES)[2])
        cls.runs["baseline"].update(wallet(root, SHARED_TRACE))

        rt.append(root, PROFILE, MULTI_LINE_WIDE_READ)
        cls.runs["multi_line"] = dict(model(root, MODEL_TRACE)[2])
        cls.runs["multi_line"].update(wallet(root, SHARED_TRACE))
        rt.reset(root, PROFILE)

        rt.edit(root, TESTS, "fn allow_rules_trace_to_declared_rights() {",
                "fn allow_rules_trace_to_declared_rights_gone() {")
        cls.runs["renamed_trace_test"] = model(root, MODEL_CITES)[2]
        rt.reset(root, TESTS)

        names, results = rt.skipped_tests(root, MODEL, "model", SKIP, args=["--test", "confine"])
        cls.skipped = [n for n in names if results.get(n) == "ok"]
        cls.passed = sum(1 for r in results.values() if r == "ok")

    def test_baseline_passes(self):
        for name in (MODEL_TRACE, MODEL_CITES, SHARED_TRACE):
            self.assertEqual(self.runs["baseline"][name], "ok", name)

    def test_control_shared_check_reads_the_multi_line_form(self):
        self.assertEqual(self.runs["multi_line"][SHARED_TRACE], "FAILED")

    @unittest.expectedFailure
    def test_fm_c6_model_trace_reads_a_multi_line_allow(self):
        """FM-C6: the model's own trace check reads lines, not forms, so a
        root-wide read split after `(allow` has no claimant and still passes;
        only the wallet crate's shared check refuses it. REPORT.md row FM-C6."""
        self.assertEqual(self.runs["multi_line"][MODEL_TRACE], "FAILED")

    @unittest.expectedFailure
    def test_fm_c6_model_citation_check_sees_every_cited_test(self):
        """FM-C6: the operations section cites
        `allow_rules_trace_to_declared_rights`; with that test renamed, the
        citation check passes because it only reads `model_*` spans. REPORT.md
        row FM-C6."""
        self.assertEqual(self.runs["renamed_trace_test"][MODEL_CITES], "FAILED")

    @unittest.expectedFailure
    def test_fm_c5_no_skipped_model_sandbox_test_counts_as_passed(self):
        """FM-C5, model provider. REPORT.md row FM-C5."""
        print("model: %d of %d passed tests printed a skip line: %s"
              % (len(self.skipped), self.passed, ", ".join(self.skipped)))
        self.assertEqual(self.skipped, [])


if __name__ == "__main__":
    unittest.main()
