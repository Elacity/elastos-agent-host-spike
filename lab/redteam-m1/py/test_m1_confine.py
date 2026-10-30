"""M1 red team: did/wallet/model confinement source checks.

Targets the shared checks in capsules/wallet-provider/tests/confine.rs that the
confine PRs rely on (#253, #259, #265, #267, #275) and the did profile test
`profile_denies_network`. Each falsifier edits a scratch clone only and runs
the owner's own named tests there.

An expected failure below is a recorded REPORT.md row (FM-C*): the owner check
does not refuse what its documentation says it refuses. Positive controls are
plain tests: the same owner tests do fail on the obvious top-level mutation, so
the run is live and the expected failures are not a broken harness.
"""

import json
import unittest

import rt

DID_PROFILE = "capsules/did-provider/confine.sb"
DID_RIGHTS = "capsules/did-provider/tests/fixtures/confine/declared-rights.json"
DID_TESTS = "capsules/did-provider/tests/confine.rs"
WALLET = "capsules/wallet-provider/Cargo.toml"
DID = "capsules/did-provider/Cargo.toml"

CONTRACT = "both_file_profiles_bind_one_storage_parameter_contract"
TRACE = "every_did_and_wallet_allow_rule_traces_to_one_declared_right"
REMOVAL = "every_did_and_wallet_allow_rule_has_a_registered_removal"
CITES = "every_operations_table_cites_existing_tests"
DID_NETWORK = "profile_denies_network"

# SBPL is a Scheme dialect: Apple's own profiles grant inside (if ...) forms and
# pull rules in with (import ...). None of these forms starts with "(allow ".
NESTED = """
(if #t (allow default))
(begin (allow network*))
(begin (allow process-exec))
(import "bsd.sb")
"""
TOP_LEVEL = "\n(allow default)\n"
# The wallet parser reads this line as sandbox-exec does (its WP31 fixture);
# did's own parser cuts the line at the `;` inside the string.
STRING_SEMICOLON = '\n(deny file-read* (literal "/x;")) (allow default)\n'
WIDE_READ = '(allow file-read* (subpath "/"))'


def wallet(root, *names):
    return rt.cargo_test(root, WALLET, "wallet", args=["--test", "confine"], filters=names)


def did(root, *names):
    return rt.cargo_test(root, DID, "did", args=["--test", "confine"], filters=names)


class ConfineSourceChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = rt.scratch_clone("confine")
        cls.root = root
        cls.runs = {}

        def record(key, wallet_names, did_names=()):
            out = {}
            if wallet_names:
                out.update(wallet(root, *wallet_names)[2])
            if did_names:
                out.update(did(root, *did_names)[2])
            cls.runs[key] = out

        record("baseline", [CONTRACT, TRACE, REMOVAL, CITES], [DID_NETWORK])

        rt.append(root, DID_PROFILE, NESTED)
        record("nested", [CONTRACT, TRACE, REMOVAL], [DID_NETWORK])
        rt.reset(root, DID_PROFILE)

        rt.append(root, DID_PROFILE, TOP_LEVEL)
        record("top_level", [CONTRACT, TRACE, REMOVAL], [DID_NETWORK])
        rt.reset(root, DID_PROFILE)

        rt.append(root, DID_PROFILE, STRING_SEMICOLON)
        record("string_semicolon", [CONTRACT], [DID_NETWORK])
        rt.reset(root, DID_PROFILE)

        # A root-wide read, added to the profile and to the "storage" right.
        rt.append(root, DID_PROFILE, WIDE_READ + "\n")
        rights = json.loads((root / DID_RIGHTS).read_text(encoding="utf-8"))
        storage = [r for r in rights["rights"] if r["id"] == "storage"]
        if len(storage) != 1:
            raise rt.SetupError("did declared rights must hold one storage right")
        storage[0]["rules"].append(WIDE_READ)
        (root / DID_RIGHTS).write_text(json.dumps(rights, indent=2) + "\n", encoding="utf-8")
        record("wide_read_declared", [CONTRACT, TRACE])
        rt.reset(root, DID_RIGHTS)
        record("wide_read_undeclared", [TRACE])
        rt.reset(root, DID_PROFILE)

        # A justification that names nothing beyond the required prefix.
        rights = json.loads((root / DID_RIGHTS).read_text(encoding="utf-8"))
        for entry in rights["platform_baseline"]["rules"]:
            entry["justification"] = "macOS did-provider executable bound as PROVIDER_EXECUTABLE: x"
        (root / DID_RIGHTS).write_text(json.dumps(rights, indent=2) + "\n", encoding="utf-8")
        record("justification_x", [TRACE])
        for entry in rights["platform_baseline"]["rules"]:
            entry["justification"] = "x"
        (root / DID_RIGHTS).write_text(json.dumps(rights, indent=2) + "\n", encoding="utf-8")
        record("justification_no_prefix", [TRACE])
        rt.reset(root, DID_RIGHTS)

        # The cited test is gone; a comment still holds its `fn name(` text.
        rt.edit(root, DID_TESTS, "fn outside_read_denied() {",
                "// fn outside_read_denied() was renamed by the red team\nfn outside_read_denied_gone() {")
        record("citation_comment", [CITES])
        rt.reset(root, DID_TESTS)
        rt.edit(root, DID_TESTS, "fn outside_read_denied() {", "fn outside_read_denied_gone() {")
        record("citation_removed", [CITES])
        rt.reset(root, DID_TESTS)

    def result(self, key, name):
        return self.runs[key][name]

    # Positive controls: the harness is live.
    def test_baseline_owner_checks_pass(self):
        for name in (CONTRACT, TRACE, REMOVAL, CITES, DID_NETWORK):
            self.assertEqual(self.result("baseline", name), "ok", name)

    def test_control_top_level_allow_default_is_refused(self):
        for name in (CONTRACT, DID_NETWORK):
            self.assertEqual(self.result("top_level", name), "FAILED", name)

    def test_control_undeclared_rule_is_refused(self):
        self.assertEqual(self.result("wide_read_undeclared", TRACE), "FAILED")

    def test_control_justification_without_prefix_is_refused(self):
        self.assertEqual(self.result("justification_no_prefix", TRACE), "FAILED")

    def test_control_removed_citation_is_refused(self):
        self.assertEqual(self.result("citation_removed", CITES), "FAILED")

    # Findings.
    @unittest.expectedFailure
    def test_fm_c1_nested_grants_are_refused(self):
        """FM-C1: (allow default), (allow network*) and a second process-exec
        allow inside (if ...)/(begin ...), and an (import ...), pass every
        Linux-runnable source check. REPORT.md row FM-C1."""
        refused = [n for n in (CONTRACT, TRACE, REMOVAL, DID_NETWORK)
                   if self.result("nested", n) == "FAILED"]
        self.assertTrue(refused, "no source check refused the nested grants")

    def test_control_both_parsers_refuse_the_string_semicolon(self):
        """Not a finding: did's own parser cuts at every `;` but fails closed
        ("incomplete profile form"); the shared check reads the string."""
        self.assertEqual(self.result("string_semicolon", CONTRACT), "FAILED")
        self.assertEqual(self.result("string_semicolon", DID_NETWORK), "FAILED")

    @unittest.expectedFailure
    def test_fm_c2_a_declared_root_wide_read_is_refused(self):
        """FM-C2: the trace check accepts any rule declared under an existing
        right id; a root-wide read declared as `storage` passes the trace and
        contract checks. REPORT.md row FM-C2."""
        refused = [n for n in (CONTRACT, TRACE) if self.result("wide_read_declared", n) == "FAILED"]
        self.assertTrue(refused, "the declared root-wide read passed both checks")

    @unittest.expectedFailure
    def test_fm_c3_justification_must_justify(self):
        """FM-C3: a platform-baseline justification of the bare prefix plus "x"
        passes. REPORT.md row FM-C3."""
        self.assertEqual(self.result("justification_x", TRACE), "FAILED")

    @unittest.expectedFailure
    def test_fm_c4_citation_must_name_a_function(self):
        """FM-C4: with the cited test renamed and its old `fn name(` text left in
        a comment, the citation check passes. REPORT.md row FM-C4."""
        self.assertEqual(self.result("citation_comment", CITES), "FAILED")


class ConfineLinuxSkips(unittest.TestCase):
    """FM-C5: on a host without /usr/bin/sandbox-exec, the sandbox tests print a
    skip line and libtest reports them as passed."""

    @classmethod
    def setUpClass(cls):
        if rt.Path("/usr/bin/sandbox-exec").exists():
            raise unittest.SkipTest("sandbox-exec is present; this host runs the sandbox tests")
        root = rt.scratch_clone("confine-skips")
        cls.counts = {}
        for key, manifest, marker in (
            ("wallet", WALLET, "SKIP wallet-provider"),
            ("did", DID, "SKIP did-provider"),
        ):
            names, results = rt.skipped_tests(root, manifest, key, marker, args=["--test", "confine"])
            skipped = [n for n in names if results.get(n) == "ok"]
            cls.counts[key] = (skipped, sum(1 for r in results.values() if r == "ok"))

    @unittest.expectedFailure
    def test_fm_c5_no_skipped_sandbox_test_counts_as_passed(self):
        """REPORT.md row FM-C5."""
        for key, (skipped, passed) in self.counts.items():
            print("%s: %d of %d passed tests printed a skip line: %s"
                  % (key, len(skipped), passed, ", ".join(skipped)))
        self.assertEqual(sum(len(skipped) for skipped, _ in self.counts.values()), 0)


if __name__ == "__main__":
    unittest.main()
