"""Sixth adversarial review of draft PR #323 at 65f003aa.

HOLDS tests assert F1 (every #\\ is refused) and F2 (citation needs the
cited file's #[test] plus that file's owning-target cargo list). NEW
decoy tests plant reader-macro, unicode, CRLF/NUL, escape, cfg, shadow,
include!, and extract-copy attacks. WEAK records the r4/r5 W1 case that
is expected red under F1, plus Mac NOT RUN.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REVIEW = ROOT / "lab/review-c1-c7-323-r6"
PROBE_BIN = REVIEW / "probe/target/debug/review323r6-probe"
WALLET_CONFINE = ROOT / "capsules/wallet-provider/tests/confine.rs"
WALLET_READER = ROOT / "capsules/wallet-provider/tests/sbpl_reader.rs"
WALLET_INCLUDE = ROOT / "capsules/wallet-provider/tests/sbpl_include.rs"
MODEL_CONFINE = ROOT / "capsules/model-provider/tests/confine/main.rs"
DID_CONFINE = ROOT / "capsules/did-provider/tests/confine.rs"
WASM_RUN = ROOT / "lab/wasm-capsule/tests/run.rs"

if str(REVIEW) not in os.sys.path:
    os.sys.path.insert(0, str(REVIEW))
import extract  # noqa: E402


def _build_probe() -> None:
    extract.build(REVIEW / "probe")
    subprocess.run(
        ["cargo", "build", "--quiet"],
        cwd=REVIEW / "probe",
        check=True,
    )


def probe(req: dict) -> dict:
    proc = subprocess.run(
        [str(PROBE_BIN)],
        input=json.dumps(req),
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        return {"ok": False, "panic": True, "stderr": proc.stderr}
    return json.loads(proc.stdout)


def fixture_profile() -> str:
    return probe({"op": "fixture"})["profile"]


def contract(extra: str) -> dict:
    return probe({"op": "contract", "profile": fixture_profile() + extra + "\n"})


def holds_cited(source: str, function: str = "present_case") -> bool:
    return probe({"op": "holds_cited", "source": source, "function": function})["holds"]


def cargo_lists(source: str, function: str = "present_case"):
    return probe({"op": "cargo_lists", "source": source, "function": function}).get(
        "listed"
    )


def rust_named_fn_source(src: str, name: str) -> str:
    return extract.extract_named(src, "fn", name)


def setUpModule() -> None:
    _build_probe()
    assert PROBE_BIN.is_file(), PROBE_BIN


class HoldsF1EveryHashBackslash(unittest.TestCase):
    """F1: every #\\ character literal is refused, anywhere."""

    FORMS = [
        r"#\;",
        r"#\; x (allow file*)",
        r'#\; "x" (allow file*)',
        r"#\; 1 (allow file*)",
        r"#\;(allow file*)",
        r"#\;(version 0)(allow file*)",
        r"#\\a",
        r"#\\space",
        r"#\\newline",
        r"#\\x",
        r"#\\(",
        r'#\\;"x"',
        r"#\\#t",
        r"#\\t",
        r"(allow file-read* (literal #\\/))",
        r'(allow file-read* (literal "#\\;"))',
    ]

    def test_holds_every_named_hash_backslash_form_is_refused(self) -> None:
        for form in self.FORMS:
            with self.subTest(form=form):
                got = contract(form)
                self.assertFalse(
                    got.get("ok"),
                    f"F1: every #\\ character literal must be refused: {form!r} -> {got}",
                )

    def test_holds_r4_r5_w1_case_is_now_refused(self) -> None:
        # r4/r5 W1 expected this accepted. Under F1 it must refuse.
        got = contract(r"#\;(allow file*)")
        self.assertFalse(
            got.get("ok"),
            "F1 refuses the r4/r5 W1 spelling; this is not a hide: "
            f"{got}",
        )
        self.assertTrue(
            got.get("panic") or "reason" in got or got.get("ok") is False,
            got,
        )


class HoldsF2CitationOwnedFileAndList(unittest.TestCase):
    """F2: cited file holds #[test] AND owning-target cargo list names it."""

    def test_holds_plain_listed_test_counts(self) -> None:
        source = "#[test]\nfn present_case() {}\n"
        self.assertIs(cargo_lists(source), True)
        self.assertTrue(holds_cited(source))

    def test_holds_name_absent_from_cited_file_does_not_count(self) -> None:
        source = "#[test]\nfn other_case() {}\n"
        self.assertFalse(
            holds_cited(source, "present_case"),
            "a name the cited file does not hold must not count",
        )

    def test_holds_name_from_another_crate_does_not_count(self) -> None:
        source = "use missing_crate::Thing;\nfn unused() { let _ = Thing; }\n"
        self.assertIsNone(cargo_lists(source, "model_provider_ops_under_profile"))
        self.assertFalse(
            holds_cited(source, "model_provider_ops_under_profile"),
            "F2: no union list; a model-only name is not a wallet citation",
        )

    def test_holds_cfg_macos_test_does_not_count_on_linux(self) -> None:
        source = (
            "#[cfg(target_os = \"macos\")]\n"
            "#[test]\n"
            "fn present_case() {}\n"
        )
        listed = cargo_lists(source)
        self.assertIn(listed, (False, None), listed)
        self.assertFalse(
            holds_cited(source),
            "a #[test] behind cfg(target_os = \"macos\") must not count on Linux",
        )

    def test_holds_cfg_macos_mod_does_not_count(self) -> None:
        source = (
            "#[cfg(target_os = \"macos\")]\n"
            "mod only_mac {\n"
            "    #[test]\n"
            "    fn present_case() {}\n"
            "}\n"
        )
        self.assertFalse(
            holds_cited(source),
            "a #[test] in a macos-only mod must not count on Linux",
        )

    def test_holds_shadowed_name_in_other_file_does_not_count(self) -> None:
        # Cited source has the name as a plain fn. A different file in the
        # same crate may list the same name. F2 requires this file's #[test].
        source = "fn present_case() {}\n"
        self.assertIs(cargo_lists(source), False)
        self.assertFalse(
            holds_cited(source),
            "a name shadowed by another file's #[test] must not count here",
        )

    def test_holds_include_only_file_does_not_count_as_holding_the_test(self) -> None:
        source = WALLET_INCLUDE.read_text()
        self.assertNotIn("#[test]", source)
        self.assertFalse(
            holds_cited(source, "shared_sbpl_reader_refuses_every_hash_backslash_character_literal"),
            "include! of a test file is not the cited file holding that #[test]",
        )


class HuntNewReaderMacros(unittest.TestCase):
    """SBPL reader-macro forms that must still refuse."""

    FORMS = [
        ("#| (allow file*) |#", "block comment hiding a grant"),
        ("#| #| inner |# (allow file*) |#", "nested block comments"),
        ("#;(allow file*)", "datum comment one form"),
        ("#;(version 0)(allow file*)", "datum comment two forms"),
        ("#; #| x |# (allow file*)", "datum comment then block then grant"),
        ("#t (allow file*)", "boolean true then extra grant"),
        ("#f (allow file*)", "boolean false then extra grant"),
        ("#x2f (allow file*)", "hex number then extra grant"),
        ("#x41", "bare hex number"),
        ("#o77 (allow file*)", "octal number then extra grant"),
        ("#b101 (allow file*)", "binary number then extra grant"),
        ("#vu8(1 2) (allow file*)", "bytevector then extra grant"),
        ("#(allow file*)", "vector reader"),
        ("#'(allow file*)", "quote reader"),
        ("#`(allow file*)", "quasiquote reader"),
        ("#,@(allow file*)", "unquote-splicing reader"),
        ("#!(allow file*)", "hash-bang glued"),
        ("#+(allow file*)", "reader-conditional plus"),
        ("#-(allow file*)", "reader-conditional minus"),
        ("#hash((a . 1)) (allow file*)", "hash table reader"),
    ]

    def test_hunt_each_reader_macro_form_is_refused(self) -> None:
        for form, why in self.FORMS:
            with self.subTest(why=why, form=form):
                got = contract(form)
                self.assertFalse(
                    got.get("ok"),
                    f"reader-macro decoy must refuse ({why}): {form!r} -> {got}",
                )


class HuntUnicodeBidiCrlfNul(unittest.TestCase):
    """Unicode confusables, bidi controls, CRLF, and NUL."""

    FORMS = [
        ("＃;(allow file*)", "fullwidth number sign"),
        ("#\u200b;(allow file*)", "ZWSP between hash and semicolon"),
        ("#\u200c;(allow file*)", "ZWNJ between hash and semicolon"),
        ("#\u2060;(allow file*)", "word-joiner between hash and semicolon"),
        ("#\ufeff;(allow file*)", "BOM between hash and semicolon"),
        ("#\u00a0;(allow file*)", "nbsp between hash and semicolon"),
        ("#\u2028;(allow file*)", "line separator between hash and semicolon"),
        ("#\u202e;(allow file*)", "bidi RLO between hash and semicolon"),
        ("(allow file*)\u202e", "bidi RLO after a grant"),
        ("(allow file-read* (literal \"/\u202a\"))", "bidi LRE in path"),
        ("(allow file-read* (literal \"/\uff0f\"))", "fullwidth slash"),
        ("(allow file-read* (literal \"/\u2215\"))", "division slash"),
        ("(allow file-read* (literal \"/\u2044\"))", "fraction slash"),
        ("(version 0)\r(allow file*)", "CR between forms"),
        ("(version 0)\r\n(allow file*)", "CRLF between extra grant"),
        ("(allow file*)\x00", "NUL after a grant"),
        ("(allow file-read* (literal \"/\x00\"))", "NUL in path"),
        (";\r(allow file*)", "CR after line comment then grant"),
    ]

    def test_hunt_each_unicode_crlf_nul_form_is_refused(self) -> None:
        for form, why in self.FORMS:
            with self.subTest(why=why, form=repr(form)):
                got = contract(form)
                self.assertFalse(
                    got.get("ok"),
                    f"unicode/CRLF/NUL decoy must refuse ({why}): {form!r} -> {got}",
                )


class HuntStringEscapes(unittest.TestCase):
    """String escapes other than \\\\, \\\", \\n, \\t."""

    FORMS = [
        (r'(allow file-read* (literal "foo\r"))', "CR escape"),
        (r'(allow file-read* (literal "foo\0"))', "NUL escape"),
        (r'(allow file-read* (literal "foo\x2f"))', "hex escape"),
        (r'(allow file-read* (literal "foo\u002f"))', "unicode escape"),
        (r'(allow file-read* (literal "foo\U0000002f"))', "long unicode escape"),
        (r'(allow file-read* (literal "foo\("))', "escaped open paren"),
        (r'(allow file-read* (literal "foo\)"))', "escaped close paren"),
        (r'(allow file-read* (literal "foo\#"))', "escaped hash"),
        (r'(allow file-read* (literal "foo\;"))', "escaped semicolon"),
        (r'(allow file-read* (literal "foo\a"))', "alert escape"),
        (r'(allow file-read* (literal "foo\b"))', "backspace escape"),
        (r'(allow file-read* (literal "foo\f"))', "formfeed escape"),
        (r'(allow file-read* (literal "foo\v"))', "vertical tab escape"),
    ]

    def test_hunt_each_unknown_string_escape_is_refused(self) -> None:
        for form, why in self.FORMS:
            with self.subTest(why=why, form=form):
                got = contract(form)
                self.assertFalse(
                    got.get("ok"),
                    f"unknown string escape must refuse ({why}): {form} -> {got}",
                )

    def test_holds_known_string_escapes_do_not_by_themselves_pass_a_grant(self) -> None:
        got = contract(r'(allow file-read* (literal "foo\nbar"))')
        self.assertFalse(
            got.get("ok"),
            f"a non-canonical extra storage form must still refuse: {got}",
        )


class HuntExtractCopyDrift(unittest.TestCase):
    """extract.py copies of profile_characters must match sbpl_reader.rs."""

    def test_holds_wallet_confine_copy_matches_sbpl_reader(self) -> None:
        shared = rust_named_fn_source(WALLET_READER.read_text(), "profile_characters")
        wallet = rust_named_fn_source(WALLET_CONFINE.read_text(), "profile_characters")
        self.assertEqual(
            shared,
            wallet,
            "wallet confine.rs profile_characters drifted from sbpl_reader.rs",
        )

    def test_holds_did_confine_copy_matches_sbpl_reader(self) -> None:
        shared = rust_named_fn_source(WALLET_READER.read_text(), "profile_characters")
        did = rust_named_fn_source(DID_CONFINE.read_text(), "profile_characters")
        self.assertEqual(
            shared,
            did,
            "did confine.rs profile_characters drifted from sbpl_reader.rs",
        )

    def test_holds_probe_copy_matches_sbpl_reader(self) -> None:
        shared = rust_named_fn_source(WALLET_READER.read_text(), "profile_characters")
        probe_lib = (REVIEW / "probe/src/lib.rs").read_text()
        extracted = rust_named_fn_source(probe_lib, "profile_characters")
        # extract.py prefixes pub
        self.assertEqual(
            extracted.replace("pub fn profile_characters", "fn profile_characters", 1),
            shared.replace("fn profile_characters", "fn profile_characters", 1),
        )
        self.assertIn(
            "the profile must refuse a Scheme character literal #\\",
            extracted,
        )

    def test_holds_model_include_points_at_sbpl_reader(self) -> None:
        text = MODEL_CONFINE.read_text()
        self.assertIn("wallet-provider/tests/sbpl_reader.rs", text)
        self.assertIn("include!", text)


class WeakExpectedRedAndMac(unittest.TestCase):
    """Document the one expected r4/r5 red and the Mac half that stays NOT RUN."""

    def test_weak_r4_w1_expected_accept_is_the_f1_policy_change(self) -> None:
        # r4/r5 W1 asserted contract("#\\;(allow file*)") is ok. Under F1
        # that spelling is refused. This is the one expected red on those
        # runners, not a reopened hide: the grant does not pass.
        got = contract(r"#\;(allow file*)")
        self.assertFalse(got.get("ok"), got)
        self.assertNotEqual(got, {"ok": True})

    def test_weak_macos_sandbox_exec_still_not_run(self) -> None:
        self.assertFalse(Path("/usr/bin/sandbox-exec").is_file())
        wallet = WALLET_CONFINE.read_text()
        self.assertIn("NOT RUN: sandbox-exec is macOS only", wallet)
        self.assertIn("wasmer_without_a_memory_cap_is_an_open_gap_not_proof", WASM_RUN.read_text())


class HoldsPriorAllowlistStillClosed(unittest.TestCase):
    """Cheap check that r1-r3 grant holes stay closed on this head."""

    def test_holds_unfiltered_file_read_as_storage_refuses(self) -> None:
        rules = probe({"op": "shared_rules"})["rules"]
        startup = probe({"op": "startup_rules"})["rules"]
        just_root = probe(
            {"op": "justification", "name": "did-provider", "id": "startup-root-directory"}
        )["text"]
        just_sys = probe(
            {"op": "justification", "name": "did-provider", "id": "startup-sysctl"}
        )["text"]
        extra = "(allow file-read*)"
        profile = fixture_profile() + startup[0] + "\n" + startup[1] + "\n" + extra + "\n"
        declared = {
            "role": "lab stand-in for the Runtime generator's input, not a manifest field",
            "provider": "did-provider",
            "rights": [
                {"id": "storage", "rules": [rules[1], rules[2], extra]},
                {"id": "bound-executable", "rules": [rules[0]]},
            ],
            "platform_baseline": {
                "status": (
                    "Runtime platform baseline for the did-provider executable "
                    "on macOS, not approved rights"
                ),
                "rules": [
                    {
                        "id": "startup-root-directory",
                        "justification": just_root,
                        "rules": [startup[0]],
                    },
                    {
                        "id": "startup-sysctl",
                        "justification": just_sys,
                        "rules": [startup[1]],
                    },
                ],
            },
        }
        got = probe(
            {
                "op": "rights",
                "name": "did-provider",
                "profile": profile,
                "declared": declared,
            }
        )
        self.assertFalse(got.get("ok"), got)

    def test_holds_allow_default_and_system_socket_refuse(self) -> None:
        self.assertFalse(contract("(allow default)").get("ok"))
        self.assertFalse(contract("(ALLOW DEFAULT)").get("ok"))
        self.assertFalse(contract("(allow system-socket)").get("ok"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RecordHeadIdentity(unittest.TestCase):
    def test_record_checker_bytes(self) -> None:
        # Presence only. REVIEW.md quotes the hashes from this run.
        for path in (
            WALLET_CONFINE,
            WALLET_READER,
            MODEL_CONFINE,
            DID_CONFINE,
            WASM_RUN,
        ):
            self.assertTrue(path.is_file(), path)
            self.assertTrue(sha256(path))
