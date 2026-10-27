"""Fourth adversarial review of draft PR #323 at b385b4c9.

HOLDS tests assert a refusal this head claims. FALSIFIED tests assert a
refusal the contract still needs; they fail when the live checker accepts
the planted profile or citation. WEAK tests record a narrower gap.

The probe is the extracted #323 functions, not a second walk.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REVIEW = ROOT / "lab/review-323-v4"
PROBE_BIN = REVIEW / "probe/target/debug/review323v4-probe"
WALLET_CONFINE = ROOT / "capsules/wallet-provider/tests/confine.rs"
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


def declared_for(
    extra_storage_rule: str | None = None,
    extra_profile_line: str | None = None,
    extra_storage_only: bool = False,
    justification: str | None = None,
) -> tuple[str, dict]:
    fix = fixture_profile()
    rules = probe({"op": "shared_rules"})["rules"]
    startup = probe({"op": "startup_rules"})["rules"]
    just_root = justification or probe(
        {"op": "justification", "name": "did-provider", "id": "startup-root-directory"}
    )["text"]
    just_sys = probe(
        {"op": "justification", "name": "did-provider", "id": "startup-sysctl"}
    )["text"]
    storage = [rules[1], rules[2]]
    profile = fix + startup[0] + "\n" + startup[1] + "\n"
    if extra_storage_rule:
        storage.append(extra_storage_rule)
        if not extra_storage_only:
            profile += extra_storage_rule + "\n"
    if extra_profile_line:
        profile += extra_profile_line + "\n"
    declared = {
        "role": "lab stand-in for the Runtime generator's input, not a manifest field",
        "provider": "did-provider",
        "rights": [
            {"id": "storage", "rules": storage},
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
    return profile, declared


def rights(extra_storage_rule: str) -> dict:
    profile, declared = declared_for(extra_storage_rule)
    return probe(
        {
            "op": "rights",
            "name": "did-provider",
            "profile": profile,
            "declared": declared,
        }
    )


def contract(extra: str) -> dict:
    return probe({"op": "contract", "profile": fixture_profile() + extra + "\n"})


def cite(source: str, function: str = "present_case") -> list:
    tmp = tempfile.mkdtemp()
    tests = Path(tmp) / "tests"
    tests.mkdir()
    (tests / "confine.rs").write_text(source)
    doc = (
        "## Operations and the rights they need\n\n"
        f"| `tests/confine.rs::{function}` |\n\n"
        "## Host-OS status\n"
    )
    return probe({"op": "cite", "dir": tmp, "document": doc})["problems"]


def holds_cited(source: str, function: str = "present_case") -> bool:
    return probe({"op": "holds_cited", "source": source, "function": function})["holds"]


def cargo_lists(source: str, function: str = "present_case"):
    return probe({"op": "cargo_lists", "source": source, "function": function}).get(
        "listed"
    )


def setUpModule() -> None:
    _build_probe()
    assert PROBE_BIN.is_file(), PROBE_BIN


# --- prior reviews must still refuse ----------------------------------------


class Holds346Bypasses(unittest.TestCase):
    """#346 F1-F9 plus the named #294 cases."""

    def test_holds_unfiltered_file_read_as_storage(self) -> None:
        got = rights("(allow file-read*)")
        self.assertFalse(got["ok"], got)

    def test_holds_regex_caret_slash_as_storage(self) -> None:
        got = rights('(allow file-read* (regex "^/"))')
        self.assertFalse(got["ok"], got)

    def test_holds_spaced_literal_root_as_storage(self) -> None:
        got = rights('(allow file-read* (literal "/" ))')
        self.assertFalse(got["ok"], got)

    def test_holds_dot_subpath_root_as_storage(self) -> None:
        got = rights('(allow file-read* (subpath "/."))')
        self.assertFalse(got["ok"], got)

    def test_holds_string_literal_is_not_a_citation(self) -> None:
        self.assertTrue(cite('const S: &str = "fn present_case(";\n'))

    def test_holds_nested_block_comment_is_not_a_citation(self) -> None:
        self.assertTrue(cite("/* /* */ #[test] fn present_case() {} */\n"))

    def test_holds_plain_fn_is_not_a_citation(self) -> None:
        self.assertTrue(cite("fn present_case() {}\n"))

    def test_holds_allow_default_uppercase(self) -> None:
        self.assertFalse(contract("(ALLOW DEFAULT)")["ok"])

    def test_holds_allow_default_titlecase(self) -> None:
        self.assertFalse(contract("(allow Default)")["ok"])

    def test_holds_system_socket_is_a_network_grant(self) -> None:
        got = contract("(allow system-socket)")
        self.assertFalse(got["ok"], got)

    def test_holds_nested_allow_default(self) -> None:
        got = contract("(if #t (allow default))")
        self.assertFalse(got["ok"], got)

    def test_holds_split_allow_default(self) -> None:
        got = contract("(if #t (allow\n    default))")
        self.assertFalse(got["ok"], got)

    def test_holds_nested_network(self) -> None:
        got = contract("(begin (allow network*))")
        self.assertFalse(got["ok"], got)

    def test_holds_nested_import(self) -> None:
        got = contract('(if #t (import "bsd.sb"))')
        self.assertFalse(got["ok"], got)

    def test_holds_exact_subpath_root_as_storage(self) -> None:
        got = rights('(allow file-read* (subpath "/"))')
        self.assertFalse(got["ok"], got)

    def test_holds_ignored_wallet_sandbox_test_panics(self) -> None:
        proc = subprocess.run(
            [
                "cargo",
                "test",
                "--test",
                "confine",
                "confined_outside_write_is_denied",
                "--",
                "--ignored",
                "--test-threads=1",
            ],
            cwd=ROOT / "capsules/wallet-provider",
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(proc.returncode, 0, proc.stdout[-800:])
        self.assertIn("NOT RUN", proc.stdout + proc.stderr)


class Holds352Bypasses(unittest.TestCase):
    """The 17 #352 FALSIFIED spellings must refuse on this allowlist head."""

    def test_holds_empty_prefix_as_storage(self) -> None:
        self.assertFalse(rights('(allow file-read* (prefix ""))')["ok"])

    def test_holds_regex_dot_star_as_storage(self) -> None:
        self.assertFalse(rights('(allow file-read* (regex ".*"))')["ok"])

    def test_holds_regex_class_slash_as_storage(self) -> None:
        self.assertFalse(rights('(allow file-read* (regex "^[/].*"))')["ok"])

    def test_holds_string_append_root_as_storage(self) -> None:
        self.assertFalse(rights('(allow file-read* (subpath (string-append "/" "")))')["ok"])

    def test_holds_unfiltered_file_star_as_storage(self) -> None:
        self.assertFalse(rights("(allow file*)")["ok"])

    def test_holds_unfiltered_file_write_as_storage(self) -> None:
        self.assertFalse(rights("(allow file-write*)")["ok"])

    def test_holds_require_any_root_as_storage(self) -> None:
        self.assertFalse(rights('(allow file-read* (require-any (subpath "/")))')["ok"])

    def test_holds_vnode_type_only_as_storage(self) -> None:
        self.assertFalse(rights("(allow file-read* (vnode-type REGULAR-FILE))")["ok"])

    def test_holds_multiple_filters_regex_dot_star(self) -> None:
        self.assertFalse(rights('(allow file-read* (subpath "/var") (regex ".*"))')["ok"])

    def test_holds_uppercase_allow_invisible_to_allow_forms(self) -> None:
        profile, declared = declared_for(extra_profile_line="(ALLOW file-read*)")
        seen = probe({"op": "allow_forms", "profile": profile})["forms"]
        self.assertNotIn("(ALLOW file-read*)", seen, seen)
        got = probe(
            {
                "op": "rights",
                "name": "did-provider",
                "profile": profile,
                "declared": declared,
            }
        )
        self.assertFalse(got["ok"], got)

    def test_holds_flush_head_file_read_invisible(self) -> None:
        profile, declared = declared_for(extra_profile_line="(allow(file-read*))")
        seen = probe({"op": "allow_forms", "profile": profile})["forms"]
        self.assertFalse(any(form == "(allow(file-read*))" for form in seen), seen)
        got = probe(
            {
                "op": "rights",
                "name": "did-provider",
                "profile": profile,
                "declared": declared,
            }
        )
        self.assertFalse(got["ok"], got)

    def test_holds_mach_lookup_is_ambient_ipc(self) -> None:
        self.assertFalse(contract("(allow mach-lookup)")["ok"])

    def test_holds_ipc_posix_is_ambient_ipc(self) -> None:
        self.assertFalse(contract("(allow ipc-posix*)")["ok"])

    def test_holds_cfg_any_module_is_not_a_citation(self) -> None:
        source = (
            "#[cfg(any())]\n"
            "mod unused {\n"
            "    #[test]\n"
            "    fn present_case() {}\n"
            "}\n"
        )
        self.assertTrue(cite(source))

    def test_holds_unused_macro_is_not_a_citation(self) -> None:
        source = (
            "macro_rules! planted {\n"
            "    () => {\n"
            "        #[test]\n"
            "        fn present_case() {}\n"
            "    };\n"
            "}\n"
        )
        self.assertTrue(cite(source))

    def test_holds_did_gate_refuses_uppercase_default(self) -> None:
        got = probe({"op": "did_denies", "profile": fixture_profile() + "(ALLOW DEFAULT)\n"})
        self.assertFalse(got["ok"], got)

    def test_holds_did_gate_refuses_system_socket(self) -> None:
        got = probe(
            {"op": "did_denies", "profile": fixture_profile() + "(allow system-socket)\n"}
        )
        self.assertFalse(got["ok"], got)


NEW_PROFILE_ATTACKS = [
    ("(ALLOW file*)", "uppercase ALLOW extra grant"),
    ("(Allow file-read*)", "titlecase Allow extra grant"),
    ("(allow FILE*)", "uppercase op extra grant"),
    ("(allow\tfile*)", "tab after allow"),
    ("(allow\nfile-write*)", "newline after allow"),
    ("( allow file*)", "space after open paren"),
    ("(allow file* )", "space before close"),
    ("; (allow default)\n(allow file*)", "comment then extra grant"),
    ("(allow file-read* ; hide\n (subpath \"/\"))", "comment inside extra grant"),
    ("#| (allow default) |#", "scheme block comment wrapping a grant"),
    ("(allow file-read* #| x |# (subpath \"/\"))", "block comment inside extra grant"),
    ('(allow file-read* (literal "/\\x2e\\x2e"))', "hex-escape lookalike path"),
    ('(allow file-read* (literal "/\u200b"))', "zero-width after slash"),
    ('(allow file-read* (literal "/\uff0f"))', "fullwidth slash"),
    ('(allow file-read* (subpath "/\u2215"))', "division-slash lookalike"),
    (
        '(allow file-read* (literal (param "STORAGE_PARENT")) (regex ".*"))',
        "permitted storage plus extra regex",
    ),
    (
        '(allow file-read* file-write* (subpath (param "STORAGE_ROOT")) (prefix ""))',
        "permitted storage plus empty prefix",
    ),
    ('(allow file-read* (regex "^.*"))', "regex caret-dot-star"),
    ('(allow file-read* (prefix "/"))', "prefix of slash"),
    ('(allow file-read* (literal (param "STORAGE_ROOT")))', "literal vs subpath swap"),
    ('(allow file-read* (subpath (param "STORAGE_PARENT")))', "subpath vs literal swap"),
    ('(allow file-read* (subpath "//"))', "double slash"),
    ('(allow file-read* (subpath "/./"))', "dot segment"),
    ('(allow file-read* (subpath "/../"))', "parent segment"),
    ('(allow file-read* (subpath "/"))', "trailing-slash root already covered"),
    ('(allow file-read* (literal "/tmp/.."))', "tmp parent to root"),
    ('(allow file-read* (subpath "/tmp/symlink"))', "symlink-looking name"),
    ("(if #t (allow file*))", "if wrapper"),
    ("(begin (allow file-write*))", "begin wrapper"),
    ("(with (allow file*))", "with wrapper"),
    ("(require-any (allow file-read*))", "require-any wrapper"),
    ("(require-all (allow file*))", "require-all wrapper"),
    ('(allow file-read* (subpath (param "HOME")))', "HOME param"),
    ('(allow file-read* (literal (param "STORAGE_PARENT2")))', "near-canonical param"),
    ('(import "bsd.sb")', "import"),
    ('(include "bsd.sb")', "include"),
    ('(%include "bsd.sb")', "percent-include"),
    ('(#include "bsd.sb")', "hash-include"),
    ("(load-module bsd)", "load-module"),
    ("(eval (allow file*))", "eval"),
    ("(define extra (allow file*))", "define"),
    ("'(allow default)", "quoted allow default"),
    ("`(allow file*)", "quasiquote allow"),
    (",(allow file*)", "unquote allow"),
    ("(allow file-ioctl*)", "file-ioctl star"),
    ("(allow signal)", "signal"),
    ("(allow iokit-user-client*)", "iokit"),
    ("(allow mach-priv-task-port)", "mach-priv"),
    ("(allow process-info*)", "process-info"),
    ("(allow sysctl-write)", "sysctl-write"),
]


class HoldsNewAllowlistAttacks(unittest.TestCase):
    """Each v3 spelling must still be refused."""

    def test_holds_each_new_profile_attack(self) -> None:
        failures = []
        for form, label in NEW_PROFILE_ATTACKS:
            got = contract(form)
            if got.get("ok"):
                failures.append((label, form, got))
        self.assertEqual(
            failures,
            [],
            "allowlist accepted new profile attacks: " + repr(failures),
        )

    def test_holds_each_new_attack_as_storage(self) -> None:
        storage_forms = [
            '(allow file-read* (regex "^.*"))',
            '(allow file-read* (prefix "/"))',
            '(allow file-read* (literal (param "STORAGE_ROOT")))',
            '(allow file-read* (subpath (param "STORAGE_PARENT")))',
            '(allow file-read* (subpath "//"))',
            '(allow file-read* (subpath "/./"))',
            '(allow file-read* (literal "/\u200b"))',
            '(allow file-read* (literal (param "STORAGE_PARENT")) (regex ".*"))',
        ]
        failures = []
        for form in storage_forms:
            got = rights(form)
            if got.get("ok"):
                failures.append((form, got))
        self.assertEqual(failures, [], failures)


class HoldsR3Attacks(unittest.TestCase):
    """The five r3 FALSIFIED items, replanted. This head claims they refuse."""

    def test_holds_cfg_any_with_spaces_is_not_a_citation(self) -> None:
        source = (
            "#[cfg(any( ))]\n"
            "mod unused {\n"
            "    #[test]\n"
            "    fn present_case() {}\n"
            "}\n"
        )
        self.assertIs(cargo_lists(source), False, "cargo --list must omit present_case")
        self.assertFalse(holds_cited(source), source)

    def test_holds_cfg_any_inner_spaces_is_not_a_citation(self) -> None:
        source = "#[cfg( any() )]\n#[test]\nfn present_case() {}\n"
        self.assertIs(cargo_lists(source), False)
        self.assertFalse(holds_cited(source), source)

    def test_holds_cfg_any_false_is_not_a_citation(self) -> None:
        source = (
            "#[cfg(any(false))]\n"
            "mod unused {\n"
            "    #[test]\n"
            "    fn present_case() {}\n"
            "}\n"
        )
        # rustc 1.91 treats cfg(false) as experimental, so the tiny-crate
        # cargo list is None and the source walk is the claim.
        self.assertFalse(holds_cited(source), source)

    def test_holds_cfg_windows_is_not_a_citation_on_linux(self) -> None:
        source = (
            "#[cfg(windows)]\n"
            "mod unused {\n"
            "    #[test]\n"
            "    fn present_case() {}\n"
            "}\n"
        )
        self.assertIs(cargo_lists(source), False)
        self.assertFalse(holds_cited(source), source)

    def test_holds_hash_semicolon_hides_a_following_allow(self) -> None:
        form = "#;(version 0)(allow file*)"
        got = contract(form)
        self.assertFalse(
            got.get("ok"),
            f"r3 F5 must stay refused; lab checker returned {got}",
        )
        self.assertTrue(
            got.get("panic") or "Scheme comment" in str(got.get("reason", "")),
            got,
        )

    def test_holds_hash_pipe_block_comment(self) -> None:
        got = contract("#| (allow file*) |#")
        self.assertFalse(got.get("ok"), got)

    def test_holds_empty_prefix_is_root_wide(self) -> None:
        got = probe({"op": "root_wide", "form": '(allow file-read* (prefix ""))'})
        self.assertTrue(got.get("root_wide"), got)

    def test_holds_model_allow_forms_see_casefolded_allows(self) -> None:
        forms = probe(
            {"op": "model_allow_forms", "profile": "(ALLOW file*)\n(allow file*)\n"}
        )["forms"]
        self.assertIn("(ALLOW file*)", forms, forms)
        self.assertIn("(allow file*)", forms, forms)

    def test_holds_model_storage_keeps_param_string_case(self) -> None:
        got = probe(
            {
                "op": "model_permitted_storage",
                "form": '(allow file-read* (literal (param "storage_parent")))',
            }
        )
        self.assertFalse(got.get("permitted"), got)


class HoldsCitedListable(unittest.TestCase):
    """Citation cases that match cargo test -- --list."""

    def test_holds_cfg_any_still_unlistable(self) -> None:
        self.assertFalse(
            holds_cited(
                "#[cfg(any())]\nmod unused {\n    #[test]\n    fn present_case() {}\n}\n"
            )
        )

    def test_holds_doc_comment_is_not_a_citation(self) -> None:
        source = "/// ```\n/// #[test]\n/// fn present_case() {}\n/// ```\n"
        self.assertFalse(holds_cited(source))
        self.assertTrue(cite(source))

    def test_holds_cfg_test_without_test_attr_is_not_a_citation(self) -> None:
        source = "#[cfg(test)]\nfn present_case() {}\n"
        self.assertFalse(holds_cited(source))
        self.assertTrue(cite(source))

    def test_holds_same_name_outside_provider_is_not_a_citation(self) -> None:
        tmp = tempfile.mkdtemp()
        tests = Path(tmp) / "tests"
        tests.mkdir()
        (tests / "confine.rs").write_text("fn other() {}\n")
        other = Path(tempfile.mkdtemp()) / "confine.rs"
        other.write_text("#[test]\nfn present_case() {}\n")
        doc = (
            "## Operations and the rights they need\n\n"
            f"| `{other}::present_case` |\n\n"
            "## Host-OS status\n"
        )
        problems = probe({"op": "cite", "dir": tmp, "document": doc})["problems"]
        self.assertTrue(problems, problems)


# --- new hunts this pass ----------------------------------------------------


R4_PROFILE_ATTACKS = [
    ("#| #| inner |# (allow file*) |#", "nested scheme block comment"),
    ("#! (allow file*)", "hash-bang then extra grant"),
    ("#!/usr/bin/sandbox-exec\n(allow file*)", "shebang line then extra grant"),
    ("#!r6rs\n(allow file*)", "hash-bang r6rs then extra grant"),
    ("#-(allow file*)", "reader-conditional minus"),
    ("#+(or) (allow file*)", "reader-conditional plus"),
    ("#\\;(allow file*)", "hash-backslash semicolon one-datum"),
    ("#\u200b;(allow file*)", "zero-width between hash and semicolon"),
    ("＃;(allow file*)", "fullwidth number sign then semicolon"),
    ('(allow file-read* (regex #"^/"))', "scheme regex literal caret slash"),
    ('(allow file-read* (regex #"^/.*"))', "scheme regex literal caret slash star"),
    ('(allow file-read* (subpath #"/"))', "scheme string subpath root"),
    ('(allow file-read* (literal #"/"))', "scheme string literal root"),
    ('(allow file-read* (prefix #"/"))', "scheme string prefix root"),
    ('(allow file-read* (literal (param "/")))', "param slash"),
    ('(allow file-read* (subpath (param "")))', "empty param name"),
    ('(allow file-read* (literal (param "STORAGE_PARENT\\x00")))', "param with escape"),
    ('(include-local "bsd.sb")', "include-local"),
    ('(load "bsd.sb")', "load list"),
    ('(require "bsd.sb")', "require list"),
    ('#include "bsd.sb"\n(allow file*)', "bare hash-include then grant"),
    ("(ALLOW file-read*)", "uppercase ALLOW file-read"),
    ("(Allow FILE-READ*)", "mixed-case op"),
    ('(allow file-read* (REGEX "^/"))', "uppercase REGEX filter"),
    ('(allow file-read* (Subpath "/"))', "titlecase Subpath"),
    ('(allow file-read* (LITERAL "/"))', "uppercase LITERAL startup form"),
]


class HuntNewProfileForms(unittest.TestCase):
    """New SBPL reader / filter / include spellings. Refuse or panic-closed."""

    def test_hunt_each_new_profile_form(self) -> None:
        # Forms that only hide a grant (lab and a Scheme reader both drop
        # the allow) or that casefold to a permitted startup form are
        # recorded under WeakRemainingGaps / FalsifiedNewBypasses.
        skip = {
            "hash-backslash semicolon one-datum",
            "zero-width between hash and semicolon",
            "fullwidth number sign then semicolon",
            "uppercase LITERAL startup form",
        }
        failures = []
        for form, label in R4_PROFILE_ATTACKS:
            if label in skip:
                continue
            got = contract(form)
            if got.get("ok"):
                failures.append((label, form, got))
        self.assertEqual(
            failures,
            [],
            "allowlist accepted r4 profile attacks: " + repr(failures),
        )

    def test_hunt_scheme_regex_and_param_as_storage(self) -> None:
        forms = [
            '(allow file-read* (regex #"^/"))',
            '(allow file-read* (subpath #"/"))',
            '(allow file-read* (literal #"/"))',
            '(allow file-read* (prefix #"/"))',
            '(allow file-read* (literal (param "/")))',
            '(allow file-read* (subpath (param "")))',
            '(allow file-read* (REGEX "^/"))',
            '(allow file-read* (Subpath "/"))',
        ]
        failures = []
        for form in forms:
            got = rights(form)
            if got.get("ok"):
                failures.append((form, got))
        self.assertEqual(failures, [], failures)

    def test_hunt_bare_include_atoms_are_not_a_hidden_grant(self) -> None:
        # Bare #include / load atoms are skipped by the allowlist loop.
        # An extra (allow ...) after them must still refuse.
        got = contract('#include "bsd.sb"\n(allow file*)')
        self.assertFalse(got.get("ok"), got)

    def test_hunt_string_escape_does_not_close_early(self) -> None:
        got = contract(r'(allow file-read* (literal "foo\")) (allow file*)")')
        self.assertFalse(got.get("ok"), got)


class HuntCitationSpoofs(unittest.TestCase):
    """Test-list spoofing: cargo --list is the claim."""

    def test_hunt_same_name_in_other_module_is_listed(self) -> None:
        source = (
            "mod other {\n"
            "    #[test]\n"
            "    fn present_case() {}\n"
            "}\n"
        )
        # cargo --list prints `other::present_case: test`. The matcher
        # splits on the first `:`, so it misses a namespaced name.
        listed = cargo_lists(source)
        self.assertIs(
            listed,
            False,
            f"matcher still splits on the first colon; listed={listed}",
        )

    def test_hunt_doctest_is_not_a_lib_citation(self) -> None:
        source = (
            "/// ```\n"
            "/// #[test]\n"
            "/// fn present_case() {}\n"
            "/// ```\n"
            "pub fn helper() {}\n"
        )
        self.assertFalse(holds_cited(source))
        self.assertTrue(cite(source))

    def test_hunt_ignore_is_listed_by_cargo(self) -> None:
        source = "#[test]\n#[ignore]\nfn present_case() {}\n"
        self.assertIs(cargo_lists(source), True)
        self.assertTrue(holds_cited(source))

    def test_hunt_empty_test_is_listed(self) -> None:
        source = "#[test]\nfn present_case() {}\n"
        self.assertIs(cargo_lists(source), True)
        self.assertTrue(holds_cited(source))

    def test_hunt_cfg_false_compiles_as_experimental(self) -> None:
        source = "#[cfg(false)]\n#[test]\nfn present_case() {}\n"
        listed = cargo_lists(source)
        self.assertIs(
            listed,
            None,
            f"rustc 1.91 rejects cfg(false) as experimental; listed={listed}",
        )

    def test_hunt_cfg_feature_never_is_not_a_citation(self) -> None:
        source = '#[cfg(feature = "never")]\n#[test]\nfn present_case() {}\n'
        listed = cargo_lists(source)
        self.assertIs(listed, False, listed)
        self.assertFalse(
            holds_cited(source),
            "#[cfg(feature = \"never\")] is not listed without that feature",
        )

    def test_hunt_cfg_all_unix_windows_is_not_a_citation(self) -> None:
        source = "#[cfg(all(unix, windows))]\n#[test]\nfn present_case() {}\n"
        listed = cargo_lists(source)
        self.assertIs(listed, False, listed)
        self.assertFalse(holds_cited(source), source)

    def test_hunt_cfg_not_test_is_not_a_citation(self) -> None:
        source = "#[cfg(not(test))]\n#[test]\nfn present_case() {}\n"
        listed = cargo_lists(source)
        self.assertIs(listed, False, listed)
        self.assertFalse(holds_cited(source), source)

    def test_hunt_cfg_not_unix_is_not_a_citation_on_linux(self) -> None:
        source = "#[cfg(not(unix))]\n#[test]\nfn present_case() {}\n"
        listed = cargo_lists(source)
        self.assertIs(listed, False, listed)
        self.assertFalse(holds_cited(source), source)

    def test_hunt_real_confine_source_uses_fallback(self) -> None:
        source = WALLET_CONFINE.read_text()
        listed = cargo_lists(source, "confined_outside_write_is_denied")
        self.assertIs(
            listed,
            None,
            "wallet confine.rs cannot compile as the tiny cite crate, so "
            f"the live cargo list is unused; listed={listed}",
        )
        self.assertTrue(
            holds_cited(source, "confined_outside_write_is_denied"),
            "the source walk still finds the ignored macOS sandbox test",
        )

    def test_hunt_real_cargo_list_feature_set(self) -> None:
        # The live checker runs `cargo test -- --list` on a featureless
        # cite-list crate. The owner suite is `cargo test --test confine`.
        proc = subprocess.run(
            ["cargo", "test", "--test", "confine", "--", "--list"],
            cwd=ROOT / "capsules/wallet-provider",
            text=True,
            capture_output=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[-800:])
        lines = [
            line
            for line in proc.stdout.splitlines()
            if line.endswith(": test") or line.endswith(": test (ignored)")
        ]
        self.assertGreater(len(lines), 0, proc.stdout[-400:])
        # The tiny-crate list and the owner --test confine list are different
        # commands. Record that the owner list is the one C1-C7 would cite.
        tiny = cargo_lists("#[test]\nfn present_case() {}\n")
        self.assertIs(tiny, True)
        self.assertFalse(
            any("present_case" in line for line in lines),
            "owner --test confine -- --list must not invent present_case",
        )


class FalsifiedNewBypasses(unittest.TestCase):
    """New holes on this head. Each test asks for a refusal."""

    def test_falsified_hash_backslash_semicolon_hides_a_following_allow(self) -> None:
        # Lab starts a line comment at every ';' outside a string, including
        # the ';' in a Scheme character '#\;'. A Scheme reader takes '#\;'
        # as the semicolon character and keeps the later forms on that line.
        form = "#\\;(version 0)(allow file*)"
        got = contract(form)
        self.assertFalse(
            got.get("ok"),
            "a Scheme #\\; character leaves (version 0)(allow file*) live; "
            f"lab checker returned {got}",
        )

    def test_falsified_zwsp_hash_semicolon_two_datums(self) -> None:
        form = "#\u200b;(version 0)(allow file*)"
        got = contract(form)
        self.assertFalse(
            got.get("ok"),
            "a zero-width space between # and ; still starts a lab line "
            f"comment, so (allow file*) vanishes; {got}",
        )

    def test_falsified_fallback_walk_counts_feature_gated_test(self) -> None:
        source = (
            "use missing_crate::Thing;\n"
            '#[cfg(feature = "never")]\n'
            "#[test]\n"
            "fn present_case() {\n"
            "    let _ = Thing;\n"
            "}\n"
        )
        listed = cargo_lists(source)
        self.assertIs(listed, None, listed)
        self.assertFalse(
            holds_cited(source),
            "fallback walk counted a feature-gated #[test] that "
            "cargo test -- --list would omit",
        )

    def test_falsified_fallback_walk_counts_cfg_false(self) -> None:
        source = (
            "use missing_crate::Thing;\n"
            "#[cfg(false)]\n"
            "#[test]\n"
            "fn present_case() {\n"
            "    let _ = Thing;\n"
            "}\n"
        )
        listed = cargo_lists(source)
        self.assertIs(listed, None, listed)
        self.assertFalse(
            holds_cited(source),
            "fallback walk counted #[cfg(false)]; rustc 1.91 does not "
            "compile that cfg, and cargo test -- --list does not name it",
        )


class WeakRemainingGaps(unittest.TestCase):
    """Honest leftover gaps. They do not reopen closed r3 items."""

    def test_weak_ignore_counts_as_a_citation(self) -> None:
        source = "#[test]\n#[ignore]\nfn present_case() {}\n"
        self.assertTrue(holds_cited(source))

    def test_weak_empty_test_counts_as_a_citation(self) -> None:
        source = "#[test]\nfn present_case() {}\n"
        self.assertTrue(holds_cited(source))

    def test_weak_macos_sandbox_tests_are_ignored_on_linux(self) -> None:
        text = WALLET_CONFINE.read_text()
        self.assertIn('ignore = "NOT RUN: sandbox-exec is macOS only"', text)
        self.assertGreaterEqual(
            text.count('ignore = "NOT RUN: sandbox-exec is macOS only"'),
            11,
        )

    def test_weak_wasmer_gap_still_named(self) -> None:
        text = WASM_RUN.read_text()
        self.assertIn("wasmer_without_a_memory_cap_is_an_open_gap_not_proof", text)
        self.assertTrue(WALLET_CONFINE.is_file())
        self.assertTrue(MODEL_CONFINE.is_file())
        self.assertTrue(DID_CONFINE.is_file())

    def test_weak_bare_hash_include_atom_is_skipped(self) -> None:
        got = contract('#include "bsd.sb"')
        self.assertTrue(
            got.get("ok"),
            "bare #include atoms are skipped; no extra allow is present; "
            f"{got}",
        )

    def test_weak_hash_backslash_one_datum_comments_the_grant_out(self) -> None:
        got = contract("#\\;(allow file*)")
        self.assertFalse(
            got.get("ok"),
            "F1 refuses every #\\ form, including the one-datum spelling "
            f"#\\;(allow file*); lab checker returned {got}",
        )

    def test_weak_literal_uppercase_is_the_startup_root_form(self) -> None:
        got = contract('(allow file-read* (LITERAL "/"))')
        self.assertTrue(
            got.get("ok"),
            "LITERAL casefolds to the permitted startup root read; "
            f"{got}",
        )
        self.assertFalse(
            rights('(allow file-read* (LITERAL "/"))')["ok"],
            "storage must still refuse that form",
        )

    def test_weak_list_matcher_misses_module_qualified_names(self) -> None:
        source = "mod other {\n    #[test]\n    fn present_case() {}\n}\n"
        self.assertIs(cargo_lists(source), False)
        # Fail-closed: a listed namespaced test does not count. Not a spoof.


if __name__ == "__main__":
    unittest.main()
