"""Third adversarial review of draft PR #323 at 495968e7.

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
REVIEW = ROOT / "lab/review-323-v3"
PROBE_BIN = REVIEW / "probe/target/debug/review323v3-probe"
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


def setUpModule() -> None:
    _build_probe()
    assert PROBE_BIN.is_file(), PROBE_BIN


# --- #346 and #352 cases must still refuse ---------------------------------


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


# --- new allowlist attacks --------------------------------------------------


NEW_PROFILE_ATTACKS = [
    # mixed-case heads of extra grants
    ("(ALLOW file*)", "uppercase ALLOW extra grant"),
    ("(Allow file-read*)", "titlecase Allow extra grant"),
    ("(allow FILE*)", "uppercase op extra grant"),
    # whitespace / newline / tab inside extra grants
    ("(allow\tfile*)", "tab after allow"),
    ("(allow\nfile-write*)", "newline after allow"),
    ("( allow file*)", "space after open paren"),
    ("(allow file* )", "space before close"),
    # line comments that leave an extra grant
    ("; (allow default)\n(allow file*)", "comment then extra grant"),
    ("(allow file-read* ; hide\n (subpath \"/\"))", "comment inside extra grant"),
    # #| block comments (reader does not strip them)
    ("#| (allow default) |#", "scheme block comment wrapping a grant"),
    ("(allow file-read* #| x |# (subpath \"/\"))", "block comment inside extra grant"),
    # string escapes and lookalikes
    ('(allow file-read* (literal "/\\x2e\\x2e"))', "hex-escape lookalike path"),
    ('(allow file-read* (literal "/\u200b"))', "zero-width after slash"),
    ('(allow file-read* (literal "/\uff0f"))', "fullwidth slash"),
    ('(allow file-read* (subpath "/\u2215"))', "division-slash lookalike"),
    # duplicate allowed form with a different filter
    (
        '(allow file-read* (literal (param "STORAGE_PARENT")) (regex ".*"))',
        "permitted storage plus extra regex",
    ),
    (
        '(allow file-read* file-write* (subpath (param "STORAGE_ROOT")) (prefix ""))',
        "permitted storage plus empty prefix",
    ),
    # regex / subpath / prefix / literal swaps
    ('(allow file-read* (regex "^.*"))', "regex caret-dot-star"),
    ('(allow file-read* (prefix "/"))', "prefix of slash"),
    ('(allow file-read* (literal (param "STORAGE_ROOT")))', "literal vs subpath swap"),
    ('(allow file-read* (subpath (param "STORAGE_PARENT")))', "subpath vs literal swap"),
    # path normalisation
    ('(allow file-read* (subpath "//"))', "double slash"),
    ('(allow file-read* (subpath "/./"))', "dot segment"),
    ('(allow file-read* (subpath "/../"))', "parent segment"),
    ('(allow file-read* (subpath "/"))', "trailing-slash root already covered"),
    ('(allow file-read* (literal "/tmp/.."))', "tmp parent to root"),
    ('(allow file-read* (subpath "/tmp/symlink"))', "symlink-looking name"),
    # nested wrappers
    ("(if #t (allow file*))", "if wrapper"),
    ("(begin (allow file-write*))", "begin wrapper"),
    ("(with (allow file*))", "with wrapper"),
    ("(require-any (allow file-read*))", "require-any wrapper"),
    ("(require-all (allow file*))", "require-all wrapper"),
    # parameterised paths that are not the shared tokens
    ('(allow file-read* (subpath (param "HOME")))', "HOME param"),
    ('(allow file-read* (literal (param "STORAGE_PARENT2")))', "near-canonical param"),
    # inclusion / reader-like heads
    ('(import "bsd.sb")', "import"),
    ('(include "bsd.sb")', "include"),
    ('(%include "bsd.sb")', "percent-include"),
    ('(#include "bsd.sb")', "hash-include"),
    ("(load-module bsd)", "load-module"),
    ("(eval (allow file*))", "eval"),
    ("(define extra (allow file*))", "define"),
    # reader macros / quoting
    ("'(allow default)", "quoted allow default"),
    ("`(allow file*)", "quasiquote allow"),
    (",(allow file*)", "unquote allow"),
    ("#;(allow file*)", "datum comment then allow"),
    ("(allow file-ioctl*)", "file-ioctl star"),
    ("(allow signal)", "signal"),
    ("(allow iokit-user-client*)", "iokit"),
    ("(allow mach-priv-task-port)", "mach-priv"),
    ("(allow process-info*)", "process-info"),
    ("(allow sysctl-write)", "sysctl-write"),
]


class HoldsNewAllowlistAttacks(unittest.TestCase):
    """Each new spelling must be refused by the contract or panic-closed."""

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

    def test_holds_mixed_case_permitted_form_is_not_a_new_grant(self) -> None:
        # A case-folded copy of a permitted form is still that form.
        got = contract('(ALLOW file-read* (literal (param "STORAGE_PARENT")))')
        # Extra exact-case SHARED_RULES already sit in the fixture; a
        # case-folded duplicate is the same grant. Contract may accept it.
        # Declared-rights must still see the leftover via allow_head.
        profile, declared = declared_for(
            extra_profile_line='(ALLOW file-read* (literal (param "STORAGE_PARENT")))'
        )
        leftover = probe(
            {
                "op": "rights",
                "name": "did-provider",
                "profile": profile,
                "declared": declared,
            }
        )
        if got.get("ok"):
            self.assertFalse(
                leftover["ok"],
                "a case-folded duplicate of a storage rule must still be "
                f"seen by declared-rights; contract={got} rights={leftover}",
            )
        else:
            self.assertFalse(got["ok"], got)

    def test_setup_allow_forms_still_needs_lowercase_prefix(self) -> None:
        forms = probe({"op": "allow_forms", "profile": "(ALLOW file*)\n(allow file*)\n"})[
            "forms"
        ]
        self.assertNotIn("(ALLOW file*)", forms, forms)
        self.assertIn("(allow file*)", forms, forms)
        heads = probe(
            {"op": "allow_head_forms", "profile": "(ALLOW file*)\n(allow file*)\n"}
        )["forms"]
        self.assertTrue(any("ALLOW" in form or "allow" in form for form in heads), heads)


class CitationUnlisting(unittest.TestCase):
    """Citation counts only if cargo test -- --list would list the #[test] fn."""

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

    def test_holds_ignore_with_test_is_listed_by_cargo(self) -> None:
        # cargo test -- --list names ignored #[test] fns. The claim is the
        # list, so this must count.
        source = "#[test]\n#[ignore]\nfn present_case() {}\n"
        self.assertTrue(holds_cited(source), "#[ignore] #[test] is listed by cargo")

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

    def test_falsified_cfg_any_with_spaces_is_not_a_citation(self) -> None:
        source = (
            "#[cfg(any( ))]\n"
            "mod unused {\n"
            "    #[test]\n"
            "    fn present_case() {}\n"
            "}\n"
        )
        self.assertFalse(
            holds_cited(source),
            "#[cfg(any( ))] is still always-false and cargo does not list "
            "the inner #[test]; the exact-string unlister must not count it",
        )

    def test_falsified_cfg_any_false_is_not_a_citation(self) -> None:
        source = (
            "#[cfg(any(false))]\n"
            "mod unused {\n"
            "    #[test]\n"
            "    fn present_case() {}\n"
            "}\n"
        )
        self.assertFalse(
            holds_cited(source),
            "#[cfg(any(false))] never compiles the inner test; "
            "cargo test -- --list does not list it",
        )

    def test_falsified_cfg_windows_is_not_a_citation_on_linux(self) -> None:
        source = (
            "#[cfg(windows)]\n"
            "mod unused {\n"
            "    #[test]\n"
            "    fn present_case() {}\n"
            "}\n"
        )
        self.assertFalse(
            holds_cited(source),
            "#[cfg(windows)] is not listed by cargo test -- --list on Linux",
        )

    def test_falsified_cfg_any_inner_spaces_is_not_a_citation(self) -> None:
        source = (
            "#[cfg( any() )]\n"
            "#[test]\n"
            "fn present_case() {}\n"
        )
        self.assertFalse(
            holds_cited(source),
            "#[cfg( any() )] is always false; cargo does not list the fn",
        )


class WeakRemainingGaps(unittest.TestCase):
    """Gaps that do not reopen a host-wide grant on the allowlist gate."""

    def test_weak_old_root_wide_helper_still_misses_empty_prefix(self) -> None:
        got = probe({"op": "root_wide", "form": '(allow file-read* (prefix ""))'})
        self.assertFalse(
            got.get("root_wide"),
            "setup: leftover is_root_wide_read must still miss empty prefix; "
            f"{got}",
        )
        self.assertFalse(
            rights('(allow file-read* (prefix ""))')["ok"],
            "the allowlist must still refuse the same form as storage",
        )

    def test_weak_model_allow_forms_still_needs_lowercase_prefix(self) -> None:
        forms = probe(
            {"op": "model_allow_forms", "profile": "(ALLOW file*)\n(allow file*)\n"}
        )["forms"]
        self.assertNotIn("(ALLOW file*)", forms, forms)
        self.assertIn("(allow file*)", forms, forms)
        self.assertFalse(
            contract("(ALLOW file*)")["ok"],
            "the shared contract must still refuse the uppercase extra grant",
        )

    def test_weak_model_storage_lowercases_param_strings(self) -> None:
        got = probe(
            {
                "op": "model_permitted_storage",
                "form": '(allow file-read* (literal (param "storage_parent")))',
            }
        )
        self.assertTrue(
            got.get("permitted"),
            "setup: model copy lowercases the whole form including the param "
            f"string; {got}",
        )
        wallet = probe(
            {
                "op": "permitted_storage",
                "form": '(allow file-read* (literal (param "storage_parent")))',
            }
        )
        self.assertFalse(
            wallet.get("permitted"),
            "the shared storage allowlist must still require STORAGE_PARENT; "
            f"{wallet}",
        )

    def test_weak_wasmer_gap_still_named(self) -> None:
        text = WASM_RUN.read_text()
        self.assertIn("wasmer_without_a_memory_cap_is_an_open_gap_not_proof", text)
        self.assertTrue(WALLET_CONFINE.is_file())
        self.assertTrue(MODEL_CONFINE.is_file())
        self.assertTrue(DID_CONFINE.is_file())


if __name__ == "__main__":
    unittest.main()
