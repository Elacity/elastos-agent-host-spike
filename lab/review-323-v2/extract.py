#!/usr/bin/env python3
"""Pull #323's live checker functions into a tiny probe crate.

Second independent review (v2). The probe is the review's one way to call
the same functions the confine tests use. It copies those functions from
the files on this branch. It does not re-implement the walk.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WALLET = REPO / "capsules/wallet-provider/tests/confine.rs"
MODEL = REPO / "capsules/model-provider/tests/confine/main.rs"
DID = REPO / "capsules/did-provider/tests/confine.rs"
OUT = Path(__file__).resolve().parent / "probe"


WALLET_FNS = [
    "allow_head",
    "allow_operation_tokens",
    "allow_filters",
    "profile_head_token",
    "is_network_allow",
    "is_default_allow",
    "is_import",
    "is_unknown_profile_head",
    "is_root_wide_read",
    "filter_is_root_wide",
    "unquote_profile_string",
    "path_normalises_to_root",
    "casefold_profile_form",
    "permitted_profile_forms",
    "is_permitted_profile_form",
    "is_permitted_storage_form",
    "allow_head_forms",
    "nested_lists",
    "collect_nested_lists",
    "rust_source_without_comments",
    "rust_source_without_unlisted_items",
    "rust_source_without_macro_rules",
    "rust_skip_macro_rules",
    "rust_source_without_cfg_any_items",
    "rust_skip_next_item",
    "rust_skip_balanced",
    "rust_holds_cited_test",
    "rust_ident_boundary_before",
    "preceding_attributes_include_test",
    "skip_fn_qualifiers",
    "strip_ending_word",
    "rust_word_boundary_str",
    "last_attribute_start",
    "attribute_is_test",
    "platform_baseline_justification_text",
    "platform_baseline_justification",
    "platform_baseline_status",
    "is_exec_allow",
    "flush_operation",
    "check_profile_contract",
    "check_declared_rights",
    "declared_claims",
    "operations_table_citation_problems",
    "section_under_one_heading",
    "backtick_spans",
    "allow_forms",
    "contract_fixture_profile",
    "profile_forms",
    "push_separator",
    "profile_characters",
]

WALLET_CONSTS = [
    "CANONICAL_PARAMS",
    "PARAM_PREFIX",
    "SHARED_RULES",
    "CONTRACT_RIGHTS",
    "STARTUP_RULES",
    "PLATFORM_BASELINE_IDS",
    "PINNED_RULES",
    "DECLARED_RIGHTS_ROLE",
    "PLATFORM_BASELINE",
    "OPERATIONS_HEADING",
    "NETWORK_OPERATIONS",
    "KNOWN_PROFILE_HEADS",
    "INCLUSION_HEADS",
    "MODEL_STARTUP_ROOT",
]

MODEL_FNS = [
    "model_allow_forms",
    "collect_model_allows",
    "model_push_separator",
    "model_profile_characters",
    "model_profile_forms",
    "model_is_root_wide_read",
    "model_path_normalises_to_root",
    "rust_source_without_comments",
    "cited_confine_test",
]


class ExtractError(RuntimeError):
    pass


def _item_end(src: str, start: int) -> int:
    """End index (exclusive) of the Rust item that starts at start."""
    i = start
    n = len(src)
    depth = 0
    square = 0
    paren = 0
    seen_brace = False
    in_string = False
    escaped = False
    in_line = False
    in_block = 0
    while i < n:
        ch = src[i]
        if in_line:
            if ch == "\n":
                in_line = False
            i += 1
            continue
        if in_block:
            if ch == "*" and i + 1 < n and src[i + 1] == "/":
                in_block -= 1
                i += 2
                continue
            if ch == "/" and i + 1 < n and src[i + 1] == "*":
                in_block += 1
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if escaped:
                escaped = False
                i += 1
                continue
            if ch == "\\":
                escaped = True
                i += 1
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            in_line = True
            i += 2
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            in_block = 1
            i += 2
            continue
        if ch == "'" and i + 1 < n:
            nxt = src[i + 1]
            if nxt == "\\":
                close = src.find("'", i + 3)
                i = (close + 1) if close >= 0 else i + 1
                continue
            if nxt != "'" and i + 2 < n and src[i + 2] == "'":
                i += 3
                continue
        if ch == '"':
            in_string = True
            i += 1
            continue
        if ch == "{":
            depth += 1
            seen_brace = True
            i += 1
            continue
        if ch == "}":
            depth -= 1
            i += 1
            if seen_brace and depth == 0 and square == 0 and paren == 0:
                return i
            continue
        if ch == "[":
            square += 1
            i += 1
            continue
        if ch == "]":
            square = max(0, square - 1)
            i += 1
            continue
        if ch == "(":
            paren += 1
            i += 1
            continue
        if ch == ")":
            paren = max(0, paren - 1)
            i += 1
            continue
        if ch == ";" and not seen_brace and depth == 0 and square == 0 and paren == 0:
            return i + 1
        i += 1
    raise ExtractError(f"unclosed item at {start}")


def _attrs_before(src: str, start: int) -> int:
    """Include #[derive(...)] lines immediately before start."""
    line_start = src.rfind("\n", 0, start)
    region = src[: start if line_start < 0 else line_start]
    m = re.search(r"(?:#\[(?:[^\]]|derive)*\]\s*)+$", region)
    if not m:
        # simpler: walk back over derive attributes
        pos = start
        while True:
            prev_nl = src.rfind("\n", 0, pos)
            line = src[(prev_nl + 1) if prev_nl >= 0 else 0 : pos].strip()
            if line.startswith("#[") and line.endswith("]"):
                pos = prev_nl if prev_nl >= 0 else 0
                continue
            if line == "":
                pos = prev_nl if prev_nl >= 0 else 0
                if prev_nl < 0:
                    break
                continue
            break
        return pos if pos < start else start
    return m.start()


def extract_named(src: str, kind: str, name: str) -> str:
    if kind == "fn":
        pat = rf"(?:pub\s+)?fn\s+{re.escape(name)}\s*[\(<]"
    elif kind == "const":
        pat = rf"(?:pub\s+)?const\s+{re.escape(name)}\s*:"
    elif kind == "struct":
        pat = rf"(?:pub\s+)?struct\s+{re.escape(name)}\b"
    else:
        raise ExtractError(kind)
    matches = list(re.finditer(pat, src))
    if not matches:
        raise ExtractError(f"{kind} {name} not found")
    if len(matches) != 1:
        raise ExtractError(f"{kind} {name} found {len(matches)} times")
    start = matches[0].start()
    if kind == "struct":
        start = _attrs_before(src, start)
    end = _item_end(src, matches[0].start())
    text = src[start:end].rstrip() + "\n"
    if kind == "fn" and not text.lstrip().startswith("pub "):
        text = re.sub(r"^fn ", "pub fn ", text, count=1)
    if kind == "const" and not text.lstrip().startswith("pub "):
        text = re.sub(r"^const ", "pub const ", text, count=1)
    if kind == "struct" and "pub struct " not in text:
        text = text.replace("struct ", "pub struct ", 1)
    return text


def extract_fn_as(src: str, name: str, alias: str) -> str:
    text = extract_named(src, "fn", name)
    text = re.sub(rf"\bfn\s+{re.escape(name)}\b", f"fn {alias}", text, count=1)
    if not text.lstrip().startswith("pub "):
        text = re.sub(r"^fn ", "pub fn ", text, count=1)
    return text


CARGO_TOML = """[package]
name = "review323v2-probe"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
serde_json = "1.0"
"""

MAIN_RS = r'''use review323v2_probe as p;
use serde_json::{json, Value};
use std::fs;
use std::io::{self, Read};
use std::path::Path;

fn main() {
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw).expect("stdin");
    let req: Value = serde_json::from_str(&raw).expect("json request");
    let op = req["op"].as_str().expect("op");
    let out = match op {
        "contract" => match p::check_profile_contract("fixture-provider", req["profile"].as_str().unwrap()) {
            Ok(()) => json!({"ok": true}),
            Err(reason) => json!({"ok": false, "reason": reason}),
        },
        "root_wide" => json!({"ok": true, "root_wide": p::is_root_wide_read(req["form"].as_str().unwrap())}),
        "default_allow" => json!({"ok": true, "default_allow": p::is_default_allow(req["form"].as_str().unwrap())}),
        "network_allow" => json!({"ok": true, "network_allow": p::is_network_allow(req["form"].as_str().unwrap())}),
        "import" => json!({"ok": true, "import": p::is_import(req["form"].as_str().unwrap())}),
        "exec_allow" => json!({"ok": true, "exec_allow": p::is_exec_allow(req["form"].as_str().unwrap())}),
        "forms" => json!({"ok": true, "forms": p::profile_forms(req["profile"].as_str().unwrap())}),
        "allow_forms" => json!({"ok": true, "forms": p::allow_forms(req["profile"].as_str().unwrap())}),
        "nested" => json!({"ok": true, "lists": p::nested_lists(req["form"].as_str().unwrap())}),
        "strip" => json!({"ok": true, "text": p::rust_source_without_comments(req["source"].as_str().unwrap())}),
        "model_strip" => json!({"ok": true, "text": p::model_rust_source_without_comments(req["source"].as_str().unwrap())}),
        "model_allow_forms" => json!({"ok": true, "forms": p::model_allow_forms(req["profile"].as_str().unwrap())}),
        "model_root_wide" => json!({"ok": true, "root_wide": p::model_is_root_wide_read(req["form"].as_str().unwrap())}),
        "did_forms" => json!({"ok": true, "forms": p::did_profile_forms(req["profile"].as_str().unwrap())}),
        "fixture" => json!({"ok": true, "profile": p::contract_fixture_profile(true)}),
        "justification" => {
            let name = req["name"].as_str().unwrap();
            let id = req["id"].as_str().unwrap();
            match p::platform_baseline_justification_text(name, id) {
                Ok(text) => json!({"ok": true, "text": text}),
                Err(reason) => json!({"ok": false, "reason": reason}),
            }
        }
        "rights" => {
            let declared: Value = req["declared"].clone();
            match p::check_declared_rights(
                req["name"].as_str().unwrap(),
                req["profile"].as_str().unwrap(),
                &declared,
            ) {
                Ok(()) => json!({"ok": true}),
                Err(reason) => json!({"ok": false, "reason": reason}),
            }
        }
        "cite" => {
            let dir = Path::new(req["dir"].as_str().unwrap());
            let problems = p::operations_table_citation_problems(
                req["name"].as_str().unwrap_or("fixture-provider"),
                req["document"].as_str().unwrap(),
                dir,
            );
            json!({"ok": true, "problems": problems})
        }
        "shared_rules" => json!({"ok": true, "rules": p::SHARED_RULES}),
        "startup_rules" => json!({"ok": true, "rules": p::STARTUP_RULES}),
        "holds_cited" => json!({
            "ok": true,
            "holds": p::rust_holds_cited_test(
                req["source"].as_str().unwrap(),
                req["function"].as_str().unwrap(),
            )
        }),
        "did_denies" => match p::profile_network_denied(req["profile"].as_str().unwrap()) {
            Ok(()) => json!({"ok": true}),
            Err(reason) => json!({"ok": false, "reason": reason}),
        }
        other => json!({"ok": false, "reason": format!("unknown op {other}")}),
    };
    println!("{}", out);
    let _ = fs::metadata(".");
}
'''


LIB_HEADER = """//! Generated from #323 checker functions for review-323-v2. Do not edit by hand.
use serde_json::Value;
use std::fs;
use std::path::Path;
"""


def build(out: Path = OUT) -> Path:
    wallet = WALLET.read_text()
    model = MODEL.read_text()
    did = DID.read_text()

    parts = [LIB_HEADER, "\n"]
    for name in WALLET_CONSTS:
        parts.append(extract_named(wallet, "const", name))
        parts.append("\n")
    parts.append(extract_named(wallet, "struct", "DeclaredClaim"))
    parts.append("\n")
    for name in WALLET_FNS:
        parts.append(extract_named(wallet, "fn", name))
        parts.append("\n")
    for name in MODEL_FNS:
        if name == "rust_source_without_comments":
            parts.append(extract_fn_as(model, name, "model_rust_source_without_comments"))
        else:
            parts.append(extract_named(model, "fn", name))
        parts.append("\n")
    parts.append(extract_fn_as(did, "profile_forms", "did_profile_forms"))
    parts.append("\n")
    for name in [
        "DID_SHARED_RULES",
        "DID_STARTUP_RULES",
        "DID_MODEL_STARTUP_ROOT",
    ]:
        parts.append(extract_named(did, "const", name))
        parts.append("\n")
    for name in [
        "did_allow_head",
        "did_casefold_profile_form",
        "did_permitted_profile_forms",
        "did_is_permitted_profile_form",
        "did_is_import",
        "did_nested_lists",
        "did_collect_nested_lists",
        "profile_network_denied",
    ]:
        parts.append(extract_named(did, "fn", name))
        parts.append("\n")

    src_dir = out / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (out / "Cargo.toml").write_text(CARGO_TOML)
    (src_dir / "lib.rs").write_text("".join(parts))
    (src_dir / "main.rs").write_text(MAIN_RS)
    (out / "EXTRACTED_FROM").write_text(
        f"wallet={WALLET}\nmodel={MODEL}\ndid={DID}\n"
        f"wallet_sha={_sha256(WALLET)}\n"
        f"model_sha={_sha256(MODEL)}\n"
        f"did_sha={_sha256(DID)}\n"
    )
    return out


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args(argv)
    dest = build(args.out)
    print(f"wrote {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
