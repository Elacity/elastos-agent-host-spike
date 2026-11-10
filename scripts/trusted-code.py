#!/usr/bin/env python3
"""Measure the code the Runtime trusts: the core crate's code lines and each file of the trusted-code
list, counted by scripts/core-size.py's own counter and lexer under one rule (docs/TRUSTED-CODE.md).

  trusted-code.py            a text report
  trusted-code.py --json     the same numbers as JSON, for the gate that follows
The core number is core-size.py's count() of elastos/crates/elastos-runtime, so the two cannot disagree.
"""
import argparse
import bisect
import importlib.util
import json
import sys
from pathlib import Path
from posixpath import normpath

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = "elastos/trusted-code.json"
KINDS = ("total", "tests", "comments", "blank", "code")

_spec = importlib.util.spec_from_file_location("core_size", Path(__file__).with_name("core-size.py"))
core_size = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(core_size)


def statement_end(vals, q):
    """Last token of the cfg(test) statement or block that starts at vals[q]: its ; or comma at depth
    0, the brace that closes a block at depth 0, or the token before the enclosing block ends."""
    depth = 0
    for p in range(q, len(vals)):
        if vals[p] in core_size.OPEN:
            depth += 1
        elif vals[p] in core_size.CLOSE:
            if depth == 0:
                return p - 1
            depth -= 1
            if depth == 0 and vals[p] == "}":
                return p
        elif vals[p] in (";", ",") and depth == 0:
            return p
    return len(vals) - 1


def analyse(tokens):
    """(test token indexes, test spans) as core-size.py's analyse gives them; where it refuses a
    #[cfg(test)] on a statement, that statement's own span from the attribute. The span stops at the
    statement's ; or closing brace, so a line the counter cannot place stays code, never test."""
    try:
        tests, spans, mods, includes = core_size.analyse(tokens)
        return tests, spans
    except core_size.Refusal as error:
        if "test cfg on a match arm" not in str(error):
            raise
    code = [token for token in tokens if token[1] != "comment"]
    vals, lines = [token[2] for token in code] + [""] * 4, [token[0] for token in code]
    found = {"spans": [], "attrs": set(), "mods": [], "mod_tokens": set(), "includes": []}
    core_size.parse_items(vals, lines, 0, len(code), False, found)
    for k in range(len(code)):  # attributes the item walk did not consume sit on a statement
        if vals[k] == "#" and k not in found["attrs"] and vals[k + 1] == "[":
            if core_size.attr_is_test(vals, k + 1, core_size.closer(vals, k + 1)):
                found["spans"].append((k, statement_end(vals, core_size.closer(vals, k + 1) + 1)))
        if vals[k] == "include" and vals[k + 1] == "!":
            raise core_size.Refusal("include! of another file: a counted file holds only its own text",
                                    lines[k])
    return {k for a, b in found["spans"] for k in range(a, b + 1)}, found["spans"]


def count_file(text):
    """The line totals of one .rs file in core-size.py's classes: its count() per-file loop without
    the module tree, over its lexer and analyser."""
    tokens, starts = core_size.lex(text)
    tests, spans = analyse(tokens)
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    code = [token for token in tokens if token[1] != "comment"]
    firsts = [token[0] for token in code]
    live = {code[k][0] for k in range(len(code)) if k not in tests}
    dead = {code[k][0] for k in tests} | {n for a, b in spans for n in range(code[a][0], code[b][0] + 1)}
    notes = {line for line, kind, value in tokens if kind == "comment"}
    totals = dict.fromkeys(KINDS, 0)
    for n in range(len(lines)):
        totals["total"] += 1
        if starts[n] == "string":
            (live if bisect.bisect_left(firsts, n) - 1 not in tests else dead).add(n)
        kind = ("code" if n in live else "tests" if n in dead else
                "comments" if n in notes or starts[n] == "comment" else "blank")
        totals[kind] += 1
    return totals


def test_file_totals(text):
    """A test file: every line is test code, so its count is zero."""
    lines = text.split("\n")
    return {"total": len(lines) - (lines[-1] == ""), "tests": len(lines) - (lines[-1] == ""),
            "comments": 0, "blank": 0, "code": 0}


def file_rows(root, manifest):
    """One row per listed file: its path, its line totals, and why it has none."""
    rows = []
    for path in manifest["files"]:
        row = {"path": path, "counts": dict.fromkeys(KINDS, 0)}
        if not path.endswith(".rs"):
            row["error"] = "not a Rust file"
        elif not (root / path).is_file():
            row["error"] = "listed but absent"
        elif "tests" in normpath(path).split("/"):
            row["test_file"] = True
            row["counts"] = test_file_totals((root / path).read_text(encoding="utf-8"))
        else:
            row["counts"] = count_file((root / path).read_text(encoding="utf-8"))
        rows.append(row)
    return rows


def measure(root, manifest):
    totals = core_size.count(core_size.worktree_files(root))
    return {
        "root": str(root),
        "core": {"crate": core_size.CRATE, "code": totals["code"], "counts": totals,
                 "counter": "scripts/core-size.py:count"},
        "files": file_rows(root, manifest),
    }


def text(report):
    core = report["core"]
    return (f"core crate {core['crate']}: {core['code']} code lines"
            f" ({core['counts']['tests']} tests, {core['counts']['comments']} comments,"
            f" {core['counts']['blank']} blank; {core['counter']})")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    parser.add_argument("--manifest", type=Path, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    manifest_path = args.manifest or args.root / MANIFEST
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        report = measure(args.root, manifest)
    except (OSError, ValueError, core_size.Refusal) as error:
        print(f"trusted-code: refused: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2) if args.json else text(report))
    return 1 if any("error" in row for row in report["files"]) else 0


if __name__ == "__main__":
    sys.exit(main())
