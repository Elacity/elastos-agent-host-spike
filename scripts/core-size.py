#!/usr/bin/env python3
"""Count the Runtime core (elastos/crates/elastos-runtime) as tests, comments, blank lines and code.

Test lines: files under a tests/ directory or named tests.rs or *_test.rs. Comment lines start
with // or /*, or lie inside a block comment. Blank lines are blank. Code is everything else,
including a line that begins inside a multi-line string literal.

  core-size.py          a short table
  core-size.py --json   {"total", "tests", "comments", "blank", "code"}
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATE = "elastos/crates/elastos-runtime"
CHAR = re.compile(r"'(\\(u\{[0-9a-fA-F]*\}|x..|.)|[^\\\n])'")
LIFETIME, WORD, RAW = re.compile(r"'\w*"), re.compile(r"\w+"), re.compile(r'#*"')
STRING, BLOCK = re.compile(r'"(?:\\.|[^"\\])*"?', re.S), re.compile(r"/\*|\*/")


def is_test_file(path):
    parts = path.split("/")
    return "tests" in parts[:-1] or parts[-1] == "tests.rs" or parts[-1].endswith("_test.rs")


def lex(text):
    """Return (tokens, starts). tokens are (line, kind, value) for everything outside strings and
    comments, plus one 'literal' or 'comment' token where each begins. starts[n] is 'comment' or
    'string' when line n begins inside one, else None."""
    tokens, starts, i, n = [], [None], 0, len(text)

    def to(j, inside):
        nonlocal i
        starts.extend([inside] * text.count("\n", i, j))
        i = j

    while i < n:
        c, line = text[i], len(starts) - 1
        if c == "\n":
            to(i + 1, None)
        elif text.startswith("//", i):
            tokens.append((line, "comment", "//"))
            to(n if text.find("\n", i) < 0 else text.find("\n", i), None)
        elif text.startswith("/*", i):
            tokens.append((line, "comment", "/*"))
            depth, end = 0, n
            for mark in BLOCK.finditer(text, i):  # block comments nest
                depth += 1 if mark.group() == "/*" else -1
                if depth == 0:
                    end = mark.end()
                    break
            to(end, "comment")
        elif c == '"':
            tokens.append((line, "literal", '"'))
            to(STRING.match(text, i).end(), "string")
        elif c == "'":
            tokens.append((line, "literal", "'"))
            i = (CHAR.match(text, i) or LIFETIME.match(text, i)).end()
        elif c.isalpha() or c == "_":
            word = WORD.match(text, i).group()
            raw = RAW.match(text, i + len(word))
            if word in ("r", "br", "cr") and raw:
                tokens.append((line, "literal", '"'))
                end = text.find('"' + "#" * (len(raw.group()) - 1), raw.end())
                to(n if end < 0 else end + len(raw.group()), "string")
            elif word in ("b", "c") and text[i + 1:i + 2] in ("'", '"'):
                i += 1
            else:
                ident = word == "r" and text[i + 1:i + 2] == "#" and WORD.match(text, i + 2)
                word = "r#" + ident.group() if ident else word
                tokens.append((line, "word", word))
                i += len(word)
        elif c.isdigit():
            i = WORD.match(text, i).end()
        else:
            if not c.isspace():
                tokens.append((line, "punct", c))
            i += 1
    return tokens, starts


def count(files):
    """files: (path inside the crate, text) pairs. Returns the line totals."""
    totals = dict.fromkeys(("total", "tests", "comments", "blank", "code"), 0)
    for path, text in files:
        lines = text.split("\n")
        if lines[-1] == "":
            lines.pop()
        totals["total"] += len(lines)
        if is_test_file(path):
            totals["tests"] += len(lines)
            continue
        tokens, starts = lex(text)
        first = {}
        for line, kind, value in tokens:
            first.setdefault(line, kind)
        for n, body in enumerate(lines):
            kind = ("comments" if starts[n] == "comment" else
                    "code" if starts[n] == "string" else "blank" if not body.strip() else
                    "comments" if first.get(n) == "comment" else "code")
            totals[kind] += 1
    return totals


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                          encoding="utf-8", errors="replace").stdout


def worktree_files(root):
    listed = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", CRATE)
    for path in sorted(set(filter(None, listed.split("\0")))):
        if path.endswith(".rs") and (root / path).is_file():
            yield path[len(CRATE) + 1:], (root / path).read_text(encoding="utf-8", errors="replace")


def table(totals):
    rows = "".join(f"| {key} | {value} |\n" for key, value in totals.items())
    return f"| {CRATE} | lines |\n|---|---:|\n{rows}"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--json", action="store_true", help="print the totals as JSON")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    totals = count(worktree_files(args.root))
    print(json.dumps(totals) if args.json else table(totals), end="\n" if args.json else "")
    return 0


if __name__ == "__main__":
    sys.exit(main())
