#!/usr/bin/env python3
"""Count the Runtime core (elastos/crates/elastos-runtime) as tests, comments, blank lines and code.

Test lines: files under a tests/ directory or named tests.rs or *_test.rs, and every item behind
#[cfg(test)] or #[cfg(all(test, ...))], from the attribute through the item's end. Code lines hold
any code token, wherever comments sit on them, or begin inside a multi-line string literal. Comment
lines hold only comments or lie inside a block comment. Blank lines are blank.

  core-size.py                   a short table
  core-size.py --json            {"total", "tests", "comments", "blank", "code"}
  core-size.py --check           fail when code is above elastos/CORE-BUDGET or 50+ below it
  core-size.py --check --base R  also show the change since the merge base of R and HEAD
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATE, BUDGET = "elastos/crates/elastos-runtime", "elastos/CORE-BUDGET"
SLACK = 50  # the budget may sit at most this far above the code; further, the check fails
OPEN, CLOSE = "{([", "})]"
ITEM_WORDS = {"fn", "mod", "impl", "struct", "enum", "trait", "union", "const", "static", "type",
              "use", "extern", "async", "unsafe", "macro_rules", "let", "default"}
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
            tokens.append((line, "literal", WORD.match(text, i).group()))
            i = WORD.match(text, i).end()
        else:
            if not c.isspace():
                tokens.append((line, "punct", c))
            i += 1
    return tokens, starts


def closer(vals, p):
    """Index of the bracket that closes the one at vals[p]."""
    depth = 0
    for q in range(p, len(vals)):
        depth += (vals[q] in OPEN) - (vals[q] in CLOSE)
        if depth == 0:
            return q
    return len(vals) - 1


def cfg_test_spans(tokens):
    """Yield (first_line, last_line) for each item behind #[cfg(test)] or #[cfg(all(test, ...))]."""
    vals = [t[2] for t in tokens]
    for k, value in enumerate(vals):
        inner = vals[k + 1:k + 2] == ["!"]
        head = k + 1 + inner
        if value != "#" or vals[head:head + 3] != ["[", "cfg", "("]:
            continue
        end = closer(vals, head)
        args = vals[head + 3:end - 1]
        if args[:2] == ["all", "("] and closer(args, 1) == len(args) - 1:
            depth, top = 0, []
            for a in args[2:-1]:
                depth -= a in CLOSE
                top += [a] if depth == 0 else []
                depth += a in OPEN
            args = ["test"] if "test" in top else args
        if args == ["test"]:
            yield tokens[k][0], item_end(tokens, vals, end + 1, inner)


def item_end(tokens, vals, j, inner):
    """Line of the last token of the item that starts at tokens[j]."""
    p = j  # Step over further attributes, comments and pub(...) to the item's first word.
    while p < len(vals) and (tokens[p][1] == "comment" or vals[p] in ("#", "!", "pub")):
        p += 1
        if p < len(vals) and vals[p] in ("[", "("):
            p = closer(vals, p) + 1
    # Fields, variants, match arms and statements also end at a comma outside <...>.
    field = not inner and not (p < len(vals) and vals[p] in ITEM_WORDS)
    depth, angle, arrow, last = 0, 0, False, tokens[j - 1][0]
    for line, kind, value in tokens[j:]:
        if kind == "comment":
            continue
        if value in CLOSE and depth == 0:  # the enclosing block closes: the item ended before
            return last
        last = line
        depth += (value in OPEN) - (value in CLOSE)
        if field and value in ("<", ">") and not arrow:
            angle += 1 if value == "<" else -1
        arrow = value in ("-", "=")
        if depth == 0 and not inner and (value in (";", "}") or (field and value == "," and angle <= 0)):
            return line
    return last


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
        tests = {n for a, b in cfg_test_spans(tokens) for n in range(a, b + 1)}
        # A line with any code token on it is code, wherever its comments sit.
        code = {line for line, kind, value in tokens if kind != "comment"}
        notes = {line for line, kind, value in tokens if kind == "comment"}
        for n in range(len(lines)):
            kind = ("tests" if n in tests else "code" if n in code or starts[n] == "string" else
                    "comments" if n in notes or starts[n] == "comment" else "blank")
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


def ref_files(root, ref):
    listed = git(root, "ls-tree", "-r", "-z", "--name-only", ref, "--", CRATE)
    for path in sorted(filter(None, listed.split("\0"))):
        if path.endswith(".rs"):
            yield path[len(CRATE) + 1:], git(root, "show", f"{ref}:{path}")


def read_budget(text):
    values = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if len(values) != 1 or not values[0].isdigit():
        raise SystemExit(f"{BUDGET} must hold exactly one integer line besides # comments")
    return int(values[0])


def table(totals):
    rows = "".join(f"| {key} | {value} |\n" for key, value in totals.items())
    return f"| {CRATE} | lines |\n|---|---:|\n{rows}"


def check(root, totals, base):
    """Print the verdict against the budget and, with base, the change since base; return the exit."""
    code, budget = totals["code"], read_budget((root / BUDGET).read_text())
    notes = []
    if base:
        try:
            point = git(root, "merge-base", base, "HEAD").strip()
        except subprocess.CalledProcessError as error:
            raise SystemExit(f"no merge base of {base} and HEAD (fetch the base with history): {error.stderr.strip()}")
        before = count(ref_files(root, point))["code"]
        try:
            old = read_budget(git(root, "show", f"{point}:{BUDGET}"))
        except subprocess.CalledProcessError:
            old = None
        notes.append(f"Change against {base} (merge base {point[:8]}): core code {code - before:+d} lines"
                     f" ({before} -> {code}).")
        notes.append(f"{BUDGET}: " + ("absent at the base" if old is None else "unchanged" if old == budget
                                      else f"changed {old} -> {budget} ({budget - old:+d})") + ".")
    failed = code > budget or budget - code > SLACK
    if code > budget:
        notes.append(f"FAIL: core code is {code} lines, above the budget of {budget} in {BUDGET}. Move code out"
                     f" of the core, or raise {BUDGET} in this change so reviewers see it.")
    elif budget - code > SLACK:  # a ratchet: room freed in the core cannot be spent again
        notes.append(f"FAIL: core code is {code} lines, {budget - code} below the budget of {budget}:"
                     f" lower {BUDGET} to {code} in this change.")
    else:
        notes.append(f"OK: core code is {code} lines, within the budget of {budget} in {BUDGET}.")
    print("".join(f"\n- {note}" for note in notes))
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--json", action="store_true", help="print the totals as JSON")
    parser.add_argument("--check", action="store_true", help=f"fail when code is above {BUDGET}")
    parser.add_argument("--base", metavar="REF", help="with --check, show the change since this git ref")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.base and not args.check:
        parser.error("--base needs --check")
    totals = count(worktree_files(args.root))
    print(json.dumps(totals) if args.json else table(totals), end="\n" if args.json else "")
    return check(args.root, totals, args.base) if args.check else 0


if __name__ == "__main__":
    sys.exit(main())
