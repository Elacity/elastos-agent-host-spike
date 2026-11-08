#!/usr/bin/env python3
"""Count the Runtime core (elastos/crates/elastos-runtime) as tests, comments, blank lines and code.

Test lines: files under a tests/ directory or named tests.rs or *_test.rs. Comment lines start
with // or /*, or lie inside a block comment. Blank lines are blank. Code is everything else,
including a line that begins inside a multi-line string literal.
"""
import re

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
