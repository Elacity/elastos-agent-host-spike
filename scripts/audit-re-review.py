#!/usr/bin/env python3
"""Fail when an ignored advisory's re-review date has passed.

The ignored ids are the strings in the TOML array advisories.ignore. Python
3.11's tomllib reads that array when it is installed. This Mac's python3 is
3.9 and has no tomllib, so the parser below reads the same array, and when
tomllib is present the two id lists must match. Each id takes the dates in
the comment block immediately above it, and a date on its own line. It needs
exactly one real date. A date is not kept for a later id. A line with two
ids gives neither of them that date.

AUDIT_RE_REVIEW_TODAY, as YYYY-MM-DD, checks another day. With that unset,
the day is the UTC date.
"""

import datetime
import os
import re
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.9, including this Mac's python3 -I
    tomllib = None

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "elastos/.cargo/audit.toml"
REVIEW = re.compile(r"re-review by (\d{4}-\d{2}-\d{2})\b")
TARGET = ("advisories", "ignore")


class ScanError(Exception):
    """The file is not an ignore list this check can pair with dates."""


def today():
    raw = os.environ.get("AUDIT_RE_REVIEW_TODAY")
    if raw:
        return require_day(raw, f"AUDIT_RE_REVIEW_TODAY {raw} is not a date")
    return datetime.datetime.now(datetime.timezone.utc).date()


def require_day(text, message):
    parts = text.split("-")
    if len(parts) != 3 or tuple(len(part) for part in parts) != (4, 2, 2):
        raise SystemExit(message)
    if any(not part.isdigit() for part in parts):
        raise SystemExit(message)
    try:
        return datetime.date(int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        raise SystemExit(message)


def dates_in(comments):
    found = []
    for comment in comments:
        found.extend(REVIEW.findall(comment))
    return found


def tokenize(text):
    """Comments, strings, and the punctuation the ignore list needs."""
    tokens, i, line, n = [], 0, 1, len(text)
    while i < n:
        char = text[i]
        if char in " \t\r":
            i += 1
            continue
        if char == "\n":
            tokens.append(("nl", "", line))
            i += 1
            line += 1
            continue
        if char == "#":
            end = text.find("\n", i)
            if end < 0:
                end = n
            tokens.append(("comment", text[i:end], line))
            i = end
            continue
        if char == "'":
            if text.startswith("'''", i):
                raise ScanError(f"audit.toml:{line}: a multi-line string is not read")
            value, i = read_literal(text, i, line)
            tokens.append(("string", value, line))
            continue
        if char == '"':
            if text.startswith('"""', i):
                raise ScanError(f"audit.toml:{line}: a multi-line string is not read")
            value, i = read_basic(text, i, line)
            tokens.append(("string", value, line))
            continue
        if char in "[]{}=,.":
            tokens.append((char, char, line))
            i += 1
            continue
        if char.isdigit() or (char in "+-" and i + 1 < n and text[i + 1].isdigit()):
            end = read_scalar(text, i)
            tokens.append(("scalar", text[i:end], line))
            i = end
            continue
        match = re.match(r"[A-Za-z0-9_-]+", text[i:])
        if match:
            tokens.append(("bare", match.group(), line))
            i += match.end()
            continue
        raise ScanError(f"audit.toml:{line}: cannot read {char!r}")
    return tokens


def read_literal(text, start, line):
    end = text.find("'", start + 1)
    if end < 0 or "\n" in text[start + 1 : end]:
        raise ScanError(f"audit.toml:{line}: a string is not closed")
    return text[start + 1 : end], end + 1


def read_basic(text, start, line):
    value, i, n = [], start + 1, len(text)
    escapes = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", '"': '"', "\\": "\\"}
    while i < n:
        char = text[i]
        if char == '"':
            return "".join(value), i + 1
        if char == "\n":
            raise ScanError(f"audit.toml:{line}: a string is not closed")
        if char != "\\":
            value.append(char)
            i += 1
            continue
        if i + 1 >= n or text[i + 1] not in escapes and text[i + 1] not in "uU":
            raise ScanError(f"audit.toml:{line}: bad escape")
        mark = text[i + 1]
        if mark in escapes:
            value.append(escapes[mark])
            i += 2
            continue
        width = 4 if mark == "u" else 8
        digits = text[i + 2 : i + 2 + width]
        if len(digits) != width or any(item not in "0123456789abcdefABCDEF" for item in digits):
            raise ScanError(f"audit.toml:{line}: bad escape")
        value.append(chr(int(digits, 16)))
        i += 2 + width
    raise ScanError(f"audit.toml:{line}: a string is not closed")


def read_scalar(text, start):
    i, n = start, len(text)
    if text[i] in "+-":
        i += 1
    if text.startswith(("0x", "0o", "0b"), i):
        alphabet = {"x": "0123456789abcdefABCDEF_", "o": "01234567_", "b": "01_"}[text[i + 1]]
        i += 2
        while i < n and text[i] in alphabet:
            i += 1
        return i
    while i < n and (text[i].isdigit() or text[i] == "_"):
        i += 1
    if i < n and text[i] == "." and i + 1 < n and text[i + 1].isdigit():
        i += 2
        while i < n and (text[i].isdigit() or text[i] == "_"):
            i += 1
    if i < n and text[i] in "eE":
        j = i + 1
        if j < n and text[j] in "+-":
            j += 1
        if j < n and text[j].isdigit():
            i = j + 1
            while i < n and (text[i].isdigit() or text[i] == "_"):
                i += 1
    return i


def skip_noise(tokens, pos):
    while pos < len(tokens) and tokens[pos][0] in ("nl", "comment"):
        pos += 1
    return pos


def skip_bracket(tokens, pos, open_kind, close_kind):
    depth = 0
    while pos < len(tokens):
        kind = tokens[pos][0]
        if kind == open_kind:
            depth += 1
        elif kind == close_kind:
            depth -= 1
            if depth == 0:
                return pos + 1
        pos += 1
    raise ScanError("audit.toml: a value is not closed")


def parse_key(tokens, pos):
    if pos >= len(tokens):
        raise ScanError("audit.toml: a key is missing")
    parts = []
    while True:
        kind, value, line = tokens[pos]
        if kind not in ("bare", "string"):
            raise ScanError(f"audit.toml:{line}: a key is missing")
        parts.append(value)
        pos += 1
        if pos < len(tokens) and tokens[pos][0] == ".":
            pos += 1
            if pos >= len(tokens):
                raise ScanError(f"audit.toml:{line}: a key is missing")
            continue
        return tuple(parts), pos


def parse_header(tokens, pos):
    line = tokens[pos][2]
    pos += 1
    array = pos < len(tokens) and tokens[pos][0] == "["
    if array:
        pos += 1
    parts = []
    while True:
        pos = skip_noise(tokens, pos)
        if pos >= len(tokens):
            raise ScanError(f"audit.toml:{line}: a table header is not closed")
        kind, value, key_line = tokens[pos]
        if kind not in ("bare", "string"):
            raise ScanError(f"audit.toml:{key_line}: a table header is not closed")
        parts.append(value)
        pos += 1
        pos = skip_noise(tokens, pos)
        if pos < len(tokens) and tokens[pos][0] == ".":
            pos += 1
            continue
        break
    if pos >= len(tokens) or tokens[pos][0] != "]":
        raise ScanError(f"audit.toml:{line}: a table header is not closed")
    pos += 1
    if array:
        if pos >= len(tokens) or tokens[pos][0] != "]":
            raise ScanError(f"audit.toml:{line}: a table header is not closed")
        pos += 1
        # An array of tables is not the advisories table, so its keys cannot
        # become the ignore list.
        return pos, ("#array",) + tuple(parts)
    return pos, tuple(parts)


def opens_ignore(path):
    return len(path) < len(TARGET) and TARGET[: len(path)] == path


def parse_ignore_array(tokens, pos):
    """The strings of one array, each with the dates that belong to it alone."""
    pos += 1
    lines, current = [], []
    while pos < len(tokens):
        kind, value, line = tokens[pos]
        if kind == "]":
            lines.append(current)
            return lines_to_items(lines), pos + 1
        if kind == "nl":
            lines.append(current)
            current = []
            pos += 1
            continue
        if kind in ("string", "comment", ","):
            current.append((kind, value))
            pos += 1
            continue
        raise ScanError(f"audit.toml:{line}: ignore entry is not a string id")
    raise ScanError("audit.toml: ignore list is not closed")


def lines_to_items(lines):
    pending, items = [], []
    for line in lines:
        strings = [value for kind, value in line if kind == "string"]
        comments = [value for kind, value in line if kind == "comment"]
        if not strings:
            if comments and all(kind == "comment" for kind, _value in line):
                pending.extend(comments)
            else:
                pending = []
            continue
        if len(strings) == 1:
            items.append((strings[0], dates_in(pending) + dates_in(comments), True))
        else:
            # One date cannot belong to two ids. Name both; keep nothing.
            for advisory in strings:
                items.append((advisory, [], False))
        pending = []
    return items


def take_value(tokens, pos, path):
    if pos >= len(tokens):
        raise ScanError("audit.toml: a value is missing")
    kind, _value, line = tokens[pos]
    if path == TARGET:
        if kind != "[":
            raise ScanError(f"audit.toml:{line}: ignore list is not an array")
        items, pos = parse_ignore_array(tokens, pos)
        return pos, items, True
    if kind == "{" and opens_ignore(path):
        return parse_inline_table(tokens, pos, path)
    if kind == "{":
        return skip_bracket(tokens, pos, "{", "}"), None, False
    if kind == "[":
        return skip_bracket(tokens, pos, "[", "]"), None, False
    if kind in ("string", "bare", "scalar"):
        return pos + 1, None, False
    raise ScanError(f"audit.toml:{line}: cannot read a value")


def parse_inline_table(tokens, pos, prefix):
    pos += 1
    found, items = False, None
    while True:
        pos = skip_noise(tokens, pos)
        if pos >= len(tokens):
            raise ScanError("audit.toml: an inline table is not closed")
        if tokens[pos][0] == "}":
            return pos + 1, items, found
        key_line = tokens[pos][2]
        key, pos = parse_key(tokens, pos)
        pos = skip_noise(tokens, pos)
        if pos >= len(tokens) or tokens[pos][0] != "=":
            raise ScanError(f"audit.toml:{key_line}: expected '='")
        pos += 1
        pos = skip_noise(tokens, pos)
        pos, got_items, got = take_value(tokens, pos, prefix + key)
        if got:
            if found:
                raise ScanError("audit.toml: ignore list is repeated")
            found, items = True, got_items
        pos = skip_noise(tokens, pos)
        if pos < len(tokens) and tokens[pos][0] == ",":
            pos += 1
            continue
        if pos >= len(tokens) or tokens[pos][0] != "}":
            raise ScanError("audit.toml: an inline table is not closed")


def parse_document(text):
    """(whether advisories.ignore was present, [(id, dates, own)])."""
    tokens, pos, table = tokenize(text), 0, ()
    found, items = False, []
    while True:
        pos = skip_noise(tokens, pos)
        if pos >= len(tokens):
            return found, items
        kind, _value, line = tokens[pos]
        if kind == "[":
            pos, table = parse_header(tokens, pos)
            continue
        key, pos = parse_key(tokens, pos)
        pos = skip_noise(tokens, pos)
        if pos >= len(tokens) or tokens[pos][0] != "=":
            raise ScanError(f"audit.toml:{line}: expected '=' after {'.'.join(key)}")
        pos += 1
        pos = skip_noise(tokens, pos)
        pos, got_items, got = take_value(tokens, pos, table + key)
        if got:
            if found:
                raise ScanError("audit.toml: ignore list is repeated")
            found, items = True, got_items


def agree_with_tomllib(text, found, items):
    if tomllib is None:
        return
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ScanError(f"audit.toml: not TOML: {error}") from None
    advisories = data.get("advisories") if isinstance(data, dict) else None
    has_list = isinstance(advisories, dict) and "ignore" in advisories
    if not has_list:
        if found:
            raise ScanError("audit.toml: ignore list is missing from the TOML")
        return
    ignore = advisories["ignore"]
    if not isinstance(ignore, list) or any(not isinstance(item, str) for item in ignore):
        raise ScanError("audit.toml: ignore list is not a list of ids")
    parsed = [advisory for advisory, _dates, _own in items]
    if parsed != list(ignore):
        left = ", ".join(parsed) if parsed else "(none)"
        right = ", ".join(ignore) if ignore else "(none)"
        raise ScanError(f"audit.toml: ignored ids {left} do not match the TOML ids {right}")


def not_one_date(advisory, dates):
    if len(dates) == 2:
        shown = f"{dates[0]} and {dates[1]}"
    else:
        shown = ", ".join(dates[:-1]) + " and " + dates[-1]
    return f"{advisory}: re-review dates {shown} are not one date"


def failures(text, on):
    """Each expired, undated, or unpaired advisory, named."""
    try:
        found, items = parse_document(text)
        agree_with_tomllib(text, found, items)
    except ScanError as error:
        return [str(error)]
    if not found:
        return ["audit.toml: ignore list is missing"]
    result = []
    for advisory, dates, own in items:
        if not own:
            result.append(f"{advisory}: re-review date is not its own")
            continue
        if not dates:
            result.append(f"{advisory}: re-review date is missing")
            continue
        if len(dates) != 1:
            result.append(not_one_date(advisory, dates))
            continue
        try:
            year, month, day = (int(part) for part in dates[0].split("-"))
            deadline = datetime.date(year, month, day)
        except ValueError:
            result.append(f"{advisory}: re-review date {dates[0]} is not a date")
            continue
        if deadline < on:
            result.append(f"{advisory}: re-review date {dates[0]} has passed")
    return result


def main(argv):
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT
    found = failures(path.read_text(encoding="utf-8"), today())
    for line in found:
        print(line, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
