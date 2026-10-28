"""Refuse a core-calls citation the worktree does not support.

One parser. ``problems`` is the only function that decides a citation.
"""

import re
import subprocess
from pathlib import Path

# One line: the prefix, a space, and forty lowercase hex digits.
PIN_LINE = re.compile(r"Pinned commit: ([0-9a-f]{40})")

# The ::func alternative is tried before :start.
CITATION = re.compile(
    r"(?P<path>(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+)"
    r"(?:::(?P<func>[A-Za-z_][A-Za-z0-9_]*)|:(?P<start>[1-9][0-9]*)(?:-(?P<end>[1-9][0-9]*))?)"
)

DRAFT = Path("lab/bus-v2-proposal/CORE-CALLS-PROPOSAL.md")

# The one owned citation. Its quotation stays unchecked until a slice owns it.
OWNED_SPAN = "examples/agent-host/src/lib.rs:3754"
OWNED_MARKER = "`" + OWNED_SPAN + "`"

# Its quotation is the second indented line after the owned span.
NEXT_SPAN = "examples/agent-host/src/lib.rs:3755"

# Its quotation is the last indented line after the marker span, source line 8162.
MARKER_SPAN = "examples/agent-host/src/lib.rs:8162"
MARKER_MARKER = "`" + MARKER_SPAN + "`"

# The draft indents a quotation by exactly four spaces.
DRAFT_INDENT = "    "


def read_file(root, rel):
    """Return file bytes, or None when ``rel`` is not a file under ``root``."""
    path = Path(root) / rel
    if not path.is_file():
        return None
    return path.read_bytes()


def decode_text(data):
    """Decode UTF-8. Raise UnicodeDecodeError on a bad byte."""
    return data.decode("utf-8")


def line_count(text):
    """Count lines. A trailing newline does not add an empty line."""
    return len(text.splitlines())


def has_function(text, name):
    """True when ``text`` defines ``fn name(`` or ``def name(``."""
    pattern = r"(?m)(?:^|\s)(?:fn|def) " + re.escape(name) + r"\("
    return re.search(pattern, text) is not None


def range_is_reversed(start, end):
    """True when line range START-END runs backwards."""
    return start > end


def worktree_root():
    """Repo root. This file lives at lab/bus-v2-proposal/check.py."""
    return Path(__file__).resolve().parents[2]


def load_draft(root):
    """Return the draft text, or None when the draft file is absent."""
    draft = Path(root) / DRAFT
    if not draft.is_file():
        return None
    return draft.read_text(encoding="utf-8")


def _pin_lines(text):
    return [line for line in text.splitlines() if line.startswith("Pinned commit:")]


def pin_refusal(text):
    """Refuse a draft that does not pin exactly one commit."""
    pins = _pin_lines(text)
    if not pins:
        return "refuse: draft has no pinned commit"
    if len(pins) != 1 or PIN_LINE.fullmatch(pins[0]) is None:
        return "refuse: pinned commit is not one 40-hex commit"
    return None


def pin_sha(text):
    """Return the pinned 40-hex commit, or None when the pin is not one."""
    pins = _pin_lines(text)
    if len(pins) != 1:
        return None
    match = PIN_LINE.fullmatch(pins[0])
    if match is None:
        return None
    return match.group(1)


def commit_exists(root, sha):
    """True when SHA names a commit object in the git repo at ``root``."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "--quiet", sha + "^{commit}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return False
    return result.returncode == 0


def _spans(text):
    spans = []
    cursor = 0
    while True:
        opened = text.find("`", cursor)
        if opened < 0:
            return spans
        closed = text.find("`", opened + 1)
        if closed < 0:
            return spans
        spans.append(text[opened + 1:closed])
        cursor = closed + 1


def pinned_line(root, sha, rel, number):
    """Return line NUMBER of REL at commit SHA, or None when it is absent."""
    if sha is None:
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "show", sha + ":" + rel],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    try:
        text = decode_text(result.stdout)
    except UnicodeDecodeError:
        return None
    lines = text.splitlines()
    if number < 1 or number > len(lines):
        return None
    return lines[number - 1]


def _span_target(span):
    """Return the path and line number of SPAN."""
    rel, _, number = span.rpartition(":")
    return rel, int(number)


def _remainders(text, marker):
    """Return the indented remainders after MARKER, in order."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if marker not in line:
            continue
        remainders = []
        for following in lines[index + 1:]:
            if not following:
                continue
            if not following.startswith(DRAFT_INDENT):
                break
            remainders.append(following[len(DRAFT_INDENT):])
        return remainders
    return []


def owned_quote(text):
    """Return the first quotation after the owned span, or None when absent."""
    remainders = _remainders(text, OWNED_MARKER)
    if not remainders:
        return None
    return remainders[0]


def next_owned_quote(text):
    """Return the second quotation after the owned span, or None when absent."""
    remainders = _remainders(text, OWNED_MARKER)
    if len(remainders) < 2:
        return None
    return remainders[1]


def marker_quote(text):
    """Return the last quotation after the marker span, or None when absent."""
    remainders = _remainders(text, MARKER_MARKER)
    if not remainders:
        return None
    return remainders[-1]


def quoted_line_matches(quoted, source):
    """True only when the quotation equals the pinned source line."""
    return quoted == source


def _next_quote_refusal(root, text, sha):
    """Return the 3755 refusal, or None when that quote is absent or matches."""
    quoted = next_owned_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(NEXT_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + NEXT_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + NEXT_SPAN
    return None


def _marker_quote_refusal(root, text, sha):
    """Return the 8162 refusal, or None when that quote is absent or matches."""
    if text.count(MARKER_MARKER) > 1:
        return "refuse: quoted line is not one line: " + MARKER_SPAN
    quoted = marker_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(MARKER_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + MARKER_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + MARKER_SPAN
    return None


def _quote_refusals(root, text, sha):
    """Return the quote refusals, the owned line first, then the marker line."""
    if text.count(OWNED_MARKER) > 1:
        return ["refuse: quoted line is not one line: " + OWNED_SPAN]
    quoted = owned_quote(text)
    if quoted is not None:
        rel, number = _span_target(OWNED_SPAN)
        source = pinned_line(root, sha, rel, number)
        if source is None:
            return ["refuse: quoted line is not in the pinned commit: " + OWNED_SPAN]
        if not quoted_line_matches(quoted, source):
            return ["refuse: quoted line does not match " + OWNED_SPAN]
        following = _next_quote_refusal(root, text, sha)
        if following is not None:
            return [following]
    marker = _marker_quote_refusal(root, text, sha)
    if marker is None:
        return []
    return [marker]


def _past_end(number, rel, count):
    return "refuse: line %s is past the end of %s (%s lines)" % (number, rel, count)


def _refusal(root, match):
    rel = match.group("path")
    data = read_file(root, rel)
    if data is None:
        return "refuse: path does not exist: " + rel
    try:
        text = decode_text(data)
    except UnicodeDecodeError:
        return "refuse: path is not utf-8 text: " + rel
    func = match.group("func")
    if func is not None:
        if not has_function(text, func):
            return "refuse: function " + func + " is not in " + rel
        return None
    start = int(match.group("start"))
    end_text = match.group("end")
    end = None if end_text is None else int(end_text)
    if end is not None and range_is_reversed(start, end):
        return "refuse: line range %s-%s is reversed in %s" % (start, end, rel)
    count = line_count(text)
    if end is None:
        if start > count:
            return _past_end(start, rel, count)
        return None
    if end > count:
        return _past_end(end, rel, count)
    if start > count:
        return _past_end(start, rel, count)
    return None


def problems(root):
    """Return one refusal per bad pin or citation, pin refusals first."""
    text = load_draft(root)
    if text is None:
        return ["refuse: proposal is absent"]
    refusals = []
    pin_reason = pin_refusal(text)
    sha = None
    pinned = False
    if pin_reason is not None:
        refusals.append(pin_reason)
    else:
        sha = pin_sha(text)
        pinned = sha is not None and commit_exists(root, sha)
        if sha is not None and not pinned:
            refusals.append("refuse: pinned commit is not a commit: " + sha)
    for span in _spans(text):
        match = CITATION.fullmatch(span)
        if match is None:
            continue
        reason = _refusal(root, match)
        if reason is not None:
            refusals.append(reason)
    if pin_reason is None and pinned:
        refusals.extend(_quote_refusals(root, text, sha))
    return refusals


def main():
    """Check this worktree. Return 1 when a refusal is printed."""
    root = worktree_root()
    found = problems(root)
    for line in found:
        print(line)
    if found:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
