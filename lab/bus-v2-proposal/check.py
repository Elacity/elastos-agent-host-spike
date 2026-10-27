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

# Its quotation is the last indented line after the launching span, source line 8168.
LAUNCHING_SPAN = "examples/agent-host/src/lib.rs:8168"
LAUNCHING_MARKER = "`" + LAUNCHING_SPAN + "`"

# Its quotation is the third indented line after the asks span, source line 8149.
ASKS_SPAN = "examples/agent-host/src/lib.rs:8149"
ASKS_MARKER = "`" + ASKS_SPAN + "`"

# Its quotation is the first indented line after the deny span, source line 3526.
DENY_SPAN = "examples/agent-host/src/lib.rs:3526"
DENY_MARKER = "`" + DENY_SPAN + "`"

# Its quotation is the second indented line after the mint span, source line 3549.
MINT_SPAN = "examples/agent-host/src/lib.rs:3549"
MINT_MARKER = "`" + MINT_SPAN + "`"

# Its quotation is the second indented line after the journal span, source line 3757.
JOURNAL_SPAN = "examples/agent-host/src/lib.rs:3757"
JOURNAL_MARKER = "`" + JOURNAL_SPAN + "`"

# Its quotation is the first indented line after the grant span, source line 3767.
GRANT_SPAN = "examples/agent-host/src/lib.rs:3767"
GRANT_MARKER = "`" + GRANT_SPAN + "`"

# Its quotation is the write ask, remainder 16 after the write span, source line 3849.
WRITE_SPAN = "examples/agent-host/src/lib.rs:3849"
WRITE_MARKER = "`" + WRITE_SPAN + "`"

# Its quotation is the read ask, remainder 17 after the read span, source line 3850.
READ_SPAN = "examples/agent-host/src/lib.rs:3850"
READ_MARKER = "`" + READ_SPAN + "`"

# Its quotation is the Read arm, remainder 8 after the kind span, source line 8187.
KIND_READ_SPAN = "examples/agent-host/src/lib.rs:8187"
KIND_READ_MARKER = "`" + KIND_READ_SPAN + "`"

# Its quotation is the Edit arm, remainder 9 after the kind span, source line 8188.
KIND_EDIT_SPAN = "examples/agent-host/src/lib.rs:8188"
KIND_EDIT_MARKER = "`" + KIND_EDIT_SPAN + "`"

# Its quotation is the Restore arm, remainder 11 after the kind span, source line 8190.
KIND_RESTORE_SPAN = "examples/agent-host/src/lib.rs:8190"
KIND_RESTORE_MARKER = "`" + KIND_RESTORE_SPAN + "`"

# Its quotation is the Run arm, the one indented line after the run span, source line 8189.
KIND_RUN_SPAN = "examples/agent-host/src/lib.rs:8189"
KIND_RUN_MARKER = "`" + KIND_RUN_SPAN + "`"

# Its quotation is the Hosted arm, the one indented line after the hosted span, source line 8191.
KIND_HOSTED_SPAN = "examples/agent-host/src/lib.rs:8191"
KIND_HOSTED_MARKER = "`" + KIND_HOSTED_SPAN + "`"

# Its quotation is the Child arm, the one indented line after the child span, source line 8192.
KIND_CHILD_SPAN = "examples/agent-host/src/lib.rs:8192"
KIND_CHILD_MARKER = "`" + KIND_CHILD_SPAN + "`"

# Its quotation is the Init arm, the one indented line after the init span, source line 8193.
KIND_INIT_SPAN = "examples/agent-host/src/lib.rs:8193"
KIND_INIT_MARKER = "`" + KIND_INIT_SPAN + "`"

# Its quotation is the JournalAppend arm, the one indented line after the append span,
# source line 8194.
KIND_APPEND_SPAN = "examples/agent-host/src/lib.rs:8194"
KIND_APPEND_MARKER = "`" + KIND_APPEND_SPAN + "`"

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


def launching_quote(text):
    """Return the last quotation after the launching span, or None when absent."""
    remainders = _remainders(text, LAUNCHING_MARKER)
    if not remainders:
        return None
    return remainders[-1]


def asks_quote(text):
    """Return the third quotation after the asks span, or None when absent."""
    remainders = _remainders(text, ASKS_MARKER)
    if len(remainders) < 3:
        return None
    return remainders[2]


def deny_quote(text):
    """Return the first quotation after the deny span, or None when absent."""
    remainders = _remainders(text, DENY_MARKER)
    if not remainders:
        return None
    return remainders[0]


def mint_quote(text):
    """Return the second quotation after the mint span, or None when absent."""
    remainders = _remainders(text, MINT_MARKER)
    if len(remainders) < 2:
        return None
    return remainders[1]


def journal_quote(text):
    """Return the second quotation after the journal span, or None when absent."""
    remainders = _remainders(text, JOURNAL_MARKER)
    if len(remainders) < 2:
        return None
    return remainders[1]


def grant_quote(text):
    """Return the first quotation after the grant span, or None when absent."""
    remainders = _remainders(text, GRANT_MARKER)
    if not remainders:
        return None
    return remainders[0]


def write_quote(text):
    """Return the seventeenth quotation after the write span, or None when absent."""
    remainders = _remainders(text, WRITE_MARKER)
    if len(remainders) < 17:
        return None
    return remainders[16]


def read_quote(text):
    """Return the eighteenth quotation after the read span, or None when absent."""
    remainders = _remainders(text, READ_MARKER)
    if len(remainders) < 18:
        return None
    return remainders[17]


def kind_read_quote(text):
    """Return the ninth quotation after the read span, or None when absent."""
    remainders = _remainders(text, KIND_READ_MARKER)
    if len(remainders) < 9:
        return None
    return remainders[8]


def kind_edit_quote(text):
    """Return the tenth quotation after the edit span, or None when absent."""
    remainders = _remainders(text, KIND_EDIT_MARKER)
    if len(remainders) < 10:
        return None
    return remainders[9]


def kind_restore_quote(text):
    """Return the twelfth quotation after the restore span, or None when absent."""
    remainders = _remainders(text, KIND_RESTORE_MARKER)
    if len(remainders) < 12:
        return None
    return remainders[11]


def kind_run_quote(text):
    """Return the one quotation after the run span, or None when absent."""
    remainders = _remainders(text, KIND_RUN_MARKER)
    if not remainders:
        return None
    return remainders[0]


def kind_hosted_quote(text):
    """Return the one quotation after the hosted span, or None when absent."""
    remainders = _remainders(text, KIND_HOSTED_MARKER)
    if not remainders:
        return None
    return remainders[0]


def kind_child_quote(text):
    """Return the one quotation after the child span, or None when absent."""
    remainders = _remainders(text, KIND_CHILD_MARKER)
    if not remainders:
        return None
    return remainders[0]


def kind_init_quote(text):
    """Return the one quotation after the init span, or None when absent."""
    remainders = _remainders(text, KIND_INIT_MARKER)
    if not remainders:
        return None
    return remainders[0]


def kind_append_quote(text):
    """Return the one quotation after the append span, or None when absent."""
    remainders = _remainders(text, KIND_APPEND_MARKER)
    if not remainders:
        return None
    return remainders[0]


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


def _launching_quote_refusal(root, text, sha):
    """Return the 8168 refusal, or None when that quote is absent or matches."""
    if text.count(LAUNCHING_MARKER) > 1:
        return "refuse: quoted line is not one line: " + LAUNCHING_SPAN
    quoted = launching_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(LAUNCHING_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + LAUNCHING_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + LAUNCHING_SPAN
    return None


def _asks_quote_refusal(root, text, sha):
    """Return the 8149 refusal, or None when that quote is absent or matches."""
    if text.count(ASKS_MARKER) > 1:
        return "refuse: quoted line is not one line: " + ASKS_SPAN
    quoted = asks_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(ASKS_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + ASKS_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + ASKS_SPAN
    return None


def _deny_quote_refusal(root, text, sha):
    """Return the 3526 refusal, or None when that quote is absent or matches."""
    if text.count(DENY_MARKER) > 1:
        return "refuse: quoted line is not one line: " + DENY_SPAN
    quoted = deny_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(DENY_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + DENY_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + DENY_SPAN
    return None


def _mint_quote_refusal(root, text, sha):
    """Return the 3549 refusal, or None when that quote is absent or matches."""
    if text.count(MINT_MARKER) > 1:
        return "refuse: quoted line is not one line: " + MINT_SPAN
    quoted = mint_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(MINT_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + MINT_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + MINT_SPAN
    return None


def _journal_quote_refusal(root, text, sha):
    """Return the 3757 refusal, or None when that quote is absent or matches."""
    if text.count(JOURNAL_MARKER) > 1:
        return "refuse: quoted line is not one line: " + JOURNAL_SPAN
    quoted = journal_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(JOURNAL_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + JOURNAL_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + JOURNAL_SPAN
    return None


def _grant_quote_refusal(root, text, sha):
    """Return the 3767 refusal, or None when that quote is absent or matches."""
    if text.count(GRANT_MARKER) > 1:
        return "refuse: quoted line is not one line: " + GRANT_SPAN
    quoted = grant_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(GRANT_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + GRANT_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + GRANT_SPAN
    return None


def _write_quote_refusal(root, text, sha):
    """Return the 3849 refusal, or None when that quote is absent or matches."""
    if text.count(WRITE_MARKER) > 1:
        return "refuse: quoted line is not one line: " + WRITE_SPAN
    quoted = write_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(WRITE_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + WRITE_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + WRITE_SPAN
    return None


def _read_quote_refusal(root, text, sha):
    """Return the 3850 refusal, or None when that quote is absent or matches."""
    if text.count(READ_MARKER) > 1:
        return "refuse: quoted line is not one line: " + READ_SPAN
    quoted = read_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(READ_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + READ_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + READ_SPAN
    return None


def _kind_read_quote_refusal(root, text, sha):
    """Return the 8187 refusal, or None when that quote is absent or matches."""
    if text.count(KIND_READ_MARKER) > 1:
        return "refuse: quoted line is not one line: " + KIND_READ_SPAN
    quoted = kind_read_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(KIND_READ_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + KIND_READ_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + KIND_READ_SPAN
    return None


def _kind_edit_quote_refusal(root, text, sha):
    """Return the 8188 refusal, or None when that quote is absent or matches."""
    if text.count(KIND_EDIT_MARKER) > 1:
        return "refuse: quoted line is not one line: " + KIND_EDIT_SPAN
    quoted = kind_edit_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(KIND_EDIT_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + KIND_EDIT_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + KIND_EDIT_SPAN
    return None


def _kind_restore_quote_refusal(root, text, sha):
    """Return the 8190 refusal, or None when that quote is absent or matches."""
    if text.count(KIND_RESTORE_MARKER) > 1:
        return "refuse: quoted line is not one line: " + KIND_RESTORE_SPAN
    quoted = kind_restore_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(KIND_RESTORE_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + KIND_RESTORE_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + KIND_RESTORE_SPAN
    return None


def _kind_run_quote_refusal(root, text, sha):
    """Return the 8189 refusal, or None when that quote is absent or matches."""
    if text.count(KIND_RUN_MARKER) > 1:
        return "refuse: quoted line is not one line: " + KIND_RUN_SPAN
    quoted = kind_run_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(KIND_RUN_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + KIND_RUN_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + KIND_RUN_SPAN
    return None


def _kind_hosted_quote_refusal(root, text, sha):
    """Return the 8191 refusal, or None when that quote is absent or matches."""
    if text.count(KIND_HOSTED_MARKER) > 1:
        return "refuse: quoted line is not one line: " + KIND_HOSTED_SPAN
    quoted = kind_hosted_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(KIND_HOSTED_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + KIND_HOSTED_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + KIND_HOSTED_SPAN
    return None


def _kind_child_quote_refusal(root, text, sha):
    """Return the 8192 refusal, or None when that quote is absent or matches."""
    if text.count(KIND_CHILD_MARKER) > 1:
        return "refuse: quoted line is not one line: " + KIND_CHILD_SPAN
    quoted = kind_child_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(KIND_CHILD_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + KIND_CHILD_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + KIND_CHILD_SPAN
    return None


def _kind_init_quote_refusal(root, text, sha):
    """Return the 8193 refusal, or None when that quote is absent or matches."""
    if text.count(KIND_INIT_MARKER) > 1:
        return "refuse: quoted line is not one line: " + KIND_INIT_SPAN
    quoted = kind_init_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(KIND_INIT_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + KIND_INIT_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + KIND_INIT_SPAN
    return None


def _kind_append_quote_refusal(root, text, sha):
    """Return the 8194 refusal, or None when that quote is absent or matches."""
    if text.count(KIND_APPEND_MARKER) > 1:
        return "refuse: quoted line is not one line: " + KIND_APPEND_SPAN
    quoted = kind_append_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(KIND_APPEND_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + KIND_APPEND_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + KIND_APPEND_SPAN
    return None


def _quote_refusals(root, text, sha):
    """Return the quote refusals in source order: 3526, 3549, 3754, 3755, 3757, 3767, 3849, 3850, 8149, 8162, 8168, 8187, 8188, 8189, 8190, 8191, 8192, 8193, then 8194."""
    deny = _deny_quote_refusal(root, text, sha)
    if deny is not None:
        return [deny]
    mint = _mint_quote_refusal(root, text, sha)
    if mint is not None:
        return [mint]
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
    journal = _journal_quote_refusal(root, text, sha)
    if journal is not None:
        return [journal]
    grant = _grant_quote_refusal(root, text, sha)
    if grant is not None:
        return [grant]
    write = _write_quote_refusal(root, text, sha)
    if write is not None:
        return [write]
    read = _read_quote_refusal(root, text, sha)
    if read is not None:
        return [read]
    asks = _asks_quote_refusal(root, text, sha)
    if asks is not None:
        return [asks]
    marker = _marker_quote_refusal(root, text, sha)
    if marker is not None:
        return [marker]
    launching = _launching_quote_refusal(root, text, sha)
    if launching is not None:
        return [launching]
    kind_read = _kind_read_quote_refusal(root, text, sha)
    if kind_read is not None:
        return [kind_read]
    kind_edit = _kind_edit_quote_refusal(root, text, sha)
    if kind_edit is not None:
        return [kind_edit]
    kind_run = _kind_run_quote_refusal(root, text, sha)
    if kind_run is not None:
        return [kind_run]
    kind_restore = _kind_restore_quote_refusal(root, text, sha)
    if kind_restore is not None:
        return [kind_restore]
    kind_hosted = _kind_hosted_quote_refusal(root, text, sha)
    if kind_hosted is not None:
        return [kind_hosted]
    kind_child = _kind_child_quote_refusal(root, text, sha)
    if kind_child is not None:
        return [kind_child]
    kind_init = _kind_init_quote_refusal(root, text, sha)
    if kind_init is not None:
        return [kind_init]
    kind_append = _kind_append_quote_refusal(root, text, sha)
    if kind_append is None:
        return []
    return [kind_append]


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
