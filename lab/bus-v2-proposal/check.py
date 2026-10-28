"""Refuse a core-calls citation the worktree does not support.

One parser. ``problems`` is the only function that decides a citation.
"""

import bisect
import collections
import functools
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

# Its quotation is the doc line, remainder 0 after the write-body span, source
# line 3961.
BODY_DOC_SPAN = "examples/agent-host/src/lib.rs:3961"
BODY_DOC_MARKER = "`" + BODY_DOC_SPAN + "`"

# Its quotation is the missing-revision arm, remainder 5 after the write-body
# span, source line 3966.
CREATE_ONLY_SPAN = "examples/agent-host/src/lib.rs:3966"
CREATE_ONLY_MARKER = "`" + CREATE_ONLY_SPAN + "`"

# Its quotation is the present-revision arm, remainder 6 after the write-body
# span, source line 3967.
PRESENT_REVISION_SPAN = "examples/agent-host/src/lib.rs:3967"
PRESENT_REVISION_MARKER = "`" + PRESENT_REVISION_SPAN + "`"

# Its quotation is remainder 7 after the condition span, source line 3935.
APPEND_CONDITION_SPAN = "examples/agent-host/src/lib.rs:3935"
APPEND_CONDITION_MARKER = "`" + APPEND_CONDITION_SPAN + "`"

# Its quotation is remainder 8 after the condition span, source line 3936.
HOST_PATH_ERR_SPAN = "examples/agent-host/src/lib.rs:3936"
HOST_PATH_ERR_MARKER = "`" + HOST_PATH_ERR_SPAN + "`"

# Its quotation is remainder 19 after the condition span, source line 3947.
HELD_ERR_SPAN = "examples/agent-host/src/lib.rs:3947"
HELD_ERR_MARKER = "`" + HELD_ERR_SPAN + "`"

# Its quotation is remainder 1 after the append span, source line 4023.
APPEND_CAP_SPAN = "examples/agent-host/src/lib.rs:4023"
APPEND_CAP_MARKER = "`" + APPEND_CAP_SPAN + "`"

# Its quotation is remainder 10 after the append range span, source line 4032.
APPEND_CALL_SPAN = "examples/agent-host/src/lib.rs:4032"

# The one range span holds the call line and the held return. It names the
# one-line arm of both decisions and is never a target for ``_span_target``.
APPEND_RANGE_SPAN = "examples/agent-host/src/lib.rs:4032-4033"
APPEND_RANGE_MARKER = "`" + APPEND_RANGE_SPAN + "`"

# Its quotation is remainder 11 after the append range span, source line 4033.
OUTCOME_HELD_SPAN = "examples/agent-host/src/lib.rs:4033"

# Its quotation is remainder 13 after the invoke span, source line 4061.
WRITE_INVOKE_SPAN = "examples/agent-host/src/lib.rs:4061"
WRITE_INVOKE_MARKER = "`" + WRITE_INVOKE_SPAN + "`"

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

# Its quotation is remainder 4 after the observe span, source line 2067.
OBSERVE_SPAN = "examples/agent-host/src/lib.rs:2067"
OBSERVE_MARKER = "`" + OBSERVE_SPAN + "`"

# Its quotation is remainder 7 after the request span, source line 2741.
REVISION_SPAN = "examples/agent-host/src/lib.rs:2741"
REVISION_MARKER = "`" + REVISION_SPAN + "`"

# Its quotation is remainder 15 after the request span, source line 2749.
OP_SPAN = "examples/agent-host/src/lib.rs:2749"
OP_MARKER = "`" + OP_SPAN + "`"

# Its quotation is the no-process remainder, remainder 1 after the run span,
# source line 2958.
NO_PROCESS_SPAN = "examples/agent-host/src/lib.rs:2958"
NO_PROCESS_MARKER = "`" + NO_PROCESS_SPAN + "`"

# Its quotation is the seat line, remainder 24 after the run span, source line
# 2981.
SEAT_SPAN = "examples/agent-host/src/lib.rs:2981"
SEAT_MARKER = "`" + SEAT_SPAN + "`"

# Its quotation is remainder 4 after the restore span, source line 3308.
NO_WRITE_SPAN = "examples/agent-host/src/lib.rs:3308"
NO_WRITE_MARKER = "`" + NO_WRITE_SPAN + "`"

# Its quotation is remainder 1 after the hosted span, source line 3339.
NO_PROVIDER_SPAN = "examples/agent-host/src/lib.rs:3339"
NO_PROVIDER_MARKER = "`" + NO_PROVIDER_SPAN + "`"

# Its quotation is remainder 1 after the child span, source line 3360.
CHILD_SPAN = "examples/agent-host/src/lib.rs:3360"
CHILD_MARKER = "`" + CHILD_SPAN + "`"

# Its quotation is remainder 11 after the child span, source line 3370.
NARROWER_SPAN = "examples/agent-host/src/lib.rs:3370"
NARROWER_MARKER = "`" + NARROWER_SPAN + "`"

# Its quotation is remainder 23 after the child span, source line 3382.
CHILD_GRANT_NONE_SPAN = "examples/agent-host/src/lib.rs:3382"
CHILD_GRANT_NONE_MARKER = "`" + CHILD_GRANT_NONE_SPAN + "`"

# Its quotation is remainder 1 after the project span, source line 3387.
PROJECT_SPAN = "examples/agent-host/src/lib.rs:3387"
PROJECT_MARKER = "`" + PROJECT_SPAN + "`"

# Its quotation is remainder 17 after the project span, source line 3403.
PROJECT_RESOURCE_SPAN = "examples/agent-host/src/lib.rs:3403"
PROJECT_RESOURCE_MARKER = "`" + PROJECT_RESOURCE_SPAN + "`"

# Its quotation is remainder 17 after the authorize span, source line 3449.
AUTHORIZE_SPAN = "examples/agent-host/src/lib.rs:3449"
AUTHORIZE_MARKER = "`" + AUTHORIZE_SPAN + "`"

# Its quotation is the child-host doc line, remainder 0 after the child host
# span, source line 3455.
CHILD_HOST_DOC_SPAN = "examples/agent-host/src/lib.rs:3455"
CHILD_HOST_DOC_MARKER = "`" + CHILD_HOST_DOC_SPAN + "`"

# Its quotation is the empty-journal line, remainder 15 after the empty-journal
# span, source line 3470.
EMPTY_JOURNAL_SPAN = "examples/agent-host/src/lib.rs:3470"
EMPTY_JOURNAL_MARKER = "`" + EMPTY_JOURNAL_SPAN + "`"

# Its quotation is the admit-system line, remainder 16 after the admit-system
# span, source line 3471.
ADMIT_SYSTEM_SPAN = "examples/agent-host/src/lib.rs:3471"
ADMIT_SYSTEM_MARKER = "`" + ADMIT_SYSTEM_SPAN + "`"

# Its quotation is the inherited arm, remainder 1 after the inherited span,
# source line 3474.
INHERITED_ERR_SPAN = "examples/agent-host/src/lib.rs:3474"
INHERITED_ERR_MARKER = "`" + INHERITED_ERR_SPAN + "`"

# Its quotation is the parent-grant arm, remainder 3 after the grant span,
# source line 3482.
GRANT_PARENT_SPAN = "examples/agent-host/src/lib.rs:3482"
GRANT_PARENT_MARKER = "`" + GRANT_PARENT_SPAN + "`"

# Its quotation is remainder 5 after the declaration span, source line 8488.
COVER_SPAN = "examples/agent-host/src/lib.rs:8488"
COVER_MARKER = "`" + COVER_SPAN + "`"

# Its quotation is remainder 4 after the edit range span, source line 2421.
EDIT_RANGE_SPAN = "examples/agent-host/src/lib.rs:2421-2422"
EDIT_RANGE_MARKER = "`" + EDIT_RANGE_SPAN + "`"
EDIT_START_SPAN = "examples/agent-host/src/lib.rs:2421"
EDIT_END_SPAN = "examples/agent-host/src/lib.rs:2422"

# Its quotation is remainder 0 after the request span, source line 2720.
REQUEST_SPAN = "examples/agent-host/src/lib.rs:2720"
REQUEST_MARKER = "`" + REQUEST_SPAN + "`"

# Its quotation is remainder 2 after the is-write span, source line 3290.
IS_WRITE_SPAN = "examples/agent-host/src/lib.rs:3290"
IS_WRITE_MARKER = "`" + IS_WRITE_SPAN + "`"

# Its quotation is remainder 8 after the scheme span, source line 123.
SCHEME_SPAN = "elastos/crates/elastos-server/src/provider_resource.rs:123"
SCHEME_MARKER = "`" + SCHEME_SPAN + "`"

# Its quotation is the one remainder after the read-action span, source line 189.
READ_ACTION_SPAN = "elastos/crates/elastos-server/src/provider_resource.rs:189"
READ_ACTION_MARKER = "`" + READ_ACTION_SPAN + "`"

# Its quotation is remainder 3 after the write-action span, source line 190.
WRITE_ACTION_SPAN = "elastos/crates/elastos-server/src/provider_resource.rs:190"
WRITE_ACTION_MARKER = "`" + WRITE_ACTION_SPAN + "`"

# Its quotation is remainder 5 after the write-action walk, source line 192.
DEFAULT_ACTION_SPAN = "elastos/crates/elastos-server/src/provider_resource.rs:192"
DEFAULT_ACTION_MARKER = "`" + DEFAULT_ACTION_SPAN + "`"

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


@functools.lru_cache(maxsize=32)
def _pinned_lines(root, sha, rel):
    """Return (number, line) for each non-empty line of REL at commit SHA.

    The number is the source line number of that line, so every pair keeps the
    number the draft cites and a window counts through the same numbers. A
    missing commit, missing file or non-UTF-8 file gives ().
    """
    if sha is None:
        return ()
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "show", sha + ":" + rel],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return ()
    if result.returncode != 0:
        return ()
    try:
        text = decode_text(result.stdout)
    except UnicodeDecodeError:
        return ()
    return tuple(
        (number, line)
        for number, line in enumerate(text.splitlines(), start=1)
        if line.strip()
    )


def _quote_window(remainders, pinned_lines, number):
    """Return the window of PINNED_LINES that stands for NUMBER, or None.

    A window is ``len(remainders)`` consecutive non-empty pinned lines that
    contain NUMBER, so a window that starts more than that width before NUMBER
    or after it is not scored. The score is how many of its lines equal the
    remainder in the same position, and a score of 0 is still a score. The
    highest score wins, and a tie keeps the smallest start line.
    """
    width = len(remainders)
    if width == 0:
        return None
    first = bisect.bisect_left(pinned_lines, (number,))
    if first >= len(pinned_lines) or pinned_lines[first][0] != number:
        return None
    best = None
    best_score = -1
    for start in range(max(0, first - width + 1), first + 1):
        window = pinned_lines[start:start + width]
        if len(window) < width:
            continue
        score = sum(
            1 for offset, row in enumerate(window) if remainders[offset] == row[1]
        )
        if score > best_score:
            best = window
            best_score = score
    return best


def quote_for(remainders, pinned_lines, number):
    """Return the remainder that stands for NUMBER, or None when none does.

    The index is how many non-empty lines of that window stand before NUMBER.
    None means the walk has no remainder, or the pinned file has no window of
    that width that contains NUMBER. A zero score still returns that index.
    """
    window = _quote_window(remainders, pinned_lines, number)
    if window is None:
        return None
    return remainders[sum(1 for row in window if row[0] < number)]


@functools.lru_cache(maxsize=64)
def _draft_lines(rel):
    """Return the pinned (number, line) of REL at this worktree's draft pin.

    The helper functions keep the one-argument signature the tests call and
    read the pin of the draft in this worktree, so a fixture draft is compared
    against the same worktree commit the checker reads.
    """
    text = load_draft(worktree_root())
    if text is None:
        return ()
    return _pinned_lines(str(worktree_root()), pin_sha(text), rel)


def _quote_for_span(text, marker, span):
    """Return the remainder that stands for SPAN, or None when none does."""
    rel, number = _span_target(span)
    return quote_for(_remainders(text, marker), _draft_lines(rel), number)


def owned_quote(text):
    """Return the remainder that stands for line 3754, or None."""
    return _quote_for_span(text, OWNED_MARKER, OWNED_SPAN)


def next_owned_quote(text):
    """Return the remainder that stands for line 3755, or None."""
    return _quote_for_span(text, OWNED_MARKER, NEXT_SPAN)


def marker_quote(text):
    """Return the remainder that stands for line 8162, or None."""
    return _quote_for_span(text, MARKER_MARKER, MARKER_SPAN)


def launching_quote(text):
    """Return the remainder that stands for line 8168, or None."""
    return _quote_for_span(text, LAUNCHING_MARKER, LAUNCHING_SPAN)


def asks_quote(text):
    """Return the remainder that stands for line 8149, or None."""
    return _quote_for_span(text, ASKS_MARKER, ASKS_SPAN)


def deny_quote(text):
    """Return the remainder that stands for line 3526, or None."""
    return _quote_for_span(text, DENY_MARKER, DENY_SPAN)


def mint_quote(text):
    """Return the remainder that stands for line 3549, or None."""
    return _quote_for_span(text, MINT_MARKER, MINT_SPAN)


def journal_quote(text):
    """Return the remainder that stands for line 3757, or None."""
    return _quote_for_span(text, JOURNAL_MARKER, JOURNAL_SPAN)


def grant_quote(text):
    """Return the remainder that stands for line 3767, or None."""
    return _quote_for_span(text, GRANT_MARKER, GRANT_SPAN)


def write_quote(text):
    """Return the remainder that stands for line 3849, or None."""
    return _quote_for_span(text, WRITE_MARKER, WRITE_SPAN)


def read_quote(text):
    """Return the remainder that stands for line 3850, or None."""
    return _quote_for_span(text, READ_MARKER, READ_SPAN)


def body_doc_quote(text):
    """Return the remainder that stands for line 3961, or None."""
    return _quote_for_span(text, BODY_DOC_MARKER, BODY_DOC_SPAN)


def create_only_quote(text):
    """Return the remainder that stands for line 3966, or None."""
    return _quote_for_span(text, CREATE_ONLY_MARKER, CREATE_ONLY_SPAN)


def present_revision_quote(text):
    """Return the remainder that stands for line 3967, or None."""
    return _quote_for_span(text, PRESENT_REVISION_MARKER, PRESENT_REVISION_SPAN)


def append_condition_quote(text):
    """Return the remainder that stands for line 3935, or None."""
    return _quote_for_span(text, APPEND_CONDITION_MARKER, APPEND_CONDITION_SPAN)


def host_path_err_quote(text):
    """Return the remainder that stands for line 3936, or None."""
    return _quote_for_span(text, HOST_PATH_ERR_MARKER, HOST_PATH_ERR_SPAN)


def held_err_quote(text):
    """Return the remainder that stands for line 3947, or None."""
    return _quote_for_span(text, HELD_ERR_MARKER, HELD_ERR_SPAN)


def append_cap_quote(text):
    """Return the remainder that stands for line 4023, or None."""
    return _quote_for_span(text, APPEND_CAP_MARKER, APPEND_CAP_SPAN)


def append_call_quote(text):
    """Return the remainder that stands for line 4032, or None."""
    return _quote_for_span(text, APPEND_RANGE_MARKER, APPEND_CALL_SPAN)


def outcome_held_quote(text):
    """Return the remainder that stands for line 4033, or None."""
    return _quote_for_span(text, APPEND_RANGE_MARKER, OUTCOME_HELD_SPAN)


def write_invoke_quote(text):
    """Return the remainder that stands for line 4061, or None."""
    return _quote_for_span(text, WRITE_INVOKE_MARKER, WRITE_INVOKE_SPAN)


def kind_read_quote(text):
    """Return the remainder that stands for line 8187, or None."""
    return _quote_for_span(text, KIND_READ_MARKER, KIND_READ_SPAN)


def kind_edit_quote(text):
    """Return the remainder that stands for line 8188, or None."""
    return _quote_for_span(text, KIND_EDIT_MARKER, KIND_EDIT_SPAN)


def kind_restore_quote(text):
    """Return the remainder that stands for line 8190, or None."""
    return _quote_for_span(text, KIND_RESTORE_MARKER, KIND_RESTORE_SPAN)


def kind_run_quote(text):
    """Return the remainder that stands for line 8189, or None."""
    return _quote_for_span(text, KIND_RUN_MARKER, KIND_RUN_SPAN)


def kind_hosted_quote(text):
    """Return the remainder that stands for line 8191, or None."""
    return _quote_for_span(text, KIND_HOSTED_MARKER, KIND_HOSTED_SPAN)


def kind_child_quote(text):
    """Return the remainder that stands for line 8192, or None."""
    return _quote_for_span(text, KIND_CHILD_MARKER, KIND_CHILD_SPAN)


def kind_init_quote(text):
    """Return the remainder that stands for line 8193, or None."""
    return _quote_for_span(text, KIND_INIT_MARKER, KIND_INIT_SPAN)


def kind_append_quote(text):
    """Return the remainder that stands for line 8194, or None."""
    return _quote_for_span(text, KIND_APPEND_MARKER, KIND_APPEND_SPAN)


def observe_quote(text):
    """Return the remainder that stands for line 2067, or None."""
    return _quote_for_span(text, OBSERVE_MARKER, OBSERVE_SPAN)


def revision_quote(text):
    """Return the remainder that stands for line 2741, or None."""
    return _quote_for_span(text, REVISION_MARKER, REVISION_SPAN)


def op_quote(text):
    """Return the remainder that stands for line 2749, or None."""
    return _quote_for_span(text, OP_MARKER, OP_SPAN)


def no_process_quote(text):
    """Return the remainder that stands for line 2958, or None."""
    return _quote_for_span(text, NO_PROCESS_MARKER, NO_PROCESS_SPAN)


def seat_quote(text):
    """Return the remainder that stands for line 2981, or None."""
    return _quote_for_span(text, SEAT_MARKER, SEAT_SPAN)


def no_write_quote(text):
    """Return the remainder that stands for line 3308, or None."""
    return _quote_for_span(text, NO_WRITE_MARKER, NO_WRITE_SPAN)


def no_provider_quote(text):
    """Return the remainder that stands for line 3339, or None."""
    return _quote_for_span(text, NO_PROVIDER_MARKER, NO_PROVIDER_SPAN)


def parent_grant_doc_quote(text):
    """Return the remainder that stands for line 3360, or None."""
    return _quote_for_span(text, CHILD_MARKER, CHILD_SPAN)


def narrower_quote(text):
    """Return the remainder that stands for line 3370, or None."""
    return _quote_for_span(text, NARROWER_MARKER, NARROWER_SPAN)


def child_grant_none_quote(text):
    """Return the remainder that stands for line 3382, or None."""
    return _quote_for_span(text, CHILD_GRANT_NONE_MARKER, CHILD_GRANT_NONE_SPAN)


def init_guard_quote(text):
    """Return the remainder that stands for line 3387, or None."""
    return _quote_for_span(text, PROJECT_MARKER, PROJECT_SPAN)


def project_resource_quote(text):
    """Return the remainder that stands for line 3403, or None."""
    return _quote_for_span(text, PROJECT_RESOURCE_MARKER, PROJECT_RESOURCE_SPAN)


def parent_compare_quote(text):
    """Return the remainder that stands for line 3449, or None."""
    return _quote_for_span(text, AUTHORIZE_MARKER, AUTHORIZE_SPAN)


def child_host_doc_quote(text):
    """Return the remainder that stands for line 3455, or None."""
    return _quote_for_span(text, CHILD_HOST_DOC_MARKER, CHILD_HOST_DOC_SPAN)


def empty_journal_quote(text):
    """Return the remainder that stands for line 3470, or None."""
    return _quote_for_span(text, EMPTY_JOURNAL_MARKER, EMPTY_JOURNAL_SPAN)


def admit_system_quote(text):
    """Return the remainder that stands for line 3471, or None."""
    return _quote_for_span(text, ADMIT_SYSTEM_MARKER, ADMIT_SYSTEM_SPAN)


def inherited_err_quote(text):
    """Return the remainder that stands for line 3474, or None."""
    return _quote_for_span(text, INHERITED_ERR_MARKER, INHERITED_ERR_SPAN)


def grant_parent_quote(text):
    """Return the remainder that stands for line 3482, or None."""
    return _quote_for_span(text, GRANT_PARENT_MARKER, GRANT_PARENT_SPAN)


def cover_quote(text):
    """Return the remainder that stands for line 8488, or None."""
    return _quote_for_span(text, COVER_MARKER, COVER_SPAN)


def edit_start_quote(text):
    """Return the remainder that stands for line 2421, or None."""
    return _quote_for_span(text, EDIT_RANGE_MARKER, EDIT_START_SPAN)


def edit_end_quote(text):
    """Return the remainder that stands for line 2422, or None."""
    return _quote_for_span(text, EDIT_RANGE_MARKER, EDIT_END_SPAN)


def request_quote(text):
    """Return the remainder that stands for line 2720, or None."""
    return _quote_for_span(text, REQUEST_MARKER, REQUEST_SPAN)


def is_write_quote(text):
    """Return the remainder that stands for line 3290, or None."""
    return _quote_for_span(text, IS_WRITE_MARKER, IS_WRITE_SPAN)


def scheme_quote(text):
    """Return the remainder that stands for line provider_resource.rs 123, or None."""
    return _quote_for_span(text, SCHEME_MARKER, SCHEME_SPAN)


def read_action_quote(text):
    """Return the remainder that stands for line provider_resource.rs 189, or None."""
    return _quote_for_span(text, READ_ACTION_MARKER, READ_ACTION_SPAN)


def write_action_quote(text):
    """Return the remainder that stands for line provider_resource.rs 190, or None."""
    return _quote_for_span(text, WRITE_ACTION_MARKER, WRITE_ACTION_SPAN)


def default_action_quote(text):
    """Return the remainder that stands for line provider_resource.rs 192, or None."""
    return _quote_for_span(text, DEFAULT_ACTION_MARKER, DEFAULT_ACTION_SPAN)


def quoted_line_matches(quoted, source):
    """True only when the quotation equals the pinned source line."""
    return quoted == source


QuoteTarget = collections.namedtuple(
    "QuoteTarget", "path number marker span quote"
)

# Every line citation a quotation is decided for, in source order. This is the
# one target list: a range's two endpoints are two entries that share a marker.
QUOTE_TARGETS = (
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 2067, OBSERVE_MARKER, OBSERVE_SPAN, "observe_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 2421, EDIT_RANGE_MARKER, EDIT_START_SPAN, "edit_start_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 2422, EDIT_RANGE_MARKER, EDIT_END_SPAN, "edit_end_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 2720, REQUEST_MARKER, REQUEST_SPAN, "request_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 2741, REVISION_MARKER, REVISION_SPAN, "revision_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 2749, OP_MARKER, OP_SPAN, "op_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 2958, NO_PROCESS_MARKER, NO_PROCESS_SPAN, "no_process_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 2981, SEAT_MARKER, SEAT_SPAN, "seat_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3290, IS_WRITE_MARKER, IS_WRITE_SPAN, "is_write_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3308, NO_WRITE_MARKER, NO_WRITE_SPAN, "no_write_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3339, NO_PROVIDER_MARKER, NO_PROVIDER_SPAN, "no_provider_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3360, CHILD_MARKER, CHILD_SPAN, "parent_grant_doc_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3370, NARROWER_MARKER, NARROWER_SPAN, "narrower_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3382, CHILD_GRANT_NONE_MARKER, CHILD_GRANT_NONE_SPAN, "child_grant_none_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3387, PROJECT_MARKER, PROJECT_SPAN, "init_guard_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3403, PROJECT_RESOURCE_MARKER, PROJECT_RESOURCE_SPAN, "project_resource_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3449, AUTHORIZE_MARKER, AUTHORIZE_SPAN, "parent_compare_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3455, CHILD_HOST_DOC_MARKER, CHILD_HOST_DOC_SPAN, "child_host_doc_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3470, EMPTY_JOURNAL_MARKER, EMPTY_JOURNAL_SPAN, "empty_journal_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3471, ADMIT_SYSTEM_MARKER, ADMIT_SYSTEM_SPAN, "admit_system_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3474, INHERITED_ERR_MARKER, INHERITED_ERR_SPAN, "inherited_err_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3482, GRANT_PARENT_MARKER, GRANT_PARENT_SPAN, "grant_parent_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3526, DENY_MARKER, DENY_SPAN, "deny_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3549, MINT_MARKER, MINT_SPAN, "mint_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3754, OWNED_MARKER, OWNED_SPAN, "owned_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3755, OWNED_MARKER, NEXT_SPAN, "next_owned_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3757, JOURNAL_MARKER, JOURNAL_SPAN, "journal_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3767, GRANT_MARKER, GRANT_SPAN, "grant_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3849, WRITE_MARKER, WRITE_SPAN, "write_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3850, READ_MARKER, READ_SPAN, "read_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3935, APPEND_CONDITION_MARKER, APPEND_CONDITION_SPAN, "append_condition_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3936, HOST_PATH_ERR_MARKER, HOST_PATH_ERR_SPAN, "host_path_err_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3947, HELD_ERR_MARKER, HELD_ERR_SPAN, "held_err_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3961, BODY_DOC_MARKER, BODY_DOC_SPAN, "body_doc_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3966, CREATE_ONLY_MARKER, CREATE_ONLY_SPAN, "create_only_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 3967, PRESENT_REVISION_MARKER, PRESENT_REVISION_SPAN, "present_revision_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 4023, APPEND_CAP_MARKER, APPEND_CAP_SPAN, "append_cap_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 4032, APPEND_RANGE_MARKER, APPEND_CALL_SPAN, "append_call_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 4033, APPEND_RANGE_MARKER, OUTCOME_HELD_SPAN, "outcome_held_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 4061, WRITE_INVOKE_MARKER, WRITE_INVOKE_SPAN, "write_invoke_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 8149, ASKS_MARKER, ASKS_SPAN, "asks_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 8162, MARKER_MARKER, MARKER_SPAN, "marker_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 8168, LAUNCHING_MARKER, LAUNCHING_SPAN, "launching_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 8187, KIND_READ_MARKER, KIND_READ_SPAN, "kind_read_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 8188, KIND_EDIT_MARKER, KIND_EDIT_SPAN, "kind_edit_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 8189, KIND_RUN_MARKER, KIND_RUN_SPAN, "kind_run_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 8190, KIND_RESTORE_MARKER, KIND_RESTORE_SPAN, "kind_restore_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 8191, KIND_HOSTED_MARKER, KIND_HOSTED_SPAN, "kind_hosted_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 8192, KIND_CHILD_MARKER, KIND_CHILD_SPAN, "kind_child_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 8193, KIND_INIT_MARKER, KIND_INIT_SPAN, "kind_init_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 8194, KIND_APPEND_MARKER, KIND_APPEND_SPAN, "kind_append_quote"
    ),
    QuoteTarget(
        "examples/agent-host/src/lib.rs", 8488, COVER_MARKER, COVER_SPAN, "cover_quote"
    ),
    QuoteTarget(
        "elastos/crates/elastos-server/src/provider_resource.rs", 123, SCHEME_MARKER, SCHEME_SPAN, "scheme_quote"
    ),
    QuoteTarget(
        "elastos/crates/elastos-server/src/provider_resource.rs", 189, READ_ACTION_MARKER, READ_ACTION_SPAN, "read_action_quote"
    ),
    QuoteTarget(
        "elastos/crates/elastos-server/src/provider_resource.rs", 190, WRITE_ACTION_MARKER, WRITE_ACTION_SPAN, "write_action_quote"
    ),
    QuoteTarget(
        "elastos/crates/elastos-server/src/provider_resource.rs", 192, DEFAULT_ACTION_MARKER, DEFAULT_ACTION_SPAN, "default_action_quote"
    ),
)


def _span_text(marker):
    """Return the citation text inside MARKER, without the backticks."""
    return marker[1:-1]


def _quote_of(target, text):
    """Return TARGET's remainder for TEXT, or None when the walk has none.

    The helper is looked up by name so that a planted helper replaces the one
    the loop calls, which is how the falsifiers reach the production path.
    """
    return globals()[target.quote](text)


def _quote_refusals(root, text, sha):
    """Return the quote refusals in source order: 2067, 2421, 2422, 2720, 2741, 2749, 2958, 2981, 3290, 3308, 3339, 3360, 3370, 3382, 3387, 3403, 3449, 3455, 3470, 3471, 3474, 3482, 3526, 3549, 3754, 3755, 3757, 3767, 3849, 3850, 3935, 3936, 3947, 3961, 3966, 3967, 4023, 4032, 4033, 4061, 8149, 8162, 8168, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8488, then 123, 189, 190, 192."""
    for target in QUOTE_TARGETS:
        if text.count(target.marker) > 1:
            return ["refuse: quoted line is not one line: " + _span_text(target.marker)]
        if not _remainders(text, target.marker):
            continue
        quoted = _quote_of(target, text)
        source = pinned_line(root, sha, target.path, target.number)
        if quoted is None or source is None:
            return ["refuse: quoted line is not in the pinned commit: " + target.span]
        if not quoted_line_matches(quoted, source):
            return ["refuse: quoted line does not match " + target.span]
    return []


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
