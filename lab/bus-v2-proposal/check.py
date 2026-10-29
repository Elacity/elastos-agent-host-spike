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


def _pinned_lines(root, sha, rel):
    """Return every line of REL at commit SHA, or None when it is absent."""
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
    return text.splitlines()


def pinned_line(root, sha, rel, number):
    """Return line NUMBER of REL at commit SHA, or None when it is absent."""
    lines = _pinned_lines(root, sha, rel)
    if lines is None or number < 1 or number > len(lines):
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


def _quote_window(remainders, pinned_lines, number):
    """Return the index inside the best window that holds NUMBER, or None.

    A window is ``len(remainders)`` consecutive non-empty pinned lines. Only a
    window that holds NUMBER is scored, so a match elsewhere in the file cannot
    hide the cited line. The score is the count of remainders that equal their
    pinned line, and it may be 0. A tie keeps the smallest start line. The
    index is how many non-empty lines of the window stand before NUMBER.
    """
    nonempty = [(line, text) for line, text in enumerate(pinned_lines, 1) if text]
    width = len(remainders)
    if not width or width > len(nonempty):
        return None
    best = None
    best_score = None
    for start in range(len(nonempty) - width + 1):
        window = nonempty[start:start + width]
        if not any(line == number for line, _ in window):
            continue
        score = sum(
            1
            for offset, (_, text) in enumerate(window)
            if quoted_line_matches(remainders[offset], text)
        )
        if best_score is None or score > best_score:
            best = start
            best_score = score
    if best is None:
        return None
    return sum(1 for line, _ in nonempty[best:best + width] if line < number)


def quote_for(remainders, pinned_lines, number):
    """Return the remainder that stands for line NUMBER, or None when none does."""
    if not remainders or pinned_lines is None:
        return None
    index = _quote_window(remainders, pinned_lines, number)
    if index is None:
        return None
    return remainders[index]


def _pin_of(text, root):
    """Return the pin SHA for TEXT, or the worktree draft pin when it has none."""
    sha = pin_sha(text)
    if sha is not None:
        return sha
    draft = load_draft(root)
    if draft is None:
        return None
    return pin_sha(draft)


def _pinned_quote(text, span, marker, root=None, sha=None, pinned=None):
    """Return the remainder that stands for SPAN, or None when none stands.

    PINNED is the pinned file's lines when the caller already read them.
    Otherwise this reads them through ``_pinned_lines`` at the draft pin, or at
    the worktree draft pin when TEXT carries none.
    """
    remainders = _remainders(text, marker)
    if not remainders:
        return None
    rel, number = _span_target(span)
    if pinned is None:
        if root is None:
            root = worktree_root()
        if sha is None:
            sha = _pin_of(text, root)
        pinned = _pinned_lines(root, sha, rel)
    return quote_for(remainders, pinned, number)


def owned_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the owned span, or None when absent."""
    return _pinned_quote(text, OWNED_SPAN, OWNED_MARKER, root, sha, pinned)


def next_owned_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the next owned span, or None."""
    return _pinned_quote(text, NEXT_SPAN, OWNED_MARKER, root, sha, pinned)


def marker_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the marker span, or None."""
    return _pinned_quote(text, MARKER_SPAN, MARKER_MARKER, root, sha, pinned)


def launching_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the launching span, or None."""
    return _pinned_quote(text, LAUNCHING_SPAN, LAUNCHING_MARKER, root, sha, pinned)


def asks_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the asks span, or None."""
    return _pinned_quote(text, ASKS_SPAN, ASKS_MARKER, root, sha, pinned)


def deny_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the deny span, or None."""
    return _pinned_quote(text, DENY_SPAN, DENY_MARKER, root, sha, pinned)


def mint_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the mint span, or None."""
    return _pinned_quote(text, MINT_SPAN, MINT_MARKER, root, sha, pinned)


def journal_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the journal span, or None."""
    return _pinned_quote(text, JOURNAL_SPAN, JOURNAL_MARKER, root, sha, pinned)


def grant_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the grant span, or None."""
    return _pinned_quote(text, GRANT_SPAN, GRANT_MARKER, root, sha, pinned)


def write_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the write span, or None."""
    return _pinned_quote(text, WRITE_SPAN, WRITE_MARKER, root, sha, pinned)


def read_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the read span, or None."""
    return _pinned_quote(text, READ_SPAN, READ_MARKER, root, sha, pinned)


def body_doc_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the body-doc span, or None."""
    return _pinned_quote(text, BODY_DOC_SPAN, BODY_DOC_MARKER, root, sha, pinned)


def create_only_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the create-only span, or None."""
    return _pinned_quote(text, CREATE_ONLY_SPAN, CREATE_ONLY_MARKER, root, sha, pinned)


def present_revision_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the present-revision span, or None."""
    return _pinned_quote(text, PRESENT_REVISION_SPAN, PRESENT_REVISION_MARKER, root, sha, pinned)


def append_condition_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the condition span, or None."""
    return _pinned_quote(text, APPEND_CONDITION_SPAN, APPEND_CONDITION_MARKER, root, sha, pinned)


def host_path_err_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the host-path span, or None."""
    return _pinned_quote(text, HOST_PATH_ERR_SPAN, HOST_PATH_ERR_MARKER, root, sha, pinned)


def held_err_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the held span, or None."""
    return _pinned_quote(text, HELD_ERR_SPAN, HELD_ERR_MARKER, root, sha, pinned)


def append_cap_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the cap span, or None."""
    return _pinned_quote(text, APPEND_CAP_SPAN, APPEND_CAP_MARKER, root, sha, pinned)


def append_call_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the call line, or None."""
    return _pinned_quote(text, APPEND_CALL_SPAN, APPEND_RANGE_MARKER, root, sha, pinned)


def outcome_held_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the held line, or None."""
    return _pinned_quote(text, OUTCOME_HELD_SPAN, APPEND_RANGE_MARKER, root, sha, pinned)


def write_invoke_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the invoke span, or None."""
    return _pinned_quote(text, WRITE_INVOKE_SPAN, WRITE_INVOKE_MARKER, root, sha, pinned)


def kind_read_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the Read arm, or None."""
    return _pinned_quote(text, KIND_READ_SPAN, KIND_READ_MARKER, root, sha, pinned)


def kind_edit_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the Edit arm, or None."""
    return _pinned_quote(text, KIND_EDIT_SPAN, KIND_EDIT_MARKER, root, sha, pinned)


def kind_restore_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the Restore arm, or None."""
    return _pinned_quote(text, KIND_RESTORE_SPAN, KIND_RESTORE_MARKER, root, sha, pinned)


def kind_run_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the Run arm, or None."""
    return _pinned_quote(text, KIND_RUN_SPAN, KIND_RUN_MARKER, root, sha, pinned)


def kind_hosted_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the Hosted arm, or None."""
    return _pinned_quote(text, KIND_HOSTED_SPAN, KIND_HOSTED_MARKER, root, sha, pinned)


def kind_child_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the Child arm, or None."""
    return _pinned_quote(text, KIND_CHILD_SPAN, KIND_CHILD_MARKER, root, sha, pinned)


def kind_init_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the Init arm, or None."""
    return _pinned_quote(text, KIND_INIT_SPAN, KIND_INIT_MARKER, root, sha, pinned)


def kind_append_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the JournalAppend arm, or None."""
    return _pinned_quote(text, KIND_APPEND_SPAN, KIND_APPEND_MARKER, root, sha, pinned)


def observe_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the observe span, or None."""
    return _pinned_quote(text, OBSERVE_SPAN, OBSERVE_MARKER, root, sha, pinned)


def revision_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the revision span, or None."""
    return _pinned_quote(text, REVISION_SPAN, REVISION_MARKER, root, sha, pinned)


def op_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the op span, or None."""
    return _pinned_quote(text, OP_SPAN, OP_MARKER, root, sha, pinned)


def no_process_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the no-process span, or None."""
    return _pinned_quote(text, NO_PROCESS_SPAN, NO_PROCESS_MARKER, root, sha, pinned)


def seat_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the seat span, or None."""
    return _pinned_quote(text, SEAT_SPAN, SEAT_MARKER, root, sha, pinned)


def no_write_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the no-write span, or None."""
    return _pinned_quote(text, NO_WRITE_SPAN, NO_WRITE_MARKER, root, sha, pinned)


def no_provider_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the no-provider span, or None."""
    return _pinned_quote(text, NO_PROVIDER_SPAN, NO_PROVIDER_MARKER, root, sha, pinned)


def parent_grant_doc_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the parent-grant doc, or None."""
    return _pinned_quote(text, CHILD_SPAN, CHILD_MARKER, root, sha, pinned)


def narrower_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the narrower call, or None."""
    return _pinned_quote(text, NARROWER_SPAN, NARROWER_MARKER, root, sha, pinned)


def child_grant_none_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the cleared grant, or None."""
    return _pinned_quote(text, CHILD_GRANT_NONE_SPAN, CHILD_GRANT_NONE_MARKER, root, sha, pinned)


def init_guard_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the host-path guard, or None."""
    return _pinned_quote(text, PROJECT_SPAN, PROJECT_MARKER, root, sha, pinned)


def project_resource_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the project resource, or None."""
    return _pinned_quote(text, PROJECT_RESOURCE_SPAN, PROJECT_RESOURCE_MARKER, root, sha, pinned)


def parent_compare_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the parent-grant compare, or None."""
    return _pinned_quote(text, AUTHORIZE_SPAN, AUTHORIZE_MARKER, root, sha, pinned)


def child_host_doc_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the child-host doc, or None."""
    return _pinned_quote(text, CHILD_HOST_DOC_SPAN, CHILD_HOST_DOC_MARKER, root, sha, pinned)


def empty_journal_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the empty-journal line, or None."""
    return _pinned_quote(text, EMPTY_JOURNAL_SPAN, EMPTY_JOURNAL_MARKER, root, sha, pinned)


def admit_system_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the admit-system line, or None."""
    return _pinned_quote(text, ADMIT_SYSTEM_SPAN, ADMIT_SYSTEM_MARKER, root, sha, pinned)


def inherited_err_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the inherited arm, or None."""
    return _pinned_quote(text, INHERITED_ERR_SPAN, INHERITED_ERR_MARKER, root, sha, pinned)


def grant_parent_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the grant-parent arm, or None."""
    return _pinned_quote(text, GRANT_PARENT_SPAN, GRANT_PARENT_MARKER, root, sha, pinned)


def cover_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the cover span, or None."""
    return _pinned_quote(text, COVER_SPAN, COVER_MARKER, root, sha, pinned)


def edit_start_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the range start, or None."""
    return _pinned_quote(text, EDIT_START_SPAN, EDIT_RANGE_MARKER, root, sha, pinned)


def edit_end_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the range end, or None."""
    return _pinned_quote(text, EDIT_END_SPAN, EDIT_RANGE_MARKER, root, sha, pinned)


def request_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the request span, or None."""
    return _pinned_quote(text, REQUEST_SPAN, REQUEST_MARKER, root, sha, pinned)


def is_write_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the is-write span, or None."""
    return _pinned_quote(text, IS_WRITE_SPAN, IS_WRITE_MARKER, root, sha, pinned)


def scheme_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the scheme span, or None."""
    return _pinned_quote(text, SCHEME_SPAN, SCHEME_MARKER, root, sha, pinned)


def read_action_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the read action, or None."""
    return _pinned_quote(text, READ_ACTION_SPAN, READ_ACTION_MARKER, root, sha, pinned)


def write_action_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the write action, or None."""
    return _pinned_quote(text, WRITE_ACTION_SPAN, WRITE_ACTION_MARKER, root, sha, pinned)


def default_action_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the default action, or None."""
    return _pinned_quote(text, DEFAULT_ACTION_SPAN, DEFAULT_ACTION_MARKER, root, sha, pinned)


# The only target list: one entry per line decision, in source order. A range's
# two endpoints share one marker. The quoter name is looked up at call time so a
# test can plant a neighbouring remainder through the production path.
QUOTE_TARGETS = (
    (OBSERVE_SPAN, OBSERVE_MARKER, "observe_quote"),
    (EDIT_START_SPAN, EDIT_RANGE_MARKER, "edit_start_quote"),
    (EDIT_END_SPAN, EDIT_RANGE_MARKER, "edit_end_quote"),
    (REQUEST_SPAN, REQUEST_MARKER, "request_quote"),
    (REVISION_SPAN, REVISION_MARKER, "revision_quote"),
    (OP_SPAN, OP_MARKER, "op_quote"),
    (NO_PROCESS_SPAN, NO_PROCESS_MARKER, "no_process_quote"),
    (SEAT_SPAN, SEAT_MARKER, "seat_quote"),
    (IS_WRITE_SPAN, IS_WRITE_MARKER, "is_write_quote"),
    (NO_WRITE_SPAN, NO_WRITE_MARKER, "no_write_quote"),
    (NO_PROVIDER_SPAN, NO_PROVIDER_MARKER, "no_provider_quote"),
    (CHILD_SPAN, CHILD_MARKER, "parent_grant_doc_quote"),
    (NARROWER_SPAN, NARROWER_MARKER, "narrower_quote"),
    (CHILD_GRANT_NONE_SPAN, CHILD_GRANT_NONE_MARKER, "child_grant_none_quote"),
    (PROJECT_SPAN, PROJECT_MARKER, "init_guard_quote"),
    (PROJECT_RESOURCE_SPAN, PROJECT_RESOURCE_MARKER, "project_resource_quote"),
    (AUTHORIZE_SPAN, AUTHORIZE_MARKER, "parent_compare_quote"),
    (CHILD_HOST_DOC_SPAN, CHILD_HOST_DOC_MARKER, "child_host_doc_quote"),
    (EMPTY_JOURNAL_SPAN, EMPTY_JOURNAL_MARKER, "empty_journal_quote"),
    (ADMIT_SYSTEM_SPAN, ADMIT_SYSTEM_MARKER, "admit_system_quote"),
    (INHERITED_ERR_SPAN, INHERITED_ERR_MARKER, "inherited_err_quote"),
    (GRANT_PARENT_SPAN, GRANT_PARENT_MARKER, "grant_parent_quote"),
    (DENY_SPAN, DENY_MARKER, "deny_quote"),
    (MINT_SPAN, MINT_MARKER, "mint_quote"),
    (OWNED_SPAN, OWNED_MARKER, "owned_quote"),
    (NEXT_SPAN, OWNED_MARKER, "next_owned_quote"),
    (JOURNAL_SPAN, JOURNAL_MARKER, "journal_quote"),
    (GRANT_SPAN, GRANT_MARKER, "grant_quote"),
    (WRITE_SPAN, WRITE_MARKER, "write_quote"),
    (READ_SPAN, READ_MARKER, "read_quote"),
    (APPEND_CONDITION_SPAN, APPEND_CONDITION_MARKER, "append_condition_quote"),
    (HOST_PATH_ERR_SPAN, HOST_PATH_ERR_MARKER, "host_path_err_quote"),
    (HELD_ERR_SPAN, HELD_ERR_MARKER, "held_err_quote"),
    (BODY_DOC_SPAN, BODY_DOC_MARKER, "body_doc_quote"),
    (CREATE_ONLY_SPAN, CREATE_ONLY_MARKER, "create_only_quote"),
    (PRESENT_REVISION_SPAN, PRESENT_REVISION_MARKER, "present_revision_quote"),
    (APPEND_CAP_SPAN, APPEND_CAP_MARKER, "append_cap_quote"),
    (APPEND_CALL_SPAN, APPEND_RANGE_MARKER, "append_call_quote"),
    (OUTCOME_HELD_SPAN, APPEND_RANGE_MARKER, "outcome_held_quote"),
    (WRITE_INVOKE_SPAN, WRITE_INVOKE_MARKER, "write_invoke_quote"),
    (ASKS_SPAN, ASKS_MARKER, "asks_quote"),
    (MARKER_SPAN, MARKER_MARKER, "marker_quote"),
    (LAUNCHING_SPAN, LAUNCHING_MARKER, "launching_quote"),
    (KIND_READ_SPAN, KIND_READ_MARKER, "kind_read_quote"),
    (KIND_EDIT_SPAN, KIND_EDIT_MARKER, "kind_edit_quote"),
    (KIND_RUN_SPAN, KIND_RUN_MARKER, "kind_run_quote"),
    (KIND_RESTORE_SPAN, KIND_RESTORE_MARKER, "kind_restore_quote"),
    (KIND_HOSTED_SPAN, KIND_HOSTED_MARKER, "kind_hosted_quote"),
    (KIND_CHILD_SPAN, KIND_CHILD_MARKER, "kind_child_quote"),
    (KIND_INIT_SPAN, KIND_INIT_MARKER, "kind_init_quote"),
    (KIND_APPEND_SPAN, KIND_APPEND_MARKER, "kind_append_quote"),
    (COVER_SPAN, COVER_MARKER, "cover_quote"),
    (SCHEME_SPAN, SCHEME_MARKER, "scheme_quote"),
    (READ_ACTION_SPAN, READ_ACTION_MARKER, "read_action_quote"),
    (WRITE_ACTION_SPAN, WRITE_ACTION_MARKER, "write_action_quote"),
    (DEFAULT_ACTION_SPAN, DEFAULT_ACTION_MARKER, "default_action_quote"),
)


def quoted_line_matches(quoted, source):
    """True only when the quotation equals the pinned source line."""
    return quoted == source


def _quote_refusal(root, text, sha, target):
    """Return the refusal for one target, or None when it matches or is absent.

    The walk has no remainder for MARKER: no refusal, and the next target runs.
    The marker is not one line: refused before the line read. The pinned line is
    absent, or no window holds the cited line: the quotation is not in the pin.
    The comparison fails, including a zero score: the quotation does not match.
    """
    span, marker, quoter = target
    if text.count(marker) > 1:
        return "refuse: quoted line is not one line: " + marker.strip("`")
    if not _remainders(text, marker):
        return None
    rel, number = _span_target(span)
    source = pinned_line(root, sha, rel, number)
    quoted = globals()[quoter](text, root, sha)
    if quoted is None or source is None:
        return "refuse: quoted line is not in the pinned commit: " + span
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + span
    return None


def _quote_refusals(root, text, sha):
    """Return at most one quote refusal, walking QUOTE_TARGETS in source order."""
    for target in QUOTE_TARGETS:
        reason = _quote_refusal(root, text, sha, target)
        if reason is not None:
            return [reason]
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
