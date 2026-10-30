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

# Its quotation is the removal at the end of the activation, source line 218.
RESIDENT_REL = "elastos/crates/elastos-compute/src/providers/component.rs"
RESIDENT_RUN_SPAN = RESIDENT_REL + ":218"
RESIDENT_RUN_MARKER = "`" + RESIDENT_RUN_SPAN + "`"

# Its quotation is the contract error in the stop body, source line 232.
RESIDENT_STOP_SPAN = RESIDENT_REL + ":232"
RESIDENT_STOP_MARKER = "`" + RESIDENT_STOP_SPAN + "`"

# Its quotation is the one export the capsule kernel provides, source line 87.
RESIDENT_EXPORT_SPAN = "elastos/wit/elastos-bus-v1.wit:87"
RESIDENT_EXPORT_MARKER = "`" + RESIDENT_EXPORT_SPAN + "`"

# The journal range holds the two budget comparisons. Its two endpoints share
# one marker, and each endpoint's remainder is its own pinned line.
JOURNAL_RANGE_SPAN = "capsules/model-provider/src/journal.rs:391-397"
JOURNAL_RANGE_MARKER = "`" + JOURNAL_RANGE_SPAN + "`"

# The model-service range holds the create comment. Its two endpoints share
# one marker, and each endpoint's remainder is its own pinned line.
GATEWAY_RANGE_SPAN = (
    "elastos/crates/elastos-server/src/api/gateway_model_service.rs:1452-1454"
)
GATEWAY_RANGE_MARKER = "`" + GATEWAY_RANGE_SPAN + "`"

# The guest range holds the zeroed step budget. Its two endpoints share one
# marker, and each endpoint's remainder is its own pinned line.
GUEST_RANGE_SPAN = "examples/agent-host/src/lib.rs:471-476"
GUEST_RANGE_MARKER = "`" + GUEST_RANGE_SPAN + "`"

# The two resident-A3 claims the draft never makes. Each has its own refusal.
A3_MET_CLAIM = "A3 is met"
A3_GRANT_CLAIM = "ComponentProvider grants resident A3 credit"

# The draft indents a quotation by exactly four spaces.
DRAFT_INDENT = "    "


# One blob at one commit never changes, so one run reads each blob once. A
# citation and the quotations of the same file share this one read.
BLOBS = {}


def read_file(root, rel, sha):
    """Return the bytes of REL at commit SHA, or None when it has no such blob.

    The pinned commit is the one revision a citation is judged against, so this
    reads the commit and never the worktree.
    """
    if sha is None:
        return None
    key = (str(root), sha, rel)
    if key in BLOBS:
        return BLOBS[key]
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "cat-file", "blob", sha + ":" + rel],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    data = None if result.returncode != 0 else result.stdout
    BLOBS[key] = data
    return data


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
    data = read_file(root, rel, sha)
    if data is None:
        return None
    try:
        text = decode_text(data)
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
    """Return the path and start line number of SPAN.

    ``CITATION`` reads the number, so a range span resolves to its start line
    and a single line span is unchanged. No text after a colon is read as an
    integer here, so a range suffix never raises.
    """
    match = CITATION.fullmatch(span)
    return match.group("path"), int(match.group("start"))


def cited_line(span, lines):
    """Return the 1-based line SPAN cites.

    A line span is the number ``_span_target`` reads. A function span is the
    first line of LINES that declares that function, using the same ``fn`` or
    ``def`` pattern as ``has_function``.
    """
    match = CITATION.fullmatch(span)
    func = None if match is None else match.group("func")
    if func is not None:
        if not lines:
            return None
        pattern = r"(?:^|\s)(?:fn|def) " + re.escape(func) + r"\("
        for number, line in enumerate(lines, 1):
            if re.search(pattern, line):
                return number
        return None
    return _span_target(span)[1]


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
    the worktree draft pin when TEXT carries none. ``cited_line`` then names
    the line: the numbered line of a line span, or the declaring line of a
    function span.
    """
    remainders = _remainders(text, marker)
    if not remainders:
        return None
    if pinned is None:
        if root is None:
            root = worktree_root()
        if sha is None:
            sha = _pin_of(text, root)
        match = CITATION.fullmatch(span)
        rel = match.group("path")
        pinned = _pinned_lines(root, sha, rel)
    return quote_for(remainders, pinned, cited_line(span, pinned))


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


def resident_run_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the activation removal, or None."""
    return _pinned_quote(text, RESIDENT_RUN_SPAN, RESIDENT_RUN_MARKER, root, sha, pinned)


def resident_stop_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the stop contract error, or None."""
    return _pinned_quote(text, RESIDENT_STOP_SPAN, RESIDENT_STOP_MARKER, root, sha, pinned)


def resident_export_quote(text, root=None, sha=None, pinned=None):
    """Return the quotation that stands for the lifecycle export, or None."""
    return _pinned_quote(text, RESIDENT_EXPORT_SPAN, RESIDENT_EXPORT_MARKER, root, sha, pinned)


# Function spans whose indented block already equals the declaring line, in
# draft order. Each one is spliced into QUOTE_TARGETS with a None quoter, so
# the tuple and the list cannot drift. A None quoter is the only selector.
FUNCTION_QUOTE_SPANS = (
    "elastos/crates/elastos-server/src/auth.rs::local_person_principal_id",
    "elastos/crates/elastos-server/src/auth.rs::principal_localhost_root",
    "elastos/crates/elastos-server/src/resource_bridge.rs::scope_current_user_alias",
    "elastos/crates/elastos-server/src/resource_bridge.rs::manifest_bound_users_self_matches_active_principal_root_only_with_context",
    "examples/agent-host/src/lib.rs::journal_resource",
    "lab/capsule-identity/src/lib.rs::name_signature_message",
    "lab/capsule-identity/src/lib.rs::sign_bundle",
    "lab/capsule-identity/src/lib.rs::verify_checked_signature",
    "examples/agent-host/src/lib.rs::authorize",
    "elastos/crates/elastos-runtime/src/capability/manager.rs::test_wrong_capsule",
    "examples/agent-host/src/lib.rs::propose_hosted",
    "capsules/model-provider/src/adapters.rs::effect_request",
    "elastos/crates/elastos-server/src/api/model_provider_egress.rs::handle",
    "examples/agent-host/src/lib.rs::step_payload",
    "capsules/model-provider/src/journal.rs::journal_budget_fault",
    "capsules/model-provider/src/journal.rs::active_run_count",
    "capsules/model-provider/src/contract.rs::is_terminal",
    "elastos/crates/elastos-server/src/api/gateway_model_service.rs::reserve_run_slot",
    "capsules/model-provider/src/journal.rs::validate_backend_usage",
    "examples/agent-host/src/lib.rs::ask_kind_name",
    "examples/agent-host/src/lib.rs::declared_ask",
    "examples/agent-host/src/lib.rs::propose_read",
    "examples/agent-host/src/lib.rs::observe",
    "examples/agent-host/src/lib.rs::propose_edit",
    "examples/agent-host/src/lib.rs::propose_restore",
    "examples/agent-host/src/lib.rs::is_write",
    "examples/agent-host/src/lib.rs::edit_request",
    "examples/agent-host/src/lib.rs::request_body",
    "elastos/crates/elastos-server/src/provider_resource.rs::provider_operation_action",
    "elastos/crates/elastos-server/src/provider_resource.rs::localhost_op_required_action",
    "examples/agent-host/src/lib.rs::propose_run",
    "elastos/crates/elastos-compute/src/exec_vm.rs::decide_exec",
    "elastos/crates/elastos-compute/src/exec_vm.rs::admit_project_files",
    "examples/agent-host/src/lib.rs::propose_child",
    "examples/agent-host/src/lib.rs::authorize_child",
    "examples/agent-host/src/lib.rs::open_child_host",
    "examples/agent-host/src/lib.rs::grant_child_host",
    "examples/agent-host/src/lib.rs::propose_init",
    "examples/agent-host/src/lib.rs::journal_write_body",
    "examples/agent-host/src/lib.rs::append_journal",
    "examples/agent-host/src/lib.rs::propose_journal_append",
    "elastos/crates/elastos-server/src/provider_resource.rs::agents_area_refusal",
    "elastos/crates/elastos-server/src/resource_bridge.rs::write_precondition",
    "lab/grant-binding/src/ops.rs::model_overwrite_grant_does_not_permit_append",
    "lab/grant-binding/src/lib.rs::register_instance",
    "lab/grant-binding/src/lib.rs::resource_name",
    "lab/grant-binding/src/lib.rs::bind_grant",
    "lab/grant-binding/src/lib.rs::use_grant",
    "lab/grant-binding/src/ledger.rs::model_reserve_over_the_ceiling_is_refused",
    "lab/grant-binding/src/ledger.rs::model_reported_usage_does_not_lower_the_hold",
    "lab/grant-binding/src/ops.rs::operate",
)

# Line spans whose block equals the pinned window once every remainder gains
# four spaces, in draft order. Each one is spliced into QUOTE_TARGETS with a
# None quoter, the same way as FUNCTION_QUOTE_SPANS.
INDENT_LINE_SPANS = (
    "elastos/crates/elastos-server/src/resource_bridge.rs:43",
    "elastos/crates/elastos-server/src/resource_bridge.rs:984",
    "elastos/crates/elastos-compute/src/providers/component.rs:352",
    "elastos/crates/elastos-server/src/api/handlers/capability.rs:182",
    "elastos/crates/elastos-server/src/api/handlers/capability.rs:339",
    "elastos/crates/elastos-server/src/api/handlers/capability.rs:341",
    "elastos/crates/elastos-server/src/resource_bridge.rs:40",
    "elastos/crates/elastos-runtime/src/capability/manager.rs:326",
    "elastos/crates/elastos-runtime/src/capability/token.rs:203",
    "examples/agent-host/asks.json:10",
    "examples/agent-host/asks.json:11",
    "capsules/model-provider/src/adapters.rs:1670",
    "capsules/model-provider/src/config.rs:111",
    "capsules/model-provider/src/config.rs:113",
    "elastos/crates/elastos-runtime/src/provider/bridge.rs:774",
    "elastos/crates/elastos-runtime/src/provider/registry.rs:841",
    "lab/grant-binding/src/lib.rs:162",
    "lab/grant-binding/src/lib.rs:244",
)

# Egress line spans whose block equals the pinned line, in draft order. Each
# one is spliced into QUOTE_TARGETS with a None quoter, the same way as
# INDENT_LINE_SPANS.
EGRESS_LINE_SPANS = (
    "elastos/crates/elastos-server/src/api/model_provider_egress.rs:504",
    "elastos/crates/elastos-server/src/api/model_provider_egress.rs:509",
)

# Retargeted line spans whose block equals the pinned window once every
# remainder gains four spaces, in draft order. Each one is spliced into
# QUOTE_TARGETS with a None quoter, the same way as EGRESS_LINE_SPANS.
RESTATED_LINE_SPANS = (
    "elastos/crates/elastos-server/src/resource_bridge.rs:931",
    "elastos/crates/elastos-server/src/resource_bridge.rs:398",
)

# Retargeted ledger line spans whose block equals the pinned line, in draft
# order. Each one is spliced into QUOTE_TARGETS with a None quoter, the same
# way as RESTATED_LINE_SPANS.
LEDGER_LINE_SPANS = (
    "lab/grant-binding/src/ledger.rs:356",
    "lab/grant-binding/src/ledger.rs:341",
    "lab/grant-binding/src/ledger.rs:417",
)

# Caller-check and grant-id line spans whose block equals the pinned line, in
# draft order. Each one is spliced into QUOTE_TARGETS with a None quoter, the
# same way as LEDGER_LINE_SPANS.
OTHER_INDENT_SPANS = (
    "elastos/crates/elastos-runtime/src/capability/manager.rs:409",
    "elastos/crates/elastos-compute/src/providers/component.rs:384",
    "elastos/wit/elastos-bus-v1.wit:10",
)

# Range line spans whose block equals the pinned start line, in draft order.
# Each one is spliced into QUOTE_TARGETS with a None quoter, the same way as
# OTHER_INDENT_SPANS, and is scored at its start line only.
RANGE_LINE_SPANS = (
    "examples/agent-host/src/lib.rs:471-476",
    "capsules/model-provider/src/journal.rs:391-397",
    "elastos/crates/elastos-server/src/api/gateway_model_service.rs:1452-1454",
    "examples/agent-host/src/lib.rs:2421-2422",
    "examples/agent-host/src/lib.rs:4032-4033",
)

# The one fixed prefix of the target list: one entry per line decision, in
# source order before the function spans and the indent line spans. A range's
# two endpoints share one marker. The quoter name is looked up at call time so
# a test can plant a neighbouring remainder through the production path.
_QUOTE_TARGETS_PREFIX = (
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
    (RESIDENT_RUN_SPAN, RESIDENT_RUN_MARKER, "resident_run_quote"),
    (RESIDENT_STOP_SPAN, RESIDENT_STOP_MARKER, "resident_stop_quote"),
    (RESIDENT_EXPORT_SPAN, RESIDENT_EXPORT_MARKER, "resident_export_quote"),
    # The 56 aligned entries this task adds, in draft order. Each reads its own
    # span through the shared window rule. A range's two endpoints share one
    # marker and stand first endpoint then second endpoint.
    ("elastos/crates/elastos-server/src/resource_bridge.rs:814", "`elastos/crates/elastos-server/src/resource_bridge.rs:814`", None),
    ("lab/capsule-identity/src/lib.rs:1425", "`lab/capsule-identity/src/lib.rs:1425`", None),
    ("lab/capsule-identity/README.md:946", "`lab/capsule-identity/README.md:946`", None),
    ("elastos/crates/elastos-compute/src/providers/component.rs:350", "`elastos/crates/elastos-compute/src/providers/component.rs:350`", None),
    ("capsules/model-provider/src/adapters.rs:58", "`capsules/model-provider/src/adapters.rs:58`", None),
    ("elastos/crates/elastos-server/src/api/gateway_model_service.rs:1", "`elastos/crates/elastos-server/src/api/gateway_model_service.rs:1`", None),
    ("elastos/crates/elastos-server/src/api/gateway_model_service.rs:4", "`elastos/crates/elastos-server/src/api/gateway_model_service.rs:4`", None),
    ("examples/agent-host/src/lib.rs:471", GUEST_RANGE_MARKER, None),
    ("examples/agent-host/src/lib.rs:476", GUEST_RANGE_MARKER, None),
    ("examples/agent-host/src/lib.rs:532", "`examples/agent-host/src/lib.rs:532`", None),
    ("examples/agent-host/src/lib.rs:754", "`examples/agent-host/src/lib.rs:754`", None),
    ("capsules/model-provider/src/journal.rs:391", JOURNAL_RANGE_MARKER, None),
    ("capsules/model-provider/src/journal.rs:397", JOURNAL_RANGE_MARKER, None),
    ("capsules/model-provider/src/journal.rs:921", "`capsules/model-provider/src/journal.rs:921`", None),
    ("capsules/model-provider/src/state.rs:530", "`capsules/model-provider/src/state.rs:530`", None),
    ("capsules/model-provider/src/state.rs:609", "`capsules/model-provider/src/state.rs:609`", None),
    ("capsules/model-provider/src/contract.rs:134", "`capsules/model-provider/src/contract.rs:134`", None),
    ("elastos/crates/elastos-server/src/api/gateway_model_service.rs:355", "`elastos/crates/elastos-server/src/api/gateway_model_service.rs:355`", None),
    ("elastos/crates/elastos-server/src/api/gateway_model_service.rs:1452", GATEWAY_RANGE_MARKER, None),
    ("elastos/crates/elastos-server/src/api/gateway_model_service.rs:1454", GATEWAY_RANGE_MARKER, None),
    ("examples/agent-host/asks.json:4", "`examples/agent-host/asks.json:4`", None),
    ("examples/agent-host/asks.json:5", "`examples/agent-host/asks.json:5`", None),
    ("examples/agent-host/asks.json:6", "`examples/agent-host/asks.json:6`", None),
    ("elastos/crates/elastos-server/src/provider_resource.rs:422", "`elastos/crates/elastos-server/src/provider_resource.rs:422`", None),
    ("examples/agent-host/asks.json:7", "`examples/agent-host/asks.json:7`", None),
    ("examples/agent-host/asks.json:8", "`examples/agent-host/asks.json:8`", None),
    ("examples/agent-host/asks.json:9", "`examples/agent-host/asks.json:9`", None),
    ("elastos/crates/elastos-compute/src/exec_vm.rs:43", "`elastos/crates/elastos-compute/src/exec_vm.rs:43`", None),
    ("elastos/crates/elastos-compute/src/exec_vm.rs:49", "`elastos/crates/elastos-compute/src/exec_vm.rs:49`", None),
    ("elastos/crates/elastos-compute/src/exec_vm.rs:130", "`elastos/crates/elastos-compute/src/exec_vm.rs:130`", None),
    ("elastos/crates/elastos-server/src/provider_resource.rs:174", "`elastos/crates/elastos-server/src/provider_resource.rs:174`", None),
    ("elastos/crates/elastos-server/src/provider_resource.rs:176", "`elastos/crates/elastos-server/src/provider_resource.rs:176`", None),
    ("elastos/crates/elastos-server/src/provider_resource.rs:163", "`elastos/crates/elastos-server/src/provider_resource.rs:163`", None),
    ("elastos/crates/elastos-server/src/provider_resource.rs:164", "`elastos/crates/elastos-server/src/provider_resource.rs:164`", None),
    ("elastos/crates/elastos-server/src/provider_resource.rs:165", "`elastos/crates/elastos-server/src/provider_resource.rs:165`", None),
    ("examples/agent-host/asks.json:12", "`examples/agent-host/asks.json:12`", None),
    ("elastos/crates/elastos-server/src/provider_resource.rs:379", "`elastos/crates/elastos-server/src/provider_resource.rs:379`", None),
    ("elastos/crates/elastos-server/src/provider_resource.rs:382", "`elastos/crates/elastos-server/src/provider_resource.rs:382`", None),
    ("elastos/crates/elastos-server/src/resource_bridge.rs:696", "`elastos/crates/elastos-server/src/resource_bridge.rs:696`", None),
    ("elastos/crates/elastos-server/src/resource_bridge.rs:697", "`elastos/crates/elastos-server/src/resource_bridge.rs:697`", None),
    ("elastos/crates/elastos-server/src/resource_bridge.rs:698", "`elastos/crates/elastos-server/src/resource_bridge.rs:698`", None),
    ("elastos/crates/elastos-server/src/resource_bridge.rs:699", "`elastos/crates/elastos-server/src/resource_bridge.rs:699`", None),
    ("elastos/crates/elastos-server/src/resource_bridge.rs:570", "`elastos/crates/elastos-server/src/resource_bridge.rs:570`", None),
    ("elastos/crates/elastos-server/src/resource_bridge.rs:571", "`elastos/crates/elastos-server/src/resource_bridge.rs:571`", None),
    ("elastos/crates/elastos-server/src/resource_bridge.rs:582", "`elastos/crates/elastos-server/src/resource_bridge.rs:582`", None),
    ("elastos/crates/elastos-server/src/resource_bridge.rs:583", "`elastos/crates/elastos-server/src/resource_bridge.rs:583`", None),
    ("elastos/crates/elastos-server/src/resource_bridge.rs:603", "`elastos/crates/elastos-server/src/resource_bridge.rs:603`", None),
    ("elastos/crates/elastos-server/src/resource_bridge.rs:606", "`elastos/crates/elastos-server/src/resource_bridge.rs:606`", None),
    ("lab/grant-binding/README.md:12", "`lab/grant-binding/README.md:12`", None),
    ("docs/AGENT_ARCHITECTURE.md:19", "`docs/AGENT_ARCHITECTURE.md:19`", None),
    ("docs/AGENT_ARCHITECTURE.md:21", "`docs/AGENT_ARCHITECTURE.md:21`", None),
    ("docs/AGENT_ARCHITECTURE.md:24", "`docs/AGENT_ARCHITECTURE.md:24`", None),
    ("docs/AGENT_ARCHITECTURE.md:332", "`docs/AGENT_ARCHITECTURE.md:332`", None),
    ("lab/grant-binding/src/lib.rs:280", "`lab/grant-binding/src/lib.rs:280`", None),
    ("lab/grant-binding/src/lib.rs:23", "`lab/grant-binding/src/lib.rs:23`", None),
    ("lab/grant-binding/src/lib.rs:25", "`lab/grant-binding/src/lib.rs:25`", None),
)

def _quote_target_tail(spans):
    return tuple((span, "`" + span + "`", None) for span in spans)


def _build_quote_targets():
    """Return the one target list from the current span tuples."""
    return (
        _QUOTE_TARGETS_PREFIX
        + _quote_target_tail(FUNCTION_QUOTE_SPANS)
        + _quote_target_tail(INDENT_LINE_SPANS)
        + _quote_target_tail(EGRESS_LINE_SPANS)
        + _quote_target_tail(RESTATED_LINE_SPANS)
        + _quote_target_tail(LEDGER_LINE_SPANS)
        + _quote_target_tail(OTHER_INDENT_SPANS)
        + _quote_target_tail(RANGE_LINE_SPANS)
    )


class _QuoteTargets:
    """Tuple-like view of the one target list."""

    def _built(self):
        return _build_quote_targets()

    def __iter__(self):
        return iter(self._built())

    def __len__(self):
        return len(self._built())

    def __getitem__(self, index):
        return self._built()[index]

    def __eq__(self, other):
        return self._built() == other

    def __repr__(self):
        return repr(self._built())


# The only target list: one entry per line decision, then one None-quoter entry
# per FUNCTION_QUOTE_SPANS entry, then one per INDENT_LINE_SPANS entry, then one
# per EGRESS_LINE_SPANS entry, then one per RESTATED_LINE_SPANS entry, then one
# per LEDGER_LINE_SPANS entry, then one per OTHER_INDENT_SPANS entry, then one
# per RANGE_LINE_SPANS entry.
QUOTE_TARGETS = _QuoteTargets()


def quoted_line_matches(quoted, source):
    """True only when the quotation equals the pinned source line."""
    return quoted == source


def _target_quotation(text, target, root, sha):
    """Return the quotation for TARGET.

    A target with a named selector reads through that selector. A target with
    no selector reads its own span at its own marker through ``_pinned_quote``,
    which is the same window rule and the same equality decision.
    """
    span, marker, quoter = target
    if quoter is None:
        return _pinned_quote(text, span, marker, root, sha)
    return globals()[quoter](text, root, sha)


def _quote_refusal(root, text, sha, target, refused_spans=frozenset()):
    """Return the refusal for one target, or None when it matches or is absent.

    The pin already refused this citation, or the marker it reads, with a
    structural reason: one citation has one reason, so no quote refusal runs.
    The walk has no remainder for MARKER: no refusal, and the next target runs.
    The marker is not one line: refused before the line read. ``cited_line``
    names the line after the pinned file is read: the numbered line of a line
    span, or the declaring line of a function span. The pinned line is absent,
    or no window holds the cited line: the quotation is not in the pin.
    The comparison fails, including a zero score: the quotation does not match.
    """
    span, marker, quoter = target
    if span in refused_spans or marker.strip("`") in refused_spans:
        return None
    if text.count(marker) > 1:
        return "refuse: quoted line is not one line: " + marker.strip("`")
    if not _remainders(text, marker):
        return None
    rel = CITATION.fullmatch(span).group("path")
    lines = _pinned_lines(root, sha, rel)
    number = cited_line(span, lines)
    source = None if number is None else pinned_line(root, sha, rel, number)
    quoted = _target_quotation(text, target, root, sha)
    if quoted is None or source is None:
        return "refuse: quoted line is not in the pinned commit: " + span
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + span
    return None


def _quote_refusals(root, text, sha, refused_spans=frozenset()):
    """Return at most one quote refusal, walking the one target list in order."""
    for target in QUOTE_TARGETS:
        reason = _quote_refusal(root, text, sha, target, refused_spans)
        if reason is not None:
            return [reason]
    return []


def a3_claim_refusals(text):
    """Return one refusal per claim that closes resident A3, each its own line."""
    refusals = []
    if A3_MET_CLAIM in text:
        refusals.append("refuse: draft says " + A3_MET_CLAIM)
    if A3_GRANT_CLAIM in text:
        refusals.append("refuse: draft says " + A3_GRANT_CLAIM)
    return refusals


def _past_end(number, rel, count):
    return "refuse: line %s is past the end of %s (%s lines)" % (number, rel, count)


def _refusal(root, match, sha):
    """Return the structural refusal for one citation at commit SHA.

    A path, a UTF-8 read, a line bound and a function name all read the pinned
    commit, so one draft is judged against one revision.
    """
    rel = match.group("path")
    data = read_file(root, rel, sha)
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


def pin_allows_structural_reads(pin_reason, pinned):
    """True only when the pin names a commit, so one revision is read.

    A missing pin, a bad pin line and an unknown pin each name no revision, so
    they stay the only refusal and the structural reads do not run.
    """
    return pin_reason is None and pinned


def problems(root):
    """Return one refusal per bad pin or citation, pin refusals first.

    A bad pin, a bad pin line or an unknown pin is the only refusal of its own,
    because no revision is named to read. The structural reads run only once
    the pin names a commit, and they read that commit.
    """
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
    if pin_allows_structural_reads(pin_reason, pinned):
        refused_spans = set()
        for span in _spans(text):
            match = CITATION.fullmatch(span)
            if match is None:
                continue
            reason = _refusal(root, match, sha)
            if reason is not None:
                refusals.append(reason)
                refused_spans.add(span)
        refusals.extend(_quote_refusals(root, text, sha, refused_spans))
        refusals.extend(a3_claim_refusals(text))
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
