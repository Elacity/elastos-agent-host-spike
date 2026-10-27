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
HOSTED_SPAN = "examples/agent-host/src/lib.rs:3339"
HOSTED_MARKER = "`" + HOSTED_SPAN + "`"

# Its quotation is remainder 1 after the child span, source line 3360.
CHILD_SPAN = "examples/agent-host/src/lib.rs:3360"
CHILD_MARKER = "`" + CHILD_SPAN + "`"

# Its quotation is remainder 11 after the child span, source line 3370.
NARROWER_SPAN = "examples/agent-host/src/lib.rs:3370"
NARROWER_MARKER = "`" + NARROWER_SPAN + "`"

# Its quotation is remainder 23 after the child span, source line 3382.
CHILD_GRANT_NONE_SPAN = "examples/agent-host/src/lib.rs:3382"
CHILD_GRANT_NONE_MARKER = "`" + CHILD_GRANT_NONE_SPAN + "`"

# Its quotation is remainder 1 after the init span, source line 3387.
INIT_SPAN = "examples/agent-host/src/lib.rs:3387"
INIT_MARKER = "`" + INIT_SPAN + "`"

# Its quotation is remainder 17 after the init span, source line 3403.
PROJECT_RESOURCE_SPAN = "examples/agent-host/src/lib.rs:3403"
PROJECT_RESOURCE_MARKER = "`" + PROJECT_RESOURCE_SPAN + "`"

# Its quotation is remainder 17 after the compare span, source line 3449.
PARENT_COMPARE_SPAN = "examples/agent-host/src/lib.rs:3449"
PARENT_COMPARE_MARKER = "`" + PARENT_COMPARE_SPAN + "`"

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


def body_doc_quote(text):
    """Return remainder 0 after the write-body span, or None when it is absent."""
    remainders = _remainders(text, BODY_DOC_MARKER)
    if not remainders:
        return None
    return remainders[0]


def create_only_quote(text):
    """Return remainder 5 after the write-body span, or None when it is absent."""
    remainders = _remainders(text, CREATE_ONLY_MARKER)
    if len(remainders) <= 5:
        return None
    return remainders[5]


def present_revision_quote(text):
    """Return remainder 6 after the write-body span, or None when it is absent."""
    remainders = _remainders(text, PRESENT_REVISION_MARKER)
    if len(remainders) <= 6:
        return None
    return remainders[6]


def append_condition_quote(text):
    """Return remainder 7 after the condition span, or None when absent."""
    remainders = _remainders(text, APPEND_CONDITION_MARKER)
    if len(remainders) <= 7:
        return None
    return remainders[7]


def host_path_err_quote(text):
    """Return remainder 8 after the condition span, or None when absent."""
    remainders = _remainders(text, HOST_PATH_ERR_MARKER)
    if len(remainders) <= 8:
        return None
    return remainders[8]


def held_err_quote(text):
    """Return remainder 19 after the condition span, or None when absent."""
    remainders = _remainders(text, HELD_ERR_MARKER)
    if len(remainders) <= 19:
        return None
    return remainders[19]


def append_cap_quote(text):
    """Return remainder 1 after the cap span, or None when it is absent."""
    remainders = _remainders(text, APPEND_CAP_MARKER)
    if len(remainders) <= 1:
        return None
    return remainders[1]


def append_call_quote(text):
    """Return remainder 10 after the range span, or None when it is absent."""
    remainders = _remainders(text, APPEND_RANGE_MARKER)
    if len(remainders) <= 10:
        return None
    return remainders[10]


def outcome_held_quote(text):
    """Return remainder 11 after the range span, or None when it is absent."""
    remainders = _remainders(text, APPEND_RANGE_MARKER)
    if len(remainders) <= 11:
        return None
    return remainders[11]


def write_invoke_quote(text):
    """Return remainder 13 after the invoke span, or None when it is absent."""
    remainders = _remainders(text, WRITE_INVOKE_MARKER)
    if len(remainders) <= 13:
        return None
    return remainders[13]


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


def observe_quote(text):
    """Return remainder 4 after the observe span, or None when it is absent."""
    remainders = _remainders(text, OBSERVE_MARKER)
    if len(remainders) <= 4:
        return None
    return remainders[4]


def revision_quote(text):
    """Return remainder 7 after the revision span, or None when it is absent."""
    remainders = _remainders(text, REVISION_MARKER)
    if len(remainders) <= 7:
        return None
    return remainders[7]


def op_quote(text):
    """Return remainder 15 after the op span, or None when it is absent."""
    remainders = _remainders(text, OP_MARKER)
    if len(remainders) <= 15:
        return None
    return remainders[15]


def no_process_quote(text):
    """Return remainder 1 after the run span, or None when it is absent."""
    remainders = _remainders(text, NO_PROCESS_MARKER)
    if len(remainders) <= 1:
        return None
    return remainders[1]


def seat_quote(text):
    """Return remainder 24 after the run span, or None when it is absent."""
    remainders = _remainders(text, SEAT_MARKER)
    if len(remainders) <= 24:
        return None
    return remainders[24]


def no_write_quote(text):
    """Return remainder 4 after the no-write span, or None when it is absent."""
    remainders = _remainders(text, NO_WRITE_MARKER)
    if len(remainders) <= 4:
        return None
    return remainders[4]


def no_provider_quote(text):
    """Return remainder 1 after the hosted span, or None when it is absent."""
    remainders = _remainders(text, HOSTED_MARKER)
    if len(remainders) <= 1:
        return None
    return remainders[1]


def parent_grant_doc_quote(text):
    """Return remainder 1 after the child span, or None when it is absent."""
    remainders = _remainders(text, CHILD_MARKER)
    if len(remainders) <= 1:
        return None
    return remainders[1]


def narrower_quote(text):
    """Return remainder 11 after the narrower span, or None when it is absent."""
    remainders = _remainders(text, NARROWER_MARKER)
    if len(remainders) <= 11:
        return None
    return remainders[11]


def child_grant_none_quote(text):
    """Return remainder 23 after the grant-none span, or None when it is absent."""
    remainders = _remainders(text, CHILD_GRANT_NONE_MARKER)
    if len(remainders) <= 23:
        return None
    return remainders[23]


def init_guard_quote(text):
    """Return remainder 1 after the init span, or None when it is absent."""
    remainders = _remainders(text, INIT_MARKER)
    if len(remainders) <= 1:
        return None
    return remainders[1]


def project_resource_quote(text):
    """Return remainder 17 after the resource span, or None when it is absent."""
    remainders = _remainders(text, PROJECT_RESOURCE_MARKER)
    if len(remainders) <= 17:
        return None
    return remainders[17]


def parent_compare_quote(text):
    """Return remainder 17 after the compare span, or None when it is absent."""
    remainders = _remainders(text, PARENT_COMPARE_MARKER)
    if len(remainders) <= 17:
        return None
    return remainders[17]


def cover_quote(text):
    """Return remainder 5 after the cover span, or None when it is absent."""
    remainders = _remainders(text, COVER_MARKER)
    if len(remainders) <= 5:
        return None
    return remainders[5]


def edit_start_quote(text):
    """Return remainder 4 after the edit range span, or None when it is absent."""
    remainders = _remainders(text, EDIT_RANGE_MARKER)
    if len(remainders) <= 4:
        return None
    return remainders[4]


def edit_end_quote(text):
    """Return remainder 5 after the edit range span, or None when it is absent."""
    remainders = _remainders(text, EDIT_RANGE_MARKER)
    if len(remainders) <= 5:
        return None
    return remainders[5]


def request_quote(text):
    """Return remainder 0 after the request span, or None when it is absent."""
    remainders = _remainders(text, REQUEST_MARKER)
    if not remainders:
        return None
    return remainders[0]


def is_write_quote(text):
    """Return remainder 2 after the is-write span, or None when it is absent."""
    remainders = _remainders(text, IS_WRITE_MARKER)
    if len(remainders) <= 2:
        return None
    return remainders[2]


def scheme_quote(text):
    """Return remainder 8 after the scheme span, or None when it is absent."""
    remainders = _remainders(text, SCHEME_MARKER)
    if len(remainders) <= 8:
        return None
    return remainders[8]


def read_action_quote(text):
    """Return remainder 0 after the read-action span, or None when absent."""
    remainders = _remainders(text, READ_ACTION_MARKER)
    if not remainders:
        return None
    return remainders[0]


def write_action_quote(text):
    """Return remainder 3 after the write-action span, or None when absent."""
    remainders = _remainders(text, WRITE_ACTION_MARKER)
    if len(remainders) <= 3:
        return None
    return remainders[3]


def default_action_quote(text):
    """Return remainder 5 after the default-action span, or None when absent."""
    remainders = _remainders(text, DEFAULT_ACTION_MARKER)
    if len(remainders) <= 5:
        return None
    return remainders[5]


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


def _observe_quote_refusal(root, text, sha):
    """Return the 2067 refusal, or None when that quote is absent or matches."""
    if text.count(OBSERVE_MARKER) > 1:
        return "refuse: quoted line is not one line: " + OBSERVE_SPAN
    quoted = observe_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(OBSERVE_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + OBSERVE_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + OBSERVE_SPAN
    return None


def _edit_start_quote_refusal(root, text, sha):
    """Return the 2421 refusal, or None when that quote is absent or matches."""
    if text.count(EDIT_RANGE_MARKER) > 1:
        return "refuse: quoted line is not one line: " + EDIT_RANGE_SPAN
    quoted = edit_start_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(EDIT_START_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + EDIT_START_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + EDIT_START_SPAN
    return None


def _edit_end_quote_refusal(root, text, sha):
    """Return the 2422 refusal, or None when that quote is absent or matches."""
    quoted = edit_end_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(EDIT_END_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + EDIT_END_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + EDIT_END_SPAN
    return None


def _request_quote_refusal(root, text, sha):
    """Return the 2720 refusal, or None when that quote is absent or matches."""
    if text.count(REQUEST_MARKER) > 1:
        return "refuse: quoted line is not one line: " + REQUEST_SPAN
    quoted = request_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(REQUEST_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + REQUEST_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + REQUEST_SPAN
    return None


def _revision_quote_refusal(root, text, sha):
    """Return the 2741 refusal, or None when that quote is absent or matches."""
    if text.count(REVISION_MARKER) > 1:
        return "refuse: quoted line is not one line: " + REVISION_SPAN
    quoted = revision_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(REVISION_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + REVISION_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + REVISION_SPAN
    return None


def _op_quote_refusal(root, text, sha):
    """Return the 2749 refusal, or None when that quote is absent or matches."""
    if text.count(OP_MARKER) > 1:
        return "refuse: quoted line is not one line: " + OP_SPAN
    quoted = op_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(OP_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + OP_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + OP_SPAN
    return None


def _no_process_quote_refusal(root, text, sha):
    """Return the 2958 refusal, or None when that quote is absent or matches."""
    if text.count(NO_PROCESS_MARKER) > 1:
        return "refuse: quoted line is not one line: " + NO_PROCESS_SPAN
    quoted = no_process_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(NO_PROCESS_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + NO_PROCESS_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + NO_PROCESS_SPAN
    return None


def _seat_quote_refusal(root, text, sha):
    """Return the 2981 refusal, or None when that quote is absent or matches."""
    if text.count(SEAT_MARKER) > 1:
        return "refuse: quoted line is not one line: " + SEAT_SPAN
    quoted = seat_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(SEAT_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + SEAT_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + SEAT_SPAN
    return None


def _is_write_quote_refusal(root, text, sha):
    """Return the 3290 refusal, or None when that quote is absent or matches."""
    if text.count(IS_WRITE_MARKER) > 1:
        return "refuse: quoted line is not one line: " + IS_WRITE_SPAN
    quoted = is_write_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(IS_WRITE_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + IS_WRITE_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + IS_WRITE_SPAN
    return None


def _no_write_quote_refusal(root, text, sha):
    """Return the 3308 refusal, or None when that quote is absent or matches."""
    if text.count(NO_WRITE_MARKER) > 1:
        return "refuse: quoted line is not one line: " + NO_WRITE_SPAN
    quoted = no_write_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(NO_WRITE_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + NO_WRITE_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + NO_WRITE_SPAN
    return None


def _no_provider_quote_refusal(root, text, sha):
    """Return the 3339 refusal, or None when that quote is absent or matches."""
    if text.count(HOSTED_MARKER) > 1:
        return "refuse: quoted line is not one line: " + HOSTED_SPAN
    quoted = no_provider_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(HOSTED_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + HOSTED_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + HOSTED_SPAN
    return None


def _parent_grant_doc_quote_refusal(root, text, sha):
    """Return the 3360 refusal, or None when that quote is absent or matches."""
    if text.count(CHILD_MARKER) > 1:
        return "refuse: quoted line is not one line: " + CHILD_SPAN
    quoted = parent_grant_doc_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(CHILD_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + CHILD_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + CHILD_SPAN
    return None


def _narrower_quote_refusal(root, text, sha):
    """Return the 3370 refusal, or None when that quote is absent or matches."""
    if text.count(NARROWER_MARKER) > 1:
        return "refuse: quoted line is not one line: " + NARROWER_SPAN
    quoted = narrower_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(NARROWER_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + NARROWER_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + NARROWER_SPAN
    return None


def _child_grant_none_quote_refusal(root, text, sha):
    """Return the 3382 refusal, or None when that quote is absent or matches."""
    if text.count(CHILD_GRANT_NONE_MARKER) > 1:
        return "refuse: quoted line is not one line: " + CHILD_GRANT_NONE_SPAN
    quoted = child_grant_none_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(CHILD_GRANT_NONE_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return (
            "refuse: quoted line is not in the pinned commit: "
            + CHILD_GRANT_NONE_SPAN
        )
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + CHILD_GRANT_NONE_SPAN
    return None


def _init_guard_quote_refusal(root, text, sha):
    """Return the 3387 refusal, or None when that quote is absent or matches."""
    if text.count(INIT_MARKER) > 1:
        return "refuse: quoted line is not one line: " + INIT_SPAN
    quoted = init_guard_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(INIT_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + INIT_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + INIT_SPAN
    return None


def _project_resource_quote_refusal(root, text, sha):
    """Return the 3403 refusal, or None when that quote is absent or matches."""
    if text.count(PROJECT_RESOURCE_MARKER) > 1:
        return "refuse: quoted line is not one line: " + PROJECT_RESOURCE_SPAN
    quoted = project_resource_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(PROJECT_RESOURCE_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return (
            "refuse: quoted line is not in the pinned commit: "
            + PROJECT_RESOURCE_SPAN
        )
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + PROJECT_RESOURCE_SPAN
    return None


def _parent_compare_quote_refusal(root, text, sha):
    """Return the 3449 refusal, or None when that quote is absent or matches."""
    if text.count(PARENT_COMPARE_MARKER) > 1:
        return "refuse: quoted line is not one line: " + PARENT_COMPARE_SPAN
    quoted = parent_compare_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(PARENT_COMPARE_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return (
            "refuse: quoted line is not in the pinned commit: "
            + PARENT_COMPARE_SPAN
        )
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + PARENT_COMPARE_SPAN
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


def _append_condition_quote_refusal(root, text, sha):
    """Return the 3935 refusal, or None when that quote is absent or matches."""
    if text.count(APPEND_CONDITION_MARKER) > 1:
        return "refuse: quoted line is not one line: " + APPEND_CONDITION_SPAN
    quoted = append_condition_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(APPEND_CONDITION_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + APPEND_CONDITION_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + APPEND_CONDITION_SPAN
    return None


def _host_path_err_quote_refusal(root, text, sha):
    """Return the 3936 refusal, or None when that quote is absent or matches."""
    if text.count(HOST_PATH_ERR_MARKER) > 1:
        return "refuse: quoted line is not one line: " + HOST_PATH_ERR_SPAN
    quoted = host_path_err_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(HOST_PATH_ERR_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + HOST_PATH_ERR_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + HOST_PATH_ERR_SPAN
    return None


def _held_err_quote_refusal(root, text, sha):
    """Return the 3947 refusal, or None when that quote is absent or matches."""
    if text.count(HELD_ERR_MARKER) > 1:
        return "refuse: quoted line is not one line: " + HELD_ERR_SPAN
    quoted = held_err_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(HELD_ERR_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + HELD_ERR_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + HELD_ERR_SPAN
    return None


def _body_doc_quote_refusal(root, text, sha):
    """Return the 3961 refusal, or None when that quote is absent or matches."""
    if text.count(BODY_DOC_MARKER) > 1:
        return "refuse: quoted line is not one line: " + BODY_DOC_SPAN
    quoted = body_doc_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(BODY_DOC_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + BODY_DOC_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + BODY_DOC_SPAN
    return None


def _create_only_quote_refusal(root, text, sha):
    """Return the 3966 refusal, or None when that quote is absent or matches."""
    if text.count(CREATE_ONLY_MARKER) > 1:
        return "refuse: quoted line is not one line: " + CREATE_ONLY_SPAN
    quoted = create_only_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(CREATE_ONLY_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + CREATE_ONLY_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + CREATE_ONLY_SPAN
    return None


def _present_revision_quote_refusal(root, text, sha):
    """Return the 3967 refusal, or None when that quote is absent or matches."""
    if text.count(PRESENT_REVISION_MARKER) > 1:
        return "refuse: quoted line is not one line: " + PRESENT_REVISION_SPAN
    quoted = present_revision_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(PRESENT_REVISION_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + PRESENT_REVISION_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + PRESENT_REVISION_SPAN
    return None


def _append_cap_quote_refusal(root, text, sha):
    """Return the 4023 refusal, or None when that quote is absent or matches."""
    if text.count(APPEND_CAP_MARKER) > 1:
        return "refuse: quoted line is not one line: " + APPEND_CAP_SPAN
    quoted = append_cap_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(APPEND_CAP_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + APPEND_CAP_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + APPEND_CAP_SPAN
    return None


def _append_call_quote_refusal(root, text, sha):
    """Return the 4032 refusal, or None when that quote is absent or matches."""
    if text.count(APPEND_RANGE_MARKER) > 1:
        return "refuse: quoted line is not one line: " + APPEND_RANGE_SPAN
    quoted = append_call_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(APPEND_CALL_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + APPEND_CALL_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + APPEND_CALL_SPAN
    return None


def _outcome_held_quote_refusal(root, text, sha):
    """Return the 4033 refusal, or None when that quote is absent or matches."""
    quoted = outcome_held_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(OUTCOME_HELD_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + OUTCOME_HELD_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + OUTCOME_HELD_SPAN
    return None


def _write_invoke_quote_refusal(root, text, sha):
    """Return the 4061 refusal, or None when that quote is absent or matches."""
    if text.count(WRITE_INVOKE_MARKER) > 1:
        return "refuse: quoted line is not one line: " + WRITE_INVOKE_SPAN
    quoted = write_invoke_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(WRITE_INVOKE_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + WRITE_INVOKE_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + WRITE_INVOKE_SPAN
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


def _cover_quote_refusal(root, text, sha):
    """Return the 8488 refusal, or None when that quote is absent or matches."""
    if text.count(COVER_MARKER) > 1:
        return "refuse: quoted line is not one line: " + COVER_SPAN
    quoted = cover_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(COVER_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + COVER_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + COVER_SPAN
    return None


def _scheme_quote_refusal(root, text, sha):
    """Return the 123 refusal, or None when that quote is absent or matches."""
    if text.count(SCHEME_MARKER) > 1:
        return "refuse: quoted line is not one line: " + SCHEME_SPAN
    quoted = scheme_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(SCHEME_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + SCHEME_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + SCHEME_SPAN
    return None


def _read_action_quote_refusal(root, text, sha):
    """Return the 189 refusal, or None when that quote is absent or matches."""
    if text.count(READ_ACTION_MARKER) > 1:
        return "refuse: quoted line is not one line: " + READ_ACTION_SPAN
    quoted = read_action_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(READ_ACTION_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + READ_ACTION_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + READ_ACTION_SPAN
    return None


def _write_action_quote_refusal(root, text, sha):
    """Return the 190 refusal, or None when that quote is absent or matches."""
    if text.count(WRITE_ACTION_MARKER) > 1:
        return "refuse: quoted line is not one line: " + WRITE_ACTION_SPAN
    quoted = write_action_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(WRITE_ACTION_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + WRITE_ACTION_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + WRITE_ACTION_SPAN
    return None


def _default_action_quote_refusal(root, text, sha):
    """Return the 192 refusal, or None when that quote is absent or matches."""
    if text.count(DEFAULT_ACTION_MARKER) > 1:
        return "refuse: quoted line is not one line: " + DEFAULT_ACTION_SPAN
    quoted = default_action_quote(text)
    if quoted is None:
        return None
    rel, number = _span_target(DEFAULT_ACTION_SPAN)
    source = pinned_line(root, sha, rel, number)
    if source is None:
        return "refuse: quoted line is not in the pinned commit: " + DEFAULT_ACTION_SPAN
    if not quoted_line_matches(quoted, source):
        return "refuse: quoted line does not match " + DEFAULT_ACTION_SPAN
    return None


def _quote_refusals(root, text, sha):
    """Return the quote refusals in source order: 2067, 2421, 2422, 2720, 2741, 2749, 2958, 2981, 3290, 3308, 3339, 3360, 3370, 3382, 3387, 3403, 3449, 3526, 3549, 3754, 3755, 3757, 3767, 3849, 3850, 3935, 3936, 3947, 3961, 3966, 3967, 4023, 4032, 4033, 4061, 8149, 8162, 8168, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8488, then 123, 189, 190, 192."""
    observe = _observe_quote_refusal(root, text, sha)
    if observe is not None:
        return [observe]
    edit_start = _edit_start_quote_refusal(root, text, sha)
    if edit_start is not None:
        return [edit_start]
    edit_end = _edit_end_quote_refusal(root, text, sha)
    if edit_end is not None:
        return [edit_end]
    request = _request_quote_refusal(root, text, sha)
    if request is not None:
        return [request]
    revision = _revision_quote_refusal(root, text, sha)
    if revision is not None:
        return [revision]
    op = _op_quote_refusal(root, text, sha)
    if op is not None:
        return [op]
    no_process = _no_process_quote_refusal(root, text, sha)
    if no_process is not None:
        return [no_process]
    seat = _seat_quote_refusal(root, text, sha)
    if seat is not None:
        return [seat]
    is_write = _is_write_quote_refusal(root, text, sha)
    if is_write is not None:
        return [is_write]
    no_write = _no_write_quote_refusal(root, text, sha)
    if no_write is not None:
        return [no_write]
    no_provider = _no_provider_quote_refusal(root, text, sha)
    if no_provider is not None:
        return [no_provider]
    parent_grant_doc = _parent_grant_doc_quote_refusal(root, text, sha)
    if parent_grant_doc is not None:
        return [parent_grant_doc]
    narrower = _narrower_quote_refusal(root, text, sha)
    if narrower is not None:
        return [narrower]
    child_grant_none = _child_grant_none_quote_refusal(root, text, sha)
    if child_grant_none is not None:
        return [child_grant_none]
    init_guard = _init_guard_quote_refusal(root, text, sha)
    if init_guard is not None:
        return [init_guard]
    project_resource = _project_resource_quote_refusal(root, text, sha)
    if project_resource is not None:
        return [project_resource]
    parent_compare = _parent_compare_quote_refusal(root, text, sha)
    if parent_compare is not None:
        return [parent_compare]
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
    condition = _append_condition_quote_refusal(root, text, sha)
    if condition is not None:
        return [condition]
    host_path = _host_path_err_quote_refusal(root, text, sha)
    if host_path is not None:
        return [host_path]
    held_err = _held_err_quote_refusal(root, text, sha)
    if held_err is not None:
        return [held_err]
    body_doc = _body_doc_quote_refusal(root, text, sha)
    if body_doc is not None:
        return [body_doc]
    create_only = _create_only_quote_refusal(root, text, sha)
    if create_only is not None:
        return [create_only]
    present_revision = _present_revision_quote_refusal(root, text, sha)
    if present_revision is not None:
        return [present_revision]
    append_cap = _append_cap_quote_refusal(root, text, sha)
    if append_cap is not None:
        return [append_cap]
    append_call = _append_call_quote_refusal(root, text, sha)
    if append_call is not None:
        return [append_call]
    outcome_held = _outcome_held_quote_refusal(root, text, sha)
    if outcome_held is not None:
        return [outcome_held]
    write_invoke = _write_invoke_quote_refusal(root, text, sha)
    if write_invoke is not None:
        return [write_invoke]
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
    if kind_append is not None:
        return [kind_append]
    cover = _cover_quote_refusal(root, text, sha)
    if cover is not None:
        return [cover]
    scheme = _scheme_quote_refusal(root, text, sha)
    if scheme is not None:
        return [scheme]
    read_action = _read_action_quote_refusal(root, text, sha)
    if read_action is not None:
        return [read_action]
    write_action = _write_action_quote_refusal(root, text, sha)
    if write_action is not None:
        return [write_action]
    default_action = _default_action_quote_refusal(root, text, sha)
    if default_action is None:
        return []
    return [default_action]


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
