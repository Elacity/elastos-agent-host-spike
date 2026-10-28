"""Citation refusals for the core-calls draft.

The tests call ``check.problems``. They do not compile a citation expression.
"""

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check

IDENTITY = {
    "GIT_AUTHOR_NAME": "citation-check",
    "GIT_AUTHOR_EMAIL": "citation-check@example.com",
    "GIT_COMMITTER_NAME": "citation-check",
    "GIT_COMMITTER_EMAIL": "citation-check@example.com",
}

OWNED_REL = "examples/agent-host/src/lib.rs"
OWNED_NUMBER = 3754
OWNED_SPAN = "examples/agent-host/src/lib.rs:3754"
OWNED_QUOTE = "/// The one place a task journal lives. The guest names only `Users/self`."
NEXT_NUMBER = 3755
NEXT_SPAN = "examples/agent-host/src/lib.rs:3755"
NEXT_QUOTE = "/// The Runtime scopes that to the launching person."

MARKER_NUMBER = 8162
MARKER_REL = OWNED_REL
MARKER_SPAN = "examples/agent-host/src/lib.rs:8162"
MARKER_HEAD = "/// The one marker a declared pattern may hold: the user-namespace root,"
MARKER_TAIL = "/// `Users/<one name>`. The declaration names no person and no host path."
MARKER_CFG = "#[cfg(test)]"
MARKER_CONST = 'const PRINCIPAL_MARKER: &str = "<principal>";'

LAUNCHING_NUMBER = 8168
LAUNCHING_SPAN = "examples/agent-host/src/lib.rs:8168"
LAUNCHING_HEAD = "/// The one principal a declared pattern may name. The guest names only"
LAUNCHING_SECOND = (
    "/// `Users/self`, which the Runtime scopes to the launching person, so the"
)
LAUNCHING_THIRD = "/// declaration covers that person and no other `Users/<name>`."
LAUNCHING_CFG = "#[cfg(test)]"
LAUNCHING_CONST = 'const LAUNCHING_PRINCIPAL: &str = "Users/self";'

ASKS_REL = OWNED_REL
ASKS_NUMBER = 8149
ASKS_SPAN = "examples/agent-host/src/lib.rs:8149"
ASKS_FIRST = "/// The declared per-step asks, compiled in from `asks.json` in this lane. The"
ASKS_SECOND = "/// file is an auditable declaration, not the policy check: the Runtime"
ASKS_THIRD = "/// enforces each grant (P4, P18). It is a lane-local stand-in for the Runtime"
ASKS_FOURTH = "/// manifest and retires into that one place when the Runtime defines per-step"
ASKS_FIFTH = "/// asks (P10). It is read by this module's tests only, so the shipped guest"
ASKS_SIXTH = "/// keeps no new production path."
ASKS_CFG = "#[cfg(test)]"
ASKS_CONST = 'const ASKS_JSON: &str = include_str!("../asks.json");'

DENY_REL = OWNED_REL
DENY_NUMBER = 3526
DENY_SPAN = "examples/agent-host/src/lib.rs:3526"
DENY_LINES = (
    "/// A missing grant denies the step. A grant id is recorded and does not run it.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn authorize(journal: &mut Journal, id: u64, grant: Option<&str>) -> bool {",
    "    let Some(step) = journal.steps.iter_mut().find(|step| step.id == id) else {",
    "        return false;",
    "    };",
    "    if step.state != StepState::Prepared {",
    "        return false;",
    "    }",
    "    match grant {",
    '        None | Some("") => {',
    "            step.state = StepState::Denied;",
    "            step.grant = None;",
    "            false",
    "        }",
    "        Some(grant_id) => {",
    "            step.grant = Some(grant_id.to_string());",
    "            true",
    "        }",
    "    }",
    "}",
)
DENY_QUOTE = DENY_LINES[0]
DENY_SECOND = DENY_LINES[1]
DENY_LAST = DENY_LINES[-1]

MINT_REL = OWNED_REL
MINT_NUMBER = 3549
MINT_SPAN = "examples/agent-host/src/lib.rs:3549"
MINT_FIRST = "/// An inbox answer. Allow once, allow for the session, and standing all fail"
MINT_SECOND = "/// closed when no grant id was sent. The guest does not mint one. Deny stores"
MINT_THIRD = "/// no grant. A second answer does not replace the first, and it does not"
MINT_FOURTH = "/// authorize another step. A child cannot be answered with the parent's"
MINT_LAST = "/// grant. The answer name is kept in the log. The grant string is not."

JOURNAL_REL = OWNED_REL
JOURNAL_NUMBER = 3757
JOURNAL_SPAN = "examples/agent-host/src/lib.rs:3757"
JOURNAL_CFG = '#[cfg(any(test, target_arch = "wasm32"))]'
JOURNAL_CONST = 'const JOURNAL_ROOT: &str = "localhost://Users/self/.AppData/Agents/";'

GRANT_REL = OWNED_REL
GRANT_NUMBER = 3767
GRANT_SPAN = "examples/agent-host/src/lib.rs:3767"
GRANT_QUOTE = "/// A grant the Runtime gave this guest for its own journal, one resource and"
GRANT_SECOND = "/// one action. It is held in memory only: the journal format has no field for"
GRANT_THIRD = "/// it, and `Debug` does not print it."
GRANT_CFG = '#[cfg(any(test, target_arch = "wasm32"))]'
GRANT_STRUCT = "struct JournalGrant(String);"
GRANT_LINES = (
    GRANT_QUOTE,
    GRANT_SECOND,
    GRANT_THIRD,
    GRANT_CFG,
    GRANT_STRUCT,
    GRANT_CFG,
    "impl JournalGrant {",
    "    fn new(id: &str) -> Option<Self> {",
    "        (!id.is_empty()).then(|| Self(id.to_string()))",
    "    }",
    "    fn id(&self) -> &str {",
    "        &self.0",
    "    }",
    "}",
)


ASK_REL = OWNED_REL
WRITE_NUMBER = 3849
WRITE_SPAN = "examples/agent-host/src/lib.rs:3849"
WRITE_QUOTE = '    let write = ask("write");'
READ_NUMBER = 3850
READ_SPAN = "examples/agent-host/src/lib.rs:3850"
READ_QUOTE = '    let read = ask("read");'
ASK_LINES = (
    "/// Ask the Runtime for exactly two grants on this agent's own journal: write,",
    "/// then read. Nothing else is asked for. A refusal leaves that grant empty, so",
    "/// nothing is sent with it.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn request_journal_grants(bus: &mut impl ResourceBus, cursor: &JournalCursor) -> JournalGrants {",
    "    if !cursor.resource.starts_with(JOURNAL_ROOT) || host_path(&cursor.resource) {",
    "        return JournalGrants {",
    "            write: None,",
    "            read: None,",
    "        };",
    "    }",
    "    let mut ask = |action: &str| {",
    '        bus.request_grant(&cursor.resource, action, "Agent Host task journal")',
    "            .ok()",
    "            .and_then(|id| JournalGrant::new(&id))",
    "    };",
    WRITE_QUOTE,
    READ_QUOTE,
    "    JournalGrants { write, read }",
    "}",
)
ASK_BLOCK_START = WRITE_NUMBER - 16

KIND_REL = OWNED_REL
KIND_READ_NUMBER = 8187
KIND_READ_SPAN = "examples/agent-host/src/lib.rs:8187"
KIND_READ_QUOTE = '        ProposalKind::Read => Some("read"),'
KIND_EDIT_NUMBER = 8188
KIND_EDIT_SPAN = "examples/agent-host/src/lib.rs:8188"
KIND_EDIT_QUOTE = '        ProposalKind::Edit => Some("edit"),'
KIND_RUN_NUMBER = 8189
KIND_RUN_SPAN = "examples/agent-host/src/lib.rs:8189"
KIND_RUN_QUOTE = '        ProposalKind::Run => Some("run"),'
KIND_HOSTED_NUMBER = 8191
KIND_HOSTED_SPAN = "examples/agent-host/src/lib.rs:8191"
KIND_HOSTED_QUOTE = '        ProposalKind::Hosted => Some("hosted"),'
KIND_CHILD_NUMBER = 8192
KIND_CHILD_SPAN = "examples/agent-host/src/lib.rs:8192"
KIND_CHILD_QUOTE = '        ProposalKind::Child => Some("child"),'
KIND_INIT_NUMBER = 8193
KIND_INIT_SPAN = "examples/agent-host/src/lib.rs:8193"
KIND_INIT_QUOTE = '        ProposalKind::Init => Some("init"),'
KIND_APPEND_NUMBER = 8194
KIND_APPEND_SPAN = "examples/agent-host/src/lib.rs:8194"
KIND_APPEND_QUOTE = '        ProposalKind::JournalAppend => Some("journal-append"),'
KIND_RESTORE_NUMBER = 8190
KIND_RESTORE_SPAN = "examples/agent-host/src/lib.rs:8190"
KIND_RESTORE_QUOTE = '        ProposalKind::Restore => Some("restore"),'
KIND_LINES = (
    "/// The declared name of one kind. The match has no wildcard, so a new",
    "/// `ProposalKind` does not compile until it is named here or marked as the",
    "/// placeholder. `Unspecified` marks a step opened without a proposal and is",
    "/// not an ask.",
    "#[cfg(test)]",
    "fn ask_kind_name(kind: ProposalKind) -> Option<&'static str> {",
    "    match kind {",
    "        ProposalKind::Unspecified => None,",
    KIND_READ_QUOTE,
    KIND_EDIT_QUOTE,
    KIND_RUN_QUOTE,
    KIND_RESTORE_QUOTE,
    '        ProposalKind::Hosted => Some("hosted"),',
    '        ProposalKind::Child => Some("child"),',
    '        ProposalKind::Init => Some("init"),',
    '        ProposalKind::JournalAppend => Some("journal-append"),',
    "    }",
    "}",
)
KIND_BLOCK_START = KIND_READ_NUMBER - 8
KIND_BLOCK_END = KIND_BLOCK_START + len(KIND_LINES) - 1

# The five one-line arms, their pinned lines and their index in the 8187 walk.
KIND_LINE_ARMS = (
    ("run", KIND_RUN_NUMBER, KIND_RUN_SPAN, KIND_RUN_QUOTE, 10),
    ("hosted", KIND_HOSTED_NUMBER, KIND_HOSTED_SPAN, KIND_HOSTED_QUOTE, 12),
    ("child", KIND_CHILD_NUMBER, KIND_CHILD_SPAN, KIND_CHILD_QUOTE, 13),
    ("init", KIND_INIT_NUMBER, KIND_INIT_SPAN, KIND_INIT_QUOTE, 14),
    ("append", KIND_APPEND_NUMBER, KIND_APPEND_SPAN, KIND_APPEND_QUOTE, 15),
)

# The order in which the quote decisions read their pinned lines.
KIND_DECISION_ORDER = (
    KIND_READ_NUMBER,
    KIND_EDIT_NUMBER,
    KIND_RUN_NUMBER,
    KIND_RESTORE_NUMBER,
    KIND_HOSTED_NUMBER,
    KIND_CHILD_NUMBER,
    KIND_INIT_NUMBER,
    KIND_APPEND_NUMBER,
)

OBSERVE_NUMBER = 2067
OBSERVE_SPAN = "examples/agent-host/src/lib.rs:2067"
OBSERVE_LINES = (
    "/// Append a read. A path that `path_refusal` refuses, or the version",
    "/// u64::MAX, adds nothing. A higher version is a new read. An older version is allowed only when the",
    "/// text still matches that version, so a reread can make it current again",
    "/// without replacing the page. This does not start a series and does not",
    "/// read a file.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn observe(journal: &mut Journal, resource: &str, version: u64, text: &str) -> bool {",
    "    if path_refusal(resource).is_some()",
    "        || version == u64::MAX",
    "        || version_bound_elsewhere(&journal.events, resource, version, None)",
    "    {",
    "        return false;",
    "    }",
    "    if let Some(row) = current_observation(&journal.events, resource) {",
    "        if version <= row.version",
    "            && observed_text_at(&journal.events, resource, version).as_deref() != Some(text)",
    "        {",
    "            return false;",
    "        }",
    "    }",
    "    let epoch = journal.epoch;",
    "    journal",
    "        .events",
    "        .push(observation_record(resource, version, text));",
    "    journal.epoch == epoch",
    "}",
)
OBSERVE_QUOTE = OBSERVE_LINES[4]

REVISION_NUMBER = 2741
REVISION_SPAN = "examples/agent-host/src/lib.rs:2741"
OP_NUMBER = 2749
OP_SPAN = "examples/agent-host/src/lib.rs:2749"
REQUEST_LINES = (
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn request_body(bound: &[BoundEdit]) -> Vec<u8> {",
    "    let files: Vec<serde_json::Value> = bound",
    "        .iter()",
    "        .map(|edit| {",
    "            serde_json::json!({",
    '                "path": edit.resource,',
    '                "if_revision": edit.revision,',
    '                "first_line": edit.first_line,',
    '                "line_count": line_count(&edit.run),',
    '                "old": edit.old,',
    '                "new": edit.new,',
    "            })",
    "        })",
    "        .collect();",
    '    serde_json::json!({ "op": "edit", "all_or_none": true, "files": files })',
    "        .to_string()",
    "        .into_bytes()",
    "}",
)
REVISION_QUOTE = REQUEST_LINES[7]
OP_QUOTE = REQUEST_LINES[15]

NO_WRITE_NUMBER = 3308
NO_WRITE_SPAN = "examples/agent-host/src/lib.rs:3308"
NO_WRITE_LINES = (
    "/// Propose restoring an observed version. An unknown version, or a version",
    "/// that is no longer current, creates no step. The step keeps the observed",
    "/// text as the text to replace and as the text to write, so a granted",
    "/// dispatch sends the restore through the same `bind_change` and",
    "/// `note_change_wrote` path an edit uses. This does not write.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn propose_restore(",
    "    journal: &mut Journal,",
    "    resource: &str,",
    "    version: u64,",
    ") -> Result<u64, &'static str> {",
    "    let Some(text) = observed_text_at(&journal.events, resource, version) else {",
    '        return Err("unknown");',
    "    };",
    "    let Some(current) = current_observation(&journal.events, resource) else {",
    '        return Err("unknown");',
    "    };",
    "    if current.version != version {",
    '        return Err("stale");',
    "    }",
    "    let id = propose_step(journal);",
    "    let step = journal",
    "        .steps",
    "        .iter_mut()",
    "        .find(|step| step.id == id)",
    '        .expect("just pushed");',
    "    step.kind = ProposalKind::Restore;",
    "    step.resource = resource.to_string();",
    "    step.old = text.clone();",
    "    step.new = text;",
    "    step.seen_version = Some(version);",
    "    Ok(id)",
    "}",
)
NO_WRITE_QUOTE = NO_WRITE_LINES[4]

COVER_NUMBER = 8488
COVER_SPAN = "examples/agent-host/src/lib.rs:8488"
COVER_LINES = (
    "/// The declaration's answer for one proposal. `Unspecified` matches nothing.",
    "#[cfg(test)]",
    "fn declared_ask(kind: ProposalKind, resource: &str) -> bool {",
    "    declared_asks()",
    "        .iter()",
    "        .any(|ask| ask.kind == kind && ask_covers(ask, resource))",
    "}",
)
COVER_QUOTE = COVER_LINES[5]

EDIT_RANGE_SPAN = "examples/agent-host/src/lib.rs:2421-2422"
EDIT_START_NUMBER = 2421
EDIT_START_SPAN = "examples/agent-host/src/lib.rs:2421"
EDIT_END_NUMBER = 2422
EDIT_END_SPAN = "examples/agent-host/src/lib.rs:2422"
EDIT_LINES = (
    "/// Record an edit proposal. An unread target, a stale version, empty old",
    "/// text, old text that is not exactly once in what that version has shown",
    "/// (a read that showed a window covers only that window), or a no-op edit",
    "/// repeated past the limit creates no step. A path that is not canonical or",
    "/// not NFC is refused. Every refusal writes one refusal record. This does not",
    "/// write.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn propose_edit(",
    "    journal: &mut Journal,",
    "    resource: &str,",
    "    old: &str,",
    "    new: &str,",
    "    seen: Option<u64>,",
    ") -> Result<u64, &'static str> {",
    "    let result = propose_edit_checked(journal, resource, old, new, seen);",
    "    result.map_err(|refusal| {",
    "        record_refusal(journal, refusal, &refused_path(resource));",
    "        refusal.reason()",
    "    })",
    "}",
)
EDIT_START_QUOTE = EDIT_LINES[4]
EDIT_END_QUOTE = EDIT_LINES[5]

REQUEST_WALK_NUMBER = 2720
REQUEST_WALK_SPAN = "examples/agent-host/src/lib.rs:2720"
REQUEST_WALK_LINES = (
    "/// The one provider request for a change or a restore: every file, each with",
    "/// the Runtime revision it was read at (`if_revision`), the lines it may",
    "/// touch, and the text to replace there. The provider applies all files or",
    "/// none. A change that does not bind sends nothing and writes one refusal",
    "/// record.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn edit_request(journal: &mut Journal, effect_id: u64) -> Result<Vec<u8>, &'static str> {",
    "    let result = bind_change(journal, effect_id);",
    "    result.map(|bound| request_body(&bound)).map_err(|refusal| {",
    '        record_refusal(journal, refusal, &format!("change {effect_id}"));',
    "        refusal.reason()",
    "    })",
    "}",
)
REQUEST_QUOTE = REQUEST_WALK_LINES[0]

IS_WRITE_NUMBER = 3290
IS_WRITE_SPAN = "examples/agent-host/src/lib.rs:3290"
IS_WRITE_LINES = (
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn is_write(kind: ProposalKind) -> bool {",
    "    matches!(kind, ProposalKind::Edit | ProposalKind::Restore)",
    "}",
)
IS_WRITE_QUOTE = IS_WRITE_LINES[2]

# The four edit-walk quotes, their pinned lines, their walk and their index.
EDIT_CASES = (
    ("edit_start", EDIT_START_NUMBER, EDIT_START_SPAN, EDIT_LINES, 4),
    ("edit_end", EDIT_END_NUMBER, EDIT_END_SPAN, EDIT_LINES, 5),
    ("request", REQUEST_WALK_NUMBER, REQUEST_WALK_SPAN, REQUEST_WALK_LINES, 0),
    ("is_write", IS_WRITE_NUMBER, IS_WRITE_SPAN, IS_WRITE_LINES, 2),
)

# The groups one combined edit body cites, in the order it emits them.
EDIT_GROUPS = (
    "observe",
    "range",
    "request_walk",
    "revision",
    "op",
    "is_write",
    "no_write",
    "deny",
)

# The order in which the edit-walk quote decisions read their pinned lines.
EDIT_DECISION_ORDER = (
    OBSERVE_NUMBER,
    EDIT_START_NUMBER,
    EDIT_END_NUMBER,
    REQUEST_WALK_NUMBER,
    REVISION_NUMBER,
    OP_NUMBER,
    IS_WRITE_NUMBER,
    NO_WRITE_NUMBER,
    DENY_NUMBER,
)

RUN_REL = OWNED_REL
NO_PROCESS_NUMBER = 2958
NO_PROCESS_SPAN = "examples/agent-host/src/lib.rs:2958"
SEAT_NUMBER = 2981
SEAT_SPAN = "examples/agent-host/src/lib.rs:2981"
RUN_LINES = (
    "/// Record a run proposal. The resource is a `localhost://` project. Arguments",
    "/// stay data. A host path creates no step. This does not start a process.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn propose_run(",
    "    journal: &mut Journal,",
    "    resource: &str,",
    "    argv: &[String],",
    ") -> Result<u64, &'static str> {",
    '    if !resource.starts_with("localhost://")',
    "        || resource.chars().any(char::is_whitespace)",
    "        || host_path(resource)",
    "        || argv.iter().any(|arg| host_path(arg))",
    "    {",
    '        return Err("host path");',
    "    }",
    "    let id = propose_step(journal);",
    "    let step = journal",
    "        .steps",
    "        .iter_mut()",
    "        .find(|step| step.id == id)",
    '        .expect("just pushed");',
    "    step.kind = ProposalKind::Run;",
    "    step.resource = resource.to_string();",
    "    step.argv = argv.to_vec();",
    '    step.seat = "microvm".to_string();',
    "    Ok(id)",
    "}",
)
NO_PROCESS_QUOTE = RUN_LINES[1]
SEAT_QUOTE = RUN_LINES[24]

BODY_DOC_NUMBER = 3961
BODY_DOC_SPAN = "examples/agent-host/src/lib.rs:3961"
CREATE_ONLY_NUMBER = 3966
CREATE_ONLY_SPAN = "examples/agent-host/src/lib.rs:3966"
PRESENT_REVISION_NUMBER = 3967
PRESENT_REVISION_SPAN = "examples/agent-host/src/lib.rs:3967"
WRITE_BODY_LINES = (
    "/// The write body the Runtime bridge reads: the whole encoding as `content`,",
    "/// and `create_only` for the first version or `if_revision` after that.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn journal_write_body(bytes: &[u8], revision: Option<&str>) -> Vec<u8> {",
    "    let body = match revision {",
    '        None => serde_json::json!({ "content": bytes, "create_only": true }),',
    '        Some(revision) => serde_json::json!({ "content": bytes, "if_revision": revision }),',
    "    };",
    "    body.to_string().into_bytes()",
    "}",
)
BODY_DOC_QUOTE = WRITE_BODY_LINES[0]
CREATE_ONLY_QUOTE = WRITE_BODY_LINES[5]
PRESENT_REVISION_QUOTE = WRITE_BODY_LINES[6]

APPEND_CONDITION_NUMBER = 3935
APPEND_CONDITION_SPAN = "examples/agent-host/src/lib.rs:3935"
HOST_PATH_ERR_NUMBER = 3936
HOST_PATH_ERR_SPAN = "examples/agent-host/src/lib.rs:3936"
HELD_ERR_NUMBER = 3947
HELD_ERR_SPAN = "examples/agent-host/src/lib.rs:3947"
APPEND_CAP_NUMBER = 4023
APPEND_CAP_SPAN = "examples/agent-host/src/lib.rs:4023"
APPEND_CALL_NUMBER = 4032
APPEND_CALL_SPAN = "examples/agent-host/src/lib.rs:4032"
APPEND_RANGE_SPAN = "examples/agent-host/src/lib.rs:4032-4033"
OUTCOME_HELD_NUMBER = 4033
OUTCOME_HELD_SPAN = "examples/agent-host/src/lib.rs:4033"
WRITE_INVOKE_NUMBER = 4061
WRITE_INVOKE_SPAN = "examples/agent-host/src/lib.rs:4061"

# The one propose_journal_append walk, as the live draft indents it.
APPEND_WALK_LINES = (
    "/// An append records a step. It waits while an earlier append has no result,",
    "/// so a lost reply is never followed by a second write.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn propose_journal_append(",
    "    journal: &mut Journal,",
    "    cursor: &JournalCursor,",
    ") -> Result<u64, &'static str> {",
    "    if !cursor.resource.starts_with(JOURNAL_ROOT) || host_path(&cursor.resource) {",
    '        return Err("host path");',
    "    }",
    "    let open = journal.steps.iter().any(|step| {",
    "        step.kind == ProposalKind::JournalAppend",
    "            && !step.has_result",
    "            && matches!(",
    "                step.state,",
    "                StepState::Prepared | StepState::Dispatched | StepState::SettlementUnknown",
    "            )",
    "    });",
    "    if cursor.pending.is_some() || cursor.stale || open {",
    '        return Err("held");',
    "    }",
    "    let id = propose_step(journal);",
    "    let step = journal",
    "        .steps",
    "        .iter_mut()",
    "        .find(|step| step.id == id)",
    '        .expect("just pushed");',
    "    step.kind = ProposalKind::JournalAppend;",
    "    step.resource = cursor.resource.clone();",
    "    step.old = cursor.revision.clone().unwrap_or_default();",
    "    Ok(id)",
    "}",
)
APPEND_CONDITION_QUOTE = APPEND_WALK_LINES[7]
HOST_PATH_ERR_QUOTE = APPEND_WALK_LINES[8]
HELD_ERR_QUOTE = APPEND_WALK_LINES[19]

# The one append_journal walk, as the live draft indents it.
DOC_WALK_LINES = (
    "/// Write the whole journal as the next version, with the journal write grant.",
    "/// No grant, an open append, or a journal over the cap sends nothing. The",
    "/// stored copy shows this step as dispatched with no result.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn append_journal(",
    "    bus: &mut impl ResourceBus,",
    "    journal: &mut Journal,",
    "    cursor: &mut JournalCursor,",
    "    grant: Option<&JournalGrant>,",
    ") -> AppendOutcome {",
    "    let Ok(id) = propose_journal_append(journal, cursor) else {",
    "        return AppendOutcome::Held;",
    "    };",
    '    let reply = bus.invoke(&cursor.resource, "write", &body, grant.id());',
)
APPEND_CAP_QUOTE = DOC_WALK_LINES[1]
APPEND_CALL_QUOTE = DOC_WALK_LINES[10]
OUTCOME_HELD_QUOTE = DOC_WALK_LINES[11]
WRITE_INVOKE_QUOTE = DOC_WALK_LINES[13]

# The seven append quotes, their pinned lines, their walk and their index.
APPEND_CASES = (
    (
        "append_condition",
        APPEND_CONDITION_NUMBER,
        APPEND_CONDITION_SPAN,
        APPEND_WALK_LINES,
        7,
    ),
    (
        "host_path_err",
        HOST_PATH_ERR_NUMBER,
        HOST_PATH_ERR_SPAN,
        APPEND_WALK_LINES,
        8,
    ),
    (
        "held_err",
        HELD_ERR_NUMBER,
        HELD_ERR_SPAN,
        APPEND_WALK_LINES,
        19,
    ),
    (
        "append_cap",
        APPEND_CAP_NUMBER,
        APPEND_CAP_SPAN,
        DOC_WALK_LINES,
        1,
    ),
    (
        "append_call",
        APPEND_CALL_NUMBER,
        APPEND_CALL_SPAN,
        DOC_WALK_LINES,
        10,
    ),
    (
        "outcome_held",
        OUTCOME_HELD_NUMBER,
        OUTCOME_HELD_SPAN,
        DOC_WALK_LINES,
        11,
    ),
    (
        "write_invoke",
        WRITE_INVOKE_NUMBER,
        WRITE_INVOKE_SPAN,
        DOC_WALK_LINES,
        13,
    ),
)

# The append decisions read their pinned lines in this order.
APPEND_DECISION_ORDER = (
    APPEND_CONDITION_NUMBER,
    HOST_PATH_ERR_NUMBER,
    HELD_ERR_NUMBER,
    APPEND_CAP_NUMBER,
    APPEND_CALL_NUMBER,
    OUTCOME_HELD_NUMBER,
    WRITE_INVOKE_NUMBER,
)

# The groups one append body cites, in the order it emits them.
APPEND_GROUPS = ("condition", "doc")

# One correct pinned line for every append decision the body cites.
APPEND_LINES = {
    APPEND_CONDITION_NUMBER: APPEND_CONDITION_QUOTE,
    HOST_PATH_ERR_NUMBER: HOST_PATH_ERR_QUOTE,
    HELD_ERR_NUMBER: HELD_ERR_QUOTE,
    APPEND_CAP_NUMBER: APPEND_CAP_QUOTE,
    APPEND_CALL_NUMBER: APPEND_CALL_QUOTE,
    OUTCOME_HELD_NUMBER: OUTCOME_HELD_QUOTE,
    WRITE_INVOKE_NUMBER: WRITE_INVOKE_QUOTE,
}

# The five run and write-body quotes, their pinned lines, walk and index.
RUN_BODY_CASES = (
    ("no_process", NO_PROCESS_NUMBER, NO_PROCESS_SPAN, RUN_LINES, 1),
    ("seat", SEAT_NUMBER, SEAT_SPAN, RUN_LINES, 24),
    ("body_doc", BODY_DOC_NUMBER, BODY_DOC_SPAN, WRITE_BODY_LINES, 0),
    ("create_only", CREATE_ONLY_NUMBER, CREATE_ONLY_SPAN, WRITE_BODY_LINES, 5),
    (
        "present_revision",
        PRESENT_REVISION_NUMBER,
        PRESENT_REVISION_SPAN,
        WRITE_BODY_LINES,
        6,
    ),
)

# The run and write-body decisions read their pinned lines in this order.
RUN_BODY_DECISION_ORDER = (
    NO_PROCESS_NUMBER,
    SEAT_NUMBER,
    BODY_DOC_NUMBER,
    CREATE_ONLY_NUMBER,
    PRESENT_REVISION_NUMBER,
)

# The five file-ask quotes, their pinned lines, their walk and their index.
FILE_ASK_CASES = (
    ("observe", OBSERVE_NUMBER, OBSERVE_SPAN, OBSERVE_LINES, 4),
    ("revision", REVISION_NUMBER, REVISION_SPAN, REQUEST_LINES, 7),
    ("op", OP_NUMBER, OP_SPAN, REQUEST_LINES, 15),
    ("no_write", NO_WRITE_NUMBER, NO_WRITE_SPAN, NO_WRITE_LINES, 4),
    ("cover", COVER_NUMBER, COVER_SPAN, COVER_LINES, 5),
)

# The groups one combined body cites, in the order it emits them.
FILE_ASK_GROUPS = (
    "observe",
    "revision",
    "op",
    "no_write",
    "deny",
    "mint",
    "owned",
    "journal",
    "grant",
    "ask",
    "asks",
    "marker",
    "launching",
    "kind",
    "arms",
    "cover",
)

# The order in which the quote decisions read their pinned lines.
QUOTE_DECISION_ORDER = (
    OBSERVE_NUMBER,
    REVISION_NUMBER,
    OP_NUMBER,
    NO_WRITE_NUMBER,
    DENY_NUMBER,
    MINT_NUMBER,
    OWNED_NUMBER,
    NEXT_NUMBER,
    JOURNAL_NUMBER,
    GRANT_NUMBER,
    WRITE_NUMBER,
    READ_NUMBER,
    ASKS_NUMBER,
    MARKER_NUMBER,
    LAUNCHING_NUMBER,
    KIND_READ_NUMBER,
    KIND_EDIT_NUMBER,
    KIND_RUN_NUMBER,
    KIND_RESTORE_NUMBER,
    KIND_HOSTED_NUMBER,
    KIND_CHILD_NUMBER,
    KIND_INIT_NUMBER,
    KIND_APPEND_NUMBER,
    COVER_NUMBER,
)

# One correct pinned line for every quote decision the combined body cites.
FILE_ASK_LINES = {
    OBSERVE_NUMBER: OBSERVE_QUOTE,
    REVISION_NUMBER: REVISION_QUOTE,
    OP_NUMBER: OP_QUOTE,
    NO_WRITE_NUMBER: NO_WRITE_QUOTE,
    DENY_NUMBER: DENY_QUOTE,
    MINT_NUMBER: MINT_SECOND,
    OWNED_NUMBER: OWNED_QUOTE,
    NEXT_NUMBER: NEXT_QUOTE,
    JOURNAL_NUMBER: JOURNAL_CONST,
    GRANT_NUMBER: GRANT_QUOTE,
    WRITE_NUMBER: WRITE_QUOTE,
    READ_NUMBER: READ_QUOTE,
    NO_PROCESS_NUMBER: NO_PROCESS_QUOTE,
    SEAT_NUMBER: SEAT_QUOTE,
    BODY_DOC_NUMBER: BODY_DOC_QUOTE,
    CREATE_ONLY_NUMBER: CREATE_ONLY_QUOTE,
    PRESENT_REVISION_NUMBER: PRESENT_REVISION_QUOTE,
    ASKS_NUMBER: ASKS_THIRD,
    MARKER_NUMBER: MARKER_CONST,
    LAUNCHING_NUMBER: LAUNCHING_CONST,
    KIND_READ_NUMBER: KIND_READ_QUOTE,
    KIND_EDIT_NUMBER: KIND_EDIT_QUOTE,
    KIND_RUN_NUMBER: KIND_RUN_QUOTE,
    KIND_RESTORE_NUMBER: KIND_RESTORE_QUOTE,
    KIND_HOSTED_NUMBER: KIND_HOSTED_QUOTE,
    KIND_CHILD_NUMBER: KIND_CHILD_QUOTE,
    KIND_INIT_NUMBER: KIND_INIT_QUOTE,
    KIND_APPEND_NUMBER: KIND_APPEND_QUOTE,
    COVER_NUMBER: COVER_QUOTE,
    EDIT_START_NUMBER: EDIT_START_QUOTE,
    EDIT_END_NUMBER: EDIT_END_QUOTE,
    REQUEST_WALK_NUMBER: REQUEST_QUOTE,
    IS_WRITE_NUMBER: IS_WRITE_QUOTE,
}

PROVIDER_REL = "elastos/crates/elastos-server/src/provider_resource.rs"

SCHEME_NUMBER = 123
SCHEME_SPAN = PROVIDER_REL + ":123"
SCHEME_LINES = (
    "/// Canonical capability action for provider operations where the Runtime owns",
    "/// the operation-to-action contract directly.",
    "pub fn provider_operation_action(scheme: &str, op: &str) -> Option<Action> {",
    "    #[cfg(test)]",
    '    if scheme == "test" {',
    "        return (op == \"read\").then_some(Action::Read);",
    "    }",
    "    match scheme {",
    '        "localhost" | "webspace" => localhost_op_required_action(op),',
    '        "did" => execute_op_required_action(op),',
    '        "availability" => match op {',
    '            "status" => Some(Action::Read),',
    '            "ensure" => Some(Action::Write),',
    "            _ => None,",
    "        },",
    '        "block-graph" => match op {',
    '            "status" | "export_graph" => Some(Action::Read),',
    '            "import_graph" => Some(Action::Write),',
    "            _ => None,",
    "        },",
    '        "chain" => chain_op_required_action(op),',
    '        "content" => match op {',
    '            "status" | "fetch" => Some(Action::Read),',
    '            "publish" | "ensure" | "repair" | "unpublish" => Some(Action::Write),',
    "            _ => None,",
    "        },",
    '        "drm" | "rights" | "key" | "decrypt" => read_only_provider_action(op),',
    '        "net" => match op {',
    '            "status" | "resolve" => Some(Action::Read),',
    '            "connect" | "stream" | "http" => Some(Action::Write),',
    "            _ => None,",
    "        },",
    '        "exit" => match op {',
    '            "status" | "discover_remote_carrier_exits" | "quote" => Some(Action::Read),',
    '            "open_stream" | "close_stream" | "http_fetch" => Some(Action::Write),',
    "            _ => None,",
    "        },",
    '        "browser-engine" => match op {',
    '            "status" | "readiness" | "page_status" | "diagnostics" | "inspect" => {',
    "                Some(Action::Read)",
    "            }",
    '            "launch" | "attach_stream" | "input" | "webrtc_signal" => Some(Action::Write),',
    '            "close_page" => Some(Action::Delete),',
    "            _ => None,",
    "        },",
    '        "wallet" => wallet_op_required_action(op),',
    '        "ipfs" => ipfs_op_required_action(op),',
    '        "model" => match op {',
    '            "offers_list" | "runs_get" | "runs_events" => Some(Action::Read),',
    '            "runs_create" | "runs_cancel" => Some(Action::Execute),',
    "            _ => None,",
    "        },",
    '        "object" => object_op_required_action(op),',
    '        "operator-drive-adapter" => match op {',
    '            "status" | "metadata_index" | "read_bytes" => Some(Action::Read),',
    '            "write_bytes" => Some(Action::Write),',
    "            _ => None,",
    "        },",
    '        "peer" => match op {',
    '            "init" | "connect" | "remember_peer" | "gossip_join" | "gossip_leave"',
    '            | "gossip_send" | "get_ticket" | "get_node_id" | "list_peers" | "list_topics"',
    '            | "list_topic_peers" | "gossip_join_peers" | "gossip_recv" => Some(Action::Message),',
    "            _ => None,",
    "        },",
    '        "tunnel" => {',
    '            Some(Action::Admin).filter(|_| matches!(op, "start" | "stop" | "status" | "ping"))',
    "        }",
    '        "inspect" => inspect_op_required_action(op),',
    "        _ => None,",
    "    }",
    "}",
)
SCHEME_QUOTE = SCHEME_LINES[8]

READ_ACTION_NUMBER = 189
READ_ACTION_SPAN = PROVIDER_REL + ":189"
READ_ACTION_LINES = (
    '        "read" | "list" | "stat" | "exists" | "resolve" | "ping" => Some(Action::Read),',
)
READ_ACTION_QUOTE = READ_ACTION_LINES[0]

WRITE_ACTION_NUMBER = 190
WRITE_ACTION_SPAN = PROVIDER_REL + ":190"
WRITE_ACTION_LINES = (
    "fn localhost_op_required_action(op: &str) -> Option<Action> {",
    "    match op {",
    '        "read" | "list" | "stat" | "exists" | "resolve" | "ping" => Some(Action::Read),',
    '        "write" | "mkdir" => Some(Action::Write),',
    '        "delete" => Some(Action::Delete),',
    "        _ => None,",
    "    }",
    "}",
)
WRITE_ACTION_QUOTE = WRITE_ACTION_LINES[3]

DEFAULT_ACTION_NUMBER = 192
DEFAULT_ACTION_SPAN = PROVIDER_REL + ":192"
DEFAULT_ACTION_QUOTE = WRITE_ACTION_LINES[5]

# The four provider quotes, their pinned lines, their walk and their index.
PROVIDER_CASES = (
    ("scheme", SCHEME_NUMBER, SCHEME_SPAN, SCHEME_LINES, 8),
    ("read_action", READ_ACTION_NUMBER, READ_ACTION_SPAN, READ_ACTION_LINES, 0),
    ("write_action", WRITE_ACTION_NUMBER, WRITE_ACTION_SPAN, WRITE_ACTION_LINES, 3),
    ("default_action", DEFAULT_ACTION_NUMBER, DEFAULT_ACTION_SPAN, WRITE_ACTION_LINES, 5),
)

# The groups one provider body cites, in the order it emits them.
PROVIDER_GROUPS = ("scheme", "read_action", "write_action", "default_action")

# The order in which the provider decisions read their pinned lines.
PROVIDER_DECISION_ORDER = (
    SCHEME_NUMBER,
    READ_ACTION_NUMBER,
    WRITE_ACTION_NUMBER,
    DEFAULT_ACTION_NUMBER,
)

# One correct pinned line for every provider decision.
PROVIDER_LINES = {
    SCHEME_NUMBER: SCHEME_QUOTE,
    READ_ACTION_NUMBER: READ_ACTION_QUOTE,
    WRITE_ACTION_NUMBER: WRITE_ACTION_QUOTE,
    DEFAULT_ACTION_NUMBER: DEFAULT_ACTION_QUOTE,
}

NO_PROVIDER_NUMBER = 3339
NO_PROVIDER_SPAN = "examples/agent-host/src/lib.rs:3339"
NO_PROVIDER_LINES = (
    "/// Record a hosted model proposal. The resource names the model. There is",
    "/// no secret field. This does not call a provider.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn propose_hosted(journal: &mut Journal, resource: &str) -> Result<u64, &'static str> {",
    '    if !resource.starts_with("localhost://")',
    "        || resource.chars().any(char::is_whitespace)",
    "        || host_path(resource)",
    "    {",
    '        return Err("host path");',
    "    }",
    "    let id = propose_step(journal);",
    "    let step = journal",
    "        .steps",
    "        .iter_mut()",
    "        .find(|step| step.id == id)",
    '        .expect("just pushed");',
    "    step.kind = ProposalKind::Hosted;",
    "    step.resource = resource.to_string();",
    "    Ok(id)",
    "}",
)
NO_PROVIDER_QUOTE = NO_PROVIDER_LINES[1]

CHILD_NUMBER = 3360
CHILD_SPAN = "examples/agent-host/src/lib.rs:3360"
NARROWER_NUMBER = 3370
NARROWER_SPAN = "examples/agent-host/src/lib.rs:3370"
CHILD_GRANT_NONE_NUMBER = 3382
CHILD_GRANT_NONE_SPAN = "examples/agent-host/src/lib.rs:3382"
CHILD_LINES = (
    "/// A child is a separate step. Its resource must sit under the parent's",
    "/// resource. It does not copy the parent's grant.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn propose_child(",
    "    journal: &mut Journal,",
    "    parent_id: u64,",
    "    resource: &str,",
    ") -> Result<u64, &'static str> {",
    "    let Some(parent) = journal.steps.iter().find(|step| step.id == parent_id) else {",
    '        return Err("no parent");',
    "    };",
    "    if parent.resource.is_empty() || !narrower_resource(&parent.resource, resource) {",
    '        return Err("not a subset");',
    "    }",
    "    let id = propose_step(journal);",
    "    let step = journal",
    "        .steps",
    "        .iter_mut()",
    "        .find(|step| step.id == id)",
    '        .expect("just pushed");',
    "    step.kind = ProposalKind::Child;",
    "    step.resource = resource.to_string();",
    "    step.parent_id = Some(parent_id);",
    "    step.grant = None;",
    "    Ok(id)",
    "}",
)
PARENT_GRANT_DOC_QUOTE = CHILD_LINES[1]
NARROWER_QUOTE = CHILD_LINES[11]
CHILD_GRANT_NONE_QUOTE = CHILD_LINES[23]

PROJECT_NUMBER = 3387
PROJECT_SPAN = "examples/agent-host/src/lib.rs:3387"
PROJECT_RESOURCE_NUMBER = 3403
PROJECT_RESOURCE_SPAN = "examples/agent-host/src/lib.rs:3403"
PROJECT_LINES = (
    "/// Record a project proposal. The resource is a `localhost://` project name.",
    "/// A host path or a slash inside the root or the name creates no step.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn propose_init(journal: &mut Journal, root: &str, name: &str) -> Result<u64, &'static str> {",
    "    if root.is_empty()",
    "        || name.is_empty()",
    "        || root",
    "            .chars()",
    "            .any(|ch| ch.is_whitespace() || ch == '/' || ch == '\\\\')",
    "        || name",
    "            .chars()",
    "            .any(|ch| ch.is_whitespace() || ch == '/' || ch == '\\\\')",
    "        || host_path(root)",
    "        || host_path(name)",
    "    {",
    '        return Err("host path");',
    "    }",
    '    let resource = format!("localhost://Users/{root}/Projects/{name}");',
    "    let id = propose_step(journal);",
    "    let step = journal",
    "        .steps",
    "        .iter_mut()",
    "        .find(|step| step.id == id)",
    '        .expect("just pushed");',
    "    step.kind = ProposalKind::Init;",
    "    step.resource = resource;",
    "    Ok(id)",
    "}",
)
INIT_GUARD_QUOTE = PROJECT_LINES[1]
PROJECT_RESOURCE_QUOTE = PROJECT_LINES[17]

AUTHORIZE_NUMBER = 3449
AUTHORIZE_SPAN = "examples/agent-host/src/lib.rs:3449"
AUTHORIZE_LINES = (
    "/// Give a child its own grant. The parent's grant string is refused, and the",
    "/// child stays prepared. This does not start a process.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn authorize_child(journal: &mut Journal, child_id: u64, grant: Option<&str>) -> bool {",
    "    let Some(child) = journal.steps.iter().find(|step| step.id == child_id) else {",
    "        return false;",
    "    };",
    "    if child.kind != ProposalKind::Child {",
    "        return false;",
    "    }",
    "    let parent_grant = child.parent_id.and_then(|parent_id| {",
    "        journal",
    "            .steps",
    "            .iter()",
    "            .find(|step| step.id == parent_id)",
    "            .and_then(|step| step.grant.clone())",
    "    });",
    '    if grant.is_none() || grant == Some("") || parent_grant.as_deref() == grant {',
    "        return false;",
    "    }",
    "    authorize(journal, child_id, grant)",
    "}",
)
PARENT_COMPARE_QUOTE = AUTHORIZE_LINES[17]

CHILD_HOST_DOC_NUMBER = 3455
CHILD_HOST_DOC_SPAN = "examples/agent-host/src/lib.rs:3455"
CHILD_HOST_WALK = (
    "/// A child host is a second journal. It keeps the system head and does not",
    "/// copy the parent's log or the parent's grant. This is not a second loaded",
    "/// component, and it does not start a process.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn open_child_host(",
    "    parent: &Journal,",
    "    parent_id: u64,",
    "    resource: &str,",
    ") -> Result<Journal, &'static str> {",
    "    let Some(parent_step) = parent.steps.iter().find(|step| step.id == parent_id) else {",
    '        return Err("no parent");',
    "    };",
    "    if parent_step.resource.is_empty() || !narrower_resource(&parent_step.resource, resource) {",
    '        return Err("not a subset");',
    "    }",
    "    let mut child = empty_journal();",
    "    admit_system(&mut child, SYSTEM_HEAD, true);",
)
CHILD_HOST_DOC_QUOTE = CHILD_HOST_WALK[0]

EMPTY_JOURNAL_NUMBER = 3470
EMPTY_JOURNAL_SPAN = "examples/agent-host/src/lib.rs:3470"
EMPTY_JOURNAL_QUOTE = CHILD_HOST_WALK[15]

ADMIT_SYSTEM_NUMBER = 3471
ADMIT_SYSTEM_SPAN = "examples/agent-host/src/lib.rs:3471"
ADMIT_SYSTEM_QUOTE = CHILD_HOST_WALK[16]

INHERITED_ERR_NUMBER = 3474
INHERITED_ERR_SPAN = "examples/agent-host/src/lib.rs:3474"
INHERITED_ERR_WALK = (
    "    if child.steps.iter().any(|step| step.grant.is_some()) {",
    '        return Err("inherited");',
    "    }",
    "    Ok(child)",
    "}",
)
INHERITED_ERR_QUOTE = INHERITED_ERR_WALK[1]

GRANT_PARENT_NUMBER = 3482
GRANT_PARENT_SPAN = "examples/agent-host/src/lib.rs:3482"
GRANT_PARENT_WALK = (
    "/// Give the child host its own grant. The parent's grant is refused.",
    '#[cfg(any(test, target_arch = "wasm32"))]',
    "fn grant_child_host(child: &mut Journal, parent_grant: Option<&str>, grant: Option<&str>) -> bool {",
    '    if grant.is_none() || grant == Some("") || grant == parent_grant {',
    "        return false;",
    "    }",
    "    let Some(id) = child",
    "        .steps",
    "        .iter()",
    "        .find(|step| {",
    "            step.kind == ProposalKind::Run",
    "                && step.grant.is_none()",
    "                && step.state == StepState::Prepared",
    "        })",
    "        .map(|step| step.id)",
    "    else {",
    "        return false;",
    "    };",
    "    authorize(child, id, grant)",
    "}",
)
GRANT_PARENT_QUOTE = GRANT_PARENT_WALK[3]

EXEC_REL = "elastos/crates/elastos-compute/src/exec_vm.rs"
EXEC_NUMBER = 43
EXEC_SPAN = EXEC_REL + ":" + str(EXEC_NUMBER)

# The twelve hosted, child and project quotes, their pinned lines and index.
HOSTED_CASES = (
    ("no_provider", NO_PROVIDER_NUMBER, NO_PROVIDER_SPAN, NO_PROVIDER_LINES, 1),
    ("parent_grant_doc", CHILD_NUMBER, CHILD_SPAN, CHILD_LINES, 1),
    ("narrower", NARROWER_NUMBER, NARROWER_SPAN, CHILD_LINES, 11),
    (
        "child_grant_none",
        CHILD_GRANT_NONE_NUMBER,
        CHILD_GRANT_NONE_SPAN,
        CHILD_LINES,
        23,
    ),
    ("init_guard", PROJECT_NUMBER, PROJECT_SPAN, PROJECT_LINES, 1),
    (
        "project_resource",
        PROJECT_RESOURCE_NUMBER,
        PROJECT_RESOURCE_SPAN,
        PROJECT_LINES,
        17,
    ),
    ("parent_compare", AUTHORIZE_NUMBER, AUTHORIZE_SPAN, AUTHORIZE_LINES, 17),
    ("child_host_doc", CHILD_HOST_DOC_NUMBER, CHILD_HOST_DOC_SPAN, CHILD_HOST_WALK, 0),
    ("empty_journal", EMPTY_JOURNAL_NUMBER, EMPTY_JOURNAL_SPAN, CHILD_HOST_WALK, 15),
    ("admit_system", ADMIT_SYSTEM_NUMBER, ADMIT_SYSTEM_SPAN, CHILD_HOST_WALK, 16),
    ("inherited_err", INHERITED_ERR_NUMBER, INHERITED_ERR_SPAN, INHERITED_ERR_WALK, 1),
    ("grant_parent", GRANT_PARENT_NUMBER, GRANT_PARENT_SPAN, GRANT_PARENT_WALK, 3),
)

# The order in which the hosted decisions read their pinned lines.
HOSTED_DECISION_ORDER = (
    NO_PROVIDER_NUMBER,
    CHILD_NUMBER,
    NARROWER_NUMBER,
    CHILD_GRANT_NONE_NUMBER,
    PROJECT_NUMBER,
    PROJECT_RESOURCE_NUMBER,
    AUTHORIZE_NUMBER,
    CHILD_HOST_DOC_NUMBER,
    EMPTY_JOURNAL_NUMBER,
    ADMIT_SYSTEM_NUMBER,
    INHERITED_ERR_NUMBER,
    GRANT_PARENT_NUMBER,
)

# The groups one hosted body cites, in the order it emits them.
HOSTED_GROUPS = (
    "no_write",
    "no_provider",
    "child",
    "init",
    "compare",
    "child_host_doc",
    "empty_journal",
    "admit_system",
    "inherited_err",
    "grant_parent",
    "deny",
    "mint",
    "cover",
    "provider",
)

# One correct pinned line for every hosted decision the body cites.
HOSTED_LINES = {
    NO_WRITE_NUMBER: NO_WRITE_QUOTE,
    NO_PROVIDER_NUMBER: NO_PROVIDER_QUOTE,
    CHILD_NUMBER: PARENT_GRANT_DOC_QUOTE,
    NARROWER_NUMBER: NARROWER_QUOTE,
    CHILD_GRANT_NONE_NUMBER: CHILD_GRANT_NONE_QUOTE,
    PROJECT_NUMBER: INIT_GUARD_QUOTE,
    PROJECT_RESOURCE_NUMBER: PROJECT_RESOURCE_QUOTE,
    AUTHORIZE_NUMBER: PARENT_COMPARE_QUOTE,
    CHILD_HOST_DOC_NUMBER: CHILD_HOST_DOC_QUOTE,
    EMPTY_JOURNAL_NUMBER: EMPTY_JOURNAL_QUOTE,
    ADMIT_SYSTEM_NUMBER: ADMIT_SYSTEM_QUOTE,
    INHERITED_ERR_NUMBER: INHERITED_ERR_QUOTE,
    GRANT_PARENT_NUMBER: GRANT_PARENT_QUOTE,
    DENY_NUMBER: DENY_QUOTE,
    MINT_NUMBER: MINT_SECOND,
    COVER_NUMBER: COVER_QUOTE,
}

# Every decision the hosted body reads, in order.
HOSTED_READ_ORDER = (
    (NO_WRITE_NUMBER,)
    + HOSTED_DECISION_ORDER
    + (DENY_NUMBER, MINT_NUMBER, COVER_NUMBER, SCHEME_NUMBER)
)

# The start line of each walk in the lib.rs fixtures, so a cited line has a
# window that contains it.
LIB_WALKS = (
    (OWNED_NUMBER, (OWNED_QUOTE, NEXT_QUOTE)),
    (DENY_NUMBER, DENY_LINES),
    (
        MINT_NUMBER - 1,
        (MINT_FIRST, MINT_SECOND, MINT_THIRD, MINT_FOURTH, MINT_LAST),
    ),
    (JOURNAL_NUMBER - 1, (JOURNAL_CFG, JOURNAL_CONST)),
    (GRANT_NUMBER, GRANT_LINES),
    (ASK_BLOCK_START, ASK_LINES),
    (
        ASKS_NUMBER - 2,
        (
            ASKS_FIRST,
            ASKS_SECOND,
            ASKS_THIRD,
            ASKS_FOURTH,
            ASKS_FIFTH,
            ASKS_SIXTH,
            ASKS_CFG,
            ASKS_CONST,
        ),
    ),
    (MARKER_NUMBER - 3, (MARKER_HEAD, MARKER_TAIL, MARKER_CFG, MARKER_CONST)),
    (
        LAUNCHING_NUMBER - 4,
        (
            LAUNCHING_HEAD,
            LAUNCHING_SECOND,
            LAUNCHING_THIRD,
            LAUNCHING_CFG,
            LAUNCHING_CONST,
        ),
    ),
    (KIND_BLOCK_START, KIND_LINES),
    (EDIT_START_NUMBER - 4, EDIT_LINES),
    (REQUEST_WALK_NUMBER, REQUEST_WALK_LINES),
    (IS_WRITE_NUMBER - 2, IS_WRITE_LINES),
    (NO_PROCESS_NUMBER - 1, RUN_LINES),
    (BODY_DOC_NUMBER, WRITE_BODY_LINES),
    (APPEND_CONDITION_NUMBER - 7, APPEND_WALK_LINES),
    (APPEND_CAP_NUMBER - 1, DOC_WALK_LINES),
    (NO_PROVIDER_NUMBER - 1, NO_PROVIDER_LINES),
    (CHILD_NUMBER - 1, CHILD_LINES),
    (PROJECT_NUMBER - 1, PROJECT_LINES),
    (AUTHORIZE_NUMBER - 17, AUTHORIZE_LINES),
    (CHILD_HOST_DOC_NUMBER, CHILD_HOST_WALK),
    (INHERITED_ERR_NUMBER - 1, INHERITED_ERR_WALK),
    (GRANT_PARENT_NUMBER - 3, GRANT_PARENT_WALK),
) + tuple(
    (number - index, lines)
    for _, number, _, lines, index in FILE_ASK_CASES
) + tuple(
    (number - index, lines)
    for _, number, _, lines, index in (EDIT_CASES + RUN_BODY_CASES + APPEND_CASES)
)

# The start line of each provider walk in the provider_resource.rs fixture.
PROVIDER_WALKS = (
    (SCHEME_NUMBER - 8, SCHEME_LINES),
    (READ_ACTION_NUMBER, READ_ACTION_LINES),
    (WRITE_ACTION_NUMBER - 3, WRITE_ACTION_LINES),
)


class CitationCheckTests(unittest.TestCase):
    def _temp_root(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "lab" / "bus-v2-proposal").mkdir(parents=True)
        return root

    def _write(self, root, body, files):
        (root / "lab" / "bus-v2-proposal" / "CORE-CALLS-PROPOSAL.md").write_text(
            body, encoding="utf-8"
        )
        for rel, data in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def _git(self, root, *args):
        env = dict(os.environ)
        env.update(IDENTITY)
        subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _git_output(self, root, *args):
        env = dict(os.environ)
        env.update(IDENTITY)
        return subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            env=env,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def _commit_all(self, root):
        self._git(root, "init", "-q")
        self._git(root, "add", "-A")
        self._git(root, "commit", "-q", "-m", "fixture")
        return self._git_output(root, "rev-parse", "HEAD")

    def _draft(self, body, files=None):
        """A temp root whose draft pins the repository's committed HEAD."""
        root = self._temp_root()
        self._write(root, body, files or {})
        sha = self._commit_all(root)
        (root / "lab" / "bus-v2-proposal" / "CORE-CALLS-PROPOSAL.md").write_text(
            "Pinned commit: " + sha + "\n" + body, encoding="utf-8"
        )
        return root

    def _raw_draft(self, body, files=None, commit=False):
        """A temp draft with the caller's pin text and no automatic pin."""
        root = self._temp_root()
        self._write(root, body, files or {})
        if commit:
            self._commit_all(root)
        return root

    def _assert_one(self, body, files, expected):
        got = check.problems(self._draft(body, files))
        assert got == [expected], expected

    def _commit_pinned(self, root, rows, body):
        """Commit ROWS, then pin BODY at that commit. Return the pinned sha."""
        source = root / OWNED_REL
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("\n".join(rows) + "\n", encoding="utf-8")
        self._git(root, "add", "-A")
        self._git(root, "commit", "-q", "-m", "source")
        sha = self._git_output(root, "rev-parse", "HEAD")
        (root / "lab" / "bus-v2-proposal" / "CORE-CALLS-PROPOSAL.md").write_text(
            "Pinned commit: " + sha + "\n" + body, encoding="utf-8"
        )
        self._git(root, "add", "-A")
        self._git(root, "commit", "-q", "-m", "pinned " + sha)
        return sha

    def _check_at(self, root):
        """Return the problems of ROOT, whose own draft pin decides."""
        return check.problems(root)

    def _padded(self, rows, blocks=None, blank=None):
        """Return ROWS as UTF-8 bytes with each cited walk laid out around it.

        A window is as wide as its walk and must contain the cited line, so a
        cited line needs the rest of its own walk around it. ROWS holds the
        line each caller decides; every other slot stays ``// filler``. Each
        walk in BLOCKS that starts inside ROWS fills its still-filler slots,
        and the file grows to hold the whole walk.

        BLANK names one line number to leave empty. An empty line is not a
        pinned line, so no window of the walk contains that number, and every
        cited line before it keeps the window its own decision reads.
        """
        blocks = LIB_WALKS if blocks is None else blocks
        rows = list(rows)
        end = len(rows)
        for start, lines in blocks:
            if start - 1 <= len(rows):
                end = max(end, start - 1 + len(lines))
        out = rows + ["// filler"] * (end - len(rows))
        for start, lines in blocks:
            if start - 1 > len(rows):
                continue
            for offset, text in enumerate(lines):
                slot = start - 1 + offset
                if slot < len(rows) and rows[slot] != "// filler":
                    continue
                out[slot] = text
        if blank is not None:
            out[blank - 1] = ""
        return ("\n".join(out) + "\n").encode("utf-8")

    def _without(self, body, lines, index):
        """Return BODY with the INDEX-th line of its LINES walk left out.

        A fixture states that a cited line is absent from the pinned commit by
        leaving that line empty there. The quote window is as wide as the walk
        and must contain the cited line, so the quotation holds the rest of the
        block without that line. The window it reads is then as wide as the
        pinned block, and every earlier decision in that block keeps the window
        it reads.
        """
        want = list(lines)
        rows = body.split("\n")
        for at in range(len(rows)):
            quoted = []
            for after in range(at + 1, len(rows)):
                if not rows[after].startswith("    "):
                    break
                quoted.append(rows[after][4:])
            if quoted == want:
                del rows[at + 1 + index]
                return "\n".join(rows)
        raise AssertionError("no walk of %d lines in the body" % len(want))

    def _source(self, quote, following=NEXT_QUOTE, absent=None):
        """A committed file whose line 3754 is QUOTE and line 3755 is FOLLOWING.

        ABSENT names a line number that the file leaves empty, which is how a
        fixture states that a cited line is not in the pinned commit.
        """
        rows = ["// filler"] * (OWNED_NUMBER - 1) + [quote]
        if following is not None:
            rows.append(following)
        return self._padded(rows, blank=absent)

    def _quote_body(self, quote, following=None):
        """A draft that cites the owned span and indents QUOTE below it."""
        body = (
            "`" + OWNED_SPAN + "` states that the guest names only `Users/self`.\n"
            "\n"
            "    " + quote + "\n"
        )
        if following is not None:
            body += "    " + following + "\n"
        return body + "\n"

    def _marker_source(self, last=MARKER_CONST, head=MARKER_HEAD):
        """A committed file with the owned lines and the marker block at 8159-8162."""
        rows = ["// filler"] * (OWNED_NUMBER - 1) + [OWNED_QUOTE, NEXT_QUOTE]
        rows += ["// filler"] * (MARKER_NUMBER - 4 - len(rows))
        rows += [head, MARKER_TAIL, MARKER_CFG, last]
        return self._padded(rows)

    def _marker_body(self, last, head=MARKER_HEAD):
        """A draft that cites the marker span and indents four lines below it."""
        return (
            "`" + MARKER_SPAN + "` defines the marker a declared pattern may hold.\n"
            "\n"
            "    " + head + "\n"
            "    " + MARKER_TAIL + "\n"
            "    " + MARKER_CFG + "\n"
            "    " + last + "\n"
            "\n"
        )

    def _launching_source(self, last=LAUNCHING_CONST, head=LAUNCHING_HEAD):
        """A committed file with lines 3754-3755, 8162 and the block at 8164-8168."""
        rows = ["// filler"] * (OWNED_NUMBER - 1) + [OWNED_QUOTE, NEXT_QUOTE]
        rows += ["// filler"] * (MARKER_NUMBER - 4 - len(rows))
        rows += [MARKER_HEAD, MARKER_TAIL, MARKER_CFG, MARKER_CONST]
        rows += ["// filler"] * (LAUNCHING_NUMBER - len(rows) - 5)
        rows += [head, LAUNCHING_SECOND, LAUNCHING_THIRD, LAUNCHING_CFG, last]
        return self._padded(rows)

    def _launching_body(self, last, head=LAUNCHING_HEAD):
        """A draft that cites the launching span and indents five lines below it."""
        return (
            "`" + LAUNCHING_SPAN + "` names the launching principal.\n"
            "\n"
            "    " + head + "\n"
            "    " + LAUNCHING_SECOND + "\n"
            "    " + LAUNCHING_THIRD + "\n"
            "    " + LAUNCHING_CFG + "\n"
            "    " + last + "\n"
            "\n"
        )

    def _asks_source(
        self,
        first=ASKS_FIRST,
        third=ASKS_THIRD,
        marker_last=MARKER_CONST,
        launching_last=LAUNCHING_CONST,
    ):
        """A committed file with the owned lines, asks, marker and launching blocks."""
        rows = ["// filler"] * (OWNED_NUMBER - 1) + [OWNED_QUOTE, NEXT_QUOTE]
        rows += ["// filler"] * (ASKS_NUMBER - 3 - len(rows))
        rows += [
            first,
            ASKS_SECOND,
            third,
            ASKS_FOURTH,
            ASKS_FIFTH,
            ASKS_SIXTH,
            ASKS_CFG,
            ASKS_CONST,
        ]
        rows += ["// filler"] * (MARKER_NUMBER - 4 - len(rows))
        rows += [MARKER_HEAD, MARKER_TAIL, MARKER_CFG, marker_last]
        rows += ["// filler"] * (LAUNCHING_NUMBER - len(rows) - 5)
        rows += [
            LAUNCHING_HEAD,
            LAUNCHING_SECOND,
            LAUNCHING_THIRD,
            LAUNCHING_CFG,
            launching_last,
        ]
        return self._padded(rows)

    def _asks_block(
        self,
        first=ASKS_FIRST,
        second=ASKS_SECOND,
        third=ASKS_THIRD,
        fourth=ASKS_FOURTH,
        last=ASKS_CONST,
        count=8,
    ):
        """A draft that cites the asks span and indents its quotation below it."""
        lines = [first, second, third, fourth, ASKS_FIFTH, ASKS_SIXTH, ASKS_CFG, last]
        body = "`" + ASKS_SPAN + "` states that the Runtime enforces each grant.\n\n"
        body += "".join("    " + line + "\n" for line in lines[:count])
        return body + "\n"

    def _deny_source(
        self,
        first=DENY_QUOTE,
        owned=OWNED_QUOTE,
        third=ASKS_THIRD,
        marker_last=MARKER_CONST,
        launching_last=LAUNCHING_CONST,
    ):
        """A committed file with line 3526, the owned lines, asks, marker and launching."""
        rows = ["// filler"] * (DENY_NUMBER - 1) + [first]
        rows += ["// filler"] * (OWNED_NUMBER - 1 - len(rows)) + [owned, NEXT_QUOTE]
        rows += ["// filler"] * (ASKS_NUMBER - 3 - len(rows))
        rows += [
            ASKS_FIRST,
            ASKS_SECOND,
            third,
            ASKS_FOURTH,
            ASKS_FIFTH,
            ASKS_SIXTH,
            ASKS_CFG,
            ASKS_CONST,
        ]
        rows += ["// filler"] * (MARKER_NUMBER - 4 - len(rows))
        rows += [MARKER_HEAD, MARKER_TAIL, MARKER_CFG, marker_last]
        rows += ["// filler"] * (LAUNCHING_NUMBER - len(rows) - 5)
        rows += [
            LAUNCHING_HEAD,
            LAUNCHING_SECOND,
            LAUNCHING_THIRD,
            LAUNCHING_CFG,
            launching_last,
        ]
        return self._padded(rows)

    def _deny_block(self, first=DENY_QUOTE, second=DENY_SECOND, last=DENY_LAST):
        """A draft that cites the deny span and indents its 21 lines below it."""
        lines = [first, second] + list(DENY_LINES[2:-1]) + [last]
        body = "`" + DENY_SPAN + "` states that a missing grant denies the step.\n\n"
        body += "".join("    " + line + "\n" for line in lines)
        return body + "\n"

    def _mint_source(self, first=MINT_FIRST, second=MINT_SECOND):
        """A committed file with line 3526, line 3548, line 3549, then the other blocks."""
        rows = ["// filler"] * (DENY_NUMBER - 1) + [DENY_QUOTE]
        rows += ["// filler"] * (MINT_NUMBER - 2 - len(rows)) + [first, second]
        rows += ["// filler"] * (OWNED_NUMBER - 1 - len(rows)) + [OWNED_QUOTE, NEXT_QUOTE]
        rows += ["// filler"] * (ASKS_NUMBER - 3 - len(rows))
        rows += [
            ASKS_FIRST,
            ASKS_SECOND,
            ASKS_THIRD,
            ASKS_FOURTH,
            ASKS_FIFTH,
            ASKS_SIXTH,
            ASKS_CFG,
            ASKS_CONST,
        ]
        rows += ["// filler"] * (MARKER_NUMBER - 4 - len(rows))
        rows += [MARKER_HEAD, MARKER_TAIL, MARKER_CFG, MARKER_CONST]
        rows += ["// filler"] * (LAUNCHING_NUMBER - len(rows) - 5)
        rows += [
            LAUNCHING_HEAD,
            LAUNCHING_SECOND,
            LAUNCHING_THIRD,
            LAUNCHING_CFG,
            LAUNCHING_CONST,
        ]
        return self._padded(rows)

    def _mint_block(self, first=MINT_FIRST, second=MINT_SECOND, last=MINT_LAST, count=5):
        """A draft that cites the mint span and indents its five lines below it."""
        lines = [first, second, MINT_THIRD, MINT_FOURTH, last]
        body = "`" + MINT_SPAN + "` states that the guest does not mint one.\n\n"
        body += "".join("    " + line + "\n" for line in lines[:count])
        return body + "\n"

    def _journal_source(
        self,
        first=JOURNAL_CFG,
        second=JOURNAL_CONST,
        owned=OWNED_QUOTE,
        following=NEXT_QUOTE,
        third=ASKS_THIRD,
        marker_last=MARKER_CONST,
        launching_last=LAUNCHING_CONST,
        grant_first=GRANT_QUOTE,
        grant_last=GRANT_LINES[-1],
    ):
        """A committed file with line 3757 below 3755, line 3767 below 3757, and the asks block."""
        rows = ["// filler"] * (OWNED_NUMBER - 1) + [owned, following]
        rows += [first, second]
        rows += ["// filler"] * (GRANT_NUMBER - 1 - len(rows))
        rows += [grant_first] + list(GRANT_LINES[1:-1]) + [grant_last]
        rows += ["// filler"] * (ASKS_NUMBER - 3 - len(rows))
        rows += [
            ASKS_FIRST,
            ASKS_SECOND,
            third,
            ASKS_FOURTH,
            ASKS_FIFTH,
            ASKS_SIXTH,
            ASKS_CFG,
            ASKS_CONST,
        ]
        rows += ["// filler"] * (MARKER_NUMBER - 4 - len(rows))
        rows += [MARKER_HEAD, MARKER_TAIL, MARKER_CFG, marker_last]
        rows += ["// filler"] * (LAUNCHING_NUMBER - len(rows) - 5)
        rows += [
            LAUNCHING_HEAD,
            LAUNCHING_SECOND,
            LAUNCHING_THIRD,
            LAUNCHING_CFG,
            launching_last,
        ]
        return self._padded(rows)

    def _journal_block(self, first=JOURNAL_CFG, second=JOURNAL_CONST, count=2):
        """A draft that cites the journal span and indents its two lines below it."""
        lines = [first, second]
        body = "`" + JOURNAL_SPAN + "` sets `JOURNAL_ROOT`.\n\n"
        body += "".join("    " + line + "\n" for line in lines[:count])
        return body + "\n"

    def _grant_block(
        self,
        first=GRANT_QUOTE,
        second=GRANT_SECOND,
        struct_line=GRANT_STRUCT,
        last=GRANT_LINES[-1],
        count=14,
    ):
        """A draft that cites the grant span and indents its quotation below it."""
        lines = (
            [first, second]
            + list(GRANT_LINES[2:4])
            + [struct_line]
            + list(GRANT_LINES[5:-1])
            + [last]
        )
        body = "`" + GRANT_SPAN + "` is `JournalGrant`.\n\n"
        body += "".join("    " + line + "\n" for line in lines[:count])
        return body + "\n"

    def _ask_source(
        self,
        write=WRITE_QUOTE,
        read=READ_QUOTE,
        ask_count=20,
        asks_third=ASKS_THIRD,
        marker_last=MARKER_CONST,
        launching_last=LAUNCHING_CONST,
        blank=None,
    ):
        """A committed file with the ask block at 3833-3852 and the later blocks."""
        rows = ["// filler"] * (OWNED_NUMBER - 1) + [OWNED_QUOTE, NEXT_QUOTE]
        rows += [JOURNAL_CFG, JOURNAL_CONST]
        rows += ["// filler"] * (GRANT_NUMBER - 1 - len(rows))
        rows += [GRANT_QUOTE] + list(GRANT_LINES[1:-1]) + [GRANT_LINES[-1]]
        block = list(ASK_LINES)
        block[16] = write
        block[17] = read
        rows += ["// filler"] * (ASK_BLOCK_START - 1 - len(rows))
        rows += block[:ask_count]
        rows += ["// filler"] * (ASKS_NUMBER - 3 - len(rows))
        rows += [
            ASKS_FIRST,
            ASKS_SECOND,
            asks_third,
            ASKS_FOURTH,
            ASKS_FIFTH,
            ASKS_SIXTH,
            ASKS_CFG,
            ASKS_CONST,
        ]
        rows += ["// filler"] * (MARKER_NUMBER - 4 - len(rows))
        rows += [MARKER_HEAD, MARKER_TAIL, MARKER_CFG, marker_last]
        rows += ["// filler"] * (LAUNCHING_NUMBER - len(rows) - 5)
        rows += [
            LAUNCHING_HEAD,
            LAUNCHING_SECOND,
            LAUNCHING_THIRD,
            LAUNCHING_CFG,
            launching_last,
        ]
        return self._padded(rows, blank=blank)

    def _ask_block(
        self,
        write=WRITE_QUOTE,
        read=READ_QUOTE,
        first=ASK_LINES[0],
        grants=ASK_LINES[18],
        last=ASK_LINES[19],
        count=20,
        spans=None,
    ):
        """A draft that cites the ask spans and indents the block below them."""
        lines = list(ASK_LINES)
        lines[0] = first
        lines[16] = write
        lines[17] = read
        lines[18] = grants
        lines[19] = last
        if spans is None:
            prose = "`" + WRITE_SPAN + "` asks write. `" + READ_SPAN + "` asks read.\n"
        else:
            prose = "".join("`" + span + "` is cited.\n" for span in spans)
        body = prose + "\n"
        body += "".join("    " + line + "\n" for line in lines[:count])
        return body + "\n"

    def _kind_source(
        self,
        read=KIND_READ_QUOTE,
        edit=KIND_EDIT_QUOTE,
        restore=KIND_RESTORE_QUOTE,
        run=KIND_RUN_QUOTE,
        hosted=KIND_HOSTED_QUOTE,
        child=KIND_CHILD_QUOTE,
        init=KIND_INIT_QUOTE,
        append=KIND_APPEND_QUOTE,
        asks_third=ASKS_THIRD,
        launching_last=LAUNCHING_CONST,
        ask_count=20,
        kind_count=len(KIND_LINES),
        blank=None,
    ):
        """A committed file with the ask block, the later blocks, then the kind arms."""
        rows = ["// filler"] * (OWNED_NUMBER - 1) + [OWNED_QUOTE, NEXT_QUOTE]
        rows += [JOURNAL_CFG, JOURNAL_CONST]
        rows += ["// filler"] * (GRANT_NUMBER - 1 - len(rows))
        rows += [GRANT_QUOTE] + list(GRANT_LINES[1:-1]) + [GRANT_LINES[-1]]
        rows += ["// filler"] * (ASK_BLOCK_START - 1 - len(rows))
        rows += list(ASK_LINES)[:ask_count]
        rows += ["// filler"] * (ASKS_NUMBER - 3 - len(rows))
        rows += [
            ASKS_FIRST,
            ASKS_SECOND,
            asks_third,
            ASKS_FOURTH,
            ASKS_FIFTH,
            ASKS_SIXTH,
            ASKS_CFG,
            ASKS_CONST,
        ]
        rows += ["// filler"] * (MARKER_NUMBER - 4 - len(rows))
        rows += [MARKER_HEAD, MARKER_TAIL, MARKER_CFG, MARKER_CONST]
        rows += ["// filler"] * (LAUNCHING_NUMBER - len(rows) - 5)
        rows += [
            LAUNCHING_HEAD,
            LAUNCHING_SECOND,
            LAUNCHING_THIRD,
            LAUNCHING_CFG,
            launching_last,
        ]
        kind = list(KIND_LINES)
        kind[8] = read
        kind[9] = edit
        kind[10] = run
        kind[11] = restore
        kind[12] = hosted
        kind[13] = child
        kind[14] = init
        kind[15] = append
        rows += ["// filler"] * (KIND_BLOCK_START - 1 - len(rows))
        rows += kind[:kind_count]
        return self._padded(rows, blank=blank)

    def _kind_block(
        self,
        read=KIND_READ_QUOTE,
        edit=KIND_EDIT_QUOTE,
        restore=KIND_RESTORE_QUOTE,
        run=KIND_RUN_QUOTE,
        hosted=KIND_HOSTED_QUOTE,
        child=KIND_CHILD_QUOTE,
        init=KIND_INIT_QUOTE,
        append=KIND_APPEND_QUOTE,
        first=KIND_LINES[0],
        last=KIND_LINES[-1],
        count=len(KIND_LINES),
        prose=None,
    ):
        """A draft that cites the kind spans and indents the arms below them."""
        lines = list(KIND_LINES)
        lines[0] = first
        lines[8] = read
        lines[9] = edit
        lines[10] = run
        lines[11] = restore
        lines[12] = hosted
        lines[13] = child
        lines[14] = init
        lines[15] = append
        lines[17] = last
        if prose is None:
            prose = (
                "`"
                + KIND_READ_SPAN
                + "` is the Read arm. `"
                + KIND_EDIT_SPAN
                + "` is the Edit arm. `"
                + KIND_RESTORE_SPAN
                + "` is the Restore arm.\n"
            )
        body = prose + "\n"
        body += "".join("    " + line + "\n" for line in lines[:count])
        return body + "\n"

    def _kind_line_body(
        self,
        block=None,
        run=KIND_RUN_QUOTE,
        hosted=KIND_HOSTED_QUOTE,
        child=KIND_CHILD_QUOTE,
        init=KIND_INIT_QUOTE,
        append=KIND_APPEND_QUOTE,
        spans=None,
        repeats=None,
        indented=True,
    ):
        """A draft whose one-line arms each sit below their own cited span."""
        body = self._kind_block() if block is None else block
        quotes = {
            KIND_RUN_SPAN: run,
            KIND_HOSTED_SPAN: hosted,
            KIND_CHILD_SPAN: child,
            KIND_INIT_SPAN: init,
            KIND_APPEND_SPAN: append,
        }
        repeats = repeats or {}
        for span in spans if spans is not None else list(quotes):
            marker = "`" + span + "`"
            prose = marker + " is the match arm."
            for _ in range(repeats.get(span, 1) - 1):
                prose += " Again " + marker + "."
            body += prose + "\n"
            if indented:
                body += "\n    " + quotes[span] + "\n"
            body += "\n"
        return body

    def _file_ask_source(self, blank=None, lines=None):
        """A committed file with one correct line for every cited quote decision."""
        rows = ["// filler"] * COVER_NUMBER
        for number, text in (lines or FILE_ASK_LINES).items():
            rows[number - 1] = text
        return self._padded(rows, blank=blank)

    def _provider_source(self, blank=None, lines=None):
        """A committed provider file with one correct line per provider decision."""
        rows = ["// filler"] * DEFAULT_ACTION_NUMBER
        for number, text in (lines or PROVIDER_LINES).items():
            rows[number - 1] = text
        return self._padded(rows, blank=blank, blocks=PROVIDER_WALKS)

    def _changed(self, lines, index):
        """Return LINES with the one line at INDEX altered by one character."""
        rows = list(lines)
        rows[index] = rows[index] + "x"
        return tuple(rows)

    def _cited(self, span, copies=1):
        sentence = "`" + span + "` is cited."
        return " ".join([sentence] * copies)

    def _file_ask_body(
        self,
        observe=OBSERVE_LINES,
        revision=REQUEST_LINES,
        op=REQUEST_LINES,
        no_write=NO_WRITE_LINES,
        cover=COVER_LINES,
        deny=DENY_QUOTE,
        ask_third=ASKS_THIRD,
        append=KIND_APPEND_QUOTE,
        groups=None,
        copies=None,
        indented=True,
        ask=ASK_LINES,
        run=RUN_LINES,
        write_body=WRITE_BODY_LINES,
        span_copies=None,
        omit=(),
    ):
        """A draft that cites the file-ask spans and indents their walks."""
        copies = copies or {}
        span_copies = span_copies or {}
        chosen = FILE_ASK_GROUPS if groups is None else tuple(groups)
        blocks = (
            ("observe", [OBSERVE_SPAN], list(observe)),
            ("revision", [REVISION_SPAN], list(revision)),
            ("op", [OP_SPAN], list(op)),
            ("no_write", [NO_WRITE_SPAN], list(no_write)),
            ("deny", [DENY_SPAN], [deny] + list(DENY_LINES[1:])),
            ("mint", [MINT_SPAN], [MINT_FIRST, MINT_SECOND]),
            ("owned", [OWNED_SPAN, NEXT_SPAN], [OWNED_QUOTE, NEXT_QUOTE]),
            ("journal", [JOURNAL_SPAN], [JOURNAL_CFG, JOURNAL_CONST]),
            ("grant", [GRANT_SPAN], list(GRANT_LINES)),
            ("run", [NO_PROCESS_SPAN, SEAT_SPAN], list(run)),
            ("ask", [WRITE_SPAN, READ_SPAN], list(ask)),
            (
                "write_body",
                [BODY_DOC_SPAN, CREATE_ONLY_SPAN, PRESENT_REVISION_SPAN],
                list(write_body),
            ),
            (
                "asks",
                [ASKS_SPAN],
                [
                    ASKS_FIRST,
                    ASKS_SECOND,
                    ask_third,
                    ASKS_FOURTH,
                    ASKS_FIFTH,
                    ASKS_SIXTH,
                    ASKS_CFG,
                    ASKS_CONST,
                ],
            ),
            (
                "marker",
                [MARKER_SPAN],
                [MARKER_HEAD, MARKER_TAIL, MARKER_CFG, MARKER_CONST],
            ),
            (
                "launching",
                [LAUNCHING_SPAN],
                [
                    LAUNCHING_HEAD,
                    LAUNCHING_SECOND,
                    LAUNCHING_THIRD,
                    LAUNCHING_CFG,
                    LAUNCHING_CONST,
                ],
            ),
            (
                "kind",
                [KIND_READ_SPAN, KIND_EDIT_SPAN, KIND_RESTORE_SPAN],
                list(KIND_LINES),
            ),
            ("cover", [COVER_SPAN], list(cover)),
        )
        parts = []
        for name, spans, lines in blocks:
            if name not in chosen:
                continue
            prose = " ".join(
                self._cited(span, span_copies.get(span, copies.get(name, 1)))
                for span in spans
                if span not in omit
            )
            if not prose:
                continue
            parts.append(prose + "\n")
            if indented:
                parts.append("".join("    " + line + "\n" for line in lines))
            parts.append("\n")
        if "arms" in chosen:
            arms = (
                (KIND_RUN_SPAN, KIND_RUN_QUOTE),
                (KIND_HOSTED_SPAN, KIND_HOSTED_QUOTE),
                (KIND_CHILD_SPAN, KIND_CHILD_QUOTE),
                (KIND_INIT_SPAN, KIND_INIT_QUOTE),
                (KIND_APPEND_SPAN, append),
            )
            for span, quote in arms:
                parts.append(self._cited(span, copies.get("arms", 1)) + "\n")
                if indented:
                    parts.append("    " + quote + "\n")
                parts.append("\n")
        return "".join(parts)

    def _edit_walk_body(
        self,
        observe=OBSERVE_LINES,
        edit=EDIT_LINES,
        request_walk=REQUEST_WALK_LINES,
        revision=REQUEST_LINES,
        op=REQUEST_LINES,
        is_write=IS_WRITE_LINES,
        no_write=NO_WRITE_LINES,
        deny=DENY_QUOTE,
        groups=None,
        copies=None,
        indented=True,
    ):
        """A draft that cites the edit range, request and is-write walks."""
        copies = copies or {}
        chosen = EDIT_GROUPS if groups is None else tuple(groups)
        blocks = (
            ("observe", [OBSERVE_SPAN], list(observe)),
            ("range", [EDIT_RANGE_SPAN], list(edit)),
            ("request_walk", [REQUEST_WALK_SPAN], list(request_walk)),
            ("revision", [REVISION_SPAN], list(revision)),
            ("op", [OP_SPAN], list(op)),
            ("is_write", [IS_WRITE_SPAN], list(is_write)),
            ("no_write", [NO_WRITE_SPAN], list(no_write)),
            ("deny", [DENY_SPAN], [deny] + list(DENY_LINES[1:])),
        )
        parts = []
        for name, spans, lines in blocks:
            if name not in chosen:
                continue
            prose = " ".join(
                self._cited(span, copies.get(name, 1)) for span in spans
            )
            parts.append(prose + "\n")
            if indented:
                parts.append("".join("    " + line + "\n" for line in lines))
            parts.append("\n")
        return "".join(parts)

    def _provider_body(
        self,
        scheme=SCHEME_LINES,
        read_action=READ_ACTION_LINES,
        write_action=WRITE_ACTION_LINES,
        default_action=WRITE_ACTION_LINES,
        groups=None,
        copies=None,
        indented=True,
    ):
        """A draft that cites the provider spans and indents their walks."""
        copies = copies or {}
        chosen = PROVIDER_GROUPS if groups is None else tuple(groups)
        blocks = (
            ("scheme", [SCHEME_SPAN], list(scheme)),
            ("read_action", [READ_ACTION_SPAN], list(read_action)),
            ("write_action", [WRITE_ACTION_SPAN], list(write_action)),
            ("default_action", [DEFAULT_ACTION_SPAN], list(default_action)),
        )
        parts = []
        for name, spans, lines in blocks:
            if name not in chosen:
                continue
            prose = " ".join(
                self._cited(span, copies.get(name, 1)) for span in spans
            )
            parts.append(prose + "\n")
            if indented:
                parts.append("".join("    " + line + "\n" for line in lines))
            parts.append("\n")
        return "".join(parts)

    def _append_source(self, blank=None, lines=None):
        """A committed file with one correct line for every append quote."""
        rows = ["// filler"] * WRITE_INVOKE_NUMBER
        for number, text in (lines or APPEND_LINES).items():
            rows[number - 1] = text
        return self._padded(rows, blank=blank)

    def _append_body(
        self,
        condition=APPEND_WALK_LINES,
        doc=DOC_WALK_LINES,
        groups=None,
        copies=None,
        span_copies=None,
        indented=True,
        omit=(),
    ):
        """A draft that cites the append spans and indents their walks."""
        copies = copies or {}
        span_copies = span_copies or {}
        chosen = APPEND_GROUPS if groups is None else tuple(groups)
        blocks = (
            (
                "condition",
                [APPEND_CONDITION_SPAN, HOST_PATH_ERR_SPAN, HELD_ERR_SPAN],
                list(condition),
            ),
            (
                "doc",
                [APPEND_CAP_SPAN, APPEND_RANGE_SPAN, WRITE_INVOKE_SPAN],
                list(doc),
            ),
        )
        parts = []
        for name, spans, lines in blocks:
            if name not in chosen:
                continue
            prose = " ".join(
                self._cited(span, span_copies.get(span, copies.get(name, 1)))
                for span in spans
                if span not in omit
            )
            if not prose:
                continue
            parts.append(prose + "\n")
            if indented:
                parts.append("".join("    " + line + "\n" for line in lines))
            parts.append("\n")
        return "".join(parts)

    def _caught(self, global_name, planted, named_test, prefix, label):
        named_test()
        original = getattr(check, global_name)
        try:
            setattr(check, global_name, planted)
            with self.assertRaises(AssertionError) as caught:
                named_test()
            self.assertIn(prefix, str(caught.exception))
        finally:
            setattr(check, global_name, original)
        print(label)

    def _pinned_reads(self, body, files, restore=None):
        """Return the problems and the numbers read from the pinned commit."""
        reads = []
        original = check.pinned_line

        def record(root, sha, rel, number):
            reads.append(number)
            return original(root, sha, rel, number)

        try:
            check.pinned_line = record
            root = self._draft(body, files)
            for rel, data in (restore or {}).items():
                (root / rel).write_bytes(data)
            got = check.problems(root)
        finally:
            check.pinned_line = original
        return got, reads

    def test_absent_draft_is_refused(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.assertEqual(
            check.problems(Path(tmp.name)),
            ["refuse: proposal is absent"],
        )

    def test_missing_pin_is_refused(self):
        got = check.problems(self._raw_draft("No pin line here.\n"))
        self.assertEqual(got, ["refuse: draft has no pinned commit"])

    def test_pin_line_is_one_commit(self):
        sha = "a" * 40
        bodies = (
            "Pinned commit: HEAD\n",
            "Pinned commit: %s\nPinned commit: %s\n" % (sha, sha),
        )
        for body in bodies:
            got = check.problems(self._raw_draft(body))
            self.assertEqual(
                got,
                ["refuse: pinned commit is not one 40-hex commit"],
                body,
            )

    def test_unknown_pin_is_refused(self):
        sha = "f" * 40
        root = self._raw_draft("Pinned commit: " + sha + "\n", commit=True)
        got = check.problems(root)
        self.assertEqual(got, ["refuse: pinned commit is not a commit: " + sha])

    def test_supported_citations_pass(self):
        body = (
            "The principal is `Users/self`.\n"
            "Open `pkg/kept.rs:1`.\n"
            "Span `pkg/kept.rs:1-2`.\n"
            "Call `pkg/kept.rs::kept`.\n"
        )
        files = {"pkg/kept.rs": b"fn kept(\nsecond\nthird\n"}
        got = check.problems(self._draft(body, files))
        self.assertEqual(got, [])

    def test_missing_path_is_refused(self):
        expected = "refuse: path does not exist: missing/no-such.rs"
        self._assert_one("See `missing/no-such.rs:1`.\n", {}, expected)

    def test_past_end_line_is_refused(self):
        one = {"pkg/one.rs": b"only\n"}
        past = "refuse: line 2 is past the end of pkg/one.rs (1 lines)"
        self._assert_one("See `pkg/one.rs:2`.\n", one, past)
        reversed_range = "refuse: line range 2-1 is reversed in pkg/one.rs"
        self._assert_one("See `pkg/one.rs:2-1`.\n", one, reversed_range)
        empty = "refuse: line 1 is past the end of pkg/empty.rs (0 lines)"
        self._assert_one("See `pkg/empty.rs:1`.\n", {"pkg/empty.rs": b""}, empty)
        over = "refuse: line 4 is past the end of pkg/two.rs (2 lines)"
        self._assert_one(
            "See `pkg/two.rs:1-4`.\n",
            {"pkg/two.rs": b"a\nb\n"},
            over,
        )

    def test_reversed_range_is_refused(self):
        expected = "refuse: line range 2-1 is reversed in pkg/ord.rs"
        self._assert_one(
            "See `pkg/ord.rs:2-1`.\n",
            {"pkg/ord.rs": b"one\ntwo\n"},
            expected,
        )

    def test_missing_function_is_refused(self):
        expected = "refuse: function wanted is not in pkg/one.rs"
        self._assert_one(
            "See `pkg/one.rs::wanted`.\n",
            {"pkg/one.rs": b"fn other(\n"},
            expected,
        )

    def test_non_utf8_file_is_refused(self):
        expected = "refuse: path is not utf-8 text: pkg/bad.rs"
        self._assert_one(
            "See `pkg/bad.rs:1`.\n",
            {"pkg/bad.rs": b"\xff"},
            expected,
        )

    def test_refusals_follow_source_order(self):
        body = "`missing/z.rs:1` `pkg/one.rs:1` `missing/a.rs:1`\n"
        got = check.problems(self._draft(body, {"pkg/one.rs": b"only\n"}))
        self.assertEqual(
            got,
            [
                "refuse: path does not exist: missing/z.rs",
                "refuse: path does not exist: missing/a.rs",
            ],
        )

    def test_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        root = self._draft(
            self._quote_body(OWNED_QUOTE + "x"),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / OWNED_REL).write_bytes(self._source("// edited in the worktree"))
        self.assertEqual(check.problems(root), [expected])

    def test_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(check.problems(root), [])
        (root / OWNED_REL).write_bytes(self._source("// edited in the worktree"))
        self.assertEqual(check.problems(root), [])

    def test_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + OWNED_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(self._quote_body(OWNED_QUOTE), {OWNED_REL: short})
        (root / OWNED_REL).write_bytes(self._source(OWNED_QUOTE))
        self.assertEqual(check.problems(root), [expected])

    def test_next_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(check.problems(root), [])
        (root / OWNED_REL).write_bytes(
            self._source(OWNED_QUOTE, "// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_next_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + NEXT_SPAN
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE + "x"),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / OWNED_REL).write_bytes(
            self._source(OWNED_QUOTE, "// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_next_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + NEXT_SPAN
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {OWNED_REL: self._source(OWNED_QUOTE, absent=NEXT_NUMBER)},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_marker_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + MARKER_SPAN
        root = self._draft(
            self._marker_body(MARKER_CONST + "x"),
            {MARKER_REL: self._marker_source()},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / MARKER_REL).write_bytes(
            self._marker_source("// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_marker_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(
            self._marker_body(MARKER_CONST),
            {MARKER_REL: self._marker_source()},
        )
        self.assertEqual(check.problems(root), [])
        (root / MARKER_REL).write_bytes(
            self._marker_source("// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_marker_first_line_does_not_stand_for_line_8162(self):
        root = self._draft(
            self._marker_body(MARKER_CONST, head=MARKER_HEAD + "x"),
            {MARKER_REL: self._marker_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_marker_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + MARKER_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(self._marker_body(MARKER_CONST), {MARKER_REL: short})
        (root / MARKER_REL).write_bytes(self._marker_source())
        self.assertEqual(check.problems(root), [expected])

    def test_two_marker_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + MARKER_SPAN
        body = (
            "`" + MARKER_SPAN + "` defines the marker.\n"
            "\n"
            "    " + MARKER_HEAD + "\n"
            "    " + MARKER_TAIL + "\n"
            "    " + MARKER_CFG + "\n"
            "    " + MARKER_CONST + "\n"
            "\n"
            "Again `" + MARKER_SPAN + "`.\n"
        )
        got, reads = self._pinned_reads(body, {MARKER_REL: self._marker_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_draft_without_the_marker_span_adds_no_marker_refusal(self):
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {OWNED_REL: self._marker_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_owned_line_mismatch_adds_no_marker_refusal(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        body = self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE) + self._marker_body(
            MARKER_CONST + "y"
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._marker_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER])

    def test_next_line_mismatch_adds_no_marker_refusal(self):
        expected = "refuse: quoted line does not match " + NEXT_SPAN
        body = self._quote_body(OWNED_QUOTE, NEXT_QUOTE + "x") + self._marker_body(
            MARKER_CONST + "y"
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._marker_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER, NEXT_NUMBER])

    def test_marker_quote_refusal_waits_for_a_known_pin(self):
        body = self._marker_body(MARKER_CONST + "x")
        files = {MARKER_REL: self._marker_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        bad_pin = "Pinned commit: HEAD\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(bad_pin, files)),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        unknown = "Pinned commit: " + "f" * 40 + "\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(unknown, files, commit=True)),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_launching_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + LAUNCHING_SPAN
        root = self._draft(
            self._launching_body(LAUNCHING_CONST + "x"),
            {MARKER_REL: self._launching_source()},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / MARKER_REL).write_bytes(
            self._launching_source("// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_launching_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(
            self._launching_body(LAUNCHING_CONST),
            {MARKER_REL: self._launching_source()},
        )
        self.assertEqual(check.problems(root), [])
        (root / MARKER_REL).write_bytes(
            self._launching_source("// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_launching_first_line_does_not_stand_for_line_8168(self):
        root = self._draft(
            self._launching_body(LAUNCHING_CONST, head=LAUNCHING_HEAD + "x"),
            {MARKER_REL: self._launching_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_launching_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + LAUNCHING_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(self._launching_body(LAUNCHING_CONST), {MARKER_REL: short})
        (root / MARKER_REL).write_bytes(self._launching_source())
        self.assertEqual(check.problems(root), [expected])

    def test_two_launching_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + LAUNCHING_SPAN
        body = self._launching_body(LAUNCHING_CONST) + (
            "\nAgain `" + LAUNCHING_SPAN + "`.\n"
        )
        got, reads = self._pinned_reads(body, {MARKER_REL: self._launching_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_draft_without_the_launching_span_adds_no_launching_refusal(self):
        root = self._draft(
            self._marker_body(MARKER_CONST),
            {MARKER_REL: self._launching_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_owned_line_mismatch_adds_no_launching_refusal(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        body = self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE) + self._launching_body(
            LAUNCHING_CONST + "y"
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._launching_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER])

    def test_next_line_mismatch_adds_no_launching_refusal(self):
        expected = "refuse: quoted line does not match " + NEXT_SPAN
        body = self._quote_body(OWNED_QUOTE, NEXT_QUOTE + "x") + self._launching_body(
            LAUNCHING_CONST + "y"
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._launching_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER, NEXT_NUMBER])

    def test_marker_line_mismatch_adds_no_launching_refusal(self):
        expected = "refuse: quoted line does not match " + MARKER_SPAN
        body = self._marker_body(MARKER_CONST + "x") + self._launching_body(
            LAUNCHING_CONST + "y"
        )
        got, reads = self._pinned_reads(body, {MARKER_REL: self._launching_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [MARKER_NUMBER])

    def test_launching_quote_refusal_waits_for_a_known_pin(self):
        body = self._launching_body(LAUNCHING_CONST + "x")
        files = {MARKER_REL: self._launching_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        bad_pin = "Pinned commit: HEAD\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(bad_pin, files)),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        unknown = "Pinned commit: " + "f" * 40 + "\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(unknown, files, commit=True)),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_short_pinned_file_refuses_the_owned_line_only(self):
        expected = "refuse: quoted line is not in the pinned commit: " + OWNED_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE), {OWNED_REL: short}
        )
        (root / OWNED_REL).write_bytes(self._source(OWNED_QUOTE))
        self.assertEqual(check.problems(root), [expected])

    def test_owned_line_mismatch_adds_no_next_refusal(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        root = self._draft(
            self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE + "y"),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_owned_line_refusal_skips_the_next_line_read(self):
        got, reads = self._pinned_reads(
            self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + OWNED_SPAN])
        self.assertEqual(reads, [OWNED_NUMBER])

    def test_shared_marker_compares_the_next_line_against_its_window(self):
        got, reads = self._pinned_reads(
            self._quote_body(OWNED_QUOTE),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + NEXT_SPAN]
        )
        self.assertEqual(reads, [OWNED_NUMBER, NEXT_NUMBER])

    def test_next_quote_refusal_waits_for_a_known_pin(self):
        body = self._quote_body(OWNED_QUOTE, NEXT_QUOTE + "x")
        files = {OWNED_REL: self._source(OWNED_QUOTE)}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        bad_pin = "Pinned commit: HEAD\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(bad_pin, files)),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        unknown = "Pinned commit: " + "f" * 40 + "\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(unknown, files, commit=True)),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_two_quoted_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + OWNED_SPAN
        body = (
            "`" + OWNED_SPAN + "` states the journal root.\n"
            "\n"
            "    " + OWNED_QUOTE + "\n"
            "\n"
            "Again `" + OWNED_SPAN + "`.\n"
        )
        original = check.pinned_line
        try:
            check.pinned_line = lambda root, sha, rel, number: None
            got = check.problems(
                self._draft(body, {OWNED_REL: self._source(OWNED_QUOTE)})
            )
        finally:
            check.pinned_line = original
        self.assertEqual(got, [expected])

    def test_draft_without_the_owned_span_adds_no_quote_refusal(self):
        bodies = (
            "Open `pkg/kept.rs:1`.\n\n    /// Not the owned quote.\n",
            "`" + OWNED_SPAN + "` states the journal root.\n\n  /// Two-space indent.\n",
        )
        for body in bodies:
            root = self._draft(
                body,
                {
                    OWNED_REL: self._source(OWNED_QUOTE),
                    "pkg/kept.rs": b"fn kept(\n",
                },
            )
            self.assertEqual(check.problems(root), [], body)

    def test_quote_refusal_waits_for_a_known_pin(self):
        body = self._quote_body(OWNED_QUOTE + "x")
        files = {OWNED_REL: self._source(OWNED_QUOTE)}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        bad_pin = "Pinned commit: HEAD\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(bad_pin, files)),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        unknown = "Pinned commit: " + "f" * 40 + "\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(unknown, files, commit=True)),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_live_draft_owned_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.owned_quote(text), OWNED_QUOTE)
        self.assertEqual(check.next_owned_quote(text), NEXT_QUOTE)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, OWNED_REL, OWNED_NUMBER),
            OWNED_QUOTE,
        )
        self.assertEqual(
            check.pinned_line(root, sha, OWNED_REL, NEXT_NUMBER),
            NEXT_QUOTE,
        )

    def test_live_draft_marker_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.marker_quote(text), MARKER_CONST)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, MARKER_REL, MARKER_NUMBER),
            MARKER_CONST,
        )

    def test_live_draft_launching_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.launching_quote(text), LAUNCHING_CONST)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, MARKER_REL, LAUNCHING_NUMBER),
            LAUNCHING_CONST,
        )

    def test_live_draft_asks_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.asks_quote(text), ASKS_THIRD)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, ASKS_REL, ASKS_NUMBER),
            ASKS_THIRD,
        )

    def test_asks_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + ASKS_SPAN
        root = self._draft(
            self._asks_block(third=ASKS_THIRD + "x"),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / ASKS_REL).write_bytes(
            self._asks_source(third="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_asks_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(self._asks_block(), {ASKS_REL: self._asks_source()})
        self.assertEqual(check.problems(root), [])
        (root / ASKS_REL).write_bytes(
            self._asks_source(third="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_asks_first_line_does_not_stand_for_line_8149(self):
        root = self._draft(
            self._asks_block(first=ASKS_FIRST + "x"),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_asks_second_line_does_not_stand_for_line_8149(self):
        root = self._draft(
            self._asks_block(second=ASKS_SECOND + "x"),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_asks_fourth_line_does_not_stand_for_line_8149(self):
        root = self._draft(
            self._asks_block(fourth=ASKS_FOURTH + "x"),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_asks_last_line_does_not_stand_for_line_8149(self):
        root = self._draft(
            self._asks_block(last=ASKS_CONST + "x"),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_two_asks_lines_are_read_once_through_the_window(self):
        got, reads = self._pinned_reads(
            self._asks_block(count=2), {ASKS_REL: self._asks_source()}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + ASKS_SPAN]
        )
        self.assertEqual(reads, [ASKS_NUMBER])

    def test_asks_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + ASKS_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(self._asks_block(), {ASKS_REL: short})
        (root / ASKS_REL).write_bytes(self._asks_source())
        self.assertEqual(check.problems(root), [expected])

    def test_two_asks_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + ASKS_SPAN
        body = self._asks_block() + "\nAgain `" + ASKS_SPAN + "`.\n"
        got, reads = self._pinned_reads(body, {ASKS_REL: self._asks_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_draft_without_the_asks_span_adds_no_asks_refusal(self):
        root = self._draft(
            self._marker_body(MARKER_CONST),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_owned_line_mismatch_adds_no_asks_refusal(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        body = self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE) + self._asks_block(
            third=ASKS_THIRD + "y"
        )
        got, reads = self._pinned_reads(body, {ASKS_REL: self._asks_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER])

    def test_next_line_mismatch_adds_no_asks_refusal(self):
        expected = "refuse: quoted line does not match " + NEXT_SPAN
        body = self._quote_body(OWNED_QUOTE, NEXT_QUOTE + "x") + self._asks_block(
            third=ASKS_THIRD + "y"
        )
        got, reads = self._pinned_reads(body, {ASKS_REL: self._asks_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER, NEXT_NUMBER])

    def test_asks_line_mismatch_adds_no_marker_or_launching_refusal(self):
        expected = "refuse: quoted line does not match " + ASKS_SPAN
        body = (
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE)
            + self._asks_block(third=ASKS_THIRD + "x")
            + self._marker_body(MARKER_CONST + "y")
            + self._launching_body(LAUNCHING_CONST + "z")
        )
        got, reads = self._pinned_reads(body, {ASKS_REL: self._asks_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER, NEXT_NUMBER, ASKS_NUMBER])

    def test_marker_line_mismatch_follows_the_asks_match(self):
        expected = "refuse: quoted line does not match " + MARKER_SPAN
        body = self._asks_block() + self._marker_body(MARKER_CONST + "x")
        got, reads = self._pinned_reads(body, {ASKS_REL: self._asks_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [ASKS_NUMBER, MARKER_NUMBER])

    def test_draft_without_the_asks_span_still_refuses_a_marker_mismatch(self):
        expected = "refuse: quoted line does not match " + MARKER_SPAN
        root = self._draft(
            self._marker_body(MARKER_CONST + "x"),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_draft_without_the_asks_span_still_refuses_a_launching_mismatch(self):
        expected = "refuse: quoted line does not match " + LAUNCHING_SPAN
        root = self._draft(
            self._launching_body(LAUNCHING_CONST + "x"),
            {ASKS_REL: self._asks_source()},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_asks_quote_refusal_waits_for_a_known_pin(self):
        body = self._asks_block(third=ASKS_THIRD + "x")
        files = {ASKS_REL: self._asks_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        bad_pin = "Pinned commit: HEAD\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(bad_pin, files)),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        unknown = "Pinned commit: " + "f" * 40 + "\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(unknown, files, commit=True)),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_live_draft_deny_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.deny_quote(text), DENY_QUOTE)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, DENY_REL, DENY_NUMBER),
            DENY_QUOTE,
        )

    def test_deny_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + DENY_SPAN
        root = self._draft(
            self._deny_block(first=DENY_QUOTE + "x"),
            {DENY_REL: self._deny_source()},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / DENY_REL).write_bytes(
            self._deny_source(first="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_deny_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(self._deny_block(), {DENY_REL: self._deny_source()})
        self.assertEqual(check.problems(root), [])
        (root / DENY_REL).write_bytes(
            self._deny_source(first="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_deny_second_line_does_not_stand_for_line_3526(self):
        root = self._draft(
            self._deny_block(second=DENY_SECOND + "x"),
            {DENY_REL: self._deny_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_deny_last_line_does_not_stand_for_line_3526(self):
        root = self._draft(
            self._deny_block(last=DENY_LAST + "x"),
            {DENY_REL: self._deny_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_deny_span_without_an_indented_line_adds_no_refusal(self):
        body = (
            "`"
            + DENY_SPAN
            + "` states that a missing grant denies the step.\n"
            "\n"
            "The block follows.\n"
        )
        got, reads = self._pinned_reads(body, {DENY_REL: self._deny_source()})
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

    def test_deny_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + DENY_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(self._deny_block(), {DENY_REL: short})
        (root / DENY_REL).write_bytes(self._deny_source())
        self.assertEqual(check.problems(root), [expected])

    def test_two_deny_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + DENY_SPAN
        body = self._deny_block() + "\nAgain `" + DENY_SPAN + "`.\n"
        got, reads = self._pinned_reads(body, {DENY_REL: self._deny_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_draft_without_the_deny_span_adds_no_deny_refusal(self):
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {DENY_REL: self._deny_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_deny_line_mismatch_adds_no_owned_or_asks_refusal(self):
        expected = "refuse: quoted line does not match " + DENY_SPAN
        body = (
            self._deny_block(first=DENY_QUOTE + "x")
            + self._quote_body(OWNED_QUOTE + "y", NEXT_QUOTE)
            + self._asks_block(third=ASKS_THIRD + "z")
        )
        got, reads = self._pinned_reads(body, {DENY_REL: self._deny_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [DENY_NUMBER])

    def test_owned_line_mismatch_follows_the_deny_match(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        body = self._deny_block() + self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE)
        got, reads = self._pinned_reads(body, {DENY_REL: self._deny_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [DENY_NUMBER, OWNED_NUMBER])

    def test_draft_without_the_deny_span_still_refuses_an_owned_mismatch(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        root = self._draft(
            self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE),
            {DENY_REL: self._deny_source()},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_draft_without_the_deny_span_still_refuses_an_asks_mismatch(self):
        expected = "refuse: quoted line does not match " + ASKS_SPAN
        root = self._draft(
            self._asks_block(third=ASKS_THIRD + "x"),
            {DENY_REL: self._deny_source()},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_deny_quote_refusal_waits_for_a_known_pin(self):
        body = self._deny_block(first=DENY_QUOTE + "x")
        files = {DENY_REL: self._deny_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        bad_pin = "Pinned commit: HEAD\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(bad_pin, files)),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        unknown = "Pinned commit: " + "f" * 40 + "\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(unknown, files, commit=True)),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_live_draft_mint_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.mint_quote(text), MINT_SECOND)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, MINT_REL, MINT_NUMBER),
            MINT_SECOND,
        )

    def test_mint_quote_with_one_indented_line_is_the_first_line(self):
        body = self._mint_block(count=1)
        self.assertEqual(check.mint_quote(body), MINT_FIRST)
        self.assertIsNone(check.mint_quote("No mint span here.\n"))

    def test_mint_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + MINT_SPAN
        root = self._draft(
            self._mint_block(second=MINT_SECOND + "x"),
            {MINT_REL: self._mint_source()},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / MINT_REL).write_bytes(self._mint_source(second="// edited in the worktree"))
        self.assertEqual(check.problems(root), [expected])

    def test_mint_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(self._mint_block(), {MINT_REL: self._mint_source()})
        self.assertEqual(check.problems(root), [])
        (root / MINT_REL).write_bytes(self._mint_source(second="// edited in the worktree"))
        self.assertEqual(check.problems(root), [])

    def test_mint_first_line_does_not_stand_for_line_3549(self):
        root = self._draft(
            self._mint_block(first=MINT_FIRST + "x"),
            {MINT_REL: self._mint_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_mint_last_line_does_not_stand_for_line_3549(self):
        root = self._draft(
            self._mint_block(last=MINT_LAST + "x"),
            {MINT_REL: self._mint_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_mint_span_without_two_indented_lines_still_compares(self):
        got, reads = self._pinned_reads(
            self._mint_block(count=1), {MINT_REL: self._mint_source()}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + MINT_SPAN]
        )
        self.assertEqual(reads, [MINT_NUMBER])

    def test_mint_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + MINT_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(self._mint_block(), {MINT_REL: short})
        (root / MINT_REL).write_bytes(self._mint_source())
        self.assertEqual(check.problems(root), [expected])

    def test_two_mint_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + MINT_SPAN
        body = self._mint_block() + "\nAgain `" + MINT_SPAN + "`.\n"
        got, reads = self._pinned_reads(body, {MINT_REL: self._mint_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_draft_without_the_mint_span_adds_no_mint_refusal(self):
        root = self._draft(
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {MINT_REL: self._mint_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_deny_line_mismatch_adds_no_mint_refusal(self):
        expected = "refuse: quoted line does not match " + DENY_SPAN
        body = self._deny_block(first=DENY_QUOTE + "x") + self._mint_block(
            second=MINT_SECOND + "y"
        )
        got, reads = self._pinned_reads(body, {MINT_REL: self._mint_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [DENY_NUMBER])

    def test_mint_line_mismatch_adds_no_owned_refusal(self):
        expected = "refuse: quoted line does not match " + MINT_SPAN
        body = (
            self._deny_block()
            + self._mint_block(second=MINT_SECOND + "y")
            + self._quote_body(OWNED_QUOTE + "z", NEXT_QUOTE)
        )
        got, reads = self._pinned_reads(body, {MINT_REL: self._mint_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [DENY_NUMBER, MINT_NUMBER])

    def test_mint_line_match_follows_to_the_owned_refusal(self):
        expected = "refuse: quoted line does not match " + OWNED_SPAN
        body = (
            self._deny_block()
            + self._mint_block()
            + self._quote_body(OWNED_QUOTE + "x", NEXT_QUOTE)
        )
        got, reads = self._pinned_reads(body, {MINT_REL: self._mint_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [DENY_NUMBER, MINT_NUMBER, OWNED_NUMBER])

    def test_draft_without_the_mint_span_still_refuses_a_deny_mismatch(self):
        expected = "refuse: quoted line does not match " + DENY_SPAN
        root = self._draft(
            self._deny_block(first=DENY_QUOTE + "x")
            + self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {MINT_REL: self._mint_source()},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_draft_without_the_deny_span_still_refuses_a_mint_mismatch(self):
        expected = "refuse: quoted line does not match " + MINT_SPAN
        root = self._draft(
            self._mint_block(second=MINT_SECOND + "x")
            + self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {MINT_REL: self._mint_source()},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_mint_quote_refusal_waits_for_a_known_pin(self):
        body = self._mint_block(second=MINT_SECOND + "x")
        files = {MINT_REL: self._mint_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        bad_pin = "Pinned commit: HEAD\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(bad_pin, files)),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        unknown = "Pinned commit: " + "f" * 40 + "\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(unknown, files, commit=True)),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_live_draft_journal_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.journal_quote(text), JOURNAL_CONST)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, JOURNAL_REL, JOURNAL_NUMBER),
            JOURNAL_CONST,
        )
        self.assertEqual(check.problems(root), [])

    def test_journal_quote_below_two_indented_lines_is_the_first_line(self):
        self.assertEqual(
            check.journal_quote(self._journal_block(count=1)), JOURNAL_CFG
        )
        self.assertIsNone(check.journal_quote("No journal span here.\n"))

    def test_journal_fixture_keeps_line_3757_between_3755_and_8149(self):
        root = self._draft(self._journal_block(), {JOURNAL_REL: self._journal_source()})
        sha = check.pin_sha(check.load_draft(root))
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, JOURNAL_REL, NEXT_NUMBER), NEXT_QUOTE
        )
        self.assertEqual(
            check.pinned_line(root, sha, JOURNAL_REL, JOURNAL_NUMBER - 1),
            JOURNAL_CFG,
        )
        self.assertEqual(
            check.pinned_line(root, sha, JOURNAL_REL, JOURNAL_NUMBER), JOURNAL_CONST
        )
        self.assertEqual(
            check.pinned_line(root, sha, JOURNAL_REL, ASKS_NUMBER), ASKS_THIRD
        )
        self.assertEqual(
            check.pinned_line(root, sha, JOURNAL_REL, LAUNCHING_NUMBER),
            LAUNCHING_CONST,
        )
        self.assertIsNone(
            check.pinned_line(root, sha, JOURNAL_REL, LAUNCHING_NUMBER + 1)
        )

    def test_journal_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + JOURNAL_SPAN
        root = self._draft(
            self._journal_block(second=JOURNAL_CONST + "x"),
            {JOURNAL_REL: self._journal_source()},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / JOURNAL_REL).write_bytes(
            self._journal_source(second="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_journal_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(
            self._journal_block(), {JOURNAL_REL: self._journal_source()}
        )
        self.assertEqual(check.problems(root), [])
        (root / JOURNAL_REL).write_bytes(
            self._journal_source(second="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_journal_first_line_does_not_stand_for_line_3757(self):
        root = self._draft(
            self._journal_block(first=JOURNAL_CFG + "x"),
            {JOURNAL_REL: self._journal_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_journal_span_without_two_indented_lines_still_compares(self):
        got, reads = self._pinned_reads(
            self._journal_block(count=1), {JOURNAL_REL: self._journal_source()}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + JOURNAL_SPAN]
        )
        self.assertEqual(reads, [JOURNAL_NUMBER])

    def test_journal_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + JOURNAL_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(self._journal_block(), {JOURNAL_REL: short})
        (root / JOURNAL_REL).write_bytes(self._journal_source())
        self.assertEqual(check.problems(root), [expected])

    def test_two_journal_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + JOURNAL_SPAN
        body = self._journal_block() + "\nAgain `" + JOURNAL_SPAN + "`.\n"
        got, reads = self._pinned_reads(body, {JOURNAL_REL: self._journal_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_draft_without_the_journal_span_adds_no_journal_refusal(self):
        root = self._draft(self._asks_block(), {JOURNAL_REL: self._journal_source()})
        self.assertEqual(check.problems(root), [])

    def test_mint_line_mismatch_adds_no_journal_refusal(self):
        expected = "refuse: quoted line does not match " + MINT_SPAN
        body = self._mint_block(second=MINT_SECOND + "x") + self._journal_block(
            second=JOURNAL_CONST + "y"
        )
        got, reads = self._pinned_reads(body, {MINT_REL: self._mint_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [MINT_NUMBER])

    def test_next_line_mismatch_adds_no_journal_refusal(self):
        expected = "refuse: quoted line does not match " + NEXT_SPAN
        body = self._quote_body(OWNED_QUOTE, NEXT_QUOTE + "x") + self._journal_block(
            second=JOURNAL_CONST + "y"
        )
        got, reads = self._pinned_reads(body, {JOURNAL_REL: self._journal_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER, NEXT_NUMBER])

    def test_draft_without_the_owned_span_still_refuses_a_journal_mismatch(self):
        expected = "refuse: quoted line does not match " + JOURNAL_SPAN
        got, reads = self._pinned_reads(
            self._journal_block(second=JOURNAL_CONST + "x"),
            {JOURNAL_REL: self._journal_source()},
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [JOURNAL_NUMBER])

    def test_journal_line_mismatch_adds_no_asks_refusal(self):
        expected = "refuse: quoted line does not match " + JOURNAL_SPAN
        body = (
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE)
            + self._journal_block(second=JOURNAL_CONST + "x")
            + self._asks_block(third=ASKS_THIRD + "y")
        )
        got, reads = self._pinned_reads(body, {JOURNAL_REL: self._journal_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER, NEXT_NUMBER, JOURNAL_NUMBER])

    def test_journal_line_match_follows_to_the_asks_refusal(self):
        expected = "refuse: quoted line does not match " + ASKS_SPAN
        body = (
            self._quote_body(OWNED_QUOTE, NEXT_QUOTE)
            + self._journal_block()
            + self._asks_block(third=ASKS_THIRD + "x")
        )
        got, reads = self._pinned_reads(body, {JOURNAL_REL: self._journal_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [OWNED_NUMBER, NEXT_NUMBER, JOURNAL_NUMBER, ASKS_NUMBER])

    def test_draft_without_the_journal_span_still_refuses_a_mint_mismatch(self):
        expected = "refuse: quoted line does not match " + MINT_SPAN
        root = self._draft(
            self._mint_block(second=MINT_SECOND + "x")
            + self._quote_body(OWNED_QUOTE, NEXT_QUOTE),
            {MINT_REL: self._mint_source()},
        )
        self.assertEqual(check.problems(root), [expected])

    def test_journal_quote_refusal_waits_for_a_known_pin(self):
        body = self._journal_block(second=JOURNAL_CONST + "x")
        files = {JOURNAL_REL: self._journal_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        bad_pin = "Pinned commit: HEAD\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(bad_pin, files)),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        unknown = "Pinned commit: " + "f" * 40 + "\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(unknown, files, commit=True)),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_grant_quote_refusal_waits_for_a_known_pin(self):
        body = self._grant_block(first=GRANT_QUOTE + "x")
        files = {GRANT_REL: self._journal_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        bad_pin = "Pinned commit: HEAD\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(bad_pin, files)),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        unknown = "Pinned commit: " + "f" * 40 + "\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(unknown, files, commit=True)),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_live_draft_grant_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.grant_quote(text), GRANT_QUOTE)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, GRANT_REL, GRANT_NUMBER), GRANT_QUOTE
        )
        self.assertEqual(check.problems(root), [])

    def test_grant_quote_is_absent_without_an_indented_line(self):
        self.assertIsNone(check.grant_quote("No grant span here.\n"))
        self.assertIsNone(
            check.grant_quote("`" + GRANT_SPAN + "` is `JournalGrant`.\n")
        )

    def test_grant_fixture_keeps_line_3767_between_3757_and_8149(self):
        root = self._draft(self._grant_block(), {GRANT_REL: self._journal_source()})
        sha = check.pin_sha(check.load_draft(root))
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, GRANT_REL, JOURNAL_NUMBER), JOURNAL_CONST
        )
        self.assertEqual(
            check.pinned_line(root, sha, GRANT_REL, GRANT_NUMBER), GRANT_QUOTE
        )
        self.assertEqual(
            check.pinned_line(root, sha, GRANT_REL, ASKS_NUMBER), ASKS_THIRD
        )
        self.assertIsNone(
            check.pinned_line(root, sha, GRANT_REL, LAUNCHING_NUMBER + 1)
        )

    def test_grant_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + GRANT_SPAN
        root = self._draft(
            self._grant_block(first=GRANT_QUOTE + "x"),
            {GRANT_REL: self._journal_source()},
        )
        self.assertEqual(check.problems(root), [expected])
        (root / GRANT_REL).write_bytes(
            self._journal_source(grant_first="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_grant_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(self._grant_block(), {GRANT_REL: self._journal_source()})
        self.assertEqual(check.problems(root), [])
        (root / GRANT_REL).write_bytes(
            self._journal_source(grant_first="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_grant_second_line_does_not_stand_for_line_3767(self):
        root = self._draft(
            self._grant_block(second=GRANT_SECOND + "x"),
            {GRANT_REL: self._journal_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_grant_struct_line_does_not_stand_for_line_3767(self):
        root = self._draft(
            self._grant_block(struct_line=GRANT_STRUCT + "x"),
            {GRANT_REL: self._journal_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_grant_last_line_does_not_stand_for_line_3767(self):
        root = self._draft(
            self._grant_block(last=GRANT_LINES[-1] + "x"),
            {GRANT_REL: self._journal_source()},
        )
        self.assertEqual(check.problems(root), [])

    def test_grant_span_without_an_indented_line_adds_no_refusal(self):
        got, reads = self._pinned_reads(
            self._grant_block(count=0), {GRANT_REL: self._journal_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

    def test_grant_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + GRANT_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        root = self._draft(self._grant_block(), {GRANT_REL: short})
        (root / GRANT_REL).write_bytes(self._journal_source())
        self.assertEqual(check.problems(root), [expected])

    def test_two_grant_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + GRANT_SPAN
        body = (
            self._grant_block()
            + "\nAgain `"
            + GRANT_SPAN
            + "`.\n"
            + self._asks_block()
        )
        got, reads = self._pinned_reads(body, {GRANT_REL: self._journal_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_draft_without_the_grant_span_adds_no_grant_refusal(self):
        root = self._draft(self._journal_block(), {GRANT_REL: self._journal_source()})
        self.assertEqual(check.problems(root), [])

    def test_journal_line_mismatch_adds_no_grant_refusal(self):
        expected = "refuse: quoted line does not match " + JOURNAL_SPAN
        body = self._journal_block(
            second=JOURNAL_CONST + "x"
        ) + self._grant_block(first=GRANT_QUOTE + "y")
        got, reads = self._pinned_reads(body, {GRANT_REL: self._journal_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [JOURNAL_NUMBER])

    def test_grant_line_mismatch_adds_no_asks_refusal(self):
        expected = "refuse: quoted line does not match " + GRANT_SPAN
        body = (
            self._journal_block()
            + self._grant_block(first=GRANT_QUOTE + "x")
            + self._asks_block(third=ASKS_THIRD + "y")
        )
        got, reads = self._pinned_reads(body, {GRANT_REL: self._journal_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [JOURNAL_NUMBER, GRANT_NUMBER])

    def test_grant_line_match_follows_to_the_asks_refusal(self):
        expected = "refuse: quoted line does not match " + ASKS_SPAN
        body = (
            self._journal_block()
            + self._grant_block()
            + self._asks_block(third=ASKS_THIRD + "x")
        )
        got, reads = self._pinned_reads(body, {GRANT_REL: self._journal_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [JOURNAL_NUMBER, GRANT_NUMBER, ASKS_NUMBER])

    def test_draft_without_the_journal_span_still_refuses_a_grant_mismatch(self):
        expected = "refuse: quoted line does not match " + GRANT_SPAN
        got, reads = self._pinned_reads(
            self._grant_block(first=GRANT_QUOTE + "x"),
            {GRANT_REL: self._journal_source()},
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [GRANT_NUMBER])

    def test_draft_without_the_grant_span_still_refuses_a_journal_mismatch(self):
        expected = "refuse: quoted line does not match " + JOURNAL_SPAN
        got, reads = self._pinned_reads(
            self._journal_block(second=JOURNAL_CONST + "x"),
            {GRANT_REL: self._journal_source()},
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [JOURNAL_NUMBER])

    def test_live_draft_write_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.write_quote(text), WRITE_QUOTE)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, ASK_REL, WRITE_NUMBER), WRITE_QUOTE
        )
        self.assertEqual(check.problems(root), [])

    def test_live_draft_read_quote_matches_its_pinned_line(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.read_quote(text), READ_QUOTE)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(check.pinned_line(root, sha, ASK_REL, READ_NUMBER), READ_QUOTE)
        self.assertEqual(check.problems(root), [])

    def test_live_draft_ask_walk_has_twenty_remainders(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        remainders = check._remainders(text, check.WRITE_MARKER)
        self.assertEqual(len(remainders), 20)
        self.assertEqual(remainders[16], WRITE_QUOTE)
        self.assertEqual(remainders[17], READ_QUOTE)
        self.assertEqual(check._remainders(text, check.READ_MARKER), remainders)

    def test_write_quote_below_seventeen_remainders_is_the_last_line(self):
        self.assertIsNone(check.write_quote("No write span here.\n"))
        self.assertEqual(check.write_quote(self._ask_block(count=16)), ASK_LINES[15])
        self.assertEqual(check.write_quote(self._ask_block(count=17)), WRITE_QUOTE)

    def test_read_quote_below_eighteen_remainders_is_the_last_line(self):
        self.assertIsNone(check.read_quote("No read span here.\n"))
        self.assertEqual(check.read_quote(self._ask_block(count=17)), ASK_LINES[16])
        self.assertEqual(check.read_quote(self._ask_block(count=18)), READ_QUOTE)

    def test_ask_fixture_keeps_line_3849_between_3767_and_3850(self):
        root = self._draft(self._ask_block(), {ASK_REL: self._ask_source()})
        sha = check.pin_sha(check.load_draft(root))
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, ASK_REL, GRANT_NUMBER), GRANT_QUOTE
        )
        self.assertEqual(
            check.pinned_line(root, sha, ASK_REL, WRITE_NUMBER), WRITE_QUOTE
        )
        self.assertEqual(check.pinned_line(root, sha, ASK_REL, READ_NUMBER), READ_QUOTE)
        self.assertEqual(check.pinned_line(root, sha, ASK_REL, ASKS_NUMBER), ASKS_THIRD)

    def test_write_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + WRITE_SPAN
        root = self._draft(
            self._ask_block(write=WRITE_QUOTE + "x"), {ASK_REL: self._ask_source()}
        )
        self.assertEqual(check.problems(root), [expected])
        (root / ASK_REL).write_bytes(
            self._ask_source(write="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_write_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(self._ask_block(), {ASK_REL: self._ask_source()})
        self.assertEqual(check.problems(root), [])
        (root / ASK_REL).write_bytes(
            self._ask_source(write="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_write_mismatch_skips_the_read_line_read(self):
        expected = "refuse: quoted line does not match " + WRITE_SPAN
        got, reads = self._pinned_reads(
            self._ask_block(write=WRITE_QUOTE + "x"), {ASK_REL: self._ask_source()}
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [WRITE_NUMBER])

    def test_read_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + READ_SPAN
        root = self._draft(
            self._ask_block(read=READ_QUOTE + "x"), {ASK_REL: self._ask_source()}
        )
        self.assertEqual(check.problems(root), [expected])
        (root / ASK_REL).write_bytes(self._ask_source(read="// edited in the worktree"))
        self.assertEqual(check.problems(root), [expected])

    def test_read_quoted_line_match_ignores_the_worktree_file(self):
        root = self._draft(self._ask_block(), {ASK_REL: self._ask_source()})
        self.assertEqual(check.problems(root), [])
        (root / ASK_REL).write_bytes(self._ask_source(read="// edited in the worktree"))
        self.assertEqual(check.problems(root), [])

    def test_read_mismatch_skips_the_asks_line_read(self):
        expected = "refuse: quoted line does not match " + READ_SPAN
        body = self._ask_block(read=READ_QUOTE + "x") + self._asks_block(
            third=ASKS_THIRD + "y"
        )
        got, reads = self._pinned_reads(body, {ASK_REL: self._ask_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [WRITE_NUMBER, READ_NUMBER])

    def test_ask_match_follows_to_the_asks_refusal(self):
        expected = "refuse: quoted line does not match " + ASKS_SPAN
        body = self._ask_block() + self._asks_block(third=ASKS_THIRD + "x")
        got, reads = self._pinned_reads(body, {ASK_REL: self._ask_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [WRITE_NUMBER, READ_NUMBER, ASKS_NUMBER])

    def test_write_doc_line_does_not_stand_for_line_3849(self):
        root = self._draft(
            self._ask_block(first=ASK_LINES[0] + "x"), {ASK_REL: self._ask_source()}
        )
        self.assertEqual(check.problems(root), [])

    def test_read_ask_line_matches_the_pinned_read(self):
        root = self._draft(self._ask_block(), {ASK_REL: self._ask_source()})
        self.assertEqual(check.problems(root), [])

    def test_ask_grants_line_does_not_stand_for_either_cited_line(self):
        root = self._draft(
            self._ask_block(grants=ASK_LINES[18] + "x"), {ASK_REL: self._ask_source()}
        )
        self.assertEqual(check.problems(root), [])

    def test_ask_close_line_does_not_stand_for_either_cited_line(self):
        root = self._draft(
            self._ask_block(last=ASK_LINES[19] + "x"), {ASK_REL: self._ask_source()}
        )
        self.assertEqual(check.problems(root), [])

    def test_write_span_without_an_indented_line_adds_no_write_refusal(self):
        got, reads = self._pinned_reads(
            self._ask_block(count=0, spans=(WRITE_SPAN,)),
            {ASK_REL: self._ask_source()},
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

    def test_write_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + WRITE_SPAN
        short = ("// filler\n" * 10).encode("utf-8")
        got, reads = self._pinned_reads(
            self._ask_block(),
            {ASK_REL: short},
            {ASK_REL: self._ask_source()},
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [WRITE_NUMBER])

    def test_read_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + READ_SPAN
        got, reads = self._pinned_reads(
            self._without(self._ask_block(), ASK_LINES, 17),
            {ASK_REL: self._ask_source(blank=READ_NUMBER)},
            {ASK_REL: self._ask_source()},
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [WRITE_NUMBER, READ_NUMBER])

    def test_two_write_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + WRITE_SPAN
        body = self._ask_block() + "\nAgain `" + WRITE_SPAN + "`.\n"
        got, reads = self._pinned_reads(body, {ASK_REL: self._ask_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_two_read_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + READ_SPAN
        body = self._ask_block() + "\nAgain `" + READ_SPAN + "`.\n"
        got, reads = self._pinned_reads(body, {ASK_REL: self._ask_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [WRITE_NUMBER])

    def test_draft_without_the_write_span_adds_no_write_refusal(self):
        got, reads = self._pinned_reads(
            self._ask_block(spans=(READ_SPAN,)), {ASK_REL: self._ask_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [READ_NUMBER])

    def test_draft_without_the_read_span_adds_no_read_refusal(self):
        got, reads = self._pinned_reads(
            self._ask_block(spans=(WRITE_SPAN,)), {ASK_REL: self._ask_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [WRITE_NUMBER])

    def test_grant_line_mismatch_adds_no_write_refusal(self):
        expected = "refuse: quoted line does not match " + GRANT_SPAN
        body = self._grant_block(first=GRANT_QUOTE + "y") + self._ask_block(
            write=WRITE_QUOTE + "x"
        )
        got, reads = self._pinned_reads(body, {ASK_REL: self._ask_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [GRANT_NUMBER])

    def test_draft_without_the_grant_span_still_refuses_a_write_mismatch(self):
        expected = "refuse: quoted line does not match " + WRITE_SPAN
        got, reads = self._pinned_reads(
            self._ask_block(write=WRITE_QUOTE + "x"), {ASK_REL: self._ask_source()}
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [WRITE_NUMBER])

    def test_ask_quote_refusal_waits_for_a_known_pin(self):
        body = self._ask_block(write=WRITE_QUOTE + "x")
        files = {ASK_REL: self._ask_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        bad_pin = "Pinned commit: HEAD\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(bad_pin, files)),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        unknown = "Pinned commit: " + "f" * 40 + "\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(unknown, files, commit=True)),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_falsifier_missing_path_is_caught(self):
        self._caught(
            "read_file",
            lambda root, rel: b"fn x() {\n",
            self.test_missing_path_is_refused,
            "refuse: path does not exist:",
            "CAUGHT missing-path",
        )

    def test_falsifier_past_end_line_is_caught(self):
        self._caught(
            "line_count",
            lambda text: 10**9,
            self.test_past_end_line_is_refused,
            "refuse: line ",
            "CAUGHT past-end-line",
        )

    def test_falsifier_missing_function_is_caught(self):
        self._caught(
            "has_function",
            lambda text, name: True,
            self.test_missing_function_is_refused,
            "refuse: function ",
            "CAUGHT missing-function",
        )

    def test_falsifier_non_utf8_is_caught(self):
        self._caught(
            "decode_text",
            lambda data: "fn x() {\n",
            self.test_non_utf8_file_is_refused,
            "refuse: path is not utf-8 text:",
            "CAUGHT non-utf8",
        )

    def test_falsifier_reversed_range_is_caught(self):
        self._caught(
            "range_is_reversed",
            lambda start, end: False,
            self.test_reversed_range_is_refused,
            "refuse: line range ",
            "CAUGHT reversed-range",
        )

    def test_falsifier_absent_draft_is_caught(self):
        self._caught(
            "load_draft",
            lambda root: "Pinned commit: " + "a" * 40 + "\n",
            self.test_absent_draft_is_refused,
            "refuse: proposal is absent",
            "CAUGHT absent-draft",
        )

    def test_falsifier_missing_pin_is_caught(self):
        self._caught(
            "pin_refusal",
            lambda text: None,
            self.test_missing_pin_is_refused,
            "refuse: draft has no pinned commit",
            "CAUGHT missing-pin",
        )

    def test_falsifier_pin_line_is_caught(self):
        self._caught(
            "pin_refusal",
            lambda text: None,
            self.test_pin_line_is_one_commit,
            "refuse: pinned commit is not one 40-hex commit",
            "CAUGHT pin-line",
        )

    def test_falsifier_unknown_pin_is_caught(self):
        self._caught(
            "commit_exists",
            lambda root, sha: True,
            self.test_unknown_pin_is_refused,
            "refuse: pinned commit is not a commit:",
            "CAUGHT unknown-pin",
        )

    def test_falsifier_quoted_line_mismatch_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT quoted-line",
        )

    def test_falsifier_next_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_next_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT next-quoted-line",
        )

    def test_falsifier_marker_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_marker_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT marker-quoted-line",
        )

    def test_falsifier_launching_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_launching_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT launching-quoted-line",
        )

    def test_falsifier_asks_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_asks_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT asks-quoted-line",
        )

    def test_falsifier_deny_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_deny_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT deny-quoted-line",
        )

    def test_falsifier_mint_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_mint_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT mint-quoted-line",
        )

    def test_falsifier_journal_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_journal_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT journal-quoted-line",
        )

    def test_falsifier_mint_one_indented_line_skip_is_caught(self):
        """Restoring the 131 skip for a one-line walk is caught."""

        def skip_a_one_line_walk(text):
            remainders = check._remainders(text, check.MINT_MARKER)
            if len(remainders) < 2:
                return None
            return remainders[-1]

        self._caught(
            "mint_quote",
            skip_a_one_line_walk,
            self.test_mint_span_without_two_indented_lines_still_compares,
            "refuse: quoted line does not match",
            "CAUGHT mint-one-line-skip",
        )

    def test_falsifier_journal_first_line_is_caught(self):
        def planted(text):
            remainders = check._remainders(text, check.JOURNAL_MARKER)
            if len(remainders) < 2:
                return None
            return remainders[0]

        self._caught(
            "journal_quote",
            planted,
            self.test_journal_first_line_does_not_stand_for_line_3757,
            "refuse: quoted line does not match",
            "CAUGHT journal-first-line",
        )

    def test_falsifier_grant_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_grant_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT grant-quoted-line",
        )

    def test_falsifier_grant_second_line_is_caught(self):
        def planted(text):
            remainders = check._remainders(text, check.GRANT_MARKER)
            if len(remainders) < 2:
                return None
            return remainders[1]

        self._caught(
            "grant_quote",
            planted,
            self.test_grant_second_line_does_not_stand_for_line_3767,
            "refuse: quoted line does not match",
            "CAUGHT grant-second-line",
        )

    def test_falsifier_write_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_write_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT write-quoted-line",
        )

    def test_falsifier_write_doc_line_is_caught(self):
        def planted(text):
            remainders = check._remainders(text, check.WRITE_MARKER)
            if not remainders:
                return None
            return remainders[0]

        self._caught(
            "write_quote",
            planted,
            self.test_write_doc_line_does_not_stand_for_line_3849,
            "refuse: quoted line does not match",
            "CAUGHT write-doc-line",
        )

    def test_falsifier_read_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_read_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT read-quoted-line",
        )

    def test_falsifier_read_write_line_is_caught(self):
        def planted(text):
            remainders = check._remainders(text, check.READ_MARKER)
            if len(remainders) < 17:
                return None
            return remainders[16]

        self._caught(
            "read_quote",
            planted,
            self.test_read_ask_line_matches_the_pinned_read,
            "refuse: quoted line does not match",
            "CAUGHT read-write-line",
        )

    def test_live_draft_kind_arms_match_their_pinned_lines(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.kind_read_quote(text), KIND_READ_QUOTE)
        self.assertEqual(check.kind_edit_quote(text), KIND_EDIT_QUOTE)
        self.assertEqual(check.kind_restore_quote(text), KIND_RESTORE_QUOTE)
        remainders = check._remainders(text, check.KIND_READ_MARKER)
        self.assertEqual(len(remainders), len(KIND_LINES))
        self.assertEqual(check._remainders(text, check.KIND_EDIT_MARKER), remainders)
        self.assertEqual(check._remainders(text, check.KIND_RESTORE_MARKER), remainders)
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, KIND_REL, KIND_READ_NUMBER), KIND_READ_QUOTE
        )
        self.assertEqual(
            check.pinned_line(root, sha, KIND_REL, KIND_EDIT_NUMBER), KIND_EDIT_QUOTE
        )
        self.assertEqual(
            check.pinned_line(root, sha, KIND_REL, KIND_RESTORE_NUMBER),
            KIND_RESTORE_QUOTE,
        )
        self.assertEqual(check.problems(root), [])

    def test_kind_fixture_keeps_the_arms_on_their_pinned_lines(self):
        root = self._draft(self._kind_block(), {KIND_REL: self._kind_source()})
        sha = check.pin_sha(check.load_draft(root))
        self.assertIsNotNone(sha)
        self.assertEqual(
            check.pinned_line(root, sha, KIND_REL, KIND_READ_NUMBER), KIND_READ_QUOTE
        )
        self.assertEqual(
            check.pinned_line(root, sha, KIND_REL, KIND_EDIT_NUMBER), KIND_EDIT_QUOTE
        )
        self.assertEqual(
            check.pinned_line(root, sha, KIND_REL, KIND_RUN_NUMBER), KIND_RUN_QUOTE
        )
        self.assertEqual(
            check.pinned_line(root, sha, KIND_REL, KIND_RESTORE_NUMBER),
            KIND_RESTORE_QUOTE,
        )
        self.assertEqual(
            check.pinned_line(root, sha, KIND_REL, KIND_BLOCK_END),
            KIND_LINES[-1],
        )
        self.assertIsNone(
            check.pinned_line(root, sha, KIND_REL, KIND_BLOCK_END + 1)
        )

    def test_kind_quotes_below_their_index_read_their_own_windows(self):
        cases = (
            (8, (KIND_LINES[7], KIND_LINES[7], KIND_LINES[7])),
            (9, (KIND_READ_QUOTE, KIND_READ_QUOTE, KIND_READ_QUOTE)),
            (
                11,
                (KIND_READ_QUOTE, KIND_EDIT_QUOTE, KIND_RUN_QUOTE),
            ),
            (
                12,
                (KIND_READ_QUOTE, KIND_EDIT_QUOTE, KIND_RESTORE_QUOTE),
            ),
        )
        for count, expected in cases:
            body = self._kind_block(count=count)
            self.assertEqual(
                (
                    check.kind_read_quote(body),
                    check.kind_edit_quote(body),
                    check.kind_restore_quote(body),
                ),
                expected,
                count,
            )
        self.assertIsNone(check.kind_read_quote("No kind span here.\n"))
        self.assertIsNone(check.kind_edit_quote("No kind span here.\n"))
        self.assertIsNone(check.kind_restore_quote("No kind span here.\n"))

    def test_kind_read_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + KIND_READ_SPAN
        got, reads = self._pinned_reads(
            self._kind_block(read=KIND_READ_QUOTE + "x"),
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [KIND_READ_NUMBER])
        root = self._draft(
            self._kind_block(read=KIND_READ_QUOTE + "x"),
            {KIND_REL: self._kind_source()},
        )
        (root / KIND_REL).write_bytes(
            self._kind_source(read="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_kind_read_doc_line_does_not_stand_for_line_8187(self):
        got, reads = self._pinned_reads(
            self._kind_block(first=KIND_LINES[0] + "x"),
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [])
        self.assertEqual(
            reads, [KIND_READ_NUMBER, KIND_EDIT_NUMBER, KIND_RESTORE_NUMBER]
        )

    def test_kind_read_quote_match_ignores_the_worktree_file(self):
        root = self._draft(self._kind_block(), {KIND_REL: self._kind_source()})
        self.assertEqual(check.problems(root), [])
        (root / KIND_REL).write_bytes(
            self._kind_source(read="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_kind_read_span_without_an_indented_line_adds_no_refusal(self):
        got, reads = self._pinned_reads(
            self._kind_block(count=0), {KIND_REL: self._kind_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

    def test_kind_read_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + KIND_READ_SPAN
        got, reads = self._pinned_reads(
            self._without(self._kind_block(), KIND_LINES, 8),
            {KIND_REL: self._kind_source(blank=KIND_READ_NUMBER)},
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [KIND_READ_NUMBER])

    def test_two_kind_read_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + KIND_READ_SPAN
        prose = (
            "`"
            + KIND_READ_SPAN
            + "` is the Read arm. Again `"
            + KIND_READ_SPAN
            + "`.\n"
        )
        got, reads = self._pinned_reads(
            self._kind_block(prose=prose), {KIND_REL: self._kind_source()}
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_draft_without_the_kind_read_span_adds_no_read_arm_refusal(self):
        prose = (
            "`"
            + KIND_EDIT_SPAN
            + "` is the Edit arm. `"
            + KIND_RESTORE_SPAN
            + "` is the Restore arm.\n"
        )
        got, reads = self._pinned_reads(
            self._kind_block(read=KIND_READ_QUOTE + "x", prose=prose),
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [KIND_EDIT_NUMBER, KIND_RESTORE_NUMBER])

    def test_draft_without_the_kind_read_span_still_refuses_the_edit_arm(self):
        prose = (
            "`"
            + KIND_EDIT_SPAN
            + "` is the Edit arm. `"
            + KIND_RESTORE_SPAN
            + "` is the Restore arm.\n"
        )
        expected = "refuse: quoted line does not match " + KIND_EDIT_SPAN
        got, reads = self._pinned_reads(
            self._kind_block(edit=KIND_EDIT_QUOTE + "x", prose=prose),
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [KIND_EDIT_NUMBER])
        expected = "refuse: quoted line does not match " + KIND_RESTORE_SPAN
        got, reads = self._pinned_reads(
            self._kind_block(restore=KIND_RESTORE_QUOTE + "x", prose=prose),
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [KIND_EDIT_NUMBER, KIND_RESTORE_NUMBER])

    def test_kind_edit_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + KIND_EDIT_SPAN
        got, reads = self._pinned_reads(
            self._kind_block(edit=KIND_EDIT_QUOTE + "x"),
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [KIND_READ_NUMBER, KIND_EDIT_NUMBER])
        root = self._draft(
            self._kind_block(edit=KIND_EDIT_QUOTE + "x"),
            {KIND_REL: self._kind_source()},
        )
        (root / KIND_REL).write_bytes(
            self._kind_source(edit="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_kind_edit_read_line_does_not_stand_for_line_8188(self):
        got, reads = self._pinned_reads(
            self._kind_block(), {KIND_REL: self._kind_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(
            reads, [KIND_READ_NUMBER, KIND_EDIT_NUMBER, KIND_RESTORE_NUMBER]
        )

    def test_kind_edit_quote_match_ignores_the_worktree_file(self):
        root = self._draft(self._kind_block(), {KIND_REL: self._kind_source()})
        self.assertEqual(check.problems(root), [])
        (root / KIND_REL).write_bytes(
            self._kind_source(edit="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_kind_edit_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + KIND_EDIT_SPAN
        got, reads = self._pinned_reads(
            self._without(self._kind_block(), KIND_LINES, 9),
            {KIND_REL: self._kind_source(blank=KIND_EDIT_NUMBER)},
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [KIND_READ_NUMBER, KIND_EDIT_NUMBER])

    def test_two_kind_edit_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + KIND_EDIT_SPAN
        prose = (
            "`"
            + KIND_READ_SPAN
            + "` is the Read arm. `"
            + KIND_EDIT_SPAN
            + "` is the Edit arm. Again `"
            + KIND_EDIT_SPAN
            + "`.\n"
        )
        got, reads = self._pinned_reads(
            self._kind_block(prose=prose), {KIND_REL: self._kind_source()}
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [KIND_READ_NUMBER])

    def test_draft_without_the_kind_edit_span_adds_no_edit_arm_refusal(self):
        prose = (
            "`"
            + KIND_READ_SPAN
            + "` is the Read arm. `"
            + KIND_RESTORE_SPAN
            + "` is the Restore arm.\n"
        )
        got, reads = self._pinned_reads(
            self._kind_block(edit=KIND_EDIT_QUOTE + "x", prose=prose),
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [KIND_READ_NUMBER, KIND_RESTORE_NUMBER])

    def test_kind_restore_quoted_line_mismatch_is_refused(self):
        expected = "refuse: quoted line does not match " + KIND_RESTORE_SPAN
        got, reads = self._pinned_reads(
            self._kind_block(restore=KIND_RESTORE_QUOTE + "x"),
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [expected])
        self.assertEqual(
            reads, [KIND_READ_NUMBER, KIND_EDIT_NUMBER, KIND_RESTORE_NUMBER]
        )
        root = self._draft(
            self._kind_block(restore=KIND_RESTORE_QUOTE + "x"),
            {KIND_REL: self._kind_source()},
        )
        (root / KIND_REL).write_bytes(
            self._kind_source(restore="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [expected])

    def test_kind_restore_run_line_does_not_stand_for_line_8190(self):
        got, reads = self._pinned_reads(
            self._kind_block(run=KIND_RUN_QUOTE + "x"),
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [])
        self.assertEqual(
            reads, [KIND_READ_NUMBER, KIND_EDIT_NUMBER, KIND_RESTORE_NUMBER]
        )

    def test_kind_close_line_does_not_stand_for_the_arms(self):
        got, reads = self._pinned_reads(
            self._kind_block(last=KIND_LINES[-1] + "x"),
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [])
        self.assertEqual(
            reads, [KIND_READ_NUMBER, KIND_EDIT_NUMBER, KIND_RESTORE_NUMBER]
        )

    def test_kind_restore_quote_match_ignores_the_worktree_file(self):
        root = self._draft(self._kind_block(), {KIND_REL: self._kind_source()})
        self.assertEqual(check.problems(root), [])
        (root / KIND_REL).write_bytes(
            self._kind_source(restore="// edited in the worktree")
        )
        self.assertEqual(check.problems(root), [])

    def test_kind_restore_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        expected = "refuse: quoted line is not in the pinned commit: " + KIND_RESTORE_SPAN
        got, reads = self._pinned_reads(
            self._without(self._kind_block(), KIND_LINES, 11),
            {KIND_REL: self._kind_source(blank=KIND_RESTORE_NUMBER)},
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [expected])
        self.assertEqual(
            reads, [KIND_READ_NUMBER, KIND_EDIT_NUMBER, KIND_RESTORE_NUMBER]
        )

    def test_two_kind_restore_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + KIND_RESTORE_SPAN
        prose = (
            "`"
            + KIND_READ_SPAN
            + "` is the Read arm. `"
            + KIND_EDIT_SPAN
            + "` is the Edit arm. `"
            + KIND_RESTORE_SPAN
            + "` is the Restore arm. Again `"
            + KIND_RESTORE_SPAN
            + "`.\n"
        )
        got, reads = self._pinned_reads(
            self._kind_block(prose=prose), {KIND_REL: self._kind_source()}
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [KIND_READ_NUMBER, KIND_EDIT_NUMBER])

    def test_draft_without_the_kind_restore_span_adds_no_restore_arm_refusal(self):
        prose = (
            "`"
            + KIND_READ_SPAN
            + "` is the Read arm. `"
            + KIND_EDIT_SPAN
            + "` is the Edit arm.\n"
        )
        got, reads = self._pinned_reads(
            self._kind_block(restore=KIND_RESTORE_QUOTE + "x", prose=prose),
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [KIND_READ_NUMBER, KIND_EDIT_NUMBER])

    def test_launching_line_mismatch_adds_no_kind_refusal(self):
        expected = "refuse: quoted line does not match " + LAUNCHING_SPAN
        body = self._launching_body(LAUNCHING_CONST + "x") + self._kind_block(
            read=KIND_READ_QUOTE + "y"
        )
        got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [LAUNCHING_NUMBER])

    def test_draft_without_the_launching_span_still_refuses_a_kind_mismatch(self):
        expected = "refuse: quoted line does not match " + KIND_READ_SPAN
        got, reads = self._pinned_reads(
            self._kind_block(read=KIND_READ_QUOTE + "x"),
            {KIND_REL: self._kind_source()},
        )
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [KIND_READ_NUMBER])

    def test_read_line_mismatch_adds_no_kind_refusal(self):
        expected = "refuse: quoted line does not match " + READ_SPAN
        body = self._ask_block(read=READ_QUOTE + "x") + self._kind_block(
            edit=KIND_EDIT_QUOTE + "z"
        )
        got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [WRITE_NUMBER, READ_NUMBER])

    def test_asks_line_mismatch_adds_no_kind_refusal(self):
        expected = "refuse: quoted line does not match " + ASKS_SPAN
        body = self._asks_block(third=ASKS_THIRD + "x") + self._kind_block()
        got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [ASKS_NUMBER])

    def test_kind_quote_refusal_waits_for_a_known_pin(self):
        body = self._kind_block(read=KIND_READ_QUOTE + "x")
        files = {KIND_REL: self._kind_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        bad_pin = "Pinned commit: HEAD\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(bad_pin, files)),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        unknown = "Pinned commit: " + "f" * 40 + "\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(unknown, files, commit=True)),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_falsifier_kind_read_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_kind_read_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT kind-read-quoted-line",
        )

    def test_falsifier_kind_read_doc_line_is_caught(self):
        def planted(text):
            remainders = check._remainders(text, check.KIND_READ_MARKER)
            if not remainders:
                return None
            return remainders[0]

        self._caught(
            "kind_read_quote",
            planted,
            self.test_kind_read_doc_line_does_not_stand_for_line_8187,
            "refuse: quoted line does not match",
            "CAUGHT kind-read-doc-line",
        )

    def test_falsifier_kind_edit_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_kind_edit_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT kind-edit-quoted-line",
        )

    def test_falsifier_kind_edit_read_line_is_caught(self):
        def planted(text):
            remainders = check._remainders(text, check.KIND_EDIT_MARKER)
            if len(remainders) < 9:
                return None
            return remainders[8]

        self._caught(
            "kind_edit_quote",
            planted,
            self.test_kind_edit_read_line_does_not_stand_for_line_8188,
            "refuse: quoted line does not match",
            "CAUGHT kind-edit-read-line",
        )

    def test_falsifier_kind_restore_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_kind_restore_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT kind-restore-quoted-line",
        )

    def test_falsifier_kind_restore_run_line_is_caught(self):
        def planted(text):
            remainders = check._remainders(text, check.KIND_RESTORE_MARKER)
            if len(remainders) < 11:
                return None
            return remainders[10]

        self._caught(
            "kind_restore_quote",
            planted,
            self.test_kind_restore_run_line_does_not_stand_for_line_8190,
            "refuse: quoted line does not match",
            "CAUGHT kind-restore-run-line",
        )

    def _arm(self, name):
        for arm in KIND_LINE_ARMS:
            if arm[0] == name:
                return arm
        raise AssertionError(name)

    def _assert_arm_mismatch(self, name, quoted):
        _, number, span, _, _ = self._arm(name)
        expected = "refuse: quoted line does not match " + span
        body = self._kind_line_body(**{name: quoted})
        got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
        self.assertEqual(got, [expected])
        position = KIND_DECISION_ORDER.index(number)
        self.assertEqual(reads, list(KIND_DECISION_ORDER[: position + 1]))
        root = self._draft(body, {KIND_REL: self._kind_source()})
        (root / KIND_REL).write_bytes(
            self._kind_source(**{name: "// edited in the worktree"})
        )
        self.assertEqual(check.problems(root), [expected])

    def _assert_block_arm_not_cited(self, name, index):
        _, number, span, quote, _ = self._arm(name)
        block = self._kind_block(**{name: quote + "x"})
        got, reads = self._pinned_reads(
            self._kind_line_body(block=block), {KIND_REL: self._kind_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, list(KIND_DECISION_ORDER))

    def test_live_draft_kind_line_arms_match_their_pinned_lines(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        for name, number, span, quote, index in KIND_LINE_ARMS:
            selector = getattr(check, "kind_" + name + "_quote")
            self.assertEqual(selector(text), quote, span)
            self.assertEqual(
                len(check._remainders(text, "`" + span + "`")), 1, span
            )
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        for name, number, span, quote, index in KIND_LINE_ARMS:
            self.assertEqual(
                check.pinned_line(root, sha, KIND_REL, number), quote, name
            )
        self.assertEqual(check.problems(root), [])

    def test_kind_line_fixture_keeps_the_arms_on_their_pinned_lines(self):
        root = self._draft(self._kind_line_body(), {KIND_REL: self._kind_source()})
        self.assertEqual(check.problems(root), [])
        sha = check.pin_sha(check.load_draft(root))
        self.assertIsNotNone(sha)
        for name, number, span, quote, index in KIND_LINE_ARMS:
            self.assertEqual(
                check.pinned_line(root, sha, KIND_REL, number), quote, name
            )

    def test_kind_line_quotes_are_absent_without_a_remainder(self):
        for name, number, span, quote, index in KIND_LINE_ARMS:
            selector = getattr(check, "kind_" + name + "_quote")
            self.assertIsNone(
                selector(self._kind_line_body(spans=[span], indented=False)), name
            )
            self.assertIsNone(selector("No kind span here.\n"), name)

    def test_run_quoted_line_mismatch_is_refused(self):
        self._assert_arm_mismatch("run", KIND_RUN_QUOTE + "x")

    def test_run_block_arm_does_not_stand_for_line_8189(self):
        self._assert_block_arm_not_cited("run", 10)

    def test_hosted_quoted_line_mismatch_is_refused(self):
        self._assert_arm_mismatch("hosted", KIND_HOSTED_QUOTE + "x")

    def test_hosted_block_arm_does_not_stand_for_line_8191(self):
        self._assert_block_arm_not_cited("hosted", 12)

    def test_child_quoted_line_mismatch_is_refused(self):
        self._assert_arm_mismatch("child", KIND_CHILD_QUOTE + "x")

    def test_child_block_arm_does_not_stand_for_line_8192(self):
        self._assert_block_arm_not_cited("child", 13)

    def test_init_quoted_line_mismatch_is_refused(self):
        self._assert_arm_mismatch("init", KIND_INIT_QUOTE + "x")

    def test_init_block_arm_does_not_stand_for_line_8193(self):
        self._assert_block_arm_not_cited("init", 14)

    def test_append_quoted_line_mismatch_is_refused(self):
        self._assert_arm_mismatch("append", KIND_APPEND_QUOTE + "x")

    def test_append_block_arm_does_not_stand_for_line_8194(self):
        self._assert_block_arm_not_cited("append", 15)

    def test_kind_line_quote_match_ignores_the_worktree_file(self):
        for name, number, span, quote, index in KIND_LINE_ARMS:
            root = self._draft(
                self._kind_line_body(), {KIND_REL: self._kind_source()}
            )
            self.assertEqual(check.problems(root), [], name)
            (root / KIND_REL).write_bytes(
                self._kind_source(**{name: "// edited in the worktree"})
            )
            self.assertEqual(check.problems(root), [], name)

    def test_kind_line_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        for name, number, span, quote, index in KIND_LINE_ARMS:
            expected = "refuse: quoted line is not in the pinned commit: " + span
            body = self._without(self._kind_line_body(), KIND_LINES, index)
            got, reads = self._pinned_reads(
                body,
                {KIND_REL: self._kind_source(blank=number)},
                {KIND_REL: self._kind_source()},
            )
            self.assertEqual(got, [expected], name)
            position = KIND_DECISION_ORDER.index(number)
            self.assertEqual(
                reads, list(KIND_DECISION_ORDER[: position + 1]), name
            )

    def _arm_span(self, number):
        for name, arm_number, span, quote, index in KIND_LINE_ARMS:
            if arm_number == number:
                return span
        return {
            KIND_READ_NUMBER: KIND_READ_SPAN,
            KIND_EDIT_NUMBER: KIND_EDIT_SPAN,
            KIND_RESTORE_NUMBER: KIND_RESTORE_SPAN,
        }[number]

    def _present_decisions(self, body):
        """Return the decision numbers whose span the draft cites."""
        return [
            number
            for number in KIND_DECISION_ORDER
            if "`" + self._arm_span(number) + "`" in body
        ]

    def test_two_kind_line_spans_are_refused(self):
        for name, number, span, quote, index in KIND_LINE_ARMS:
            expected = "refuse: quoted line is not one line: " + span
            body = self._kind_line_body(spans=[span], repeats={span: 2})
            got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
            self.assertEqual(got, [expected], name)
            present = self._present_decisions(body)
            self.assertEqual(reads, present[: present.index(number)], name)

    def test_draft_without_a_kind_line_span_adds_no_refusal(self):
        all_spans = [arm[2] for arm in KIND_LINE_ARMS]
        for name, number, span, quote, index in KIND_LINE_ARMS:
            body = self._kind_line_body(
                spans=[other for other in all_spans if other != span]
            )
            got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
            self.assertEqual(got, [], name)
            self.assertEqual(
                reads,
                [other for other in KIND_DECISION_ORDER if other != number],
                name,
            )

    def test_kind_line_span_without_an_indented_line_adds_no_refusal(self):
        for name, number, span, quote, index in KIND_LINE_ARMS:
            body = self._kind_line_body(spans=[span], indented=False)
            got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
            self.assertEqual(got, [], name)
            present = self._present_decisions(body)
            self.assertEqual(
                reads, [other for other in present if other != number], name
            )

    def test_kind_edit_mismatch_stops_the_run_decision(self):
        body = self._kind_line_body(
            block=self._kind_block(edit=KIND_EDIT_QUOTE + "x"),
            run=KIND_RUN_QUOTE + "y",
        )
        got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + KIND_EDIT_SPAN]
        )
        self.assertEqual(reads, [KIND_READ_NUMBER, KIND_EDIT_NUMBER])

    def test_draft_without_the_kind_edit_span_still_refuses_the_run_arm(self):
        prose = (
            "`"
            + KIND_READ_SPAN
            + "` is the Read arm. `"
            + KIND_RESTORE_SPAN
            + "` is the Restore arm.\n"
        )
        body = self._kind_line_body(
            block=self._kind_block(prose=prose), run=KIND_RUN_QUOTE + "y"
        )
        got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + KIND_RUN_SPAN]
        )
        self.assertEqual(reads, [KIND_READ_NUMBER, KIND_RUN_NUMBER])

    def test_edit_mismatch_without_the_run_span_stays_the_edit_refusal(self):
        body = self._kind_line_body(
            block=self._kind_block(edit=KIND_EDIT_QUOTE + "x"),
            spans=[arm[2] for arm in KIND_LINE_ARMS if arm[0] != "run"],
        )
        got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + KIND_EDIT_SPAN]
        )
        self.assertEqual(reads, [KIND_READ_NUMBER, KIND_EDIT_NUMBER])

    def test_draft_without_the_run_span_keeps_the_restore_refusal(self):
        body = self._kind_line_body(
            block=self._kind_block(restore=KIND_RESTORE_QUOTE + "x"),
            spans=[arm[2] for arm in KIND_LINE_ARMS if arm[0] != "run"],
        )
        got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + KIND_RESTORE_SPAN]
        )
        self.assertEqual(
            reads, [KIND_READ_NUMBER, KIND_EDIT_NUMBER, KIND_RESTORE_NUMBER]
        )

    def test_draft_without_the_run_span_still_refuses_a_later_arm(self):
        spans = [arm[2] for arm in KIND_LINE_ARMS if arm[0] != "run"]
        for name, number, span, quote, index in KIND_LINE_ARMS:
            if name == "run":
                continue
            body = self._kind_line_body(spans=spans, **{name: quote + "x"})
            got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
            self.assertEqual(
                got, ["refuse: quoted line does not match " + span], name
            )

    def test_kind_restore_mismatch_stops_the_hosted_decision(self):
        body = self._kind_line_body(
            block=self._kind_block(restore=KIND_RESTORE_QUOTE + "x"),
            hosted=KIND_HOSTED_QUOTE + "y",
        )
        got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + KIND_RESTORE_SPAN]
        )
        self.assertEqual(
            reads,
            [
                KIND_READ_NUMBER,
                KIND_EDIT_NUMBER,
                KIND_RUN_NUMBER,
                KIND_RESTORE_NUMBER,
            ],
        )

    def test_launching_mismatch_stops_the_run_decision(self):
        body = self._launching_body(LAUNCHING_CONST + "x") + self._kind_line_body(
            run=KIND_RUN_QUOTE + "y"
        )
        got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + LAUNCHING_SPAN]
        )
        self.assertEqual(reads, [LAUNCHING_NUMBER])

    def test_asks_mismatch_stops_the_run_decision(self):
        body = self._asks_block(third=ASKS_THIRD + "x") + self._kind_line_body()
        got, reads = self._pinned_reads(body, {KIND_REL: self._kind_source()})
        self.assertEqual(got, ["refuse: quoted line does not match " + ASKS_SPAN])
        self.assertEqual(reads, [ASKS_NUMBER])

    def test_kind_line_quote_refusal_waits_for_a_known_pin(self):
        body = self._kind_line_body(run=KIND_RUN_QUOTE + "x")
        files = {KIND_REL: self._kind_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        bad_pin = "Pinned commit: HEAD\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(bad_pin, files)),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        unknown = "Pinned commit: " + "f" * 40 + "\n" + body
        self.assertEqual(
            check.problems(self._raw_draft(unknown, files, commit=True)),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def _caught_block_arm(self, selector, index, named_test, label):
        def planted(text):
            remainders = check._remainders(text, check.KIND_READ_MARKER)
            if len(remainders) <= index:
                return None
            return remainders[index]

        self._caught(
            selector,
            planted,
            named_test,
            "refuse: quoted line does not match",
            label,
        )

    def test_falsifier_run_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_run_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT run-quoted-line",
        )

    def test_falsifier_run_block_arm_is_caught(self):
        self._caught_block_arm(
            "kind_run_quote",
            10,
            self.test_run_block_arm_does_not_stand_for_line_8189,
            "CAUGHT run-block-arm",
        )

    def test_falsifier_hosted_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_hosted_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT hosted-quoted-line",
        )

    def test_falsifier_hosted_block_arm_is_caught(self):
        self._caught_block_arm(
            "kind_hosted_quote",
            12,
            self.test_hosted_block_arm_does_not_stand_for_line_8191,
            "CAUGHT hosted-block-arm",
        )

    def test_falsifier_child_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_child_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT child-quoted-line",
        )

    def test_falsifier_child_block_arm_is_caught(self):
        self._caught_block_arm(
            "kind_child_quote",
            13,
            self.test_child_block_arm_does_not_stand_for_line_8192,
            "CAUGHT child-block-arm",
        )

    def test_falsifier_init_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_init_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT init-quoted-line",
        )

    def test_falsifier_init_block_arm_is_caught(self):
        self._caught_block_arm(
            "kind_init_quote",
            14,
            self.test_init_block_arm_does_not_stand_for_line_8193,
            "CAUGHT init-block-arm",
        )

    def test_falsifier_append_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_append_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT append-quoted-line",
        )

    def test_falsifier_append_block_arm_is_caught(self):
        self._caught_block_arm(
            "kind_append_quote",
            15,
            self.test_append_block_arm_does_not_stand_for_line_8194,
            "CAUGHT append-block-arm",
        )

    def _zero_score_case(self):
        """A draft whose cited line sits in a window that scores zero.

        The pinned file holds text at 3754 that the walk does not repeat, so
        every window that contains 3754 scores 0. That window is still the one
        compared, so the walk's second line is refused against 3754.
        """
        body = (
            "`" + OWNED_SPAN + "` states the journal root.\n"
            "\n"
            "    /// the line before the cited one\n"
            "    /// the line after the cited one\n"
            "\n"
        )
        return body, {OWNED_REL: self._source("// not the owned quote")}

    def _foreign_source(self, away=3800):
        """A pinned file whose unchanged 3754 text stands at AWAY, not at 3754."""
        rows = ["// filler"] * (away - 1)
        rows[OWNED_NUMBER - 1] = "// not the owned quote"
        rows += [OWNED_QUOTE, NEXT_QUOTE]
        return self._padded(rows)

    def test_quote_window_score_is_the_matching_lines(self):
        """The window with more matching lines wins."""
        remainders = ["/// one", "/// two"]
        pinned = (
            (11, "/// no match here"),
            (12, "/// one"),
            (13, "/// two"),
        )
        self.assertEqual(
            check._quote_window(remainders, pinned, 12),
            pinned[1:3],
            "refuse: quoted line does not match " + OWNED_SPAN,
        )
        self.assertEqual(
            check._quote_window(remainders, pinned, 11),
            pinned[0:2],
            "refuse: quoted line does not match " + OWNED_SPAN,
        )

    def test_quote_window_scores_only_windows_that_contain_the_line(self):
        """A window away from the cited line is never scored for it."""
        remainders = ["/// one", "/// two"]
        pinned = (
            (10, "/// no match here"),
            (11, "/// no match here"),
            (14, "/// one"),
            (15, "/// two"),
        )
        self.assertEqual(
            check._quote_window(remainders, pinned, 11),
            pinned[0:2],
            "refuse: quoted line does not match " + OWNED_SPAN,
        )
        self.assertIsNone(check._quote_window([], pinned, 11))
        self.assertIsNone(check._quote_window(remainders, pinned, 17))
        self.assertIsNone(check._quote_window(remainders, (), 11))

    def test_quote_window_tie_uses_earliest_start(self):
        """Two windows that score the same keep the earlier start line."""
        remainders = ["/// one", "/// two"]
        pinned = (
            (10, "/// one"),
            (11, "/// one"),
            (12, "/// one"),
        )
        self.assertEqual(
            check._quote_window(remainders, pinned, 11),
            pinned[0:2],
            "refuse: quoted line does not match " + OWNED_SPAN,
        )

    def test_zero_score_window_is_refused(self):
        """A zero score is a window that gets compared, not a skip."""
        body, files = self._zero_score_case()
        got = check.problems(self._draft(body, files))
        self.assertEqual(
            got, ["refuse: quoted line does not match " + OWNED_SPAN]
        )

    def test_falsifier_zero_score_window_is_caught(self):
        original = check._quote_window

        def skip_a_zero_score(remainders, pinned_lines, number):
            window = original(remainders, pinned_lines, number)
            if window is None:
                return None
            score = sum(
                1
                for offset, row in enumerate(window)
                if remainders[offset] == row[1]
            )
            return None if score == 0 else window

        self._caught(
            "_quote_window",
            skip_a_zero_score,
            self.test_zero_score_window_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT zero-score-window",
        )

    def _pin_change_case(self):
        """A draft checked at one pin, then at a pin whose lines differ.

        The draft keeps the same two remainders. The first pin holds them at
        8189 and 8190, so that check passes. The second pin moves the text, so
        the same draft must be refused at 8189. A window cached by path alone
        would keep the first pin's lines and accept the draft.
        """
        root = self._temp_root()
        self._git(root, "init", "-q")
        body = (
            "`" + KIND_RUN_SPAN + "` cites the arm.\n"
            "\n"
            "    A\n"
            "    B\n"
            "\n"
        )
        self._commit_pinned(root, ["// filler"] * (KIND_RUN_NUMBER - 2) + ["X", "A", "B"], body)
        self.assertEqual(self._check_at(root), [])
        self._commit_pinned(root, ["// filler"] * (KIND_RUN_NUMBER - 2) + ["A", "A", "X"], body)
        return root

    def test_a_changed_pin_selects_the_new_lines(self):
        """A second check at a new pin reads that pin, not the first one."""
        root = self._pin_change_case()
        self.assertEqual(
            self._check_at(root),
            ["refuse: quoted line does not match " + KIND_RUN_SPAN],
        )

    def test_falsifier_pin_change_reuse_is_caught(self):
        original = check._draft_lines
        cache = {}

        def keep_the_first_pin(rel):
            if rel not in cache:
                cache[rel] = original(rel)
            return cache[rel]

        self._caught(
            "_draft_lines",
            keep_the_first_pin,
            self.test_a_changed_pin_selects_the_new_lines,
            "refuse: quoted line does not match",
            "CAUGHT changed-pin",
        )

    def _candidate_case(self):
        """A candidate root whose source differs from this checker's draft pin.

        The checker's own source holds the quoted pair at 8189-8190. The
        candidate holds `A`, `A`, `X` at 8188-8190, so its earliest
        highest-scoring window for the cited line picks `B`, which does not
        equal the candidate's line 8189. Selection and comparison must read the
        candidate root and its pin, so the candidate draft is refused.
        """
        root = self._temp_root()
        self._git(root, "init", "-q")
        body = (
            "`" + KIND_RUN_SPAN + "` cites the arm.\n"
            "\n"
            "    A\n"
            "    B\n"
            "\n"
        )
        self._commit_pinned(
            root, ["// filler"] * (KIND_RUN_NUMBER - 2) + ["A", "A", "X"], body
        )
        return root

    def test_selection_and_comparison_read_one_root_and_pin(self):
        """A candidate whose window differs from the draft pin is refused."""
        root = self._candidate_case()
        self.assertEqual(
            check.problems(root),
            ["refuse: quoted line does not match " + KIND_RUN_SPAN],
        )

    def _elsewhere_pair_root(self, pair=("X", "A", "B")):
        """A committed source whose cited lines hold PAIR, not the candidate's."""
        root = self._temp_root()
        self._git(root, "init", "-q")
        source = root / OWNED_REL
        source.parent.mkdir(parents=True, exist_ok=True)
        rows = ["// filler"] * (KIND_RUN_NUMBER - 2) + list(pair)
        source.write_text("\n".join(rows) + "\n", encoding="utf-8")
        self._git(root, "add", "-A")
        self._git(root, "commit", "-q", "-m", "elsewhere")
        return root, self._git_output(root, "rev-parse", "HEAD")

    def test_falsifier_selection_root_is_caught(self):
        """Selecting from another root while comparing the candidate is caught."""
        root, sha = self._elsewhere_pair_root()

        def read_another_root(rel):
            return check._pinned_lines(str(root), sha, rel)

        self._caught(
            "_draft_lines",
            read_another_root,
            self.test_selection_and_comparison_read_one_root_and_pin,
            "refuse: quoted line does not match",
            "CAUGHT selection-root",
        )

    def test_foreign_match_does_not_hide_a_mismatch(self):
        """A higher score away from the cited line does not win the window."""
        remainders = ["/// one", "/// two"]
        pinned = (
            (10, "/// no match here"),
            (11, "/// one"),
            (12, "/// two"),
        )
        self.assertEqual(
            check._quote_window(remainders, pinned, 10),
            pinned[0:2],
            "refuse: quoted line does not match " + OWNED_SPAN,
        )
        self.assertEqual(
            check.quote_for(remainders, pinned, 10),
            "/// one",
            "refuse: quoted line does not match " + OWNED_SPAN,
        )

    def test_unchanged_text_away_from_the_line_does_not_stand_for_it(self):
        """The 3754 text that stands at 3800 does not cover line 3754."""
        body = (
            "`" + OWNED_SPAN + "` states the journal root.\n"
            "\n"
            "    " + OWNED_QUOTE + "\n"
            "    " + NEXT_QUOTE + "\n"
            "\n"
        )
        files = {OWNED_REL: self._foreign_source()}
        got = check.problems(self._draft(body, files))
        self.assertEqual(
            got, ["refuse: quoted line does not match " + OWNED_SPAN]
        )

    def test_falsifier_foreign_match_is_caught(self):
        def keep_a_foreign_match(remainders, pinned_lines, number):
            width = len(remainders)
            if width == 0:
                return None
            best = None
            best_score = -1
            for start in range(len(pinned_lines) - width + 1):
                window = pinned_lines[start:start + width]
                score = sum(
                    1
                    for offset, row in enumerate(window)
                    if remainders[offset] == row[1]
                )
                if score > best_score:
                    best = window
                    best_score = score
            return best

        self._caught(
            "_quote_window",
            keep_a_foreign_match,
            self.test_foreign_match_does_not_hide_a_mismatch,
            "refuse: quoted line does not match",
            "CAUGHT foreign-match",
        )

    def test_falsifier_later_tie_is_caught(self):
        def keep_the_later_tie(remainders, pinned_lines, number):
            width = len(remainders)
            if width == 0:
                return None
            best = None
            best_score = -1
            for start in range(len(pinned_lines) - width + 1):
                window = pinned_lines[start:start + width]
                if not any(row[0] == number for row in window):
                    continue
                score = sum(
                    1
                    for offset, row in enumerate(window)
                    if remainders[offset] == row[1]
                )
                if score >= best_score:
                    best = window
                    best_score = score
            return best

        self._caught(
            "_quote_window",
            keep_the_later_tie,
            self.test_quote_window_tie_uses_earliest_start,
            "refuse: quoted line does not match",
            "CAUGHT tie-earliest-start",
        )

    def test_falsifier_lower_score_window_is_caught(self):
        def keep_the_lower_score(remainders, pinned_lines, number):
            width = len(remainders)
            if width == 0:
                return None
            best = None
            best_score = None
            for start in range(len(pinned_lines) - width + 1):
                window = pinned_lines[start:start + width]
                if not any(row[0] == number for row in window):
                    continue
                score = sum(
                    1
                    for offset, row in enumerate(window)
                    if remainders[offset] == row[1]
                )
                if best_score is None or score < best_score:
                    best = window
                    best_score = score
            return best

        self._caught(
            "_quote_window",
            keep_the_lower_score,
            self.test_quote_window_score_is_the_matching_lines,
            "refuse: quoted line does not match",
            "CAUGHT lower-score-window",
        )

    def test_worktree_root_contains_checker(self):
        root = check.worktree_root()
        checker = root / "lab" / "bus-v2-proposal" / "check.py"
        self.assertTrue(checker.is_file())
        self.assertEqual(checker.resolve(), Path(check.__file__).resolve())

    def test_main_on_this_worktree(self):
        root = check.worktree_root()
        draft = root / "lab" / "bus-v2-proposal" / "CORE-CALLS-PROPOSAL.md"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = check.main()
        self.assertIsInstance(code, int)
        if not draft.is_file():
            self.assertEqual(code, 1)
            self.assertEqual(buf.getvalue(), "refuse: proposal is absent\n")
            self.assertFalse(draft.exists())
            return
        found = check.problems(root)
        if found:
            self.fail("draft refusals:\n" + "\n".join(found))
        self.assertEqual(code, 0)
        self.assertEqual(buf.getvalue(), "")

    def _main_at(self, root):
        original = check.worktree_root
        buf = io.StringIO()
        try:
            check.worktree_root = lambda: root
            with contextlib.redirect_stdout(buf):
                code = check.main()
        finally:
            check.worktree_root = original
        return code, buf.getvalue()

    def test_main_absent_draft_prints_and_creates_nothing(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        draft = root / "lab" / "bus-v2-proposal" / "CORE-CALLS-PROPOSAL.md"
        code, out = self._main_at(root)
        self.assertEqual(check.problems(root), ["refuse: proposal is absent"])
        self.assertEqual(code, 1)
        self.assertEqual(out, "refuse: proposal is absent\n")
        self.assertFalse(draft.exists())

    def test_main_agrees_with_problems(self):
        clean = self._draft(
            "Open `pkg/kept.rs:1`.\n",
            {"pkg/kept.rs": b"fn kept(\n"},
        )
        code, out = self._main_at(clean)
        self.assertEqual(check.problems(clean), [])
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        bad = self._draft("See `missing/no-such.rs:1`.\n", {})
        code, out = self._main_at(bad)
        found = check.problems(bad)
        self.assertEqual(found, ["refuse: path does not exist: missing/no-such.rs"])
        self.assertEqual(code, 1)
        self.assertEqual(out, found[0] + "\n")

    def _file_ask_case(self, name):
        for case in FILE_ASK_CASES:
            if case[0] == name:
                return case
        raise AssertionError(name)

    def test_live_draft_file_ask_quotes_match_their_pinned_lines(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        for name, number, span, lines, index in FILE_ASK_CASES:
            selector = getattr(check, name + "_quote")
            self.assertEqual(selector(text), lines[index], span)
            self.assertEqual(
                len(check._remainders(text, "`" + span + "`")), len(lines), span
            )
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        for name, number, span, lines, index in FILE_ASK_CASES:
            self.assertEqual(
                check.pinned_line(root, sha, OWNED_REL, number), lines[index], span
            )
        self.assertEqual(check.problems(root), [])

    def test_file_ask_fixture_keeps_every_decision_on_its_pinned_line(self):
        body = self._file_ask_body()
        files = {OWNED_REL: self._file_ask_source()}
        got, reads = self._pinned_reads(body, files)
        self.assertEqual(got, [])
        self.assertEqual(reads, list(QUOTE_DECISION_ORDER))

    def _assert_truncated_walk(self, selector, body, index, span):
        """A walk cut below INDEX still selects the window that holds the line.

        An empty walk has no remainder and selects nothing. A shorter walk still
        has a window of that width around the cited line, so it selects that
        window even when no line in it matches.
        """
        if index == 0:
            self.assertIsNone(selector(body), span)
            return
        self.assertIsNotNone(selector(body), span)

    def test_file_ask_quotes_read_their_own_windows(self):
        for name, number, span, lines, index in FILE_ASK_CASES:
            selector = getattr(check, name + "_quote")
            self.assertIsNone(
                selector(self._file_ask_body(groups=[name], indented=False)), span
            )
            self.assertIsNone(selector("No file-ask span here.\n"), span)
            self._assert_truncated_walk(
                selector,
                self._file_ask_body(groups=[name], **{name: lines[:index]}),
                index,
                span,
            )

    def _assert_file_ask_mismatch(self, name):
        _, number, span, lines, index = self._file_ask_case(name)
        expected = "refuse: quoted line does not match " + span
        body = self._file_ask_body(
            groups=[name], **{name: self._changed(lines, index)}
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [number])
        root = self._draft(body, {OWNED_REL: self._file_ask_source()})
        (root / OWNED_REL).write_bytes(
            self._file_ask_source(
                lines={**FILE_ASK_LINES, number: "// edited in the worktree"}
            )
        )
        self.assertEqual(check.problems(root), [expected])

    def test_observe_quoted_line_mismatch_is_refused(self):
        self._assert_file_ask_mismatch("observe")

    def test_revision_quoted_line_mismatch_is_refused(self):
        self._assert_file_ask_mismatch("revision")

    def test_op_quoted_line_mismatch_is_refused(self):
        self._assert_file_ask_mismatch("op")

    def test_no_write_quoted_line_mismatch_is_refused(self):
        self._assert_file_ask_mismatch("no_write")

    def test_cover_quoted_line_mismatch_is_refused(self):
        self._assert_file_ask_mismatch("cover")

    def test_file_ask_quote_match_ignores_the_worktree_file(self):
        root = self._draft(
            self._file_ask_body(), {OWNED_REL: self._file_ask_source()}
        )
        self.assertEqual(check.problems(root), [])
        for name, number, span, lines, index in FILE_ASK_CASES:
            (root / OWNED_REL).write_bytes(
                self._file_ask_source(
                    lines={**FILE_ASK_LINES, number: "// edited in the worktree"}
                )
            )
            self.assertEqual(check.problems(root), [], span)

    def _assert_file_ask_line_not_cited(self, name, index):
        _, number, span, lines, _ = self._file_ask_case(name)
        body = self._file_ask_body(groups=[name], **{name: self._changed(lines, index)})
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(got, [], span)
        self.assertEqual(reads, [number], span)

    def test_observe_series_line_does_not_stand_for_line_2067(self):
        self._assert_file_ask_line_not_cited("observe", 3)

    def test_revision_path_line_does_not_stand_for_line_2741(self):
        self._assert_file_ask_line_not_cited("revision", 6)

    def test_op_revision_line_does_not_stand_for_line_2749(self):
        self._assert_file_ask_line_not_cited("op", 7)

    def test_no_write_doc_line_does_not_stand_for_line_3308(self):
        self._assert_file_ask_line_not_cited("no_write", 0)

    def test_cover_iter_line_does_not_stand_for_line_8488(self):
        self._assert_file_ask_line_not_cited("cover", 4)

    def test_file_ask_block_lines_do_not_stand_for_the_cited_lines(self):
        cases = (
            ("observe", 0),
            ("observe", 25),
            ("revision", 0),
            ("revision", 18),
            ("op", 0),
            ("op", 18),
            ("no_write", 5),
            ("no_write", 32),
            ("cover", 0),
            ("cover", 6),
        )
        for name, index in cases:
            self._assert_file_ask_line_not_cited(name, index)

    def test_two_file_ask_spans_are_refused(self):
        for name, number, span, lines, index in FILE_ASK_CASES:
            expected = "refuse: quoted line is not one line: " + span
            body = self._file_ask_body(copies={name: 2})
            got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
            self.assertEqual(got, [expected], span)
            self.assertEqual(
                reads,
                list(QUOTE_DECISION_ORDER[: QUOTE_DECISION_ORDER.index(number)]),
                span,
            )

    def test_draft_without_a_file_ask_span_adds_no_refusal(self):
        for name, number, span, lines, index in FILE_ASK_CASES:
            groups = tuple(group for group in FILE_ASK_GROUPS if group != name)
            body = self._file_ask_body(groups=groups)
            got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
            self.assertEqual(got, [], span)
            self.assertEqual(
                reads,
                [other for other in QUOTE_DECISION_ORDER if other != number],
                span,
            )

    def test_file_ask_span_without_an_indented_line_adds_no_refusal(self):
        body = self._file_ask_body(indented=False)
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

    def test_file_ask_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        for name, number, span, lines, index in FILE_ASK_CASES:
            expected = "refuse: quoted line is not in the pinned commit: " + span
            got, reads = self._pinned_reads(
                self._file_ask_body(),
                {OWNED_REL: self._file_ask_source(blank=number)},
                {OWNED_REL: self._file_ask_source()},
            )
            self.assertEqual(got, [expected], span)
            self.assertEqual(
                reads,
                list(
                    QUOTE_DECISION_ORDER[
                        : QUOTE_DECISION_ORDER.index(number) + 1
                    ]
                ),
                span,
            )

    def test_observe_mismatch_stops_every_later_decision(self):
        got, reads = self._pinned_reads(
            self._file_ask_body(observe=self._changed(OBSERVE_LINES, 4)),
            {OWNED_REL: self._file_ask_source()},
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + OBSERVE_SPAN]
        )
        self.assertEqual(reads, [OBSERVE_NUMBER])

    def test_revision_mismatch_stops_the_op_decision(self):
        got, reads = self._pinned_reads(
            self._file_ask_body(revision=self._changed(REQUEST_LINES, 7)),
            {OWNED_REL: self._file_ask_source()},
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + REVISION_SPAN]
        )
        self.assertEqual(reads, [OBSERVE_NUMBER, REVISION_NUMBER])

    def test_op_mismatch_stops_the_no_write_decision(self):
        got, reads = self._pinned_reads(
            self._file_ask_body(op=self._changed(REQUEST_LINES, 15)),
            {OWNED_REL: self._file_ask_source()},
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + OP_SPAN])
        self.assertEqual(
            reads, [OBSERVE_NUMBER, REVISION_NUMBER, OP_NUMBER]
        )

    def test_no_write_mismatch_stops_the_deny_and_cover_decisions(self):
        got, reads = self._pinned_reads(
            self._file_ask_body(no_write=self._changed(NO_WRITE_LINES, 4)),
            {OWNED_REL: self._file_ask_source()},
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + NO_WRITE_SPAN]
        )
        self.assertEqual(
            reads,
            [OBSERVE_NUMBER, REVISION_NUMBER, OP_NUMBER, NO_WRITE_NUMBER],
        )

    def test_append_mismatch_stops_the_cover_decision(self):
        got, reads = self._pinned_reads(
            self._file_ask_body(append=KIND_APPEND_QUOTE + "x"),
            {OWNED_REL: self._file_ask_source()},
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + KIND_APPEND_SPAN]
        )
        self.assertEqual(
            reads,
            list(
                QUOTE_DECISION_ORDER[
                    : QUOTE_DECISION_ORDER.index(KIND_APPEND_NUMBER) + 1
                ]
            ),
        )

    def test_observe_mismatch_wins_over_the_deny_mismatch(self):
        body = self._file_ask_body(
            observe=self._changed(OBSERVE_LINES, 4), deny=DENY_QUOTE + "x"
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + OBSERVE_SPAN]
        )
        self.assertEqual(reads, [OBSERVE_NUMBER])

    def test_deny_mismatch_without_the_file_ask_spans_stays_the_deny_refusal(self):
        groups = tuple(
            group
            for group in FILE_ASK_GROUPS
            if group not in ("observe", "revision", "op", "no_write")
        )
        body = self._file_ask_body(groups=groups, deny=DENY_QUOTE + "x")
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(got, ["refuse: quoted line does not match " + DENY_SPAN])
        self.assertEqual(reads, [DENY_NUMBER])

    def test_asks_mismatch_follows_the_file_ask_matches(self):
        body = self._file_ask_body(ask_third=ASKS_THIRD + "x")
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(got, ["refuse: quoted line does not match " + ASKS_SPAN])
        self.assertEqual(
            reads,
            list(QUOTE_DECISION_ORDER[: QUOTE_DECISION_ORDER.index(ASKS_NUMBER) + 1]),
        )

    def test_file_ask_quote_refusal_waits_for_a_known_pin(self):
        body = self._file_ask_body(observe=self._changed(OBSERVE_LINES, 4))
        files = {OWNED_REL: self._file_ask_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        self.assertEqual(
            check.problems(
                self._raw_draft("Pinned commit: HEAD\n" + body, files)
            ),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        self.assertEqual(
            check.problems(
                self._raw_draft(
                    "Pinned commit: " + "f" * 40 + "\n" + body, files, commit=True
                )
            ),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def _caught_file_ask_line(self, name, index, named_test, label):
        _, number, span, lines, _ = self._file_ask_case(name)
        marker = "`" + span + "`"

        def planted(text):
            remainders = check._remainders(text, marker)
            if len(remainders) <= index:
                return None
            return remainders[index]

        self._caught(
            name + "_quote",
            planted,
            named_test,
            "refuse: quoted line does not match",
            label,
        )

    def test_falsifier_observe_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_observe_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT observe-quoted-line",
        )

    def test_falsifier_observe_series_line_is_caught(self):
        self._caught_file_ask_line(
            "observe",
            3,
            self.test_observe_series_line_does_not_stand_for_line_2067,
            "CAUGHT observe-series-line",
        )

    def test_falsifier_revision_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_revision_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT revision-quoted-line",
        )

    def test_falsifier_revision_path_line_is_caught(self):
        self._caught_file_ask_line(
            "revision",
            6,
            self.test_revision_path_line_does_not_stand_for_line_2741,
            "CAUGHT revision-path-line",
        )

    def test_falsifier_op_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_op_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT op-quoted-line",
        )

    def test_falsifier_op_revision_line_is_caught(self):
        self._caught_file_ask_line(
            "op",
            7,
            self.test_op_revision_line_does_not_stand_for_line_2749,
            "CAUGHT op-revision-line",
        )

    def test_falsifier_no_write_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_no_write_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT no-write-quoted-line",
        )

    def test_falsifier_no_write_doc_line_is_caught(self):
        self._caught_file_ask_line(
            "no_write",
            0,
            self.test_no_write_doc_line_does_not_stand_for_line_3308,
            "CAUGHT no-write-doc-line",
        )

    def test_falsifier_cover_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_cover_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT cover-quoted-line",
        )

    def test_falsifier_cover_iter_line_is_caught(self):
        self._caught_file_ask_line(
            "cover",
            4,
            self.test_cover_iter_line_does_not_stand_for_line_8488,
            "CAUGHT cover-iter-line",
        )

    def _edit_case(self, name):
        for case in EDIT_CASES:
            if case[0] == name:
                return case
        raise AssertionError(name)

    def _edit_group(self, name):
        return {
            "edit_start": "range",
            "edit_end": "range",
            "request": "request_walk",
            "is_write": "is_write",
        }[name]

    def _edit_lines_arg(self, name):
        return {
            "edit_start": "edit",
            "edit_end": "edit",
            "request": "request_walk",
            "is_write": "is_write",
        }[name]

    def _present_edit_decisions(self, body):
        """Return the edit-walk decisions whose span the draft cites.

        A decision is cited when its own group's marker is in the body. The
        range's two endpoints share the range marker, so one citation states
        both decisions.
        """
        markers = {
            "range": EDIT_RANGE_SPAN,
            "request_walk": REQUEST_WALK_SPAN,
            "is_write": IS_WRITE_SPAN,
        }
        cited = [
            number
            for name, number, _, _, _ in EDIT_CASES
            if "`" + markers[self._edit_group(name)] + "`" in body
        ]
        return [number for number in EDIT_DECISION_ORDER if number in cited]

    def test_live_draft_edit_walk_quotes_match_their_pinned_lines(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.edit_start_quote(text), EDIT_START_QUOTE)
        self.assertEqual(check.edit_end_quote(text), EDIT_END_QUOTE)
        self.assertEqual(check.request_quote(text), REQUEST_QUOTE)
        self.assertEqual(check.is_write_quote(text), IS_WRITE_QUOTE)
        for span, lines in (
            (EDIT_RANGE_SPAN, EDIT_LINES),
            (REQUEST_WALK_SPAN, REQUEST_WALK_LINES),
            (IS_WRITE_SPAN, IS_WRITE_LINES),
        ):
            self.assertEqual(
                len(check._remainders(text, "`" + span + "`")), len(lines), span
            )
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        for name, number, span, lines, index in EDIT_CASES:
            self.assertEqual(
                check.pinned_line(root, sha, OWNED_REL, number), lines[index], span
            )
        self.assertEqual(check.problems(root), [])

    def test_edit_walks_read_their_own_windows(self):
        for name, number, span, lines, index in EDIT_CASES:
            selector = getattr(check, name + "_quote")
            group = self._edit_group(name)
            self.assertIsNone(
                selector(self._edit_walk_body(groups=[group], indented=False)), span
            )
            self.assertIsNone(selector("No edit span here.\n"), span)
            self._assert_truncated_walk(
                selector,
                self._edit_walk_body(
                    groups=[group],
                    **{self._edit_lines_arg(name): lines[:index]}
                ),
                index,
                span,
            )

    def test_edit_walk_fixture_keeps_every_decision_on_its_pinned_line(self):
        got, reads = self._pinned_reads(
            self._edit_walk_body(), {OWNED_REL: self._file_ask_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, list(EDIT_DECISION_ORDER))

    def _assert_edit_quote_mismatch(self, name):
        _, number, span, lines, index = self._edit_case(name)
        group = self._edit_group(name)
        expected = "refuse: quoted line does not match " + span
        body = self._edit_walk_body(
            groups=[group],
            **{self._edit_lines_arg(name): self._changed(lines, index)}
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(got, [expected])
        if name == "edit_end":
            self.assertEqual(reads, [EDIT_START_NUMBER, EDIT_END_NUMBER])
        else:
            self.assertEqual(reads, [number])
        root = self._draft(body, {OWNED_REL: self._file_ask_source()})
        (root / OWNED_REL).write_bytes(
            self._file_ask_source(
                lines={**FILE_ASK_LINES, number: "// edited in the worktree"}
            )
        )
        self.assertEqual(check.problems(root), [expected])
        root = self._draft(
            self._edit_walk_body(groups=[group]),
            {OWNED_REL: self._file_ask_source()},
        )
        (root / OWNED_REL).write_bytes(
            self._file_ask_source(
                lines={**FILE_ASK_LINES, number: "// edited in the worktree"}
            )
        )
        self.assertEqual(check.problems(root), [])

    def test_edit_start_quoted_line_mismatch_is_refused(self):
        self._assert_edit_quote_mismatch("edit_start")

    def test_edit_end_quoted_line_mismatch_is_refused(self):
        self._assert_edit_quote_mismatch("edit_end")

    def test_request_quoted_line_mismatch_is_refused(self):
        self._assert_edit_quote_mismatch("request")

    def test_is_write_quoted_line_mismatch_is_refused(self):
        self._assert_edit_quote_mismatch("is_write")

    def test_edit_limit_line_does_not_stand_for_line_2421(self):
        body = self._edit_walk_body(
            groups=["range"], edit=self._changed(EDIT_LINES, 3)
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(got, [])
        self.assertEqual(reads, [EDIT_START_NUMBER, EDIT_END_NUMBER])

    def test_edit_start_line_does_not_stand_for_line_2422(self):
        lines = {
            **FILE_ASK_LINES,
            EDIT_START_NUMBER: EDIT_START_QUOTE,
            EDIT_END_NUMBER: EDIT_START_QUOTE,
        }
        got, reads = self._pinned_reads(
            self._edit_walk_body(groups=["range"]),
            {OWNED_REL: self._file_ask_source(lines=lines)},
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + EDIT_END_SPAN]
        )
        self.assertEqual(reads, [EDIT_START_NUMBER, EDIT_END_NUMBER])

    def test_request_revision_line_does_not_stand_for_line_2720(self):
        body = self._edit_walk_body(
            groups=["request_walk"],
            request_walk=self._changed(REQUEST_WALK_LINES, 1),
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(got, [])
        self.assertEqual(reads, [REQUEST_WALK_NUMBER])

    def test_is_write_fn_line_does_not_stand_for_line_3290(self):
        body = self._edit_walk_body(
            groups=["is_write"], is_write=self._changed(IS_WRITE_LINES, 1)
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(got, [])
        self.assertEqual(reads, [IS_WRITE_NUMBER])

    def test_edit_walk_other_lines_do_not_stand_for_the_edit_lines(self):
        for index in (0, 3, 6, 19):
            body = self._edit_walk_body(
                groups=["range"], edit=self._changed(EDIT_LINES, index)
            )
            got, reads = self._pinned_reads(
                body, {OWNED_REL: self._file_ask_source()}
            )
            self.assertEqual(got, [], index)
            self.assertEqual(reads, [EDIT_START_NUMBER, EDIT_END_NUMBER], index)

    def test_request_record_line_does_not_stand_for_line_2720(self):
        body = self._edit_walk_body(
            groups=["request_walk"],
            request_walk=self._changed(REQUEST_WALK_LINES, 12),
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(got, [])
        self.assertEqual(reads, [REQUEST_WALK_NUMBER])

    def test_is_write_walk_other_lines_do_not_stand_for_line_3290(self):
        for index in (0, 3):
            body = self._edit_walk_body(
                groups=["is_write"], is_write=self._changed(IS_WRITE_LINES, index)
            )
            got, reads = self._pinned_reads(
                body, {OWNED_REL: self._file_ask_source()}
            )
            self.assertEqual(got, [], index)
            self.assertEqual(reads, [IS_WRITE_NUMBER], index)

    def test_edit_walks_without_an_indented_line_add_no_refusal(self):
        got, reads = self._pinned_reads(
            self._edit_walk_body(indented=False),
            {OWNED_REL: self._file_ask_source()},
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

    def test_edit_walk_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        for name, number, span, lines, index in EDIT_CASES:
            group = self._edit_group(name)
            expected = "refuse: quoted line is not in the pinned commit: " + span
            body = self._without(self._edit_walk_body(groups=[group]), lines, index)
            got, reads = self._pinned_reads(
                body,
                {OWNED_REL: self._file_ask_source(blank=number)},
                {OWNED_REL: self._file_ask_source()},
            )
            self.assertEqual(got, [expected], span)
            present = self._present_edit_decisions(body)
            self.assertEqual(reads, present[: present.index(number) + 1], span)

    def test_two_edit_range_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + EDIT_RANGE_SPAN
        body = self._edit_walk_body(groups=["range"], copies={"range": 2})
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_two_request_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + REQUEST_WALK_SPAN
        body = self._edit_walk_body(
            groups=["request_walk"], copies={"request_walk": 2}
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_two_is_write_spans_are_refused(self):
        expected = "refuse: quoted line is not one line: " + IS_WRITE_SPAN
        body = self._edit_walk_body(groups=["is_write"], copies={"is_write": 2})
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(got, [expected])
        self.assertEqual(reads, [])

    def test_draft_without_the_edit_range_span_adds_no_edit_refusal(self):
        groups = [group for group in EDIT_GROUPS if group != "range"]
        got, reads = self._pinned_reads(
            self._edit_walk_body(groups=groups),
            {OWNED_REL: self._file_ask_source()},
        )
        self.assertEqual(got, [])
        self.assertEqual(
            reads,
            [
                number
                for number in EDIT_DECISION_ORDER
                if number not in (EDIT_START_NUMBER, EDIT_END_NUMBER)
            ],
        )

    def test_draft_without_the_request_span_adds_no_request_refusal(self):
        groups = [group for group in EDIT_GROUPS if group != "request_walk"]
        got, reads = self._pinned_reads(
            self._edit_walk_body(groups=groups),
            {OWNED_REL: self._file_ask_source()},
        )
        self.assertEqual(got, [])
        self.assertEqual(
            reads,
            [number for number in EDIT_DECISION_ORDER if number != REQUEST_WALK_NUMBER],
        )

    def test_draft_without_the_is_write_span_adds_no_is_write_refusal(self):
        groups = [group for group in EDIT_GROUPS if group != "is_write"]
        got, reads = self._pinned_reads(
            self._edit_walk_body(groups=groups),
            {OWNED_REL: self._file_ask_source()},
        )
        self.assertEqual(got, [])
        self.assertEqual(
            reads,
            [number for number in EDIT_DECISION_ORDER if number != IS_WRITE_NUMBER],
        )

    def test_observe_mismatch_wins_over_the_edit_range_mismatch(self):
        body = self._edit_walk_body(
            observe=self._changed(OBSERVE_LINES, 4),
            edit=self._changed(EDIT_LINES, 4),
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + OBSERVE_SPAN]
        )
        self.assertEqual(reads, [OBSERVE_NUMBER])

    def test_draft_without_the_observe_span_still_refuses_the_edit_start(self):
        groups = [group for group in EDIT_GROUPS if group != "observe"]
        body = self._edit_walk_body(
            groups=groups, edit=self._changed(EDIT_LINES, 4)
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + EDIT_START_SPAN]
        )
        self.assertEqual(reads, [EDIT_START_NUMBER])

    def test_edit_start_mismatch_stops_the_edit_end_decision(self):
        body = self._edit_walk_body(
            groups=["range", "request_walk", "revision"],
            edit=self._changed(EDIT_LINES, 4),
            request_walk=self._changed(REQUEST_WALK_LINES, 0),
            revision=self._changed(REQUEST_LINES, 7),
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + EDIT_START_SPAN]
        )
        self.assertEqual(reads, [EDIT_START_NUMBER])

    def test_edit_end_mismatch_stops_the_request_decision(self):
        body = self._edit_walk_body(
            groups=["range", "request_walk"],
            edit=self._changed(EDIT_LINES, 5),
            request_walk=self._changed(REQUEST_WALK_LINES, 0),
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + EDIT_END_SPAN]
        )
        self.assertEqual(reads, [EDIT_START_NUMBER, EDIT_END_NUMBER])

    def test_request_mismatch_stops_the_revision_decision(self):
        body = self._edit_walk_body(
            groups=["range", "request_walk", "revision"],
            request_walk=self._changed(REQUEST_WALK_LINES, 0),
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + REQUEST_WALK_SPAN]
        )
        self.assertEqual(
            reads, [EDIT_START_NUMBER, EDIT_END_NUMBER, REQUEST_WALK_NUMBER]
        )

    def test_request_mismatch_without_the_edit_range_span_stays_the_request_refusal(self):
        groups = [group for group in EDIT_GROUPS if group != "range"]
        body = self._edit_walk_body(
            groups=groups, request_walk=self._changed(REQUEST_WALK_LINES, 0)
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + REQUEST_WALK_SPAN]
        )
        self.assertEqual(reads, [OBSERVE_NUMBER, REQUEST_WALK_NUMBER])

    def test_revision_mismatch_without_the_edit_spans_stays_the_revision_refusal(self):
        body = self._edit_walk_body(
            groups=["revision"], revision=self._changed(REQUEST_LINES, 7)
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + REVISION_SPAN]
        )
        self.assertEqual(reads, [REVISION_NUMBER])

    def test_op_mismatch_stops_the_is_write_and_no_write_decisions(self):
        body = self._edit_walk_body(
            groups=["range", "request_walk", "op", "is_write", "no_write"],
            op=self._changed(REQUEST_LINES, 15),
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(got, ["refuse: quoted line does not match " + OP_SPAN])
        self.assertEqual(
            reads,
            [
                EDIT_START_NUMBER,
                EDIT_END_NUMBER,
                REQUEST_WALK_NUMBER,
                OP_NUMBER,
            ],
        )

    def test_is_write_mismatch_stops_the_no_write_decision(self):
        body = self._edit_walk_body(
            groups=["range", "request_walk", "is_write", "no_write"],
            is_write=self._changed(IS_WRITE_LINES, 2),
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._file_ask_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + IS_WRITE_SPAN]
        )
        self.assertEqual(
            reads,
            [
                EDIT_START_NUMBER,
                EDIT_END_NUMBER,
                REQUEST_WALK_NUMBER,
                IS_WRITE_NUMBER,
            ],
        )

    def test_edit_quote_refusal_waits_for_a_known_pin(self):
        body = self._edit_walk_body(edit=self._changed(EDIT_LINES, 4))
        files = {OWNED_REL: self._file_ask_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        self.assertEqual(
            check.problems(
                self._raw_draft("Pinned commit: HEAD\n" + body, files)
            ),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        self.assertEqual(
            check.problems(
                self._raw_draft(
                    "Pinned commit: " + "f" * 40 + "\n" + body, files, commit=True
                )
            ),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def _caught_walk_index(self, global_name, index, marker, named_test, label):
        def planted(text):
            remainders = check._remainders(text, marker)
            if len(remainders) <= index:
                return None
            return remainders[index]

        self._caught(
            global_name,
            planted,
            named_test,
            "refuse: quoted line does not match",
            label,
        )

    def test_falsifier_edit_start_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_edit_start_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT edit-start-quoted-line",
        )

    def test_falsifier_edit_limit_line_is_caught(self):
        self._caught_walk_index(
            "edit_start_quote",
            3,
            "`" + EDIT_RANGE_SPAN + "`",
            self.test_edit_limit_line_does_not_stand_for_line_2421,
            "CAUGHT edit-limit-line",
        )

    def test_falsifier_edit_end_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_edit_end_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT edit-end-quoted-line",
        )

    def test_falsifier_edit_start_as_end_is_caught(self):
        self._caught_walk_index(
            "edit_end_quote",
            4,
            "`" + EDIT_RANGE_SPAN + "`",
            self.test_edit_start_line_does_not_stand_for_line_2422,
            "CAUGHT edit-start-as-end",
        )

    def test_falsifier_request_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_request_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT request-quoted-line",
        )

    def test_falsifier_request_revision_line_is_caught(self):
        self._caught_walk_index(
            "request_quote",
            1,
            "`" + REQUEST_WALK_SPAN + "`",
            self.test_request_revision_line_does_not_stand_for_line_2720,
            "CAUGHT request-revision-line",
        )

    def test_falsifier_is_write_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_is_write_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT is-write-quoted-line",
        )

    def test_falsifier_is_write_fn_line_is_caught(self):
        self._caught_walk_index(
            "is_write_quote",
            1,
            "`" + IS_WRITE_SPAN + "`",
            self.test_is_write_fn_line_does_not_stand_for_line_3290,
            "CAUGHT is-write-fn-line",
        )

    def _provider_case(self, name):
        for case in PROVIDER_CASES:
            if case[0] == name:
                return case
        raise KeyError(name)

    def test_live_draft_provider_quotes_match_their_pinned_lines(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        self.assertEqual(check.scheme_quote(text), SCHEME_QUOTE)
        self.assertEqual(check.read_action_quote(text), READ_ACTION_QUOTE)
        self.assertEqual(check.write_action_quote(text), WRITE_ACTION_QUOTE)
        self.assertEqual(check.default_action_quote(text), DEFAULT_ACTION_QUOTE)
        for span, count in (
            (SCHEME_SPAN, 71),
            (READ_ACTION_SPAN, 1),
            (WRITE_ACTION_SPAN, 8),
            (DEFAULT_ACTION_SPAN, 8),
        ):
            self.assertEqual(
                len(check._remainders(text, "`" + span + "`")), count, span
            )
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        for name, number, span, lines, index in PROVIDER_CASES:
            self.assertEqual(
                check.pinned_line(root, sha, PROVIDER_REL, number),
                lines[index],
                span,
            )
        self.assertEqual(check.problems(root), [])

    def test_provider_selectors_read_their_own_windows(self):
        for name, number, span, lines, index in PROVIDER_CASES:
            selector = getattr(check, name + "_quote")
            self.assertIsNone(selector("No provider span here.\n"), span)
            self.assertIsNone(
                selector(self._provider_body(groups=[name], indented=False)), span
            )
            self._assert_truncated_walk(
                selector,
                self._provider_body(groups=[name], **{name: lines[:index]}),
                index,
                span,
            )

    def test_provider_fixture_reads_each_pinned_line_once(self):
        got, reads = self._pinned_reads(
            self._provider_body(), {PROVIDER_REL: self._provider_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, list(PROVIDER_DECISION_ORDER))

    def _assert_provider_quote_mismatch(self, name):
        _, number, span, lines, index = self._provider_case(name)
        expected = "refuse: quoted line does not match " + span
        changed = self._changed(lines, index)
        if name == "default_action":
            body = self._provider_body(
                groups=["write_action", "default_action"],
                write_action=changed,
                default_action=changed,
            )
        else:
            body = self._provider_body(groups=[name], **{name: changed})
        got, reads = self._pinned_reads(
            body, {PROVIDER_REL: self._provider_source()}
        )
        self.assertEqual(got, [expected])
        if name == "default_action":
            self.assertEqual(reads, [WRITE_ACTION_NUMBER, DEFAULT_ACTION_NUMBER])
        else:
            self.assertEqual(reads, [number])
        root = self._draft(body, {PROVIDER_REL: self._provider_source()})
        (root / PROVIDER_REL).write_bytes(
            self._provider_source(
                lines={**PROVIDER_LINES, number: "// edited in the worktree"}
            )
        )
        self.assertEqual(check.problems(root), [expected])
        root = self._draft(
            self._provider_body(groups=[name]),
            {PROVIDER_REL: self._provider_source()},
        )
        (root / PROVIDER_REL).write_bytes(
            self._provider_source(
                lines={**PROVIDER_LINES, number: "// edited in the worktree"}
            )
        )
        self.assertEqual(check.problems(root), [])

    def test_scheme_quoted_line_mismatch_is_refused(self):
        self._assert_provider_quote_mismatch("scheme")

    def test_read_action_quoted_line_mismatch_is_refused(self):
        self._assert_provider_quote_mismatch("read_action")

    def test_write_action_quoted_line_mismatch_is_refused(self):
        self._assert_provider_quote_mismatch("write_action")

    def test_default_action_quoted_line_mismatch_is_refused(self):
        self._assert_provider_quote_mismatch("default_action")

    def test_scheme_did_line_does_not_stand_for_line_123(self):
        body = self._provider_body(
            groups=["scheme"], scheme=self._changed(SCHEME_LINES, 9)
        )
        got, reads = self._pinned_reads(
            body, {PROVIDER_REL: self._provider_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [SCHEME_NUMBER])

    def test_read_action_block_arm_does_not_stand_for_line_189(self):
        body = self._provider_body(
            groups=["read_action", "write_action"],
            write_action=self._changed(WRITE_ACTION_LINES, 2),
        )
        got, reads = self._pinned_reads(
            body, {PROVIDER_REL: self._provider_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [READ_ACTION_NUMBER, WRITE_ACTION_NUMBER])

    def test_write_action_delete_line_does_not_stand_for_line_190(self):
        body = self._provider_body(
            groups=["write_action"],
            write_action=self._changed(WRITE_ACTION_LINES, 4),
        )
        got, reads = self._pinned_reads(
            body, {PROVIDER_REL: self._provider_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [WRITE_ACTION_NUMBER])

    def test_default_action_delete_line_does_not_stand_for_line_192(self):
        changed = self._changed(WRITE_ACTION_LINES, 4)
        body = self._provider_body(
            groups=["write_action", "default_action"],
            write_action=changed,
            default_action=changed,
        )
        got, reads = self._pinned_reads(
            body, {PROVIDER_REL: self._provider_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [WRITE_ACTION_NUMBER, DEFAULT_ACTION_NUMBER])

    def test_scheme_walk_other_lines_do_not_stand_for_line_123(self):
        for index in (0, 7, 9, 70):
            body = self._provider_body(
                groups=["scheme"], scheme=self._changed(SCHEME_LINES, index)
            )
            got, reads = self._pinned_reads(
                body, {PROVIDER_REL: self._provider_source()}
            )
            self.assertEqual(got, [], index)
            self.assertEqual(reads, [SCHEME_NUMBER], index)

    def test_write_walk_other_lines_do_not_stand_for_190_or_192(self):
        for index in (0, 2, 4, 7):
            changed = self._changed(WRITE_ACTION_LINES, index)
            body = self._provider_body(
                groups=["write_action", "default_action"],
                write_action=changed,
                default_action=changed,
            )
            got, reads = self._pinned_reads(
                body, {PROVIDER_REL: self._provider_source()}
            )
            self.assertEqual(got, [], index)
            self.assertEqual(
                reads, [WRITE_ACTION_NUMBER, DEFAULT_ACTION_NUMBER], index
            )

    def test_provider_spans_without_an_indented_line_add_no_refusal(self):
        got, reads = self._pinned_reads(
            self._provider_body(indented=False),
            {PROVIDER_REL: self._provider_source()},
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

    def test_provider_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        for name, number, span, lines, index in PROVIDER_CASES:
            expected = "refuse: quoted line is not in the pinned commit: " + span
            got, reads = self._pinned_reads(
                self._provider_body(groups=[name]),
                {PROVIDER_REL: self._provider_source(blank=number)},
                {PROVIDER_REL: self._provider_source()},
            )
            self.assertEqual(got, [expected], span)
            self.assertEqual(reads, [number], span)

    def test_two_provider_spans_are_refused(self):
        for name, number, span, lines, index in PROVIDER_CASES:
            expected = "refuse: quoted line is not one line: " + span
            body = self._provider_body(groups=[name], copies={name: 2})
            got, reads = self._pinned_reads(
                body, {PROVIDER_REL: self._provider_source()}
            )
            self.assertEqual(got, [expected], span)
            self.assertEqual(reads, [], span)

    def test_draft_without_a_provider_span_adds_no_refusal(self):
        for name, number, span, lines, index in PROVIDER_CASES:
            groups = [group for group in PROVIDER_GROUPS if group != name]
            got, reads = self._pinned_reads(
                self._provider_body(groups=groups),
                {PROVIDER_REL: self._provider_source()},
            )
            self.assertEqual(got, [], span)
            self.assertEqual(
                reads,
                [n for n in PROVIDER_DECISION_ORDER if n != number],
                span,
            )

    def test_cover_mismatch_stops_the_scheme_decision(self):
        body = self._provider_body(
            groups=["scheme"], scheme=self._changed(SCHEME_LINES, 8)
        ) + self._file_ask_body(
            groups=["cover"], cover=self._changed(COVER_LINES, 5)
        )
        got, reads = self._pinned_reads(
            body,
            {
                OWNED_REL: self._file_ask_source(),
                PROVIDER_REL: self._provider_source(),
            },
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + COVER_SPAN]
        )
        self.assertEqual(reads, [COVER_NUMBER])

    def test_is_write_mismatch_stops_the_scheme_decision(self):
        body = self._provider_body(
            groups=["scheme"], scheme=self._changed(SCHEME_LINES, 8)
        ) + self._edit_walk_body(
            groups=["is_write"], is_write=self._changed(IS_WRITE_LINES, 2)
        )
        got, reads = self._pinned_reads(
            body,
            {
                OWNED_REL: self._file_ask_source(),
                PROVIDER_REL: self._provider_source(),
            },
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + IS_WRITE_SPAN]
        )
        self.assertEqual(reads, [IS_WRITE_NUMBER])

    def test_scheme_mismatch_stops_the_read_action_decision(self):
        body = self._provider_body(
            groups=["scheme", "read_action"],
            scheme=self._changed(SCHEME_LINES, 8),
            read_action=self._changed(READ_ACTION_LINES, 0),
        )
        got, reads = self._pinned_reads(
            body, {PROVIDER_REL: self._provider_source()}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + SCHEME_SPAN]
        )
        self.assertEqual(reads, [SCHEME_NUMBER])

    def test_read_action_mismatch_stops_the_write_action_decision(self):
        body = self._provider_body(
            groups=["scheme", "read_action", "write_action"],
            read_action=self._changed(READ_ACTION_LINES, 0),
        )
        got, reads = self._pinned_reads(
            body, {PROVIDER_REL: self._provider_source()}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + READ_ACTION_SPAN]
        )
        self.assertEqual(reads, [SCHEME_NUMBER, READ_ACTION_NUMBER])

    def test_write_action_mismatch_stops_the_default_action_decision(self):
        body = self._provider_body(
            groups=["write_action", "default_action"],
            write_action=self._changed(WRITE_ACTION_LINES, 3),
            default_action=self._changed(WRITE_ACTION_LINES, 5),
        )
        got, reads = self._pinned_reads(
            body, {PROVIDER_REL: self._provider_source()}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + WRITE_ACTION_SPAN]
        )
        self.assertEqual(reads, [WRITE_ACTION_NUMBER])

    def test_absent_read_action_line_stops_the_write_action_decision(self):
        body = self._provider_body(groups=["read_action", "write_action"])
        got, reads = self._pinned_reads(
            body,
            {PROVIDER_REL: self._provider_source(blank=READ_ACTION_NUMBER)},
            {PROVIDER_REL: self._provider_source()},
        )
        self.assertEqual(
            got,
            [
                "refuse: quoted line is not in the pinned commit: "
                + READ_ACTION_SPAN
            ],
        )
        self.assertEqual(reads, [READ_ACTION_NUMBER])

    def test_absent_write_action_line_stops_the_default_action_decision(self):
        body = self._provider_body(
            groups=["write_action", "default_action"],
            default_action=self._changed(WRITE_ACTION_LINES, 5),
        )
        got, reads = self._pinned_reads(
            body,
            {PROVIDER_REL: self._provider_source(blank=WRITE_ACTION_NUMBER)},
            {PROVIDER_REL: self._provider_source()},
        )
        self.assertEqual(
            got,
            [
                "refuse: quoted line is not in the pinned commit: "
                + WRITE_ACTION_SPAN
            ],
        )
        self.assertEqual(reads, [WRITE_ACTION_NUMBER])

    def test_provider_quote_refusal_waits_for_a_known_pin(self):
        body = self._provider_body(
            groups=["scheme"], scheme=self._changed(SCHEME_LINES, 8)
        )
        files = {PROVIDER_REL: self._provider_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        self.assertEqual(
            check.problems(
                self._raw_draft("Pinned commit: HEAD\n" + body, files)
            ),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        self.assertEqual(
            check.problems(
                self._raw_draft(
                    "Pinned commit: " + "f" * 40 + "\n" + body, files, commit=True
                )
            ),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_falsifier_scheme_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_scheme_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT scheme-quoted-line",
        )

    def test_falsifier_scheme_did_line_is_caught(self):
        self._caught_walk_index(
            "scheme_quote",
            9,
            "`" + SCHEME_SPAN + "`",
            self.test_scheme_did_line_does_not_stand_for_line_123,
            "CAUGHT scheme-did-line",
        )

    def test_falsifier_read_action_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_read_action_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT read-action-quoted-line",
        )

    def test_falsifier_read_action_block_arm_is_caught(self):
        self._caught_walk_index(
            "read_action_quote",
            2,
            "`" + WRITE_ACTION_SPAN + "`",
            self.test_read_action_block_arm_does_not_stand_for_line_189,
            "CAUGHT read-action-block-arm",
        )

    def test_falsifier_write_action_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_write_action_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT write-action-quoted-line",
        )

    def test_falsifier_write_action_delete_line_is_caught(self):
        self._caught_walk_index(
            "write_action_quote",
            4,
            "`" + WRITE_ACTION_SPAN + "`",
            self.test_write_action_delete_line_does_not_stand_for_line_190,
            "CAUGHT write-action-delete-line",
        )

    def test_falsifier_default_action_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_default_action_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT default-action-quoted-line",
        )

    def test_falsifier_default_action_delete_line_is_caught(self):
        self._caught_walk_index(
            "default_action_quote",
            4,
            "`" + DEFAULT_ACTION_SPAN + "`",
            self.test_default_action_delete_line_does_not_stand_for_line_192,
            "CAUGHT default-action-delete-line",
        )

    def _run_body_case(self, name):
        for case in RUN_BODY_CASES:
            if case[0] == name:
                return case
        raise AssertionError(name)

    def _run_body_group(self, name):
        return "run" if name in ("no_process", "seat") else "write_body"

    def _run_body_span(self, number):
        for name, case_number, span, lines, index in RUN_BODY_CASES:
            if case_number == number:
                return span
        raise AssertionError(number)

    def _present_run_body_decisions(self, body):
        """Return the run and write-body decisions whose span the draft cites."""
        return [
            number
            for number in RUN_BODY_DECISION_ORDER
            if "`" + self._run_body_span(number) + "`" in body
        ]

    def test_live_draft_run_body_quotes_match_their_pinned_lines(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        for name, number, span, lines, index in RUN_BODY_CASES:
            selector = getattr(check, name + "_quote")
            self.assertEqual(selector(text), lines[index], span)
            self.assertEqual(
                len(check._remainders(text, "`" + span + "`")), len(lines), span
            )
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        for name, number, span, lines, index in RUN_BODY_CASES:
            self.assertEqual(
                check.pinned_line(root, sha, RUN_REL, number), lines[index], span
            )
        self.assertEqual(check.problems(root), [])

    def test_run_body_fixture_keeps_every_decision_on_its_pinned_line(self):
        body = self._file_ask_body(groups=["run", "write_body"])
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._file_ask_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, list(RUN_BODY_DECISION_ORDER))

    def test_run_body_selectors_read_their_own_windows(self):
        for name, number, span, lines, index in RUN_BODY_CASES:
            selector = getattr(check, name + "_quote")
            group = self._run_body_group(name)
            self.assertIsNone(
                selector(self._file_ask_body(groups=[group], indented=False)), span
            )
            self.assertIsNone(selector("No run or write-body span here.\n"), span)
            self._assert_truncated_walk(
                selector,
                self._file_ask_body(groups=[group], **{group: lines[:index]}),
                index,
                span,
            )

    def _assert_run_body_quote_mismatch(self, name):
        _, number, span, lines, index = self._run_body_case(name)
        group = self._run_body_group(name)
        expected = "refuse: quoted line does not match " + span
        body = self._file_ask_body(
            groups=[group], **{group: self._changed(lines, index)}
        )
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._file_ask_source()}
        )
        self.assertEqual(got, [expected])
        present = self._present_run_body_decisions(body)
        self.assertEqual(reads, present[: present.index(number) + 1])
        root = self._draft(body, {OWNED_REL: self._file_ask_source()})
        (root / OWNED_REL).write_bytes(
            self._file_ask_source(
                lines={**FILE_ASK_LINES, number: "// edited in the worktree"}
            )
        )
        self.assertEqual(check.problems(root), [expected])
        root = self._draft(
            self._file_ask_body(groups=[group]),
            {OWNED_REL: self._file_ask_source()},
        )
        (root / OWNED_REL).write_bytes(
            self._file_ask_source(
                lines={**FILE_ASK_LINES, number: "// edited in the worktree"}
            )
        )
        self.assertEqual(check.problems(root), [])

    def test_no_process_quoted_line_mismatch_is_refused(self):
        self._assert_run_body_quote_mismatch("no_process")

    def test_seat_quoted_line_mismatch_is_refused(self):
        self._assert_run_body_quote_mismatch("seat")

    def test_body_doc_quoted_line_mismatch_is_refused(self):
        self._assert_run_body_quote_mismatch("body_doc")

    def test_create_only_quoted_line_mismatch_is_refused(self):
        self._assert_run_body_quote_mismatch("create_only")

    def test_present_revision_quoted_line_mismatch_is_refused(self):
        self._assert_run_body_quote_mismatch("present_revision")

    def _assert_run_body_line_not_cited(self, name, index):
        _, number, span, lines, _ = self._run_body_case(name)
        group = self._run_body_group(name)
        body = self._file_ask_body(
            groups=[group], **{group: self._changed(lines, index)}
        )
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._file_ask_source()}
        )
        self.assertEqual(got, [], span)
        self.assertEqual(reads, self._present_run_body_decisions(body), span)

    def test_run_record_line_does_not_stand_for_line_2958(self):
        self._assert_run_body_line_not_cited("no_process", 0)

    def test_run_walk_other_lines_do_not_stand_for_the_run_lines(self):
        for index in (2, 25, 26):
            self._assert_run_body_line_not_cited("no_process", index)

    def test_seat_kind_line_does_not_stand_for_line_2981(self):
        self._assert_run_body_line_not_cited("seat", 21)

    def test_seat_walk_other_lines_do_not_stand_for_line_2981(self):
        for index in (0, 2, 25, 26):
            self._assert_run_body_line_not_cited("seat", index)

    def test_body_follow_line_does_not_stand_for_line_3961(self):
        self._assert_run_body_line_not_cited("body_doc", 1)

    def test_write_body_walk_other_lines_do_not_stand_for_line_3961(self):
        for index in (2, 4, 7, 9):
            self._assert_run_body_line_not_cited("body_doc", index)

    def test_present_revision_line_does_not_stand_for_line_3966(self):
        lines = {
            **FILE_ASK_LINES,
            CREATE_ONLY_NUMBER: PRESENT_REVISION_QUOTE,
            PRESENT_REVISION_NUMBER: PRESENT_REVISION_QUOTE,
        }
        body = self._file_ask_body(groups=["write_body"])
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._file_ask_source(lines=lines)}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + CREATE_ONLY_SPAN]
        )
        self.assertEqual(reads, [BODY_DOC_NUMBER, CREATE_ONLY_NUMBER])

    def test_create_only_line_does_not_stand_for_line_3967(self):
        lines = {
            **FILE_ASK_LINES,
            CREATE_ONLY_NUMBER: CREATE_ONLY_QUOTE,
            PRESENT_REVISION_NUMBER: CREATE_ONLY_QUOTE,
        }
        body = self._file_ask_body(groups=["write_body"])
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._file_ask_source(lines=lines)}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + PRESENT_REVISION_SPAN]
        )
        self.assertEqual(
            reads, [BODY_DOC_NUMBER, CREATE_ONLY_NUMBER, PRESENT_REVISION_NUMBER]
        )

    def test_run_body_spans_without_an_indented_line_add_no_refusal(self):
        got, reads = self._pinned_reads(
            self._file_ask_body(groups=["run", "write_body"], indented=False),
            {OWNED_REL: self._file_ask_source()},
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

    def test_run_body_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        for name, number, span, lines, index in RUN_BODY_CASES:
            expected = "refuse: quoted line is not in the pinned commit: " + span
            body = self._file_ask_body(groups=[self._run_body_group(name)])
            got, reads = self._pinned_reads(
                body,
                {OWNED_REL: self._file_ask_source(blank=number)},
                {OWNED_REL: self._file_ask_source()},
            )
            self.assertEqual(got, [expected], span)
            present = self._present_run_body_decisions(body)
            self.assertEqual(reads, present[: present.index(number) + 1], span)

    def test_two_run_body_spans_are_refused(self):
        cases = (
            ("run", {NO_PROCESS_SPAN: 2}, NO_PROCESS_SPAN, []),
            ("run", {SEAT_SPAN: 2}, SEAT_SPAN, [NO_PROCESS_NUMBER]),
            ("write_body", {BODY_DOC_SPAN: 2}, BODY_DOC_SPAN, []),
            (
                "write_body",
                {CREATE_ONLY_SPAN: 2},
                CREATE_ONLY_SPAN,
                [BODY_DOC_NUMBER],
            ),
            (
                "write_body",
                {PRESENT_REVISION_SPAN: 2},
                PRESENT_REVISION_SPAN,
                [BODY_DOC_NUMBER, CREATE_ONLY_NUMBER],
            ),
        )
        for group, span_copies, span, present in cases:
            body = self._file_ask_body(groups=[group], span_copies=span_copies)
            got, reads = self._pinned_reads(
                body, {OWNED_REL: self._file_ask_source()}
            )
            self.assertEqual(
                got, ["refuse: quoted line is not one line: " + span], span
            )
            self.assertEqual(reads, present, span)

    def test_draft_without_a_run_body_span_adds_no_refusal(self):
        for name, number, span, lines, index in RUN_BODY_CASES:
            body = self._file_ask_body(
                groups=["run", "write_body"], omit=(span,)
            )
            got, reads = self._pinned_reads(
                body, {OWNED_REL: self._file_ask_source()}
            )
            self.assertEqual(got, [], span)
            self.assertEqual(
                reads,
                [other for other in RUN_BODY_DECISION_ORDER if other != number],
                span,
            )

    def test_op_mismatch_does_not_read_the_run_lines(self):
        body = self._edit_walk_body(
            groups=["op"], op=self._changed(REQUEST_LINES, 15)
        ) + self._file_ask_body(
            groups=["run"], run=self._changed(RUN_LINES, 1)
        )
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._file_ask_source()}
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + OP_SPAN])
        self.assertEqual(reads, [OP_NUMBER])

    def test_draft_without_the_op_span_still_refuses_the_no_process_line(self):
        body = self._file_ask_body(
            groups=["run"], run=self._changed(RUN_LINES, 1)
        )
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._file_ask_source()}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + NO_PROCESS_SPAN]
        )
        self.assertEqual(reads, [NO_PROCESS_NUMBER])

    def test_seat_mismatch_stops_the_later_decisions(self):
        body = (
            self._file_ask_body(
                groups=["run"], run=self._changed(RUN_LINES, 24)
            )
            + self._edit_walk_body(
                groups=["is_write"], is_write=self._changed(IS_WRITE_LINES, 2)
            )
            + self._file_ask_body(
                groups=["write_body"],
                write_body=self._changed(WRITE_BODY_LINES, 0),
            )
        )
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._file_ask_source()}
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + SEAT_SPAN])
        self.assertEqual(reads, [NO_PROCESS_NUMBER, SEAT_NUMBER])

    def test_is_write_mismatch_does_not_read_the_write_body_lines(self):
        body = self._edit_walk_body(
            groups=["is_write"], is_write=self._changed(IS_WRITE_LINES, 2)
        ) + self._file_ask_body(
            groups=["write_body"],
            write_body=self._changed(WRITE_BODY_LINES, 0),
        )
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._file_ask_source()}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + IS_WRITE_SPAN]
        )
        self.assertEqual(reads, [IS_WRITE_NUMBER])

    def test_read_mismatch_does_not_read_the_write_body_lines(self):
        body = (
            self._file_ask_body(groups=["run"])
            + self._file_ask_body(
                groups=["ask"], ask=self._changed(ASK_LINES, 17)
            )
            + self._file_ask_body(
                groups=["write_body"],
                write_body=self._changed(WRITE_BODY_LINES, 0),
            )
        )
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._file_ask_source()}
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + READ_SPAN])
        self.assertEqual(
            reads,
            [NO_PROCESS_NUMBER, SEAT_NUMBER, WRITE_NUMBER, READ_NUMBER],
        )

    def test_body_doc_mismatch_stops_the_later_decisions(self):
        body = self._file_ask_body(
            groups=["write_body"],
            write_body=self._changed(WRITE_BODY_LINES, 0),
        )
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._file_ask_source()}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + BODY_DOC_SPAN]
        )
        self.assertEqual(reads, [BODY_DOC_NUMBER])

    def test_create_only_mismatch_stops_the_present_revision_decision(self):
        body = self._file_ask_body(
            groups=["write_body"],
            write_body=self._changed(WRITE_BODY_LINES, 5),
        )
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._file_ask_source()}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + CREATE_ONLY_SPAN]
        )
        self.assertEqual(reads, [BODY_DOC_NUMBER, CREATE_ONLY_NUMBER])

    def test_present_revision_mismatch_stops_the_asks_decision(self):
        body = (
            self._file_ask_body(groups=["run"])
            + self._file_ask_body(
                groups=["write_body"],
                write_body=self._changed(WRITE_BODY_LINES, 6),
            )
            + self._file_ask_body(
                groups=["asks"], ask_third=ASKS_THIRD + "x"
            )
        )
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._file_ask_source()}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + PRESENT_REVISION_SPAN]
        )
        self.assertEqual(reads, list(RUN_BODY_DECISION_ORDER[:5]))

    def test_asks_mismatch_follows_the_run_body_matches(self):
        body = self._file_ask_body(
            groups=["run", "write_body", "asks"], ask_third=ASKS_THIRD + "x"
        )
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._file_ask_source()}
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + ASKS_SPAN])
        self.assertEqual(
            reads, list(RUN_BODY_DECISION_ORDER) + [ASKS_NUMBER]
        )

    def test_cover_mismatch_follows_the_run_body_matches(self):
        body = self._file_ask_body(
            groups=["run", "write_body", "cover"],
            cover=self._changed(COVER_LINES, 5),
        )
        got, reads = self._pinned_reads(
            body,
            {
                OWNED_REL: self._file_ask_source(),
                PROVIDER_REL: self._provider_source(),
            },
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + COVER_SPAN])
        self.assertEqual(reads, list(RUN_BODY_DECISION_ORDER) + [COVER_NUMBER])

    def test_run_body_quote_refusal_waits_for_a_known_pin(self):
        body = self._file_ask_body(
            groups=["run"], run=self._changed(RUN_LINES, 1)
        )
        files = {OWNED_REL: self._file_ask_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        self.assertEqual(
            check.problems(
                self._raw_draft("Pinned commit: HEAD\n" + body, files)
            ),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        self.assertEqual(
            check.problems(
                self._raw_draft(
                    "Pinned commit: " + "f" * 40 + "\n" + body, files, commit=True
                )
            ),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def _caught_run_body_index(self, global_name, index, span, named_test, label):
        def planted(text):
            remainders = check._remainders(text, "`" + span + "`")
            if len(remainders) <= index:
                return None
            return remainders[index]

        self._caught(
            global_name,
            planted,
            named_test,
            "refuse: quoted line does not match",
            label,
        )

    def test_falsifier_no_process_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_no_process_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT no-process-quoted-line",
        )

    def test_falsifier_run_record_line_is_caught(self):
        self._caught_run_body_index(
            "no_process_quote",
            0,
            NO_PROCESS_SPAN,
            self.test_run_record_line_does_not_stand_for_line_2958,
            "CAUGHT run-record-line",
        )

    def test_falsifier_seat_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_seat_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT seat-quoted-line",
        )

    def test_falsifier_seat_kind_line_is_caught(self):
        self._caught_run_body_index(
            "seat_quote",
            21,
            SEAT_SPAN,
            self.test_seat_kind_line_does_not_stand_for_line_2981,
            "CAUGHT seat-kind-line",
        )

    def test_falsifier_body_doc_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_body_doc_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT body-doc-quoted-line",
        )

    def test_falsifier_body_follow_line_is_caught(self):
        self._caught_run_body_index(
            "body_doc_quote",
            1,
            BODY_DOC_SPAN,
            self.test_body_follow_line_does_not_stand_for_line_3961,
            "CAUGHT body-follow-line",
        )

    def test_falsifier_create_only_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_create_only_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT create-only-quoted-line",
        )

    def test_falsifier_present_revision_as_missing_is_caught(self):
        self._caught_run_body_index(
            "create_only_quote",
            6,
            CREATE_ONLY_SPAN,
            self.test_present_revision_line_does_not_stand_for_line_3966,
            "CAUGHT present-revision-as-missing",
        )

    def test_falsifier_present_revision_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_present_revision_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT present-revision-quoted-line",
        )

    def test_falsifier_create_only_as_present_is_caught(self):
        self._caught_run_body_index(
            "present_revision_quote",
            5,
            PRESENT_REVISION_SPAN,
            self.test_create_only_line_does_not_stand_for_line_3967,
            "CAUGHT create-only-as-present",
        )

    def _append_case(self, name):
        for case in APPEND_CASES:
            if case[0] == name:
                return case
        raise AssertionError(name)

    def _append_group(self, name):
        if name in ("append_condition", "host_path_err", "held_err"):
            return "condition"
        return "doc"

    def _append_span(self, number):
        if number in (APPEND_CALL_NUMBER, OUTCOME_HELD_NUMBER):
            return APPEND_RANGE_SPAN
        for name, case_number, span, lines, index in APPEND_CASES:
            if case_number == number:
                return span
        raise AssertionError(number)

    def _present_append_decisions(self, body):
        """Return the append decisions whose span the draft cites."""
        return [
            number
            for number in APPEND_DECISION_ORDER
            if "`" + self._append_span(number) + "`" in body
        ]

    def _assert_append_quote_mismatch(self, name):
        _, number, span, lines, index = self._append_case(name)
        group = self._append_group(name)
        expected = "refuse: quoted line does not match " + span
        body = self._append_body(
            groups=[group], **{group: self._changed(lines, index)}
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._append_source()})
        self.assertEqual(got, [expected])
        present = self._present_append_decisions(body)
        self.assertEqual(reads, present[: present.index(number) + 1])
        root = self._draft(body, {OWNED_REL: self._append_source()})
        (root / OWNED_REL).write_bytes(
            self._append_source(
                lines={**APPEND_LINES, number: "// edited in the worktree"}
            )
        )
        self.assertEqual(check.problems(root), [expected])
        root = self._draft(
            self._append_body(groups=[group]),
            {OWNED_REL: self._append_source()},
        )
        (root / OWNED_REL).write_bytes(
            self._append_source(
                lines={**APPEND_LINES, number: "// edited in the worktree"}
            )
        )
        self.assertEqual(check.problems(root), [])

    def _assert_append_line_not_cited(self, name, index):
        _, number, span, lines, _ = self._append_case(name)
        group = self._append_group(name)
        body = self._append_body(
            groups=[group], **{group: self._changed(lines, index)}
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._append_source()})
        self.assertEqual(got, [], span)
        self.assertEqual(reads, self._present_append_decisions(body), span)

    def test_live_draft_append_quotes_match_their_pinned_lines(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        for name, number, span, lines, index in APPEND_CASES:
            selector = getattr(check, name + "_quote")
            self.assertEqual(selector(text), lines[index], span)
            self.assertEqual(
                len(check._remainders(text, "`" + self._append_span(number) + "`")),
                len(lines),
                span,
            )
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        for name, number, span, lines, index in APPEND_CASES:
            self.assertEqual(
                check.pinned_line(root, sha, OWNED_REL, number), lines[index], span
            )
        self.assertEqual(check.problems(root), [])

    def test_append_fixture_keeps_every_decision_on_its_pinned_line(self):
        got, reads = self._pinned_reads(
            self._append_body(), {OWNED_REL: self._append_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, list(APPEND_DECISION_ORDER))

    def test_append_selectors_read_their_own_windows(self):
        for name, number, span, lines, index in APPEND_CASES:
            selector = getattr(check, name + "_quote")
            group = self._append_group(name)
            self.assertIsNone(
                selector(self._append_body(groups=[group], indented=False)), span
            )
            self.assertIsNone(selector("No append span here.\n"), span)
            self._assert_truncated_walk(
                selector,
                self._append_body(groups=[group], **{group: lines[:index]}),
                index,
                span,
            )

    def test_append_condition_quoted_line_mismatch_is_refused(self):
        self._assert_append_quote_mismatch("append_condition")

    def test_host_path_err_quoted_line_mismatch_is_refused(self):
        self._assert_append_quote_mismatch("host_path_err")

    def test_held_err_quoted_line_mismatch_is_refused(self):
        self._assert_append_quote_mismatch("held_err")

    def test_append_cap_quoted_line_mismatch_is_refused(self):
        self._assert_append_quote_mismatch("append_cap")

    def test_append_call_quoted_line_mismatch_is_refused(self):
        self._assert_append_quote_mismatch("append_call")

    def test_outcome_held_quoted_line_mismatch_is_refused(self):
        self._assert_append_quote_mismatch("outcome_held")

    def test_write_invoke_quoted_line_mismatch_is_refused(self):
        self._assert_append_quote_mismatch("write_invoke")

    def test_host_path_return_does_not_stand_for_line_3935(self):
        lines = {
            **APPEND_LINES,
            APPEND_CONDITION_NUMBER: HOST_PATH_ERR_QUOTE,
            HOST_PATH_ERR_NUMBER: HOST_PATH_ERR_QUOTE,
        }
        body = self._append_body(groups=["condition"])
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._append_source(lines=lines)}
        )
        self.assertEqual(
            got,
            ["refuse: quoted line does not match " + APPEND_CONDITION_SPAN],
        )
        self.assertEqual(reads, [APPEND_CONDITION_NUMBER])

    def test_append_walk_other_lines_do_not_stand_for_line_3935(self):
        for index in (0, 18, 31):
            self._assert_append_line_not_cited("append_condition", index)

    def test_append_condition_does_not_stand_for_line_3936(self):
        lines = {
            **APPEND_LINES,
            HOST_PATH_ERR_NUMBER: APPEND_CONDITION_QUOTE,
        }
        body = self._append_body(groups=["condition"])
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._append_source(lines=lines)}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + HOST_PATH_ERR_SPAN]
        )
        self.assertEqual(
            reads, [APPEND_CONDITION_NUMBER, HOST_PATH_ERR_NUMBER]
        )

    def test_host_path_return_does_not_stand_for_line_3947(self):
        lines = {**APPEND_LINES, HELD_ERR_NUMBER: HOST_PATH_ERR_QUOTE}
        body = self._append_body(groups=["condition"])
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._append_source(lines=lines)}
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + HELD_ERR_SPAN])
        self.assertEqual(
            reads,
            [APPEND_CONDITION_NUMBER, HOST_PATH_ERR_NUMBER, HELD_ERR_NUMBER],
        )

    def test_append_grant_line_does_not_stand_for_line_4023(self):
        lines = {**APPEND_LINES, APPEND_CAP_NUMBER: DOC_WALK_LINES[0]}
        body = self._append_body(groups=["doc"])
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._append_source(lines=lines)}
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + APPEND_CAP_SPAN])
        self.assertEqual(reads, [APPEND_CAP_NUMBER])

    def test_append_doc_walk_other_lines_do_not_stand_for_line_4023(self):
        for index in (2, 12):
            self._assert_append_line_not_cited("append_cap", index)

    def test_outcome_held_line_does_not_stand_for_line_4032(self):
        lines = {
            **APPEND_LINES,
            APPEND_CALL_NUMBER: OUTCOME_HELD_QUOTE,
            OUTCOME_HELD_NUMBER: OUTCOME_HELD_QUOTE,
        }
        body = self._append_body(groups=["doc"])
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._append_source(lines=lines)}
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + APPEND_CALL_SPAN])
        self.assertEqual(reads, [APPEND_CAP_NUMBER, APPEND_CALL_NUMBER])

    def test_append_call_line_does_not_stand_for_line_4033(self):
        lines = {**APPEND_LINES, OUTCOME_HELD_NUMBER: APPEND_CALL_QUOTE}
        body = self._append_body(groups=["doc"])
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._append_source(lines=lines)}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + OUTCOME_HELD_SPAN]
        )
        self.assertEqual(
            reads,
            [APPEND_CAP_NUMBER, APPEND_CALL_NUMBER, OUTCOME_HELD_NUMBER],
        )

    def test_outcome_held_line_does_not_stand_for_line_4061(self):
        lines = {**APPEND_LINES, WRITE_INVOKE_NUMBER: OUTCOME_HELD_QUOTE}
        body = self._append_body(groups=["doc"])
        got, reads = self._pinned_reads(
            body, {OWNED_REL: self._append_source(lines=lines)}
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + WRITE_INVOKE_SPAN]
        )
        self.assertEqual(reads, list(APPEND_DECISION_ORDER[3:]))

    def test_append_spans_without_an_indented_line_add_no_refusal(self):
        got, reads = self._pinned_reads(
            self._append_body(indented=False), {OWNED_REL: self._append_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

    def test_append_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        for name, number, span, lines, index in APPEND_CASES:
            expected = "refuse: quoted line is not in the pinned commit: " + span
            body = self._append_body(
                groups=[self._append_group(name)],
                omit=tuple(
                    other_span
                    for other, _, other_span, _, _ in APPEND_CASES
                    if other != name
                ),
            )
            got, reads = self._pinned_reads(
                body,
                {OWNED_REL: self._append_source(blank=number)},
                {OWNED_REL: self._append_source()},
            )
            self.assertEqual(got, [expected], span)
            present = self._present_append_decisions(body)
            self.assertEqual(reads, present[: present.index(number) + 1], span)

    def test_two_append_spans_are_refused(self):
        cases = (
            (
                "condition",
                {APPEND_CONDITION_SPAN: 2},
                APPEND_CONDITION_SPAN,
                [],
            ),
            (
                "condition",
                {HOST_PATH_ERR_SPAN: 2},
                HOST_PATH_ERR_SPAN,
                [APPEND_CONDITION_NUMBER],
            ),
            (
                "condition",
                {HELD_ERR_SPAN: 2},
                HELD_ERR_SPAN,
                [APPEND_CONDITION_NUMBER, HOST_PATH_ERR_NUMBER],
            ),
            ("doc", {APPEND_CAP_SPAN: 2}, APPEND_CAP_SPAN, []),
            (
                "doc",
                {APPEND_RANGE_SPAN: 2},
                APPEND_RANGE_SPAN,
                [APPEND_CAP_NUMBER],
            ),
            (
                "doc",
                {WRITE_INVOKE_SPAN: 2},
                WRITE_INVOKE_SPAN,
                [
                    APPEND_CAP_NUMBER,
                    APPEND_CALL_NUMBER,
                    OUTCOME_HELD_NUMBER,
                ],
            ),
        )
        for group, span_copies, span, present in cases:
            body = self._append_body(groups=[group], span_copies=span_copies)
            got, reads = self._pinned_reads(
                body, {OWNED_REL: self._append_source()}
            )
            self.assertEqual(
                got, ["refuse: quoted line is not one line: " + span], span
            )
            self.assertEqual(reads, present, span)

    def test_draft_without_an_append_span_adds_no_refusal(self):
        removed = (
            (APPEND_CONDITION_SPAN, (APPEND_CONDITION_NUMBER,)),
            (HOST_PATH_ERR_SPAN, (HOST_PATH_ERR_NUMBER,)),
            (HELD_ERR_SPAN, (HELD_ERR_NUMBER,)),
            (APPEND_CAP_SPAN, (APPEND_CAP_NUMBER,)),
            (APPEND_RANGE_SPAN, (APPEND_CALL_NUMBER, OUTCOME_HELD_NUMBER)),
            (WRITE_INVOKE_SPAN, (WRITE_INVOKE_NUMBER,)),
        )
        for span, gone in removed:
            body = self._append_body(omit=(span,))
            got, reads = self._pinned_reads(
                body, {OWNED_REL: self._append_source()}
            )
            self.assertEqual(got, [], span)
            self.assertEqual(
                reads,
                [number for number in APPEND_DECISION_ORDER if number not in gone],
                span,
            )

    def test_3850_mismatch_does_not_read_the_append_lines(self):
        body = self._file_ask_body(
            groups=["ask"], ask=self._changed(ASK_LINES, 17)
        ) + self._append_body(
            groups=["condition"],
            condition=self._changed(APPEND_WALK_LINES, 7),
        )
        got, reads = self._pinned_reads(
            body,
            {
                OWNED_REL: self._file_ask_source(
                    lines={**FILE_ASK_LINES, **APPEND_LINES}
                )
            },
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + READ_SPAN])
        self.assertEqual(reads, [WRITE_NUMBER, READ_NUMBER])

    def test_3935_mismatch_does_not_read_the_host_path_line(self):
        body = self._append_body(condition=self._changed(APPEND_WALK_LINES, 7))
        got, reads = self._pinned_reads(body, {OWNED_REL: self._append_source()})
        self.assertEqual(
            got,
            ["refuse: quoted line does not match " + APPEND_CONDITION_SPAN],
        )
        self.assertEqual(reads, [APPEND_CONDITION_NUMBER])

    def test_3936_mismatch_does_not_read_the_held_line(self):
        body = self._append_body(condition=self._changed(APPEND_WALK_LINES, 8))
        got, reads = self._pinned_reads(body, {OWNED_REL: self._append_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + HOST_PATH_ERR_SPAN]
        )
        self.assertEqual(
            reads, [APPEND_CONDITION_NUMBER, HOST_PATH_ERR_NUMBER]
        )

    def test_3947_mismatch_does_not_read_the_body_doc_line(self):
        body = self._append_body(
            condition=self._changed(APPEND_WALK_LINES, 19)
        ) + self._file_ask_body(groups=["write_body"])
        got, reads = self._pinned_reads(
            body,
            {
                OWNED_REL: self._file_ask_source(
                    lines={**FILE_ASK_LINES, **APPEND_LINES}
                )
            },
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + HELD_ERR_SPAN])
        self.assertEqual(
            reads,
            [APPEND_CONDITION_NUMBER, HOST_PATH_ERR_NUMBER, HELD_ERR_NUMBER],
        )

    def test_3961_mismatch_does_not_read_the_append_doc_lines(self):
        body = self._file_ask_body(
            groups=["write_body"],
            write_body=self._changed(WRITE_BODY_LINES, 0),
        ) + self._append_body(groups=["doc"])
        got, reads = self._pinned_reads(
            body,
            {
                OWNED_REL: self._file_ask_source(
                    lines={**FILE_ASK_LINES, **APPEND_LINES}
                )
            },
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + BODY_DOC_SPAN])
        self.assertEqual(reads, [BODY_DOC_NUMBER])

    def test_3967_mismatch_does_not_read_the_append_doc_lines(self):
        body = self._file_ask_body(
            groups=["write_body"],
            write_body=self._changed(WRITE_BODY_LINES, 6),
        ) + self._append_body(groups=["doc"])
        got, reads = self._pinned_reads(
            body,
            {
                OWNED_REL: self._file_ask_source(
                    lines={**FILE_ASK_LINES, **APPEND_LINES}
                )
            },
        )
        self.assertEqual(
            got,
            ["refuse: quoted line does not match " + PRESENT_REVISION_SPAN],
        )
        self.assertEqual(
            reads, [BODY_DOC_NUMBER, CREATE_ONLY_NUMBER, PRESENT_REVISION_NUMBER]
        )

    def test_4023_mismatch_does_not_read_the_call_line(self):
        body = self._append_body(
            groups=["doc"], doc=self._changed(DOC_WALK_LINES, 1)
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._append_source()})
        self.assertEqual(got, ["refuse: quoted line does not match " + APPEND_CAP_SPAN])
        self.assertEqual(reads, [APPEND_CAP_NUMBER])

    def test_4032_mismatch_does_not_read_the_outcome_line(self):
        body = self._append_body(
            groups=["doc"], doc=self._changed(DOC_WALK_LINES, 10)
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._append_source()})
        self.assertEqual(got, ["refuse: quoted line does not match " + APPEND_CALL_SPAN])
        self.assertEqual(reads, [APPEND_CAP_NUMBER, APPEND_CALL_NUMBER])

    def test_4033_mismatch_does_not_read_the_invoke_line(self):
        body = self._append_body(
            groups=["doc"], doc=self._changed(DOC_WALK_LINES, 11)
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._append_source()})
        self.assertEqual(
            got, ["refuse: quoted line does not match " + OUTCOME_HELD_SPAN]
        )
        self.assertEqual(
            reads,
            [APPEND_CAP_NUMBER, APPEND_CALL_NUMBER, OUTCOME_HELD_NUMBER],
        )

    def test_4061_mismatch_does_not_read_the_asks_line(self):
        body = self._append_body(
            groups=["doc"], doc=self._changed(DOC_WALK_LINES, 13)
        ) + self._file_ask_body(groups=["asks"], ask_third=ASKS_THIRD + "x")
        got, reads = self._pinned_reads(
            body,
            {
                OWNED_REL: self._file_ask_source(
                    lines={**FILE_ASK_LINES, **APPEND_LINES}
                )
            },
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + WRITE_INVOKE_SPAN]
        )
        self.assertEqual(reads, list(APPEND_DECISION_ORDER[3:]))

    def test_asks_mismatch_follows_the_append_matches(self):
        body = self._append_body() + self._file_ask_body(
            groups=["asks", "marker"], ask_third=ASKS_THIRD + "x"
        )
        got, reads = self._pinned_reads(
            body,
            {
                OWNED_REL: self._file_ask_source(
                    lines={**FILE_ASK_LINES, **APPEND_LINES}
                )
            },
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + ASKS_SPAN])
        self.assertEqual(reads, list(APPEND_DECISION_ORDER) + [ASKS_NUMBER])

    def test_cover_mismatch_follows_the_append_matches(self):
        body = (
            self._append_body()
            + self._file_ask_body(
                groups=["cover"], cover=self._changed(COVER_LINES, 5)
            )
            + self._provider_body(groups=["scheme"])
        )
        got, reads = self._pinned_reads(
            body,
            {
                OWNED_REL: self._file_ask_source(
                    lines={**FILE_ASK_LINES, **APPEND_LINES}
                ),
                PROVIDER_REL: self._provider_source(),
            },
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + COVER_SPAN])
        self.assertEqual(reads, list(APPEND_DECISION_ORDER) + [COVER_NUMBER])

    def test_append_quote_refusal_waits_for_a_known_pin(self):
        body = self._append_body(condition=self._changed(APPEND_WALK_LINES, 7))
        files = {OWNED_REL: self._append_source()}
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        self.assertEqual(
            check.problems(
                self._raw_draft("Pinned commit: HEAD\n" + body, files)
            ),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        self.assertEqual(
            check.problems(
                self._raw_draft(
                    "Pinned commit: " + "f" * 40 + "\n" + body, files, commit=True
                )
            ),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_falsifier_append_condition_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_append_condition_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT append-condition-quoted-line",
        )

    def test_falsifier_host_path_return_as_condition_is_caught(self):
        self._caught_run_body_index(
            "append_condition_quote",
            8,
            APPEND_CONDITION_SPAN,
            self.test_host_path_return_does_not_stand_for_line_3935,
            "CAUGHT host-path-return-as-condition",
        )

    def test_falsifier_host_path_err_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_host_path_err_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT host-path-err-quoted-line",
        )

    def test_falsifier_append_condition_as_return_is_caught(self):
        self._caught_run_body_index(
            "host_path_err_quote",
            7,
            HOST_PATH_ERR_SPAN,
            self.test_append_condition_does_not_stand_for_line_3936,
            "CAUGHT append-condition-as-return",
        )

    def test_falsifier_held_err_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_held_err_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT held-err-quoted-line",
        )

    def test_falsifier_host_path_return_as_held_is_caught(self):
        self._caught_run_body_index(
            "held_err_quote",
            8,
            HELD_ERR_SPAN,
            self.test_host_path_return_does_not_stand_for_line_3947,
            "CAUGHT host-path-return-as-held",
        )

    def test_falsifier_append_cap_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_append_cap_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT append-cap-quoted-line",
        )

    def test_falsifier_append_grant_line_is_caught(self):
        self._caught_run_body_index(
            "append_cap_quote",
            0,
            APPEND_CAP_SPAN,
            self.test_append_grant_line_does_not_stand_for_line_4023,
            "CAUGHT append-grant-line",
        )

    def test_falsifier_append_call_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_append_call_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT append-call-quoted-line",
        )

    def test_falsifier_outcome_held_as_call_is_caught(self):
        self._caught_run_body_index(
            "append_call_quote",
            11,
            APPEND_RANGE_SPAN,
            self.test_outcome_held_line_does_not_stand_for_line_4032,
            "CAUGHT outcome-held-as-call",
        )

    def test_falsifier_outcome_held_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_outcome_held_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT outcome-held-quoted-line",
        )

    def test_falsifier_append_call_as_outcome_is_caught(self):
        self._caught_run_body_index(
            "outcome_held_quote",
            10,
            APPEND_RANGE_SPAN,
            self.test_append_call_line_does_not_stand_for_line_4033,
            "CAUGHT append-call-as-outcome",
        )

    def test_falsifier_write_invoke_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_write_invoke_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT write-invoke-quoted-line",
        )

    def test_falsifier_outcome_held_as_invoke_is_caught(self):
        self._caught_run_body_index(
            "write_invoke_quote",
            11,
            WRITE_INVOKE_SPAN,
            self.test_outcome_held_line_does_not_stand_for_line_4061,
            "CAUGHT outcome-held-as-invoke",
        )

    def _hosted_case(self, name):
        for case in HOSTED_CASES:
            if case[0] == name:
                return case
        raise AssertionError(name)

    def _hosted_group(self, name):
        if name == "no_provider":
            return "no_provider"
        if name in ("parent_grant_doc", "narrower", "child_grant_none"):
            return "child"
        if name in ("init_guard", "project_resource"):
            return "init"
        if name in (
            "child_host_doc",
            "empty_journal",
            "admit_system",
            "inherited_err",
            "grant_parent",
        ):
            return name
        return "compare"

    def _hosted_span(self, number):
        for name, case_number, span, lines, index in HOSTED_CASES:
            if case_number == number:
                return span
        raise AssertionError(number)

    def _present_hosted_decisions(self, body):
        """Return the hosted decisions whose span the draft cites."""
        return [
            number
            for number in HOSTED_DECISION_ORDER
            if "`" + self._hosted_span(number) + "`" in body
        ]

    def _hosted_body(
        self,
        no_write=NO_WRITE_LINES,
        no_provider=NO_PROVIDER_LINES,
        child=CHILD_LINES,
        init=PROJECT_LINES,
        compare=AUTHORIZE_LINES,
        child_host_doc=CHILD_HOST_WALK,
        empty_journal=CHILD_HOST_WALK,
        admit_system=CHILD_HOST_WALK,
        inherited_err=INHERITED_ERR_WALK,
        grant_parent=GRANT_PARENT_WALK,
        deny=DENY_QUOTE,
        cover=COVER_LINES,
        provider=SCHEME_LINES,
        groups=None,
        copies=None,
        span_copies=None,
        indented=True,
        omit=(),
    ):
        """A draft that cites the hosted spans and indents their walks."""
        copies = copies or {}
        span_copies = span_copies or {}
        chosen = HOSTED_GROUPS if groups is None else tuple(groups)
        blocks = (
            ("no_write", [NO_WRITE_SPAN], list(no_write)),
            ("no_provider", [NO_PROVIDER_SPAN], list(no_provider)),
            ("child", [CHILD_SPAN, NARROWER_SPAN, CHILD_GRANT_NONE_SPAN], list(child)),
            ("init", [PROJECT_SPAN, PROJECT_RESOURCE_SPAN], list(init)),
            ("compare", [AUTHORIZE_SPAN], list(compare)),
            ("child_host_doc", [CHILD_HOST_DOC_SPAN], list(child_host_doc)),
            ("empty_journal", [EMPTY_JOURNAL_SPAN], list(empty_journal)),
            ("admit_system", [ADMIT_SYSTEM_SPAN], list(admit_system)),
            ("inherited_err", [INHERITED_ERR_SPAN], list(inherited_err)),
            ("grant_parent", [GRANT_PARENT_SPAN], list(grant_parent)),
            ("deny", [DENY_SPAN], [deny] + list(DENY_LINES[1:])),
            ("mint", [MINT_SPAN], [MINT_FIRST, MINT_SECOND]),
            ("cover", [COVER_SPAN], list(cover)),
            ("provider", [SCHEME_SPAN], list(provider)),
        )
        parts = []
        for name, spans, lines in blocks:
            if name not in chosen:
                continue
            prose = " ".join(
                self._cited(span, span_copies.get(span, copies.get(name, 1)))
                for span in spans
                if span not in omit
            )
            if not prose:
                continue
            parts.append(prose + "\n")
            if indented:
                parts.append("".join("    " + line + "\n" for line in lines))
            parts.append("\n")
        return "".join(parts)

    def _shared_child_host_body(self, lines=CHILD_HOST_WALK):
        """A draft whose 3455, 3470 and 3471 citations share one prose line."""
        prose = " ".join(
            "`" + span + "` is cited."
            for span in (
                CHILD_HOST_DOC_SPAN,
                EMPTY_JOURNAL_SPAN,
                ADMIT_SYSTEM_SPAN,
            )
        )
        return (
            prose
            + "\n"
            + "".join("    " + line + "\n" for line in lines)
            + "\n"
        )

    def _hosted_source(self, blank=None, lines=None):
        """A committed file with one correct line for every hosted quote."""
        rows = ["// filler"] * COVER_NUMBER
        for number, text in (lines or HOSTED_LINES).items():
            rows[number - 1] = text
        return self._padded(rows, blank=blank)

    def _hosted_files(self):
        return {
            OWNED_REL: self._hosted_source(),
            PROVIDER_REL: self._provider_source(),
        }

    def _assert_hosted_quote_mismatch(self, name):
        _, number, span, lines, index = self._hosted_case(name)
        group = self._hosted_group(name)
        expected = "refuse: quoted line does not match " + span
        body = self._hosted_body(
            groups=[group], **{group: self._changed(lines, index)}
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._hosted_source()})
        self.assertEqual(got, [expected])
        present = self._present_hosted_decisions(body)
        self.assertEqual(reads, present[: present.index(number) + 1])
        root = self._draft(body, {OWNED_REL: self._hosted_source()})
        (root / OWNED_REL).write_bytes(
            self._hosted_source(
                lines={**HOSTED_LINES, number: "// edited in the worktree"}
            )
        )
        self.assertEqual(check.problems(root), [expected])
        root = self._draft(
            self._hosted_body(groups=[group]),
            {OWNED_REL: self._hosted_source()},
        )
        (root / OWNED_REL).write_bytes(
            self._hosted_source(
                lines={**HOSTED_LINES, number: "// edited in the worktree"}
            )
        )
        self.assertEqual(check.problems(root), [])

    def _assert_hosted_line_not_cited(self, name, index, omit=()):
        _, number, span, lines, _ = self._hosted_case(name)
        group = self._hosted_group(name)
        body = self._hosted_body(
            groups=[group], **{group: self._changed(lines, index)}, omit=omit
        )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._hosted_source()})
        self.assertEqual(got, [], span)
        self.assertEqual(reads, self._present_hosted_decisions(body), span)

    def test_live_draft_hosted_quotes_match_their_pinned_lines(self):
        root = check.worktree_root()
        text = check.load_draft(root)
        if text is None:
            self.skipTest("no draft in this worktree")
        for name, number, span, lines, index in HOSTED_CASES:
            selector = getattr(check, name + "_quote")
            self.assertEqual(selector(text), lines[index], span)
            self.assertEqual(
                len(check._remainders(text, "`" + span + "`")), len(lines), span
            )
        sha = check.pin_sha(text)
        self.assertIsNotNone(sha)
        for name, number, span, lines, index in HOSTED_CASES:
            self.assertEqual(
                check.pinned_line(root, sha, OWNED_REL, number), lines[index], span
            )
        self.assertEqual(check.problems(root), [])

    def test_hosted_fixture_keeps_every_decision_on_its_pinned_line(self):
        got, reads = self._pinned_reads(self._hosted_body(), self._hosted_files())
        self.assertEqual(got, [])
        self.assertEqual(reads, list(HOSTED_READ_ORDER))

    def test_hosted_selectors_read_their_own_windows(self):
        for name, number, span, lines, index in HOSTED_CASES:
            selector = getattr(check, name + "_quote")
            group = self._hosted_group(name)
            self.assertIsNone(
                selector(self._hosted_body(groups=[group], indented=False)), span
            )
            self.assertIsNone(selector("No hosted span here.\n"), span)
            self._assert_truncated_walk(
                selector,
                self._hosted_body(groups=[group], **{group: lines[:index]}),
                index,
                span,
            )

    def test_one_prose_line_citing_3455_3470_and_3471_walks_each_marker(self):
        body = self._shared_child_host_body()
        for span in (
            CHILD_HOST_DOC_SPAN,
            EMPTY_JOURNAL_SPAN,
            ADMIT_SYSTEM_SPAN,
        ):
            self.assertEqual(
                len(check._remainders(body, "`" + span + "`")),
                len(CHILD_HOST_WALK),
                span,
            )
        got, reads = self._pinned_reads(body, {OWNED_REL: self._hosted_source()})
        self.assertEqual(got, [])
        self.assertEqual(
            reads,
            [
                CHILD_HOST_DOC_NUMBER,
                EMPTY_JOURNAL_NUMBER,
                ADMIT_SYSTEM_NUMBER,
            ],
        )
        self.assertEqual(check.child_host_doc_quote(body), CHILD_HOST_WALK[0])
        self.assertEqual(check.empty_journal_quote(body), CHILD_HOST_WALK[15])
        self.assertEqual(check.admit_system_quote(body), CHILD_HOST_WALK[16])
        cases = (
            (0, CHILD_HOST_DOC_SPAN, CHILD_HOST_DOC_NUMBER),
            (15, EMPTY_JOURNAL_SPAN, EMPTY_JOURNAL_NUMBER),
            (16, ADMIT_SYSTEM_SPAN, ADMIT_SYSTEM_NUMBER),
        )
        for index, span, number in cases:
            got, reads = self._pinned_reads(
                self._shared_child_host_body(
                    self._changed(CHILD_HOST_WALK, index)
                ),
                {OWNED_REL: self._hosted_source()},
            )
            self.assertEqual(got, ["refuse: quoted line does not match " + span])
            self.assertEqual(
                reads,
                [
                    other
                    for other in (
                        CHILD_HOST_DOC_NUMBER,
                        EMPTY_JOURNAL_NUMBER,
                        ADMIT_SYSTEM_NUMBER,
                    )
                    if other <= number
                ],
                span,
            )

    def test_no_provider_quoted_line_mismatch_is_refused(self):
        self._assert_hosted_quote_mismatch("no_provider")

    def test_parent_grant_doc_quoted_line_mismatch_is_refused(self):
        self._assert_hosted_quote_mismatch("parent_grant_doc")

    def test_narrower_quoted_line_mismatch_is_refused(self):
        self._assert_hosted_quote_mismatch("narrower")

    def test_child_grant_none_quoted_line_mismatch_is_refused(self):
        self._assert_hosted_quote_mismatch("child_grant_none")

    def test_init_guard_quoted_line_mismatch_is_refused(self):
        self._assert_hosted_quote_mismatch("init_guard")

    def test_project_resource_quoted_line_mismatch_is_refused(self):
        self._assert_hosted_quote_mismatch("project_resource")

    def test_parent_compare_quoted_line_mismatch_is_refused(self):
        self._assert_hosted_quote_mismatch("parent_compare")

    def test_child_host_doc_quoted_line_mismatch_is_refused(self):
        self._assert_hosted_quote_mismatch("child_host_doc")

    def test_empty_journal_quoted_line_mismatch_is_refused(self):
        self._assert_hosted_quote_mismatch("empty_journal")

    def test_admit_system_quoted_line_mismatch_is_refused(self):
        self._assert_hosted_quote_mismatch("admit_system")

    def test_inherited_err_quoted_line_mismatch_is_refused(self):
        self._assert_hosted_quote_mismatch("inherited_err")

    def test_grant_parent_quoted_line_mismatch_is_refused(self):
        self._assert_hosted_quote_mismatch("grant_parent")

    def test_hosted_doc_start_does_not_stand_for_line_3339(self):
        self._assert_hosted_line_not_cited("no_provider", 0)

    def test_child_doc_start_does_not_stand_for_line_3360(self):
        self._assert_hosted_line_not_cited("parent_grant_doc", 0)

    def test_parent_grant_doc_does_not_stand_for_line_3370(self):
        self._assert_hosted_line_not_cited("narrower", 1, omit=(CHILD_SPAN,))

    def test_narrower_line_does_not_stand_for_line_3382(self):
        self._assert_hosted_line_not_cited(
            "child_grant_none", 11, omit=(CHILD_SPAN, NARROWER_SPAN)
        )

    def test_init_doc_start_does_not_stand_for_line_3387(self):
        self._assert_hosted_line_not_cited("init_guard", 0)

    def test_init_guard_line_does_not_stand_for_line_3403(self):
        self._assert_hosted_line_not_cited(
            "project_resource", 1, omit=(PROJECT_SPAN,)
        )

    def test_authorize_false_line_does_not_stand_for_line_3449(self):
        self._assert_hosted_line_not_cited("parent_compare", 18)

    def test_copy_log_line_does_not_stand_for_line_3455(self):
        self._assert_hosted_line_not_cited("child_host_doc", 1)

    def test_child_host_doc_does_not_stand_for_line_3470(self):
        self._assert_hosted_line_not_cited("empty_journal", 0)

    def test_empty_journal_line_does_not_stand_for_line_3471(self):
        self._assert_hosted_line_not_cited("admit_system", 15)

    def test_grant_some_line_does_not_stand_for_line_3474(self):
        self._assert_hosted_line_not_cited("inherited_err", 0)

    def test_grant_false_line_does_not_stand_for_line_3482(self):
        self._assert_hosted_line_not_cited("grant_parent", 4)

    def test_hosted_block_lines_do_not_stand_for_the_cited_lines(self):
        cases = (
            ("no_provider", 8),
            ("no_provider", 19),
            ("parent_grant_doc", 12),
            ("parent_grant_doc", 25),
            ("init_guard", 15),
            ("init_guard", 27),
            ("parent_compare", 0),
            ("parent_compare", 5),
            ("parent_compare", 8),
            ("parent_compare", 21),
            ("child_host_doc", 10),
            ("child_host_doc", 13),
            ("inherited_err", 3),
            ("inherited_err", 4),
            ("grant_parent", 0),
            ("grant_parent", 16),
            ("grant_parent", 19),
        )
        for name, index in cases:
            self._assert_hosted_line_not_cited(name, index)

    def test_two_hosted_spans_are_refused(self):
        for name, number, span, lines, index in HOSTED_CASES:
            expected = "refuse: quoted line is not one line: " + span
            group = self._hosted_group(name)
            body = self._hosted_body(
                groups=[group], span_copies={span: 2}
            )
            got, reads = self._pinned_reads(
                body, {OWNED_REL: self._hosted_source()}
            )
            self.assertEqual(got, [expected], span)
            present = self._present_hosted_decisions(body)
            self.assertEqual(reads, present[: present.index(number)], span)

    def test_new_duplicate_spans_keep_the_earlier_decisions(self):
        cases = (
            ("empty_journal", ("child_host_doc",), EMPTY_JOURNAL_SPAN, EMPTY_JOURNAL_NUMBER),
            (
                "admit_system",
                ("child_host_doc", "empty_journal"),
                ADMIT_SYSTEM_SPAN,
                ADMIT_SYSTEM_NUMBER,
            ),
            (
                "inherited_err",
                ("child_host_doc", "empty_journal", "admit_system"),
                INHERITED_ERR_SPAN,
                INHERITED_ERR_NUMBER,
            ),
            (
                "grant_parent",
                ("child_host_doc", "empty_journal", "admit_system", "inherited_err"),
                GRANT_PARENT_SPAN,
                GRANT_PARENT_NUMBER,
            ),
        )
        for group, earlier, span, number in cases:
            body = self._hosted_body(
                groups=list(earlier) + [group], span_copies={span: 2}
            )
            got, reads = self._pinned_reads(
                body, {OWNED_REL: self._hosted_source()}
            )
            self.assertEqual(
                got, ["refuse: quoted line is not one line: " + span], span
            )
            present = self._present_hosted_decisions(body)
            self.assertEqual(reads, present[: present.index(number)], span)
            self.assertNotIn(number, reads, span)

    def test_draft_without_a_hosted_span_adds_no_refusal(self):
        for name, number, span, lines, index in HOSTED_CASES:
            body = self._hosted_body(omit=(span,))
            got, reads = self._pinned_reads(body, self._hosted_files())
            self.assertEqual(got, [], span)
            self.assertEqual(
                reads, [other for other in HOSTED_READ_ORDER if other != number], span
            )

    def test_hosted_span_without_an_indented_line_adds_no_refusal(self):
        got, reads = self._pinned_reads(
            self._hosted_body(indented=False), self._hosted_files()
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

    def test_hosted_quoted_line_absent_from_the_pinned_commit_is_refused(self):
        for name, number, span, lines, index in HOSTED_CASES:
            expected = "refuse: quoted line is not in the pinned commit: " + span
            got, reads = self._pinned_reads(
                self._without(self._hosted_body(), lines, index),
                {
                    OWNED_REL: self._hosted_source(blank=number),
                    PROVIDER_REL: self._provider_source(),
                },
                {OWNED_REL: self._hosted_source()},
            )
            self.assertEqual(got, [expected], span)
            self.assertEqual(
                reads,
                [NO_WRITE_NUMBER]
                + list(HOSTED_DECISION_ORDER[: HOSTED_DECISION_ORDER.index(number) + 1]),
                span,
            )

    def test_no_write_mismatch_stops_the_no_provider_decision(self):
        got, reads = self._pinned_reads(
            self._hosted_body(
                no_write=self._changed(NO_WRITE_LINES, 4),
                no_provider=self._changed(NO_PROVIDER_LINES, 1),
            ),
            self._hosted_files(),
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + NO_WRITE_SPAN]
        )
        self.assertEqual(reads, [NO_WRITE_NUMBER])

    def test_no_provider_line_mismatch_follows_the_no_write_match(self):
        got, reads = self._pinned_reads(
            self._hosted_body(no_provider=self._changed(NO_PROVIDER_LINES, 1)),
            self._hosted_files(),
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + NO_PROVIDER_SPAN]
        )
        self.assertEqual(reads, [NO_WRITE_NUMBER, NO_PROVIDER_NUMBER])

    def test_no_provider_line_mismatch_without_the_no_write_span(self):
        groups = tuple(group for group in HOSTED_GROUPS if group != "no_write")
        got, reads = self._pinned_reads(
            self._hosted_body(
                groups=groups, no_provider=self._changed(NO_PROVIDER_LINES, 1)
            ),
            self._hosted_files(),
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + NO_PROVIDER_SPAN]
        )
        self.assertEqual(reads, [NO_PROVIDER_NUMBER])

    def test_parent_grant_mismatch_stops_the_narrower_decision(self):
        got, reads = self._pinned_reads(
            self._hosted_body(child=self._changed(CHILD_LINES, 1)),
            self._hosted_files(),
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + CHILD_SPAN])
        self.assertEqual(
            reads, [NO_WRITE_NUMBER, NO_PROVIDER_NUMBER, CHILD_NUMBER]
        )

    def test_child_grant_none_mismatch_follows_the_earlier_matches(self):
        got, reads = self._pinned_reads(
            self._hosted_body(child=self._changed(CHILD_LINES, 23)),
            self._hosted_files(),
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + CHILD_GRANT_NONE_SPAN]
        )
        self.assertEqual(
            reads,
            [NO_WRITE_NUMBER]
            + list(HOSTED_DECISION_ORDER[: HOSTED_DECISION_ORDER.index(CHILD_GRANT_NONE_NUMBER) + 1]),
        )

    def test_deny_mismatch_follows_the_hosted_matches(self):
        got, reads = self._pinned_reads(
            self._hosted_body(deny=DENY_QUOTE + "x"), self._hosted_files()
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + DENY_SPAN])
        self.assertEqual(
            reads,
            [NO_WRITE_NUMBER]
            + list(HOSTED_DECISION_ORDER)
            + [DENY_NUMBER],
        )
        self.assertNotIn(MINT_NUMBER, reads)

    def test_deny_mismatch_without_the_hosted_spans_stays_the_deny_refusal(self):
        got, reads = self._pinned_reads(
            self._hosted_body(groups=["deny"], deny=DENY_QUOTE + "x"),
            {OWNED_REL: self._hosted_source()},
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + DENY_SPAN])
        self.assertEqual(reads, [DENY_NUMBER])
        self.assertNotIn(MINT_NUMBER, reads)

    def _decisions_read_through(self, number):
        return [NO_WRITE_NUMBER] + list(
            HOSTED_DECISION_ORDER[: HOSTED_DECISION_ORDER.index(number) + 1]
        )

    def test_authorize_mismatch_stops_the_child_host_doc_decision(self):
        got, reads = self._pinned_reads(
            self._hosted_body(
                compare=self._changed(AUTHORIZE_LINES, 17),
                child_host_doc=self._changed(CHILD_HOST_WALK, 0),
            ),
            self._hosted_files(),
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + AUTHORIZE_SPAN]
        )
        self.assertEqual(reads, self._decisions_read_through(AUTHORIZE_NUMBER))
        self.assertNotIn(CHILD_HOST_DOC_NUMBER, reads)

    def test_child_host_doc_mismatch_follows_the_authorize_match(self):
        got, reads = self._pinned_reads(
            self._hosted_body(
                child_host_doc=self._changed(CHILD_HOST_WALK, 0),
                empty_journal=self._changed(CHILD_HOST_WALK, 15),
            ),
            self._hosted_files(),
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + CHILD_HOST_DOC_SPAN]
        )
        self.assertEqual(
            reads, self._decisions_read_through(CHILD_HOST_DOC_NUMBER)
        )
        self.assertNotIn(EMPTY_JOURNAL_NUMBER, reads)

    def test_empty_journal_mismatch_follows_the_child_host_doc_match(self):
        got, reads = self._pinned_reads(
            self._hosted_body(
                empty_journal=self._changed(CHILD_HOST_WALK, 15),
                admit_system=self._changed(CHILD_HOST_WALK, 16),
            ),
            self._hosted_files(),
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + EMPTY_JOURNAL_SPAN]
        )
        self.assertEqual(reads, self._decisions_read_through(EMPTY_JOURNAL_NUMBER))
        self.assertNotIn(ADMIT_SYSTEM_NUMBER, reads)

    def test_admit_system_mismatch_follows_the_empty_journal_match(self):
        got, reads = self._pinned_reads(
            self._hosted_body(
                admit_system=self._changed(CHILD_HOST_WALK, 16),
                inherited_err=self._changed(INHERITED_ERR_WALK, 1),
            ),
            self._hosted_files(),
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + ADMIT_SYSTEM_SPAN]
        )
        self.assertEqual(reads, self._decisions_read_through(ADMIT_SYSTEM_NUMBER))
        self.assertNotIn(INHERITED_ERR_NUMBER, reads)

    def test_inherited_err_mismatch_follows_the_admit_system_match(self):
        got, reads = self._pinned_reads(
            self._hosted_body(
                inherited_err=self._changed(INHERITED_ERR_WALK, 1),
                grant_parent=self._changed(GRANT_PARENT_WALK, 3),
            ),
            self._hosted_files(),
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + INHERITED_ERR_SPAN]
        )
        self.assertEqual(reads, self._decisions_read_through(INHERITED_ERR_NUMBER))
        self.assertNotIn(GRANT_PARENT_NUMBER, reads)

    def test_grant_parent_mismatch_follows_the_inherited_match(self):
        got, reads = self._pinned_reads(
            self._hosted_body(
                grant_parent=self._changed(GRANT_PARENT_WALK, 3),
                deny=DENY_QUOTE + "x",
            ),
            self._hosted_files(),
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + GRANT_PARENT_SPAN]
        )
        self.assertEqual(reads, self._decisions_read_through(GRANT_PARENT_NUMBER))
        self.assertNotIn(DENY_NUMBER, reads)

    def test_draft_without_the_authorize_span_still_refuses_a_child_host_doc_mismatch(self):
        groups = tuple(group for group in HOSTED_GROUPS if group != "compare")
        got, reads = self._pinned_reads(
            self._hosted_body(
                groups=groups, child_host_doc=self._changed(CHILD_HOST_WALK, 0)
            ),
            self._hosted_files(),
        )
        self.assertEqual(
            got, ["refuse: quoted line does not match " + CHILD_HOST_DOC_SPAN]
        )
        self.assertEqual(
            reads,
            [
                number
                for number in self._decisions_read_through(CHILD_HOST_DOC_NUMBER)
                if number != AUTHORIZE_NUMBER
            ],
        )

    def test_unchecked_exec_vm_line_is_not_compared(self):
        body = self._hosted_body() + (
            "`" + EXEC_SPAN + "` says `A ready decision still does not boot.`\n"
            "\n"
            "    // a different remainder no slice compares yet\n"
        )
        files = self._hosted_files()
        files[EXEC_REL] = ("// filler\n" * EXEC_NUMBER).encode("utf-8")
        got, reads = self._pinned_reads(body, files)
        self.assertEqual(got, [])
        self.assertEqual(reads, list(HOSTED_READ_ORDER))

    def test_cover_mismatch_stops_the_provider_decision(self):
        got, reads = self._pinned_reads(
            self._hosted_body(cover=self._changed(COVER_LINES, 5)),
            self._hosted_files(),
        )
        self.assertEqual(got, ["refuse: quoted line does not match " + COVER_SPAN])
        self.assertEqual(
            reads,
            [NO_WRITE_NUMBER]
            + list(HOSTED_DECISION_ORDER)
            + [DENY_NUMBER, MINT_NUMBER, COVER_NUMBER],
        )
        self.assertNotIn(SCHEME_NUMBER, reads)

    def test_hosted_quote_refusal_waits_for_a_known_pin(self):
        body = self._hosted_body(no_provider=self._changed(NO_PROVIDER_LINES, 1))
        files = self._hosted_files()
        self.assertEqual(
            check.problems(self._raw_draft(body, files)),
            ["refuse: draft has no pinned commit"],
        )
        self.assertEqual(
            check.problems(
                self._raw_draft("Pinned commit: HEAD\n" + body, files)
            ),
            ["refuse: pinned commit is not one 40-hex commit"],
        )
        self.assertEqual(
            check.problems(
                self._raw_draft(
                    "Pinned commit: " + "f" * 40 + "\n" + body, files, commit=True
                )
            ),
            ["refuse: pinned commit is not a commit: " + "f" * 40],
        )

    def test_falsifier_no_provider_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_no_provider_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT no-provider-quoted-line",
        )

    def test_falsifier_hosted_doc_start_is_caught(self):
        self._caught_walk_index(
            "no_provider_quote",
            0,
            "`" + NO_PROVIDER_SPAN + "`",
            self.test_hosted_doc_start_does_not_stand_for_line_3339,
            "CAUGHT hosted-doc-start",
        )

    def test_falsifier_parent_grant_doc_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_parent_grant_doc_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT parent-grant-doc-quoted-line",
        )

    def test_falsifier_child_doc_start_is_caught(self):
        self._caught_walk_index(
            "parent_grant_doc_quote",
            0,
            "`" + CHILD_SPAN + "`",
            self.test_child_doc_start_does_not_stand_for_line_3360,
            "CAUGHT child-doc-start",
        )

    def test_falsifier_narrower_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_narrower_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT narrower-quoted-line",
        )

    def test_falsifier_parent_grant_doc_as_narrower_is_caught(self):
        self._caught_walk_index(
            "narrower_quote",
            1,
            "`" + NARROWER_SPAN + "`",
            self.test_parent_grant_doc_does_not_stand_for_line_3370,
            "CAUGHT parent-grant-doc-as-narrower",
        )

    def test_falsifier_child_grant_none_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_child_grant_none_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT child-grant-none-quoted-line",
        )

    def test_falsifier_narrower_as_grant_none_is_caught(self):
        self._caught_walk_index(
            "child_grant_none_quote",
            11,
            "`" + CHILD_GRANT_NONE_SPAN + "`",
            self.test_narrower_line_does_not_stand_for_line_3382,
            "CAUGHT narrower-as-grant-none",
        )

    def test_falsifier_init_guard_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_init_guard_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT init-guard-quoted-line",
        )

    def test_falsifier_init_doc_start_is_caught(self):
        self._caught_walk_index(
            "init_guard_quote",
            0,
            "`" + PROJECT_SPAN + "`",
            self.test_init_doc_start_does_not_stand_for_line_3387,
            "CAUGHT init-doc-start",
        )

    def test_falsifier_project_resource_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_project_resource_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT project-resource-quoted-line",
        )

    def test_falsifier_init_guard_as_resource_is_caught(self):
        self._caught_walk_index(
            "project_resource_quote",
            1,
            "`" + PROJECT_RESOURCE_SPAN + "`",
            self.test_init_guard_line_does_not_stand_for_line_3403,
            "CAUGHT init-guard-as-resource",
        )

    def test_falsifier_parent_compare_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_parent_compare_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT parent-compare-quoted-line",
        )

    def test_falsifier_authorize_false_as_compare_is_caught(self):
        self._caught_walk_index(
            "parent_compare_quote",
            18,
            "`" + AUTHORIZE_SPAN + "`",
            self.test_authorize_false_line_does_not_stand_for_line_3449,
            "CAUGHT authorize-false-as-compare",
        )

    def test_falsifier_child_host_doc_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_child_host_doc_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT child-host-doc-quoted-line",
        )

    def test_falsifier_copy_log_as_child_host_is_caught(self):
        self._caught_walk_index(
            "child_host_doc_quote",
            1,
            "`" + CHILD_HOST_DOC_SPAN + "`",
            self.test_copy_log_line_does_not_stand_for_line_3455,
            "CAUGHT copy-log-as-child-host",
        )

    def test_falsifier_empty_journal_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_empty_journal_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT empty-journal-quoted-line",
        )

    def test_falsifier_child_host_doc_as_empty_journal_is_caught(self):
        self._caught_walk_index(
            "empty_journal_quote",
            0,
            "`" + EMPTY_JOURNAL_SPAN + "`",
            self.test_child_host_doc_does_not_stand_for_line_3470,
            "CAUGHT child-host-doc-as-empty-journal",
        )

    def test_falsifier_admit_system_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_admit_system_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT admit-system-quoted-line",
        )

    def test_falsifier_empty_journal_as_admit_is_caught(self):
        self._caught_walk_index(
            "admit_system_quote",
            15,
            "`" + ADMIT_SYSTEM_SPAN + "`",
            self.test_empty_journal_line_does_not_stand_for_line_3471,
            "CAUGHT empty-journal-as-admit",
        )

    def test_falsifier_inherited_err_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_inherited_err_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT inherited-err-quoted-line",
        )

    def test_falsifier_grant_some_as_inherited_is_caught(self):
        self._caught_walk_index(
            "inherited_err_quote",
            0,
            "`" + INHERITED_ERR_SPAN + "`",
            self.test_grant_some_line_does_not_stand_for_line_3474,
            "CAUGHT grant-some-as-inherited",
        )

    def test_falsifier_grant_parent_quoted_line_is_caught(self):
        self._caught(
            "quoted_line_matches",
            lambda quoted, source: True,
            self.test_grant_parent_quoted_line_mismatch_is_refused,
            "refuse: quoted line does not match",
            "CAUGHT grant-parent-quoted-line",
        )

    def test_falsifier_grant_false_as_parent_is_caught(self):
        self._caught_walk_index(
            "grant_parent_quote",
            4,
            "`" + GRANT_PARENT_SPAN + "`",
            self.test_grant_false_line_does_not_stand_for_line_3482,
            "CAUGHT grant-false-as-parent",
        )

    def test_falsifier_shared_line_child_host_index_is_caught(self):
        self._caught_walk_index(
            "child_host_doc_quote",
            1,
            "`" + CHILD_HOST_DOC_SPAN + "`",
            self.test_one_prose_line_citing_3455_3470_and_3471_walks_each_marker,
            "CAUGHT shared-line-child-host-index",
        )
