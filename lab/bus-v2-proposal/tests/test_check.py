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
KIND_RUN_QUOTE = '        ProposalKind::Run => Some("run"),'
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

    def _source(self, quote, following=NEXT_QUOTE):
        """A committed file whose line 3754 is QUOTE and line 3755 is FOLLOWING."""
        rows = ["// filler"] * (OWNED_NUMBER - 1) + [quote]
        if following is not None:
            rows.append(following)
        return ("\n".join(rows) + "\n").encode("utf-8")

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
        return ("\n".join(rows) + "\n").encode("utf-8")

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
        return ("\n".join(rows) + "\n").encode("utf-8")

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
        return ("\n".join(rows) + "\n").encode("utf-8")

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
        return ("\n".join(rows) + "\n").encode("utf-8")

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
        return ("\n".join(rows) + "\n").encode("utf-8")

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
        return ("\n".join(rows) + "\n").encode("utf-8")

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
        return ("\n".join(rows) + "\n").encode("utf-8")

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
        asks_third=ASKS_THIRD,
        launching_last=LAUNCHING_CONST,
        ask_count=20,
        kind_count=len(KIND_LINES),
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
        kind[11] = restore
        rows += ["// filler"] * (KIND_BLOCK_START - 1 - len(rows))
        rows += kind[:kind_count]
        return ("\n".join(rows) + "\n").encode("utf-8")

    def _kind_block(
        self,
        read=KIND_READ_QUOTE,
        edit=KIND_EDIT_QUOTE,
        restore=KIND_RESTORE_QUOTE,
        run=KIND_RUN_QUOTE,
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
            self._quote_body(OWNED_QUOTE),
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
            {OWNED_REL: self._source(OWNED_QUOTE, following=None)},
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

    def test_absent_next_quote_skips_the_next_line_read(self):
        got, reads = self._pinned_reads(
            self._quote_body(OWNED_QUOTE),
            {OWNED_REL: self._source(OWNED_QUOTE)},
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [OWNED_NUMBER])

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

    def test_two_asks_lines_are_not_read(self):
        got, reads = self._pinned_reads(
            self._asks_block(count=2), {ASKS_REL: self._asks_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

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

    def test_mint_quote_is_absent_with_one_indented_line(self):
        body = self._mint_block(count=1)
        self.assertIsNone(check.mint_quote(body))
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

    def test_mint_span_without_two_indented_lines_adds_no_refusal(self):
        got, reads = self._pinned_reads(
            self._mint_block(count=1), {MINT_REL: self._mint_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

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

    def test_journal_quote_is_absent_below_two_indented_lines(self):
        self.assertIsNone(check.journal_quote(self._journal_block(count=1)))
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

    def test_journal_span_without_two_indented_lines_adds_no_refusal(self):
        got, reads = self._pinned_reads(
            self._journal_block(count=1), {JOURNAL_REL: self._journal_source()}
        )
        self.assertEqual(got, [])
        self.assertEqual(reads, [])

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

    def test_write_quote_is_absent_below_seventeen_remainders(self):
        self.assertIsNone(check.write_quote("No write span here.\n"))
        self.assertIsNone(check.write_quote(self._ask_block(count=16)))
        self.assertEqual(check.write_quote(self._ask_block(count=17)), WRITE_QUOTE)

    def test_read_quote_is_absent_below_eighteen_remainders(self):
        self.assertIsNone(check.read_quote("No read span here.\n"))
        self.assertIsNone(check.read_quote(self._ask_block(count=17)))
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
        short = (
            "// filler\n" * (WRITE_NUMBER - 1) + WRITE_QUOTE + "\n"
        ).encode("utf-8")
        got, reads = self._pinned_reads(
            self._ask_block(),
            {ASK_REL: short},
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

    def test_kind_quotes_are_absent_below_their_index(self):
        cases = (
            (8, (None, None, None)),
            (9, (KIND_READ_QUOTE, None, None)),
            (11, (KIND_READ_QUOTE, KIND_EDIT_QUOTE, None)),
            (12, (KIND_READ_QUOTE, KIND_EDIT_QUOTE, KIND_RESTORE_QUOTE)),
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
            self._kind_block(),
            {KIND_REL: self._kind_source(kind_count=8)},
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
            self._kind_block(),
            {KIND_REL: self._kind_source(kind_count=9)},
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
            self._kind_block(),
            {KIND_REL: self._kind_source(kind_count=11)},
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
