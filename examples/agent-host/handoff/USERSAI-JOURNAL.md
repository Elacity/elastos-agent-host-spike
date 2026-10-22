# UsersAI journal: object contract, format 2

**Format 2 since 22 Oct 2026** (the code PR for the design in `JOURNAL-FORMAT-2.md`, PR #25). Every node has a typed
kind, and a format 1 journal is refused with `journal format 1 not supported; start a new task`. The format 2 bytes,
kinds, rendering table and refusals are in "Format 2" below. The rest of this note is the S2 and S3 contract; where it
says format 1, format 2 keeps the same rule unless "Format 2" says otherwise.

Written 20 Oct 2026 for slice S2 (overnight 1). `docs/AGENT_ARCHITECTURE.md` lines 332-343 say agent state lives under the agent principal's `UsersAI/...` space, and that the path layout needs its own versioned object contract before anything depends on it. This is that contract for one object: the Agent Host task journal. S2 builds only the bytes, in the guest, with no I/O. S3 stores them.

## What exists today (checked in the code, 20 Oct)

- `UsersAI` is a file-backed, owner-only root (`elastos/crates/elastos-common/src/localhost.rs:9-30`, `:118`). Nothing maps a principal to a `UsersAI/<id>` root yet, and no code refuses another principal's `UsersAI` tree. The only principal mapping is for humans: `principal_localhost_root` gives `localhost://Users/<hex(sha256(principal)[..12])>` (`elastos/crates/elastos-server/src/auth.rs:7036-7039`).
- Two version styles exist:
  - The Assistant workspace v2 keeps a `u64 revision` and refuses a write whose `if_revision` is not the current one, under one process-wide lock, with an 8 MiB cap (`elastos/crates/elastos-server/src/api/gateway_assistant_workspace_v2.rs:8-42`, conflict code `assistant_workspace_revision_conflict`).
  - Principal-root objects have a content revision, `"hex(sha256(principal \0 uri \0 plaintext))"`, and an atomic `write_principal_root_object_if_revision` with the preconditions `Absent` or `Revision(..)` (`auth.rs:5602-5654`). Today it accepts only `Users/` roots.
- Library objects carry `revision = "rev:" + sha256(bytes)` (`library.rs:3413`).
- A Runtime resource frame is at most 1 MiB (`MAX_RESOURCE_FRAME_BYTES`, `resource_bridge.rs:32`).

## The contract

**Resource (changed after the PR #3 review, 20 Oct).** For the spike, `localhost://Users/self/.AppData/Agents/<agent-id>/tasks/<task-id>/journal`, under the launching person, whom the bridge already scopes. It moves to the original choice below once the Runtime scopes `UsersAI` like `Users/self`.

Original choice: `localhost://UsersAI/self/.AppData/ElastOS/AgentHost/tasks/<task-id>/journal`
- The guest only ever names `UsersAI/self`. The Runtime rewrites `self` to the active agent principal's root, the same way it rewrites `Users/self` today (`resource_bridge.rs` `scope_current_user_alias`). Any other `UsersAI/<root>` from the guest is refused. That rule is S3 work.
- `<task-id>` is the durable task id from `docs/AGENT_ARCHITECTURE.md` (session and interaction contract): ASCII letters, digits, `-`, at most 64 bytes.
- The relative path mirrors workspace v2 (`.AppData/ElastOS/Assistant/workspace-v2.json`).

**Object versions and append.**
- The journal is one object. Each append writes the whole new encoding as a compare-and-swap on the previous version:
  - The first write uses precondition `Absent`.
  - Every later write uses precondition `Revision(<revision of the version it read>)`.
  - That is the content revision of `auth.rs:5618-5630`, computed by the Runtime, not the guest.
- A stale version is refused and nothing is written. The guest must read again, so there is no blind retry.
- Each encoding also carries `prev_head`: the head hash (below) of the version it replaces, or 32 zero bytes for the first version. So a stored version names its parent even without the store's revision.

**Format 1 bytes** (all integers little-endian):

```text
header   magic "EAHJ" (4) | format u16 = 1 | epoch u64 | compaction_open u8 (0/1)
         | backup u8 (0/1) | backup_epoch u64 | pending u8 (0/1) | prev_head [32] | record_count u32
records  record_count times: tag u8 | len u32 | payload [len] | link [32]
trailer  head [32]
```

- `link_0 = sha256(header)`. For each record, `link_i = sha256(link_(i-1) | tag | len | payload)`, and the record stores `link_i`. Every record is hash-linked to the one before it. The trailer `head` equals the last link (or `link_0` with no records).
- A change to any byte breaks either the format check or the chain.
- **The chain detects corruption, not tampering.** It is plain SHA-256 with no key, so anyone who can write the object can recompute every link. Protection against a hostile writer comes from the Runtime: the object sits in the agent principal's owner-only root, and only the Runtime writes it, by compare-and-swap. For bytes that are re-linked but malformed, decode also refuses non-canonical input on its own: tags out of order, a bool that is not 0 or 1, an absent option with a non-zero value, or a backup or pending record without its flag.
- Record tags must come in this order, never decreasing:
  - 1 model event
  - 2 marker
  - 3 step
  - 4 turn
  - 5 compaction backup node (only when `backup = 1`)
  - 6 compaction pending node (only when `pending = 1`)
- One journal has exactly one encoding.
- Payloads:
  - node: role u8 | source u8 | text. The role and source tags are the ones `model_bytes` uses.
  - step: id u64 | state u8 | kind u8 | resource | effect_id u64 | has_result u8 | old | new | argv (u32 count + strings) | parent_id (u8 flag + u64) | seat | seen_version (u8 flag + u64) | inbox.
    Kind tags: 1 unspecified, 2 read, 3 edit, 4 run, 5 restore, 6 hosted, 7 child, 8 init, 9 journal append (added in S3). State tags: 1 prepared, 2 not started, 3 denied, 4 cancelled, 5 dispatched, 6 settlement unknown.
  - turn: id u64 | step ids (u32 count + u64 each).
  - A string is u32 length plus UTF-8 bytes. A bool is exactly 0 or 1.
- **Size cap: 192 KiB of encoded bytes** (lowered from 256 KiB on 20 Oct, after review). The Runtime bridge carries the bytes as a JSON number array (`request_content_bytes`, `resource_bridge.rs`), so each byte costs up to four characters (`255,`). The worst case at the cap, all `0xFF`, is about 768 KiB: inside the 1 MiB `MAX_RESOURCE_FRAME_BYTES`, with room for the envelope and token. 256 KiB of `0xFF` would be about 1 MiB, and the frame is refused. `a_worst_case_journal_at_the_cap_fits_through_the_bridge` writes both through the bridge. `encode` refuses a bigger journal, and `decode` refuses bigger input. Compaction is what keeps a long task under the cap.

**What is stored, and what is model-visible.**
- **Model-visible:** only `derive(events)`. That excludes markers, observations, and an empty assistant line.
- **Stored but never model-visible:** steps, turns, markers, observations, and the compaction backup and pending copies.
- **Never stored: grant strings.** The format has no field for them.
  - `docs/AGENT_ARCHITECTURE.md:336` says the Runtime owns sessions, grants and revocation. PRINCIPLES 16 says bearer tokens are not exposed. The spike has kept "the grant string is not in the log" since 13 Oct.
  - After a decode, every step has `grant: None`. A Prepared step must be granted again by the Runtime before it can dispatch (fail closed). A Dispatched step stays Dispatched, and a crash note makes it `settlement_unknown`, as today.
  - So `decode(encode(j)) == j` exactly when no step holds a grant. When a step holds one, the result equals `j` with every grant cleared.
- **Empty assistant text is kept.** We keep an empty assistant line in the journal and in `model_bytes`; `derive` drops it from the model view. DeepSeek (687f282e, `packages/llm/llm-deepseek/src/serialize.ts:30, :123`) now drops it while serializing the request instead. We keep it because the journal is the durable record: `model_bytes` and `replay` must stay exact inverses of the log (SLICES review corrections). The model still never sees it, because the view drops it. Our record and our view are separate layers, so a later serializer change cannot change stored bytes.

## Refusals (decode returns an error, and nothing is half-read)

| Input | Error |
| --- | --- |
| more than 192 KiB | `too large` |
| shorter than a header, or a record or trailer cut short | `truncated` |
| magic is not `EAHJ` | `not a journal` |
| format is not 2 (format 1 has its own reason, see Format 2) | `format version` |
| a link or the trailer head does not match the chain | `hash` |
| a tag out of order, unknown, or a backup or pending record without its flag | `record` |
| a bad enum tag, a bool that is not 0 or 1, bad UTF-8, or a length past the payload | `record` |
| bytes after the trailer | `trailing bytes` |

## Tests (S2, guest only)

- `a_journal_round_trips_through_format_one`: a journal with turns, steps of several kinds, markers, observations, a snapshot, a skill, an empty assistant line, and an open compaction decodes to the same journal.
- `decoding_keeps_the_replay_bytes`: `model_bytes` and `derive` of the decoded events equal the original.
- `every_flipped_byte_is_refused`: flipping any single bit of the encoding is refused.
- `a_wrong_format_version_is_refused`
- `every_truncation_is_refused`: every shorter prefix is refused.
- `node_zero_and_the_epoch_survive_a_round_trip`: before and after compaction (epoch 1, then 2).
- `a_grant_is_never_stored`: the grant string is not in the bytes, a decoded step has no grant, and a decoded Prepared step is Denied at dispatch.
- `a_journal_over_the_cap_is_refused`: both encode and decode.
- `the_cap_holds_at_the_last_byte`: exactly 192 KiB encodes and decodes; one byte more is refused.
- `a_relinked_but_malformed_journal_is_refused`: records out of order, a bad bool, a non-canonical option, an unflagged backup or pending record, and an unknown tag are refused even with every link recomputed.
- `the_previous_head_links_two_versions`: version 2's `prev_head` is version 1's head.

## Format 2 (22 Oct)

**Why.** In format 1, records the person and the model can see (todo, plan, goal, spill pointer, inbox answer, refusal)
were message nodes whose text started with a label line, and readers picked them out by that label. So a person who
typed `goal\nship it` got a node that compaction kept as a goal, and `spill\n<resource>\n<version>` read back as a
spill pointer. Format 2 gives every node a typed kind; no reader looks at text to decide a kind.

**Decided (Sasha, 21 Oct).** One path: the guest writes and reads only format 2. A format 1 journal is refused with
`journal format 1 not supported; start a new task`; nothing migrates it, and the old object is never touched.

**Bytes** (integers little-endian, strings u32 length plus UTF-8, a bool exactly 0 or 1):

```text
header   magic "EAHJ" | format u16 = 2 | epoch u64 | compaction_open u8 | backup u8 | backup_epoch u64
         | pending u8 | cancelled_from (u8 flag + u64 step id) | task_budget (u8 flag + requests u32 + seconds u64)
         | depth u8 | prev_head [32] | record_count u32                                    (84 bytes)
records  tag u8 | len u32 | payload | link [32]       (same chain and the same tag order 1..6 as format 1)
trailer  head [32]
```

- `cancelled_from`, `task_budget` and `depth` are OMP idea 2's (since 22 Oct, OMP2-DESIGN.md). `cancelled_from` is
  the last step id when the task was cancelled; `task_budget` is the budget the Runtime granted, recorded as data;
  `depth` is a child host journal's depth (0 for a top task). Zero still means none, no budget, depth 0.
- **Step payload:** format 1's fields, then `depth u8 | budget (u8 flag + requests u32 + seconds u64) | requests_used u32
  | stop u8`. The depth byte is always 0 (depth is derived from the `parent_id` chain). The budget is a Child step's;
  `requests_used` counts the model calls in its subtree; stop is 0 none, 1 requests, 2 time, 3 cancelled. Steps that
  are not Child steps keep all of them zero. A budget flag of 0 with non-zero values is `record`. No existing field
  changes meaning: a journal written before idea 2 decodes and re-encodes to the same bytes.
- **Turn payload:** unchanged.
- **Node payload:** `role u8 | kind u8 | fields`. Each kind fixes its role; any other pairing is `record`, and the
  encoder gives nothing. Kinds without free text keep the node's text empty (the encoder refuses otherwise).

| kind | tag | role | fields | model-visible text (`render_record`) |
| --- | --- | --- | --- | --- |
| head | 1 | system | text | text |
| history | 2 | assistant or tool result | text | text |
| message | 3 | user | text | text |
| snapshot | 4 | user | text | text |
| skill | 5 | user | text | text |
| turn marker | 6 | user | none | not visible |
| step marker | 7 | user | step id u64 | not visible |
| compaction checkpoint | 8 | user | text | text |
| observation | 9 | user | resource, version u64, text hash [32], revision (u8 flag + string, empty when absent), window (u8 flag + first u64 + count u64, zeros when absent), cut u8, text | not visible |
| todo | 10 | user | text | `todo: <text>` |
| plan entered | 11 | user | text | `plan entered: <text>` |
| plan exit asked | 12 | user | text | `plan exit asked: <text>` |
| goal | 13 | user | text | `goal: <text>` |
| spill | 14 | user | resource, version u64 | `spill: <resource> version <n>` |
| inbox answer | 15 | user | answer u8 (1 allow-once, 2 allow-session, 3 standing, 4 deny) | `inbox: <answer name>` |
| refused | 16 | user | reason, what | `refused: <reason> (<what>)` |
| child budget | 17 | user | child step id u64, requests u32, seconds u64 | `child <id> budget: <requests> requests, <seconds> s` |
| child stop | 18 | user | child step id u64, reason u8 (1 requests, 2 time, 3 cancelled), requests_used u32 | `child <id> stopped: <reason> (<used> requests used)` |
| system line | 19 | system | text | text |

- **Child records (17, 18), OMP idea 2.** Written only by the host: one child-budget record when a child is made, and
  one child-stop record when it first stops. Their rendering has its own pin (`IDEA_2_RENDERING_PIN`), so the 17
  earlier kinds and `RENDERING_PIN` are unchanged. Compaction keeps them, like the other visible records.
- **System line (19).** A later system line (`admit_system(.., in_history = true)`) is its own kind, written only by the
  host (Sasha, 22 Oct). No person's, model's or tool's text becomes it, and history no longer allows the system role.
- An observation's fields must fit its text: the hash, a revision that is one token, a cut only with a window, a window
  only with a revision, a window from line 1 or later with exactly `count` whole lines. A read at version `u64::MAX`
  decodes but is not a read (that is never a version number).

**The rendering table is frozen for format 2.** `render_record` is the one place that builds model text for a record.
The model view (`derive`), `visible_bytes`, the summary input and the cache bytes use it. No function turns the text
back into a kind. The texts above have no trailing newline.
- Golden bytes for one example of every kind are pinned in `each_kind_renders_byte_for_byte`.
- `the_rendering_changes_only_with_the_format_number` hashes the rendered golden table and pins the hash next to the
  format number (`RENDERING_FORMAT` must equal `JOURNAL_FORMAT`).
- So changing a rendering needs a format bump. That refuses stored journals of the old format, which keeps the cached
  prefix of every live task stable.

**Cache bytes.** `model_bytes` writes, for each node, the rendered text (u32 length + bytes) and then the typed record
(u32 length + the node payload above). `replay` decodes the record and refuses bytes whose rendered text is not what the
record renders to, so the round trip stays exact.

**A format 1 task.**
- Every load decodes: resume gives `ResumeOutcome::FormatNotSupported("journal format 1 not supported; start a new
  task")` (not `Unknown`, so the task does not wait on a person), and reread gives the same text as its error.
- The guest's run, when its first append meets a stored format 1 journal (a conflict), rereads it and returns that text
  as its refusal (`BusError::Invalid`). No append is sent over it, and the old object is not touched.
- Home: whether Home shows a capsule's run refusal on the task is not checked in this PR (no Home change here).

**Paths (Sasha, 22 Oct).** `path_key` wherever it makes a limit stricter (the no-op count, the duplicate checks);
the exact canonical NFC path wherever it decides which file (reads, versions, seen ranges, spill pointers, the project,
grants). A spill pointer's resource follows the path rule on load, like a read's.

**Refusals added by format 2** (the table above still holds; format 1 now has its own reason):

| Input | Error |
| --- | --- |
| format 1 | `journal format 1 not supported; start a new task` |
| a format other than 1 or 2 | `format version` |
| an unknown kind (0, or 20 and above), or a kind with the wrong role | `record` |
| an observation whose fields do not fit its text, or an absent revision or window with a value | `record` |
| an unknown inbox answer | `record` |
| a non-zero step depth byte, an unknown stop reason, or a budget flag of 0 with values | `record` |
| a child past the depth limit (header or chain) | `depth limit` |
| a child resource not strictly under its parent's | `not a subset` |
| a child budget of zero, below its count, or larger than its owner's (or the task's) | `over the parent's budget` |
| a parent that is missing or later than its child; a parent on a step other than a child or a call under a child; a budget, count or stop on a step that is not a child; a count that is not the calls below it; a zero task budget or more calls than it; child records that do not match the steps one for one; a child below a stopped child that has not stopped; a cancelled task with a running child or a later child or call | `record` |

## Not in S2

No file, no Bus call, no import change. Computing the revision, the compare-and-swap, the `UsersAI/self` rewrite, and refusing another principal's root are S3.

## Guest side (S3, 20 Oct)

- **Writing.** `append_journal` records a `journal append` step, then writes the whole encoding with `write`. The body is `{"content": [bytes], "create_only": true}` for the first version, and `{"content": [bytes], "if_revision": "<revision>"}` after that. The revision comes from the Runtime's last reply; the guest never computes it. The stored copy shows the append step as dispatched with no result. The step's `old` field keeps the revision it replaces.
- **The grants.** The guest asks the Runtime, with `capabilities.request`, for exactly two grants on its own journal: write, then read (option B, chosen 20 Oct). Each is a `JournalGrant` held in memory and sent only as `invoke-request.grant`. `Debug` does not print it, the step drops it once dispatched, and the format has no field for it. The manifest declares only `localhost://Users/self/.AppData/Agents/agent-host/*`.
- **Outcomes.** An ok reply with a revision: written, and the cursor moves. `revision_conflict`: nothing written, no retry; the guest must read again. `denied` or `invalid` from the Bus: refused before storage. No grant, an append still open, or a journal over the cap: nothing sent. Anything else is unknown: the step is `settlement_unknown`.
- **Resume by head hash.** `resume_journal` reads the object with a read grant and decodes it. If the stored head is the head the guest sent, the append landed. If it is the parent head, it did not, and a new append may be proposed. The revision check means the old write and a new one cannot both land. Anything else, including bytes that do not decode, stays unknown for a person. No append is sent while one is unknown.
- **Words in `new`** when a journal append closes: `written`, `not written`, `conflict`, `refused`. None enter the model view.
- **Ids.** Agent and task ids match `^[a-z0-9][a-z0-9._-]*$` (1 to 64 bytes), the rule the bridge applies to every segment under Agents.
- **Not yet.** No end-to-end write through a real Runtime; that test comes after the `elastos-compute` error-mapping PR.
