# Journal format 2: typed records (design note, no code)

Written 21 Oct 2026. **Design only.** The code comes in its own draft PR, branched after PR #24 merges. OMP idea 2
(child limits) is built on it afterwards. This note changes USERSAI-JOURNAL.md ("format 1") when it is built.

## Decided (Sasha, 21 Oct)

- **Format 2, one path.** The guest writes and reads only format 2. A format 1 journal is refused with a clear reason:
  `journal format 1 not supported; start a new task`. There is no migration code.
- **Every record has a typed kind** (message, spill, todo, goal, refused, budget, ...). A kind is never parsed from
  text, so a person's message can never read as a record.
- **Falsifier required:** a message that starts with each label stays a message.
- One refusal record per refusal (as in PR #24). Budgets bound the volume.

## Why: format 1 reads kinds out of text

In format 1 a node is `role | source | text`. Records the person or the model can see are Person nodes whose text
starts with a label line, the same source as a person's own message (`admit_user`). At PR #24's head
(`examples/agent-host/src/lib.rs`):
- `record_visible` writes `todo`, `plan-entered`, `plan-exit-asked`, `goal` and `spill` as `"<label>\n<text>"`.
- `apply_inbox` writes `"inbox\n<answer>"`, and `record_refusal` writes `"refused\n<reason>\n<what>"`.
- `is_durable_visible` picks the first five and `inbox` by that label. Compaction keeps those nodes and leaves them out
  of the summary input.
- `text_at_spill` reads a `spill` node's resource and version out of its text.
- `is_refusal_record` matches `refused\n`.

So a person who types `goal\nship it` gets a node that compaction keeps as a goal, and one who types
`spill\n<resource>\n<version>` gets something read back as a spill pointer. Nothing here grants: it misfiles the
record and weakens the log as an audit trail.

Observation rows (PR #24) use a separate source, so a message cannot be mistaken for one. Their typed fields
(version, hash, revision, window, cut) still live in a text head, though, and format 2 makes them typed too.

## Format 2 bytes

Integers are little-endian, strings are `u32` length plus UTF-8, and a bool is exactly 0 or 1 (as in format 1).

```text
header   magic "EAHJ" | format u16 = 2 | epoch u64 | compaction_open u8 | backup u8 | backup_epoch u64
         | pending u8 | cancelled_from (u8 flag + u64 step id) | task_budget (u8 flag + requests u32 + seconds u64)
         | depth u8 | prev_head [32] | record_count u32
records  tag u8 | len u32 | payload | link [32]       (same chain, same tag order 1..6 as format 1)
trailer  head [32]
```

- `cancelled_from`, `task_budget` and `depth` are the room for OMP idea 2. Until idea 2 is built, they are written as
  "none", 0, and decode refuses any other value. Each field then gets its rule in idea 2's PR.
- `task_budget` is the budget the Runtime granted to this task, recorded as data. The guest never sets it.

**Node payload:** `role u8 | kind u8 | fields`. The kind replaces format 1's `source`, and every kind fixes its role.
Decode refuses any other pairing.

| kind | tag | role | fields | model-visible text (rendered, never parsed) |
| --- | --- | --- | --- | --- |
| head | 1 | system | text | text |
| history | 2 | assistant or tool result | text | text |
| message | 3 | user | text | text |
| snapshot | 4 | user | text | text |
| skill | 5 | system | text | text |
| turn marker | 6 | user | (none) | not visible |
| step marker | 7 | user | step id u64 | not visible |
| compaction checkpoint | 8 | user | text | text |
| observation | 9 | user | resource, version u64, text_hash [32], revision (flag + string), window (flag + first u64 + count u64), cut u8, text | not visible |
| todo | 10 | user | text | `todo: <text>` |
| plan entered | 11 | user | text | `plan entered: <text>` |
| plan exit asked | 12 | user | text | `plan exit asked: <text>` |
| goal | 13 | user | text | `goal: <text>` |
| spill | 14 | user | resource, version u64 | `spill: <resource> version <n>` |
| inbox answer | 15 | user | answer u8 (allow once, allow for session, standing, deny) | `inbox: <answer>` |
| refused | 16 | user | reason, what | `refused: <reason> (<what>)` |
| child budget | 17 | user | child step id u64, requests u32, seconds u64 | (idea 2) |
| child stop | 18 | user | child step id u64, reason u8 (requests, time, cancelled), requests_used u32 | (idea 2) |

- Kinds 17 and 18 are reserved here and refused by decode until idea 2's PR adds them.
- **Rendering is one way.** `derive` turns a record into model text. No function turns text back into a kind: every
  reader matches on the kind byte (`is_durable_visible`, `text_at_spill`, the refusal count, compaction, the observation
  readers).
- `model_bytes` and `replay` (the cache bytes) also carry the kind, so the round trip stays exact.

**Step payload:** format 1's fields, then `depth u8 | budget (u8 flag + requests u32 + seconds u64) |
requests_used u32 | stop u8`.
- This is the room for idea 2.
- Until idea 2 is built, they are written as 0 / none / 0 / none, and decode refuses any other value.
- No existing field changes meaning.

**Turn payload:** unchanged.

## Decode refusals (new or changed)

| Input | Error |
| --- | --- |
| format 1 | `journal format 1 not supported; start a new task` |
| a format other than 1 or 2 | `format version` |
| an unknown kind tag, or a kind with the wrong role | `record` |
| an observation whose text does not match its hash, a window whose text does not have `count` whole lines, a cut without a window, or a window without a revision | `record` |
| an inbox answer or stop reason tag that is not known | `record` |
| an idea-2 field that is not "none" or 0 before idea 2 is built | `record` |

The old refusals (size, truncation, magic, chain, order, bools, UTF-8, trailing bytes) stay as they are.

**Resume.** `resume_journal` decodes the stored object.
- A format 1 object gives the reason above, and the task stays unknown for a person, as for any journal that does
  not decode.
- No new append is sent, and the person starts a new task.

## Tests and falsifiers (for the code PR)

| Test | Falsifier |
| --- | --- |
| `a_message_starting_with_each_label_stays_a_message`: for every label (`todo`, `plan-entered`, `plan-exit-asked`, `goal`, `spill`, `inbox`, `refused`, and the rendered forms like `goal: `), a person's message is kind message after admit, after round trip, after compaction (summarized, not kept) and for `text_at_spill` (no pointer) | read the kind from a text prefix again |
| `every_kind_round_trips` (each kind with its fields) | drop one field on encode |
| `a_format_1_journal_is_refused_with_its_reason` | accept format 1 |
| `an_unknown_kind_is_refused` and `a_kind_with_the_wrong_role_is_refused` | map unknown to message; skip the pair check |
| `an_observation_with_a_wrong_hash_or_window_is_refused` | trust the fields |
| `idea_2_fields_must_be_empty_until_built` | accept a value |
| `every_flipped_byte_is_refused`, `every_truncation_is_refused`, `the_cap_holds_at_the_last_byte`, `a_relinked_but_malformed_journal_is_refused` (re-run for format 2) | as today |
| the S3 end-to-end test writes and reads format 2 through the real bridge | write format 1 |

## What changes, and what does not

- **Changes:**
  - the guest's encoder and decoder;
  - every record writer and reader listed above;
  - the observation readers from PR #24 (typed fields in place of the text head);
  - USERSAI-JOURNAL.md;
  - the S3 tests that check format bytes.
- **The guest hash changes. The import list does not.**
- **Does not change:** the object path, the compare-and-swap with `create_only` / `if_revision`, the 192 KiB cap, the
  grant rule (no grant string is ever stored), or the bridge.

## Not decided

- The exact rendered text for each record kind in the model view. The table above is a proposal. It must stay stable,
  because it is in the cached prefix.
