# UsersAI journal: object contract, format 1

Written 20 Oct 2026 for slice S2 (overnight 1). `docs/AGENT_ARCHITECTURE.md` lines 332-343 say agent state lives under the agent principal's `UsersAI/...` space, and that the path layout needs its own versioned object contract before anything depends on it. This is that contract for one object: the Agent Host task journal. S2 builds only the bytes, in the guest, with no I/O. S3 stores them.

## What exists today (checked in the code, 20 Oct)

- `UsersAI` is a file-backed, owner-only root (`elastos/crates/elastos-common/src/localhost.rs:9-30`, `:118`). Nothing maps a principal to a `UsersAI/<id>` root yet, and no code refuses another principal's `UsersAI` tree. The only principal mapping is for humans: `principal_localhost_root` gives `localhost://Users/<hex(sha256(principal)[..12])>` (`elastos/crates/elastos-server/src/auth.rs:7036-7039`).
- Two version styles exist:
  - The Assistant workspace v2 keeps a `u64 revision` and refuses a write whose `if_revision` is not the current one, under one process-wide lock, with an 8 MiB cap (`elastos/crates/elastos-server/src/api/gateway_assistant_workspace_v2.rs:8-42`, conflict code `assistant_workspace_revision_conflict`).
  - Principal-root objects have a content revision, `"hex(sha256(principal \0 uri \0 plaintext))"`, and an atomic `write_principal_root_object_if_revision` with the preconditions `Absent` or `Revision(..)` (`auth.rs:5602-5654`). Today it accepts only `Users/` roots.
- Library objects carry `revision = "rev:" + sha256(bytes)` (`library.rs:3413`).
- A Runtime resource frame is at most 1 MiB (`MAX_RESOURCE_FRAME_BYTES`, `resource_bridge.rs:32`).

## The contract

**Resource.** `localhost://UsersAI/self/.AppData/ElastOS/AgentHost/tasks/<task-id>/journal`
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
  - turn: id u64 | step ids (u32 count + u64 each).
  - A string is u32 length plus UTF-8 bytes. A bool is exactly 0 or 1.
- **Size cap: 256 KiB of encoded bytes.** After base64 that is about 342 KiB, inside the 1 MiB Runtime frame with room for the envelope. `encode` refuses a bigger journal, and `decode` refuses bigger input. Compaction is what keeps a long task under the cap.

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
| more than 256 KiB | `too large` |
| shorter than a header, or a record or trailer cut short | `truncated` |
| magic is not `EAHJ` | `not a journal` |
| format is not 1 | `format version` |
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
- `the_cap_holds_at_the_last_byte`: exactly 256 KiB encodes and decodes; one byte more is refused.
- `a_relinked_but_malformed_journal_is_refused`: records out of order, a bad bool, a non-canonical option, an unflagged backup or pending record, and an unknown tag are refused even with every link recomputed.
- `the_previous_head_links_two_versions`: version 2's `prev_head` is version 1's head.

## Not in S2

No file, no Bus call, no import change. Computing the revision, the compare-and-swap, the `UsersAI/self` rewrite, and refusing another principal's root are S3.
