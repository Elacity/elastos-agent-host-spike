# Agent file and the signed chain

A load of `agent-records.json` parses the file, runs the file rules, then
compares its sequence and the sha256 of the bytes it read with the newest
agent event in the verified audit chain. The chain is the one the sign-in
loader already verified. This module does not verify it again and does not
call back into that loader while the loader is the caller. `merge_into` and
`without_agent_roots` pass the chain they were given. `open` (list, launch,
stop, and every write) asks for the owner's principals through the existing
reader. That read leaves the verified chain for the one caller that asked,
then calls the same load. The agents module does not read the sign-in file.

The agent events are `agent.records.enable`, `agent.records.disable`,
`agent.record.create`, `agent.record.rename`, `agent.record.retire`,
`agent.record.active`, and `agent.records.anchor`. Each reason is
`seq=<n> sha256=<64 hex>`. The sha256 is the file bytes, not a second
encoding. No field is added to the agent file. An older build of this fork
reads the same JSON. It does not read the commit mark, and it stores an
`agent.records.anchor` event as an ordinary signed audit event.

The commit mark is this Runtime's signature over the file bytes
(`elastos.agent.file-commit.v1`), stored as the file attribute
`user.elastos.agent.file-commit` on the inode before the name is published.
The mark is how a file that reached disk before its audit event is
recognized. A file without that signature is not that write.

| Row | What load does |
| --- | --- |
| (a) File sequence below the newest agent event, or the same sequence with a different sha256 | Named refusal. Agents are unavailable. The file and the owner's sign-in file are left as they were. |
| (b) No file, and the verified chain has an agent event | Named refusal, `agent file is missing`. This is not "no agents". |
| (c) File sequence is exactly one above the newest agent event, or it is the first file (sequence 1) and the full chain has no agent event, and the commit mark verifies | Load accepts it. The next `open` takes the agent lock, appends `agent.records.anchor` for those bytes, then reads again. A file one ahead without the mark is refused, so another file cannot use that step. |
| (d) The newest agent event is no longer in the retained chain | A present file is refused: `agent file has no signed record in the retained chain`. See the open part below. |
| (e) No file and no agent event | No agents. The first successful write stores sequence 1 and one matching event. |
| (f) A restored copy of this Home | The copy carries the file and the chain together. Load applies the same rows. A file from an earlier sequence on a newer chain is row (a). |
| (g) Recovery import on the same Home | The import appends its own audit event and leaves the agent file in place. The newest agent event is unchanged, so a matching file still loads. |

## Open part (d)

`auth` retains the newest 512 audit events. The anchor it keeps for the
dropped prefix is a sequence and a chain hash. It does not carry an agent
event's sequence or file sha256. Nothing this module can append is exempt
from that retention, and this change does not edit `auth.rs`.

What holds: while the newest agent event is still one of those 512, load
requires the file's sequence and sha256 to match it (row (a) and row (c)).
The event remains through the next 511 audit events and leaves on the 512th
event appended after it. After that, a present file has no signed record in
the retained chain and agents are unavailable. A missing file with no agent
event left in the tail is "no agents", because the tail no longer shows that
an agent event existed.

A keep-alive appended from this module would move the same window forward
only when this module runs before those 512 events. It would not keep the
record when other audit writes fill the tail first. That is not a record
that survives. The open part stays open until the retained chain itself can
carry this anchor.

## Readers and cost

`merge_into`, `without_agent_roots`, `open` (launch, stop, and list), and
every write call `load` once for the decision. `load` takes no lock and
writes nothing. Recording row (c) is the following `open`: the agent lock,
then the sign-in lock inside the audit append. The sign-in load cannot
append, because it already holds its activation lock.

One load hashes the file it read and walks the retained tail for the newest
agent event. The measured cost is that load, including the verified-state
read the caller already does, on this machine. The number is in the report.

The verified-state cache lives in `auth.rs` and stores the sign-in state
before `merge_into`. It does not store the merged agent records. This change
does not add a cache and does not edit that one.
