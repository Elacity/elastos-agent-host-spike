# RA-3 The `run` launcher takes its storage directory from the selected Home

Rank 3 of 7. Effort S (1 point). Checks named: A9 (1). Score 1.00.

Sources: `lab/owned-storage/PROPOSED-LAUNCHER-CHANGE.md` in #290, and
AC-006-STORAGE in `lab/agent-conformance/GAPS.md`. Both name the same three
lines.

## The ask

`elastos run` builds its Runtime with a storage directory under the selected
Home's data directory. It stops using the fixed path `/tmp/elastos/storage`.

#290 calls this a per-instance storage root. The evidence shows a per-Home
root: the directory follows the Home, and every client of one Home shares it.
One client per Home gives one directory per client (see Risks).

## Checks it unblocks

| Check | Acceptance row that names it | Where | What else the row needs |
| --- | --- | --- | --- |
| A9 | `real_runtime_each_instance_has_its_own_storage_root`, BLOCKED AC-006-STORAGE | #290 `src/launch.rs` | A live run of a component client. The lab holds one state for both rows, so it needs a split first (see Acceptance test). |
| A9 | `real_runtime_agent_a_read_of_b_is_refused`, BLOCKED AC-006-STORAGE | #290 `src/launch.rs` | This ask is not enough. See "Open item". |

agent-conformance also keeps `operator_storage_is_under_throwaway_home`,
blocked: AC-006-STORAGE. Its table row has no A label. `GAPS.md` records
AC-006-STORAGE as an open exception for the client-storage half of the lab
halves of A3, A6 and A9, and for the A12 census (`/tmp/elastos/storage` is the
known leftover). Those are exceptions beside passing journeys, so the count
above includes A9 only.

## Today: evidence

| Citation | Text on that line | What it shows |
| --- | --- | --- |
| `elastos/crates/elastos-server/src/run_cmd.rs:62` | `crate::create_runtime("/tmp/elastos/storage")` | Site 1: the `Data` capsule arm. |
| `elastos/crates/elastos-server/src/run_cmd.rs:70` | `crate::create_runtime("/tmp/elastos/storage")` | Site 2: the fallback arm. |
| `elastos/crates/elastos-server/src/run_cmd.rs:225` | `async fn run_component_via_operator_runtime(` | The component path. |
| `elastos/crates/elastos-server/src/run_cmd.rs:236` | `crate::create_runtime("/tmp/elastos/storage")` | Site 3: the component path. |
| `elastos/crates/elastos-server/src/main.rs:2297` | `pub(crate) async fn create_runtime(` | The constructor is crate-private. A lab cannot call it. |
| `elastos/crates/elastos-server/src/main.rs:123` | `#[arg(long, default_value = "/tmp/elastos/storage")]` | `serve` has the same default, but it is a flag. |
| `elastos/crates/elastos-server/src/serve_cmd.rs:47` | `let runtime = crate::create_runtime(&storage_path).await?;` | `serve` passes its flag through. |
| `elastos/crates/elastos-server/src/capsule_cmd.rs:149` | `crate::create_runtime(default_data_dir().join("storage"))` | `elastos capsule` already uses the proposed expression. |
| `elastos/crates/elastos-server/src/runtime.rs:42` | `// Keep the storage provider alive for runtime/lifecycle ownership even` | The Runtime keeps the provider and does not serve reads from it. |
| `elastos/crates/elastos-server/src/runtime.rs:44` | `_storage: Arc<dyn StorageProvider>,` | The field name starts with an underscore. |
| `elastos/crates/elastos-server/src/sources.rs:12` | `Default data directory:` | The doc comment states the Linux rule. |
| `elastos/crates/elastos-server/src/sources.rs:14` | `dirs::data_dir()` | The function delegates to the platform rule. |
| `lab/agent-conformance/GAPS.md:34` | `delegates to` | The lab's reading of that function. |
| `lab/agent-conformance/GAPS.md:37` | `does not move it` | On the Mac, `XDG_DATA_HOME` does not move the data directory. `HOME` does. |
| `lab/agent-conformance/GAPS.md:58` | `AC-006-STORAGE` | The blocker record for the component launcher. |
| `lab/agent-conformance/GAPS.md:71` | `Anders makes the existing component launcher derive storage from the selected` | The lab's wording of the Runtime change. |
| `lab/agent-conformance/GAPS.md:819` | `AC-006-STORAGE above covers both clients' shared` | The process-isolation journey keeps this half BLOCKED. |
| `lab/agent-conformance/tests/effects.rs:129` | `#[ignore = "blocked: AC-006-STORAGE"]` | The agent-conformance row is ignored with the blocker ID. |
| `lab/agent-conformance/tests/effects.rs:131` | `panic!("blocked: AC-006-STORAGE` | Its body is a panic. No journey is written. |
| `#290 lab/owned-storage/PROPOSED-LAUNCHER-CHANGE.md:13` | `create_runtime("/tmp/elastos/storage")` | The literal as #290 quotes it. |
| `#290 lab/owned-storage/PROPOSED-LAUNCHER-CHANGE.md:45` | `already avoids the shared literal` | #290 notes that `elastos capsule` is the model. |
| `#290 lab/owned-storage/PROPOSED-LAUNCHER-CHANGE.md:70` | `On Linux that directory` | The proposal's example uses the Linux rule (`XDG_DATA_HOME`). |
| `#290 lab/owned-storage/PROPOSED-LAUNCHER-CHANGE.md:76` | `That edit stops` | The edit stops `elastos run` from creating `/tmp/elastos/storage`. |
| `#290 lab/owned-storage/PROPOSED-LAUNCHER-CHANGE.md:77` | `not by itself make agent A's read of B's file return a reason` | The proposal says it is not enough for the read refusal. |
| `#290 lab/owned-storage/PROPOSED-LAUNCHER-CHANGE.md:84` | `process has its own` | The later proof runs two processes with separate data directories. |
| `#290 lab/owned-storage/src/launch.rs:54` | `id: "real_runtime_each_instance_has_its_own_storage_root",` | Row 1. |
| `#290 lab/owned-storage/src/launch.rs:58` | `id: "real_runtime_agent_a_read_of_b_is_refused",` | Row 2. |
| `#290 lab/owned-storage/src/launch.rs:59` | `agent file reads do not use that storage provider` | Row 2's reason in the lab's own words. |
| `#290 lab/owned-storage/src/launch.rs:40` | `pub state: RowState,` | The journey holds one state for both rows. |
| `#290 lab/owned-storage/src/launch.rs:48` | `fn real_runtime_row_state() -> RowState {` | The state is a function that returns BLOCKED today. |
| `#290 lab/owned-storage/src/launch.rs:144` | `fn real_runtime_rows_match_the_launcher() {` | The test that guards both rows. |
| `#290 lab/owned-storage/src/launch.rs:178` | `rows stay blocked after elastos run stopped using` | The failure text when the literals disappear. |
| `#290 lab/owned-storage/src/launch.rs:180` | `assert_eq!(count, 3, "run_cmd.rs constructor count changed");` | While BLOCKED, the test requires exactly three literals. |
| `#290 lab/owned-storage/src/launch.rs:217` | `.expect("ready without a runtime refusal reason");` | The Ready state needs a refusal captured from a real run. |
| `#290 lab/owned-storage/README.md:3` | `Lab stand-in for M1 check A9.` | #290 names A9 as the check. |

## Smallest change

In `run_cmd.rs`, replace the three calls (`:62`, `:70`, `:236`) with

```rust
let runtime = crate::create_runtime(crate::default_data_dir().join("storage")).await?;
```

This is the expression `capsule_cmd.rs:149` already uses. One file, three
lines, no new flag.

## How it fits the capability and grant model

The change moves a directory. It adds no grant, no route and no new authority.
Grants, manifest bounds and principal checks run in the bridge, and the bridge
does not read this directory (`runtime.rs:42-44`; `PROPOSED-LAUNCHER-CHANGE.md`
lines 38 to 43 say object reads use the Home data directory). The change
removes a shared path outside any Home (Principle 3, no ambient authority) and
makes `run` follow the same rule as `capsule` (Principle 10, one canonical
path).

## Risks

- **Per-Home, not per-instance.** Two `run` clients of one Home now share
  `<data dir>/storage`. They shared `/tmp/elastos/storage` before. The two
  labs reach separate directories by giving each client its own Home. agent-
  conformance already does this for its two-instance journeys.
- **The proposal's example uses the Linux rule.** It says each process can have
  its own `XDG_DATA_HOME` (`PROPOSED-LAUNCHER-CHANGE.md:70`, `:84`). The M1 lab
  runs on the Mac, where `HOME` moves the data directory and `XDG_DATA_HOME`
  does not (`GAPS.md:37`). Use `HOME` in the Mac proof.
- **No effect on object reads, by the proposal's own reading.** The storage
  provider stays unused for reads (`runtime.rs:44`), and the proposal says
  object reads use the Home data directory. The edit then leaves bridge reads
  as they are. No run measured this.
- **Directory creation.** The constructor creates the directory when it opens
  the provider (`GAPS.md` cites `elastos-storage/src/providers/local.rs:18-20`).
  Its permissions under a Home were not checked.
- **Review class.** `run_cmd.rs` is a launcher. `AGENTS.md` lists provider
  launchers as code that needs the adversarial review. Anders decides whether
  a CLI launcher counts.

## Open item: A9's read-refusal row has no ask yet

`PROPOSED-LAUNCHER-CHANGE.md:76-77` says the edit does not by itself make A's
read of B's file return a reason. Row 2's own reason says agent file reads do
not use this storage provider (`launch.rs:59`). So RA-3 can move row 1 and
leaves row 2 BLOCKED.

#290 names no Runtime change that makes "A reads B's file" a Runtime refusal
inside one Home. The closest named item is the "UsersAI binding" blocker in
`GAPS.md:619-627`: bind the launch to a verified agent principal and enforce
that principal on every access to an agent's object. RA-5 covers the alias half
of that item. This proposal does not claim it also closes row 2.

## Acceptance test already written

- **`real_runtime_rows_match_the_launcher`** in #290. Class: TRIPWIRE. While
  BLOCKED it requires three literals (`launch.rs:180`). After this ask it fails
  with "rows stay blocked after elastos run stopped using ..." (`:178`). The
  Ready branch needs a refusal captured from a real component run (`:217`),
  and the lab keeps one state for both rows (`:40`). No such run exists. The
  falsifier `plants/F-A9-fake-runtime.txt` marks the rows Ready with no refusal
  and the test fails. So this ask turns the test red. It turns no row green.
  To use row 1 on its own, the lab splits the state per row first.
- **`operator_storage_is_under_throwaway_home`** in agent-conformance. Class:
  PLACEHOLDER. The body is a panic (`effects.rs:131`). A journey that checks
  the client's storage path under the throwaway Home must be written first.
- The passing lab tests (`agent_a_is_denied_b_directly` and the others) check a
  lab store. They are not Runtime evidence.

## Not shown

- No component was started. `elastos` was not on the author's `PATH`, so #290
  ran no live row.
- Whether any Runtime refusal of A's read of B's file exists inside one Home was
  not measured in these PRs.
