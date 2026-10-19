# Spike history, 12-14 Oct 2026

Copied from Sasha's task log on the Mac. One entry per proven step, oldest first. Paths under `/Users/sash/code/wt-agent-host/` mean the repo root. Ports like 61180 were a desktop test Home that no longer runs. Guest hashes are the proof at that moment; the current one is in HANDOFF.md.

- New Anders PRs (all open, non-draft): #348 Local AI 0.8.0 (touches `_shared/model-management.js`, `model-selection.js`; not our #116 files), #349 Browser on Linux x86 (touches setup.rs), #350 Home as a background service (#183), #351 cargo audit + patched crates (#311). #347 safe-removal helper. Draft #334 (Community profiles) updated.

## 12 Oct 2026, 17:30 — agent-host spike started (local only)
- Design: DeepSeek Harness is the coding-loop reference. Our Assistant is chat with no tools. A later Agent Host copies the journal and prefix rules and keeps Runtime as the only authority. WASM is the guest room; a running Home does not execute a WASM guest today. Grades and the phase plan are in the Cursor plan `deepseek_harness_audit` and the canvas `deepseek-vs-elastos-grades`.
- Branch: `spike/agent-host` at `/Users/sash/code/wt-agent-host`, cut from origin/develop `520e7e3a`. Upstream unset so a push cannot target develop. No PR.
- First slice: `examples/agent-host`. Three host tests pass. `./verify.sh` built `agent-host.component.wasm` (`d3a84b511a81138daf68061ac345c1b7f1bf5574565ccde1a95ae1a261297961`). Not committed yet.
- Not done: `elastos serve` from this branch. No release binary exists here. The guest does not appear in the Home window. `elastos run` is the operator proof, after a Runtime built from this worktree.

## 12 Oct 2026, 17:40 — spike paused, still local
- Wasmtime proof passed: `providers::component::tests::agent_host_example_runs_one_turn_in_wasmtime` via `examples/agent-host/run-local.sh`. It does not start `elastos serve` and does not open ~/Library/Application Support/elastos.
- Uncommitted on purpose: `examples/agent-host/` (untracked) and `elastos/crates/elastos-compute/src/providers/component.rs` (the ignored test). No local commit, no push, no PR. Upstream is unset.
- Resume: worktree `/Users/sash/code/wt-agent-host`, branch `spike/agent-host`, base `520e7e3a`. Phone work stays in `/Users/sash/code/wt-phone`. Setup-progress stays in `/Users/sash/code/wt-setup-progress`. Switching to Anders' PRs does not touch this worktree.
- Next local slice when we return: a second journal turn where an appended system line leaves the first line byte-for-byte the same. Still no Home icon, no model call, no GitHub.

## 12 Oct 2026, 17:55 — desktop Home is open; second journal turn proven locally
- Desktop Home is a source install from the 2 Oct phone-layout tree (`/Users/sash/code/elastos-runtime-071`), so it can be opened today. It is not the spike branch. Data dir: `/Users/sash/code/agent-host-desktop/Library/Application Support/elastos`. Gateway `http://localhost:61180/home/` returned HTTP 200 and was opened. The first visit asks for an admin passkey.
- Kubo did not download (`dist.ipfs.tech` reset the connection), so Library and Documents publish is absent. The Browser VM image is not installed, so Browser has no local machine yet. Assistant and the other web apps are installed.
- The September folder `~/Library/Application Support/elastos` was not the install target. An earlier empty launch wrote `config.toml` (`dev_mode = true`, no trusted keys) and lock files there, then stopped.
- Spike, still uncommitted: `examples/agent-host` now folds two turns. The first system line stays byte-for-byte the same when turn two appends a user line and a later system line. Four host tests pass. Wasmtime test `agent_host_example_runs_two_turns_in_wasmtime` passed. Guest hash `e58c5ac8f216681cd2743fa33f22b2bd68a8c1f7b65dc0fac7d415182a661e87`. No commit, no push, no PR. The guest is not a Home icon.

## 12 Oct 2026, 18:05 — journal series and compaction, still local
- `examples/agent-host` now keeps a cache epoch. Appending a second turn stays on series 1. Rewriting the system head with the same text does not start a series. A different head starts series 2.
- Compaction replaces the tail with one shorter summary and starts the next series. Node 0 stays byte-for-byte the same. A summary that does not shrink, or an empty summary, leaves the journal unchanged.
- Seven host tests pass. Wasmtime test `agent_host_example_keeps_the_head_across_a_compaction` passed. Guest hash `f3c0b946fbbf9d9896bd3ecb055d64fb59205faf076b73c586d4bb63441de750`. No commit, no push, no PR. No Home icon, no model call, no tool.

## 12 Oct 2026, 18:10 — crash settlement, still local
- A step recorded before dispatch, then crashed, stays `not started` and dispatch of that same step returns false.
- A step dispatched and then crashed becomes `settlement_unknown`. A second crash leaves that status. Dispatch does not run it again.
- The model-visible history and the series epoch stay unchanged. Ten host tests pass. The same Wasmtime test passed. Guest hash `54eea93a2c5cfc616a9f906b119cf0173dd99e2b137850b773a45badf786eb12`. No commit, no push, no PR.

## 12 Oct 2026, 18:15 — journal replay, still local
- The visible journal encodes to canonical bytes and reads back to the same bytes. A short or unknown record returns nothing. A head rewrite changes the bytes. A step record does not. Compaction changes the bytes and the replayed node 0 is still the original head.
- Thirteen host tests pass. Wasmtime test `agent_host_example_keeps_the_head_across_a_compaction` passed. Guest hash `413b99298b2d1efa4cd793208acd3b4e58a24923bb23df79e23e5251a61ff464`. No commit, no push, no PR.
- Plan todos now track the spike by slice. Next local slice is a read proposal recorded in the journal and not executed.

## 12 Oct 2026, 18:44 — read proposal denied, still local
- A read of `localhost://Users/self/Documents/note.txt` with no grant stays `denied`. Dispatch does not run it. Model bytes and the series stay unchanged. A second authorize stays `denied`.
- The crash-after-dispatch proof records the test token `fixture-grant` before dispatch. That token is not a Runtime grant. The guest does not call `providers.invoke`.
- Sixteen host tests pass. `./verify.sh` and `./run-local.sh` passed. Wasmtime test `agent_host_example_keeps_the_head_across_a_compaction` passed. Guest hash `d7dc89f02ace399c79eed633ecee956dc064f2516b3766326f9c5ebc564ba8a5`. No commit, no push, no PR.
- `Cancelled` is not in this slice. The wasm32 build warned when only a host test constructed it. B7 adds it together with `cancel()`.

## 12 Oct 2026, 20:33 — cancel before dispatch, still local
- `cancel` on a prepared step becomes `cancelled`. Dispatch of that step returns false. A second cancel returns false. A crash note does not rewrite it.
- `cancel` after dispatch returns false and leaves `dispatched`. After the crash word, cancel leaves `settlement_unknown`. It does not become a success.
- Cancel does not change model bytes or the series. Nineteen host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `fa54c2c57cb21e770a418e16931e1633e9466f7d1901bb376b446c6f3c193630`. No commit, no push, no PR.

## 12 Oct 2026, 20:44 — user snapshots, still local
- A snapshot appends the workspace, the time, and the open files as user nodes after the head. Node 0 and the series stay put. An empty workspace or an empty time leaves the journal unchanged. An empty open-file list adds no third node.
- The log bytes now store the node source, so replay restores a snapshot as a snapshot. The names used are `localhost://` resources, not host paths.
- Twenty-two host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `705e2b04587c884423e60c68c2b75cce5e5c2e1b6ba1e3509d1f63de56a570a1`. No commit, no push, no PR. The compaction summary is still a system node. The user checkpoint is a later slice.

## 12 Oct 2026, 20:49 — checkpoint before an effect, still local
- `checkpoint` copies the model bytes before a step. Cancel after that copy does not dispatch, and the bytes still match the copy. The series stays put.
- A crash after the copy, before dispatch, stays `not started`. A crash after dispatch stays `settlement_unknown`. Neither path invents a success, and neither changes the copied bytes.
- Twenty-four host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `3beeebc986ac302a215ed980bb483e025b3ec20cafa7b9ac621d3543e86cc9a5`. No commit, no push, no PR.

## 12 Oct 2026, 20:53 — skill budget, still local
- A skill of at most 4000 bytes appends as a user node. Empty text and 4001 bytes leave the journal unchanged. Node 0 and the series stay put.
- Compaction keeps the skill and does not count it toward the shrink. The summary is still a system node. Snapshots in that folded copy are replaced. The skill is not.
- Twenty-seven host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `34307f5b7e3427219cf8fbbe8f0bae64e69d97a56a2c5b0a085d6b9a632ee158`. No commit, no push, no PR. The local guest slices B1 through B10 are proved. The hold line waits until a present is requested.

## 12 Oct 2026, 20:57 — Bus-only imports, still local
- The Wasmtime load now checks the component's own import list. It is `elastos:bus/identity@1.0.0`, `elastos:bus/runtime@1.0.0`, and `elastos:bus/types@1.0.0`. `capabilities` and `providers` are not imported. The lifecycle export remains. `./run-local.sh` passed. Guest hash unchanged: `34307f5b7e3427219cf8fbbe8f0bae64e69d97a56a2c5b0a085d6b9a632ee158`.
- No gateway route and no `UsersAI` file were added. Those are Runtime authority and still wait for a present, then an adversarial review before any push. No commit, no push, no PR.

## 12 Oct 2026, 21:02 — principle check, still local
- The Assistant capsule smoke now requires the sentence "You have no tools and no capsule authority in this session". `node scripts/home-agent-shell-smoke.mjs` passed.
- No new gateway route. No `UsersAI` path. `fixture-grant` remains a journal record inside the example, not a Runtime grant. No commit, no push, no PR.

## 12 Oct 2026, 21:10 — no-grant read denied before the bridge, still local
- A component `invoke` with no grant, or an empty grant, returns `Denied` and does not call the bridge. A hostcall that would have returned success is never reached. Five component host tests pass, and the guest Wasmtime test stays ignored.
- The resource bridge already returns `missing_token` for a read whose envelope has no token, and that request does not reach the provider. That code stays `missing_token`. No new HTTP route was added.
- `UsersAI` is still not a file path. The architecture says that layout is not frozen. No commit, no push, no PR.

## 12 Oct 2026, 21:16 — a turn id, still local
- `open_turn` records a turn and returns that turn's id. The id counts turns. It does not read the series epoch. A new turn has no steps. Model bytes and the epoch stay put. After compaction the epoch is 2 and the first turn id is 1.
- Twenty-eight host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `c9638e211f3708e809890369f0f750dbe6fcaa6145864c8092573262e81d9fc3`. No commit, no push, no PR. Turn and step markers are still not log events. `derive` is still a copy of the log.

## 12 Oct 2026, 21:20 — markers stay out of the model view, still local
- Two steps opened on one turn share the epoch. An unknown turn adds no step. The conversation bytes stay unchanged.
- Turn and step markers sit beside the conversation. `derive` omits them. `model_bytes` still records a marker when that marker is the node it is given, and replay restores it.
- Twenty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `216c34e1f41d98227ad6b824ac92f031b0cd5e1a1920512557555ca9577c0a5a`. No commit, no push, no PR. The branch `spike/agent-host` has no upstream.

## 12 Oct 2026, 21:20 — assistant and tool-result tags, still local
- The log bytes now use role tag 3 for an assistant line and role tag 4 for a tool result. Replay restores both. `model_bytes` does not drop either one. An empty assistant line stays in the bytes and in the current view. `derive` still only omits turn and step markers.
- Thirty host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `fcbb09a4ee069b0ff61369409c818d7e297288d1ecd316bf4c82c58f70a44df8`. No commit, no push, no PR.

## 12 Oct 2026, 21:22 — empty assistant stays in the log, still local
- An empty assistant line stays in the journal and in replay. `derive` omits that line. `model_bytes` still records it. A spoken assistant line stays in the view. An empty tool result stays in the view.
- Thirty-one host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `a416939917960a6ec7fe650e0d73983e69d7178ef1a4840b04804f8af7507a2d`. No commit, no push, no PR.

## 12 Oct 2026, 21:25 — a tool result enters the view, still local
- One tool result may be recorded for a step. That line enters the model view and replays with the log. A second result, or a result for a missing step, leaves the journal unchanged. The series stays put.
- A step with no result stays in the marker log. `derive` omits that marker. Opening the step still does not change the conversation bytes.
- Thirty-two host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `b55f64602c95f5ced32777f721e9d340c040affd34d5af6721886bd36627aa15`. No commit, no push, no PR.

## 12 Oct 2026, 21:30 — compaction checkpoint, crash bracket, and observations, still local
- The compaction summary is now one user checkpoint. Node 0 stays the system head. `./verify.sh` and `./run-local.sh` passed on that slice. Guest hash `a4b31e41e16732d5ccecedb3ead641eaaa5eda4ac1e9e491c6a2e0c0f4a31269`. Thirty-three host tests.
- Compaction now opens before it commits. A crash between them restores the saved bytes and the series, and the skill is still there. A second open while the first is open does nothing. Commit keeps the skill after the checkpoint. Verified before the next slice. Guest hash `c592c784406dc4e56e7e6381210076ccdf2aaebb3b4c749b01f486711bb9156f`. Thirty-four host tests.
- A read observation appends the resource, the version, and the SHA-256 of the text. The empty-string digest and the digest of `abc` match the known answers. Replay keeps the older version when a later read is appended. `derive` omits the record. An empty resource, or a resource with a space, adds nothing. The first verify of this slice failed one existing test: source tag 9 had been the unknown-source refusal, and it is now an observation. That refusal moved to tag 10, and the rerun passed.
- Thirty-five host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `05bd00b4efb77acd69b68d20815ab7136b3faf920d3838a450c3f70dc25329cf`. No commit, no push, no PR.

## 12 Oct 2026, 21:35 — unread and stale edits create no step, still local
- An edit of a resource with no observation is refused. An edit that names an older version, or no version, is refused. Empty old text is refused. Each refusal leaves the journal unchanged.
- A proposal for the current version records one Prepared edit, keeps the old text and the new text, and does not change the log or the series. It does not write the resource.
- Thirty-six host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `bf05f03eda46255fd5b93cff28a8bdbf3fde1fdf0a47977abf77b674d3a7f6a5`. No commit, no push, no PR.

## 12 Oct 2026, 21:40 — old text must occur once, still local
- An edit is refused when the old text is missing from the observed text, and when it occurs more than once. Neither refusal creates a step or changes the log.
- One occurrence records a Prepared edit. Replay still has the older observation, and the current observation is the later read.
- Thirty-seven host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `46a8b7a7745f8920089a9a785f9484e7db10eff565145e19ca5beb7e4d05e78a`. No commit, no push, no PR.

## 12 Oct 2026, 21:42 — a later write waits, still local
- Two edits each keep their own effect id. The later edit stays Prepared while the earlier edit has no result. Dispatch does not turn that wait into a denial, and a result for the later edit is refused. After the earlier edit has a result, the later edit can be dispatched.
- Thirty-eight host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `dc5e1179ea0d1e2906df07b74e68e1a2fc4afb2654b35270a19dcbcbd4601ae0`. No commit, no push, no PR. The grant string in that proof is the test token `fixture-grant`. It is not a Runtime grant.

## 12 Oct 2026, 21:50 — writes, runs, restores, and hosted proposals, still local
- A provider write may be asked only when the step has a grant string and the version is still current. The ask does not change the log, the observed text, or the result flag. A read cannot ask for a write. `./verify.sh` and `./run-local.sh` passed. Guest hash `4f698b5288af633f63ca50a2a19be9f1f55847cd968850b0c9d0d2054a053696`. Thirty-nine host tests. `fixture-grant` remains a test token.
- A run proposal stores a `localhost://` project and its arguments as data. A host path, including `/bin/sh` and `..`, creates no step. Cancel after the checkpoint leaves the run cancelled, and dispatch returns false. No process is started. Verified before restore. Guest hash `eba5a3dfdd1a528869dcf134f910d07babcd31241a6cd7981e2bf3d2eae3a67b`. Forty host tests.
- A restore of an unknown version creates no step. A version that is no longer current is refused until that version is read again. A current version records a Restore step and does not apply the text. Replay still has the older observation. Verified before the hosted slice. Guest hash `c66667f88670da86aac4eb01f6ecff65b3f47179ea9a5d63086d5e8edc14697f`. Forty-one host tests.
- A hosted proposal names a model resource and has no secret field. A missing grant is Denied, and dispatch does not run. The log stays unchanged.
- Forty-two host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `8a66e124736ded8b157428eca952340547899d58448704a8b3880e42a72a0442`. No commit, no push, no PR. The micro-VM, the Home version list, prefix packing, and `UsersAI` stay unbuilt.

## 12 Oct 2026, 21:55 — child grant, project resource, and the local cache lock, still local
- A child resource must sit under the parent resource. A sibling path creates no step. The parent's grant string is refused, and the child stays prepared. `child-grant` is a test token, not a Runtime grant. No process is started. `./verify.sh` and `./run-local.sh` passed. Guest hash `dabf20d47c946890a9a1c1efbe76d09653f28e6522d80e23e2b1c79697b5a75d`. Forty-three host tests.
- A project proposal stores `localhost://Users/self/Projects/demo`. A slash, `..`, or `/tmp` creates no step. The proposal does not write a scaffold.
- The local engine source still sets `--cache-ram` to `0`, the idle release is still 60 seconds, and the input-token count still refuses a prompt that exceeds the context. Those provider files were not edited.
- Forty-five host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `a19d44a820b6c81b3d05d1f87972798796e3b5b3d3106dde966cdbd9bef74cbc`. No commit, no push, no PR.

## 12 Oct 2026, 22:00 — project tree hash, scaffold rules, and the microvm seat, still local
- A project tree hash changes when `style.css` changes and when `index.html` changes. The same files in another order keep the same hash. A host path has no hash. Capsule admission still hashes the entrypoint file. That verifier was not edited.
- A scaffold write of an empty observed file follows the version rules. Unread, stale, a host path, and text that is already present create no step. The proposal does not apply the file.
- A run seat is `microvm`. It is not `browser` and not `terminal`. No process is started, and no WASI import was added. The exec provider itself is not built.
- Forty-eight host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `486ce604c041fca2651379688d61ee249ff5701c99bc5c67a1b3350614b22ace`. No commit, no push, no PR.

## 12 Oct 2026, 22:05 — a run result shape, still no VM, still local
- A run result may be recorded only after the step is dispatched with a grant. The record is an exit code, a log, and an artifact. Together the log and the artifact must be at most 4000 bytes. A host path is refused. A result before dispatch, after cancel, or a second result leaves the journal unchanged.
- The first clippy check failed because the budget constant was unused on the host library build. It is now compiled only with the guest and the tests. The rerun passed.
- Forty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `177cf72d7d3e41c9eaf207289fdd84016b82151d1080beac0618675ae9b633b7`. No commit, no push, no PR. No process was started. `fixture-grant` remains a test token.

## 12 Oct 2026, 22:30 — exec adapter gate, still no boot, still local
- `decide_exec` in `elastos-compute` refuses a missing grant, a cancel, a host path, a missing `rootfs.ext4`, and a host that is not Mac or Linux. Mac names Apple Virtualization. Linux names crosvm. The function does not call those providers and does not boot.
- Three exec tests pass. `cargo clippy -p elastos-compute --lib -- -D warnings` passed. No rootfs was downloaded. The Browser launch path was not edited. No commit, no push, no PR.

## 12 Oct 2026, 22:35 — ext4 handoff, still no hypervisor boot, still local
- `begin_exec` calls a launcher only after `decide_exec` admits the run and the file has the ext4 superblock magic. A file that is only named `rootfs.ext4` never reaches the launcher. A log that contains a host path is refused after the launcher returns.
- Five exec tests pass. `cargo clippy -p elastos-compute --lib -- -D warnings` passed. Apple Virtualization and crosvm were not called. The Browser rootfs was not opened. No commit, no push, no PR.

## 12 Oct 2026, 22:40 — kernel and browser-disk gate, still no boot, still local
- `admit_boot_image` refuses a disk under `browser-vm`, a missing kernel, and a kernel that is not ELF. An ELF stub plus an ext4 stub names Apple Virtualization on Mac and crosvm on Linux. The hypervisor is not called.
- This machine has no `vmlinux`, no exec `rootfs.ext4`, no `mke2fs`, and no `busybox`, so a guest cannot be built or started here. Six exec tests pass. `cargo clippy -p elastos-compute --lib -- -D warnings` passed. No commit, no push, no PR.

## 12 Oct 2026, 22:50 — exec disk built and Apple VZ started it, still local
- The kernel is the crosvm guest kernel named by `scripts/setup-crosvm.sh`, saved at `/Users/sash/code/elastos-exec-image/vmlinux`. `file` reports a Linux ARM64 boot Image.
- The disk is `/Users/sash/code/elastos-exec-image/rootfs.ext4`, 64 MB, built by `scripts/build/build-vm-smoke-rootfs.sh` from Alpine's static aarch64 BusyBox. It is not under `browser-vm`.
- A signed `elastos-vz` test loaded and started that pair through `VzProvider`. `start` returned. No console line appeared in 45 seconds. The VZ boot path only forwards virtio console `hvc0`, and this kernel is the crosvm serial kernel, so the guest was silent. The VM was stopped.
- No commit, no push, no PR. The Browser disk was not opened.

## 12 Oct 2026, 22:55 — initramfs boot, console still silent, still local
- The same BusyBox is now also an initramfs at `/Users/sash/code/elastos-exec-image/initrd`, and a gzip copy beside it. The signed Apple Virtualization test started the guest with `console=hvc0 init=/init` for both. `start` returned each time. No console line appeared. The VM was stopped.
- This kernel is the crosvm serial kernel. The Mac adapter only forwards the virtio console. The kernel that prints on that console is the separate ElastOS `bin/vmlinux` from a verified image set. That file is not installed here. The Browser disk was not opened. No commit, no push, no PR.

## 12 Oct 2026, 23:10 — virtio console printed the hello line, still local
- The kernel is Debian `linux-image-6.1.0-50-arm64` version `6.1.176-1`, from the same 2026-10-08 snapshot the Browser recipe pins. Deb hash `914f75b57a8e165d85fb910c3e2dcc7000a05a9fea3f42f90b26e8dd590d5f06`. The Image is `/Users/sash/code/elastos-exec-image/vmlinux-debian`. It is an ARM64 boot Image, with the PE signature at offset `0x40`.
- `virtio_console` is a module in that package. The initramfs at `initrd-debian` loads `virtio_pci` and then `virtio_console`. The module load status was 0.
- The signed test `exec_smoke_image_prints_hello` captured `init: hello from vm smoke test` and passed. The VM was stopped. The disk was the smoke `rootfs.ext4`, not the Browser disk.
- That line is not yet a guest tool result. `cargo test` inside the guest was not run. No commit, no push, no PR.

## 12 Oct 2026, 23:15 — the hello machine stays small, and a long log is cut, still local
- The exec seat is 1 core and 256 MiB. The signed hello boot ran again and passed in about a third of a second. The Browser disk was not opened.
- A console log longer than 4000 bytes is cut, and the ending is kept. The hello line stays whole. Seven exec tests pass. `cargo clippy -p elastos-compute --lib --tests -- -D warnings` passed.
- The smoke-disk script no longer waits 30 seconds after the hello. The disk already on disk was not rebuilt. The boot that passed uses the initramfs, which exits. No commit, no push, no PR.

## 12 Oct 2026, 23:20 — the hello console is a legal short log, still local
- The signed boot ran again and passed in about a third of a second. The captured console text went through `cap_exec_output`. It contains `init: hello from vm smoke test`, it is within 4000 bytes, and it has no artifact.
- That check does not write the guest journal. `cargo test` inside the guest was not run. No commit, no push, no PR.

## 12 Oct 2026, 23:30 — the hello line is in the guest notebook, still local
- After a granted dispatch, the guest records `exit 0` and `init: hello from vm smoke test`. The guest does not boot the machine. `fixture-grant` remains a test token.
- Fifty host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `a8a82863f9e93b9cd4dc77bcae5284fc33629d4de7018b55e1bb5408ff19e88a`. The Wasmtime import list is still identity, runtime, and types.
- `cargo test` inside the machine was not run. No commit, no push, no PR.

## 12 Oct 2026, 23:40 — a passing command and a failing command return real exit codes, still local
- The small machine reads `elastos.exec=true` or `elastos.exec=false`. It prints `elastos-exec-exit` and the host refuses a console with no mark, two different codes, or a host path. Silence is not exit 0.
- On this Mac the passing command returned exit 0 and `init: hello from vm smoke test`. The failing command returned exit 1 and `init: command failed`. Both boots together took about half a second, at 1 core and 256 MiB. The Browser disk was not opened.
- The guest notebook records both shapes. Fifty-one host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `fb2aa43172a8ea147363c70c2d61ba7479a02163137649a58c34183bceb77b53`. The guest does not boot the machine. `fixture-grant` remains a test token. `cargo test` inside the machine was not run, because this image has no Rust toolchain. No commit, no push, no PR.

## 12 Oct 2026, 23:50 — compiled Rust tests ran inside the small machine, still local
- `examples/vm-smoke` builds a 1.1 MB static aarch64 test program. The machine ran `tests::project_is_ready` and returned exit 0 with `test result: ok`. It ran `tests::a_missing_piece_fails` and returned exit 101 with `test result: FAILED`. The shell pass and fail still return exit 0 and exit 1. Four boots took about a second.
- The guest notebook records those shapes. Fifty-two host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `338b93d909badc46273f6feadeddfcadedb0e5e081c1ef084aa3a0f30749e36e`. The guest does not boot the machine, and the `cargo` command is not inside the image. `fixture-grant` remains a test token. No commit, no push, no PR.

## 12 Oct 2026, 23:55 — the exit code comes from the console, still local
- `begin_exec` reads the exit code from the `elastos-exec-exit` mark. A console with no mark is refused. A launcher cannot supply its own exit code.
- The guest refuses exit 0 with `test result: FAILED`, and exit 101 with `test result: ok`. An unknown command booted on this Mac returned exit 1 and `init: command refused`. Five boots took about a second and a half.
- Fifty-two host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `59c9a5893365a4dfeb856cf14bbb1cca2928bc9fcd2d7e4eb0aeb6882f8d8e12`. The guest does not boot the machine. `fixture-grant` remains a test token. No commit, no push, no PR.

## 12 Oct 2026, 23:58 — cargo is refused because it is not in the image, still local
- The provider runs `vm-smoke` with `tests::project_is_ready` or `tests::a_missing_piece_fails`, or the shell checks `true` and `false`. `cargo test` returns `program missing` and the launcher is not called. An unknown command returns `command refused`.
- The signed boot still ran those admitted programs, and `nope` still returned exit 1. Nine exec tests pass. `cargo clippy -p elastos-compute --lib --tests -- -D warnings` passed. The guest was not rebuilt. No commit, no push, no PR.

## 13 Oct 2026, 00:20 — the machine saw the admitted project page, still local
- `admit_project_files` accepts `localhost://Users/self/Projects/demo` and `index.html`. A host path, a `..` segment, or file text that is a host path is refused. Nothing is copied from the host disk.
- The small machine read that page and printed `project demo index.html ready`, then exit 0. The notebook stores that line with `test result: ok`. Fifty-two host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `97c37cceeb88f127db772faa294d361d278ebb17723b97572e67b2d13fe3b6d2`. The guest does not boot the machine. No commit, no push, no PR.

## 13 Oct 2026, 00:30 — the machine and the guest share one project digest, still local
- The admitted tree is `index.html` and `style.css`. The machine printed `project demo 157af2e20c421bfaf3ac59d51f059bd9b8fb1cf2e40a2b45e8b898771ff938f5`. The guest computes the same digest, and a change to `style.css` changes it. The notebook stores that digest with `test result: ok`.
- Fifty-two host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `29aff647ad2b8ce8f1cb2bae286db100f7df1277f7120a9863a34913718e099a`. The guest does not boot the machine. No commit, no push, no PR.

## 13 Oct 2026, 00:35 — an edited stylesheet needs a new digest, still local
- Reading `style.css` as `h1{}` changes the project digest. The machine printed `project demo 5ff4215e2135fbfa327187523ad3a6ffb536fec2d893526d9a271b36f95c72b7`. The notebook accepts that digest and refuses the previous one.
- Fifty-three host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `2d6359d6eb1e78ebafd1806980b55832bb193d708c8e60a48113c1820f7fe02f`. The edit is a new read, not a file written on the host. The guest does not boot the machine. No commit, no push, no PR.

## 13 Oct 2026, 00:40 — a granted edit becomes the current text, still local
- Before a grant, an edit of `style.css` leaves the text as `body{}`. After a granted dispatch, the journal's current text is `h1{}`. The old project digest is then refused and the new one is stored. No file is written on the host. `fixture-grant` remains a test token.
- Fifty-four host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `1bce945413d48d1f4f5cd0be3c4cbc0821c73c6391568a95b16a7dd0e3dae59d`. The guest does not boot the machine. No commit, no push, no PR.

## 13 Oct 2026, 00:45 — a moved version is not written, still local
- If `style.css` is read again after the edit was proposed, the write is refused and the newer text stays. The provider function returns `h1{}` for a current version and writes no file. A missing grant, a host path, and a stale version are refused.
- Fifty-five host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `e406cb4c312464f9b41880008ff3585870782668ac84905a5f94915b33c6fefc`. `fixture-grant` remains a test token. No commit, no push, no PR.

## 13 Oct 2026, 00:50 — the edit survives resume, and the machine can list its files, still local
- Replaying the log after a granted edit still reads `style.css` as `h1{}`. The machine listed `project file index.html` and `project file style.css` and did not name a host path. Exit code 0.
- Fifty-five host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `52e17c6712ebc66da39a4a6a7a7707db253ad1c77da88556c46bbafe51d5099a`. The guest does not boot the machine. No commit, no push, no PR.

## 13 Oct 2026, 00:55 — a typed note is part of the project digest, still local
- `notes.txt` says `hello from the project`. The machine listed `project file notes.txt` and printed digest `a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1`. The guest computes the same digest. The notebook stores it with `test result: ok`.
- Fifty-five host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `a4d02a2038589a9443d64507ee2dbc214d4e77f16f0fc1f1ce9b40fec9f42a03`. The note is an admitted file, not a live keyboard session. No commit, no push, no PR.

## 13 Oct 2026, 01:00 — retyping the note changes the digest, still local
- Before a grant, the note stays `hello from the project`. After a granted edit it is `hello again`. The machine printed digest `8256365b5a513111b73d3ee3b646a78d58c821c9f3cba1346f6f27c0f38dd36d`. The notebook refuses the previous digest, stores the new one, and still has `hello again` after replay.
- Fifty-six host tests pass. `./verify.sh` and `./run-local.sh` passed. The guest component hash is unchanged because this check is in the tests. `fixture-grant` remains a test token. No file was written on the host. No commit, no push, no PR.

## 13 Oct 2026, 01:05 — the machine prints the note sentence, still local
- The original tree printed `project note hello from the project`. The retyped tree printed `project note hello again`. The notebook accepts only the sentence that is current. An older sentence and a host path are refused.
- Fifty-six host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `9d1ca4d8d4630551305305c4e362d1e1deeaa9be6db3ae986b7158e9d4872b10`. The guest does not boot the machine. No commit, no push, no PR.

## 13 Oct 2026, 01:10 — a crash does not apply the note, still local
- After the note edit is sent, a crash leaves the step `settlement_unknown`. The text stays `hello from the project`. `hello again` is refused. Replay still shows the original sentence.
- Fifty-seven host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `68e7a66ecae6a2300fccf3f65d73bf8e7488e53379fcf126b408342cbf5201ac`. `fixture-grant` remains a test token. No commit, no push, no PR.

## 13 Oct 2026, 01:15 — cancel before send keeps the note, still local
- Cancel before the note edit is sent leaves `hello from the project`. The new sentence and its digest are refused. Cancel after the edit is sent returns false and does not take the edit back. The write can still become `hello again`.
- Fifty-eight host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `7563edd3dd35037a17f726a8e9ab4396b583af66db1870da9b6501057912c7a1`. No file was written on the host. No commit, no push, no PR.

## 13 Oct 2026, 01:20 — a file list may name only files already shown, still local
- `index.html` and `style.css` can be listed after they have been shown. `notes.txt` is refused until it is shown. A host path in the list is refused. The machine's live list of those three names passed the same check.
- Fifty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `f8b7a93da72b96d5a89ec51e0be43d98bc8416d6b22f7914f4348a5187f658af`. The guest does not boot the machine. No commit, no push, no PR.

## 13 Oct 2026, 01:25 — a file list must name every shown file, still local
- After `notes.txt` has been shown, a list that names only that file is refused. The full list of `index.html`, `style.css`, and `notes.txt` is accepted. The machine's live list is exactly those three names.
- Fifty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `663b966a141099005d748db674a275e0cc23de34832c767269dd2545c00e794d`. The guest does not boot the machine. No commit, no push, no PR.

## 13 Oct 2026, 01:30 — the file list and the digest have to match, still local
- After the note is `hello again`, the full file list paired with the old digest is refused. A list that leaves `notes.txt` out is refused. The full list with the new digest and `project note hello again` is stored.
- Fifty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `663b966a141099005d748db674a275e0cc23de34832c767269dd2545c00e794d`. No commit, no push, no PR.

## 13 Oct 2026, 01:35 — a repeated file name still counts once, still local
- The machine prints each file name twice. The notebook treats that as one `index.html`, one `notes.txt`, and one `style.css`. A list that leaves a shown file out is still refused. The doubled list with the current digest is stored.
- Fifty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `21dd0a5d697aa335ca1b3e934c80161e1bc84680bd758ca92485bc66e4c0a14c`. No commit, no push, no PR.

## 13 Oct 2026, 01:40 — a cargo test result is refused, still local
- The proposal may still name `cargo test`. A result for that program is refused, because `cargo` is not in the machine. Results are stored for `vm-smoke` and the other programs the machine can run.
- Fifty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `945a18c376ac174d93ccf06f881943cc6fb12d2faf6c93cdd3bae389dcda0cfb`. No commit, no push, no PR.

## 13 Oct 2026, 01:45 — hello and failure belong to true and false, still local
- `init: hello from vm smoke test` is stored only for the program `true`. `init: command failed` is stored only for `false`. `vm-smoke` cannot store either line.
- Fifty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `d8c4e43cb03ad3b8788bfd31ea29162668bda0aeed10f9ae60ef4b141281dbce`. No commit, no push, no PR.

## 13 Oct 2026, 01:50 — each console line belongs to its program, still local
- A file list is stored only for `files`. A note sentence is stored only for `note`, or for the edited project test when that test prints the sentence with the digest. A file list mixed into the Rust test result is refused.
- Fifty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `f645308e35c726f74308c2104974d10028a6bc298671cf152a84508a172cf014`. No commit, no push, no PR.

## 13 Oct 2026, 01:55 — one grant covers three programs, still local
- The same grant string authorizes `files`, `note`, and the Rust test. Each step keeps its own effect id. A file list cannot be stored on the note step, and the note sentence cannot be stored on the file step.
- Sixty host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `36602a72b8a5f218ded2adfd9721ec3f77d81eaf1ac1a844e2d9e04b61635fda`. `fixture-grant` remains a test token. No commit, no push, no PR.

## 13 Oct 2026, 02:00 — a crash after the result does not erase it, still local
- Once the note is `hello again` and the result is stored, a later crash does not change the step or the text. Replay still shows `hello again`. A crash before the result is still unfinished.
- Sixty-one host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `12ab18e81295273279540e9b9a4fb11a9d1495c4c947d0af03923b38364fae04`. No commit, no push, no PR.

## 13 Oct 2026, 02:05 — a later note read uses the rewritten sentence, still local
- After the note becomes `hello again`, a later `note` result that still says `hello from the project` is refused. The old project digest is refused. The new digest `8256365b5a513111b73d3ee3b646a78d58c821c9f3cba1346f6f27c0f38dd36d` is accepted with the new sentence.
- An earlier scaffold that has not finished still blocks that rewrite, and the sentence stays `hello from the project`.
- Sixty-two host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `8064cf50126dbd3685af25215eedb6d686ce5e3abfe89f6c57272187e4119b76`. No commit, no push, no PR.

## 13 Oct 2026, 02:10 — cancelling the open scaffold lets the note rewrite land, still local
- While the scaffold is still open, the note rewrite does not run and the sentence stays `hello from the project`. Cancelling the scaffold does not change the sentence by itself. After that cancel, the waiting rewrite can be sent, the note becomes `hello again`, and a later read of the old sentence is refused.
- Sixty-three host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `51db85aac0ebfec58b802009d3a4634149a718695397a0ee6ba6daac0e1bf15b`. No commit, no push, no PR.

## 13 Oct 2026, 02:15 — a sent scaffold leaves the page empty, still local
- A scaffold can be granted and sent, and the page version can be copied onto that step. The write still does not land. `index.html` stays empty, and the step has no result. An empty old string is refused, which is the same rule the provider already uses.
- Sixty-four host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `4ea3a0252155cbd415ca4b1afd54edb1680f659a0670819dad3bde76dd6e5428`. `fixture-grant` remains a test token. No commit, no push, no PR.

## 13 Oct 2026, 02:20 — a refused write does not block the next one, still local
- A sent scaffold still leaves `index.html` empty. That step is now denied, so a later note rewrite can be sent and becomes `hello again`. A write whose version moved is denied the same way, and an edit of the current text can follow it. A crash that is still unknown does not get this treatment.
- Sixty-four host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `92771b375d13049c009ab4c80f7dc745ddcd110686d4ec78c59814b4c4025a32`. No commit, no push, no PR.

## 13 Oct 2026, 02:25 — a same-version read cannot replace the page, still local
- A file already read at version 1 stays that text if the next read reuses version 1 with different words. The page content is a new read at version 2. Reading version 1 again is allowed only when the text is still `one`, which makes that older version current again.
- Sixty-four host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `9be98d1d293c21373ae430865dcdf04d8acae416330a6494a7d0ee7bfa2628a7`. No commit, no push, no PR.

## 13 Oct 2026, 02:30 — the older note is current again, still local
- After the note is `hello again`, reading version 1 with the words `hello again` is refused. Reading version 1 with `hello from the project` makes that sentence current. A later note result must quote it. The rewritten sentence and the edited digest are refused. The original digest `a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1` is accepted.
- Sixty-four host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `2ccb54e2315d6717de8009519ea9acd38b7af391494403b8f62e7c3aa22eb0ab`. No commit, no push, no PR.

## 13 Oct 2026, 02:35 — a rewrite edit does not land after the older read, still local
- An edit from `hello again` to `hello once more` can be prepared while that rewrite is current. After version 1 is read again, sending that edit is denied. The note stays `hello from the project`. A new proposal that still names version 2 is stale.
- Sixty-four host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `d5f64b4d9bdddcb4f7acefe3ea90a8377ee575b85f3392a41697aead546059f1`. No commit, no push, no PR.

## 13 Oct 2026, 02:40 — a fresh edit of the current note lands, still local
- After the stale rewrite is denied, an edit of the current sentence `hello from the project` to `hello again` is sent and lands. A later note result must quote `hello again`. The original digest is refused. The edited digest `8256365b5a513111b73d3ee3b646a78d58c821c9f3cba1346f6f27c0f38dd36d` is accepted.
- Sixty-four host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `78f8e7aa10609ea701e38282823e274c71091ad7b313f75f5df57bce66b7da7e`. No commit, no push, no PR.

## 13 Oct 2026, 02:45 — resume still shows the current note, still local
- After the fresh edit, reading the log bytes back still shows `hello again`. The plan checklist is 49 of 62 slices done. The grade toward a 5 on every row stays about 43 of 70.
- Sixty-four host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `3a6d3e9d98c2bd598d4afd7405b6c2155167b34fde512e9c70e73d3275ec98c0`. No commit, no push, no PR.

## 13 Oct 2026, 02:50 — a shorter log keeps the current note, still local
- Compaction still replaces the conversation with one shorter summary. The file read stays. After that shortening, the note is still `hello again`, and reading the log back shows the same sentence.
- Sixty-five host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `93020d463868cd91036de43b1a44187cc3f1265e2a1db240b07839dfc9b28328`. No commit, no push, no PR.

## 13 Oct 2026, 02:55 — a shorter log still accepts the current note, still local
- After compaction, a result that says `hello from the project` is refused. A result that says `hello again` is stored. An edit of that sentence to `hello once more` lands.
- Sixty-five host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `94fdccebcfa31ea8d1ead94db309e4873650430bfeefe97d2d58c6fef5a9ae9e`. No commit, no push, no PR.

## 13 Oct 2026, 03:00 — a second shortening keeps the older note, still local
- After the note becomes `hello once more` and the log is shortened again, that sentence stays current. Reading version 1 with `hello once more` is refused. Reading version 1 with `hello again` makes the older sentence current.
- Sixty-five host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `ea3652db42d69c8fa85f4330c957369f19cf559559630fda2e4a0b36e6d0c5b5`. No commit, no push, no PR.

## 13 Oct 2026, 03:05 — a crash during shortening keeps both notes, still local
- If the second shortening crashes before it finishes, the current sentence stays `hello once more` and version 1 is still `hello again`. The shortening does not stay open, and it cannot be finished after the crash.
- Sixty-five host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `7ce71aa2c6f71e81febb10eb37ad2424bee6a8e041ccd09748c76a36d06f7cd2`. No commit, no push, no PR.

## 13 Oct 2026, 03:10 — a shorter log keeps the whole project, still local
- After compaction, the skill stays, and the file list must still name `index.html`, `notes.txt`, and `style.css`. A short list is refused. The project digest `a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1` is accepted.
- Sixty-six host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `dc0b142ccfddc570b4af966914e26bd0c707b8ef73b7c90cd64a619da34e9ec4`. No commit, no push, no PR.

## 13 Oct 2026, 03:15 — a shorter log keeps the workspace snapshot, still local
- Compaction keeps the workspace, the time, and the open file. Reading the log back still has those three lines. If the conversation is already short, a new summary is refused and the snapshot stays.
- Sixty-seven host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `6a742807343afa7c1f02be45aa1a79aa16a128761a1784c5f582b63104d78ab8`. No commit, no push, no PR.

## 13 Oct 2026, 03:20 — a workspace snapshot refuses a host path, still local
- A snapshot of `/tmp`, a `..` segment, or an open file at `/tmp/secret` adds nothing. The earlier workspace lines stay. Shortening cannot keep a host path that was never stored.
- Sixty-seven host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `9bef3ba2c2825f507488c5dd673b6aab8946bfc7021b96a1c5e88fc8eb6f0599`. No commit, no push, no PR.

## 13 Oct 2026, 03:25 — a skill or a file read refuses a host path, still local
- A skill whose text is `/tmp` adds nothing. A file read of `/tmp/secret`, or a path with `..`, adds nothing. The log stays as it was, so a shorter log cannot keep that path.
- Sixty-seven host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `b0e701adcc6423c7874041314b6d9eb8c874457402e7c49ca43ffea2ad6c4a2e`. No commit, no push, no PR.

## 13 Oct 2026, 03:30 — a shortening summary refuses a host path, still local
- A summary of `/tmp`, or a summary with `..`, does not shorten the log. The series stays put. The real summary still replaces the conversation.
- Sixty-seven host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `e6ec6896b1aa58c6839a82d5257d2ba1ff8c43e868decc017ba104b6bff59c41`. No commit, no push, no PR.

## 13 Oct 2026, 03:35 — a goal survives shortening and does not grant, still local
- A goal, a to-do, a plan entry, a plan-exit ask, and a spill pointer stay after the conversation is shortened. An empty text or a host path adds nothing. No step is created, and the series stays put. Ordinary chat such as `second turn` is still replaced by the summary.
- Sixty-eight host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `a41f3902e0ed8990ffc636b336bbd09597496bb638480adc25892b46c03071cb`. No commit, no push, no PR.

## 13 Oct 2026, 03:40 — an inbox answer does not mint a grant, still local
- Deny ignores a grant that was passed in and leaves the step denied. Allow once with no grant, and allow for the session with an empty grant, also leave the step denied. Standing keeps only the grant that was sent, here the test token `fixture-grant`, and the step can then be dispatched. The guest does not invent a grant.
- Sixty-eight host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `9cff728d1367a809da051afc720a39dc687b4d7adfe4dea4b8fe84d3ae4e16e7`. No commit, no push, no PR.

## 13 Oct 2026, 03:45 — a second inbox answer does not replace the first, still local
- After standing is recorded with the test token, a later deny does not clear it. A new step stays prepared with no grant and no inbox answer. The first step can still be dispatched.
- Sixty-eight host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `6c4dd86d63fc12418cd7394c741a539d87f82b17419546271fa44a9586f6a04a`. No commit, no push, no PR.

## 13 Oct 2026, 03:50 — the inbox answer name stays in the log, still local
- Standing writes `inbox` and `standing` into the log. The test token `fixture-grant` is not in those bytes. After the conversation is shortened, the answer name is still there.
- Sixty-eight host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `e0d376b4932afdfcc07f628503af7e6c9e11a667afeffa4d3eb4c0c87ae8db9a`. No commit, no push, no PR.

## 13 Oct 2026, 03:55 — cancel before send stops a standing step, still local
- A standing answer can be cancelled before it is sent. The step becomes cancelled and does not dispatch. The log still shows `inbox` and `standing`. Another step is not authorized by that answer.
- Sixty-eight host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `bdbff1c2037366685704d7a21bad93fac9b2584ea3de5a14fffcbea8cb292f8e`. No commit, no push, no PR.

## 13 Oct 2026, 04:00 — a spill pointer keeps the file text, still local
- A granted, dispatched step can record `spill` plus the object name. The note stays `hello from the project`. A host path and a second pointer are refused. After shortening, the pointer remains and the test token is not in the log. This is not an object-provider blob yet.
- Sixty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `04452cd0b51a81c6379b4fe098a869164a16fbbb9f5a413082d572387de92346`. No commit, no push, no PR.

## 13 Oct 2026, 04:05 — a spill pointer requires a file that was read, still local
- A pointer to `style.css` is refused when that file has not been read. The step is still free, so the pointer to the note that was read can be stored. The note text stays `hello from the project`.
- Sixty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `ee0f4f00b4a3d35012241db5ee3fa40319bee21a40b390ab16cf7f319789a4df`. No commit, no push, no PR.

## 13 Oct 2026, 04:10 — a spill pointer stays on the version that was read, still local
- The pointer is `spill`, the note name, and version 1. After the note becomes `hello again`, the pointer still says version 1. That version still reads `hello from the project`.
- Sixty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `8c49917c4a3d609d19248e2c956009010f2d0049aafd757178dd1a2304161cdd`. No commit, no push, no PR.

## 13 Oct 2026, 04:15 — reading a spill pointer uses its version, still local
- After the note is `hello again`, reading the pointer still returns `hello from the project`. A pointer that names version 9, which was never read, returns nothing.
- Sixty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `9a656730d9fad0431dd65400086669b32cf39c792a5d543e86dd3091faeb8f9d`. No commit, no push, no PR.

## 13 Oct 2026, 04:20 — a missing spill version does not hide the earlier pointer, still local
- A pointer that names version 9, which was never read, is skipped. The earlier pointer still returns `hello from the project`.
- Sixty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `b66c6acc64a0432409b11a76fefb9328b634424878fbe69b0b69f6e52573bb09`. No commit, no push, no PR.

## 13 Oct 2026, 10:55 — the newer spill pointer is the one that is read, still local
- After the note becomes `hello again`, a second pointer names version 2. Reading the pointers returns `hello again`. Version 1 still reads `hello from the project`. A later pointer to version 9, which was never read, is skipped.
- Sixty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `9b6fd3ca69a692d43142930abe845e36a4928706acecc9059861cc18bdbfed19`. No commit, no push, no PR.

## 13 Oct 2026, 11:00 — spill pointers stay with their own files, still local
- The finished note step cannot take a pointer for `style.css`. A new step can. Reading the note pointer still returns `hello again`. Reading the stylesheet pointer returns `body{}`.
- Sixty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `27a8aa44ffb304473760b39bdb691494841b30036a316f7fb66f2f7a2b720428`. No commit, no push, no PR.

## 13 Oct 2026, 11:05 — a child cannot take the parent grant, still local
- An inbox answer that repeats the parent's grant leaves the child with no grant. A later answer can record `child-grant`. The parent still has `fixture-grant`. Both strings are test tokens.
- Sixty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `ae275c5eae09fec4f43c7c52f810a68fe87e0431be1a6061e7280262ed6266de`. No commit, no push, no PR.

## 13 Oct 2026, 11:10 — a spill pointer stays inside the step folder, still local
- A child whose folder is `demo/src` cannot point at `notes.txt`. It can point at `src/main.rs`. Reading the note pointer still returns `hello again`. Reading the `main.rs` pointer returns `fn main() {}`.
- Sixty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `581dd8938d9dd7d2ecdaf0e27a4f00d132263b59ac40c189b3a0b5d3ae980e78`. No commit, no push, no PR.

## 13 Oct 2026, 11:15 — a refused child answer adds no inbox line, still local
- The parent's standing line is the only inbox line while the child is offered the parent's grant. After the child receives `child-grant`, there are two standing lines. Sending the child leaves the parent prepared. Neither grant string is in the log. Both are test tokens.
- Sixty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `26a638f2b7a15e7b2711a620d40c7dbd6dc0f68f5472db38a952b697b14f6da8`. No commit, no push, no PR.

## 13 Oct 2026, 11:20 — cancelling a child does not cancel the parent, still local
- A child that has its own grant can be cancelled before it is sent. That child does not run. The parent stays prepared. The child that was already sent stays sent. The standing lines stay in the log.
- Sixty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `8a13a82f585c6195ba381af199069f6ac2d790de7eb4d8b91a0d143a40171af9`. No commit, no push, no PR.

## 13 Oct 2026, 11:25 — a crash of a sent child leaves the parent prepared, still local
- After a child is sent, a crash marks that child unfinished. It cannot be sent again. The parent stays prepared. The child that already finished stays sent. The standing lines stay in the log.
- Sixty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `f003394efb25000128bc7731ceb89c425cc68a8e693c7c823594b4a8c977e19e`. No commit, no push, no PR.

## 13 Oct 2026, 11:30 — a crash does not erase a child's result, still local
- After the child records `fn main() {}`, a crash does not change that child or the parent. Reading the pointer still returns `fn main() {}`.
- Sixty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `0d9351eab5cce8285a1299bdcd9e7bdc73a22c601275962e1ff6b44c6050c0ea`. No commit, no push, no PR.

## 13 Oct 2026, 11:35 — resume and shortening keep the child's file, still local
- After the child records `fn main() {}`, reading the log bytes back still returns that text. Shortening the log keeps it too.
- Sixty-nine host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `1232b06b2cc60d0cd70727df34687c57c6c723793255b2f82ed68f2ec14353e5`. No commit, no push, no PR.

## 13 Oct 2026, 11:40 — the same command waits for the first result, still local
- A second `note` stays prepared, with its grant, while the first `note` has no result. A `files` command can run beside it. After the first `note` has a result, the second can be sent. A crash of an unfinished `note` still holds the next one.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `e930e5fa3a2b443f1731421063032c46fc8ee008c5580f842a2ec7da42d92201`. No commit, no push, no PR.

## 13 Oct 2026, 11:45 — the same command on another project can run, still local
- While `note` on `demo` is unfinished, a second `note` on `demo` stays prepared. A `note` on `other` can be sent. The projects do not share that wait.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `e01e1ff6956b364cb0816db601fae3acf6933b8e50914dad98a62af37cfeda67`. No commit, no push, no PR.

## 13 Oct 2026, 11:50 — different test names can run together, still local
- `tests::project_is_ready` and `tests::a_missing_piece_fails` can both be sent while each is unfinished. A second `tests::project_is_ready` stays prepared until the first of that name has a result.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `4da3ca03d0ebe16ebfe8472fc6d9e40d1eb0a4817b5699ddd2b1fa7d53b0e11c`. No commit, no push, no PR.

## 13 Oct 2026, 11:55 — a finished test name can run again, still local
- Once `tests::project_is_ready` has a result, that name can be sent again. `tests::a_missing_piece_fails` stays unfinished, so a second copy of that name stays prepared.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `cc91e72b4598d1dabf9fef6d6d97437fe668ee3598b0f86f27ecfce4c6b19d5c`. No commit, no push, no PR.

## 13 Oct 2026, 12:00 — a crash of one test holds only that name, still local
- A crash of `tests::a_missing_piece_fails` leaves that name unfinished, so the next copy stays prepared. `tests::project_is_ready` stays sent, and its finished result stays. A result cannot be written onto the crashed step.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `f2235015fe5f76287d8e1aae681d8711b9ce8b46c77eb63e42966515c97c6858`. No commit, no push, no PR.

## 13 Oct 2026, 11:30 — a finished test can run again after the other crashes, still local
- After `tests::a_missing_piece_fails` crashes, a result on `tests::project_is_ready` lets that name run again. The crashed name stays unfinished, so its waiting copy stays prepared. The crash does not receive a result.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `a0e4100977e18a03137867dd640e97d30d0c4b6e03726e16705c5e111323871a`. No commit, no push, no PR.

## 13 Oct 2026, 11:35 — cancelling the waiting copy does not free a crash, still local
- The crashed test cannot be cancelled. Cancelling the copy that is still waiting leaves that copy cancelled, and the next copy of the same name stays prepared. The other test name stays sent.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `665b284fb4b8079044a778525fd34b17fa152d0793114d1c3b681d3299fa6faa`. No commit, no push, no PR.

## 13 Oct 2026, 11:40 — the crashed name can finish on another project, still local
- `tests::a_missing_piece_fails` can be sent and finished on another project while the first project is still crashed. The failure is exit 101. The first project's waiting copy stays prepared, and the other test name on the first project stays sent.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `587e3e5b6abd8054c7dba07433896aeb9294809fecdedd4acfe5b63504ffaa9b`. No commit, no push, no PR.

## 13 Oct 2026, 11:45 — the other project's failure stays in the log, still local
- The failure line `exit 101` and `test result: FAILED` is in the log and comes back on replay. The grant string is not in the log. The next copy of that name on the other project can be sent. The first project's crash still holds.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `eca84c9c553d0024d881b091740c41bf471fdaf75f14433338a4b7b64b419667`. No commit, no push, no PR.

## 13 Oct 2026, 11:50 — a crash on the other project stays there, still local
- A crash of the other project's open `tests::a_missing_piece_fails` holds the next copy on that project. The first project's crash still holds, and its other test stays sent. The finished failure line stays in the log. The crashed step cannot take a result and cannot be cancelled.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `8354f6237266bc4c78c2d9261e63a55a2ca8d5b73b3b83fcb0c2940403d5be7d`. No commit, no push, no PR.

## 13 Oct 2026, 11:55 — a pass does not free either crash, still local
- A result on `tests::project_is_ready` lets that name run again. The crash on this project and the crash on the other project both stay held. The pass line and the failure line both stay in the log. The grant string does not.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `8b3d7cc2a778d955f6d97e2c17c55855c242e4aeec5c60ede4fb3e75ba88112f`. No commit, no push, no PR.

## 13 Oct 2026, 12:00 — true can finish beside a crash, still local
- The program `true` can be sent and finished on each crashed project. An exact repeat of `true` waits until the first has a result, then it can run. The hello line stays in the log beside the pass line and the failure line. Neither crash is freed, and the open test stays sent. The grant string is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `49c71f33875bd1019191571f778ecb8fe5c4380428c4a476e43f40f03a0c5d29`. No commit, no push, no PR.

## 13 Oct 2026, 12:05 — false stays apart from true, still local
- The program `false` can be sent and finished on each crashed project. An exact repeat waits, then it can be sent. The hello line is refused for `false`. `init: command failed` is refused for the open `true`. The failed-command line stays in the log beside the hello line and the test lines. Neither crash is freed, and the open test stays sent. The grant string is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `2e0ca68c1641098287664ca47d533465ffe52fa2eefe1caad4ece646362c3818`. No commit, no push, no PR.

## 13 Oct 2026, 12:10 — an unread note is refused, still local
- `tests::project_was_edited` can be sent while `tests::project_is_ready` is still open and `tests::a_missing_piece_fails` is crashed. An exact repeat waits. A note line is refused until the note has been read, and that line does not land on the open ready test. The pass line can still be recorded. Neither crash is freed. The grant string is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `49fa2e1cd990feebd116f2b89d334c2ef632dd0a53caf807eb11a7bc004132a4`. No commit, no push, no PR.

## 13 Oct 2026, 12:15 — a read note can be quoted, still local
- Once `notes.txt` has been read, the open `tests::project_was_edited` can quote `hello from the project`. An older sentence and a host path are refused. The note text stays in the read. Neither crash is freed, and the ready test stays sent. The grant string is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `ac6f58ff88f14332f7cc9327b90790535c6db512ca5eea7686e0fae25eb3e48a`. No commit, no push, no PR.

## 13 Oct 2026, 12:20 — the file list names only the note, still local
- The open file list can name `notes.txt`, the only file that was read. A missing file, a note line, and a host path are refused. An exact repeat waits, then it can be sent. The other project cannot name this file. Neither crash is freed, and the note text stays. The grant string is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `2b58f096e1ad766b8cb72700887d1264a67578fcd4e11ff4980b03c42a540a58`. No commit, no push, no PR.

## 13 Oct 2026, 13:35 — the file list must name both files, still local
- Once `style.css` has been read, the open file list must name `notes.txt` and `style.css`. Naming only the note, only the stylesheet, or a host path is refused. The other project cannot name them. Neither crash is freed. The note text and the stylesheet text stay. The grant string is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `7584cd424cd05f6e51b26244f3f4bef16ce70529d8d90c9cc4bd43b19a232234`. No commit, no push, no PR.

## 13 Oct 2026, 14:15 — the ready test quotes both files, still local
- The open `tests::project_is_ready` can quote digest `f607cd56` of `notes.txt` and `style.css`. A digest that includes `index.html`, which was not read, is refused. The other project cannot quote this digest. Neither crash is freed. The grant string is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `658c4af5bc5d23d7d0ca16096bd288a4c44936f9e768093c2d45b1e5872f8492`. No commit, no push, no PR.

## 13 Oct 2026, 14:25 — a stylesheet reread refuses the old digest, still local
- After `style.css` is read again as `h1{}`, the open ready test refuses digest `f607cd56` and accepts `d2cfc9d2`. The note text stays `hello from the project`. Neither crash is freed. The grant string is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `bb38082dc45d6be94df4d77ebc482605725dcf0d78d276cbc7c63ddbdc26b85a`. No commit, no push, no PR.

## 13 Oct 2026, 14:30 — #116 note posted, file list still names both files
- Pushed `a0dc89d0` to `feat/home-phone-layout-0.7.1-models`. Comment https://github.com/Elacity/elastos-runtime/pull/116#issuecomment-6140547782. The local pre-push hook was not active in that worktree, so the heavy gate did not run before the push.
- After the stylesheet reread, the file list must still name `notes.txt` and `style.css`. Naming only the note is refused. The crash still holds. Guest hash `89c0296fad8116c383680f9df70b2be789ccc4bee2109a7f1e76e903d8cb3fbe`. No commit of the agent journal.

## 13 Oct 2026, 14:40 — an unread file stays out of the list, still local
- After the stylesheet rewrite, a file list that adds `index.html` is refused. The list of `notes.txt` and `style.css` is accepted. The other project cannot name those files. The crash still holds, and `index.html` is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `ffcc4ebeda672f028e5ac3e5b0d6900b279747c8c910ec8f678d145725541f78`. No commit, no push, no PR.

## 13 Oct 2026, 14:50 — a read page must be named, still local
- Once `index.html` is read as `<h1>demo</h1>`, the file list must name it with `notes.txt` and `style.css`. Leaving it out is refused. The digest must be `e618ccee`, and the earlier digest is refused. The other project cannot name these files. The crash still holds. The grant string is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `f6e751a9167e36345166e8fbfe07201da7ee002f80f1d43559e42bdcec095ef6`. No commit, no push, no PR.

## 13 Oct 2026, 15:00 — a rewritten page needs a new digest, still local
- After `index.html` is read again as `<h1>next</h1>`, digest `e618ccee` is refused and `c96eb153` is accepted. The file names stay `notes.txt`, `style.css`, and `index.html`. Leaving the page out of the list is still refused. The note and the stylesheet stay. The crash still holds. The grant string is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `8df3d5b514fd508b1a1db97b642767e80aac00fa097366203207eaba91c533f4`. No commit, no push, no PR.

## 13 Oct 2026, 15:10 — the older page can become current, still local
- Reading version 1 of `index.html` again makes `<h1>demo</h1>` current. A different wording of version 2 is refused, and `<h1>next</h1>` stays stored. The digest follows the current page. The crash still holds. The grant string is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `fd02ef2c0ef0d372203082b4b475674529c2d5ebebbcaa82c8dad1a0a51c94ea`. No commit, no push, no PR.

## 13 Oct 2026, 15:15 — reading the log keeps the current page, still local
- Reading the log back returns `<h1>demo</h1>` as the current page and keeps `<h1>next</h1>` as the newer wording. The note and the stylesheet stay. The grant string is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `31a65fcce038ec80bfc17713db506e64bc35c4fda2c0d37a30b6676c15327fd0`. No commit, no push, no PR.

## 13 Oct 2026, 15:20 — a host path does not join the project, still local
- A host path, a `..` path, a blank name, and a path with a space add nothing, and the log bytes stay the same. A file name `/tmp/out` is refused. Leaving the page out of the list is refused. The digest of the rewritten page is refused. The current digest is accepted. Shortening without a head, including a summary that is a host path, leaves the log as it is. Reading it back keeps `<h1>demo</h1>` and `<h1>next</h1>`. The grant string is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `625ea353ea7d3315894386cb10888803800fa90aded579db84a60af0bbebe8e7`. No commit, no push, no PR.

## 13 Oct 2026, 15:30 — shortening keeps the project reads, still local
- Giving the log a head lets it shorten. The head stays. The current page `<h1>demo</h1>`, the newer wording `<h1>next</h1>`, the note, and the stylesheet stay. A second shortening that does not shrink is refused. A host-path summary is refused. After that, the file list must still name all three files, and the digest must be the current page. The crash still holds. Reading the log back keeps the head and both page wordings. The grant string is not in the log.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `ff1e1e0457fc165ba3f2539ba80b919d91d6ba11b988c60a0ba00c2343cf5497`. No commit, no push, no PR.

## 13 Oct 2026, 15:45 — the version list is not a grant, still local
- The guest list for the page is version 1 `<h1>demo</h1>` and version 2 `<h1>next</h1>`. A host path and a blank name return nothing. Restoring the current wording records a proposal and does not change the page. Restoring the other wording is refused until it is read again. Sending the proposal with no grant is denied. This does not finish the Home screen. That screen is still the open slice.
- Seventy host tests pass. `./verify.sh` and `./run-local.sh` passed. Guest hash `1ae2926633577f625dbebe31f0cfe242ef31b613e963749e643126d7835f8416`. Checklist stays 50 of 62. No commit, no push, no PR.

## 13 Oct 2026, 15:35 — the provider invariant is written, still local
- Re-read DeepSeek `docs/tool-execution-pipeline.md`. The call is logged before the body. A denial skips the body. One result is the outcome. Home is the card, not the grant. `begin_exec` still does not call `VzProvider` or `CrosvmProvider`.
- Checklist is now 50 of 62. The grade stays 43 of 70. No guest code change. No commit, no push, no PR.

## 13 Oct 2026, 16:00 — Home version screen, still local
- Anders is not blocking Home testing. Selling to another Home stays his scope. The installed desktop at `localhost:61180` was left running.
- The spike Home GUI now has a Versions screen. It lists version 1 `<h1>demo</h1>` and version 2 `<h1>next</h1>`. Restoring version 2 is refused. Restoring version 1 prepares a restore and leaves the page as `<h1>demo</h1>`. Send is denied because the screen has no grant. A host path lists nothing. `scripts/home-version-list-smoke.mjs` passed on a fixture port. Checklist stays 50 of 62. No commit, no push, no PR.

## 13 Oct 2026, 19:10 — Versions opens from the ElastOS menu, still local
- The ElastOS menu reads `file_versions` on the Home summary. With the demo page, the sheet lists both wordings, refuses version 2, denies Send, and leaves the page as `<h1>demo</h1>`. A grant stuffed into that summary is not shown. A host path lists nothing. The menu closes when the sheet opens.
- The installed desktop at `localhost:61180` was left running. Its summary does not carry these reads yet, so that window does not show them. Checklist stays 50 of 62. No commit, no push, no PR.

## 13 Oct 2026, 19:25 — the Versions window reads the saved page, still local
- `examples/agent-host/file-versions.json` is the saved page. The journal test checks it. The Versions window loads that file. Version 2 is refused. Send is denied. The page stays `<h1>demo</h1>`. The open Home was left running and does not load this file. Checklist stays 50 of 62. No commit, no push, no PR.

## 13 Oct 2026, 19:35 — the open Home has the saved page, still local
- The Home already running on port 61180 was not restarted. Versions was added to its menu, and it loads the same saved page. Refresh that window, then choose Versions in the ElastOS menu. Checklist stays 50 of 62. No commit, no push, no PR.

## 13 Oct 2026, 19:42 — Versions is on the open Home
- Sasha opened the ElastOS menu and saw Versions. The saved page is `index.html`. Version 1 is `<h1>demo</h1>`. Version 2 is `<h1>next</h1>`. The list does not change the page. Checklist is 51 of 62. No commit, no push, no PR.

## 13 Oct 2026, 19:50 — Demo is in Apps, still local
- Apps has a Demo icon. Opening it shows the saved page. The running Home was not restarted. Checklist stays 51 of 62. No commit, no push, no PR.
- The first Demo window was blank because the page was hidden. The word demo is now drawn in the window. Sasha reloads and opens Demo again.

## 13 Oct 2026, 20:07 — Demo shows the word demo
- Sasha opened Demo and saw the word demo on a white page. Checklist is 52 of 62. No commit, no push, no PR.

## 13 Oct 2026, 20:15 — the same three approval answers, still local
- A tool and a hosted model share Once, This session, and Until I stop it. Missing permission is denied. The log is not uploaded. Approval is on the ElastOS menu and does not allow the action. Checklist stays 52 of 62. No commit, no push, no PR.

## 13 Oct 2026, 20:16 — Approval is on the open Home
- Sasha chose This session for the hosted model. The line said Not allowed. Checklist is 53 of 62. No commit, no push, no PR.

## 13 Oct 2026, 20:30 — the prompt head stays put, still local
- The model prompt is now the system line, then notes, then excerpts. Changing a note does not change the head. `--cache-ram` stays 0. Checklist is 55 of 62. No commit, no push, no PR.

## 13 Oct 2026, 20:35 — a repeated prompt line is counted, still local
- The same system line counts as extra tokens in the memory check. A different first line counts as zero. `--cache-ram` stays 0. Checklist stays 55 of 62. No commit, no push, no PR.

## 13 Oct 2026, 20:40 — long tool results are shortened, still local
- A tool result longer than 80 characters is cut before a summary. The head stays. No model is installed, so a model has not written the summary. Checklist stays 55 of 62. No commit, no push, no PR.

## 14 Oct 2026, 12:30 — Qwen wrote one summary, still local
- Qwen 3.8 27B, already on this computer, wrote: "The person greeted, the page was read as a demo, and the test result was okay." That sentence shortens the log and replays. The model was then stopped. The guest does not call it. Checklist stays 55 of 62. No commit, no push, no PR.

## 14 Oct 2026, 12:35 — the guest stores Qwen's sentence, still local
- The summary the guest keeps is now that sentence. 72 host tests passed. The loaded guest hash is `b4b9a2316dcc2f1e3ac18ff75b5abf34de8257c18ac0791a10301d9299598376`. The guest does not call the model. Checklist stays 55 of 62. No commit, no push, no PR.

## 14 Oct 2026, 13:15 — a long tool result is shortened before the sentence, still local
- The loaded guest now cuts a tool result longer than 80 bytes before it stores Qwen's sentence. A skill line is left out of that summary text. 72 host tests passed. The loaded guest hash is `c66119d20bd29ecf8b9fc1c834a1663a5ebcd243df520ba2f900fc95a407fade`. The guest does not call the model. Checklist stays 55 of 62. No commit, no push, no PR.

## 14 Oct 2026, 17:15 — a tiny model reused the opening line, still local
- A tiny public story model ran in llama.cpp, then the server was stopped. The first prompt used 13 tokens and reused none. The same prompt again reused 12. The same opening with a different next line reused 11. `--cache-ram` stays 0. This was not Home and not SmolLM2. Checklist stays 55 of 62. No commit, no push, no PR.

## 14 Oct 2026, 17:55 — the child keeps its own log, still local
- The child now has its own journal. The parent stores one line, "child result ok", and does not copy the child's log. The parent's permission is refused for the child. 72 host tests passed. The loaded guest hash is `fe9bcaa48669b10c9e7633f9ba7f34db1fcc65fa0dcc41ea1517c2dfc10f60c5`. This is not a second loaded component. Checklist stays 55 of 62. No commit, no push, no PR.

## 14 Oct 2026, 18:05 — two copies of the guest were loaded, still local
- The loader starts the guest twice. The two copies have different ids, and each start builds its own store. Both runs passed. They still share one test program. They are not two operating-system processes. The guest hash stays `fe9bcaa48669b10c9e7633f9ba7f34db1fcc65fa0dcc41ea1517c2dfc10f60c5`. Checklist stays 55 of 62. No commit, no push, no PR.

