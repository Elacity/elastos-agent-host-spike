# Upstream sync, 27 October 2026: import surfaces

- PR: <https://github.com/Elacity/elastos-agent-host-spike/pull/675>, state `MERGED`
- Base branch: `spike/agent-host`
- Merge commit: `b49c32552bd934c00a152c48819a2929aca056be`
- Parents: `ba24246809268ece8e06f68e16a387d41442cc7e` and
  `d96bfad9bdab392a1ab0714f60679fc2f89de082`
- Audit API: v1. Classification ran against the crate source at the merge
  commit: `lab/wasm-capsule/audit/src/lib.rs` blob `6c3fc48f`, SHA-256
  `c90500513ac3b71fb3fb12ddc929900557fe9d60cccb5075abcea39d9978262d`.

On this base, the merge commit `b49c32552bd934c00a152c48819a2929aca056be` is an
ancestor of this worktree's HEAD. The classification still reads every upstream
path below at `b49c3255` with `git show` and audits every binary from those
bytes, so the report classifies the #675 merge tree.

`wasm-capsule-audit` is a static lab pre-check. It makes no admission, launch
or trust decision, and this report claims no grade row. One `.wasm` binary
changed; its core imports are classified below under v1. No Component or WIT
import changed.

## Commands and output

```sh
$ gh pr view 675 --repo Elacity/elastos-agent-host-spike --json state,mergeCommit,baseRefName
{"baseRefName":"spike/agent-host","mergeCommit":{"oid":"b49c32552bd934c00a152c48819a2929aca056be"},"state":"MERGED"}

$ git cat-file -p b49c32552bd934c00a152c48819a2929aca056be | head -6
tree 77f2d74c43e27c2df74fc52aa3cc61275653dde7
parent ba24246809268ece8e06f68e16a387d41442cc7e
parent d96bfad9bdab392a1ab0714f60679fc2f89de082
author Sash <sash@ela.city> 1793149253 +0800
committer GitHub <noreply@github.com> 1793149253 +0800

$ git diff --name-only b49c32552bd934c00a152c48819a2929aca056be^1 b49c32552bd934c00a152c48819a2929aca056be -- capsules elastos/wit
capsules/_shared/model-management.js
capsules/archive-manager/browser/archive-manager.js
capsules/assistant/browser/agent-harness.css
capsules/assistant/browser/agent-harness.js
capsules/assistant/browser/agent-live.js
capsules/assistant/browser/agent-shelf.js
capsules/assistant/browser/agent-stream.js
capsules/assistant/browser/agent-workspace.js
capsules/assistant/browser/harness-host.js
capsules/assistant/browser/home-agent.js
capsules/browser/browser/browser-clipboard.js
capsules/browser/browser/browser-clipboard.test.mjs
capsules/browser/browser/browser-input-surface.js
capsules/browser/browser/browser-input-surface.test.mjs
capsules/browser/browser/browser-input.js
capsules/browser/browser/browser-remote-display.js
capsules/browser/browser/browser.js
capsules/browser/browser/index.html
capsules/chain-provider/Cargo.lock
capsules/chat-room-ui/.chat_room_ui_source.sha256
capsules/chat-room-ui/Cargo.toml
capsules/chat-room-ui/src/lib.rs
capsules/chat-room/browser/chat-chrome.js
capsules/chat-room/browser/chat_room_ui.js
capsules/chat-room/browser/chat_room_ui_bg.wasm
capsules/custody-provider/Cargo.lock
capsules/documents/browser/documents.js
capsules/documents/browser/index.html
capsules/home-gui/browser/home-gui-shell.js
capsules/home-gui/browser/home-gui-template.html
capsules/home-gui/browser/home-gui.js
capsules/home-gui/browser/shell-setup-sheet.js
capsules/home-gui/browser/shell-surface.js
capsules/home-gui/browser/shell-windows.js
capsules/home-gui/browser/style.css
capsules/home/browser/home-clipboard-client.js
capsules/home/browser/home-clipboard-client.test.mjs
capsules/home/browser/home-clipboard-host.js
capsules/home/browser/home-clipboard-host.test.mjs
capsules/home/browser/home-clipboard-protocol.js
capsules/home/browser/home-clipboard-protocol.test.mjs
capsules/home/browser/home-shell-host.js
capsules/home/browser/index.html
capsules/home/browser/shell-auth.js
capsules/home/browser/style.css
capsules/inbox/browser/inbox.js
capsules/inbox/browser/index.html
capsules/ipfs-provider/Cargo.lock
capsules/ipfs-provider/Cargo.toml
capsules/ipfs-provider/src/directory_hash.rs
capsules/ipfs-provider/src/main.rs
capsules/library/browser/library.css
capsules/library/browser/src/actions.js
capsules/library/browser/src/actions.test.mjs
capsules/library/browser/src/app.js
capsules/library/browser/src/dialog.js
capsules/library/browser/src/events.js
capsules/library/browser/src/menu.js
capsules/library/browser/src/model.js
capsules/library/browser/src/render.js
capsules/library/browser/src/selection.js
capsules/library/browser/src/state.js
capsules/marketplace/browser/index.html
capsules/marketplace/browser/marketplace.css
capsules/marketplace/browser/marketplace.js
capsules/marketplace/browser/model-management.css
capsules/marketplace/browser/model-management.js
capsules/marketplace/browser/model-services.js
capsules/media-provider/Cargo.lock
capsules/model-provider/src/adapters.rs
capsules/model-provider/src/execution.rs
capsules/model-provider/src/journal.rs
capsules/model-provider/src/local_llama.rs
capsules/model-provider/src/local_memory.rs
capsules/model-provider/src/test_support.rs
capsules/object-provider/Cargo.lock
capsules/people/browser/people.js
capsules/protected-content-decrypt-provider/Cargo.lock
capsules/protected-content-protect-provider/Cargo.lock
capsules/system/browser/index.html
capsules/system/browser/model-management.js
capsules/system/browser/system.js
capsules/wallet-provider/Cargo.lock
capsules/wallet/browser/wallet-render.js
capsules/wallet/browser/wallet.js

$ git diff --name-only b49c32552bd934c00a152c48819a2929aca056be^1 b49c32552bd934c00a152c48819a2929aca056be -- '*.wasm' '*.wat'
capsules/chat-room/browser/chat_room_ui_bg.wasm
```

The first diff changed no file under `elastos/wit/`. The second diff found no
`.wat` file and one `.wasm` file.

The two crate gates ran from the repository root with
`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`.

```sh
$ cargo fmt --manifest-path lab/wasm-capsule/audit/Cargo.toml -- --check
exit 0

$ cargo test --locked --manifest-path lab/wasm-capsule/audit/Cargo.toml
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit 0
```

## How the surfaces were read

Audited bytes, both read with `git show`: the previous revision is 889084 bytes
with SHA-256
`f01cb4585c18aa0a7e67f3c668456f194aa4151877b33829c478db49dd87cf41`; the merge
revision is 900388 bytes with SHA-256
`6cfc8a3a2b5f8eae3c31d746894b7907d57b219059e29d9fa915f2a1d27f4ed8`, the same
hash that `capsules/chat-room-ui/.chat_room_ui_source.sha256` records for
`browser_wasm_sha256`.

A throwaway program under `/tmp` depended on the merge revision of this crate
and called only `audit` and `audit_component`. It read both revisions of the
binary with `git show`. It listed imports by declaring each refusal in turn,
then checked each surface with the declaration set complete except that one
surface. No other parser read the bytes. The program was deleted after use.

```text
old import count = 159
new import count = 162
new audit(all declared) = Ok(162) admitted
old audit(empty) = Undeclared { module: "wbg", name: "__wbg_new_8a6f238a6ece86ea" } "undeclared import wbg.__wbg_new_8a6f238a6ece86ea"
new audit(empty) = Undeclared { module: "wbg", name: "__wbg_new_8a6f238a6ece86ea" } "undeclared import wbg.__wbg_new_8a6f238a6ece86ea"
old audit_component(empty) = NotAComponent "not a component"
new audit_component(empty) = NotAComponent "not a component"
added = 9
removed = 6
```

Under v1, an import is admitted only when its module and name both equal a
declared entry; v1 does not compare the import kind, so an import whose kind
changed under the same module and name reads the same here.
`audit` returns the first undeclared import in section order,
so nothing declared always refuses `wbg.__wbg_new_8a6f238a6ece86ea`, and a
lone declaration of a later import also fails there. The last column gives the
decision for that surface when the module's earlier imports are declared too;
leaving that surface out of the complete declaration set returns `Undeclared`
naming it. Declaring every import returns `Ok(162)`.

## Import surfaces

| Path | Kind | Surface | Nothing declared | That exact surface declared |
| --- | --- | --- | --- | --- |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | Component import check | none: core module | `NotAComponent` → `not a component` | `NotAComponent` → `not a component` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (added) | `wbg.__wbg_timeout_38cc9e1d85d89832` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | admitted, `Ok(162)`; omitted → `undeclared import wbg.__wbg_timeout_38cc9e1d85d89832` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (added) | `wbg.__wbg_aborted_5324479d548fefa2` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | admitted, `Ok(162)`; omitted → `undeclared import wbg.__wbg_aborted_5324479d548fefa2` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (added) | `wbg.__wbg_set_signal_dda2cf7ccb6bee0f` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | admitted, `Ok(162)`; omitted → `undeclared import wbg.__wbg_set_signal_dda2cf7ccb6bee0f` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (added) | `wbg.__wbindgen_cast_8e41d7e73025f5e7` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | admitted, `Ok(162)`; omitted → `undeclared import wbg.__wbindgen_cast_8e41d7e73025f5e7` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (added) | `wbg.__wbindgen_cast_c6269665d8d90269` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | admitted, `Ok(162)`; omitted → `undeclared import wbg.__wbindgen_cast_c6269665d8d90269` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (added) | `wbg.__wbindgen_cast_084e932f9d940537` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | admitted, `Ok(162)`; omitted → `undeclared import wbg.__wbindgen_cast_084e932f9d940537` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (added) | `wbg.__wbindgen_cast_5ffe8d2bb663a9d7` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | admitted, `Ok(162)`; omitted → `undeclared import wbg.__wbindgen_cast_5ffe8d2bb663a9d7` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (added) | `wbg.__wbindgen_cast_61c78d73bd4a60c7` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | admitted, `Ok(162)`; omitted → `undeclared import wbg.__wbindgen_cast_61c78d73bd4a60c7` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (added) | `wbg.__wbindgen_cast_033187b0d76e19c0` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | admitted, `Ok(162)`; omitted → `undeclared import wbg.__wbindgen_cast_033187b0d76e19c0` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (removed) | `wbg.__wbindgen_cast_0f76fca626397b3d` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | absent from the new module; declaration unused, `Ok(162)`; on the previous bytes omitted → `undeclared import wbg.__wbindgen_cast_0f76fca626397b3d` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (removed) | `wbg.__wbindgen_cast_35956445d45c659d` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | absent from the new module; declaration unused, `Ok(162)`; on the previous bytes omitted → `undeclared import wbg.__wbindgen_cast_35956445d45c659d` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (removed) | `wbg.__wbindgen_cast_e4e79728745f57ee` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | absent from the new module; declaration unused, `Ok(162)`; on the previous bytes omitted → `undeclared import wbg.__wbindgen_cast_e4e79728745f57ee` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (removed) | `wbg.__wbindgen_cast_dbbceaac3432bddd` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | absent from the new module; declaration unused, `Ok(162)`; on the previous bytes omitted → `undeclared import wbg.__wbindgen_cast_dbbceaac3432bddd` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (removed) | `wbg.__wbindgen_cast_30a893855537e77b` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | absent from the new module; declaration unused, `Ok(162)`; on the previous bytes omitted → `undeclared import wbg.__wbindgen_cast_30a893855537e77b` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core import (removed) | `wbg.__wbindgen_cast_9674205ec213e2ec` | `Undeclared` → `undeclared import wbg.__wbg_new_8a6f238a6ece86ea` | absent from the new module; declaration unused, `Ok(162)`; on the previous bytes omitted → `undeclared import wbg.__wbindgen_cast_9674205ec213e2ec` |
| `capsules/_shared/model-management.js` | JavaScript | none: no import surface | — | — |
| `capsules/archive-manager/browser/archive-manager.js` | JavaScript | none: no import surface | — | — |
| `capsules/assistant/browser/agent-harness.css` | CSS | none: no import surface | — | — |
| `capsules/assistant/browser/agent-harness.js` | JavaScript | none: no import surface | — | — |
| `capsules/assistant/browser/agent-live.js` | JavaScript | none: no import surface | — | — |
| `capsules/assistant/browser/agent-shelf.js` | JavaScript | none: no import surface | — | — |
| `capsules/assistant/browser/agent-stream.js` | JavaScript | none: no import surface | — | — |
| `capsules/assistant/browser/agent-workspace.js` | JavaScript | none: no import surface | — | — |
| `capsules/assistant/browser/harness-host.js` | JavaScript | none: no import surface | — | — |
| `capsules/assistant/browser/home-agent.js` | JavaScript | none: no import surface | — | — |
| `capsules/browser/browser/browser-clipboard.js` | JavaScript | none: no import surface | — | — |
| `capsules/browser/browser/browser-clipboard.test.mjs` | JavaScript test | none: no import surface | — | — |
| `capsules/browser/browser/browser-input-surface.js` | JavaScript | none: no import surface | — | — |
| `capsules/browser/browser/browser-input-surface.test.mjs` | JavaScript test | none: no import surface | — | — |
| `capsules/browser/browser/browser-input.js` | JavaScript | none: no import surface | — | — |
| `capsules/browser/browser/browser-remote-display.js` | JavaScript | none: no import surface | — | — |
| `capsules/browser/browser/browser.js` | JavaScript | none: no import surface | — | — |
| `capsules/browser/browser/index.html` | HTML | none: no import surface | — | — |
| `capsules/chain-provider/Cargo.lock` | Cargo lockfile | none: no import surface | — | — |
| `capsules/chat-room-ui/.chat_room_ui_source.sha256` | source hash record | none: no import surface | — | — |
| `capsules/chat-room-ui/Cargo.toml` | Cargo manifest | none: no import surface | — | — |
| `capsules/chat-room-ui/src/lib.rs` | Rust | none in source: this file compiles the module whose imports are the rows above | — | — |
| `capsules/chat-room/browser/chat-chrome.js` | JavaScript | none: no import surface | — | — |
| `capsules/chat-room/browser/chat_room_ui.js` | JavaScript | none: no import surface | — | — |
| `capsules/custody-provider/Cargo.lock` | Cargo lockfile | none: no import surface | — | — |
| `capsules/documents/browser/documents.js` | JavaScript | none: no import surface | — | — |
| `capsules/documents/browser/index.html` | HTML | none: no import surface | — | — |
| `capsules/home-gui/browser/home-gui-shell.js` | JavaScript | none: no import surface | — | — |
| `capsules/home-gui/browser/home-gui-template.html` | HTML | none: no import surface | — | — |
| `capsules/home-gui/browser/home-gui.js` | JavaScript | none: no import surface | — | — |
| `capsules/home-gui/browser/shell-setup-sheet.js` | JavaScript | none: no import surface | — | — |
| `capsules/home-gui/browser/shell-surface.js` | JavaScript | none: no import surface | — | — |
| `capsules/home-gui/browser/shell-windows.js` | JavaScript | none: no import surface | — | — |
| `capsules/home-gui/browser/style.css` | CSS | none: no import surface | — | — |
| `capsules/home/browser/home-clipboard-client.js` | JavaScript | none: no import surface | — | — |
| `capsules/home/browser/home-clipboard-client.test.mjs` | JavaScript test | none: no import surface | — | — |
| `capsules/home/browser/home-clipboard-host.js` | JavaScript | none: no import surface | — | — |
| `capsules/home/browser/home-clipboard-host.test.mjs` | JavaScript test | none: no import surface | — | — |
| `capsules/home/browser/home-clipboard-protocol.js` | JavaScript | none: no import surface | — | — |
| `capsules/home/browser/home-clipboard-protocol.test.mjs` | JavaScript test | none: no import surface | — | — |
| `capsules/home/browser/home-shell-host.js` | JavaScript | none: no import surface | — | — |
| `capsules/home/browser/index.html` | HTML | none: no import surface | — | — |
| `capsules/home/browser/shell-auth.js` | JavaScript | none: no import surface | — | — |
| `capsules/home/browser/style.css` | CSS | none: no import surface | — | — |
| `capsules/inbox/browser/inbox.js` | JavaScript | none: no import surface | — | — |
| `capsules/inbox/browser/index.html` | HTML | none: no import surface | — | — |
| `capsules/ipfs-provider/Cargo.lock` | Cargo lockfile | none: no import surface | — | — |
| `capsules/ipfs-provider/Cargo.toml` | Cargo manifest | none: no import surface | — | — |
| `capsules/ipfs-provider/src/directory_hash.rs` | Rust | none: no import surface | — | — |
| `capsules/ipfs-provider/src/main.rs` | Rust | none: no import surface | — | — |
| `capsules/library/browser/library.css` | CSS | none: no import surface | — | — |
| `capsules/library/browser/src/actions.js` | JavaScript | none: no import surface | — | — |
| `capsules/library/browser/src/actions.test.mjs` | JavaScript test | none: no import surface | — | — |
| `capsules/library/browser/src/app.js` | JavaScript | none: no import surface | — | — |
| `capsules/library/browser/src/dialog.js` | JavaScript | none: no import surface | — | — |
| `capsules/library/browser/src/events.js` | JavaScript | none: no import surface | — | — |
| `capsules/library/browser/src/menu.js` | JavaScript | none: no import surface | — | — |
| `capsules/library/browser/src/model.js` | JavaScript | none: no import surface | — | — |
| `capsules/library/browser/src/render.js` | JavaScript | none: no import surface | — | — |
| `capsules/library/browser/src/selection.js` | JavaScript | none: no import surface | — | — |
| `capsules/library/browser/src/state.js` | JavaScript | none: no import surface | — | — |
| `capsules/marketplace/browser/index.html` | HTML | none: no import surface | — | — |
| `capsules/marketplace/browser/marketplace.css` | CSS | none: no import surface | — | — |
| `capsules/marketplace/browser/marketplace.js` | JavaScript | none: no import surface | — | — |
| `capsules/marketplace/browser/model-management.css` | CSS | none: no import surface | — | — |
| `capsules/marketplace/browser/model-management.js` | JavaScript | none: no import surface | — | — |
| `capsules/marketplace/browser/model-services.js` | JavaScript | none: no import surface | — | — |
| `capsules/media-provider/Cargo.lock` | Cargo lockfile | none: no import surface | — | — |
| `capsules/model-provider/src/adapters.rs` | Rust | none: no import surface | — | — |
| `capsules/model-provider/src/execution.rs` | Rust | none: no import surface | — | — |
| `capsules/model-provider/src/journal.rs` | Rust | none: no import surface | — | — |
| `capsules/model-provider/src/local_llama.rs` | Rust | none: no import surface | — | — |
| `capsules/model-provider/src/local_memory.rs` | Rust | none: no import surface | — | — |
| `capsules/model-provider/src/test_support.rs` | Rust | none: no import surface | — | — |
| `capsules/object-provider/Cargo.lock` | Cargo lockfile | none: no import surface | — | — |
| `capsules/people/browser/people.js` | JavaScript | none: no import surface | — | — |
| `capsules/protected-content-decrypt-provider/Cargo.lock` | Cargo lockfile | none: no import surface | — | — |
| `capsules/protected-content-protect-provider/Cargo.lock` | Cargo lockfile | none: no import surface | — | — |
| `capsules/system/browser/index.html` | HTML | none: no import surface | — | — |
| `capsules/system/browser/model-management.js` | JavaScript | none: no import surface | — | — |
| `capsules/system/browser/system.js` | JavaScript | none: no import surface | — | — |
| `capsules/wallet-provider/Cargo.lock` | Cargo lockfile | none: no import surface | — | — |
| `capsules/wallet/browser/wallet-render.js` | JavaScript | none: no import surface | — | — |
| `capsules/wallet/browser/wallet.js` | JavaScript | none: no import surface | — | — |

## Asks for Flint

None.
