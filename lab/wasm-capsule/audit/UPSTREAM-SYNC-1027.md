# 27 Oct sync import surfaces (027)

This report states which WASM import surfaces the 27 Oct upstream sync added
or changed, and whether `audit` or `audit_component` admits or refuses each one
under import audit API v1 as it stands. It claims no grade row.

## Base identity

- PR: <https://github.com/Elacity/elastos-agent-host-spike/pull/675>
  (`state` `MERGED`, base `spike/agent-host`).
- Merge commit: `b49c32552bd934c00a152c48819a2929aca056be`, parents
  `ba24246809268ece8e06f68e16a387d41442cc7e` and
  `d96bfad9bdab392a1ab0714f60679fc2f89de082`.
- `refs/remotes/spike/spike/agent-host` is that merge commit.
- This worktree's `HEAD` (`76bd1510…`) is not descended from the merge
  (`git merge-base HEAD b49c3255…` is `b7c613a1…`). All surfaces below were read
  from the merge tree with `git show` and `git diff`; no branch was checked out.

```console
$ gh pr view 675 --repo Elacity/elastos-agent-host-spike --json state,mergeCommit,baseRefName
{"baseRefName":"spike/agent-host","mergeCommit":{"oid":"b49c32552bd934c00a152c48819a2929aca056be"},"state":"MERGED"}

$ git rev-list --parents -n 1 b49c32552bd934c00a152c48819a2929aca056be
b49c32552bd934c00a152c48819a2929aca056be ba24246809268ece8e06f68e16a387d41442cc7e d96bfad9bdab392a1ab0714f60679fc2f89de082

$ git rev-parse refs/remotes/spike/spike/agent-host
b49c32552bd934c00a152c48819a2929aca056be
```

## Commands and file list

```console
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
```

`wc -l` on that output is 85. `git diff --name-only … -- elastos/wit`
alone is empty (0 lines): the sync changed no WIT file under `elastos/wit`.

```console
$ git diff --name-only b49c32552bd934c00a152c48819a2929aca056be^1 b49c32552bd934c00a152c48819a2929aca056be -- '*.wasm' '*.wat'
capsules/chat-room/browser/chat_room_ui_bg.wasm
```

Exactly one binary changed and no `.wat` file changed.

## What v1 does with these surfaces

`audit` reads core-module imports and `audit_component` reads top-level
Component imports. Admit below means the crate does not refuse: the exact import
text was declared, so the call returns `Ok` with the import in its result.
Refuse means the v1 variant and Display string. Neither call admits a capsule
for execution; the Runtime owns enforcement.

The changed binary is a core module. The audit runner declared the imports
returned by `audit` until the call returned `Ok`, so every byte was read by this
crate's one parser. No second parser read the binary. The extracted bytes match
the hashes in `.chat_room_ui_source.sha256`:

```console
$ sha256sum /tmp/sync1027-new.wasm /tmp/sync1027-old.wasm
6cfc8a3a2b5f8eae3c31d746894b7907d57b219059e29d9fa915f2a1d27f4ed8  /tmp/sync1027-new.wasm
f01cb4585c18aa0a7e67f3c668456f194aa4151877b33829c478db49dd87cf41  /tmp/sync1027-old.wasm
```

The new hash is the post-sync `browser_wasm_sha256` in
`capsules/chat-room-ui/.chat_room_ui_source.sha256`; the old hash is the
pre-sync value in the same file.

```console
$ cargo run --offline --quiet -- /tmp/sync1027-new.wasm /tmp/sync1027-old.wasm
== /tmp/sync1027-new.wasm ==
/tmp/sync1027-new.wasm: audit(empty) => Undeclared first wbg.__wbg_new_8a6f238a6ece86ea
/tmp/sync1027-new.wasm: audit total 162
/tmp/sync1027-new.wasm: audit_component(empty) => NotAComponent / not a component
/tmp/sync1027-new.wasm: audit_component(declared) => NotAComponent / not a component
== /tmp/sync1027-old.wasm ==
/tmp/sync1027-old.wasm: audit(empty) => Undeclared first wbg.__wbg_new_8a6f238a6ece86ea
/tmp/sync1027-old.wasm: audit total 159
/tmp/sync1027-old.wasm: audit_component(empty) => NotAComponent / not a component
/tmp/sync1027-old.wasm: audit_component(declared) => NotAComponent / not a component
```

The post-sync module has 162 imports and the pre-sync module 159. Comparing the
two returned lists gives nine names present after the sync and absent before,
and six names present before and absent after. Every import in both lists has
module `wbg`.

The nine added names are the functions the sync's regenerated
`capsules/chat-room/browser/chat_room_ui.js` defines on `imports.wbg`; each
name appears once there and the six removed names do not. The source reason is
`capsules/chat-room-ui/src/lib.rs` adding `AbortSignal` use and
`capsules/chat-room-ui/Cargo.toml` adding the `web-sys` `AbortSignal` feature.
The JavaScript file's definitions are the JS side of the same core imports, not
a second import surface.

## Import surfaces added or changed

Every changed path has a row. Rows with Kind `no import surface` have no
core-module import section and no Component or WIT import text in the diff.
JavaScript `import` statements are module loads, not WASM imports, and the
audited surface of `chat_room_ui.js` is the `wbg` import list of the `.wasm` it
glues.

| Path | Kind | Surface | Nothing declared | Exact surface declared |
| --- | --- | --- | --- | --- |
| `capsules/_shared/model-management.js` | no import surface | none | n/a | n/a |
| `capsules/archive-manager/browser/archive-manager.js` | no import surface | none | n/a | n/a |
| `capsules/assistant/browser/agent-harness.css` | no import surface | none | n/a | n/a |
| `capsules/assistant/browser/agent-harness.js` | no import surface | none | n/a | n/a |
| `capsules/assistant/browser/agent-live.js` | no import surface | none | n/a | n/a |
| `capsules/assistant/browser/agent-shelf.js` | no import surface | none | n/a | n/a |
| `capsules/assistant/browser/agent-stream.js` | no import surface | none | n/a | n/a |
| `capsules/assistant/browser/agent-workspace.js` | no import surface | none | n/a | n/a |
| `capsules/assistant/browser/harness-host.js` | no import surface | none | n/a | n/a |
| `capsules/assistant/browser/home-agent.js` | no import surface | none | n/a | n/a |
| `capsules/browser/browser/browser-clipboard.js` | no import surface | none | n/a | n/a |
| `capsules/browser/browser/browser-clipboard.test.mjs` | no import surface | none | n/a | n/a |
| `capsules/browser/browser/browser-input-surface.js` | no import surface | none | n/a | n/a |
| `capsules/browser/browser/browser-input-surface.test.mjs` | no import surface | none | n/a | n/a |
| `capsules/browser/browser/browser-input.js` | no import surface | none | n/a | n/a |
| `capsules/browser/browser/browser-remote-display.js` | no import surface | none | n/a | n/a |
| `capsules/browser/browser/browser.js` | no import surface | none | n/a | n/a |
| `capsules/browser/browser/index.html` | no import surface | none | n/a | n/a |
| `capsules/chain-provider/Cargo.lock` | no import surface | none | n/a | n/a |
| `capsules/chat-room-ui/.chat_room_ui_source.sha256` | no import surface | none | n/a | n/a |
| `capsules/chat-room-ui/Cargo.toml` | no import surface | none | n/a | n/a |
| `capsules/chat-room-ui/src/lib.rs` | no import surface | none | n/a | n/a |
| `capsules/chat-room/browser/chat-chrome.js` | no import surface | none | n/a | n/a |
| `capsules/chat-room/browser/chat_room_ui.js` | no import surface | none | n/a | n/a |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core function import (module `wbg`) | `wbg.__wbg_aborted_5324479d548fefa2` | `Undeclared { module: "wbg", name: "__wbg_aborted_5324479d548fefa2" }`, Display `undeclared import wbg.__wbg_aborted_5324479d548fefa2` | admitted; listed as `wbg.__wbg_aborted_5324479d548fefa2` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core function import (module `wbg`) | `wbg.__wbg_set_signal_dda2cf7ccb6bee0f` | `Undeclared { module: "wbg", name: "__wbg_set_signal_dda2cf7ccb6bee0f" }`, Display `undeclared import wbg.__wbg_set_signal_dda2cf7ccb6bee0f` | admitted; listed as `wbg.__wbg_set_signal_dda2cf7ccb6bee0f` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core function import (module `wbg`) | `wbg.__wbg_timeout_38cc9e1d85d89832` | `Undeclared { module: "wbg", name: "__wbg_timeout_38cc9e1d85d89832" }`, Display `undeclared import wbg.__wbg_timeout_38cc9e1d85d89832` | admitted; listed as `wbg.__wbg_timeout_38cc9e1d85d89832` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core function import (module `wbg`) | `wbg.__wbindgen_cast_033187b0d76e19c0` | `Undeclared { module: "wbg", name: "__wbindgen_cast_033187b0d76e19c0" }`, Display `undeclared import wbg.__wbindgen_cast_033187b0d76e19c0` | admitted; listed as `wbg.__wbindgen_cast_033187b0d76e19c0` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core function import (module `wbg`) | `wbg.__wbindgen_cast_084e932f9d940537` | `Undeclared { module: "wbg", name: "__wbindgen_cast_084e932f9d940537" }`, Display `undeclared import wbg.__wbindgen_cast_084e932f9d940537` | admitted; listed as `wbg.__wbindgen_cast_084e932f9d940537` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core function import (module `wbg`) | `wbg.__wbindgen_cast_5ffe8d2bb663a9d7` | `Undeclared { module: "wbg", name: "__wbindgen_cast_5ffe8d2bb663a9d7" }`, Display `undeclared import wbg.__wbindgen_cast_5ffe8d2bb663a9d7` | admitted; listed as `wbg.__wbindgen_cast_5ffe8d2bb663a9d7` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core function import (module `wbg`) | `wbg.__wbindgen_cast_61c78d73bd4a60c7` | `Undeclared { module: "wbg", name: "__wbindgen_cast_61c78d73bd4a60c7" }`, Display `undeclared import wbg.__wbindgen_cast_61c78d73bd4a60c7` | admitted; listed as `wbg.__wbindgen_cast_61c78d73bd4a60c7` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core function import (module `wbg`) | `wbg.__wbindgen_cast_8e41d7e73025f5e7` | `Undeclared { module: "wbg", name: "__wbindgen_cast_8e41d7e73025f5e7" }`, Display `undeclared import wbg.__wbindgen_cast_8e41d7e73025f5e7` | admitted; listed as `wbg.__wbindgen_cast_8e41d7e73025f5e7` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | core function import (module `wbg`) | `wbg.__wbindgen_cast_c6269665d8d90269` | `Undeclared { module: "wbg", name: "__wbindgen_cast_c6269665d8d90269" }`, Display `undeclared import wbg.__wbindgen_cast_c6269665d8d90269` | admitted; listed as `wbg.__wbindgen_cast_c6269665d8d90269` |
| `capsules/chat-room/browser/chat_room_ui_bg.wasm` | Component | none: core-module bytes, no Component imports | `NotAComponent`, Display `not a component` | `NotAComponent`, Display `not a component`; a declared interface cannot match core-module bytes |
| `capsules/custody-provider/Cargo.lock` | no import surface | none | n/a | n/a |
| `capsules/documents/browser/documents.js` | no import surface | none | n/a | n/a |
| `capsules/documents/browser/index.html` | no import surface | none | n/a | n/a |
| `capsules/home-gui/browser/home-gui-shell.js` | no import surface | none | n/a | n/a |
| `capsules/home-gui/browser/home-gui-template.html` | no import surface | none | n/a | n/a |
| `capsules/home-gui/browser/home-gui.js` | no import surface | none | n/a | n/a |
| `capsules/home-gui/browser/shell-setup-sheet.js` | no import surface | none | n/a | n/a |
| `capsules/home-gui/browser/shell-surface.js` | no import surface | none | n/a | n/a |
| `capsules/home-gui/browser/shell-windows.js` | no import surface | none | n/a | n/a |
| `capsules/home-gui/browser/style.css` | no import surface | none | n/a | n/a |
| `capsules/home/browser/home-clipboard-client.js` | no import surface | none | n/a | n/a |
| `capsules/home/browser/home-clipboard-client.test.mjs` | no import surface | none | n/a | n/a |
| `capsules/home/browser/home-clipboard-host.js` | no import surface | none | n/a | n/a |
| `capsules/home/browser/home-clipboard-host.test.mjs` | no import surface | none | n/a | n/a |
| `capsules/home/browser/home-clipboard-protocol.js` | no import surface | none | n/a | n/a |
| `capsules/home/browser/home-clipboard-protocol.test.mjs` | no import surface | none | n/a | n/a |
| `capsules/home/browser/home-shell-host.js` | no import surface | none | n/a | n/a |
| `capsules/home/browser/index.html` | no import surface | none | n/a | n/a |
| `capsules/home/browser/shell-auth.js` | no import surface | none | n/a | n/a |
| `capsules/home/browser/style.css` | no import surface | none | n/a | n/a |
| `capsules/inbox/browser/inbox.js` | no import surface | none | n/a | n/a |
| `capsules/inbox/browser/index.html` | no import surface | none | n/a | n/a |
| `capsules/ipfs-provider/Cargo.lock` | no import surface | none | n/a | n/a |
| `capsules/ipfs-provider/Cargo.toml` | no import surface | none | n/a | n/a |
| `capsules/ipfs-provider/src/directory_hash.rs` | no import surface | none | n/a | n/a |
| `capsules/ipfs-provider/src/main.rs` | no import surface | none | n/a | n/a |
| `capsules/library/browser/library.css` | no import surface | none | n/a | n/a |
| `capsules/library/browser/src/actions.js` | no import surface | none | n/a | n/a |
| `capsules/library/browser/src/actions.test.mjs` | no import surface | none | n/a | n/a |
| `capsules/library/browser/src/app.js` | no import surface | none | n/a | n/a |
| `capsules/library/browser/src/dialog.js` | no import surface | none | n/a | n/a |
| `capsules/library/browser/src/events.js` | no import surface | none | n/a | n/a |
| `capsules/library/browser/src/menu.js` | no import surface | none | n/a | n/a |
| `capsules/library/browser/src/model.js` | no import surface | none | n/a | n/a |
| `capsules/library/browser/src/render.js` | no import surface | none | n/a | n/a |
| `capsules/library/browser/src/selection.js` | no import surface | none | n/a | n/a |
| `capsules/library/browser/src/state.js` | no import surface | none | n/a | n/a |
| `capsules/marketplace/browser/index.html` | no import surface | none | n/a | n/a |
| `capsules/marketplace/browser/marketplace.css` | no import surface | none | n/a | n/a |
| `capsules/marketplace/browser/marketplace.js` | no import surface | none | n/a | n/a |
| `capsules/marketplace/browser/model-management.css` | no import surface | none | n/a | n/a |
| `capsules/marketplace/browser/model-management.js` | no import surface | none | n/a | n/a |
| `capsules/marketplace/browser/model-services.js` | no import surface | none | n/a | n/a |
| `capsules/media-provider/Cargo.lock` | no import surface | none | n/a | n/a |
| `capsules/model-provider/src/adapters.rs` | no import surface | none | n/a | n/a |
| `capsules/model-provider/src/execution.rs` | no import surface | none | n/a | n/a |
| `capsules/model-provider/src/journal.rs` | no import surface | none | n/a | n/a |
| `capsules/model-provider/src/local_llama.rs` | no import surface | none | n/a | n/a |
| `capsules/model-provider/src/local_memory.rs` | no import surface | none | n/a | n/a |
| `capsules/model-provider/src/test_support.rs` | no import surface | none | n/a | n/a |
| `capsules/object-provider/Cargo.lock` | no import surface | none | n/a | n/a |
| `capsules/people/browser/people.js` | no import surface | none | n/a | n/a |
| `capsules/protected-content-decrypt-provider/Cargo.lock` | no import surface | none | n/a | n/a |
| `capsules/protected-content-protect-provider/Cargo.lock` | no import surface | none | n/a | n/a |
| `capsules/system/browser/index.html` | no import surface | none | n/a | n/a |
| `capsules/system/browser/model-management.js` | no import surface | none | n/a | n/a |
| `capsules/system/browser/system.js` | no import surface | none | n/a | n/a |
| `capsules/wallet-provider/Cargo.lock` | no import surface | none | n/a | n/a |
| `capsules/wallet/browser/wallet-render.js` | no import surface | none | n/a | n/a |
| `capsules/wallet/browser/wallet.js` | no import surface | none | n/a | n/a |

## Surfaces the sync removed

These six names were in the pre-sync binary and are absent from the post-sync
binary. `audit` cannot return them for the post-sync bytes, so there is no
surface to declare. The regenerated JavaScript glue removed the matching
definitions.

- `wbg.__wbindgen_cast_0f76fca626397b3d`
- `wbg.__wbindgen_cast_30a893855537e77b`
- `wbg.__wbindgen_cast_35956445d45c659d`
- `wbg.__wbindgen_cast_9674205ec213e2ec`
- `wbg.__wbindgen_cast_dbbceaac3432bddd`
- `wbg.__wbindgen_cast_e4e79728745f57ee`

## Why each result follows from v1

- `audit` with nothing declared refuses the first import in section order:
  `Undeclared { module: "wbg", name: "__wbg_new_8a6f238a6ece86ea" }`, Display
  `undeclared import wbg.__wbg_new_8a6f238a6ece86ea`. A name is declared only
  when module and name both equal one `DeclaredImport` entry, so `wbg` is not
  special: the crate refuses because the entry is absent, not because of the
  module.
- `audit` with the exact `wbg.<name>` entry declared admits the import and lists
  it in import-section order. v1 does not compare the import kind, so the
  function kind of these imports is not part of the match.
- A declaration that lists only capsule-kernel imports refuses all nine, because
  no `wbg` entry is present. The audit does not define the capsule-kernel
  surface; the caller's declaration is the surface. The Runtime still owns
  enforcement.
- `audit_component` reads the same bytes as a Component. The encoding check runs
  before the import check, so a core module returns `NotAComponent`, Display
  `not a component`, with or without a declaration. The binary has no Component
  or WIT import string to declare.

## Asks for Flint

None. The nine added names are unversioned core function imports in module
`wbg`. No upstream name or version contradicts a sentence in `INTERFACE.md`;
the exact module-and-name rule and the `NotAComponent` sentence describe them
without change.

## Verification

```console
$ cargo fmt --manifest-path lab/wasm-capsule/audit/Cargo.toml -- --check
exit 0

$ cargo test --locked --manifest-path lab/wasm-capsule/audit/Cargo.toml
exit 0
```

This task adds no Rust, no test and no falsifier. The temporary audit runner
under `/tmp` was deleted after use. No upstream bytes were copied into this
crate.
