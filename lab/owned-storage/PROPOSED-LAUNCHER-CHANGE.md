# Proposed launcher change for AC-006-STORAGE

The real-Runtime rows in this crate are **BLOCKED**. No component was started.
`elastos` is not on `PATH`, and `elastos run` cannot take a per-instance
storage root. Applying this change belongs in the Runtime repo. This file
does not apply it.

## What the launcher does now

`elastos run` builds the runtime here, three times, with one literal:

```rust
let runtime = crate::create_runtime("/tmp/elastos/storage").await?;
```

The sites in `elastos/crates/elastos-server/src/run_cmd.rs` are:

- the `Data` capsule arm in `run_capsule`
- the fallback arm in `run_capsule`
- `run_component_via_operator_runtime`, which is the component path named by AC-006-STORAGE

`create_runtime` is `pub(crate)` in `elastos/crates/elastos-server/src/main.rs`.
A lab crate cannot call it. `elastos run` has no storage flag and no environment
variable for this path.

`elastos serve --storage-path` does pass its argument into `create_runtime`
(`elastos/crates/elastos-server/src/serve_cmd.rs`). That is not a substitute.
`Runtime` keeps the provider in `_storage` and does not serve object reads
from it:

```rust
// elastos/crates/elastos-server/src/runtime.rs
// Keep the storage provider alive for runtime/lifecycle ownership even
// before direct storage API calls are exposed from this layer.
_storage: Arc<dyn StorageProvider>,
```

Agent file bytes go through `rooted_localhost_fs_path` under the Home data
directory (`elastos/crates/elastos-common/src/localhost.rs`). The bridge
refuses a resource outside the manifest with `manifest_capability_denied`,
and a `Users` root without a principal with `principal_context_required`
(`elastos/crates/elastos-server/src/resource_bridge.rs`). Those refusals do
not consult `/tmp/elastos/storage`.

`elastos capsule` already avoids the shared literal. `run_component_capsule`
in `elastos/crates/elastos-server/src/capsule_cmd.rs` calls:

```rust
let runtime = crate::create_runtime(default_data_dir().join("storage")).await?;
```

It still requires an operator runtime and still does not, by itself, prove a
cross-agent read. `run` does not use this call.

## Minimal change

In `elastos/crates/elastos-server/src/run_cmd.rs`, replace each of the three
calls

```rust
let runtime = crate::create_runtime("/tmp/elastos/storage").await?;
```

with

```rust
let runtime = crate::create_runtime(crate::default_data_dir().join("storage")).await?;
```

`run_cmd.rs` already calls `crate::default_data_dir()`. On Linux that directory
is `$XDG_DATA_HOME/elastos` or `$HOME/.local/share/elastos`. One Home, one
storage directory. A lab wrapper can then give each process its own
`XDG_DATA_HOME` and each component client gets its own `storage` directory.
No new flag is required. This is the same expression `capsule_cmd.rs` uses.

That edit stops `elastos run` from creating `/tmp/elastos/storage`. It does
not by itself make agent A's read of B's file return a reason: object reads
still use the Home data directory, not the `LocalFSProvider` passed to
`create_runtime`.

## What a later proof needs

After the three replacements, a real proof is two component processes. Each
process has its own `XDG_DATA_HOME`. Each runs through `elastos run` (or
`elastos capsule` once an operator is up). Agent A asks the bridge to read
B's object. The captured bridge response carries a non-empty reason, and B's
bytes are unchanged. Until that run exists, the rows stay BLOCKED.
