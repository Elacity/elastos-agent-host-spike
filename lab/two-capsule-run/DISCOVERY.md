# Two-capsule run discovery

lab stand-in, not admission

This record states three facts about this tree: which component bytes the A3
half can load, whether a stand-in entry can take a bridge envelope line, and
whether the falsifier runner knows this crate. The test that reads this record
loads no component, starts nothing and calls no provider. A later run on this
Runtime is two concurrent bounded activations, not two resident instances. This
lane claims no A3 credit and no resident credit until the stand-in binds an
instance to its component hash.

## Record

component_sha256: unpublished
component_artifact: none
core_module_lab_cid: lab-cid:sha256:9ca715378b264e54614d2a231ee4d8e58e6a145873c55291fd02066aaf57f930
bridge_entry: none
agent_host_component: gap
agent_host_world: product-capsule-v1
agent_host_entrypoint: agent-host.component.wasm
agent_host_build: scripts/build-component-capsule.sh
agent_host_lifecycle_entry: impl exports::elastos::bus::lifecycle::Guest for AgentHost
agent_host_run: fn run() -> Result<(), elastos::bus::types::BusError>
agent_host_export: export!(AgentHost)
falsify_command: two-capsule-run

## Component bytes

`lab/wasm-capsule/LOG.md` has no line that contains both `component` and a
64-digit hex SHA-256. The component SHA-256 therefore stays unpublished and no
component artifact path exists. When such a line appears, the last matching
line in the append-only LOG names the newest change; the record stores that
SHA-256 together with an explicit artifact path, and the test hashes the named
file's bytes. Earlier matching lines are history, not a second target.

The core-module lab CID `lab-cid:sha256:9ca715378b264e54614d2a231ee4d8e58e6a145873c55291fd02066aaf57f930`
on LOG.md line 68 is not the component target: it names a core module. This
tree has no `*.wasm` under `lab/wasm-capsule/`.

## Bridge entry

`lab/agent-conformance/standin-runtime/mod.rs` has no public synchronous
`StandIn` method whose parameters after the receiver are
`(&str, &str, Option<&str>)` and whose return type is
`Result<String, String>`. The nearest method, `authorise`, takes
`Caller<'_>` and `request_id: &str` and returns
`Result<(), (u16, String)>`, so it is not the hostcall shape. A new unrelated
`StandIn` method leaves the bridge entry at none.

## Agent Host component

`examples/agent-host/src/lib.rs` declares:

```rust
world: "product-capsule-v1"
impl exports::elastos::bus::lifecycle::Guest for AgentHost
    fn run() -> Result<(), elastos::bus::types::BusError>
export!(AgentHost);
```

`examples/agent-host/build.sh` calls
`scripts/build-component-capsule.sh`, and `capsule.json` declares the
entrypoint `agent-host.component.wasm`. That file is absent on this tree, so
the build output is unverified and no component bytes exist to hash. The
missing artifact is not the A3 target.

## Falsifier command

The `PROVIDER_CRATES` table in `examples/agent-host/falsify.py` registers the
key `two-capsule-run` for the manifest `lab/two-capsule-run/Cargo.toml`, with no
extra Cargo arguments. The shared runner's `two-capsule-run` command therefore
covers this crate's tests. This crate adds no `falsifiers.json` and uses no
second test runner.
