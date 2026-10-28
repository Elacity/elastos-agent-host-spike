# Two-capsule run discovery

lab stand-in, not admission

This crate holds one check of [DISCOVERY.md](DISCOVERY.md) against this tree.
`discovery_matches_the_tree` in `tests/discovery.rs` reads the record and the
files it names. It loads no component, starts no activation and calls no
provider. The record states whether component bytes exist for the A3 half,
whether a stand-in entry takes a bridge envelope line, and whether the
falsifier runner knows this crate.

From the repository root:

```sh
cargo test --locked --manifest-path lab/two-capsule-run/Cargo.toml -- --nocapture discovery_matches_the_tree
```
