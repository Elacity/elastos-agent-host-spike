grant-binding-002 lab/grant-binding/src/link.rs 6a0fbd834c87e1ff3f246158c0669670537ca1da sha256 0cc4da8b8931bd12c18c6d83b2f985542089ab8cfe5fe51f02e3c803f6c2f7f5

probe: test_escaped_path_dependency_matches_cargo
observed: detector returned false
cargo metadata package: grant-binding

## Rerun at 261d7f2d654248902cbcb47fd63655d47cb1a02c

Outcome: PASS (closed at the current target). Cargo resolves the escaped path,
and the current detector reports the grant-binding dependency.
Current target: lab/grant-binding/src/link.rs at 8ec8a9b819fd629110a4b9e3be557c34d724cb0b,
sha256 8878c9786cdbb76ec117c560aca0749eb1bff21ad42066abe90e06fd7ff490b6.

Run output:

```text
escaped link outcome: failed
escaped metadata packages: escape-probe, grant-binding
detector returned true
test_escaped_path_dependency_matches_cargo ... ok
```
