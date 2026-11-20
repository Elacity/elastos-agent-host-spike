grant-binding-002 lab/grant-binding/src/link.rs 6a0fbd834c87e1ff3f246158c0669670537ca1da sha256 0cc4da8b8931bd12c18c6d83b2f985542089ab8cfe5fe51f02e3c803f6c2f7f5

probe: test_escaped_path_dependency_matches_cargo
observed: detector returned false
cargo metadata package: grant-binding

## Rerun at 05ef91d9e06e3274fcbe6546aac757f591243382

Outcome: PASS (closed at the current target). Cargo resolves the escaped path,
and the current detector reports the grant-binding dependency.
Current target: lab/grant-binding/src/link.rs at 05ef91d9e06e3274fcbe6546aac757f591243382,
sha256 7ce2a880aad0773c7e94432cdc9f0c3257a8418394ccda4ae5937dabfc65145c.

Command: `python3 -I -m unittest discover -s py -p test_grant_replay.py -k test_escaped_path_dependency_matches_cargo -v`
Full log: `grant-binding-002-rerun.log` in the private S1 fix evidence folder.

Run output:

```text
escaped link outcome: failed
escaped metadata packages: escape-probe, grant-binding
detector returned true
ok

----------------------------------------------------------------------
Ran 1 test in 2.262s

OK
```
