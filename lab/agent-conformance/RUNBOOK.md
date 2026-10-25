# Agent conformance checks

From the repository root on the Mac, with the shared heavy-build lease held, run:

```sh
lab/agent-conformance/run.sh
```

The command uses cached dependencies, the pinned Rust toolchain and its
`wasm32-unknown-unknown` target. Reserve 8 GiB for builds plus 2 GiB free. The
lease procedure is in [scripts/README.md](../../scripts/README.md#local-pre-push-gate).
The command prints `elastos sha256:<hex>` above the one table from Cargo's
test inventory and result lines. This identifies the binary built and exercised
in that run. The hash is computed each process and is specific to the machine
and toolchain; it is identification evidence, rather than a graded rule. A
failed Runtime build has no binary hash and makes its test rows FAIL.
`ok` becomes PASS. `ignored, blocked: <id> …` becomes BLOCKED with that ID.
A failure, missing result, repeated result, ignored test without a blocker ID,
or Cargo error gives FAIL and a non-zero command exit status. BLOCKED rows
remain open in [GAPS.md](GAPS.md).

- `home_is_throwaway`: checks the Mac data path, fresh root, path guard, symlink refusals and removal after success.
- `launch_env_is_only_the_throwaway_home`: checks the three allowed environment entries, null stdin, exit status and both output streams.
- `launch_stops_a_child_past_its_bound`: checks that a one-second bound stops a three-second sleep with the exact timeout reason.
- `run_without_operator_is_refused_with_reason`: runs the probe directory under a fresh Home and checks the nonzero exit and `This command requires a running runtime.` reason.
- `runtime_data_dir_is_under_throwaway_home`: writes a dummy coordinates file at the guarded data path, then checks that Runtime removes it and gives the same operator refusal. Its documentation address is rejected before network access.
- `run_table_requires_cargo_results`: checks PASS, BLOCKED and FAIL grading against Cargo-format result fixtures.
- `foreign_and_wrong_version_imports_are_refused`: rejects imports outside the probe's Bus subset.
- `non_component_and_invalid_component_are_refused`: rejects a core module and invalid component bytes.
- `probe_hash_is_stable`: compares the SHA-256 values from two fresh builds on this Mac.
- `probe_imports_only_the_bus`: checks the imports of both built components.
- `probe_manifest_names_the_current_bus_world`: checks the WIT hash and component manifest fields.
- `tests::probe_refuses_without_a_launch_argument_channel`: checks the probe's explicit unavailable result.
- `cargo` (failure only): Cargo could not supply a complete test inventory or finish the suite.

The harness owns each fresh root under this lane's ignored `target/`. It checks
HOME and the derived data path before reading those paths or starting a child.
The launch primitive clears the parent environment and sets HOME, TMPDIR and
the fixed system PATH. The environment test checks that complete allowlist.
F-ac1c selects the inherited HOME and proves the guard refuses it before any
read. These checks protect the real Home by construction; they never read its
data. The fixture stores a selector, rather than a user's Home path.

The Runtime build uses `cargo build --locked --offline --manifest-path
elastos/Cargo.toml -p elastos-server --bin elastos` in the normal toolchain
environment, with development debug info disabled. `runtime::runtime_under_test`
caches its result once per test process. Its target, build intermediates and
temporary files stay under `target/runtime`. The probe and Runtime builds share
`build::offline_build`; each Runtime launch uses `harness::ThrowawayHome::launch`.
The Runtime returns the operator refusal before it creates storage. Operator
launches and the AC-006-STORAGE blocker remain for later tasks.

F-ac1f changes the single harness data rule to the Linux path. The decoy test
then fails because Runtime leaves that decoy in place on the Mac. F-ac1g
changes only the probe Runtime ABI. The refusal test then fails on the changed
reason. Each named test passes again after its original bytes are restored.

A passed test removes its root. A failed test prints and retains its root for
inspection. A failed command also retains Cargo output under `target/run-table.*`.
Keep each failed root only until its result is reviewed, then remove that root.
The [falsifier list](falsifiers.json) owns the exact mutations; [LOG.md](LOG.md)
records their local runs. The provider lane owns the shared runner's `lab` arm;
until it is available, apply and restore each mutation by hand.
