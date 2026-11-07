# Exec cargo-test admission: reproducible falsifiers

Task 022, branch `spark/agent-host/022-admit-cargo-test-on-exec-path`.
Machine: macOS arm64. Every command below ran with
`RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`.

The registered `examples/agent-host/falsifiers.json` entries run only
`examples/agent-host/src/lib.rs` through `falsify.py`. The exec rules live in
`elastos/crates/elastos-compute/src/exec_vm.rs` and the initramfs, so their
falsifiers are the exact replacements below. Each replacement was applied once,
the named test ran, the stated failure was observed, and the original text was
put back. The final state reran green.

Commands:

```bash
cargo test --locked --manifest-path elastos/crates/elastos-compute/Cargo.toml \
  --lib cargo_is_not_in_the_image -- --test-threads=2
python3 scripts/build/test_build_exec_initrd.py
```

Named tests:

- `exec_vm::tests::cargo_is_not_in_the_image_and_an_unknown_command_does_not_launch`
  (`exec_vm.rs:764`)
- `BuildExecInitrd.test_the_init_runs_every_command_through_the_supervisor`
  (`scripts/build/test_build_exec_initrd.py:291`)

## Refusal reasons (`exec_vm.rs`)

The one match in `admit_exec_argv` (`exec_vm.rs:185`) now returns a distinct
reason for each refusal class: `command missing` (`:195`),
`cargo subcommand missing` (`:196`), `cargo test arguments refused` (`:197`),
`cargo operation refused` (`:198`), `command refused` (`:199`). `begin_exec`
propagates them unchanged. The named test asserts each exact string and zero
launcher calls for the four acceptance inputs (`exec_vm.rs:771-789`,
`:835-851`).

### R1: merge the cargo-test argument refusal into the unknown-command reason

Old:

```rust
        ["cargo", "test", _, ..] => Err("cargo test arguments refused"),
```

New:

```rust
        ["cargo", "test", _, ..] => Err("command refused"),
```

Observed: the named test failed on `["cargo", "test", "--offline"]`, `left:
Err("command refused") right: Err("cargo test arguments refused")`.

### R2: merge the cargo-operation refusal into the missing-subcommand reason

Old:

```rust
        ["cargo", _, ..] => Err("cargo operation refused"),
```

New:

```rust
        ["cargo", _, ..] => Err("cargo subcommand missing"),
```

Observed: the named test failed on `["cargo", "build"]`, `left: Err("cargo
subcommand missing") right: Err("cargo operation refused")`.

### R3: merge the empty-command refusal into the unknown-command reason

Old:

```rust
        [] => Err("command missing"),
```

New:

```rust
        [] => Err("command refused"),
```

Observed: the named test failed on `[]`, `left: Err("command refused") right:
Err("command missing")`.

### R4: refuse the admitted cargo test

Old:

```rust
        ["cargo", "test"] => Ok(ExecCommand::CargoTest),
```

New:

```rust
        ["cargo", "test"] => Err("cargo test arguments refused"),
```

Observed: the named test failed, `left: Err("cargo test arguments refused")
right: Ok(CargoTest)`.

### R5: name the admitted command with another token

Old:

```rust
            Self::CargoTest => "cargo-test",
```

New:

```rust
            Self::CargoTest => "test-pass",
```

Observed: the named test failed, `left: "test-pass" right: "cargo-test"`.

### R6: let a refused argv reach the launcher

Old (`begin_exec`):

```rust
    let command = admit_exec_argv(request.argv)?;
```

New:

```rust
    let command = admit_exec_argv(request.argv).unwrap_or(ExecCommand::CargoTest);
```

Observed: the named test failed on `["cargo"]`, `left: Ok(ExecBody {
exit_code: 0, log: "cargo test: ok", artifact: "" }) right: Err("cargo
subcommand missing")`.

### R7: block an admitted cargo test before the launcher

Old (`begin_exec`):

```rust
    let command = admit_exec_argv(request.argv)?;
```

New:

```rust
    let command = admit_exec_argv(request.argv)?;
    if command == ExecCommand::CargoTest {
        return Err("cargo operation refused");
    }
```

Observed: the named test failed, `left: Err("cargo operation refused") right:
Ok(0)`.

## Initramfs arm (`examples/exec-image/init:61`)

The test (`scripts/build/test_build_exec_initrd.py:291`) requires every arm to
call `run`, pins the exact operation `if [ -x /bin/cargo ]; then exec /bin/cargo
test; fi`, pins the reason and non-zero status `echo "init: cargo is not in the
image"; exit 1`, and rejects `/bin/cargo build` and `exit 0` (`:306-310`).

### I1: run cargo build instead of cargo test

New arm:

```sh
    cargo-test) run /bin/sh -c 'if [ -x /bin/cargo ]; then exec /bin/cargo build; fi; echo "init: cargo is not in the image"; exit 1' ;;
```

Observed: the initrd test failed with `'if [ -x /bin/cargo ]; then exec
/bin/cargo test; fi' not found in '... exec /bin/cargo build; ...'`.

### I2: report success when cargo is absent

New arm:

```sh
    cargo-test) run /bin/sh -c 'if [ -x /bin/cargo ]; then exec /bin/cargo test; fi; echo "init: cargo is not in the image"; exit 0' ;;
```

Observed: the initrd test failed with `'echo "init: cargo is not in the image";
exit 1' not found in '... exit 0'`.

### I3: bypass the supervisor

New arm:

```sh
    cargo-test) /bin/sh -c 'if [ -x /bin/cargo ]; then exec /bin/cargo test; fi; echo "init: cargo is not in the image"; exit 1' ;;
```

Observed: the initrd test failed with `') run ' not found in '... : cargo-test'`.

### I4: remove the clear reason

New arm:

```sh
    cargo-test) run /bin/sh -c 'if [ -x /bin/cargo ]; then exec /bin/cargo test; fi; exit 1' ;;
```

Observed: the initrd test failed with `'echo "init: cargo is not in the image";
exit 1' not found in '...'`.

### I5: remove the arm

Observed: the initrd test failed with `12 != 13` and the case list without
`cargo-test`.

## Final state after restoration

- named Rust test: `1 passed`.
- initrd test: `19 tests`, `OK (skipped=1)`.
- `examples/agent-host/verify.sh`: 215 passed, 2 ignored; capsule hash
  `12d02f29`.
- `examples/agent-host/run-local.sh`: 1 passed.
- `examples/agent-host/run-e2e.sh`: 3 passed.
- `falsify.py --self-test`: OK.
- `falsify.py`: 88 CAUGHT of 88.
- `cargo fmt --check` for `elastos-compute` and `elastos-vz`.
