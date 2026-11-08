# ElastOS Rust workspace

This directory contains the Cargo workspace for the Runtime libraries, the
`elastos` host binary, and the Rust capsules maintained with them. For
installation and product use, start with the repository
[README](../README.md).

Run Cargo workspace commands from this directory. From the repository root:

```bash
cd elastos
```

When running Cargo from the repository root, pass
`--manifest-path elastos/Cargo.toml`.

## Requirements

- Rust 1.91.0, pinned by the repository's
  [`rust-toolchain.toml`](../rust-toolchain.toml)
- Git

Platform requirements depend on the code path. Linux/crosvm microVM work
requires Linux and KVM. macOS source staging uses VZ; see the
[Mac runbook](../docs/MAC.md).

## Build

```bash
cargo build --workspace --release
./target/release/elastos --help
```

The `elastos-server` package produces the `elastos` binary.

## Navigate the code

- [`Cargo.toml`](Cargo.toml) is the source of truth for workspace members and
  shared Rust settings.
- [`crates/`](crates/) contains the Runtime libraries and the `elastos-server`
  host package.
- [`capsules/`](capsules/) contains the Rust capsules included in this
  workspace.
- [`tools/`](tools/) contains standalone Rust and JavaScript utilities. They are
  not built by `cargo build --workspace`; use each tool's own manifest or
  package file.
- [`wit/`](wit/) contains the checked-in ElastOS Bus interface.

## Testing

```bash
cargo test --workspace
cargo test -p elastos-runtime
```

From the repository root, `just test` runs both the Runtime workspace and the
own-workspace capsule suites, preparing the required provider binaries first.
Use `just test-elastos`, `just test-capsules` or `just test-crate <crate>` for
narrow checks. `just verify` adds the source, lint and contract gates; a plain
`cargo test --workspace` covers only this workspace.

## Core size budget

The trusted core is `crates/elastos-runtime`. The goal is about 10,000 lines of
code: small enough to review in full and to put on a chip, with everything
else in capsules. [`CORE-BUDGET`](CORE-BUDGET) holds the most code lines the
core may have, and the `core-size` CI job fails above it. From the repository
root:

```bash
python3 scripts/core-size.py           # the table
python3 scripts/core-size.py --check   # against the budget
```

Only code counts: no files under `tests/`, `tests.rs` or `*_test.rs`, no
`#[cfg(test)]` items, no comment lines and no blank lines. A line of code with
a trailing comment is code. To grow the core, raise `CORE-BUDGET` in the same
pull request, so reviewers see the growth. The budget ratchets down: when the
core falls more than 50 lines below it, the check fails until the same pull
request lowers the budget to the new count, so freed room cannot be spent
again.

## Related documentation

- [Architecture](../docs/ARCHITECTURE.md)
- [Command matrix](../docs/COMMAND_MATRIX.md)
- [Changelog](CHANGELOG.md)
