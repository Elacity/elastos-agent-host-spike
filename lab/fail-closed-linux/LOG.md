# fail-closed-linux lab: log

- 26 Oct 2026, restore (branch `cursor/fail-closed-linux-recover`, base `spike/agent-host` at `563017a7`): the guard
  was restored byte for byte from the saved files of a session whose VM broke before it could commit. Its
  `RECOVERY.md`, `README.txt` and old `LOG.md` are left out: they describe that VM and hold results this session
  could not re-prove. Everything below was run in this session on the code at `753c4c4a`: Linux 6.12.94+ x86-64,
  rustc 1.91.0, Landlock ABI 6, an unprivileged user (uid 1000), `RUST_TEST_THREADS=2`.
  - `cargo fmt -- --check` and `cargo clippy --locked --all-targets -- -D warnings`: clean.
  - `cargo test --locked` on a cold build: `tests/real_kernel.rs` 14 passed, `tests/refusals.rs` 16 passed, and the
    same counts on five repeats. `FCL_ALLOW_UNCONFINABLE_HOST` was not set, so the test that starts a provider
    confined ran and did not return early.
  - `python3 -I falsify.py`: 26 of 26 planted bugs CAUGHT. Control `F-FC00` SURVIVED, as it must. The first run on a
    fresh checkout reported NOT RUN for all 27: the scratch copy built with cargo 1.83.0 (rustup's default) and
    not the pinned 1.91.0, and that cargo could not find `libc` offline. Fixed in `6fe2f18d`. I replayed
    `F-FC12`, `F-FC17`, `F-FC20` and `F-FC24` by hand and read the failure text; each fails at the assertion for
    its own bug. `F-FC12` fails with "the provider started although a layer failed".
  - `cargo check --locked --all-targets --target aarch64-unknown-linux-gnu`: compiles.
  - NOT RUN: any execution on aarch64 (no `qemu-user`, no `binfmt_misc` entry was made), any Jetson, any kernel
    other than this VM's, any kernel with a Landlock ABI below 5, a real-kernel test of the id-map refusal (the
    harness cannot single out those writes), real did, wallet or model provider binaries, and any call into
    `lab/linux-confine`.
