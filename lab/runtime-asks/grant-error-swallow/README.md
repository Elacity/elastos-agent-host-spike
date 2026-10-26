# Grant-request Internal swallowed as a deny (for Anders, after 0.8.0)

This is a lab note. It is not a Runtime change. Nothing here lands in
elastos-runtime. The grant path lives in Elacity `develop` `92aeea44`
(`bus_error` in `elastos-compute`) and in this tree's Agent Host guest
(`examples/agent-host/src/lib.rs`, blob `ae50487d`). Every commit on the
Runtime files is the Runtime team's. The spike owns the guest copy.

## The gap

An internal error during a journal grant request can look like an ordinary
deny.

1. Runtime `bus_error` maps an unknown code to `BusError::Internal`
   (`elastos/crates/elastos-compute/src/providers/component.rs:289`).
   A8's undeclared-authority refusal uses `manifest_capability_denied`
   (`resource_bridge.rs:274`), which is not in the Denied list
   (`component.rs:271`), so it is Internal. A genuine operator deny uses
   code `denied` and is Denied.
2. Guest `WasmBus::request_grant` maps Internal to `BusFailure::Other`
   and drops the text (`examples/agent-host/src/lib.rs:4213`).
3. `request_journal_grants` uses `.ok()` (`lib.rs:3846`), so Other and
   Denied both become an empty grant. `run()` treats
   `(None, AppendOutcome::Denied)` as a normal deny and returns `Ok(())`
   (`lib.rs:8086`).

The caller sees `Ok` for both. The two outcomes are not distinguishable.

This is not 0.8.0 work. Treat it as a hunch from the A8 row on draft #301
until an independent party reviews it.

## Reproduction

`lab/runtime-asks/grant-error-swallow` injects the Runtime code at the
grant-request point. The Internal case uses `manifest_capability_denied`.
The control uses `denied`. Both then follow the shipped WasmBus map,
`.ok()`, and `run()`.

```bash
CARGO_TARGET_DIR=/workspace/target-lab-grant-error \
  cargo test --locked --manifest-path lab/runtime-asks/grant-error-swallow/Cargo.toml
```

Or `lab/runtime-asks/grant-error-swallow/run.sh` for twenty runs and the
planted falsifier.

## Trial patch

`lab/runtime-asks/grant-error-swallow/trial.patch` is a trial only. Apply
it to this tree, run the Agent Host host tests if you want, then restore
`examples/agent-host/src/lib.rs`. Do not land it here. Do not open a PR
on elastos-runtime.

The patch does one small thing: `request_journal_grants` returns
`Result`. A genuine `Denied` is still an empty grant. `Other` and
`Invalid` fail. `run()` maps `Other` to `BusError::Internal`, so the
caller sees an error, not `Ok`.

## How to prove

```bash
git hash-object examples/agent-host/src/lib.rs
git apply --check lab/runtime-asks/grant-error-swallow/trial.patch
export RUST_TEST_THREADS=2
export CARGO_TARGET_DIR=/workspace/target-lab-grant-error
lab/runtime-asks/grant-error-swallow/run.sh
# falsifier: set SWALLOW_INTERNAL = true; trial_propagates_internal_and_keeps_deny fails
git checkout -- examples/agent-host/src/lib.rs
git hash-object examples/agent-host/src/lib.rs
```

Results of the run that wrote this note:

- Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28).
- Verdict: **CONFIRMED**. Injected Internal and a genuine deny both return
  `OkDeny` on the shipped path. The trial path returns `Err` for Internal
  and `OkDeny` for deny.
- Ownership: Runtime `bus_error` Denied list and Internal default match
  Elacity `develop` `92aeea44`. Guest blob `ae50487d` before and after
  the trial apply.
- Pins (this tree): `.ok()` `examples/agent-host/src/lib.rs:3845-3846`;
  WasmBus Internal→Other `:4213-4218`; `run()` empty grants → Ok `:8086`;
  `bus_error` Denied `:271`, Internal `:289`;
  `manifest_capability_denied` `resource_bridge.rs:274`.
- Repro (unpatched / shipped path): lab suite 20 of 20.
  `injected_internal_is_reported_as_ordinary_deny` and
  `genuine_deny_is_also_ok` both `OkDeny`;
  `caller_cannot_tell_internal_from_deny` holds;
  `shipped_mapping_fails_the_trial_property` holds.
- Trial property (patched rule): `trial_propagates_internal_and_keeps_deny`
  Internal=`Err`, Denied=`OkDeny`, 20 of 20.
- Falsifier: `SWALLOW_INTERNAL=true` →
  `trial_propagates_internal_and_keeps_deny` panicked
  `SWALLOW_INTERNAL must stay false; the plant sets it`. Constant restored.
- `trial.patch` `git apply --check` clean. Applied once: `.ok()` gone;
  `tests::the_guest_asks_for_exactly_two_grants_on_its_own_journal`,
  `tests::a_refused_grant_request_sends_nothing`,
  `tests::no_grant_is_asked_for_a_path_outside_the_agents_journal` passed;
  then `git checkout --` restored `ae50487d`.
- Runtime files were not edited.

Not run here: a live `elastos serve` / wasm guest (the A8 Home path).
This lab injects at the grant-request mapping, with source pins. It does
not load `agent-host.component.wasm`. The full Agent Host suite was not
run. Nothing was pushed to elastos-runtime.

## Lab rule

`lab/runtime-asks/grant-error-swallow/src/lib.rs` is the same path in a
few lines, so a plant can turn the swallow back on.
`trial_propagates_internal_and_keeps_deny` must fail when
`SWALLOW_INTERNAL` is set to `true`.
