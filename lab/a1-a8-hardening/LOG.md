# Log

## 26 Oct 2026: first runs (Linux x86_64)

Machine: Linux x86_64 cloud VM, rustc 1.91.0 (f8297e351 2025-10-28), no KVM.
Base: `spike/agent-host` at `b5069b992dac29d1457576efabd5700e34ea05e7`.
Elacity `develop` was not merged: this task may change only this folder.

### Rows

Command: `lab/a1-a8-hardening/run.sh` (after the falsifiers below, with the
Runtime source restored). Result: cargo exit 0, 1m57s.

```text
a1 runtime: elastos sha256 97c4cc2e31d6fe3b72413022cfc640829bd4f6d57ac6efd4cc40304eddfb7931
a1 wasi build: sha256 a6aa5328127a6c08cd2aee4aae4ef58cf5bb0ca0047e9e3089dedd0b4a33d884 imports ["wasi:cli/environment@0.2.0", "elastos:bus/types@1.0.0"]
a1 control build: sha256 b2eaaf6f054837ca0880218909766100214706fbaa9a098aba4fca72e06f6c4f imports ["elastos:bus/types@1.0.0"]
a1 refused run: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; allowed imports: elastos:bus/types@1.0.0, elastos:bus/runtime@1.0.0, elastos:bus/identity@1.0.0, elastos:bus/capabilities@1.0.0, elastos:bus/providers@1.0.0")
a1 control run: exit:Some(0) admitted_line:Some("[run] Component capsule 'a1-wasi-guest' exited")
a8 runtime: elastos sha256 97c4cc2e31d6fe3b72413022cfc640829bd4f6d57ac6efd4cc40304eddfb7931
a8 shipped agent-host: sha256 c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d imports ["elastos:bus/types@1.0.0", "elastos:bus/runtime@1.0.0", "elastos:bus/identity@1.0.0", "elastos:bus/capabilities@1.0.0", "elastos:bus/providers@1.0.0"]
a8 injected agent-host: sha256 9cff3664618f2ad65cd2ff4e0b3349568ee1f5b8ab159e78f8548e112eed8a96 imports ["elastos:bus/types@1.0.0", "elastos:bus/runtime@1.0.0", "elastos:bus/identity@1.0.0", "elastos:bus/capabilities@1.0.0", "elastos:bus/providers@1.0.0"]
a8 host key read: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Compute error: Component capsule denied: BusError::Internal(\"capsule manifest does not declare authority for localhost://Public/../../../../.ssh/id_ed25519\")") marker_absent:true unchanged:true

row | test | result
A1 | wasi_import_is_refused_at_admission | PASS
A8 | agent_host_host_key_read_is_refused | PASS
A8 | shipped_agent_host_bytes_read_host_key | BLOCKED (AC-002-ARGS; the shipped agent-host names only its own journal)
```

The same component hashes came out of every build in this session (the two
guest builds also match a manual trial build), so the builds were stable on
this machine. The `localhost-provider` hash is not printed; it is pinned in
each Home's `components.json` and verified by the Runtime at `serve`.

The first separate runs of each test file (before any falsifier) gave the same
lines: A1 passed in 189 s (including the provider and guest builds), A8 passed
in 39 s.

### Falsifiers

Command: `python3 lab/a1-a8-hardening/falsify.py <ID>`, one at a time.

| ID | Observed | Verdict |
| --- | --- | --- |
| F-A1a | The control build in the refused slot was admitted: `exit:Some(0) refusal_line:None`. The test failed at the refusal assertion (exit 101). | CAUGHT |
| F-A1-runtime | Runtime rebuilt with the allowlist check off (elastos sha256 `15f2aa61…`). The WASI build was still refused, now by the core-module check: `Error: Component capsule failed: Invalid manifest: component core module import "wasi:cli/environment@0.2.0::get-environment" is forbidden`. The exact-reason assertion failed (exit 101). | CAUGHT |
| F-A8a | The staged manifest declared the fake key. The request went on to the operator and stayed pending: `Component capsule denied: BusError::Internal("capability request still pending after 30s")`. Marker absent, key unchanged. The refusal assertion failed (exit 101). | CAUGHT |
| F-A8-runtime | Runtime rebuilt with the manifest refusal off (elastos sha256 `02099ce8…`). Same pending-request result as F-A8a. Marker absent, key unchanged. The refusal assertion failed (exit 101). | CAUGHT |

After each entry `falsify.py` restored the edited file and checked its SHA-256:

- `tests/a1_wasi_import.rs`: `ccf9fc61b70f4c0e6a9b7c44de03ecfbac9a76595bdf07ddb55e55a84d34f17a`
- `tests/a8_agent_host_host_key.rs`: `c20d3ba1dd15b3cb37ee587e27e6a68dfeed8290dd833f9e4105297476d27e2d`
- `elastos/crates/elastos-server/src/component.rs`: `7ef1dea5f1bcb725c08f8e54e347a23caa9856992007a2306b8289896a0da992`
- `elastos/crates/elastos-server/src/resource_bridge.rs`: `b8edb86cf709a23c1634e420691cf9916e07014f648009e19878285a3da076be`

`sha256sum -c` on both Runtime files matched the hashes taken before the first
Runtime falsifier, `git status` showed no Runtime change, and the final run's
rebuilt `elastos` has the original hash `97c4cc2e…`.

What the falsifiers show beyond "caught":

- A1: behind the allowlist, the Runtime's core-module import check refuses the
  same WASI import. The A1 row pins the allowlist reason, so it fails if the
  allowlist alone is removed.
- A8: behind the manifest bound, the next step is an operator decision. This
  operator (`dev_mode = true`, no shell attached) left the request pending, and
  the client gave up after 30 s. No grant reached the guest, so the provider's
  own `..` check was not reached in these runs.

### Cleanup

Passing runs removed their Homes. The four falsifier Homes (each holding only
its staged capsules and captures) were checked and removed by hand. No
`elastos` or `localhost-provider` process was left. `/tmp/elastos/storage`
exists as an empty directory from `elastos run` (AC-006-STORAGE); it was left
in place.
