# The Linux design for the one file-profile contract

The providers are not confined on Linux today, and nothing in this file is
current behaviour. It covers the one contract that `did-provider`,
`wallet-provider` and `model-provider` present: `check_profile_contract`, run
over `FILE_PROFILES` in `tests/confine.rs`, with `(version 1)` first,
`(deny default)` second, an explicit `(deny network*)`, no `(allow default)`,
no network allow, only the `PROVIDER_EXECUTABLE`, `STORAGE_ROOT` and
`STORAGE_PARENT` tokens, and the three shared rules verbatim. `confine.sb` stays
each provider's one oracle. The contract is shared, so its Linux mapping is
written once here, beside the one contract check (P10). The Linux policy that
the Runtime would generate from the same approved declared rights must carry
each oracle rule as this file maps it, and no second profile file exists (P10).

## The frame

The Runtime generates each provider's policy from the provider's approved
declared rights. On Linux the same generator would emit one launch
specification instead of a Seatbelt text: a user namespace, a mount namespace,
a network namespace, a PID namespace and an IPC namespace; every capability
dropped; `no_new_privs` set before any filter; one seccomp filter; and one
Landlock ruleset. The three parameters keep their names and bind to the same
paths as on macOS: `PROVIDER_EXECUTABLE` is the provider binary; for
`did-provider`, `STORAGE_ROOT` is `Init.base_path/did` and `STORAGE_PARENT` is
`Init.base_path`; for `wallet-provider`, `STORAGE_ROOT` is
`base_path/ElastOS/SystemServices/Wallet` and `STORAGE_PARENT` is
`base_path/ElastOS/SystemServices`; the model profile states its own root.

The Linux policy holds no path rule beyond those three: it adds none for `/`,
for `/proc` or for a library directory. The private `/proc` mount the mount
namespace provides is a mount, not a grant. The policy is a second rendering of
the same rights, and the one contract check stays the one check of the oracle.

The Linux policy would be applied before the provider image is entered. This
file is a design: each row names the Linux test that would prove it, none of
those tests exists yet, and no sentence here claims that any provider is
confined on Linux.

## The contract on Linux

| Oracle rule | Linux primitive that would carry it | How exact the match is | Linux test that would prove it |
| --- | --- | --- | --- |
| `(version 1)` | The generator's policy version; no kernel primitive carries it. | Exact: the generator emits one version, and the contract check refuses any other head. | `both_file_profiles_bind_one_storage_parameter_contract` |
| `(deny default)`, files | A Landlock ruleset whose only path rules are the three parameters; every file right not beneath a rule fails. The capability drop removes `CAP_DAC_READ_SEARCH` and `CAP_DAC_OVERRIDE`, so privilege grants no file right. | Exact for every access right the ABI reports. Narrower where the ABI lacks a right; the start is then refused, never weakened. Wider only where a rule on a directory covers the tree beneath it, as the next section says. | `outside_write_denied`, `outside_read_denied`, `confined_outside_write_is_denied` and `confined_outside_read_is_denied` |
| `(deny default)`, processes and signals | A PID namespace; the empty capability set; a seccomp filter that refuses process creation other than the provider's own threads, exec of any file other than `PROVIDER_EXECUTABLE`, and every cross-process operation (`ptrace`, `process_vm_*`, `pidfd_getfd`). Landlock `EXECUTE` also pins the one binary. | Exact for signals: a PID namespace contains no PID outside itself, so a signal to a host process cannot be expressed. Narrower for process creation because the provider's threads must start: the filter admits the thread form of `clone` and refuses a new process. The Linux test decides the exact flag set. | `confined_provider_denies_process_and_signal_boundaries` |
| `(deny default)`, IPC | An IPC namespace; seccomp refusing every `socket` and `socketpair` family, SysV IPC creation and POSIX message queues; Landlock's default denial refusing reads and writes to shared-memory files. | Exact for host IPC objects: a private IPC namespace cannot name them. Narrower for new objects if the provider needs none. The Linux test decides. | `confined_provider_denies_ipc_boundaries` |
| `(deny default)`, kernel facts | A private, read-only `/proc` mount limited to the provider's own PID namespace and a hidden host `/sys`; Landlock denying reads outside the granted paths; seccomp refusing syscalls that read host kernel state (`bpf`, `perf_event_open`). | No exact match: the oracle denies every kernel-fact operation except `sysctl-read`, and Linux splits kernel facts across `/proc`, `/sys` and syscalls, so the map is wider in one place and narrower in another. The Linux test decides. | `confined_provider_denies_kernel_fact_boundaries` |
| `(deny network*)`, with no network allow | A network namespace with no interface and no route; the empty capability set; seccomp refusing `socket` and `socketpair` for every family, `AF_UNIX` included, and refusing `connect`, `sendmsg`, `recvmsg`, `pidfd_getfd` and `process_vm_*` so no descriptor can arrive from outside. | Exact for every family the oracle refuses: the filter names each family, Unix-domain included, and the namespace removes every interface. macOS puts a Unix-domain connect under `network*` (cc-model-confine 010, macOS 26.5.2), so this row covers it too. | `profile_denies_network` (the oracle text) and `linux_profile_denies_every_socket_family` (the policy) |
| no `(allow default)` | The generator emits only the rights the oracle grants; the launch adds no permissive rule. | Exact: the Linux policy has no permissive term, and the one contract check refuses one in the oracle. | `both_file_profiles_bind_one_storage_parameter_contract` and `file_profile_contract_rejects_an_allow_default` |
| Only `PROVIDER_EXECUTABLE`, `STORAGE_ROOT` and `STORAGE_PARENT` | The same three parameters, bound to the same paths; the launch specification accepts no other path. | Exact: no other path enters the policy. | `both_file_profiles_bind_one_storage_parameter_contract` and `file_profile_contract_rejects_a_non_canonical_token` |
| `(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))` | Landlock `EXECUTE` on the file named by `PROVIDER_EXECUTABLE`; seccomp refuses every exec of any other file. | Exact: a Landlock rule on a file grants only that file, and the oracle's `literal` names only that file. | `confined_provider_serves_did_operations_under_its_root` and `confined_provider_serves_wallet_operations_under_its_root` |
| `(allow file-read* (literal "/"))` | No path rule. The nearest rule is a Landlock read rule on `/`, which would grant the whole tree and be a fourth path, so the design does not use it. | No exact match: the nearest rule is wider (all files) and the design's mapping is narrower (no rule). The Linux test decides whether the loader starts without it. | `confined_provider_serves_did_operations_under_its_root` and `confined_provider_serves_wallet_operations_under_its_root` |
| `(allow sysctl-read)` | Seccomp allows the kernel-fact syscalls the loader and the allocator use; no path rule. Landlock has no sysctl right. | No exact match: the oracle grants every sysctl read, and the filter is narrower (named syscalls only). The Linux test decides the set. | `confined_provider_serves_did_operations_under_its_root`, `confined_provider_serves_wallet_operations_under_its_root` and `confined_provider_denies_kernel_fact_boundaries` |
| `(allow file-read* (literal (param "STORAGE_PARENT")))` | A Landlock read rule on `STORAGE_PARENT`. | No exact match: a Landlock rule on a directory covers the whole tree beneath it, so it is wider than a literal read of the directory alone. The Linux test decides whether the wider rule still refuses the outside read. | `outside_read_denied` and `confined_outside_read_is_denied` |
| `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))` | Landlock read and write rights on `STORAGE_ROOT`, covering its tree. | Exact for the path: a rule beneath `STORAGE_ROOT` covers the same subtree as the oracle's `subpath`. The rights are exact only when the ABI reports every right the oracle's read and write cover; a missing right (`REFER`, `TRUNCATE`, `IOCTL_DEV`) makes the row narrower, and the start is refused. | `confined_provider_serves_did_operations_under_its_root`, `confined_provider_serves_wallet_operations_under_its_root`, `outside_write_denied` and `confined_outside_write_is_denied` |
| `(allow file-read-data (literal "/"))` (model profile) | No path rule, for the same reason as the read of `/`. | No exact match: the nearest rule, a read rule on `/`, is wider (data and metadata for all files); the design's mapping is narrower (no rule). The Linux test decides. | `model_provider_ops_under_profile` (the model provider's named test) and `both_file_profiles_bind_one_storage_parameter_contract` |

The five allow rules cover `model-provider` too. The table names the model
profile only where it differs: it presents `(allow file-read-data (literal
"/"))` instead of the shared `(allow file-read* (literal "/"))`, and the model
provider's own document states its storage root.

## Rows with no exact Linux match

Four rows have no exact Linux rule. Each says which way its nearest rule
departs from the oracle, and the Linux test decides the row.

- The literal read of `STORAGE_PARENT` alone. A Landlock rule on
  `STORAGE_PARENT` covers the whole tree beneath it, so the nearest rule is
  wider than the oracle. If the wider rule makes the outside read succeed, the
  mapping fails `outside_read_denied` or `confined_outside_read_is_denied`, and
  the design does not accept the row: the start is refused until a rule that
  matches the oracle exists.
- The read of `/`. A Landlock read rule on `/` would grant the whole filesystem
  and add a fourth path, so the nearest rule is wider than the oracle. The
  design's mapping is narrower: no rule. The Linux test decides whether the
  loader starts without it.
- `(allow sysctl-read)`. Landlock has no sysctl right. The nearest rule, a
  seccomp allowance of the fact syscalls the loader and the allocator use, is
  narrower than the oracle's grant of every sysctl read. The Linux test decides
  the set.
- The model profile's `file-read-data (literal "/")`. It is the same case as
  the read of `/`, and the nearest read rule on `/` is wider in both path and
  access kind. The Linux test decides.

## Open questions

These are open questions for the Linux tests, not facts:

- Which reads the loader and the allocator need at start on Linux, the
  counterparts of `sysctl-read` and of the read of `/`.
- Whether a dynamically linked provider needs to read its shared libraries. If
  it does, this design admits no fourth path, so the provider is built to need
  no library read outside `PROVIDER_EXECUTABLE`, or the start is refused.
- The Landlock ABI of a given kernel. The Runtime reads the reported ABI and
  refuses any row the ABI cannot express.
- Whether the provider's threads need a `clone` form that the process boundary
  must allow.

## When a primitive is missing

The start is refused with a reason that names the missing primitive (item 16's
rule, P11). Each refusal has its own reason and its own Linux test:

- The kernel has no Landlock:
  `linux confinement refused: the kernel has no Landlock`; the test that would
  prove it is `linux_start_is_refused_when_landlock_is_absent`.
- The Landlock ABI cannot express a row:
  `linux confinement refused: the Landlock ABI cannot express <row>`; the test
  that would prove it is
  `linux_start_is_refused_when_the_landlock_abi_cannot_express_a_row`. The test
  presents an ABI that lacks one right per row and requires the reason to name
  that row.
- User namespaces are turned off:
  `linux confinement refused: user namespaces are turned off`; the test that
  would prove it is
  `linux_start_is_refused_when_user_namespaces_are_turned_off`.
- The seccomp filter cannot be installed:
  `linux confinement refused: the seccomp filter cannot be installed`; the test
  that would prove it is
  `linux_start_is_refused_when_the_seccomp_filter_cannot_be_installed`.

No row falls back to a weaker rule or to an unconfined start, and no
best-effort mode is used. A refusal leaves nothing under `STORAGE_ROOT`. A
falsifier for these tests is a launch that starts the provider unconfined when a
primitive is missing; the test fails because the provider answers. A second
falsifier returns a fixed reason that names no primitive; the test fails on the
reason.

## The tests

None of the Linux tests below exists yet. `linux` joins
`DECLARED_CONFINED_OS` only when they exist and pass, and the gate then holds
Linux to them (027). Until then, adding `linux` fails the gate on purpose.

Today `sandbox_gate` requires `/usr/bin/sandbox-exec`, and
`sandbox_gate_fails_instead_of_skipping_on_a_declared_os` explicitly expects
`linux` to skip. Before `linux` is declared, both change: `sandbox_gate` gains
a Linux branch that checks the Landlock ABI, user namespaces and seccomp, and
the gate test gains a `linux` case in which each missing primitive is an error
that names it, not a skip.

A Linux counterpart of a named macOS test reuses that test's name; a test with
no macOS counterpart is named here for the first time.

- `both_file_profiles_bind_one_storage_parameter_contract` runs on Linux today.
  It proves the head terms, the three tokens and the three shared rules of the
  oracle, and it needs no Linux counterpart. Falsifier: rename `STORAGE_ROOT`
  (WP22) or add `(allow default)`; the check fails.
- `confined_provider_serves_did_operations_under_its_root` (Linux counterpart)
  drives `Init`, `get_did`, `get_persona_did`, `get_nickname`, `set_nickname`
  and `resolve` under the Linux policy and requires each answer and each file
  under `STORAGE_ROOT`. It fails without the `EXECUTE` rule (the start is
  refused), without the `STORAGE_ROOT` read and write rights (the identity
  write is denied) and without the rule that carries the loader's start reads.
  Falsifier for the exec row: drop the `EXECUTE` rule; the test fails because
  the provider cannot start. Falsifier for the state row: drop the
  `STORAGE_ROOT` write right; the test fails on the denied identity write.
  Falsifier for the loader reads: refuse the fact syscalls the loader uses; the
  test fails because the provider cannot start.
- `confined_provider_serves_wallet_operations_under_its_root` (Linux
  counterpart) drives `Init`, `status`, `CreateManagedAccount` and
  `ListAccounts`, and requires the account and the storage key under the wallet
  root. Falsifier for the exec row: drop the `EXECUTE` rule; the test fails
  because the provider cannot start. Falsifier for the state row: drop the
  `STORAGE_ROOT` write right; the test fails on the denied account write.
- `verify_did_recovery_under_profile` (Linux counterpart) requires
  `invalid_signature` with its reason from the confined provider and a later
  `get_did` that proves the service stayed up. Falsifier: make the confined
  process die in the refusal branch (DID06); the test fails without a response.
- `outside_write_denied` and `confined_outside_write_is_denied` (Linux
  counterparts) point a link inside the root at a target outside it, require
  `storage_error`, require that no file outside the root exists, and require a
  later write under the root to succeed. Falsifier: widen the `STORAGE_ROOT`
  rule to `STORAGE_PARENT`; the outside write succeeds and the test fails.
- `outside_read_denied` and `confined_outside_read_is_denied` (Linux
  counterparts) require the outside read to be refused. They also decide the
  `STORAGE_PARENT` row: a wider rule that lets the read succeed fails the test.
  Falsifier: add the `STORAGE_PARENT` read right; the outside read succeeds.
  Falsifier for the read of `/` row: add a Landlock read rule on `/`; the
  outside read succeeds, and the test fails, as does the model provider's
  `model_outside_read_denied`.
- `startup_denial_reports_its_reason` (Linux counterpart) starts the provider
  under a policy that denies the exec and requires the failure to name the
  request, the exit status and the policy's reason. Falsifier: drop the reason
  from the failure (DID12); the test fails.
- `startup_is_refused_when_the_profile_cannot_be_applied` (Linux counterpart)
  refuses the start for each of the four missing primitives, requires its own
  reason, and requires nothing under `STORAGE_ROOT`. Falsifier: start the
  provider unconfined when a primitive is missing; the provider answers and the
  test fails.
- `profile_denies_network` runs on Linux today and checks the oracle text.
  `linux_profile_denies_every_socket_family` (new) starts a test probe under the
  same Linux policy and requires `socket(AF_INET)`, `socket(AF_INET6)`,
  `socket(AF_UNIX, SOCK_STREAM)` and `socketpair(AF_UNIX, ...)` each to fail
  with `EPERM`, a `connect` to a Unix-domain stand-in to fail, and the provider
  to stay in service. Falsifier: allow `AF_UNIX` in the filter; the Unix-domain
  case succeeds and the test fails.
- `confined_provider_denies_process_and_signal_boundaries` (new) requires a
  probe under the same policy to fail to exec a second program, fork a new
  process, signal a host PID, or use `ptrace` or `process_vm_*` on a host
  process. Falsifier: remove the PID namespace; the signal to the host PID
  succeeds.
- `confined_provider_denies_ipc_boundaries` (new) requires a probe to fail to
  create a SysV queue, a POSIX message queue or a Unix socket pair, and to fail
  to open a host shared-memory object. Falsifier: drop the IPC namespace; the
  host queue is reachable.
- `confined_provider_denies_kernel_fact_boundaries` (new) requires a probe to
  fail to read `/proc/kallsyms`, host `/proc/sys` entries outside the grant or
  `/sys` kernel state, and to fail `bpf` and `perf_event_open`. Falsifier:
  share the host `/proc`; the read succeeds.
- `model_provider_ops_under_profile` (Linux counterpart) drives the model
  provider's named operations and decides the `file-read-data` row. Falsifier
  for the read row: add a Landlock read rule on `/`; the model provider's
  `model_outside_read_denied` fails. Falsifier for its start reads: refuse the
  fact syscalls its loader uses; the provider cannot start.
- `linux_start_is_refused_when_landlock_is_absent`,
  `linux_start_is_refused_when_the_landlock_abi_cannot_express_a_row`,
  `linux_start_is_refused_when_user_namespaces_are_turned_off` and
  `linux_start_is_refused_when_the_seccomp_filter_cannot_be_installed` each
  require their exact reason. Falsifier: a fixed reason that names no
  primitive; each test fails on the reason.
- `sandbox_gate_fails_instead_of_skipping_on_a_declared_os` (future `linux`
  case) requires a missing Landlock, userns or seccomp on a declared `linux` to
  be an error that names the OS and the primitive. Today the test expects
  `linux` to skip; that expectation changes only with the tests above (027).
