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
file is a design: each row names the Linux test that would prove it, most of
those tests are future work, and no sentence here claims that any provider is
confined on Linux.

## The contract on Linux

| Oracle rule | Linux primitive that would carry it | How exact the match is | Linux test that would prove it |
| --- | --- | --- | --- |
| `(version 1)` | The generator's policy version; no kernel primitive carries it. | Exact: the generator emits one version, and the contract check refuses any other head. | `both_file_profiles_bind_one_storage_parameter_contract` |
| `(deny default)`, files | A Landlock ruleset whose only path rules are the three parameters; every file right the ruleset handles and no rule grants fails. The capability drop removes `CAP_DAC_READ_SEARCH` and `CAP_DAC_OVERRIDE`, so privilege adds no file right. | Exact for the access rights Landlock handles. Wider for the nine operations it has no right for (`chdir`, `stat`, `flock`, `chmod`, `chown`, `setxattr`, `utime`, `fcntl` and `access`): the next section gives each one the layer, if any, that refuses it. A right that a newer ABI adds is not restricted by an older ABI, which is wider, so the start is refused when the ABI cannot express a right this row needs. | `linux_metadata_outside_every_grant_is_unrestricted`, `outside_write_denied`, `outside_read_denied`, `confined_outside_write_is_denied` and `confined_outside_read_is_denied` |
| `(deny default)`, processes and signals | A PID namespace; the empty capability set; a seccomp filter that refuses process creation other than the provider's own threads, and every cross-process operation (`ptrace`, `process_vm_*`, `pidfd_getfd`). Landlock `EXECUTE` alone carries exec of any file other than `PROVIDER_EXECUTABLE`: a seccomp filter sees only a system call's raw argument values and cannot read the path behind an `execve` pointer, so it cannot tell one exec path from another. | Exact for signals: a PID namespace contains no PID outside itself, so a signal to a host process cannot be expressed. Narrower for process creation because the provider's threads must start: the filter admits the thread form of `clone` and refuses a new process. The Linux test decides the exact flag set. | `confined_provider_denies_process_and_signal_boundaries` |
| `(deny default)`, IPC | An IPC namespace; a seccomp filter that refuses every `socket` and `socketpair` call, SysV IPC creation and POSIX message queues; Landlock's default denial refusing reads and writes to shared-memory files. | Exact for host IPC objects: a private IPC namespace cannot name them. Narrower for new objects if the provider needs none. The Linux test decides. | `confined_provider_denies_ipc_boundaries` |
| `(deny default)`, kernel facts | A private, read-only `/proc` mount limited to the provider's own PID namespace and a hidden host `/sys`; Landlock denying reads outside the granted paths; seccomp refusing syscalls that read host kernel state (`bpf`, `perf_event_open`). | No exact match: the oracle denies every kernel-fact operation except `sysctl-read`, and Linux splits kernel facts across `/proc`, `/sys` and syscalls, so the map is wider in one place and narrower in another. The Linux test decides. | `confined_provider_denies_kernel_fact_boundaries` |
| `(deny network*)`, with no network allow | A network namespace with no interface and no route; the empty capability set; a seccomp filter that refuses every `socket` and `socketpair` call by system call number alone, with no family list, and refuses `connect`, `sendmsg`, `recvmsg`, `pidfd_getfd` and `process_vm_*`. | Exact for every family the oracle refuses: the filter refuses every call, so no family is left out, and the namespace removes every interface. The `connect`, `sendmsg` and `recvmsg` refusals are a second boundary for a descriptor that arrives from outside; the test cannot observe them while `socket` is refused and claims no assertion for them. macOS puts a Unix-domain connect under `network*` (cc-model-confine 010, macOS 26.5.2), so this row covers it too. | `profile_denies_network` (the oracle text) and `linux_profile_denies_every_socket_family` (the policy) |
| no `(allow default)` | The generator emits only the rights the oracle grants; the launch adds no permissive rule. | Exact: the Linux policy has no permissive term, and the one contract check refuses one in the oracle. | `both_file_profiles_bind_one_storage_parameter_contract` and `file_profile_contract_rejects_an_allow_default` |
| Only `PROVIDER_EXECUTABLE`, `STORAGE_ROOT` and `STORAGE_PARENT` | The same three parameters, bound to the same paths; the launch specification accepts no other path. | Exact: no other path enters the policy. | `both_file_profiles_bind_one_storage_parameter_contract` and `file_profile_contract_rejects_a_non_canonical_token` |
| `(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))` | Landlock `EXECUTE` on the file named by `PROVIDER_EXECUTABLE`, and no other rule. No seccomp rule carries this row: the filter cannot read the path behind the `execve` pointer. | Exact: a Landlock rule on a file grants only that file, and the oracle's `literal` names only that file; a copy of the binary at another path has no rule. | `linux_exec_of_a_copy_is_denied`; `confined_provider_serves_did_operations_under_its_root` and `confined_provider_serves_wallet_operations_under_its_root` prove the granted exec starts the provider |
| `(allow file-read* (literal "/"))` | No path rule. The nearest rule is a Landlock read rule on `/`, which would grant the whole tree and be a fourth path, so the design does not use it. | No exact match: the nearest rule is wider (all files) and the design's mapping is narrower (no rule). The Linux test decides whether the loader starts without it. | `confined_provider_serves_did_operations_under_its_root` and `confined_provider_serves_wallet_operations_under_its_root` |
| `(allow sysctl-read)` | Seccomp allows the kernel-fact syscalls the loader and the allocator use; no path rule. Landlock has no sysctl right. | No exact match: the oracle grants every sysctl read, and the filter is narrower (named syscalls only). The Linux test decides the set. | `confined_provider_serves_did_operations_under_its_root`, `confined_provider_serves_wallet_operations_under_its_root` and `confined_provider_denies_kernel_fact_boundaries` |
| `(allow file-read* (literal (param "STORAGE_PARENT")))` | `LANDLOCK_ACCESS_FS_READ_DIR` on `STORAGE_PARENT`, and no right that opens a file beneath it for reading. | No exact match: a Landlock rule covers the whole hierarchy beneath the directory, so listing the directories under `STORAGE_PARENT` is wider than the oracle's `literal` read of the directory alone. Reading any file beneath `STORAGE_PARENT` is refused, as the oracle grants no file read there. The Linux test plants a readable file beneath `STORAGE_PARENT` and decides the row. | `linux_outside_read_beneath_storage_parent_is_denied` |
| `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))` | Landlock read and write rights on `STORAGE_ROOT`, covering its tree. | Exact for the path: a rule beneath `STORAGE_ROOT` covers the same subtree as the oracle's `subpath`. The rights are exact only when the ABI reports every right the oracle's read and write cover. A right the ABI does not have is not restricted at all, so it is wider: `TRUNCATE` before ABI 3 and `IOCTL_DEV` before ABI 5 are always allowed. `REFER` before ABI 2 is the one missing right that is narrower, because every link or rename across directories is refused. The start is refused when the ABI cannot express a row, so neither departure is taken. | `confined_provider_serves_did_operations_under_its_root`, `confined_provider_serves_wallet_operations_under_its_root`, `outside_write_denied` and `confined_outside_write_is_denied` |
| `(allow file-read-data (literal "/"))` (model profile) | No path rule, for the same reason as the read of `/`. | No exact match: the nearest rule, a read rule on `/`, is wider (data and metadata for all files); the design's mapping is narrower (no rule). The Linux test decides. | `model_provider_ops_under_profile` (the model provider's named test) and `both_file_profiles_bind_one_storage_parameter_contract` |

The five allow rules cover `model-provider` too. The table names the model
profile only where it differs: it presents `(allow file-read-data (literal
"/"))` instead of the shared `(allow file-read* (literal "/"))`, and the model
provider's own document states its storage root.

## What Landlock cannot restrict

Landlock's documentation lists nine actions it has no right for: `chdir`,
`stat`, `flock`, `chmod`, `chown`, `setxattr`, `utime`, `fcntl` and `access`.
Outside every grant each one is wider than the oracle. The capability drop does
not close the gap: it refuses a change of owner inside every grant too, which
is narrower than the oracle's own `STORAGE_ROOT` write, not a rule about the
outside case. These nine are not Landlock rights, so the files row's
start-refusal rule does not cover them: no ABI can express them, and refusing
the start would leave Linux with no provider at all. The design records the
wider mapping and the test that observes it.

| Operation | The layer of this design that refuses it outside every grant | What the Linux test requires |
| --- | --- | --- |
| `chdir` | none; the mapping is wider | the call succeeds into a directory outside every grant |
| `stat` | none; the mapping is wider | the call succeeds on a file outside every grant |
| `access` | none; the mapping is wider | the call succeeds on a file outside every grant |
| `flock` | none; the mapping is wider, and the ruleset's data rights keep any descriptor for the file from being opened, so the call cannot be observed | no probe |
| `fcntl` | none; the mapping is wider, and the ruleset's data rights keep any descriptor for the file from being opened, so the call cannot be observed | no probe |
| `chmod` | none; the mapping is wider | the call succeeds on a file outside every grant |
| `chown` | the empty capability set refuses a change of owner, inside every grant too, so it narrows the inside case rather than matching the outside one | no probe |
| `setxattr` | none; the mapping is wider | the call succeeds on a file outside every grant |
| `utime` | none; the mapping is wider | the call succeeds on a file outside every grant |

`linux_metadata_outside_every_grant_is_unrestricted` is the Linux test for this
part. A probe under the same policy calls `stat`, `access`, `chdir`, `chmod`,
`setxattr` and `utime` outside every grant and requires each call to succeed,
and it requires a read of that file's data and a write of it to fail, because
those are rights the ruleset holds. Falsifier: add a seccomp refusal for
`fchmodat`; the probe's `chmod` fails and the test fails, because the design
claims that no layer refuses it. The files row's other tests,
`outside_write_denied`, `outside_read_denied`,
`confined_outside_write_is_denied` and `confined_outside_read_is_denied`, keep
the data refusal.

## Rows with no exact Linux match

Five rows have no exact Linux rule. Each says which way its nearest rule
departs from the oracle, and the Linux test decides the row.

- The nine operations Landlock cannot restrict. No layer of this design
  refuses them, so the mapping is wider than the oracle; the section above
  lists each one and the layer, if any, that refuses it.
- The literal read of `STORAGE_PARENT` alone. No Landlock right grants a
  directory's own read without its tree: `READ_DIR` on a directory covers every
  directory beneath it. The design grants `READ_DIR` alone, so listing is wider
  while reading any file beneath `STORAGE_PARENT` is refused.
  `linux_outside_read_beneath_storage_parent_is_denied` plants a readable file
  at `STORAGE_PARENT/<sibling>/<file>`, reaches it through a link inside
  `STORAGE_ROOT`, and requires the read to be refused; that refusal decides the
  row.
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
- The Landlock ABI of a given kernel. The Runtime would read the reported ABI
  and refuse any row the ABI cannot express.
- Whether the provider's threads need a `clone` form that the process boundary
  must allow.

## When a primitive is missing

The start is refused with a reason that names the missing primitive (item 16's
rule, P11). "The frame" names each primitive, and each one has its own reason
and its own Linux test:

- The kernel has no Landlock:
  `linux confinement refused: the kernel has no Landlock`; the test that would
  prove it is `linux_start_is_refused_when_landlock_is_absent`.
- The Landlock ABI cannot express a row:
  `linux confinement refused: the Landlock ABI cannot express <row>`; the test
  that would prove it is
  `linux_start_is_refused_when_the_landlock_abi_cannot_express_a_row`. The test
  presents an ABI that lacks one right per row and requires the reason to name
  that row.
- The user namespace cannot be created:
  `linux confinement refused: user namespaces are turned off`; the test that
  would prove it is
  `linux_start_is_refused_when_user_namespaces_are_turned_off`.
- The mount namespace cannot be created:
  `linux confinement refused: the mount namespace cannot be created`; the test
  that would prove it is
  `linux_start_is_refused_when_the_mount_namespace_cannot_be_created`.
- The network namespace cannot be created:
  `linux confinement refused: the network namespace cannot be created`; the
  test that would prove it is
  `linux_start_is_refused_when_the_network_namespace_cannot_be_created`.
- The PID namespace cannot be created:
  `linux confinement refused: the PID namespace cannot be created`; the test
  that would prove it is
  `linux_start_is_refused_when_the_pid_namespace_cannot_be_created`.
- The IPC namespace cannot be created:
  `linux confinement refused: the IPC namespace cannot be created`; the test
  that would prove it is
  `linux_start_is_refused_when_the_ipc_namespace_cannot_be_created`.
- A capability cannot be dropped:
  `linux confinement refused: the capabilities cannot be dropped`; the test
  that would prove it is
  `linux_start_is_refused_when_the_capabilities_cannot_be_dropped`.
- `no_new_privs` cannot be set:
  `linux confinement refused: no_new_privs cannot be set`; the test that would
  prove it is `linux_start_is_refused_when_no_new_privs_cannot_be_set`.
- The seccomp filter cannot be installed:
  `linux confinement refused: the seccomp filter cannot be installed`; the test
  that would prove it is
  `linux_start_is_refused_when_the_seccomp_filter_cannot_be_installed`.

Each primitive keeps its own refusal because a kernel can be built with one
namespace absent while it has the others, and because a launch that cannot
create one of them would leave part of "The frame" absent. The macOS test
`startup_is_refused_when_the_profile_cannot_be_applied` has no separate Linux
counterpart: its cases are the Landlock absence and the ABI case above, and
each refusal keeps one test name.

No row falls back to a weaker rule or to an unconfined start, and no
best-effort mode is used. A refusal leaves nothing under `STORAGE_ROOT`. A
falsifier for each refusal test is a launch that starts the provider unconfined
when that primitive is missing; the test fails because the provider answers. A
second falsifier returns a fixed reason that names no primitive; each test
fails on the reason.

## The tests

Most of the Linux tests below are future work. Two run on Linux today,
`both_file_profiles_bind_one_storage_parameter_contract` and
`profile_denies_network`, and are named in place. `linux` joins
`DECLARED_CONFINED_OS` only when every test below exists and passes, and the
gate then holds Linux to them (027). Until then, adding `linux` fails the gate
on purpose.

A probe named below runs under the same generated policy with
`PROVIDER_EXECUTABLE` bound to the probe itself, because the policy grants exec
of that one file and no other.

Today `sandbox_gate` requires `/usr/bin/sandbox-exec`, and
`sandbox_gate_fails_instead_of_skipping_on_a_declared_os` explicitly expects
`linux` to skip. Before `linux` is declared, both change: `sandbox_gate` gains
a Linux branch that checks the Landlock ABI, the namespaces, the capability
drop, `no_new_privs` and seccomp, and the gate test gains a `linux` case in
which each missing primitive is an error that names it, not a skip.

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
  Falsifier for the state row: drop the `STORAGE_ROOT` write right; the test
  fails on the denied identity write. Falsifier for the loader reads: refuse
  the fact syscalls the loader uses; the test fails because the provider cannot
  start.
- `linux_exec_of_a_copy_is_denied` (new) copies the provider binary to a path
  outside `PROVIDER_EXECUTABLE` and launches that copy under the same policy,
  with the parameter still bound to the original binary. The launch of the copy
  must be refused on the exec, and a launch of the original binary under the
  same policy must serve. Falsifier: add a Landlock `EXECUTE` rule for the
  copy's path; the copy starts and answers, and the test fails on the refusal.
  Dropping the `EXECUTE` rule for the named file is not this test's falsifier:
  it refuses the provider's own start, which the two serve tests assert.
- `confined_provider_serves_wallet_operations_under_its_root` (Linux
  counterpart) drives `Init`, `status`, `CreateManagedAccount` and
  `ListAccounts`, and requires the account and the storage key under the wallet
  root. Falsifier for the state row: drop the `STORAGE_ROOT` write right; the
  test fails on the denied account write.
- `verify_did_recovery_under_profile` (Linux counterpart) requires
  `invalid_signature` with its reason from the confined provider and a later
  `get_did` that proves the service stayed up. Falsifier: make the confined
  process die in the refusal branch (DID06); the test fails without a response.
- `outside_write_denied` and `confined_outside_write_is_denied` (Linux
  counterparts) repeat what the two macOS tests do today. `outside_write_denied`
  writes through a link at `STORAGE_ROOT/nickname.enc` to two targets, an
  unrelated temporary directory and `Init.base_path/sibling`, which is beneath
  did's `STORAGE_PARENT`; it requires `storage_error`, requires that no file
  appears at either target and that the target directory stays unchanged, and
  requires a later write under the root to succeed.
  `confined_outside_write_is_denied` sends `Init` for three outside bases, an
  unrelated temporary directory, `base/sibling` and
  `base/ElastOS/SystemServices/Sibling`, the last beneath wallet's
  `STORAGE_PARENT`; it uses no link, requires `storage_error`, requires that no
  wallet directory appears under any of them, and requires a later `status` to
  answer. Falsifier for both: widen the `STORAGE_ROOT` rule to
  `STORAGE_PARENT`; the sibling write or the sibling `Init` succeeds and the
  test fails.
- `outside_read_denied` and `confined_outside_read_is_denied` (Linux
  counterparts) require the outside read to be refused. As written today,
  neither decides the `STORAGE_PARENT` row: `outside_read_denied` plants its
  encrypted fixture in a separate temporary directory, and
  `confined_outside_read_is_denied` plants the key at `base/sibling`, which is
  not beneath `STORAGE_PARENT` (`base/ElastOS/SystemServices`). Falsifier for
  the read of `/` row: add a Landlock read rule on `/`; the outside read
  succeeds, and the test fails, as does the model provider's
  `model_outside_read_denied`.
- `linux_outside_read_beneath_storage_parent_is_denied` (new) plants a readable
  file at `STORAGE_PARENT/<sibling>/<file>`, outside `STORAGE_ROOT`, and a link
  inside `STORAGE_ROOT` that names it; a probe under the same policy opens that
  link for reading and the read must be refused. Falsifier: give the
  `STORAGE_PARENT` rule the `READ_FILE` right as well as `READ_DIR`; the read
  succeeds and the test fails. The design's `READ_DIR`-only mapping passes this
  test, and no other test plants a file beneath `STORAGE_PARENT`.
- `startup_denial_reports_its_reason` (Linux counterpart) starts the provider
  under a policy that denies the exec and requires the failure to name the
  request, the exit status and the policy's reason. Falsifier: drop the reason
  from the failure (DID12); the test fails.
- `profile_denies_network` runs on Linux today and checks the oracle text.
  `linux_profile_denies_every_socket_family` (new) starts a probe under the
  same Linux policy and calls `socket(family, type, 0)` for every address
  family number from 0 up to `AF_MAX` with every socket type number Linux
  defines, `SOCK_STREAM`, `SOCK_DGRAM`, `SOCK_RAW`, `SOCK_RDM`,
  `SOCK_SEQPACKET`, `SOCK_DCCP` and `SOCK_PACKET`, and
  `socketpair(family, SOCK_STREAM, 0)` for the same numbers; every call must
  fail with `EPERM`, and the provider must stay in service. The design refuses
  each `socket` and `socketpair` call by system call number with no family
  list, so the loop covers every family the kernel can name, including ones
  this design does not mention. Falsifier: replace the whole-call refusal with
  a family list that omits `AF_NETLINK`; the `AF_NETLINK` iteration succeeds
  and the test fails there. The filter's `connect`, `sendmsg` and `recvmsg`
  refusals are not observed: no descriptor can exist to call them while
  `socket` is refused, and the test claims no assertion for them.
- `confined_provider_denies_process_and_signal_boundaries` (new) requires a
  probe under the same policy to fail to fork a new process, to signal a host
  PID, and to use `ptrace` or `process_vm_*` on a host process. Falsifier:
  remove the PID namespace; the signal to the host PID succeeds and the test
  fails on that assertion. Exec of another file is not repeated here; the exec
  row's copy test decides it.
- `confined_provider_denies_ipc_boundaries` (new) requires a probe to fail to
  create a SysV queue, a POSIX message queue or a Unix socket pair, and to fail
  to open a host shared-memory object. The filter refuses creation only, so
  `msgget` without `IPC_CREAT` reaches the namespace: the test creates a queue
  under a fixed key outside the namespace before the probe starts, and the
  probe's `msgget(host_key, 0)` must fail with `ENOENT`. Falsifier: drop the
  IPC namespace; the creation assertions, the socket pair and the shared-memory
  object still fail under the filter and Landlock, and the test fails on the
  `msgget(host_key, 0)` assertion, which returns the host queue's id.
- `confined_provider_denies_kernel_fact_boundaries` (new) requires a probe to
  fail to read `/proc/kallsyms`, host `/proc/sys` entries outside the grant or
  `/sys` kernel state, and to fail `bpf` and `perf_event_open`. It also
  requires `stat` of `/proc/<pid>` for a sentinel process that the test started
  outside the provider's PID namespace to fail with `ENOENT`: the private
  `/proc` mount shows only the provider's namespace, and `stat` is a read of
  `/proc` that Landlock leaves unrestricted, so it observes the mount.
  Falsifier for the mount: bind-mount the host `/proc` instead of mounting a
  private one; the read assertions still pass because the design holds no
  `/proc` path rule and Landlock still refuses them, and the test fails on the
  `stat` assertion, which resolves the sentinel PID. Falsifier for the path
  rule: add a Landlock read rule on `/proc`; the `/proc/kallsyms` read succeeds
  and the test fails on that assertion.
- `model_provider_ops_under_profile` (Linux counterpart) drives the model
  provider's named operations and decides the `file-read-data` row. Falsifier
  for the read row: add a Landlock read rule on `/`; the model provider's
  `model_outside_read_denied` fails. Falsifier for its start reads: refuse the
  fact syscalls its loader uses; the provider cannot start.
- `linux_start_is_refused_when_landlock_is_absent`,
  `linux_start_is_refused_when_the_landlock_abi_cannot_express_a_row`,
  `linux_start_is_refused_when_user_namespaces_are_turned_off`,
  `linux_start_is_refused_when_the_mount_namespace_cannot_be_created`,
  `linux_start_is_refused_when_the_network_namespace_cannot_be_created`,
  `linux_start_is_refused_when_the_pid_namespace_cannot_be_created`,
  `linux_start_is_refused_when_the_ipc_namespace_cannot_be_created`,
  `linux_start_is_refused_when_the_capabilities_cannot_be_dropped`,
  `linux_start_is_refused_when_no_new_privs_cannot_be_set` and
  `linux_start_is_refused_when_the_seccomp_filter_cannot_be_installed` each
  require their exact reason and require that nothing is left under
  `STORAGE_ROOT`. Falsifier: a fixed reason that names no primitive; each test
  fails on the reason.
- `sandbox_gate_fails_instead_of_skipping_on_a_declared_os` (future `linux`
  case) requires a missing Landlock, a missing namespace, a capability that
  cannot be dropped, `no_new_privs` that cannot be set or a missing seccomp on
  a declared `linux` to be an error that names the OS and the primitive. Today
  the test expects `linux` to skip; that expectation changes only with the
  tests above (027).
