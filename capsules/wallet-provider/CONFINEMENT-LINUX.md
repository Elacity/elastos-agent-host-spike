# The Linux design for the one file-profile contract

The lab contract that `did-provider`, `wallet-provider` and `model-provider`
present is the one file-profile contract: `check_profile_contract`, run over
`FILE_PROFILES` in `tests/confine.rs`, with `(version 1)` first,
`(deny default)` second, an explicit `(deny network*)`, no `(allow default)`,
no network allow, only the `PROVIDER_EXECUTABLE`, `STORAGE_ROOT` and
`STORAGE_PARENT` tokens, and the three shared rules verbatim.
This contract has no Linux enforcement or tests yet. Nothing in this file is
current behaviour.
`confine.sb` stays each provider's one oracle. The contract is shared, so its
Linux mapping is written once here, beside the one contract check (P10). The
Linux policy that the Runtime would generate from the same approved declared
rights must carry each oracle rule as this file maps it, and no second profile
file exists (P10).

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

The Linux policy holds no path rule beyond the bound parameters: it adds none
for `/`, `/proc`, `/sys` or a library directory, and `STORAGE_PARENT` carries no
rule, as its row says. The private `/proc` mount the mount namespace provides
is a mount, not a grant. The policy is a second rendering of the same rights,
and the one contract check stays the one check of the oracle.

The Linux policy would be applied before the provider image is entered. This
file is a design: each row names the Linux test that would prove it, the Linux
counterparts do not exist yet, and no sentence here claims that any provider is
confined on Linux.

## The contract on Linux

| Oracle rule | Linux primitive that would carry it | How exact the match is | Linux test that would prove it |
| --- | --- | --- | --- |
| `(version 1)` | The generator's policy version; no kernel primitive carries it. | Exact: the generator emits one version, and the contract check refuses any other head. | `both_file_profiles_bind_one_storage_parameter_contract` |
| `(deny default)`, files | A Landlock ruleset whose only path rules are `PROVIDER_EXECUTABLE` (`EXECUTE`) and `STORAGE_ROOT` (read and write). Every file right the ABI reports and that no rule covers fails. The capability drop removes `CAP_DAC_READ_SEARCH` and `CAP_DAC_OVERRIDE`, so privilege grants no file right. | Exact for every access right the ABI reports. Landlock's [filesystem flags](https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags) report no right for `chdir`, `stat`, `flock`, `chmod`, `chown`, `setxattr`, `utime`, `fcntl` and `access`, so the ruleset does not restrict them. No layer of the design refuses `chdir`, `stat`, `access`, `chmod`, `utime` or `setxattr` on a fixture the provider owns with ordinary permissions, in a searchable fixture directory beneath searchable parents, so the mapping is wider than the oracle for those six; the kernel's ordinary permission check still applies, so the design claims no such success for a host-owned file or a file whose permissions deny the call. The capability drop removes `CAP_CHOWN`, so `chown` to a different owner is refused and the mapping is narrower than the oracle inside `STORAGE_ROOT`; an owner that keeps `uid` `-1` may still change its file's group to a group of which it is a member ([chown(2)](https://man7.org/linux/man-pages/man2/chown.2.html)), so the drop does not refuse every `chown`; the probe requires that group call to succeed and the resulting group to be the chosen mapped gid, and the policy run checks its own fixture directory's mode and owner before its `chdir`, as the positive control checks its copy, so a mismatch is missing evidence with its cause, not a kernel change. A seccomp rule that refuses every `chown` by syscall number is the group-call falsifier only when the test reports the failing call as the group `chown` itself and every earlier call as a success; a failure at an earlier call is missing evidence. Landlock checks a new data open against the rules for its path, so a data open outside every grant fails; the rules are checked at open time, so a descriptor opened before enforcement is not checked: the [filesystem flags](https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags) section states that "Files or directories opened before the sandboxing are not subject to these restrictions", and an `O_PATH` open does not open the file itself for reading or writing ([open(2)](https://man7.org/linux/man-pages/man2/open.2.html)); whether Landlock restricts it is open and unclaimed, and the probe's required success decides the row. The launch precondition is that a provider inherits no descriptor other than its stdin, stdout and stderr protocol streams, which are the harness pipes (`Stdio::piped()` in `ConfinedProvider::spawn` in `capsules/wallet-provider/tests/confine.rs`); future Runtime work proves it, for example by listing `/proc/self/fd` at provider start and allowing exactly 0, 1 and 2, and the design claims no falsifier for it. One raw `fcntl` call with the `F_DUPFD` command duplicates an outside `O_PATH` descriptor that the probe obtains with `openat` ([open(2)](https://man7.org/linux/man-pages/man2/open.2.html)) and gives no content read; the probe issues that raw command itself, not a library duplicate that may use another command such as `F_DUPFD_CLOEXEC`, so the `F_DUPFD`-only falsifier reaches the probe's call. The design claims that one raw call only, not every `fcntl` or `flock`, whose departures stay unclaimed. Falsifier for the duplication: add a seccomp rule that refuses `fcntl` only when its command argument is `F_DUPFD` ([fcntl(2)](https://man7.org/linux/man-pages/man2/fcntl.2.html)); the duplication fails and the test fails. The probe and the Rust runtime make other `fcntl` calls, so a rule that refuses every `fcntl` could stop the probe before its `F_DUPFD` call. Wider also where a rule on a directory covers the tree beneath it, as the next section says. A row that needs a right the ABI lacks departs as the `STORAGE_ROOT` row states, and the start is then refused, never weakened. | `outside_write_denied`, `outside_read_denied`, `confined_outside_write_is_denied`, `confined_outside_read_is_denied`, `linux_file_operations_landlock_cannot_restrict` and `linux_capability_drop_refuses_chown` |
| `(deny default)`, processes and signals | A PID namespace; the empty capability set; a seccomp filter that refuses process creation other than the provider's own threads and every cross-process operation (`ptrace`, `process_vm_*`, `pidfd_getfd`). Landlock `EXECUTE` on `PROVIDER_EXECUTABLE` alone carries exec of any other file. | Exact for signals: a PID namespace contains no PID outside itself, so a signal to a host process cannot be expressed. Narrower for process creation because the provider's threads must start: the filter admits the thread form of `clone` and refuses a new process. The filter adds no exec rule: it sees only the syscall number and cannot read the path behind `execve`'s pointer, so it cannot separate the granted binary from another file, and a refusal by number would also refuse the provider's own launch, which the oracle permits. The Linux test decides the exact flag set. | `confined_provider_denies_process_and_signal_boundaries` |
| `(deny default)`, IPC | An IPC namespace; seccomp refusing every `socket` and `socketpair` call, SysV IPC creation (`msgget` and `shmget` when the key is `IPC_PRIVATE` or the flags carry `IPC_CREAT`, both plain integer arguments the filter can read) and POSIX message queue creation (`mq_open` with `O_CREAT`); Landlock's default denial refusing reads and writes to shared-memory files. | Exact for host IPC objects: a private IPC namespace cannot name them, and the one SysV creation rule refuses every form including the private key. The `mq_open` rule refuses the `O_CREAT` form of the call, and the create also passes through the message queue filesystem ([mq_overview(7)](https://man7.org/linux/man-pages/man7/mq_overview.7.html)). Landlock's default denial would refuse that create only if the ruleset reaches the queue's internal mount; [Landlock's documentation](https://docs.kernel.org/userspace-api/landlock.html) does not settle that reach, and if it does not, no other layer refuses the create. The outcome is open, so the design leaves the `mq_open` falsifier unclaimed: a future isolated probe that drops only the `mq_open` `O_CREAT` refusal and records the outcome would settle it. Wider for a lookup of an existing object: `msgget(key, 0)` and `shmget(key, 0, 0)` are not refused, and inside the namespace they find nothing. Narrower for new objects if the provider needs none. The Linux test decides. | `confined_provider_denies_ipc_boundaries` |
| `(deny default)`, kernel facts | A private, read-only `/proc` mount limited to the provider's own PID namespace and a hidden host `/sys`; Landlock denying reads outside the granted paths, with no `/proc` or `/sys` rule; seccomp refusing syscalls that read host kernel state (`bpf`, `perf_event_open`). | No exact match: the oracle denies every kernel-fact operation except `sysctl-read`, and Linux splits kernel facts across `/proc`, `/sys` and syscalls, so the map is wider in one place and narrower in another. The Linux test decides. | `confined_provider_denies_kernel_fact_boundaries` |
| `(deny network*)`, with no network allow | A network namespace with no interface and no route; the empty capability set; seccomp refusing every `socket` and `socketpair` call by syscall number, with no family list, and refusing `connect`, `sendmsg`, `recvmsg`, `pidfd_getfd` and `process_vm_*` so no descriptor can arrive from outside. | Exact for every family the oracle refuses: the filter refuses the whole call instead of naming families, so no family is left out, Unix-domain included, and the namespace removes every interface. macOS puts a Unix-domain connect under `network*` (cc-model-confine 010, macOS 26.5.2), so this row covers it too. | `profile_denies_network` (the oracle text) and `linux_profile_denies_every_socket_family` (the policy) |
| no `(allow default)` | The generator emits only the rights the oracle grants; the launch adds no permissive rule. | Exact: the Linux policy has no permissive term, and the one contract check refuses one in the oracle. | `both_file_profiles_bind_one_storage_parameter_contract` and `file_profile_contract_rejects_an_allow_default` |
| Only `PROVIDER_EXECUTABLE`, `STORAGE_ROOT` and `STORAGE_PARENT` | The same three parameters, bound to the same paths; the parent takes no path rule, and its row says why. The launch specification accepts no other path. | Exact: no other path enters the policy. | `both_file_profiles_bind_one_storage_parameter_contract` and `file_profile_contract_rejects_a_non_canonical_token` |
| `(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))` | Landlock `EXECUTE` on the file named by `PROVIDER_EXECUTABLE`; no other layer carries exec, because a seccomp filter sees only the syscall number and cannot read the path behind `execve`'s pointer. | Exact: a Landlock rule on a file grants only that file, the oracle's `literal` names only that file, and the design gives the whole exec rule to Landlock. | `confined_provider_serves_did_operations_under_its_root` and `confined_provider_serves_wallet_operations_under_its_root` |
| `(allow file-read* (literal "/"))` | No path rule. The nearest rule is a Landlock read rule on `/`, which would grant the whole tree and be a fourth path, so the design does not use it. | No exact match: the nearest rule is wider (all files) and the design's mapping is narrower (no rule). The Linux test decides whether the loader starts without it. | `confined_provider_serves_did_operations_under_its_root` and `confined_provider_serves_wallet_operations_under_its_root` |
| `(allow sysctl-read)` | Seccomp allows the kernel-fact syscalls the loader and the allocator use; no path rule. Landlock has no sysctl right. | No exact match: the oracle grants every sysctl read, and the filter is narrower (named syscalls only). The Linux test decides the set. | `confined_provider_serves_did_operations_under_its_root`, `confined_provider_serves_wallet_operations_under_its_root` and `confined_provider_denies_kernel_fact_boundaries` |
| `(allow file-read* (literal (param "STORAGE_PARENT")))` | No read rule on `STORAGE_PARENT`. Landlock has no rule that names a directory alone: a path rule on a directory covers the whole tree beneath it, so the nearest rule would let a read beneath the parent succeed. | No exact match: the nearest rule is wider than the oracle (the whole tree beneath the parent), so the design's mapping is narrower: no rule. The `STORAGE_PARENT` read test plants a readable file beneath the parent, outside `STORAGE_ROOT`, and requires its read to fail. If the provider needs the directory alone to start, the start is refused with `linux confinement refused: the Landlock ABI cannot express the STORAGE_PARENT read`, and `linux_start_is_refused_when_the_landlock_abi_cannot_express_a_row` requires that reason. | `outside_read_denied` and `confined_outside_read_is_denied` |
| `(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))` | Landlock read and write rights on `STORAGE_ROOT`, covering its tree. | Exact for the path: a rule beneath `STORAGE_ROOT` covers the same subtree as the oracle's `subpath`. The rights are exact when the ABI reports every right the oracle's read and write cover. A right the ABI lacks departs the row: `REFER` before ABI 2 refuses every link or rename across directories, which is narrower; `TRUNCATE` before ABI 3 and `IOCTL_DEV` before ABI 5 are not restricted at all, which is wider. Because a wider departure is not confinement, the start is refused when the ABI cannot express this row. | `confined_provider_serves_did_operations_under_its_root`, `confined_provider_serves_wallet_operations_under_its_root`, `outside_write_denied` and `confined_outside_write_is_denied` |
| `(allow file-read-data (literal "/"))` (model profile) | No path rule, for the same reason as the read of `/`. | No exact match: the nearest rule, a read rule on `/`, is wider (data and metadata for all files); the design's mapping is narrower (no rule). The Linux test decides. | `model_provider_ops_under_profile` (the model provider's named test) and `both_file_profiles_bind_one_storage_parameter_contract` |

The five allow rules cover `model-provider` too. The table names the model
profile only where it differs: it presents `(allow file-read-data (literal
"/"))` instead of the shared `(allow file-read* (literal "/"))`, and the model
provider's own document states its storage root.

## Rows with no exact Linux match

Five rows have no exact Linux rule. Each says which way its nearest rule
departs from the oracle, and the Linux test decides the row.

- The file operations Landlock cannot restrict: `chdir`, `stat`, `flock`,
  `chmod`, `chown`, `setxattr`, `utime`, `fcntl` and `access`
  ([filesystem flags](https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags)).
  Each departs the oracle in one stated way. No layer of the design refuses
  `chdir`, `stat`, `access`, `chmod`, `utime` or `setxattr` on a fixture the
  provider owns with ordinary permissions, in a searchable fixture directory
  beneath searchable parents, so the mapping is wider than the oracle's
  `(deny default)` for those six; the
  kernel's ordinary permission check still applies, so the design claims no
  such success for a host-owned file or a file whose permissions deny the
  call. `linux_file_operations_landlock_cannot_restrict` probes them on
  isolated file and directory fixtures outside every grant, under the probe's
  mapped uid and gids, with that uid as the fixture owner, the fixture
  directory searchable by that uid (owned by it, mode `0700`), and the search
  bit set on every parent. A positive control under the same uid/gid mappings
  and namespaces, without the proposed Landlock ruleset, capability drop and
  seccomp filter, requires each intended call to succeed first; a fixture the
  host cannot supply or a call the control already refuses is reported with
  its cause as missing evidence. The policy run checks its own fixture
  directory's mode and owner before its `chdir`, the same check the positive
  control makes on its copy, and reports a mismatch as missing evidence with
  its cause, not as a kernel change. Under the policy the probe requires each
  call to succeed, so the widening is recorded rather than claimed as
  confinement; a later kernel that refuses one of them fails the test and the
  row is rewritten. Falsifier for the metadata calls: add a seccomp rule that
  refuses `chmod` and `stat` by syscall number
  ([seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)); a
  filter reads syscall arguments as integers, not paths, so the rule cannot
  select only the probe's calls, and the probe and the Rust runtime make
  other `stat` calls.
  The rule can stop the probe before its own calls, so the design leaves this
  falsifier unclaimed.
  `chown` separates two cases. Changing the owner to a different mapped uid
  is refused because the capability drop removes `CAP_CHOWN`, so the mapping
  is narrower than the oracle inside `STORAGE_ROOT`;
  `linux_capability_drop_refuses_chown` requires `EPERM` with the owner
  unchanged. Falsifier: keep `CAP_CHOWN` in the capability set; the chown
  succeeds and the test fails. Changing only the group of a file the probe
  owns, with `uid` `-1` and a different mapped group of which the probe is a
  member, stays permitted because
  [chown(2)](https://man7.org/linux/man-pages/man2/chown.2.html) lets the
  owner set a group it belongs to; the same probe requires that call to
  succeed and the resulting group to change. Falsifier: add a seccomp rule
  that refuses every `chown` by syscall number; this falsifier counts only
  when the test reports the failing call as the group `chown` itself and every
  earlier call as a success. A failure at an earlier call is reported as
  missing evidence, so the group call is not inferred from it. A fixture
  without the required mapped uid or gid supplies a
  clear reason for missing evidence. `flock` and `fcntl` act only on a
  descriptor, so the descriptor conditions decide them. Landlock refuses a
  new data open outside every grant. A descriptor opened before enforcement
  is not checked: the [filesystem flags](https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags)
  section states that "Files or directories opened before the sandboxing are
  not subject to these restrictions".
  The launch precondition is that a provider inherits no descriptor other
  than its stdin, stdout and stderr protocol streams, which are the harness
  pipes (`Stdio::piped()` in `ConfinedProvider::spawn` in
  `capsules/wallet-provider/tests/confine.rs`); future Runtime work proves
  it, for example by listing `/proc/self/fd` at provider start and allowing
  exactly 0, 1 and 2, and the design claims no falsifier for it. An `O_PATH`
  open does not open the file itself for reading or writing
  ([open(2)](https://man7.org/linux/man-pages/man2/open.2.html)); whether
  Landlock restricts it is open and unclaimed, and the probe's required
  success decides the row. The same probe obtains an outside `O_PATH`
  descriptor with `openat` and duplicates it by calling `fcntl` with the raw
  `F_DUPFD` command ([open(2)](https://man7.org/linux/man-pages/man2/open.2.html)),
  not through a library duplicate that may use another command such as
  `F_DUPFD_CLOEXEC`; it requires both descriptors and closes both. The
  duplication gives no proof of a content read, because `open(2)` gives
  `EBADF` for a read on an `O_PATH` descriptor. The design claims this one
  raw `fcntl(F_DUPFD)` call and no other `fcntl` command and no `flock`
  operation, so those departures stay unclaimed. Falsifier for the `O_PATH` open:
  add a seccomp rule that refuses `openat` when its flags carry `O_PATH`; the
  open fails and the test fails. Falsifier for the duplication: add a seccomp
  rule that refuses `fcntl` only when its command argument is `F_DUPFD`
  ([fcntl(2)](https://man7.org/linux/man-pages/man2/fcntl.2.html)); the
  duplication fails and the test fails. The probe and the Rust runtime make
  other `fcntl` calls, so a rule that refuses every `fcntl` could stop the
  probe before its `F_DUPFD` call.
- The literal read of `STORAGE_PARENT` alone. Landlock has no right that names
  a directory without its tree, so the nearest rule is wider than the oracle
  and would let a read beneath the parent succeed. The design's mapping is
  narrower: no rule. The test that decides the row plants a readable file at
  `STORAGE_PARENT/<sibling>/<file>`, outside `STORAGE_ROOT`, and requires the
  read to fail. If the provider needs the directory alone to start, the start
  is refused with `linux confinement refused: the Landlock ABI cannot express
  the STORAGE_PARENT read`, and
  `linux_start_is_refused_when_the_landlock_abi_cannot_express_a_row` requires
  that reason. Falsifier: add the read rule on `STORAGE_PARENT`; the planted
  read succeeds and the test fails.
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
  it does, this design admits no fourth path, so the provider would be built to
  need no library read outside `PROVIDER_EXECUTABLE`, or the start would be
  refused.
- The Landlock ABI of a given kernel. The Runtime would read the reported ABI
  and would refuse any row the ABI cannot express.
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
  that row. For the `STORAGE_PARENT` row the reason names that read, because
  Landlock has no literal-directory right at any ABI.
- User namespaces are turned off:
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
- The capability set cannot be dropped:
  `linux confinement refused: the capability set cannot be dropped`; the test
  that would prove it is
  `linux_start_is_refused_when_the_capability_set_cannot_be_dropped`. The test
  injects a `capset` failure (`ENOMEM` and a refusal by an inherited seccomp
  filter) and requires this exact reason before the provider starts.
- `no_new_privs` cannot be set:
  `linux confinement refused: no_new_privs cannot be set`; the test that would
  prove it is `linux_start_is_refused_when_no_new_privs_cannot_be_set`. The
  test injects a `prctl(PR_SET_NO_NEW_PRIVS)` failure (`EPERM` and a refusal by
  an inherited seccomp filter) and requires this exact reason before the
  provider starts.
- The seccomp filter cannot be installed:
  `linux confinement refused: the seccomp filter cannot be installed`; the test
  that would prove it is
  `linux_start_is_refused_when_the_seccomp_filter_cannot_be_installed`.

Kernel support does not guarantee success: `capset` can return `ENOMEM`, and
an inherited seccomp filter can refuse `capset` or `prctl`, so each failure has
its own reason and test above and no failure starts the provider unconfined.

No row falls back to a weaker rule or to an unconfined start, and no
best-effort mode is used. A refusal leaves nothing under `STORAGE_ROOT`. A
falsifier for these tests is a launch that starts the provider unconfined when a
primitive is missing; the test fails because the provider answers. A second
falsifier returns a fixed reason that names no primitive; the test fails on the
reason.

## The tests

Most of the Linux tests below are future work. Two run today and check the
oracle text rather than the Linux policy:
`both_file_profiles_bind_one_storage_parameter_contract` and
`profile_denies_network`. `linux` joins `DECLARED_CONFINED_OS` only when the
Linux counterparts exist and pass, and the gate then holds Linux to them (027).
Until then, adding `linux` fails the gate on purpose.

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
  under `STORAGE_ROOT`. The test harness places a copy of
  `PROVIDER_EXECUTABLE` in `STORAGE_ROOT`, under a name other than the
  original, before the confined probe starts and outside the policy. Under the
  policy the probe first shows the copy is present and readable under the
  `STORAGE_ROOT` grant, and only then requires the exec of the copy to fail; a
  failure before the exec is reported as missing evidence with its cause, not
  as the exec rule's refusal. A copy outside every grant would also fail its
  read, so that probe would not decide the exec rule. It fails
  without the `EXECUTE` rule (the start is refused), without the `STORAGE_ROOT`
  read and write rights (the identity write is denied) and without the rule
  that carries the loader's start reads. Falsifier for the exec row: add a
  Landlock `EXECUTE` rule for the copy under `STORAGE_ROOT`; the copy is
  readable and runs, and the test fails. Dropping the `EXECUTE` rule fails the
  test too, but only through the startup refusal. Falsifier for the state row:
  drop the `STORAGE_ROOT` write right; the test fails on the denied identity
  write. Falsifier for the loader reads: refuse the fact syscalls the loader
  uses; the test fails because the provider cannot start.
- `confined_provider_serves_wallet_operations_under_its_root` (Linux
  counterpart) drives `Init`, `status`, `CreateManagedAccount` and
  `ListAccounts`, and requires the account and the storage key under the wallet
  root. The test harness places a copy of `PROVIDER_EXECUTABLE` in
  `STORAGE_ROOT`, under a name other than the original, before the confined
  probe starts and outside the policy. Under the policy the probe first shows
  the copy is present and readable under the `STORAGE_ROOT` grant, and only
  then requires the exec of the copy to fail; a failure before the exec is
  reported as missing evidence with its cause, not as the exec rule's
  refusal. A copy outside every grant would also fail its read, so that probe
  would not decide the exec rule. Falsifier for the exec
  row: add a Landlock `EXECUTE` rule for the copy under `STORAGE_ROOT`; the
  copy is readable and runs, and the test fails. Falsifier for the state row:
  drop the `STORAGE_ROOT` write right; the test fails on the denied account
  write.
- `verify_did_recovery_under_profile` (Linux counterpart) requires
  `invalid_signature` with its reason from the provider under the policy and a
  later `get_did` that proves the service stayed up. Falsifier: make the
  process die in the refusal branch (DID06); the test fails without a response.
- `outside_write_denied` and `confined_outside_write_is_denied` (Linux
  counterparts). As written today, did's `outside_write_denied` writes through
  a link inside the root to two targets, an unrelated directory and a sibling
  of `did/` under `Init.base_path`; wallet's `confined_outside_write_is_denied`
  sends `Init` for three outside bases, an unrelated directory, `base/sibling`
  and `base/ElastOS/SystemServices/Sibling` beneath `STORAGE_PARENT`, and uses
  no link. The Linux counterparts reuse those fixtures: they require
  `storage_error`, no file outside the root, and a later write under the root
  to succeed. Falsifier for either: widen the `STORAGE_ROOT` rule to
  `STORAGE_PARENT`; the sibling write or the beneath-parent `Init` succeeds and
  the test fails.
- `outside_read_denied` and `confined_outside_read_is_denied` (Linux
  counterparts) plant a readable file beneath `STORAGE_PARENT`, outside
  `STORAGE_ROOT`, and reach it through a link from inside the root: did's at
  `STORAGE_PARENT/<sibling>/did/nickname.enc`, wallet's storage key under
  `STORAGE_PARENT/<sibling>/Wallet`. Under the design no read rule covers
  `STORAGE_PARENT`, so the read is refused and the provider stays in service.
  Falsifier: add the `STORAGE_PARENT` read rule; the planted read succeeds and
  the test fails. As written today neither test plants a file beneath
  `STORAGE_PARENT` — did plants it in a separate temporary directory and wallet
  at `base/sibling` — so neither one alone decides the row; the Linux
  counterparts add the fixture. Falsifier for the read of `/` row: add a
  Landlock read rule on `/`; the outside read succeeds, and the test fails, as
  does the model provider's `model_outside_read_denied`.
- `startup_denial_reports_its_reason` (Linux counterpart) starts the provider
  under a policy that denies the exec and requires the failure to name the
  request, the exit status and the policy's reason. Falsifier: drop the reason
  from the failure (DID12); the test fails.
- Each refusal test named in "When a primitive is missing" refuses the start
  for exactly one named failure, requires its own exact reason, and requires
  nothing under `STORAGE_ROOT`. The macOS test
  `startup_is_refused_when_the_profile_cannot_be_applied` covers three
  profile-load failures; the Linux refusals split, so each primitive has one
  name and no test covers two. Falsifiers:
  start the provider unconfined when a primitive is missing (the provider
  answers and the test fails), or return a fixed reason that names no primitive
  (each test fails on the reason).
- `profile_denies_network` runs on Linux today and checks the oracle text.
  `linux_profile_denies_every_socket_family` (new) starts a test probe under the
  same Linux policy and calls `socket(family, type)` for every address family
  number from 0 to `AF_MAX` and every socket type (`SOCK_STREAM`, `SOCK_DGRAM`,
  `SOCK_SEQPACKET`, `SOCK_RAW`, `SOCK_RDM`, `SOCK_DCCP`, `SOCK_PACKET`), and
  `socketpair` for each type, and requires every call to fail with `EPERM`. It
  also requires a `connect` to a Unix-domain stand-in to fail, and the provider
  to stay in service. Falsifier:
  replace the whole-call refusal with a family list that omits `AF_VSOCK`;
  `socket(AF_VSOCK, SOCK_STREAM)` succeeds and the test fails. Because the test
  covers every family number and every type, a list that omits any one of them
  fails.
- `linux_file_operations_landlock_cannot_restrict` (new) uses an isolated
  fixture file and an isolated fixture directory outside every path grant.
  The probe runs under the mapped uid and mapped gids of the policy; the
  fixture file and directory are owned by that uid, the fixture directory
  carries the search bit for that uid (mode `0700`, owned by that uid), every
  parent directory carries the search bit for that uid
  ([chdir(2)](https://man7.org/linux/man-pages/man2/chdir.2.html)), the
  positive control checks its copy of the fixture directory's mode and owner
  before its `chdir`, and the policy run checks its own fixture directory's
  mode and owner before its `chdir`; a mismatch in either copy is reported as
  missing evidence with its cause, not as a kernel change. The file has
  ordinary `0644` permissions so its owner
  may `chmod`, `utime` and `setxattr` it. One mapped supplementary gid
  differs from the file's group and is the target of the group `chown`. The
  file's filesystem supports the chosen `user.*` xattr.
  The calls use the fixture file for `stat`, `chmod`, `access`, `utime`,
  `setxattr` and `chown(path, -1, gid)`, the fixture directory for `chdir`,
  and the fixture file for `openat(AT_FDCWD, path, O_PATH)`, whose descriptor
  the probe duplicates by calling `fcntl(fd, F_DUPFD, 3)` itself with the raw
  `F_DUPFD` command, not through a library duplicate that may use another
  command such as `F_DUPFD_CLOEXEC`, and closes twice. A
  positive control runs the same calls on its own copies of the fixture,
  under the same uid/gid mappings and the same user, mount, PID and IPC
  namespaces without the proposed Landlock ruleset, capability drop or
  seccomp filter, and requires each call to succeed; a fixture the host
  cannot supply, a fixture directory whose mode or owner does not give that
  uid the search bit, a missing uid or gid mapping, a filesystem without the
  xattr, or a call the positive control already refuses is reported with its
  cause as missing evidence, and the probe claims no widening from it. The
  control is a precondition check and claims no policy falsifier. Under the
  policy each call must succeed, the group `chown` must return success and
  the resulting group must be the chosen mapped gid, and the `O_PATH`
  descriptor and its duplicate must both be obtained; a refusal of any of
  these calls under the policy fails the test. The probe reads no file
  content, because `open(2)` gives `EBADF` for a read on an `O_PATH`
  descriptor. Falsifier for the metadata calls: add a seccomp rule that
  refuses `chmod` and `stat` by syscall number
  ([seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)); a
  filter reads syscall arguments as integers, not paths, so the rule cannot
  select only the probe's calls, and the probe and the Rust runtime make
  other `stat` calls.
  The rule can stop the probe before its own calls, so the design leaves this
  falsifier unclaimed. Falsifier for the group case: add a seccomp rule that
  refuses every `chown` by syscall number; the test reports the failing call,
  and the falsifier counts only when that call is the group `chown` itself and
  every earlier call is reported as a success; a failure at an earlier call
  is missing evidence.
  Falsifier for the `O_PATH` open: add a seccomp rule that refuses `openat`
  when its flags carry `O_PATH`; the open fails and the test fails. Falsifier
  for the duplication: add a seccomp rule that refuses `fcntl` only when its
  command argument is `F_DUPFD` ([fcntl(2)](https://man7.org/linux/man-pages/man2/fcntl.2.html));
  the duplication fails and the test fails. The probe and the Rust runtime
  make other `fcntl` calls, so a rule that refuses every `fcntl` could stop
  the probe before its `F_DUPFD` call. A descriptor opened before
  enforcement is not checked: the [filesystem flags](https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags)
  section states that "Files or directories opened before the sandboxing are
  not subject to these restrictions".
  The launch precondition is that a provider inherits no descriptor other
  than its stdin, stdout and stderr protocol streams, which are the harness
  pipes (`Stdio::piped()` in `ConfinedProvider::spawn` in
  `capsules/wallet-provider/tests/confine.rs`); future Runtime work proves
  it, for example by listing `/proc/self/fd` at provider start and allowing
  exactly 0, 1 and 2, and this probe claims no falsifier for it.
- `linux_capability_drop_refuses_chown` (new) probes
  `chown(path, other_uid, -1)` on a file under `STORAGE_ROOT` that the probe's
  mapped uid owns, under the same policy, and requires `EPERM` with the owner
  unchanged, so the narrowing of the files row is observed. The fixture maps
  the file's owner and the target as two different uids; a fixture without
  that mapping supplies a clear reason for missing evidence. A positive
  control under the same uid/gid mappings and namespaces uses its own file
  with the same owner, keeps `CAP_CHOWN` in the capability set, and requires
  the same call to succeed, so the fixture is shown to permit it before the
  policy's refusal is attributed to the drop.
  Falsifier: keep `CAP_CHOWN` in the capability set; the chown succeeds and
  the test fails.
- `confined_provider_denies_process_and_signal_boundaries` (new) requires a
  probe under the same policy to fail to exec a copy of `PROVIDER_EXECUTABLE`.
  The test harness places a copy of `PROVIDER_EXECUTABLE` in `STORAGE_ROOT`,
  under a name other than the original, before the confined probe starts and
  outside the policy. Under the policy the probe first shows the copy is
  present and readable under the `STORAGE_ROOT` grant, and only then requires
  the exec of the copy to fail; a failure before the exec is reported as
  missing evidence with its cause, not as the exec rule's refusal. A copy
  outside every grant would also fail its read, so that probe would not decide
  the exec rule.
  The same probe must fail to fork a new process and to signal a host PID, and
  must fail `ptrace(PTRACE_TRACEME)`, `process_vm_readv` and `pidfd_getfd` on
  its own process; the seccomp rule refuses those three calls by number, so a
  self-target probe observes it without the PID namespace or a Landlock scope.
  Falsifier: remove the PID namespace; the signal to the host PID succeeds and
  the test fails on that assertion. Falsifier for the creation refusal: admit
  the process form of `clone`; the new process starts and the test fails.
  Falsifier for the exec row: add a Landlock `EXECUTE` rule for the copy under
  `STORAGE_ROOT`; the copy is readable and runs, and the test fails. Falsifier
  for the cross-process refusals: allow `ptrace`; the self-trace succeeds and
  the test fails. A host process is not the target here, because the PID
  namespace and Landlock's ptrace restriction would mask that mutation.
- `confined_provider_denies_ipc_boundaries` (new) first creates a SysV queue in
  the host namespace; then a probe under the policy requires
  `msgget(host_key, IPC_CREAT)`, `msgget(IPC_PRIVATE, 0600)` and
  `shmget(IPC_PRIVATE, 4096, 0600)` to fail, `msgget(host_key, 0)` to fail with
  `ENOENT` because the queue is not in the private IPC namespace, a POSIX
  message queue create and a Unix socket pair to fail, and a host shared-memory
  object to fail to open. Falsifier: drop the IPC namespace;
  `msgget(host_key, 0)` returns the host queue and the test fails on that
  assertion, while the seccomp refusals and the Landlock default denial stay in
  place. Falsifier for the `msgget` and `shmget` creation refusals: drop the
  `IPC_PRIVATE` check or the `IPC_CREAT` check; the corresponding create
  succeeds and the test fails on that assertion, because the private IPC
  namespace permits a new object inside itself and Landlock's
  [filesystem flags](https://docs.kernel.org/userspace-api/landlock.html#filesystem-flags)
  restrict files and directories, not SysV objects. The POSIX queue create
  also passes through the message queue filesystem
  ([mq_overview(7)](https://man7.org/linux/man-pages/man7/mq_overview.7.html)).
  Landlock's default denial would refuse that create only if the ruleset
  reaches the queue's internal mount; the cited documents do not settle that
  reach, and if it does not, no other layer refuses the create. The outcome is
  open, so the design leaves the `mq_open` falsifier unclaimed: a future
  isolated probe that drops only the `mq_open` `O_CREAT` refusal and records
  the outcome would settle it.
- `confined_provider_denies_kernel_fact_boundaries` (new) requires a probe to
  fail to read `/proc/kallsyms`, host `/proc/sys` entries outside the grant or
  `/sys` kernel state, and to fail `bpf` and `perf_event_open`. The design adds
  no `/proc` or `/sys` path rule, so the
  [Landlock](https://docs.kernel.org/userspace-api/landlock.html) ruleset
  refuses every read under `/proc` and every read of kernel state under a
  mounted host `/sys`; the private `/proc` mount hides host PIDs and the
  hidden host `/sys` hides sysfs, and no assertion observes either mount.
  Falsifier for the `/proc` read: add a `/proc` read rule to the ruleset; the
  read of `/proc/kallsyms` succeeds and the test fails. The `/sys` read has no
  single-rule falsifier: adding a `/sys` read rule alone leaves the read
  refused because the hidden host `/sys` mount still hides sysfs, and mounting
  the host `/sys` alone leaves it refused because Landlock's default denial has
  no `/sys` read rule. The combined edit of mounting the host `/sys` and
  adding a `/sys` read rule makes the read of `/sys` kernel state succeed, so
  it is an experiment that shows the assertion can fail, not proof of either
  rule; the design leaves a falsifier for the `/sys` read unclaimed. It claims
  no falsifier for either mount, because a mount change alone leaves Landlock's
  default denial in place. Falsifier for the `bpf` refusal, read only when
  the host precondition check passes: allow `bpf`; the probe's call succeeds
  and the test fails. This precondition check is a check of the host and the
  probe's launch, read before the mutation, and it passes only when
  `kernel.unprivileged_bpf_disabled` reads 0
  ([unprivileged_bpf_disabled](https://docs.kernel.org/admin-guide/sysctl/kernel.html#unprivileged-bpf-disabled)),
  the probe's `bpf(BPF_MAP_CREATE, ...)` request
  ([bpf(2)](https://man7.org/linux/man-pages/man2/bpf.2.html)) names a map
  type an unprivileged caller may create, and the process holds a memlock or
  memory-cgroup budget for that map; no primary documentation states which
  budget the kernel charges that map to, so the design treats this condition
  as an open precondition the check reads, not a settled kernel fact. The
  design's empty capability set leaves
  the probe without `CAP_BPF` or `CAP_SYS_ADMIN`, so the kernel treats it as
  unprivileged. A value of 1 or 2 makes the kernel refuse the call with
  `EPERM` without `CAP_SYS_ADMIN` or `CAP_BPF`, and a request outside those
  other conditions is refused by the kernel even when the filter permits it;
  those cases are masked, so the design leaves them unclaimed. The design
  claims no falsifier for `perf_event_open`, because a
  `perf_event_paranoid` value that refuses the probe's event to an unprivileged
  caller can keep the refusal after the filter permits the call
  ([perf_event_paranoid](https://docs.kernel.org/admin-guide/sysctl/kernel.html#perf-event-paranoid)).
- `model_provider_ops_under_profile` (Linux counterpart) drives the model
  provider's named operations and decides the `file-read-data` row. Falsifier
  for the read row: add a Landlock read rule on `/`; the model provider's
  `model_outside_read_denied` fails. Falsifier for its start reads: refuse the
  fact syscalls its loader uses; the provider cannot start.
- `sandbox_gate_fails_instead_of_skipping_on_a_declared_os` (future `linux`
  case) requires a missing Landlock, userns or seccomp on a declared `linux` to
  be an error that names the OS and the primitive. Today the test expects
  `linux` to skip; that expectation changes only with the tests above (027).
