# did-provider confinement

`confine.sb` supplies the DID reference pattern for provider confinement.
It starts with `(version 1)` and `(deny default)`. The process reads requests
from stdin and writes responses to stdout. It opens no network listener or
socket, and the profile grants no network operation.

Runtime passes the canonical `PROVIDER_EXECUTABLE`, `DID_STORAGE_ROOT`
(`Init.base_path/did`), and `DID_STORAGE_PARENT` (`Init.base_path`). Runtime
creates the base before launch. One recursive read/write grant covers the
identity directory. The existing parent has literal read access for startup.
The other grants let the process load its binary and system libraries, read
kernel facts, and obtain entropy from `/dev/urandom`.

The Runtime owns the profile: it loads `confine.sb` only from the signed
provider bundle, checks its hash, refuses any profile with `(allow default)` or
a network allow, and fails closed with a reason; the provider proposes, the
Runtime checks (P4, P11). The bridge integration loads this file and binds the
three parameters when it launches the provider. This document specifies the
Runtime half; the reference files exercise the provider directly.

`tests/confine.rs` runs the real binary under `/usr/bin/sandbox-exec` and uses
the line-delimited JSON protocol. It covers every operation in `capsule.json`,
persists an encrypted nickname and persona, reloads them, and checks refusal
of writes to both an unrelated base and a sibling under the shared base.
The provider must answer after each refusal. The test uses a disposable key
held only in its process and removes its temporary state on completion.

Run `cargo test --locked --manifest-path capsules/did-provider/Cargo.toml`
from the repository root. When `sandbox-exec` is absent, native tests print a
skip reason. A present sandbox that refuses to launch the child fails the test.
`profile_denies_network` runs on every platform and rejects a network grant or
`(allow default)`, including one appended after `(deny default)`.

To falsify the write boundary, temporarily replace `(deny default)` with
`(allow default)` and run `confined_outside_write_is_denied`; the outside
nickname write succeeds and the test fails. Restore the profile afterward.
The wallet reference uses the same launch and subtree-grant pattern in
`../wallet-provider/`, with a separate test that reaches an outside key read.
