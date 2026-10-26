# Agent conformance discovery and gaps

This is the lane's single gap record. Source evidence establishes the available
interfaces; live results below name their tests. Open blockers remain separate from
the closed AC-010-OFFLINE prerequisite.
Task 006 used the supplied Mission, backlog and task text. `MISSION.md`, the
lane's `BACKLOG.md` and stopped task 001 are absent from this checkout; the
external queue was outside the permitted read scope.

Tasks 010 and 013 settle the operator prerequisite in [Operator in a throwaway
home](#operator-in-a-throwaway-home). Its verdict gates the earlier 006 launch
and grant examples. Tasks 008/009 now own the guard and data-directory proof;
task 019 owns positive-grant acceptance.

## Launch and data directory (006 discovery, 009 no-operator proof)

The non-interactive component command is `elastos run <component-directory>`.
The content-addressed form is `elastos run --cid <bundle-CID>`
(`elastos/crates/elastos-server/src/main.rs:90-113`,
`elastos/crates/elastos-server/src/run_cmd.rs:127-146`). A local directory locates
the fixture; its computed hash identifies the artifact. An artifact SHA-256
alone is not a published bundle CID. CID resolution uses the content provider;
an offline fixture must already have the content available.

The component branch calls `run_component_via_operator_runtime`
(`elastos/crates/elastos-server/src/run_cmd.rs:51-60`). It requires an existing
operator Runtime: `operator_runtime_coords` reads that Home's coordinates and
returns an error if it cannot find one (`run_cmd.rs:165-170`;
`elastos/crates/elastos-server/src/runtime_control.rs:885-891`). It attaches,
awaits `run_local`, and returns after activation (`run_cmd.rs:225-269`). It does
not start `serve` or wait for Ctrl+C. `--with` hosts native providers; it cannot
supply a grant to an app capsule (`run_cmd.rs:24-29`).

`default_data_dir()` delegates to `dirs::data_dir()`, falls back to `/tmp`, then
appends `elastos` (`elastos/crates/elastos-server/src/sources.rs:12-17`). On this
Mac the platform rule is `$HOME/Library/Application Support/elastos`;
`XDG_DATA_HOME` does not move it. The comment above that function describes the
Linux rule. A child-process `HOME="$AC_HOME"` moves the Mac data directory to
`$AC_HOME/Library/Application Support/elastos`. Task 009's
`runtime_data_dir_is_under_throwaway_home` checks this resolution by observing
Runtime remove a decoy at 008's guarded path. `run` has no `--data-dir` option
(`main.rs:90-113`). Both the operator and its `run` child need the same fixture
Home. Clear inherited `ELASTOS_RUNTIME_COORDS_FILE`, which otherwise overrides
coordinate lookup (`runtime_control.rs:446-450`), and select the fixture's
operator kind (`elastos/crates/elastos-server/src/serve_cmd.rs:415-418`).

The fixture uses `tests/common/operator.rs::Operator::start` and the single
`ThrowawayHome` spawn primitive. The ordered operator recipe below contains
`serve`. A later `run` also needs AC-006-STORAGE resolved before it can claim
complete throwaway-root isolation.

Admission is a separate prerequisite. A source fixture can set `dev_mode = true`
in its own data directory's `config.toml` for the unsigned 002 probe; this selects
unsigned admission, not resource grants (`elastos/crates/elastos-server/src/main.rs:2323-2336`,
`elastos/crates/elastos-server/src/runtime.rs:181-227`). Signed-bundle acceptance
still needs its own trust and CID evidence.

### AC-006-STORAGE — component launcher storage isolation

The fixed `/tmp/elastos/storage` also occurs in the component/operator path at
`elastos/crates/elastos-server/src/run_cmd.rs:236`, as well as the generic paths
at lines 62 and 70. `create_runtime` constructs `LocalFSProvider`
(`elastos/crates/elastos-server/src/main.rs:2297-2300`), whose constructor calls
`create_dir_all` (`elastos/crates/elastos-storage/src/providers/local.rs:18-20`).
Changing `HOME` or the operator's `serve --storage-path` does not relocate this
second storage constructor. Thus the source trace establishes the launch API,
not complete throwaway-root isolation. This gate stays BLOCKED until the path
is contained. Task 009's `run_without_operator_is_refused_with_reason` reaches
the operator lookup at `run_cmd.rs:230` and returns before this constructor.
Its contained refusal does not close AC-006-STORAGE. Runtime change that flips the blocker:
Anders makes the existing component launcher derive storage from the selected
Home's data directory instead of the fixed path. This lane adds no launcher.

For plain `serve`, the same path is a CLI **default**
(`elastos/crates/elastos-server/src/main.rs:122-124`). Its explicit
`--storage-path` reaches `create_runtime` unchanged (`serve_cmd.rs:9-12,47`).
Thus an in-root argument contains this constructor for `serve`;
AC-006-STORAGE remains the separate `run` blocker above.

## Operator in a throwaway home

operator recipe: create a fresh guarded Home; install the matching localhost-provider fixture; write the two-setting config; start through the fixed four-entry environment with loopback API and in-root storage; require live readiness and two loopback socket samples; stop and verify the whole process group before removing the root.

1. `ThrowawayHome::new` owns a fresh root under this lane's ignored `target/`.
   `HOME`, `TMPDIR`, the captures and storage stay inside that root; the fixed
   `PATH` selects system tools and `ELASTOS_CARRIER_MDNS=0` disables discovery.
   Every launch uses that same four-entry environment.
2. `write_operator_home` installs the built localhost-provider bytes into
   `D/bin/localhost-provider`, where `D` is the guarded Mac data directory.
   Its minimal `components.json` stamps those bytes' SHA-256, size and native
   platform. It copies `fixtures/operator-config.toml` to `D/config.toml`:
   `dev_mode = true` and `carrier_bind_addr = "127.0.0.1:0"`.
3. `Operator::start` reads the API host from `fixtures/operator-api-host.txt`
   (`127.0.0.1`), selects a free loopback port and starts
   `elastos serve --addr <host>:<port> --storage-path <root>/storage` through
   `ThrowawayHome::start`. The child leads its own process group.
4. Within 60 seconds, while the child stays alive, require that
   `D/runtime-coords.json` exists and loopback `GET /api/health` returns HTTP
   200. The harness checks file existence; Runtime owns its attach data.
5. Through the same launch primitive, take a group internet-socket census at
   readiness and again at least three seconds later, just before stop. Both
   require the API listener and loopback local and remote endpoints. Empty,
   unparseable and non-loopback listings stop the operator and fail.
6. Send SIGTERM to `serve`, allow at most ten seconds for exit and group drain,
   then require an empty process group. A timeout kills the group and fails.
   Dropping an unstopped handle kills its group and retains the root. A passed
   test removes its root only after stop succeeds.

AC-010-OFFLINE is closed by `fixture_operator_starts_ready_and_stops_cleanly`
and `fixture_operator_sockets_are_loopback_only`. The measured census saw two
loopback sockets in each sample, including the API listener. F-ac1j's wildcard
API listener was refused by that real census; F-ac1k checks the fixed mDNS
setting without launching an operator under the mutation. The matching-byte
ready operator is also 012's positive control for the native platform key.

The census takes point-in-time samples of the process group's internet sockets;
it is not a packet capture. It covers this Mac fixture, rather than capsule
effects or other hosts. AC-006-STORAGE stays open for `run`.
A Home-config mDNS key remains a possible Runtime improvement for Anders,
rather than a blocker for this recipe.

Source references without a directory below are relative to
`elastos/crates/elastos-server/src/`. Task 010 supplied the source trace;
task 013 adds the measured fixture results.

### Files and startup ownership

Let `D` be the guarded `$HOME/Library/Application Support/elastos` inside the
lane's throwaway root. The platform rule and its guard remain in the existing
launch/data-directory section and `lab/agent-conformance/src/harness.rs:14-18,192`. The fixture owns
`components.json`, its installed binary and any prewritten config. Runtime
owns first-run state. Key files below are identified only by name and role;
this discovery inspected source, never their contents.

| Path under `D`, unless stated | Reader/writer and startup requirement |
| --- | --- |
| `host-process.lock` | Main authorizes a host start, then `serve` creates `D`, takes the exclusive file lock and writes process metadata. The file can remain after the lock is released (`main.rs:1365-1370`; `host_lock.rs:100-146,177-178`; `serve_cmd.rs:21-30`). A fresh root owns its own lock. |
| `config.toml` | `RuntimeConfig::load` reads it or writes defaults on first run. All config fields are optional; `dev_mode` defaults to false (`elastos/crates/elastos-runtime/src/bootstrap/runtime_builder.rs:57-64,69-125`). A fixture prewrites its admission and bind settings in this one file. |
| `identity/identity.lock`, `identity/device.key` | The session owner loads or creates the device identity before provider startup; the device key backs that identity and local encryption (`server_infra.rs:653-655,726`; `sources.rs:186-188`; `elastos/crates/elastos-identity/src/store.rs:296-319`; `store_files.rs:42-76` in that crate). Runtime creates these files; the fixture supplies neither key bytes nor a real Home identity. |
| `components.json`, `bin/localhost-provider` | Required fixture inputs. `serve` resolves and verifies the installed binary, then starts its stdio bridge (`server_infra.rs:768-806`; `binaries.rs:112-180`). `serve` does not install or download the missing provider. Optional binaries are described below. |
| `signing_key`, `capability_store/` | Runtime's capability signing key and revocation-state directory (`server_infra.rs:631-667`; `elastos/crates/elastos-runtime/src/capability/manager.rs:123-168`, `store.rs:46-63`). An empty store starts with an in-memory epoch; existing `epoch` and `revoked_tokens` are loaded, and later persistence writes them (`store.rs:180-223`). These are separate from the device key. |
| `ca.pem`, `ca.key`, `tls.pem`, `tls.key`, `tls.ips` | Infrastructure attempts local CA/leaf generation and IP-list persistence, even though plain `serve` supplies `tls_config: None` to its HTTP API (`server_infra.rs:669-678`; `serve_cmd.rs:476`; `elastos/crates/elastos-tls/src/lib.rs:21-80,114-115,176-182`). The two `.key` files hold TLS signing material; their contents stay private. |
| `AppCapsules/`, `ElastOS/`, `Local/`, `MyWebSite/`, `Public/`, `Users/`, `UsersAI/`; `namespaces/` | Infrastructure creates the canonical file-backed roots and namespace directory (`server_infra.rs:680,1635-1651`; `elastos/crates/elastos-common/src/localhost.rs:9-17,120-130`). |
| Explicit storage path inside the throwaway root | `serve --storage-path` creates this directory through `LocalFSProvider::new` (`serve_cmd.rs:47`; `main.rs:2297-2300`; `elastos/crates/elastos-storage/src/providers/local.rs:18-20`). This path can be outside `D` but stays inside the fixture root. |
| `runtime-coords.json` | Written after infrastructure setup, before HTTP bind, with owner-only permissions; it carries attach information (`serve_cmd.rs:410-446`; `runtime_control.rs:446-450,624-636`). The inherited coords override is cleared by the lane's launch primitive. Readiness is specified below. |

An empty Home supplies no passkey database or collaboration profile. The
identity manager loads `identity/credentials.json` if present; startup alone
does not register a passkey (`server_infra.rs:1653-1666`;
`elastos/crates/elastos-identity/src/webauthn.rs:234-242`,
`store.rs:407-426`). Missing `collaboration-network-v1.json` selects isolation
without writing a profile or starting a collaboration worker
(`collaboration_startup.rs:34,164-180,264-270`). Content, documents, inspect,
session and audit services are constructed in process (`server_infra.rs:650-724`);
they require no additional executable. The supervisor records capsule and VM
paths without launching or downloading a capsule (`serve_cmd.rs:375-387`;
`supervisor.rs:381-412`). These are startup inputs and outputs, not an inventory
of files later effects could create.

### Native artifacts and the installed manifest

Task 012 shows checksum refusal in `serve_refuses_provider_whose_bytes_differ_from_its_hash`; task 013 adds the matching-byte ready-operator control named above.

Plain `serve` uses `setup_server_infrastructure_impl(true, ...)`
(`serve_cmd.rs:295`; `server_infra.rs:430-431`). Only `localhost-provider` is
mandatory. An absent or rejected `did-provider` is skipped
(`server_infra.rs:740-766`). An absent, rejected or failed shell child is also
skipped (`serve_cmd.rs:327-366`). The three-item prerequisite list
`localhost-provider`, `did-provider`, `shell` belongs to managed runtime startup
(`runtime_control.rs:43-44,1269-1291`); plain `serve` calls its own path directly
(`main.rs:1383-1389`). A shell-scoped attach session is an API role; it does not
require a shell binary.

Other installed/configured services are optional: availability, content block
graph, object, webspace, media, operator drive, IPFS and model
(`server_infra.rs:810-1148`); chain, net, Browser local Exit, Exit, Browser engine
and wallet (`server_infra.rs:1150-1360`); DRM, rights, key, decrypt, protected
content decrypt/protect and custody (`server_infra.rs:1363-1545`). The minimal
fixture omits their manifest entries, binaries and configs. Missing IPFS only
leaves content publish/fetch unavailable (`server_infra.rs:1010-1024`). Carrier
is built into Runtime and is still started (`server_infra.rs:1547-1609`).

For each native provider, `components.json` contains `external.<name>` with
`install_path: "bin/<name>"`, `platforms.<platform>.checksum`, and
`provider_runtime`. The latter has `role: "provider"`, `substrate: "native"`,
`runtime_abi: "elastos.provider-stdio/v1"`, `execution: "native-provider"`,
`provides: "localhost://*"` for localhost-provider. The repository's
`components.json` entry at `external.localhost-provider` is the source for these
fields; it omits `runtime_only`, whose default is false. The fixture copies that
entry instead of restating its fields. These type/URI checks are in
`setup.rs:95-153,198-236`.
The top-level `profiles` map is required and can be empty; `capsules` defaults
empty (`setup.rs:34-55`). Optional version, URL, CID and install-strategy fields
are not required for this already-installed binary check (`setup.rs:95-109,170-189`).

Use the native platform key (`darwin-arm64` or `darwin-amd64` on Mac;
`setup.rs:940-957`) and `sha256:<hex digest of the copied binary bytes>`.
The resolver requires the exact install path and a nonempty current-platform
checksum (`binaries.rs:137-168`). Verification requires an installed-root path,
compares the binary bytes, and rejects an archive `extract_path` for this route
(`setup.rs:969-1033,1046-1075,2727-2740`). The provider name locates a manifest
entry; the checksum identifies its code. The fixture copies the executable
into `D/bin/` and hashes that copy; a build-directory override alone does not
satisfy installed verification. It supplies a minimal local manifest, separate
from signed-release provenance.

`localhost_provider_under_test()` now builds the required provider through the
same offline helper and native target as `runtime_under_test()`. LOG records
the measured build. The helper uses the committed lockfile, cached dependencies,
`CARGO_PROFILE_DEV_DEBUG=0`, and cleared Rust flags. Its command is:

```sh
cargo build --locked --offline --manifest-path elastos/Cargo.toml \
  -p localhost-provider --bin localhost-provider
```

The helper keeps the binary at `target/runtime/debug/localhost-provider`,
intermediates at `target/runtime/build` and scratch files at `target/runtime/tmp`
inside this lane. Builds use the checkout as input. The optional DID provider
remains outside this fixture. A native build failure remains a prerequisite
failure; effect tests need their own behavior evidence.

### Network decision: AC-010-OFFLINE

The backlog's possible community-bootstrap dial needs qualification. Carrier
starts unconditionally, but a fresh Home's missing collaboration file produces
an empty community bootstrap list (`collaboration_startup.rs:78-89,164-180`).
The separate operator peer store seeds only peers it contains
(`carrier.rs:899-920,2044-2049`). Community IDs also select the hub role
(`carrier.rs:2051-2072`); their passage to startup alone does not prove a dial.

With a cleared environment, Carrier selects direct/Minimal networking, without
public relay or public address discovery (`carrier.rs:1521-1541,1754-1770`).
Its default listener is `0.0.0.0:4433` (`carrier.rs:1921-1922,2010-2022`). The
Home can set `carrier_bind_addr = "127.0.0.1:0"` in `config.toml`
(`carrier.rs:1845-1864`). That clears the other IP transports, disables port
mapping and refuses a failed explicit bind instead of falling back to a
wildcard (`carrier.rs:1792-1805,1833-1841,2020`).

LAN mDNS discovery is a separate startup service. It defaults on and reads only
`ELASTOS_CARRIER_MDNS`; `0`, `false` or `no` disable it
(`carrier.rs:1209-1221`). The node constructs and adds that lookup after binding
the endpoint (`carrier.rs:2024-2035`). Thus a loopback Carrier listener does not
by itself establish zero LAN discovery traffic. Task 013 extends the one launch
primitive with the documented
`ELASTOS_CARRIER_MDNS=0` entry, as 008's extension rule permits. The environment
test checks exactly HOME, TMPDIR, PATH and that entry. The two live operator
tests above close AC-010-OFFLINE with the existing Runtime control.

The other minimal-start surfaces have local roles: the HTTP API binds the
explicit `--addr 127.0.0.1:<port>` (`api/server.rs:538-547`; its CLI default is
wildcard at `main.rs:118-120`); localhost-provider uses stdio
(`elastos/capsules/localhost-provider/src/main.rs:822-847`); TLS setup invokes
`hostname -I` and falls back to loopback addresses (`elastos/crates/elastos-tls/src/lib.rs:188-210`).
Collaboration stays isolated as above, optional network providers stay absent,
and the content repair worker defaults off (`server_infra.rs:2005-2012`). This
source trace is supplemented by the two socket samples above. Their scope is
process-group internet sockets at those times; packet traffic remains outside
this measurement.

### Readiness, stop and unsigned admission

The harness waits for both the coordinates file and a successful loopback
`GET /api/health` on its chosen port while its child remains alive. The
coordinates write and the printed attach-ready line precede HTTP bind
(`serve_cmd.rs:437-446,462-483`; `api/server.rs:538-547`), so the file alone is
insufficient. Wait for health before invoking `run`: its coordinate validation
can remove the file if it races startup. `run` requires a live PID, a loopback
API URL, successful health and matching attach credentials, then an operator
runtime kind (`runtime_control.rs:769-810,885-891`; `run_cmd.rs:165-170,230`).
Runtime consumes its own attach data; this discovery reads or prints none.
Any later credential controller remains subject to its separate task rules.

For stop, send SIGTERM to the fixture-owned `serve` process and wait/reap it
and its owned process group. On Unix, `serve` creates its own group; its signal
handler forwards SIGTERM to the group and escalates to SIGKILL after two
seconds (`main.rs:71-75,1284-1322`). This is the existing bounded stop path,
not proof that every async destructor runs. Normal server return additionally
shuts down collaboration and Carrier (`serve_cmd.rs:484-495`). The fixture
verifies child termination and an empty process group before removing its root.
Residual coords are fixture state, not a readiness claim for a later run.

The unsigned probe requires `dev_mode = true` in this Home's `config.toml`
before both `serve` and `run` construct Runtime (`main.rs:2323-2336`). This
applies to a source fixture with no installed signed-release source: installed
release admission takes precedence over `dev_mode`
(`runtime.rs:181-227`). Admission changes neither capability grants nor
provider checksums. AC-006-STORAGE still gates the attached `run` constructor,
after this operator recipe is accepted. Open blockers retain their BLOCKED grade.

## Positive-grant decision for 003

Task 019 uses the production shell-authenticated approval routes through the
one controller in `tests/common/grants.rs`. The root is
`localhost://Public/agent-conformance-grants`, and the one manifest bound is
`localhost://Public/agent-conformance-grants/*`. Task 003's resources stay
outside this bound. The bound permits a request; the operator supplies the grant.

The controller reads only the fixture's `attach_secret` field into memory and
attaches once with scope `shell` at the port owned by `Operator`. The secret,
session token and returned grant tokens stay in memory. The controller uses
`GET /api/capability/pending`, matches resource/action/reason exactly against
`fixtures/grants.json`, and posts one `once` grant for the listed read. Every
other pending request receives the fixture denial reason. Ambiguous matches
are denied before any grant is selected. The Runtime mints the grant for the
requesting session (`api/handlers/capability.rs:339-346`); the observed guest
invocation checks that the requesting client can use it.

Seed preparation uses Runtime writes through the existing production
`/api/provider/localhost/write` route with the controller's shell session.
Runtime owns the provider's stored representation. The fixture supplies ordinary
bytes from `fixtures/granted-bytes.txt`; the guest independently compares the
complete UTF-8 response and its byte count. The fixture reads no encryption key.
The `Public` root requires no principal, so this does not claim UsersAI or
principal-bound storage acceptance.

`granted_read_succeeds` requires one matched pending request and one grant,
then exit 0 after the guest byte check. `ungranted_sibling_read_is_refused`
requires one pending denial and exit 1 with the delivered fixture reason.
Both require credential checks, two loopback socket samples and operator group
drain. The files' bytes stay in the guest. LOG.md records the measured results.
The secret test also requires every expected capture and a nonempty source,
report and serialized-receipt inventory. Runtime owns the original coordinates;
controller copies remain in memory. These checks retain the existing grant,
admission, package-identity and process-isolation acceptance boundaries.
F-ac1a expands the parent fixture directory's approval to its two exact child
entries; F-ac1b changes only the host seed. They distinguish grant enforcement
from file content checking without adding an alternate matcher or provider path.

AC-006-STORAGE still describes the attached launcher's scratch path, and
AC-002-ARGS still describes runtime selectors and success payloads. The new
checks prove the build-time read effect, rather than those separate claims.

## AC-002-ARGS — selector and success payload

AC-002-ARGS remains open. Runtime owns the channel that supplies a selector to
the component and returns its result. The intended selector is one of
`read:<path>`, `net:<resource>`, `model:<resource>` or `address:<instance>`.

The existing `elastos/wit/elastos-bus-v1.wit:87` exports `lifecycle.run()` with zero
arguments and `result<_, bus-error>`. Its imported interfaces expose runtime
information, identity, capability requests and provider invocation. They expose
neither launch arguments nor an output stream. The instantiation helper used
by `ComponentProvider::start` in
`elastos/crates/elastos-compute/src/providers/component.rs:133` calls this entry
without forwarding launch arguments; `component.rs:183` initializes
`CapsuleHandle.args = Vec::new()`. Thus a selector on `elastos run` cannot reach
this component. Runtime change that flips AC-002-ARGS: Anders extends the typed
lifecycle WIT with an activation selector and result payload, then updates the
ComponentProvider bindings and CLI result forwarding in `elastos/`. The same
Bus path must carry both; this lane adds no alternate channel.

A guest can still attempt one build-time-fixed effect at activation through
the `capabilities` and `providers` imports
(`elastos/wit/elastos-bus-v1.wit:72-95`). If it propagates the Bus refusal as its
lifecycle error, Runtime surfaces the reason on `elastos run`'s nonzero
exit/stderr. The exact source format is `Component capsule denied: {err:?}`
(`component.rs:135`), wrapped by `Component capsule failed: {}`
(`elastos/crates/elastos-server/src/run_cmd.rs:264-267`). For the current probe,
the source-derived inner string is
`Component capsule denied: Unavailable("probe launch arguments are unavailable in elastos:bus@v1")`
(`lab/agent-conformance/probe/src/lib.rs:14-25`). This is not an observed launch
transcript: **to confirm in 003**. A successful lifecycle call returns unit;
provider response data can reach the guest, but no success payload reaches the
CLI through `lifecycle.run`.

The initial probe attempted no effect. Tasks 003/004/005 select one fixed
effect with a Cargo feature on the same probe source, check its response inside
the guest and propagate a clear error on failure. AC-002-ARGS does not block
that refusal experiment. A zero exit alone remains insufficient effect proof.

The current import fixture in `component.rs` includes `types`, `runtime`,
`identity`, `capabilities` and `providers`; the task's three-interface description
is older than that fixture. The artifact check retains the task's narrower
three-interface set (`types`, `runtime`, `identity`). This component needs only
Bus types for its refusal. Enabling an effect will also need agreement on the
requested import scope.

The existing tests cover component bytes, manifest/WIT agreement, imports and
two independent builds on this machine. They grade artifact properties only.
Signed-bundle identity, Runtime admission and effect evidence remain with later
tasks. Stopped 007 split into 008's harness and 009's contained refusal; 010
supplied operator discovery and 013 now proves the ready-operator recipe.

Task 006 made zero spike launches and skipped the full Runtime build. Task 009
checks Mac data-root resolution in `tests/runtime.rs::runtime_data_dir_is_under_throwaway_home`
and no-operator refusal stderr in `tests/runtime.rs::run_without_operator_is_refused_with_reason`.
Task 008's guard and cleared launch environment protect the real Home by
construction; this lane reads only its fixture Home. The real-Home digest was
dropped when 007 split into 008 and 009. Grant delivery and component-effect
refusal stderr remain with the later effect and grant tasks.
AC-010-OFFLINE is closed by the two named operator tests; AC-006-STORAGE and
AC-002-ARGS remain open.


## Task 003 — ungranted requests through the live Bus

Task 003 supersedes the earlier pending effect experiment. The default build
still returns AC-002-ARGS, now measured by
`default_activation_refuses_without_selector`. The `read` and `network` Cargo
features select one request each on the same probe source. The existing build
script accepts inherited `RUSTFLAGS`, so the shared build helper passes
`--cfg feature="read"` or `--cfg feature="network"`. It saves each build's bytes
before the next build. The five allowed imports are Bus v1 `types`, `runtime`,
`identity`, `capabilities` and `providers`; foreign and wrong-version imports
remain refused.

The deny-only probe requests `read` on the synthetic resource in
`fixtures/ungranted-read.txt`, or `execute` on `elastos://net/stream` from
`fixtures/ungranted-network.txt`. These resources are outside the probe's fixture-directory
manifest bound and outside future granted fixture directories. The Runtime
owns resource authority. Its manifest refusal returns through the guest's Bus
call and lifecycle to `elastos run`. The live wrapper uses
`Component capsule denied: BusError::Internal("capsule manifest does not declare authority for <resource>")`;
the default build uses `BusError::Unavailable` with the AC-002-ARGS reason.
The probe returns immediately after the
request, including unexpected success, so this check performs no provider
invoke, storage read or network effect. A successful request makes its refusal
test fail. Network provider execution is a separate acceptance question.

`tests/effects.rs` uses 013's `Operator::start`, readiness, two socket samples
at least three seconds apart, and process-group stop. It uses the existing
Runtime build and guarded launch primitive throughout. The fixture's operator
captures and attach data stay unread. AC-006-STORAGE remains the recorded
Runtime-owned constructor exception; this lane reads nothing through it.

| Ignored test | Blocker ID | Runtime change that enables acceptance |
| --- | --- | --- |
| `ungranted_model_call_is_refused` | RT3 | Anders supplies the component model-call grant contract and its refusal path. |
| `operator_storage_is_under_throwaway_home` | AC-006-STORAGE | Anders derives the `run` client's storage path from the selected Home, as specified above. |

Both rows are `#[ignore = "blocked: <ID>"]`, print BLOCKED in the one table,
and fail explicitly if forced with `--ignored`. They supply zero passing
acceptance checks. AC-010-OFFLINE remains closed by 013's measured operator
recipe. The positive-grant controller is carried by task 019; launch by bundle
CID remains a separate task. Artifact SHA-256 identifies the exact local
component bytes used here and is separate from signed-bundle admission.


## 005 — parallel activation scope

Runtime owns activation and its resource limits. The harness starts four
`elastos run` clients against one fixture operator, with a different guarded
Home for each client. `RunningInstances` extends the existing spawn primitive
and collects natural exits under one wall-clock deadline. The fixed
`ELASTOS_RUNTIME_COORDS_FILE` entry points to the borrowed operator Home; Runtime
reads that file for client attach. The grant controller is the one fixture reader
of its attach credential. The harness checks both Homes.
Inherited coordinate overrides remain cleared.

The client path constructs a ComponentProvider in each `run` process
(`run_cmd.rs:236-269`). Attaching four client sessions to one operator therefore
proves **process isolation, not capsule isolation**. RT4 remains open: Anders
supplies Bus v2 resident component instances with independent lifecycle and
resource ownership inside one Runtime before that claim can pass.

| Ignored test | Blocker ID | Runtime change that enables acceptance |
| --- | --- | --- |
| `parallel_capsules_complete_independently` | RT4 | Resident component lifecycle and concurrent instances hosted by one Runtime. |
| `parallel_instances_return_success_payloads` | AC-002-ARGS | Typed lifecycle success payload and CLI result forwarding, through the existing Bus path. |

Both tests fail explicitly when forced with `--ignored` and remain BLOCKED in
the table. The finite process fallback performs four different additions
inside the same probe source. A build-time `task` feature and fixture index
select the task; the guest receives neither launch arguments nor an environment.
Each completed computation returns its distinct diagnostic through
`BusError::Unavailable`, which reaches CLI stderr with exit 1. The live test
requires the expected computed value and excludes every sibling result from
both captures. This is diagnostic completion only. It supplies no evidence for
success payloads, grants, principal separation, or shared-scratch isolation.
AC-006-STORAGE retains its existing scope and blocker.

### AC-005-REASON — resource-stop cause on the CLI

`process_isolation::runaway_is_stopped_with_reason` is
`#[ignore = "blocked: AC-005-REASON"]`. Runtime must preserve the resource-stop
cause from Wasmtime through ComponentProvider and `elastos run` stderr (for
example the fuel-exhaustion cause). The strict test still requires that cause,
a natural exit with code 1 inside ten seconds, and three completed siblings.
It remains BLOCKED and is excluded from passing acceptance.

The measured runaway returned naturally after 0.053 seconds, with the
`Component lifecycle run failed: error while executing at wasm backtrace:`
context. The CLI omitted the fuel cause. Source inspection finds a fuel budget
of 100,000,000 and a 128 MiB memory limit in
`elastos/crates/elastos-compute/src/providers/component.rs:28-29,80-97,121`;
the error conversion at line 134 formats only the outer error. These constants
are Runtime-owned and have no fixture override. Source presence alone does
not supply the missing CLI reason.

`process_isolation::runaway_trap_is_bounded_while_siblings_finish` is the narrower
live check: it requires a natural lifecycle trap within ten seconds and all
three diagnostic completions. A harness timeout or signal exit fails. F-ac3a
changes the runaway probe loop to a short finite loop; it tests this live
bounded-trap evidence only. Its result does not close AC-005-REASON. The strict
reason test remains available with `--ignored` for the future Runtime fix.


## 004 — agent memory and the shared authority model

Runtime owns each verified agent principal and its resource grants. The same
probe now has a `memory-write` build feature, with its target in
`fixtures/memory-write.txt`. It requests write authority before invoking the
Bus provider. `human-read` is a build-time variant of the existing `read`
feature; `fixtures/human-read.txt` supplies its target. Neither variant reads
guest environment variables or receives a runtime selector.

### UsersAI binding — principal-scoped agent launches

Anders must bind the existing component launch to a verified agent principal,
resolve `UsersAI/self` to that principal's root, and enforce the principal and
explicit Runtime grants on every access to an agent or human object. The
human-side reference is `principal_localhost_root` and the bridge's
`scope_current_user_alias`; agent-side acceptance uses the same authority
model. `run_cmd.rs::run_component_via_operator_runtime` currently calls
`Runtime::run_local`, whose principal context is `None`. Runtime must carry
its verified launch principal through this existing path. A fixture label or
a separate Home supplies zero principal evidence.

| Ignored test | Blocker IDs | Acceptance after the Runtime change |
| --- | --- | --- |
| `agent_memory_under_own_principal` | UsersAI binding; AC-002-ARGS | Launch the two identities in `fixtures/agent-principals.json` through the existing primitive, write one memory object each, and compare the Runtime's resolved owners and distinct roots. |
| `agent_cannot_read_other_agent_memory` | UsersAI binding; AC-002-ARGS | Launch agent-b with its verified context, request agent-a's exact memory path, and require a reason with zero returned bytes. F-ac2a then explicitly grants that read. |
| `agent_can_read_human_space_with_grant` | UsersAI binding; AC-002-ARGS | Reuse `Controller` to seed the human object and grant the verified agent its exact read; compare the complete bytes inside the existing probe read path. |

These tests are explicit failing placeholders when forced with `--ignored`.
They remain BLOCKED until the verified launch and typed selector/result seam
can be wired into the existing helpers. AC-002-ARGS requires the WIT,
ComponentProvider and CLI forwarding change described above, including the
resolved ownership result. Merely removing an ignore or changing a fixture
cannot establish acceptance. F-ac2a and F-ac2b are retired in `falsifiers.json`
under `UsersAI binding; AC-002-ARGS` until their named tests become live.
F-ac2a grants agent-b agent-a's exact memory path for
`agent_cannot_read_other_agent_memory`. F-ac2b changes agent-b's principal to
agent-a for `agent_memory_under_own_principal`. Return each mutation to the
active list when its named journey is live; both supply zero caught evidence
while retired.

`agent_cannot_read_human_space_without_grant` is the live refusal half. It
requires the Runtime's principal-context refusal for `Users/self` through the
003 read feature. This proves refusal for today's unbound CLI launch; the
verified agent's refusal/positive-grant pair remains under both blockers above.
`ungranted_memory_write_is_refused` requires a manifest-authority refusal from
the memory-write Bus request. It proves the request cannot write without
allowance, rather than proving principal-scoped storage. The new variants also
undergo the existing two-build hash, import and feature-exclusivity checks.

`no_policy_file_does_not_mean_allow` attempts one in-manifest read using the
existing granted-read probe. `fixtures/no-policy.json` is absent in the
baseline. The existing Controller attaches only to seed the known object and
check credential surfaces; it supplies zero approval or denial decisions.
The Runtime must exit naturally with its explicit pending-request refusal
within the collector's 40-second bound. A collector timeout or any other
error fails. The capsule's manifest and successful admission supply zero
grant credit. F-ac2c creates that optional policy file with an exact entry for
the one attempted effect; the same Controller then approves the pending
request. The guest checks every byte and exits successfully, which must fail
the refusal assertion. This is a controller-owned fixture policy, using the
existing approval API; it claims no Runtime policy-file loader.

AC-010-OFFLINE remains closed by 013's measured recipe. AC-006-STORAGE keeps
its existing `run` constructor scope. All these launches use the existing
operator census, guarded spawn site, bounded collector and group cleanup.
A missing-policy acceptance failure receives private triage under spec section
6. The test always remains active; only a neutral blocker belongs here.

## 017 — M1 A8, one fake host-file route

Runtime owns access to files through the Bus. The `host-key-read` build uses
`localhost://Public/../../../../.ssh/id_ed25519` as its fixed resource.
The one data-dir rule in `src/harness.rs::data_dir` gives
`<home>/Library/Application Support/elastos`; a file-backed `Public` root adds
one level. Four parent segments therefore name `<home>/.ssh/id_ed25519`.
`host_key::fixture_path_uses_the_guarded_home_rule` checks this depth from that
rule without resolving the resource on the host. The fixture copies only the
committed fake marker, through exclusive creation inside the guarded home,
before the operator starts. It sits outside every Runtime Home root.

The first refusal is the `run` client's manifest bound in
`elastos/crates/elastos-server/src/resource_bridge.rs:1379`. Its lifecycle reason
is exactly `Internal("capsule manifest does not declare authority for localhost://Public/../../../../.ssh/id_ed25519")`.
`host_key_read_is_refused` requires that reason, a nonzero exit, zero controller
decisions, marker-free stdout/stderr and unchanged fake-file bytes. F-ac8a adds
only this exact manifest bound and the matching one-use fixture grant. Both
named F-ac8a tests observed one grant, then the provider's
`Path traversal not allowed` reason with unchanged fake bytes. Its parent-segment
check is in `elastos/capsules/localhost-provider/src/main.rs:300`. LOG.md records
the commands and same-run receipts.

This proves one named Bus route to one fake file outside the Home roots. Other
routes and key stores require separate journeys. The fixture owns only its fake
file; Runtime keeps ownership of its first-run state. The real home and Runtime
key stores stay outside the probe's inputs. AC-006-STORAGE retains the existing
component client's fixed scratch-path exception. All other fixture reads and
writes stay inside the repository. Local fixture traffic uses loopback.

The new build uses the existing component, import gate, SHA-256 staging and
complete bundle lab CID. The existing report requires its launched identity for
both this row and `attach_secret_stays_in_memory`; each A8 result is read with
that invocation's VERSIONS.json. Identity, unsigned fixture admission and the
explicit grant decision remain separate. The credential check runs before
refusal assertions, including under F-ac8a. It covers both process captures,
actual printed journey lines, the rendered report, serialized receipt, committed
lane blobs and candidate source files. Missing coverage fails with a fixed
reason; the fake marker is separate from the in-memory fixture credentials.

## Cleanup census — lab half of A10/A11/A12 (021)

The existing read journey collects every `run` child, then its fixture shell
checks `/api/capability/pending` and `/api/capability/list` while the operator
is still alive. `Operator::finish_check` takes its second socket sample, stops
the operator group, and checks the root through the shared census module.
Each read journey prints one checked `cleanup census:` line. A leftover fails
the journey and identifies the retained Home by its lane-relative name.

The physical check covers handles on named files, directories, current
directories and sockets under this throwaway root, the operator's loopback API
port, and entries in this root's `tmp/`. The root scan uses one bounded lsof
call. Its tool runs through the existing spawn site in a separate scratch Home;
after exit, its captures move into the journey's existing capture inventory.
Only the test PID is excluded. On macOS, lsof exit 1 means that some selected
`+D` entries have zero handles, even when other entries match. That selection
result is parsed; warnings, other exit codes and malformed records fail.
The live socket samples retain their existing success requirement.

This is a point-in-time census, with a five-second lsof limit and a 200 ms API
connection limit. Pending requests must be empty for the granted and denied
fixture journeys. The earlier absent-policy journey keeps its refusal scope
and reports its pending/grant checks as unmeasured. Cancel, worker kill,
settlement and whole-device cleanup need the later journey. AC-006-STORAGE
remains open: `/tmp/elastos/storage` is the known outside-root leftover. The
census neither enumerates nor reads nor removes that directory. The table's
scope and the same invocation's VERSIONS.json keep these limits visible.

### AC-021-GRANTS — cross-session live-grant visibility

`run_leaves_no_live_grant` is ignored with `blocked: AC-021-GRANTS`. When
explicitly selected, it reuses the granted-read journey and requires a global
live-grant result before the Home can pass. The normal journeys report this
check as BLOCKED, including when the shell's own list is empty.

Runtime owns the grant lifetime. A `once` approval sets `max_uses = 1`
(`elastos/crates/elastos-server/src/api/handlers/capability.rs:335`). The first
successful validation spends that allowance; the next validation is refused
(`elastos/crates/elastos-runtime/src/capability/manager.rs:485` and
`capability/store.rs:140`). The allowance is consumed at validation, rather
than waiting for a provider's successful result.

The `run` client attaches shell and client sessions
(`elastos/crates/elastos-server/src/runtime_control.rs:917`), then returns from
`run_local` without a detach or grant-revoke call (`run_cmd.rs:264`). Thus client
exit alone does not end its grants or prove their absence. The shell can see
all pending requests (`api/handlers/capability.rs:244`), but the current list
selects grants by the caller's session (`api/handlers/capability.rs:433`). Its
rows describe granted requests; they are not a global inventory of remaining
allowances. Audit events provide supporting history only.

The Runtime change that flips this check is a shell-authorized view of every
session's live grants, with exhausted, revoked and expired grants filtered by
Runtime. The fixture expects the existing list response to identify that view
with `scope: "all_sessions_live"` and `capabilities: []`. A session-local or
unmarked response stays BLOCKED. A global nonempty list fails with `live grant
leftover`. This is a future response contract, not a claim that Runtime exposes
it today. Client callers retain their own-session view. This lane changes zero
Runtime routes and performs zero revocations. F-cleanup-grant is deferred until
this blocker closes; the synthetic scope falsifier tests honest grading only.

Before tests, `run.sh` uses the existing report executable to check earlier
`target/home-*` roots. It selects only those direct children (two-second limit)
and uses the same five-second lsof path. A live holder prints its PID and root
name, fails the command, and stays owned by the operator who started it. The
check reads metadata only and leaves the build tree outside its selection.
