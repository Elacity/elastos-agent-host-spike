# Agent conformance discovery and gaps

This is the lane's single gap record. Source evidence establishes the available
interfaces; it does not prove a live effect. Every blocker below remains open.
Task 006 used the supplied Mission, backlog and task text. `MISSION.md`, the
lane's `BACKLOG.md` and stopped task 001 are absent from this checkout; the
external queue was outside the permitted read scope.

Task 010 settles the operator prerequisite in [Operator in a throwaway
home](#operator-in-a-throwaway-home). Its verdict gates the earlier 006 launch
and grant examples. Tasks 008/009 now own the guard and data-directory proof;
the later grant-controller task owns positive-grant acceptance.

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

Commands for the future fixture, after its isolation gate is met: `AC_ELASTOS`
is the absolute candidate binary, `AC_HOME` is its temporary Home, `AC_PORT` is
its reserved loopback port, and `AC_PROBE` is its verified component directory.
The fixture owns and stops the long-running first process; the second exits.

```sh
env -u ELASTOS_RUNTIME_COORDS_FILE HOME="$AC_HOME" ELASTOS_RUNTIME_KIND=operator \
  "$AC_ELASTOS" serve --addr "127.0.0.1:$AC_PORT" --storage-path "$AC_HOME/storage"
env -u ELASTOS_RUNTIME_COORDS_FILE HOME="$AC_HOME" \
  "$AC_ELASTOS" run "$AC_PROBE"
```

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
second storage constructor. Thus the commands above establish the launch API,
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

blocked: AC-010-OFFLINE — Runtime change: read a typed `carrier_mdns = false` setting from the selected Home's `config.toml` in the existing Carrier startup path and skip mDNS construction before it opens discovery sockets; combine it with the existing loopback bind and empty peer configuration. Task 003 keeps the operator-dependent tests BLOCKED until this home-config control and its zero-off-box-traffic evidence exist.

This is a source-derived fixture prerequisite, not a live result. References
without a directory below are relative to
`elastos/crates/elastos-server/src/`. The scope is plain `serve` on this Mac,
with only the required provider installed, an empty peer inventory and the
008 launch environment (`lab/agent-conformance/src/harness.rs:201-207`).
Runtime and provider builds and launches were excluded from task 010.

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

The repository's `components.json` entry `external.localhost-provider` is the
fixture's source. For each native provider, `components.json` contains `external.<name>` with
`install_path: "bin/<name>"`, `platforms.<platform>.checksum`, and
`provider_runtime`. The latter has `role: "provider"`, `substrate: "native"`,
`runtime_abi: "elastos.provider-stdio/v1"`, `execution: "native-provider"`,
`provides: "localhost://*"` for this provider. Its entry omits `runtime_only`,
which defaults to false. These type/URI checks are in `setup.rs:95-153,198-236`.
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

Task 012's shared provider fixture and checksum refusal are shown by `serve_refuses_provider_whose_bytes_differ_from_its_hash`; ready-operator acceptance remains with 013.

Source permits the following offline builds with the committed lockfiles and
an already-installed toolchain/dependency cache. **Neither build was run in 010**:
offline cache completeness and successful native compilation were unmeasured in that task.
There are no package-local build scripts in these provider folders or their
local common/guest/identity dependencies. `--locked --offline` refuses missing
resolution inputs instead of fetching or changing a lockfile. Both output
directories override the shared root build directory (`.cargo/config.toml:1-10`).

`AC_LANE` denotes the absolute `lab/agent-conformance` directory. A future build
owner first checks disk space and creates `target/native-tmp` there. These are
build commands, not authorization to start an operator while the verdict is
BLOCKED:

```sh
# Required: elastos/capsules/localhost-provider/ (elastos/Cargo.toml:23).
(cd elastos && env CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 RUST_TEST_THREADS=2 \
  CARGO_TARGET_DIR="$AC_LANE/target/native" \
  CARGO_BUILD_BUILD_DIR="$AC_LANE/target/native-build" \
  TMPDIR="$AC_LANE/target/native-tmp" \
  cargo build --locked --offline --release -p localhost-provider --bin localhost-provider)
# Optional: capsules/did-provider/ has its own workspace and Cargo.lock.
env CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 RUST_TEST_THREADS=2 \
  CARGO_TARGET_DIR="$AC_LANE/target/native" \
  CARGO_BUILD_BUILD_DIR="$AC_LANE/target/native-build" \
  TMPDIR="$AC_LANE/target/native-tmp" \
  cargo build --locked --offline --release \
    --manifest-path capsules/did-provider/Cargo.toml --bin did-provider
```

Outputs would be `target/native/release/localhost-provider` and, if requested,
`target/native/release/did-provider`. Their manifests name those binary targets
and local dependencies (`elastos/capsules/localhost-provider/Cargo.toml:1-24`;
`capsules/did-provider/Cargo.toml:1-37`). Builds use the checkout as input;
generated artifacts stay in the lane. A native build failure remains a
prerequisite failure, never evidence about a probe effect.

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
by itself establish zero LAN discovery traffic. There is no Home-file switch
in these selectors that disables mDNS or the whole Carrier node. The existing
environment switch is real, but 008 deliberately supplies exactly HOME,
TMPDIR and PATH (`src/harness.rs:201-207`, `tests/harness.rs:82-105` in this lane).
An `env` wrapper or a second launch path would change that contract. Task 010
therefore records AC-010-OFFLINE, rather than asserting that all offline
operator use is impossible. The Runtime change is named in the verdict above;
this task adds neither a config parser nor a network workaround.

The other minimal-start surfaces have local roles: the HTTP API binds the
explicit `--addr 127.0.0.1:<port>` (`api/server.rs:538-547`; its CLI default is
wildcard at `main.rs:118-120`); localhost-provider uses stdio
(`elastos/capsules/localhost-provider/src/main.rs:822-847`); TLS setup invokes
`hostname -I` and falls back to loopback addresses (`elastos/crates/elastos-tls/src/lib.rs:188-210`).
Collaboration stays isolated as above, optional network providers stay absent,
and the content repair worker defaults off (`server_infra.rs:2005-2012`). This
is a source trace, not a socket census or packet capture. The later live gate
must measure zero off-box traffic before it can accept an operator recipe.

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
verifies child termination and lock release before removing its root; residual
coords are fixture state, not a readiness claim for a later run.

The unsigned probe requires `dev_mode = true` in this Home's `config.toml`
before both `serve` and `run` construct Runtime (`main.rs:2323-2336`). This
applies to a source fixture with no installed signed-release source: installed
release admission takes precedence over `dev_mode`
(`runtime.rs:181-227`). Admission changes neither capability grants nor
provider checksums. AC-006-STORAGE still gates the attached `run` constructor,
even after AC-010-OFFLINE is resolved. No blocker here receives a passing grade.

## Positive-grant decision for 003

**seam exists (operator Runtime's shell-authenticated HTTP approval) —
fixture/command recipe 003 uses:** after the operator isolation gate passes, start the
fixture operator as above, then run one build-time-fixed effect probe. The guest
requests one action within its manifest's resource bound. A fixture-owned shell
controller approves that exact pending request through the existing API while
the guest's bridge waits. This is a live-test route in the source, not a measured
grant or effect result. There is no missing-grant-seam blocker; current execution
still depends on AC-006-STORAGE and the operator prerequisites in 010. Runtime-selected effects and a guest
success payload remain BLOCKED under AC-002-ARGS.

1. The fixture controller uses its own operator's `POST /api/auth/attach` with
   scope `shell`; `attach_to_runtime` and `call_attach` show this non-interactive
   path (`elastos/crates/elastos-server/src/runtime_control.rs:917-941,1001-1026`).
   Only isolated fixture credentials belong in that controller's memory; the
   guest receives the resource grant through the Bus. This discovery read no
   credential files and made no HTTP calls.
2. The guest calls `capabilities.request` with one action. The host maps it to
   the bridge and returns the received grant ID
   (`elastos/crates/elastos-compute/src/providers/component.rs:358-388`). The remote
   bridge checks the manifest bound, posts `/api/capability/request`, then polls
   `/api/capability/request/:id` for up to 30 seconds
   (`elastos/crates/elastos-server/src/resource_bridge.rs:1379-1454`).
3. The controller uses `GET /api/capability/pending` and matches the fixture's
   resource, action and unique reason, requiring exactly one pending request.
   It sends `POST /api/capability/grant` with
   `{"request_id":"<that request>","duration":"once","rationale":"isolated conformance fixture"}`.
   The shell-only routes are in `elastos/crates/elastos-server/src/api/server.rs:258-277`;
   pending fields and grant handling are in
   `elastos/crates/elastos-server/src/api/handlers/capability.rs:225-257,294-359`.
   Approval uses the requesting session and updates that pending request. Grant
   responses contain credentials, so the future harness must consume them
   privately and report only the decision.
4. The guest passes the returned grant to `providers.invoke`
   (`elastos/crates/elastos-compute/src/providers/component.rs:392-429`). Task 003
   needs a fixture provider and a measured effect result; granting alone does
   not prove provider execution. The remote bridge still applies resource and
   principal restrictions (`elastos/crates/elastos-server/src/resource_bridge.rs:1237-1259`).
   A grant therefore does not settle 004's principal-storage tests.

Other candidates checked: `configure_capsule_admission` sets signature and
unsigned-admission policy only (`runtime.rs:188-227`); manifest capabilities
bound requests (`run_cmd.rs:240,252`, `resource_bridge.rs:1379-1383`). Neither is
an automatic positive grant. A home-file pre-seeded grant seam: **none found**.
Startup creates a pending store (`elastos/crates/elastos-server/src/server_infra.rs:659-667`);
persisted capability state loads epochs and revocations
(`elastos/crates/elastos-runtime/src/capability/store.rs:193-223`). The component
gets its grant from the live request response (`component.rs:379-388`). Direct
`CapabilityManager::grant` and `PendingRequestStore` manipulation in server test
fixtures (`runtime.rs:508,1026-1043,1073-1085,1121-1127`) is test-internal access, not a
black-box seam or a substitute for the HTTP recipe.

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

The current probe attempts no effect. Tasks 003/004/005 can select one fixed
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
owns operator discovery for 003. These prerequisites
are outstanding work, not additional Runtime API blockers or passing grades.

Task 006 made zero spike launches and skipped the full Runtime build. Task 009
checks Mac data-root resolution in `tests/runtime.rs::runtime_data_dir_is_under_throwaway_home`
and no-operator refusal stderr in `tests/runtime.rs::run_without_operator_is_refused_with_reason`.
Task 008's guard and cleared launch environment protect the real Home by
construction; this lane reads only its fixture Home. The real-Home digest was
dropped when 007 split into 008 and 009. Grant delivery and component-effect
refusal stderr remain **to confirm in 003** after the operator prerequisites.
Every blocker above remains open.
