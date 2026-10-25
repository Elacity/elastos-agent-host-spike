# Agent conformance discovery and gaps

This is the lane's single gap record. Source evidence establishes the available
interfaces; it does not prove a live effect. Every blocker below remains open.
Task 006 used the supplied Mission, backlog and task text. `MISSION.md`, the
lane's `BACKLOG.md` and stopped task 001 are absent from this checkout; the
external queue was outside the permitted read scope.

## Launch and data directory (006, source evidence)

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
`$AC_HOME/Library/Application Support/elastos`. Task 009 verifies that resolved
path with `runtime_data_dir_is_under_throwaway_home`: Runtime removes a decoy
from the guarded data directory under a fresh temporary root. `run` has no `--data-dir` option
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
not complete throwaway-root isolation. Task 007 must keep that isolation gate
BLOCKED until this path is contained. Runtime change that flips the blocker:
Anders makes the existing component launcher derive storage from the selected
Home's data directory instead of the fixed path. This lane adds no launcher.

## Positive-grant decision for 003

**seam exists (operator Runtime's shell-authenticated HTTP approval) —
fixture/command recipe 003 uses:** after 007 establishes isolation, start the
fixture operator as above, then run one build-time-fixed effect probe. The guest
requests one action within its manifest's resource bound. A fixture-owned shell
controller approves that exact pending request through the existing API while
the guest's bridge waits. This is a live-test route in the source, not a measured
grant or effect result. There is no missing-grant-seam blocker; current execution
still depends on AC-006-STORAGE and 007. Runtime-selected effects and a guest
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
Task 008 adds the guarded launch primitive. Task 009 adds the Runtime build
and the no-operator launch checks. Signed-bundle identity, Runtime admission
and effect evidence remain with the later tasks; all listed blockers remain open.

Task 006 made zero spike launches and skipped the full Runtime build: source
evidence is sufficient for this discovery, and AC-006-STORAGE needs resolution
before an operator launch. Task 009 now checks Mac data-root resolution with
`runtime_data_dir_is_under_throwaway_home` and the no-operator refusal stderr
with `run_without_operator_is_refused_with_reason`. Both use 008's guarded Home
and launch primitive. Runtime refuses before the AC-006-STORAGE constructor;
that blocker remains open. Real-Home safety is proved by construction and the
decoy test; the dropped real-Home digest is outside the lane's read scope.
Grant delivery and guest refusal stderr remain **to confirm in 003**, subject
to operator isolation. [LOG.md](LOG.md) records the measured task 009 results.
