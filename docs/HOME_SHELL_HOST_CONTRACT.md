# Home Shell Host Contract

Home has one small trusted browser host and two selectable shells:

| Identity | Purpose | Browser origin |
| --- | --- | --- |
| `home` | Front door, sign-in, shell lifecycle, and recovery | Home origin |
| `home-gui` | Desktop and window projection | Opaque sandboxed frame |
| `home-cli` | Terminal and TUI projection | Opaque sandboxed frame |

`home` is not a selectable shell. It does not render the desktop or terminal.
Runtime state selects either `home-gui` or `home-cli`, and the host mounts that
shell as the single root view.

The host lifecycle is:

`unlock -> read Runtime shell state -> launch one root shell -> route validated intents -> recover`

## Equal Shells

`home-gui` and `home-cli` are sibling shell capsules. They have the same:

- trust class and origin isolation;
- signed-in principal and Runtime-derived facts;
- launch-token validation;
- shell lifecycle and recovery rules;
- ability to request allowed capsule launches, unlock, sign-out, and an
  explicit shell change;
- prohibition on direct provider, network, wallet, storage, or Carrier
  authority.

They are not identical renderers. `home-gui` owns desktop windows and web
projections. `home-cli` owns the Runtime-owned PTY terminal and TUI projections. A
CLI action uses a CLI projection when one exists. Opening a GUI-only projection
from CLI is an explicit `switch shell and open` action; it never happens as a
side effect of running a normal CLI command.

The PTY contract uses explicit start/events/input/resize/close routes. Runtime
owns the process and stream lifecycle; `home-cli` renders bytes and sends input
or dimensions through those scoped routes.

Both shell manifests expose the common `capsule.open` and `shell.switch`
methods. Projection-specific methods such as `desktop.render` and
`facts.search` describe presentation, not additional authority.

## Origin Boundary

The Home DOM is a trusted host surface. Neither shell nor an app shares Home's
effective origin. Runtime serves every browser projection under the same
`/apps/<capsule>/` host and Home mounts it in a sandbox without
`allow-same-origin`. The browser therefore gives each frame a unique opaque
origin. This requires no wildcard DNS, extra certificate, or reverse-proxy
rule.

Opaque frames cannot read Home's DOM, session cookie, passkey surface, browser
storage, or sibling frames. Capsule state that must survive a frame belongs in
the principal-scoped Runtime namespace, not ambient browser storage. Static
assets and token-authenticated API calls may cross the opaque boundary through
the gateway's narrow `Origin: null` CORS policy; unrelated web origins remain
denied.

Home keeps one bounded `browser:<32 lowercase hexadecimal digits>` correlation
identifier in its trusted top-level browser profile. It uses browser
`crypto.getRandomValues`; there is no weak or opaque-frame fallback. After the
active `home-gui` frame sends `home:shell-ready`, Home checks the exact source
WindowProxy, opaque origin, active target, and launch token before handing that
identifier to the frame. The identifier only correlates an encrypted
principal-scoped GUI session with the same browser profile. It is not a
capability, proof, launch fact, routing input, or authorization decision, and it
is not added as a Runtime Home summary fact. The existing browser-state session
payload remains presentation state in the single encrypted principal file. The
GUI neither reads nor writes browser storage and will not restore or persist a
window session until this checked handoff succeeds.

Runtime-generated browser routes carry a scoped launch token in the URL
fragment. Its contract is `elastos.home.launch-token/v4`. The fragment is
removed from visible history after bootstrap and is never sent as an HTTP
referrer. Runtime signs the v4 payload under the matching
`elastos.home.launch.v4` domain, including a collision-resistant launch id, the
selected resource, executable actor, authorizing actor, principal, session,
proof binding, grant, issue/expiry times, non-delegation flag, and any exact
operation/request digest. A direct launch uses the executable actor as its
authorizing actor. A Home-created child launch records `home` as the authorizing
actor and cannot delegate again. A viewer is therefore the actor for selected
content, not a replacement identity for that content. Browser API calls from
capsules require one valid Host and exactly
`Origin: null`; direct Home calls require same-origin browser provenance from an
exact destination Origin or Referer, or `Sec-Fetch-Site: same-origin`. Internal
shell launch-grant transfer uses a separate non-browser validation path. Runtime
rejects missing or conflicting provenance, v2, v3, mixed-shape, expired, and
substituted tokens. A Home session cookie alone cannot mint an app token.

The two Home launch operations, `POST /api/apps/home/launch` and
`POST /api/home/launch/content`, accept the Home session only from the `/home/`
document. These requests carry the exact destination `Origin`, a `/home/`
`Referer`, and `Sec-Fetch-Site: same-origin`; another page receives
`home_page_only`. The Home document sends its referrer only to its own origin.
The native CLI uses its own app-scoped launch grants. Its `home-cli` grant for
these two operations selects `home-launch`; that grant can ask the gateway to
launch or open content without browser provenance. For content
open, the gateway gives the Runtime a `home-shell` projection grant bound to
`home` only when the caller's context has a proof binding; the Runtime accepts
that grant only on its internal content-open hop.
`elastos home --cli-launch-token` asks the Home on this computer for one
exported grant. The command creates a fresh secret, registers a bound request,
and waits. While it waits, its error output prints `Approve terminal request
ABCD-EFGH in Home`. That code is the first eight hex characters of the request
id, in upper case, with a hyphen after the fourth character. It is not the
secret. Home shows that same code to the signed-in human admin. When one
request is waiting, Home asks for a fresh passkey for that request. When more
than one request is waiting, Home shows each code and asks the admin to choose.
Home does not open a passkey prompt for one of those requests by itself, and an
open prompt stays on the request it opened for. Home begins the chosen request
and then sends the passkey assertion. Home does not approve a request it has
not begun. When the admin approves, the command prints the grant once. When the
admin refuses the passkey or dismisses it, the command prints no grant and
stops as refused or cancelled. When the admin cancels before the claim commits,
the request times out, or the request does not match, the command prints no
grant and stops with a non-zero status. A cancel that arrives after the claim
has committed is refused. If the signer then succeeds, the command still prints
that one grant. If the signer then fails, the command prints no grant. If Home
cannot be reached before a request is registered, the command says Home is not
running and the admin can request the grant again. If the command loses Home's
reply after a claim may have been delivered, it does not ask the admin to
approve again. The gateway keeps the approval in its own memory. It signs
only when that memory record is approved and the request, the
secret, the owner, the session, the proof, the grant, and the operation match.
It marks the record delivered in that same memory before returning the grant.
The grant lasts 5 minutes from the signature. A stolen grant still reaches only
`POST /api/apps/home/launch` and `POST /api/home/launch/content`, and only until
that grant expires or the admin session is revoked. A file in the data
directory is not an approval and cannot deliver a grant. A restart drops a
request that is still waiting. `Origin: null` cannot register a request or
claim a grant, including when the caller presents a launch token. The command
does not mint from the process environment.
The gateway still gives its `elastos home` TUI
child the terminal environment. That child uses the environment for an internal
projection token. The TUI has no host shell and no export-mint action. The
public journey smoke requires `ELASTOS_CLI_LAUNCH_TOKEN` from the operator.

The device key issues a launch token for two shells: `home` and `home-cli`. A
standalone summary read for one of those shells uses that token. A standalone
write for another app stops. The gateway-owned environment route mints a token
only when its proof-binding variable is set, the live grant matches that
binding, the session, and the person, and that grant names `home`. With no
proof binding, that route mints nothing and the command uses the device mint,
which accepts only `home` and `home-cli`. A proofless device token for another
app is refused. Content open signs its `home-shell` projection only for a
context that has a proof binding. This closed
result for a standalone write on behalf of another app is the boundary
recorded in #1817.

The Home session cookie is `HttpOnly`, `SameSite=Strict`, and `Secure` on HTTPS.
Capsule responses use CSP, referrer, content-type, and resource-policy headers
appropriate to their document or asset role.

Home reads its own facts from `GET /api/apps/home/summary`. Chat summary at
`GET /api/apps/chat-room/summary` requires a signed Chat launch token; a Home
session cookie does not give access to that route. Marketplace reads the shared
`/api/capsules/catalog` and `/api/capsules/interfaces` routes with its scoped
launch token. The old `/api/apps/marketplace/catalog` alias is absent.

## Host Responsibilities

The Home host may:

- show the passkey or guest sign-in surface;
- read the Runtime-owned Home summary;
- launch exactly one trusted root shell;
- validate child source, origin, target, and launch token before accepting a
  message;
- retain and hand the non-authoritative browser-profile correlation only to an
  accepted active `home-gui` ready message;
- mint target-scoped routes through Runtime using host-held authority;
- route Runtime events and approved payloads to their registered child frame;
- show a minimal reload, Desktop, or sign-out recovery surface;
- ask for a reload, never reload by itself, when a summary reports a Runtime
  version other than the one that served the page: after an update the page,
  the shell and open windows keep their old code until the page reloads, and
  a reload would drop what open windows have not saved.

The Home host must not:

- contain desktop, taskbar, launcher, window, or terminal implementation;
- infer authority from iframe placement or a manifest role;
- expose its session cookie or passkey result to an arbitrary frame;
- let an app or shell address a sibling frame directly;
- keep an inactive shell alive behind CSS;
- switch shells because an ordinary app-open intent was received.

## Shell Messages

Shell messages are a local browser adapter for typed Runtime intent. Every
message must come from the active shell frame, its opaque origin, and its
current launch token.

Common shell messages are:

| Message | Result |
| --- | --- |
| `home:shell-ready` | For accepted `home-gui`, Home first sends the profile correlation, then the current Runtime summary. Other shells receive only the summary. |
| `home:shell-context` | Home sends the bounded non-authoritative profile correlation to the accepted active GUI frame. |
| `home:refresh-summary` | Home refreshes Runtime facts. |
| `home:launch-target` | Runtime returns a target-scoped launch route. |
| `home:request-unlock` | Home displays its host-owned sign-in surface. |
| `home:sign-out` | Home revokes the active session and reloads the front door. |
| `home:close-self` | Home closes the active root shell through Runtime state. |

`home:switch-shell-and-open-target` is the explicit CLI-to-GUI transition for a
GUI-only target. Home validates the target, persists `home-gui` through the
Runtime shell route, launches the GUI shell, and then asks that shell to open
the target. A plain `home:open-target` from `home-cli` cannot trigger this
transition.

New active-shell writes accept only Runtime-approved `home-gui` and `home-cli`
candidates. A manifest declaring `role: shell` does not grant shell authority.

## App Messages

Apps post directly to the top-level Home host. Home registers a child only when
its source window, opaque origin, target id, and launch token all match a route
that Home obtained from Runtime.

Allowed app intents are source-scoped. Examples include opening a known target,
opening a supported object URI, delivering a typed payload to an installed
viewer, closing the current app, and requesting a fresh passkey proof for an
approved high-risk operation. Home rejects unknown sources, origins, targets,
tokens, payload shapes, and operations.

The GUI shell receives only presentation commands such as opening or closing a
window. It does not receive another capsule's authority token. App-to-app work
remains a Runtime-gated intent and, for off-box effects, follows the provider and
Carrier path described in [Capsule Interface Contract](CAPSULE_INTERFACE_CONTRACT.md).

### First-party Clipboard edge

First-party capsule Clipboard access terminates in the trusted top-level Home
document. This is one closed browser edge adapter shared by Browser, Wallet,
MetaMask, UniSat, WalletConnect, Library, and Documents. It is not an ESP
capability, generic app message, provider RPC, shell method, audit event, or new
source of Home authority. `home-gui` only projects opaque capsule iframes and
does not receive `clipboard-read` or `clipboard-write` permission. No opaque
first-party capsule calls `navigator.clipboard` or keeps a direct or fallback
Clipboard path.

The canonical request is `elastos.home.clipboard.request/v1`. Home derives the
app target from the launch record it received from Runtime; a capsule never
asserts its target in request JSON. Home accepts a request only from that
launch's exact opaque `WindowProxy`, `Origin: null`, parent origin, app-bound
Home token, random lifecycle generation, bounded random request id, operation,
purpose, MIME type, and payload bound. Each frame may have at most one request
in flight. Home keeps only bounded, expiring replay ids and text-free in-flight
metadata. Concurrent, replayed, substituted, malformed, oversized, stale,
retired, and timed-out requests fail closed. A Home page whose code predates a
purpose answers it as `malformed` with purpose `invalid`; the client reports
that as `unknown_purpose`, so the app can ask for a Home reload.

The purpose policy is closed. Browser may read or write bounded `text/plain`
for `browser.text`. Wallet may write addresses and Wallet Recovery Keys.
MetaMask, UniSat, and WalletConnect may write linked Wallet addresses. Library
may write resource URIs and bounded technical identifiers under separate
purposes; Documents may write resource URIs. No non-Browser target may read
the OS Clipboard, and no caller-supplied purpose widens its target's policy.

Every OS Clipboard read or write requires a new click on the visible,
top-level, Home-owned Clipboard prompt. Only that prompt continuation invokes
`navigator.clipboard.readText()` or `navigator.clipboard.writeText()`. The
prompt identifies the operation and purpose without displaying Clipboard
payload. A Wallet Recovery Key prompt explicitly identifies secret material
but never displays, logs, persists, or audits the secret. A Library identifier
prompt identifies technical identifier material without displaying it. Home
never persists, logs, audits, or sends Clipboard text to any other capsule,
shell, provider, or Runtime route. It returns read text only to the exact
requesting Browser frame and returns write success only after the OS Clipboard
operation completes.

Guest Clipboard output is inert unless the local user first performs an
explicit copy action in Browser. Browser binds the next strict, bounded,
canonical `text/plain` guest response to that exact pending request before
asking Home to write it. Unsolicited remote Clipboard messages cannot change the
host Clipboard. Browser paste comes either from an explicit `ClipboardEvent`
carrying `text/plain` or from the closed Home read action, and guest input still
travels through the existing Runtime-mediated Browser input route.

The shared limit remains 65,536 UTF-8 bytes. Canonical base64, chunk size,
chunk-count, assembly timeout, and teardown checks remain on guest Clipboard
messages. Home and each client clear text-bearing and in-flight state on
completion, rejection, timeout, frame retirement, sign-out, or root-shell
replacement. Copy UI reports success only after the matching Home result
succeeds.

### Injected wallet connector effects

MetaMask/Brave and UniSat browser-extension effects terminate in the trusted
Home host because opaque connector frames cannot receive top-level injected
providers. This function is a closed browser edge adapter, not a shell and not
an additional source of shell authority. It does not change the authority of
`home`, `home-gui`, or `home-cli`. The only connector-to-Home request is
`home:wallet-connector-effect` with schema
`elastos.home.wallet-connector-effect/v1`, an exact bounded request id, the
connector id and launch token, and one closed action:

- `{ "kind": "link" }`; or
- `{ "kind": "approve", "approvalRequestId": "<exact Runtime id>" }`.

Home accepts that message only from the registered connector WindowProxy with
`Origin: null`, the exact connector target and launch token, and the exact
message/action schema. Each frame has one in-flight effect and a bounded set of
consumed request ids; concurrent and replayed requests fail closed. Replies
carry only a bounded status result or error to the same source window. Connector
frames cannot supply a provider method, signing message, chain transaction,
Runtime authority, or arbitrary provider parameters.

The Home host discovers MetaMask through exact EIP-6963 `io.metamask`
announcements, falls back to exact `com.brave.wallet`, and rejects conflicting,
ambiguous, or over-limit provider discovery. UniSat is read only from the
top-level host. Home asks these providers to perform only the fixed link or
typed approval effect selected by Runtime; the opaque connector frames never
receive `window.ethereum`, `window.unisat`, provider objects, signatures, or
transaction payloads. EIP-6963 `rdns` values make provider selection
deterministic, but they are self-asserted announcement metadata, not
cryptographic extension authentication. Runtime verification of the issued
challenge, returned signature, selected account, and completion receipt remains
authoritative.

The matching Runtime endpoints require two independently validated launch-token
v4 authorities: Home's exact same-origin authority and the carried connector
token. They must bind the same principal, session, proof, and grant, while the
connector token must name the exact connector resource and executable actor
authorized by Home. Runtime issues link challenges and typed approval handoffs,
then verifies or completes them through the existing private Wallet Bus
lifecycle. No Home message is a generic wallet RPC surface, and WalletConnect's
configured connector path remains unchanged.

## Passkeys And Sign-Out

Runtime owns principals, passkey records, session grants, revocation, and audit.
Home owns the browser sign-in prompt because WebAuthn is bound to the top-level
Home origin.

Only approved first-party targets may ask Home for fresh passkey authority.
Home binds that proof to the requesting capsule, operation, and request before
returning a new target-scoped token to the same source and origin. Home also
asks for a fresh passkey when a terminal is waiting for an exported Home CLI
grant. That prompt shows the same request code the terminal printed. When
several requests are waiting, Home asks the admin to choose one code before
the passkey prompt. The prompt begins the chosen request and then approves it.
The passkey result stays in Home. The waiting command receives the grant. A
cancel after the claim has committed does not take a delivered grant back. The
admin signs out to revoke a grant the terminal already received.

Both shells can sign out. Browser `home-cli` sign-out is a launch-token-bound
terminal host intent; `home-gui` uses the same host message contract. Neither
shell owns or clears authentication state itself.

## First-run recovery and Profile sequence

For a new principal, Home presents Recovery Kit first and Profile second.
Runtime-owned `recovery_readiness` and `profile_readiness` facts decide the
state. System owns Recovery Kit creation and export; People owns the signed
Profile. Home only coordinates the visible sequence.

The first Profile must fail closed until Runtime reports that the principal root
is protected and a Recovery Kit has been handed to the person. The setup UI has
no skip authority. Closing or pressing Escape may leave a session reminder, but
it cannot mint readiness or bypass the People gate. Existing Profiles are not
retroactively treated as new first-run accounts.

The readiness projection and the first-Profile mutation gate must derive from
one recovery rule or be protected by an equivalence regression test. UI state,
browser storage, a successful route, or a downloaded filename is not recovery
authority.

## Recovery And Cleanup

Changing shells retires the previous root frame before the next shell becomes
active. CSS hiding is not an accepted lifecycle model for a live previous
shell. Home's browser-local active-shell hint may suppress a flash during boot,
but Runtime state remains authoritative.

If the selected shell fails to launch, Home shows the host-owned recovery
surface. Recovery can retry, return to `home-gui` through the Runtime shell
route, or sign out. It does not mount a hidden desktop as a fallback.

A saved shell that is no longer launchable (for example the Terminal view when
host developer mode is off) is not a launch failure: Runtime drops it from the
shell candidates and resets the saved choice, and Home switches to `home-gui`
through the same Runtime shell route, so every later load opens the Desktop.

## Verification

The minimum machine proof is:

```bash
node scripts/home-shell-bridge-smoke.mjs
node scripts/home-browser-context-smoke.mjs
scripts/home-browser-context-opaque-frame-smoke.sh
node scripts/home-clipboard-headless-smoke.mjs
node scripts/home-clipboard-source-gate.mjs
node scripts/home-shell-system-switch-smoke.mjs
node scripts/home-shell-switchback-recovery-smoke.mjs
node scripts/home-shell-unavailable-shell-fallback-smoke.mjs
node scripts/home-cli-browser-smoke.mjs
node scripts/wallet-connector-transaction-smoke.mjs
node scripts/check-product-data.mjs
node scripts/home-shell-objective-audit.mjs
(cd elastos && cargo test -p elastos-server test_home_launch -- --nocapture)
```

The contract audit `first_party_capsules_have_complete_projection_contract`
keeps shell-facing catalog facts aligned. Product acceptance additionally uses
`scripts/home-shell-objective-audit.mjs --require-complete` with hash-bound
operator evidence.

For a behavior-changing shell review, create a screen-capture-free artifact
path and validate it before the objective audit:

```bash
node scripts/home-shell-manual-ux-report.mjs --template
node scripts/home-shell-manual-ux-report.mjs --notes-template --out /tmp/home-shell-manual-notes.md
node scripts/home-shell-manual-ux-report.mjs --artifact-entry /tmp/home-shell-manual-notes.md
node scripts/home-shell-manual-ux-report.mjs --report-from-notes /tmp/home-shell-manual-notes.md --out /tmp/home-shell-manual-ux.json
node scripts/home-shell-manual-ux-report.mjs --input /tmp/home-shell-manual-ux.json
node scripts/home-shell-objective-audit.mjs --manual-ux /tmp/home-shell-manual-ux.json --require-complete
```

The notes-to-report command converts the reviewed notes, requires
`source.commit` to match the candidate, and records the absence of desktop
first-paint before Home CLI. Set `redacted=true` only after reviewing the notes
for secrets.
