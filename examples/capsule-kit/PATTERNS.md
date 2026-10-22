# Capsule patterns: the checklist a new app must meet

Draft for the capsule kit (roadmap 2.4). It is drawn from the photo viewer spike (`examples/photo-viewer`)
and the Bus v2 proof (`examples/bus2-proof`). Each pattern says what the app must do, what proves it, and
where the photo viewer does it today.

A new app meets a pattern only when every box is ticked **and** the proof exists: a test for each rule, and a
falsifier that breaks the rule and sees that test fail. A rule with no failing falsifier is not proven.

Items marked **(added)** come from the second viewer (`examples/docs-viewer`): the photo viewer did not need
them, the documents viewer did. Why each was added is in `KIT-REPORT.md`, "What I had to change".

The six patterns:

1. [Grant-only reads with header checks](#1-grant-only-reads-with-header-checks)
2. [Render-only page with a launch token](#2-render-only-page-with-a-launch-token)
3. [Signed bundle by CID with policy](#3-signed-bundle-by-cid-with-policy)
4. [Reproducible build](#4-reproducible-build)
5. [Mutation tests](#5-mutation-tests)
6. [Bus v2 slices and stop](#6-bus-v2-slices-and-stop)

## The shape of an app

An app is two capsules, each with one role (principle 13):

| Capsule | Role | Runs as | Holds |
|---|---|---|---|
| The **core** | `app` | a WASM component (`execution: component`) | grants it asks for, one by one, while it runs |
| The **surface** | `viewer` | a render-only page (`execution: web-projection`) | its launch token, nothing else |

The core does all the work: it reads, checks and decides. The surface only draws what the core wrote. Neither
capsule can reach a file, a socket, a clock or the environment except through Runtime.

## 1. Grant-only reads with header checks

Every byte the core reads comes through `providers.invoke`, with a grant it asked for, for that one object. It
checks what it reads before it trusts it, and reads no more than it needs.

**The core must:**

- [ ] import only the `elastos:bus` interfaces it uses. No WASI, files, sockets, clock or environment
      (`capsule.json` `bus_contract`, and the admission import check).
- [ ] bound its storage in `capsule.json` `permissions.storage` to the prefixes it needs, and no wider.
- [ ] ask for a grant (`capabilities.request`) for each object, with exactly one action, before it reads or
      writes it. Never reuse one object's grant for another.
- [ ] read with the offset/length window only, and always name a `length`.
- [ ] check the type from the first bytes (magic bytes, or the encoding for text) before reading further.
- [ ] **(added)** for a format that must be read whole (text), read the rest only after the head check and the
      size probe, and check the whole again.
- [ ] tell an oversize object by reading one byte past the limit, not by reading it all.
- [ ] cap everything it reads whole (input lists, documents) and everything it counts (items, segments).
- [ ] **(added)** cap what one run reads in all, and count every byte read in full, whether the item is then
      shown or skipped.
- [ ] **(added)** cap what one run writes: on Bus v1 each output byte costs fuel and travels as a number of up
      to four characters in a 1 MiB bridge frame. Write the output and the write body straight to bytes, never
      through a `serde_json::Value` per byte.
- [ ] **(added)** keep every parser linear in its input. A content failure must never cost a trap.
- [ ] parse every input strictly: a fixed schema string, unknown fields refused, URIs checked (prefix, no empty,
      `.` or `..` segment, no `?`, `#`, `\` or control character).
- [ ] sort its failures in two kinds:
  - **authority** (no grant, a refused or failed call, a provider error, an answer of the wrong shape, a bad
    input list): the run **stops** before anything is written, and `lifecycle.run` returns a `bus-error`
    that names the resource and the reason;
  - **content** (wrong type, truncated, malformed, oversize): the item is **skipped**, and the output lists it
    with its position, a reason code and a message.
- [ ] write its output once, whole, to its own output object, with a deterministic encoding (sorted keys).
- [ ] stay within the Runtime's fixed fuel (100,000,000 per run on Bus v1): the worst input within its caps
      must use at most 80% of it, and a test must gate that.
- [ ] **(added)** put in that gate the largest output and inputs made against each parser (openers that never
      close, the most spans), not only the largest input.

**Proof:** guest tests against a fake Runtime that checks bodies the way the localhost provider does, the same
run inside the Runtime's own `ComponentProvider`, the admission import check, and a fuel gate.

**In the photo viewer:** `src/lib.rs` (run order, stop and skip), `src/bus.rs` (the two calls), `src/album.rs`
(strict input), `src/image.rs` (header checks), `src/fake.rs` and `src/tests.rs`, and `host-test/`.

## 2. Render-only page with a launch token

The surface draws the core's output and nothing else. It is not authority (principle 16).

**The surface must:**

- [ ] declare no capabilities, no storage and no requirements other than its core by CID (pattern 3). An
      interface entry, if any, is for discovery only and grants nothing.
- [ ] hold one thing: the launch token Runtime puts in its fragment (`#home_token=`). Send it in
      `x-elastos-home-token` to its own read routes and nowhere else.
- [ ] read only through the read-only routes bound to its launch, with `GET`, `credentials: "omit"`,
      `cache: "no-store"` and `redirect: "error"`. One `fetch` call site.
- [ ] never build a path or URI. It asks for things by position in the core's output, and drops `uri` fields
      unread.
- [ ] show text with `textContent` only. No `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`,
      `eval` or `Function`.
- [ ] **(added)** have no parser of its own: the core turns content into a typed document (text-only blocks;
      links and images as text), and the page only draws its kinds. A kind it does not know is "not shown".
- [ ] **(added)** be tested against what the core actually writes (a fixture the core's tests check).
- [ ] cut every string it shows to a fixed length.
- [ ] use no storage, no cookies, no `postMessage`, no WebSocket, no other network, no `window.open`.
- [ ] ship no inline script, style or handler: one module script and one stylesheet.
- [ ] check the output's schema, and refuse an output that is not one.
- [ ] with no launch token, ask for nothing and say how to open it.

**Runtime must** (the seam): bind the launch to one output object in the signed launch token, serve that
object and nothing else to that launch's token, refuse every other viewer's token, have no write route, audit
each request once, and give the token a short life.

**Proof:** node tests with a fake fetch and a fake document, a source check that the forbidden calls are
absent, and the real page in real Chromium framed in Home's sandbox.

**In the photo viewer:** `surface/browser/photos.js`, `surface/photos.test.mjs`,
`surface/photos-browser-smoke.mjs`, and the seam in
`elastos/crates/elastos-server/src/api/viewer_gateway.rs` ("Photos surface", `image-viewer` only).

## 3. Signed bundle by CID with policy

A capsule is named by the hash of what it ships, and a publisher signs that name (principle 15).

**The app must:**

- [ ] ship each capsule as a closure: a folder of exactly the files it runs from, with `capsule.json` at its
      root. No source, no build output other than the artifact, no symlinks or special files.
- [ ] be named by the CID of its closure listing (CIDv1, raw, sha2-256 over the canonical listing).
- [ ] have a detached claim `{cid, name, version, role, publisher_did}`, signed by the publisher's DID.
- [ ] be admitted only when the policy lets that publisher ship that role (and that name, if the policy names
      them); a revoked DID or CID, an expired or rolled-back policy, a lower version, or a dev key outside dev
      mode is refused.
- [ ] be loaded only from its read-only copy staged under its CID, re-hashed at every load.
- [ ] have its surface name its core by CID (`requires[].cid`). A name alone never selects the core.

**Proof:** admission tests for the app's own two closures: the good path, and the refusals that depend on the
app (another CID, another publisher, another role, a core required by name only).

**In the photo viewer:** `bundle/` (crate `capsule-bundle`) and `bundle/tests/admission.rs`.

## 4. Reproducible build

Anyone can tie a CID to its source by building it again.

**The app must:**

- [ ] pin its toolchain (`rust-toolchain.toml`) and lock its crates (`Cargo.lock`, built `--locked`).
- [ ] build with the repository builder (`scripts/build-component-capsule.sh`): `SOURCE_DATE_EPOCH=0`, no
      incremental, path remapping, componentize, and a check that no host path is left in the artifact.
- [ ] build in the one pinned Linux container (image by digest, `linux/amd64`), because a native Mac build and
      a native Linux build of the same commit differ.
- [ ] record the expected artifact sha256 for each commit that changes the core.

**Proof:** the same sha256 from two machines, both in the container.

**In the photo viewer:** `repro/build-in-container.sh` and `repro/README.md`.

## 5. Mutation tests

Every check has a test, and every test is shown to catch its check being broken.

**The app must:**

- [ ] have one falsifier per refusal, per bound and per rule: an exact text replacement in the source.
- [ ] require that each mutant **compiles**. A mutant that does not compile proves nothing.
- [ ] require that the named tests **fail** under the mutant.
- [ ] restore the file from its saved bytes after each mutant, also on error or Ctrl-C, and leave a clean tree.
- [ ] check that each anchor occurs exactly once (`--check`), so a refactor cannot silently disable one.
- [ ] run every falsifier from the app's `verify.sh`, together with fmt, clippy and every test.

**Proof:** `verify.sh` ends in a line that says it passed, and lists each falsifier as caught.

**In the photo viewer:** `falsify.py`, `falsify-surface.py`, `falsify-bundle.py`, `falsify-seam.py`, and
`verify.sh`.

## 6. Bus v2 slices and stop

On Bus v2 the core is a resident guest. It runs until Runtime closes its events, under limits it cannot escape.

**The core must:**

- [ ] import only `elastos:bus/*@2.0.0`, never v1 and v2 together.
- [ ] stop when its events stream closes, and return. It must not depend on `stop-requested`.
- [ ] **(added)** end the run on an authority failure (a refused grant, a denied read) with its reason; for
      content it cannot show, draw a frame that says so and go on.
- [ ] do no work at start-up beyond setting up. Start-up runs guest code too, and is limited the same way.
- [ ] read with `providers.invoke` under a cap it states, refuse more bytes than it asked for, and use no byte
      until the trailing future says the read is whole.
- [ ] draw with `ui.present`, one declarative frame: images by granted handle, never by URI or bytes; no
      script.
- [ ] check credentials only to refuse, against a key pinned in its own manifest, before it draws.

**Runtime must:** slice fuel and yield (fuel slices and the epoch) from before instantiation; drive start-up
and the run in the same place as the stop and the grace timer; end every run with a named reason.

**Proof:** tests that the guest stops on close, that a guest that does not is cancelled after the grace
period (also during start-up), that the epoch deadline ends one that never yields, and that a busy guest does
not starve a second guest. Each with a falsifier.

**In the Bus v2 proof:** `examples/bus2-proof/host/src/run.rs`, `host/tests/lifecycle.rs`,
`host/tests/fairness.rs`, and the photo guest in `guests/photo`.
