# ElastOS capsule roadmap: where we are headed

Source: Flint's "ElastOS Capsule System: Master Product Definition and PRD" (20 Oct 2026, from the Shanghai
meetings, `ElastOS-Capsule-PRD.pdf` in this folder), checked against `develop` 3beb8164 on 20 Oct.
Sasha approved it as the direction on 20 Oct. Owner of this file: Cursor (Claude). Update it when a phase,
decision or app status changes.

## North star

One signed capsule, named by its hash, runs on any ElastOS device with no ambient authority. Paid content is
unlocked only by a key that independent key holders (dKMS, 2-of-3) release to a Runtime that can prove what it is.

In plain words: every app is a sealed box with a fingerprint for a name. It can do nothing unless the Runtime
hands it a permission. The same box runs on Mac, Linux, a NAS and later a frame.

## Phases

| Phase | Goal | Size (estimate) |
|---|---|---|
| 1 | Ship 0.8.0 (alpha.25, #451, stable end Oct, move to elastos org, launcher pin) | weeks |
| 2 | WASM capsules on today's Runtime: signed bundles named by CID (2.2), Wasmtime 48 + limits (2.1), Bus v2 async (2.3), capsule kit (2.4), first app = photo/signage viewer (2.5), move apps one at a time (2.6), confine providers (2.7), dDRM to an Elacity bundle (2.8), CDN on Carrier (2.9), metering receipts (2.10), elastos-slim (2.11) | 6-9 months |
| 3 | Trusted hardware: RK3588-class board, verified fast boot, measured Runtime in TEE/SE, keys sealed to device, attested play counts | 6-12 months, overlaps 2 |

Phase 2 starts only after 0.8.0 ships. Nothing here may delay 0.8.0.

## Decision rule (from PRINCIPLES.md)

When two options both work, pick the one that: (1) strengthens rooted and content identity, (2) reduces ambient
authority, (3) removes hidden alternate paths, (4) keeps the trusted core smaller, (5) makes the user model clearer.

## Corrections and additions to the PRD (verified 20 Oct)

1. Capsule signatures ARE checked at launch on develop (`runtime.rs:351` verify_capsule_signature; admission
   configured with trusted keys and dev_mode at `main.rs:2331`). Missing: bundle-CID naming, per-publisher trust
   policy by role, recursive dependency check, fetched/Carrier launch paths. Milestone 2.2 is smaller than stated.
2. Reproducible builds are missing. The same guest source builds to a different wasm hash on Mac and Linux
   (Cargo mixes host metadata through proc-macros). "Named by hash" needs one pinned build environment so anyone
   can tie a CID to its source. Add to 2.2 / 2.4.
3. Agents as principals (P7) need a milestone: `UsersAI` is not scoped per principal (only 0700 on disk), and no
   agent principal type exists.
4. Authority prerequisites for Phase 2: hand-run `elastos serve` defaults the shell to auto-approve
   (`serve_cmd.rs:333`, `main.rs:1912`); Home mints every app's token (#173).
5. Wasmtime is 36 (`elastos-compute/Cargo.toml`). All 20 first-party apps declare `execution: web-projection`
   even where `type` says `wasm`. No dedicated photo viewer exists (Library shows previews).

## Every app and what it needs

Legend. Wave = suggested order (my judgement, not decided). "Move" = logic into a Bus v2 WASM component, UI
render-only, signed bundle named by CID, smallest capability list, old web version deleted in the same change,
old journeys are the gate (P10, P12).

### Apps and viewers (20 web projections today, plus one new)

| Wave | Capsule | Role | What it needs | Notes |
|---|---|---|---|---|
| A | photo viewer (NEW) | viewer | Build new as WASM: read image objects by grant, check type and size, playlist, render-only surface | PRD first app (2.5). New, so no regression risk. Frames/signage want it. Second track for Claude. |
| B | documents | viewer | Move | Markdown/text; small. |
| B | archive-manager | viewer | Move | Archive parsing is a classic attack surface; WASM sandbox helps most here. |
| B | gba-emulator | viewer | Move; content capsules name it by CID | gba-ucity, gba-nonogram are content capsules; switch `viewer` from name to CID. |
| B | elacity-player | viewer | Move after 2.8; plays only decrypt-provider output | Elacity viewer; protected content; keys never in the viewer. |
| C | chat-room (+ chat-room-ui) | app | Move logic; Carrier stays below the Bus | Needs Bus v2 events/streams. |
| C | people | app | Move | Identity display only; authority stays in Runtime. |
| C | library | app | Move | Object browser; P13 objects vs capsules. |
| C | marketplace | app | Move; Elacity calls go through the dDRM bundle | Store row is not identity (P13). |
| C | assistant | app | Becomes the Agent Host capsule | Our private spike is this track (P7). |
| C | inbox | app | Move with care | Approval surface; UI is not authority (P16). Decisions stay in Runtime. |
| C | services, system | app | Move | Operator surfaces; P6 boundaries. |
| D | wallet, wallet-metamask, wallet-unisat, wallet-walletconnect | app | Logic to wallet-provider; connectors may stay web | Browser-wallet connectors are web by nature (P9 edge). My judgement. |
| D | browser | app | UI render-only; engine stays in its microVM | Already isolated by microVM. |
| E | home, home-gui, home-cli | app/shell | Last; Home loses power to mint every app's token (#173 T2/T3) | Biggest change; do after the kit is proven. |

### Content capsules

| Capsule | What it needs |
|---|---|
| gba-ucity, gba-nonogram | Name the viewer by CID; signed bundle; later encrypted assets + policy (PRD section 8). |

### Providers (stay native; confine under 2.7; not WASM)

| Priority | Providers | What they need |
|---|---|---|
| 1 | decrypt-provider, custody-provider, protected-content-decrypt-provider, protected-content-protect-provider, key-provider (provisional, to remove) | Confine first; move Elacity-specific parts to the dDRM bundle (2.8); Phase 3 key rebuild in TEE. |
| 2 | drm-provider, rights-provider, chain-provider (Elacity calls), media-provider | dDRM bundle split (2.8); chain-provider keeps generic chain access. |
| 3 | wallet-provider, did-provider, object-provider, localhost-provider, webspace-provider, site-provider | Confine; principal scoping (UsersAI). |
| 4 | net-provider, tunnel-provider, exit-provider, ipfs-provider, availability-provider, content-block-graph-provider | Confine; CDN and receipts (2.9). |
| 5 | model-provider (partly confined), operator-drive-adapter, browser-engine-adapter | Finish confinement. |
| - | shell (decision engine) | Fix auto-approve default; agent defaults include unscoped UsersAI. |

## Our work mapped to the roadmap

| Work | Phase / milestone |
|---|---|
| 0.8.0 reviews (#412, #420, #421, #424, #416, #411, #428), #433 timeout gate | Phase 1 |
| Agent Host spike (private repo): S1 admission tests, S2 journal, S3 revisioned bridge write | Phase 2: 2.2 groundwork, 2.3/2.4 patterns, P7 |
| Guest hash per machine | 2.2 / 2.4 reproducible builds |
| OSS Scanner + threat model | All phases (security baseline) |
| Shell auto default, UsersAI scoping, #173 | Phase 2 prerequisites |
| Photo viewer spike (proposed second track) | 2.5 early proof on Bus v1 |

## Standing checks for every task and review

1. Does it name things by hash (CID/SHA-256), not by URL or name?
2. Does it add ambient authority, or give Home/UI authority it should not hold?
3. Does it add a second path for one operation?
4. Does it grow the trusted core, or move protocol work into providers?
5. Does it fail closed with a clear reason?
6. Does it delay 0.8.0? If yes, it waits.

## Open decisions for Sasha (PRD 11.2) and Cursor's leaning

1. Phase 2 after 0.8.0, signing/naming first: yes.
2. First board RK3588-class NAS; frames must be 64-bit: yes.
3. dDRM out of the MIT repo: yes, lawyer first.
4. Play counts "auditable" now, "hardware-attested" later: yes.
5. Player named by CID, bundled only for offline/games: yes.
6. dKMS binds bundle CIDs (Phase 2) and device attestation (Phase 3): yes, to the dKMS lead.
7. On-hold items (Boson, NAS/expo, camera relay): hold until 0.8.0.
8. Custom silicon: not now.
