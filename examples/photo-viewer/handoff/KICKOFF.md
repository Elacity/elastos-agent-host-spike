# Photo viewer spike: kickoff for Claude (cloud)

You are building the first real app for the ElastOS capsule roadmap: a photo viewer whose logic runs as a WASM
component inside the Runtime, with a render-only surface. It is milestone 2.5 of the roadmap, proven early on
today's Bus v1 so that Phase 2 starts from working code. Read `examples/photo-viewer/handoff/ROADMAP.md` first.

## Hard rules (same as the Agent Host spike)

- Work only in the private repo SashaMIT/elastos-agent-host-spike. Never push to Elacity. Never touch main.
- Base branch: `spike/photo-viewer` (develop 3beb8164 plus this handoff). One branch per slice:
  `claude/photo-<slice>`. Draft PRs into `spike/photo-viewer`. Merge commits only. Sasha merges.
- No rebase, amend, force-push, branch deletion. Commits end with
  `Co-authored-by: Claude <noreply@anthropic.com>`.
- Do not change shipping Runtime code outside test modules without Sasha's yes; stop and report first.
- No ambient authority: the component imports only `elastos:bus` interfaces. No WASI files, sockets or clock.
- Fail closed with a clear reason. Every refusal gets a test and a falsifier (break it, see the test fail,
  restore it).
- Do not touch `examples/agent-host/`. That is a separate track.
- Cloud limits: no KVM, no running Home, no models.

## Slices

| Slice | Goal | Exit |
|---|---|---|
| P0 Map (no code) | How a viewer is chosen for a Library object today (`interfaces`, `accepts`); how a component capsule is launched and returns output (`elastos-compute/src/providers/component.rs`, `elastos-guest`, `templates/capsules/component-app`, `examples/hello`); what path could hand component output to a render-only surface. | Report with file:line citations, the smallest design, and questions. |
| P1 Core in WASM | Component that, given an album (list of `elastos://object` URIs), reads each through `providers.invoke` with a grant, checks magic bytes (PNG, JPEG, WebP), size and dimension caps, and returns a playlist (order, duration, width, height, object CID/hash). Host tests with fakes, like `examples/agent-host`. | Tests and falsifiers pass; refusals for no grant, wrong type, oversize, truncated header. Guest hash and import list reported. |
| P2 Reproducible build | Build the guest in one pinned Linux container so Mac and cloud produce the same wasm hash. | Same sha256 from two machines; recipe in the report. |
| P3 Render-only surface (design first) | Smallest surface that only displays the playlist output and holds no authority of its own. | Design note and Sasha's yes before code. |
| P4 Signed bundle by CID (design only) | How the bundle would be named by CID and signed by a publisher DID, per roadmap 2.2. | Design note; no shipping change. |

## Report format (every slice)

Branch, PR, last commit, tests run and results, falsifiers, guest hash and import list, principles checked
(3, 10, 11, 13, 15, 16, 18), roadmap milestone served, questions for Sasha, next slice.
