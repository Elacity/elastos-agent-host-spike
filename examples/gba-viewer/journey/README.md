# The GBA viewer's journey

A person signed in to Home opens the product GBA page and the product game, each by its CID, and the page boots
the real ROM the core recorded; frames advance. End to end, through the built `elastos` binary as the gateway and
as Home's Runtime.

```bash
(cd elastos && cargo build --locked -p elastos-server --bin elastos)
(cd elastos && cargo build --locked -p localhost-provider)   # its own package: Home's Runtime refuses to start without it
bash examples/gba-viewer/journey/run-journey.sh . <new work folder>
bash examples/gba-viewer/journey/falsify-journey.sh . <new work folder>
```

The core is built by the journey itself from a throwaway copy of `examples/gba-viewer/core` in the work folder,
using `scripts/build-component-capsule.sh` (the builder `examples/gba-viewer/core/build.sh` wraps); it needs the
`wasm32-unknown-unknown` target. Playwright with Chromium is taken from `ELASTOS_PLAYWRIGHT_MODULE`, or from
`elastos/tools/browser-playwright-engine`; its browsers from `PLAYWRIGHT_BROWSERS_PATH`, or the usual cache. The
binary and the storage provider are read from `${CARGO_TARGET_DIR:-elastos/target}/debug`. The work folder must be
outside the checkout: the bundle sources (`prepare_bundles.py`), the copied core and its component are written
there, and the journey writes nothing into the tree.

## What runs

1. A throwaway HOME and data folder, owner-only. Home's capsule and the storage provider installed in it as
   `elastos setup` lays them out.
2. The GBA core built from a throwaway copy of `examples/gba-viewer/core` under the work folder. Three
   publishers with a key each made for this run: the core, the product page
   (`capsules/gba-emulator/browser`, pinning the core) and the product ROM
   (`capsules/gba-ucity/ucity.gba`, pinning the page). `prepare_bundles.py` copies the page assets and the ROM
   byte-for-byte and derives both manifests; `elastos stage-bundle` names the core, the page and the content in
   dependency order, then stages them under this Home's trust.
3. `elastos gateway`, which holds the host lock, and `elastos serve` under it as Home's Runtime, writing its
   coordinates where Home's open reads them.
4. In headless Chromium with a virtual passkey (`journey-browser.mjs`): a new person registers in Home; from
   Home's page, `POST /api/home/launch/content` with the content CID the content's manifest pinned the page CID
   into; the page loaded at the answered address with its token in the fragment; then the pass conditions:
   `#status` hidden and empty, `#power-led` without `off`, and at least 30 more `MainLoop_runner` frames between
   two samples, the second stamped by the page's own clock no more than 2500 ms after the first.

The page token is a bearer credential. Every recorded text is redacted before it is printed or written (the
fragment, any JSON `token` field, the raw and percent-encoded token); a refusal is recorded only by an allowlisted
name and its length; the page and page URL only in their expected shapes.

## How frames are measured, and the census behind it

A wrapper installed with `page.addInitScript` (before the page's own scripts) counts
`window.requestAnimationFrame` calls by callback name. The census of this page found exactly two callers:
mGBA's rendering loop `MainLoop_runner` (`capsules/gba-emulator/browser/mgba.js:5810,5949-5952`) and the page's
own input poller `pollInput` (`emulator.js:661-669`). The check counts only `MainLoop_runner`, so the page's input
loop alone cannot make the counter grow; the recorded samples name the callers they saw. Each sample also saves
a `#canvas` screenshot (`canvas-sample-1.png`, `canvas-sample-2.png`) as information, not as a pass condition.

## What the journey proves and what it does not

It proves: the product page assets and the product ROM are admitted from their CIDs; the Runtime follows the
content's pin to the page and the page's pin to the core; the core runs for the launch, reads the launch's file
listing and asks the Runtime for the ROM's digest (it never reads a ROM byte), and writes the record the page
reads; the page fetches the recorded path, compares size and sha256, boots the game in mGBA, and the engine's
frame loop runs.

It does not prove: saves (a by-CID launch is play-only; the page skips the saved-game read and writes no save,
save state or library), the installed by-name GBA app (unchanged, out of this journey's subject), a Home control
button for a by-CID launch (there is none yet), that the picture is the game's animation (frame counting is
independent of what the game draws; the canvas shots are information), or gameplay, audio or input. The Linux
x86-64 receipt is owed when the ROG returns; this Mac receipt is the only one.

AP4 ("gba viewer named by CID from its content capsules") counts only when this journey passes at a merged head
with its four falsifiers red **and** Sash has re-confirmed the ruling's Option 2 with the new fact that one Runtime
operation `digest` is added. Until then the journey proves the mechanism and is reported as such.

## Planted faults (`falsify-journey.sh`)

Each one run must fail with the named check and the named refusal or page text in that check's detail:

| plant | what changes | where it goes red |
|---|---|---|
| `wrong-content-cid` | a valid CID the store never staged is given the page's files in its slot | `Home opens the game by its CID`: non-2xx, `bundle_cid_mismatch`, no token |
| `token-dropped` | the launch page loaded without its `#home_token` fragment | the boot check: `#status` shows `Open GBA from Home or Library.` |
| `rom-record-mismatch` | a throwaway copy of the core source copies the Runtime's digest answer and alters one hex digit; that core is rebuilt and restaged | the boot check: `#status` shows `gba_launch_rom_hash_mismatch` |
| `content-byte-flipped` | one byte of the staged `ucity.gba` changed in the store | `Home opens the game by its CID`: non-2xx, `bundle_cid_mismatch`, no token |

The first and last plants share one production fault class: a store slot that no longer recomputes to its name
(`BundleRefusal::CidMismatch`, `bundle_cid_mismatch`). They differ only in which slot is tampered: a foreign bundle
copied under the asked name, versus the content's own ROM byte-flipped. The middle two are page-side refusals, one
from the missing token and one from the record's disagreement with the ROM's bytes.
