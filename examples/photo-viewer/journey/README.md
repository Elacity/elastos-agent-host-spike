# The photo viewer's journey

A person signed in to Home opens a photo set named by its CID, and the photo viewer's page shows its pictures in a
browser; a set whose bytes no longer match its CID, and a CID never staged, are each refused by name. End to end,
through the built `elastos` binary as the gateway and as Home's Runtime.

```bash
cargo build --locked -p elastos-server --bin elastos   # in elastos/
cargo build --locked -p localhost-provider             # its own command: --bin elastos would leave it unbuilt
bash examples/photo-viewer/journey/run-journey.sh . <new work folder> <photo-viewer.component.wasm>
bash examples/photo-viewer/journey/falsify-journey.sh . <new work folder> <photo-viewer.component.wasm>
```

The `.wasm` must be the photo core's reference artifact: the run checks it against the `photo-viewer` line of
`examples/capsule-kit/repro/recorded-hashes.txt` and stops otherwise (`repro/README.md` says how it is built).
Playwright with Chromium is taken from `ELASTOS_PLAYWRIGHT_MODULE`, or from
`elastos/tools/browser-playwright-engine`; its browsers from `PLAYWRIGHT_BROWSERS_PATH`, or the usual cache.

## What runs

1. A throwaway HOME and data folder, owner-only. Home's capsule and the storage provider installed in it as
   `elastos setup` lays them out (Home from this checkout's `capsules/home`; the provider built here, listed with
   this checkout's own entry in `components.json` and the checksum of the binary built here).
2. Three publishers, a key each made for this run: the photo core (`examples/photo-viewer`), the page
   (`examples/photo-viewer/surface`, pinning the core by CID) and the photo set (the three committed pictures
   under `images/`, pinning the page). A second set is staged and then one byte of one picture is changed where it
   is kept; a third is never staged. This Home trusts the three publishers.
3. `elastos gateway`, which holds the host lock, and `elastos serve` under it as Home's Runtime, writing its
   coordinates where Home's open reads them (`home-runtime-coords.json`), as the Runtime Home starts for itself
   does.
4. In headless Chromium with a virtual passkey (`journey-browser.mjs`): a new person registers in Home; from Home's
   page, `POST /api/home/launch/content` with the set's CID; the page loaded at the answered address with its
   token in the fragment; the three pictures shown in order (red `01.png`, green `02.jpg`, blue `03.webp`, read
   back from their pixels), each at the size the photo core read from its bytes; the page asking only for the
   playlist and the three pictures. Then the changed set (`bundle_cid_mismatch`) and the CID never staged
   (`bundle_missing`), each refused by name, with no page token.

## Limits

- Home's Runtime is started by the script, not by Home's own "ensure" (which also needs the shell and identity
  providers that `elastos setup` installs). The Runtime runs the same code and is found by Home's open the same
  way; only its starting differs.
- The page is loaded in its own tab at its address, not framed inside Home's desktop.
- The keys and the throwaway folder are made for one run and left in the work folder.

## Planted faults (`falsify-journey.sh`)

Each must turn the journey red at the check named: the page loaded without its token (no pictures); the page
pinning another CID as its core (the open refused); one byte of the good set changed too (the open refused); the
page reading the routes it read before it read by path (no pictures).
