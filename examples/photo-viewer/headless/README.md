# The photo viewer, headless: a by-CID receipt for any machine

A machine with a shell, `python3` and `curl` — no browser and no node — starts the photo viewer's signed bundle by
its CID through the Runtime's own open route, and shows that a copy of the bundle whose bytes no longer match its
CID is refused by name. `results.json` in the run's folder is the receipt; `compare-hashes.py` says whether two
machines' receipts name the same bundles.

This proves what PH5 counts: the same signed bundle starts on this machine. It does not show the page or its
pictures; the browser journey shows those (`../journey/README.md`).

## Run it

```bash
cargo build --locked -p elastos-server --bin elastos   # in elastos/
cargo build --locked -p localhost-provider             # its own command: --bin elastos would leave it unbuilt
bash examples/photo-viewer/headless/run-headless.sh . <new work folder> <photo-viewer.component.wasm>
python3 examples/photo-viewer/headless/compare-hashes.py <work folder>/results.json <reference>
bash examples/photo-viewer/headless/falsify-headless.sh . <new work folder> <photo-viewer.component.wasm>
```

`CARGO_TARGET_DIR` picks where the built binaries are read (`<target>/debug/elastos`, `<target>/debug/localhost-provider`);
without it the checkout's `elastos/target` is used, as the browser journey does. The `.wasm` must be the photo
core's reference artifact: the run checks it against the `photo-viewer` line of
`examples/capsule-kit/repro/recorded-hashes.txt` and stops otherwise. The same artifact bytes can be carried to
every machine and checked there; a fresh build on any machine is compared with that record
(`examples/photo-viewer/repro/README.md` says how the reference is built).

### macOS (arm64 or x86_64)

```bash
bash examples/photo-viewer/headless/run-headless.sh . /tmp/ph5-headless-mac /tmp/ph5-core.wasm
```

The throwaway data folder is `~/Library/Application Support/elastos` under the run's own HOME.

### Linux x86_64

```bash
bash examples/photo-viewer/headless/run-headless.sh . /tmp/ph5-headless-rog /tmp/ph5-core.wasm
```

The throwaway data folder is `~/.local/share/elastos` under the run's own HOME. The receipt's `host_triple` reads
`Linux x86_64`.

### Linux aarch64

The same command on the aarch64 machine:

```bash
bash examples/photo-viewer/headless/run-headless.sh . /tmp/ph5-headless-spark4 /tmp/ph5-core.wasm
```

The receipt's `host_triple` reads `Linux aarch64`. The Runtime binary is that machine's own build, so its
`runtime_binary_sha256` differs from another arch's; the CIDs and the component hash are what must match.

## What the run does

1. A throwaway HOME and data folder, owner-only. Home's capsule and the storage provider installed in it as
   `elastos setup` lays them out, with this checkout's provider checksum in `components.json`; `dev_mode = true`
   and this run's three publishers as trusted keys.
2. Three publishers, a key each made for this run: the photo core (`examples/photo-viewer`, its reference `.wasm`),
   the page (`examples/photo-viewer/surface`, pinning the core by CID) and the photo set (the three committed
   pictures under `images/`, pinning the page). A second copy of the set is staged too, and then one byte of one
   picture is changed where the store keeps it; the source folder is never touched.
3. `elastos gateway`, which holds the host lock, and `elastos serve` under it as Home's Runtime, writing its
   coordinates where a local caller reads them (`home-runtime-coords.json`).
4. The open by CID, `POST /api/launch/open` on the Runtime with `{cid}` — the route the browser journey's gateway
   calls for the person's open (`journey/journey-browser.mjs` → `POST /api/home/launch/content` →
   `elastos-server/src/api/viewer_gateway.rs:1105`). A shell attach token comes from the Runtime's own
   `attach_secret`. The person's passkey session needs a browser, so the open carries the Runtime's local device
   authority instead: a launch token signed by this Home's own device key for the device principal, with a
   `local:` session and a `grant:local:` grant — the authority `elastos home` uses for local tools
   (`elastos-server/src/api/gateway_home_token.rs`, the proofless-device arm of the verifier). The script makes
   that token from the run's own `identity/device.key`, uses it for this run's two opens (the good one and the changed
   copy), and deletes it with every other credential file when the run ends, on success or failure; it is never
   printed or recorded. When the run ends, on success or failure, the throwaway Home (its device key and the Runtime's
   attach secret) and the credential files are removed by `secure_rm.py`: the work folder is opened without following
   a symlink and its device and inode are checked against the folder the run made; the Home is opened from it and
   checked the same way on the open descriptor, then emptied through that descriptor. If a check fails, nothing is
   removed there and the run fails, naming what may remain. Boundary: the folders above the work folder are resolved
   normally (the identity check on the open folder is what binds the removal); the emptied Home is then removed by
   name, and rmdir removes only an empty folder (a failure there fails the run); a Home moved away after its contents
   were removed leaves only an empty folder. This is an examples script run by the owner in owner-only folders: a
   process of the same user could read the throwaway key directly, so the bar is that removal stays inside the run's
   own folders and no credential is left without the run failing. The work folder is made owner-only and must lie outside the checkout (real paths).
5. `results.json` is written in the run's folder. Exit 0 only when the good open answered `200` with a page named
   and the changed-byte open answered `400` with `bundle_cid_mismatch`.

## results.json

```json
{
  "schema": "elastos.photo-viewer.headless-receipt/v1",
  "host_triple": "Darwin arm64",
  "content_cid": "<the set's CID>",
  "page_cid": "<the page's CID>",
  "core_cid": "<the photo core's CID>",
  "component_sha256": "<the core .wasm's sha256>",
  "runtime_binary_sha256": "<the elastos binary's sha256>",
  "start_status": 200,
  "start_page": "image-viewer",
  "changed_start_status": 400,
  "changed_start_refusal": "bundle_cid_mismatch",
  "checks": {"good_start_started": true, "changed_byte_refused": true}
}
```

No token, key or URL goes into it. The refusal is recorded by its name, never the server's text.

## compare-hashes.py

```bash
python3 examples/photo-viewer/headless/compare-hashes.py mac/results.json spark4/results.json
python3 examples/photo-viewer/headless/compare-hashes.py mac/results.json examples/capsule-kit/repro/recorded-hashes.txt
```

`content_cid`, `page_cid`, `core_cid` and `component_sha256` must match. `host_triple` and
`runtime_binary_sha256` may differ and are printed as such. A recorded-hash reference compares only the component
hash and says so. Exit 1 names every field that is missing or differs; a receipt that does not record a good start
and the expected refusal also fails.

## What is and is not proved

Proved by one green run on a machine: the photo viewer's signed bundle, with the page and core it pins, passes the
Runtime's by-CID admission and the core runs to its end there; a copy whose one byte changed is refused as
`bundle_cid_mismatch`; the artifact hashes and CIDs in the receipt name exactly that input.

Not proved here:

- that the page renders or the pictures appear — that is the browser journey's result;
- that Home's own passkey-signed open works on this machine — the browser journey covers it, and this receipt
  takes the Runtime's local device authority instead;
- that the Runtime was installed from a release: the run reads `<target>/debug/elastos`, built in the checkout.

## Falsifiers (`falsify-headless.sh`)

Each must turn the receipt red at the check named, not at a build error: the changed-byte copy left alone (the
run's own refusal check), one CID altered in a copy of the receipt (compare names `content_cid`), a required
field removed from a copy (compare names `component_sha256`), and a reference receipt whose changed copy was not
refused (compare names it `INVALID reference: changed_start_status 200 is not 400`), and the Home swapped for another
folder before cleanup (the run refuses to remove it and fails: `home is not the folder this run made; nothing removed there`). The plants change no file in the checkout: one is an
environment variable and two work on copies under the work folder.
