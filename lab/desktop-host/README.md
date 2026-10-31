# ElastOS desktop host, prototype P1

lab prototype, not a product

A macOS menu-bar app around Home. It is the first step of ELASTOS-DESKTOP-APP: ElastOS
installs and runs like any desktop app, while the Runtime, Home, capsules and the updater
stay exactly as they are.

P1 shows whether Home answers, shows Home and quits. It runs no Runtime command, writes
no file, and registers nothing with launchd. `src/runtime.rs` is the only file that knows
about ElastOS.

Home opens in the app's own window, a built-in macOS web view (WebKit, through `wry`).
There is no browser: one app, one Dock icon, one Home window. Opening the app, double-
clicking it again or clicking its Dock icon shows that window when Home is running.
Closing the window hides it; the app stays in the menu bar. The window loads only
`http://localhost:8090/home/` and gets no bridge to native code, so it holds no more
authority than a browser tab.

## Menu

- Status line: "Home is running" or "Home is not running", refreshed every 3 seconds.
- Open Home: shows the Home window, or says Home is not running.
- Stop Home: disabled. It needs the background service planned for 0.8.1 (P2).
- Check for Updates: opens Home; updates stay in System > About.
- Quit ElastOS Lab: closes the menu-bar app only. Home keeps running.

On start the app refuses anything other than an Apple silicon Mac, and says so when
`~/.local/bin/elastos` is missing (with a note when less than about 8 GB is free).

## Limits

- Any Home on port 8090 counts as running. P2 asks the Runtime instead, which only
  reports this data folder's Home.
- No signing beyond ad-hoc, no notarization, no DMG, no installer.
- Passkey sign-in in the built-in window is under test. macOS lets an app's web view
  use passkeys only for sites the app proves it owns, or for apps Apple grants its
  browser passkey permission; `localhost` cannot be proven. Passkeys made in a browser
  stay in that browser.
- Links that leave Home and requests for new windows get no special handling yet.

## Experiment P4: first open from the signed release inside the app

LAB DRAFT. Needs the lab Runtime branch `lab/standalone-install`, which adds
`elastos install --from DIR` and the quiet start `ELASTOS_SERVICE=1`. Neither is in a
published release.

`make-release-folder.py` fetches one release into a folder: head, release, sources,
and every file for this Mac named by its CID, each checked against its SHA-256. With
`--lab-runtime` it swaps in a lab Runtime and signs the release with a lab key.
`bundle.sh` packs that folder into `Contents/Resources/release`. On first open the
window shows "Starting ElastOS…", the release's own Runtime runs `install --from` (the
same publisher, signature, CID and SHA-256 checks as a download), then Home starts
without a browser and loads in the window. Only `LAB_HOME` is ever written. Timings go
to `$LAB_HOME/firstrun-timing.log`.

```sh
python3 lab/desktop-host/make-release-folder.py --sources SOURCES_JSON --out ~/elastos-lab-release/lab \
  --lab-runtime LAB_ELASTOS --lab-key ~/elastos-lab-release/lab-publisher.key --signer LAB_ELASTOS
LAB_RELEASE=~/elastos-lab-release/lab LAB_HOME=~/elastos-lab-user4 lab/desktop-host/bundle.sh
hdiutil create -volname "ElastOS Lab" -srcfolder DMG_SOURCE_FOLDER -format ULFO lab/desktop-host/dist/ElastOS-Lab.dmg
```

## Build and run

```sh
lab/desktop-host/bundle.sh
open "lab/desktop-host/dist/ElastOS Lab.app"
```

Checks:

```sh
cargo fmt --check --manifest-path lab/desktop-host/Cargo.toml
cargo clippy --all-targets --locked --manifest-path lab/desktop-host/Cargo.toml -- -D warnings
```
