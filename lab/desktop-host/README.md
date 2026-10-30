# ElastOS desktop host, prototype P1

lab prototype, not a product

A macOS menu-bar app around Home. It is the first step of ELASTOS-DESKTOP-APP: ElastOS
installs and runs like any desktop app, while the Runtime, Home, capsules and the updater
stay exactly as they are.

P1 shows whether Home answers, opens Home and quits. It runs no Runtime command, writes
no file, and registers nothing with launchd. `src/runtime.rs` is the only file that knows
about ElastOS.

Opening the app opens Home when Home is running, and so does double-clicking the app
again while it runs (the macOS reopen event).

## Menu

- Status line: "Home is running" or "Home is not running", refreshed every 3 seconds.
- Open Home, in order of preference:
  1. the Home app installed from the browser ("Install ElastOS" in Brave, Chrome or
     Edge at `http://localhost:8090/home/`); opening it brings its window forward and
     it has its own Dock icon;
  2. a new app-mode window (no tabs, no address bar) in Brave, Chrome, Edge or
     Chromium, whichever is installed first in that order;
  3. a tab of the default browser.

  Each is the real browser, so passkeys work. Passkeys belong to `localhost`, so the
  app never uses `127.0.0.1` or an embedded web view, which cannot use them there.
- Stop Home: disabled. It needs the background service planned for 0.8.1 (P2).
- Check for Updates: opens Home; updates stay in System > About.
- Quit ElastOS Lab: closes the menu-bar app only. Home keeps running.

On start the app refuses anything other than an Apple silicon Mac, and says so when
`~/.local/bin/elastos` is missing (with a note when less than about 8 GB is free).

## Limits

- Any Home on port 8090 counts as running. P2 asks the Runtime instead, which only
  reports this data folder's Home.
- No signing beyond ad-hoc, no notarization, no DMG, no installer.
- Without an installed Home app, app mode opens a new Home window each time; it does
  not bring an open one forward.

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
