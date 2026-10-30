# ElastOS desktop host, prototype P1

lab prototype, not a product

A macOS menu-bar app around Home. It is the first step of ELASTOS-DESKTOP-APP: ElastOS
installs and runs like any desktop app, while the Runtime, Home, capsules and the updater
stay exactly as they are.

P1 shows whether Home answers, opens Home and quits. It runs no Runtime command, writes
no file, and registers nothing with launchd. `src/runtime.rs` is the only file that knows
about ElastOS.

## Menu

- Status line: "Home is running" or "Home is not running", refreshed every 3 seconds.
- Open Home: opens `http://localhost:8090/home/` as its own window (app mode: no tabs,
  no address bar) in Brave, Chrome, Edge or Chromium, whichever is installed first in
  that order; otherwise in a tab of the default browser. It is still the real browser,
  so passkeys work. Passkeys belong to `localhost`, so the app never uses `127.0.0.1`
  or an embedded web view, which cannot use them there.
- Stop Home: disabled. It needs the background service planned for 0.8.1 (P2).
- Check for Updates: opens Home; updates stay in System > About.
- Quit ElastOS Lab: closes the menu-bar app only. Home keeps running.

On start the app refuses anything other than an Apple silicon Mac, and says so when
`~/.local/bin/elastos` is missing (with a note when less than about 8 GB is free).

## Limits

- Any Home on port 8090 counts as running. P2 asks the Runtime instead, which only
  reports this data folder's Home.
- No signing beyond ad-hoc, no notarization, no DMG, no installer.

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
