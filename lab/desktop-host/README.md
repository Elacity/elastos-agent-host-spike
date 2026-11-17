# ElastOS desktop app (lab)

Lab prototype, not a product.

One app for macOS, Linux and Windows that carries a signed ElastOS release, installs it
on first open and shows Home in its own window. There is no browser and no terminal.
The Runtime still does the installing, starting and updating; the app only runs it
and shows Home.

| Platform | Window | Passkeys | ElastOS runs |
|---|---|---|---|
| macOS, Apple silicon | WebKit (WKWebView) | the app's own, in the Secure Enclave, behind Touch ID | as the user |
| Linux, x86_64 and arm64 | WebKitGTK 4.1 | the app's own, in the TPM, behind a PIN the TPM checks | as the user |
| Windows, x86_64 | WebView2 | Windows Hello, through WebView2 | in its own WSL 2 system, with no Windows drives or programs |

The window is `wry` with `tao`; `src/runtime.rs` is the only file that knows how to
reach Home.

## First open

1. The window shows "Starting ElastOS…".
2. The app copies the Runtime named in the release into the data folder, but only if
   its SHA-256 matches the one built into the app.
3. That Runtime runs `install --from` on the release inside the app. The release head,
   its one publisher, the Runtime and the sources file are pinned in the app at build
   time, so the folder cannot name its own. The Runtime then checks the signatures,
   CIDs and SHA-256 of every file, exactly as for a download.
4. The Runtime starts Home without opening a browser, and Home loads in the window.

Later opens skip the install and only start Home if it is not running.

## The window and menu

- The window loads only `http://localhost:8090/home/`. Home's passkeys belong to
  `localhost`, and `127.0.0.1` would be a different site.
- Closing the window hides it. The app stays in the menu bar or system tray, and
  opening the app again shows the window.
- Downloads, such as the Recovery Kit, open a Save dialog.
- When Home shows something fullscreen, the window goes fullscreen with it.
- Menu: whether Home is running (checked every second), Open Home, Stop Home
  (disabled until the Runtime has a background service), Check for Updates (opens
  Home; updates are in System > About), and Quit (closes the app only; Home keeps
  running).
- The app refuses to run on an Intel Mac, a 32-bit or Arm Windows PC, or any other
  system. When ElastOS is not installed and the app carries no release, it says so,
  with a note when less than about 8 GB is free.

## What it needs from the Runtime

The two Runtime commands the app runs, `install --from` and the quiet Home start, are
not in a published release yet. They are on the lab Runtime branch
`lab/standalone-install` and planned for ElastOS 2.0.2. Until then, the release
inside a lab app carries a lab Runtime signed with a lab key.

## Limits

- Any Home on port 8090 counts as running, not only this data folder's.
- No Developer ID signing, notarization or Windows code signing.
- Updates are offered only while System is open in Home.
- Linux: the tarball needs WebKitGTK 4.1 from the system. The planned download is an
  AppImage.
- Windows: WSL must be turned on once, as administrator.
- Links that leave Home and requests for new windows get no special handling yet.

## Build

Make the release folder the app carries. `make-release-folder.py` fetches one release:
the head, the release, the sources file and every file for one platform, each named by
its CID and checked against its SHA-256. With `--lab-runtime` it swaps in a lab Runtime
and signs the release with a lab key.

```sh
python3 lab/desktop-host/make-release-folder.py --sources SOURCES_JSON --out RELEASE \
  [--platform aarch64-linux] --lab-runtime LAB_ELASTOS --lab-key LAB_KEY --signer LAB_ELASTOS
```

Then pack the app. `bundle.sh` copies in only the files the signed release names,
found by `release-files.py`, and stops if one is missing. `LAB_HOME` is the folder the
app uses as the user's home folder.

```sh
# macOS: dist/ElastOS Lab.app
LAB_RELEASE=RELEASE LAB_HOME=LAB_HOME lab/desktop-host/bundle.sh
hdiutil create -volname "ElastOS Lab" -srcfolder DMG_SOURCE_FOLDER -format ULFO lab/desktop-host/dist/ElastOS-Lab.dmg

# Linux, built on Ubuntu 22.04 so it runs on older glibc: dist/elastos-lab-<platform>.tar.gz
LAB_RELEASE=RELEASE LAB_HOME=LAB_HOME lab/desktop-host/bundle.sh

# Windows, cross-built on a Mac with cargo-xwin, from an x86_64 Linux release and the
# Ubuntu 22.04 WSL image: dist/elastos-lab-windows-x86_64.zip
LAB_RELEASE=RELEASE LAB_WINDOWS_IMAGE=UBUNTU_WSL_TARBALL lab/desktop-host/bundle.sh
```

Builds have no Web Inspector and no `window-diag.log`. Set `LAB_DIAG=1` for a lab test
build that has them. Every lab build writes first-run timings to
`LAB_HOME/firstrun-timing.log`.

The app's icons are made from Home's own icon,
`capsules/home/browser/elastos-home-icon.svg`. After it changes, run
`lab/desktop-host/icons/make.sh` on a Mac and commit what it writes in `icons/`.

Checks:

```sh
cargo clippy --all-targets --locked --manifest-path lab/desktop-host/Cargo.toml -- -D warnings
cargo xwin clippy --all-targets --locked --target x86_64-pc-windows-msvc \
  --manifest-path lab/desktop-host/Cargo.toml -- -D warnings
```
