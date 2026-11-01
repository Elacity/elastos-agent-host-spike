#!/bin/sh
# Wraps the release binary as dist/ElastOS Lab.app: a local, ad-hoc signed
# menu-bar app. No Developer ID, no notarization, no DMG. On Linux it makes
# dist/elastos-lab-<platform>.tar.gz: the binary, the release and a desktop file.
set -eu

cd "$(dirname "$0")"
case "$(uname -s)/$(uname -m)" in
	Darwin/arm64) platform=aarch64-darwin ;;
	Linux/aarch64) platform=aarch64-linux ;;
	Linux/x86_64) platform=x86_64-linux ;;
	*) echo "unsupported build host $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac
# The app, not the folder, names the release it installs: the head CID, its only
# publisher, and the Runtime that runs the install are built into the executable.
if [ -n "${LAB_RELEASE:-}" ]; then
	pins="$(python3 - "$LAB_RELEASE" "$platform" <<'PY'
import base64, hashlib, json, os, re, stat, sys
folder, platform = sys.argv[1], sys.argv[2]
def read(name):
    path = os.path.join(folder, name)
    if not stat.S_ISREG(os.lstat(path).st_mode):
        sys.exit(f"{name} in the release folder is not a regular file")
    return open(path, "rb").read()
head = read("release-head.json")
release = read("release.json")
head_payload = json.loads(head)
if head_payload["payload"]["release_sha256"] != hashlib.sha256(release).hexdigest():
    sys.exit("release.json is not the release the head names")
binary = json.loads(release)["payload"]["platforms"][platform]["binary"]
runtime = read(binary["cid"])
if hashlib.sha256(runtime).hexdigest() != binary["sha256"] or len(runtime) != binary["size"]:
    sys.exit("the Runtime file is not the one the release names")
pins = [
    "b" + base64.b32encode(bytes([0x01, 0x55, 0x12, 0x20]) + hashlib.sha256(head).digest()).decode().lower().rstrip("="),
    head_payload["signer_did"],
    binary["cid"],
    binary["sha256"],
    hashlib.sha256(read("sources.json")).hexdigest(),
]
patterns = [r"b[a-z2-7]{58}", r"did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}", r"[A-Za-z0-9]{1,128}", r"[0-9a-f]{64}", r"[0-9a-f]{64}"]
for pin, pattern in zip(pins, patterns):
    if not re.fullmatch(pattern, pin):
        sys.exit(f"unexpected release pin {pin!r}")
print("\n".join(pins))
PY
)"
	ELASTOS_RELEASE_HEAD="$(printf '%s\n' "$pins" | sed -n 1p)"
	ELASTOS_RELEASE_PUBLISHER="$(printf '%s\n' "$pins" | sed -n 2p)"
	ELASTOS_RELEASE_RUNTIME="$(printf '%s\n' "$pins" | sed -n 3p)"
	ELASTOS_RELEASE_RUNTIME_SHA256="$(printf '%s\n' "$pins" | sed -n 4p)"
	ELASTOS_RELEASE_SOURCES_SHA256="$(printf '%s\n' "$pins" | sed -n 5p)"
	export ELASTOS_RELEASE_HEAD ELASTOS_RELEASE_PUBLISHER ELASTOS_RELEASE_RUNTIME \
		ELASTOS_RELEASE_RUNTIME_SHA256 ELASTOS_RELEASE_SOURCES_SHA256
fi
cargo build --release --locked --features lab-diag

if [ "$platform" != aarch64-darwin ]; then
	: "${LAB_RELEASE:?LAB_RELEASE is required on Linux}"
	: "${LAB_HOME:?LAB_HOME is required with LAB_RELEASE}"
	root="dist/elastos-lab"
	rm -rf "$root" "dist/elastos-lab-$platform.tar.gz"
	mkdir -p "$root/bin" "$root/Resources"
	cp target/release/elastos-desktop-host "$root/bin/elastos-desktop-host"
	cp -Rp "$LAB_RELEASE" "$root/Resources/release"
	# Installed by the user as ~/.local/share/applications/elastos-lab.desktop;
	# @APP@ is where the folder was unpacked.
	cat > "$root/elastos-lab.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=ElastOS Lab
Exec=env ELASTOS_LAB_HOME=$LAB_HOME @APP@/bin/elastos-desktop-host
Terminal=false
Categories=Network;
DESKTOP
	tar -czf "dist/elastos-lab-$platform.tar.gz" -C dist elastos-lab
	echo "Built dist/elastos-lab-$platform.tar.gz"
	exit 0
fi

app="dist/ElastOS Lab.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp target/release/elastos-desktop-host "$app/Contents/MacOS/elastos-desktop-host"

cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>ElastOS Lab</string>
	<key>CFBundleDisplayName</key>
	<string>ElastOS Lab</string>
	<key>CFBundleIdentifier</key>
	<string>org.elastos.lab.desktop-host</string>
	<key>CFBundleExecutable</key>
	<string>elastos-desktop-host</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>0.1.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>NSLocalNetworkUsageDescription</key>
	<string>ElastOS uses your local network to find your other ElastOS devices.</string>
</dict>
</plist>
PLIST

# Experiment P4: first open installs from a signed release folder made by
# make-release-folder.py with the lab Runtime. LAB_HOME is the throwaway folder the
# app then treats as the user's home folder.
if [ -n "${LAB_RELEASE:-}" ]; then
	: "${LAB_HOME:?LAB_HOME is required with LAB_RELEASE}"
	res="$app/Contents/Resources"
	mkdir -p "$res"
	cp -cRp "$LAB_RELEASE" "$res/release"
	plutil -insert LSEnvironment -dictionary "$app/Contents/Info.plist"
	plutil -insert LSEnvironment.ELASTOS_LAB_HOME -string "$LAB_HOME" "$app/Contents/Info.plist"
fi

codesign --force --sign - "$app"
echo "Built $app"
