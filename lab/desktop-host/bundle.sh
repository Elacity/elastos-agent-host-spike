#!/bin/sh
# Wraps the release binary as dist/ElastOS Lab.app: a local, ad-hoc signed
# menu-bar app. No Developer ID, no notarization, no DMG.
set -eu

cd "$(dirname "$0")"
cargo build --release --locked

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
	python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["payload"]["platforms"]["aarch64-darwin"]["binary"]["cid"])' \
		"$res/release/release.json" > "$res/runtime-cid"
	plutil -insert LSEnvironment -dictionary "$app/Contents/Info.plist"
	plutil -insert LSEnvironment.ELASTOS_LAB_HOME -string "$LAB_HOME" "$app/Contents/Info.plist"
fi

codesign --force --sign - "$app"
echo "Built $app"
