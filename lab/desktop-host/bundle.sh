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

# Experiment P3, SIMULATED install from the files inside the app. LAB_SEED is a fresh
# alpha.26 install made by the official installer with HOME=$LAB_SEED; LAB_HOME is the
# throwaway folder the app then treats as the user's home folder.
if [ -n "${LAB_SEED:-}" ]; then
	: "${LAB_HOME:?LAB_HOME is required with LAB_SEED}"
	res="$app/Contents/Resources"
	payload="$res/payload"
	mkdir -p "$payload" "$res/sim-bin"
	cp -cRp "$LAB_SEED/.local" "$LAB_SEED/Library" "$payload/"
	rm -rf "$payload/Library/Caches" "$payload/Library/Application Support/elastos/host-process.lock"
	(
		cd "$payload"
		find . -type l | while read -r link; do
			printf '%s\t%s\n' "${link#./}" "$(readlink "$link")"
			rm "$link"
		done > .path-links
		grep -rlIF --exclude=.path-links "$LAB_SEED" . | sed 's#^\./##' > .path-files
	)
	printf '%s\n' "$LAB_SEED" > "$payload/.seed-home"
	printf '#!/bin/sh\nexit 0\n' > "$res/sim-bin/open"
	chmod +x "$res/sim-bin/open"
	plutil -insert LSEnvironment -dictionary "$app/Contents/Info.plist"
	plutil -insert LSEnvironment.ELASTOS_LAB_HOME -string "$LAB_HOME" "$app/Contents/Info.plist"
fi

codesign --force --sign - "$app"
echo "Built $app"
