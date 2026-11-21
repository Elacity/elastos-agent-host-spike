#!/bin/sh
# Remakes every app icon from Home's icon. Run on a Mac after Home's icon changes,
# then commit the results; Linux and Windows builds use them as they are.
set -eu

cd "$(dirname "$0")"
svg=../../../capsules/home/browser/elastos-home-icon.svg
rm -rf ElastOS.iconset
mkdir ElastOS.iconset
swift render.swift "$svg" .
iconutil -c icns -o ElastOS.icns ElastOS.iconset
rm -rf ElastOS.iconset
python3 pack.py .
for size in 16 24 48 64 128; do
	rm "elastos-$size.png"
done
echo "Made ElastOS.icns, elastos.ico, elastos.res, elastos-{32,256,512}.png, tray-template.png"
