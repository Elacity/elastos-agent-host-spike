#!/bin/sh
# Static B4 map. Starts no provider. Linux and macOS execution are NOT RUN.
set -eu
cd "$(dirname "$0")/../.."
python3 -I lab/b4-permission-map/check.py --write
python3 -I lab/b4-permission-map/check.py --check
python3 -I -m unittest discover -s lab/b4-permission-map/tests -v
python3 -I lab/b4-permission-map/check.py --plant lab/b4-permission-map/plants/macos-network-allow
python3 -I lab/b4-permission-map/check.py --plant-baseline lab/b4-permission-map/plants/baseline-network-allow
echo "linux_x86_64_execution=NOT RUN"
echo "jetson_aarch64_execution=NOT RUN"
echo "macos_execution=NOT RUN"
