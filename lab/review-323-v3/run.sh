#!/bin/sh
# Rebuild the #323 probe and run the v3 review tests.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
python3 -I lab/review-323-v3/extract.py
( cd lab/review-323-v3/probe && cargo build --quiet )
python3 -I -m unittest discover -s lab/review-323-v3/py -v
