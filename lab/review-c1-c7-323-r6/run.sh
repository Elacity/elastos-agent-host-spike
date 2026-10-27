#!/bin/sh
# Rebuild the #323 probe and run the r6 review tests.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
python3 -I lab/review-c1-c7-323-r6/extract.py
( cd lab/review-c1-c7-323-r6/probe && cargo build --quiet )
python3 -I -m unittest discover -s lab/review-c1-c7-323-r6/py -v
