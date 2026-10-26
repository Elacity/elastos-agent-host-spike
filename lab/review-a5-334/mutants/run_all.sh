#!/bin/bash
# Replay PR #334 official falsifiers and run review mutants.
# Mutates only a copy under /tmp/a5-review-copy. Does not touch #334's branch.
set -eu
REVIEW_DIR=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
SRC=${A5_SRC:-/tmp/a5-334-wt}
COPY=/tmp/a5-review-copy
OUT="$REVIEW_DIR/mutants/results"
mkdir -p "$OUT"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0

rm -rf "$COPY"
mkdir -p "$COPY/lab" "$COPY/elastos"
cp -a "$SRC/lab/a5-binding-harness" "$COPY/lab/"
# Pin files the BLOCKED rows read via repo_root().
while IFS= read -r rel; do
    mkdir -p "$COPY/$(dirname "$rel")"
    cp -a "$SRC/$rel" "$COPY/$rel"
done <<'PINS'
elastos/crates/elastos-server/src/api/handlers/capability.rs
elastos/crates/elastos-server/src/api/server.rs
elastos/crates/elastos-runtime/src/capability/token.rs
elastos/crates/elastos-runtime/src/session/registry.rs
elastos/crates/elastos-server/src/run_cmd.rs
elastos/crates/elastos-server/src/resource_bridge.rs
elastos/crates/elastos-server/src/auth.rs
elastos/crates/elastos-compute/src/providers/component.rs
elastos/crates/elastos-server/src/api/routes.rs
PINS
rm -rf "$COPY/lab/a5-binding-harness/target"

HARNESS="$COPY/lab/a5-binding-harness"
MANIFEST="$HARNESS/Cargo.toml"
export CARGO_TARGET_DIR="$HARNESS/target/host"

echo "=== official falsifiers ==="
python3 "$REVIEW_DIR/mutants/run_official_falsifiers.py" "$HARNESS" "$OUT"

unblock_gaps() {
    python3 - "$HARNESS/src/capability.rs" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
text = p.read_text()
old = """    pub fn gap(self) -> Option<&'static [Pin]> {
        Some(match self {
            Capability::LiveGrantView => LIVE_GRANT_VIEW,
            Capability::Settlement => SETTLEMENT,
            Capability::HomeStorage => HOME_STORAGE,
            Capability::UsersAiAlias => USERS_AI_ALIAS,
            Capability::ResidentCore => RESIDENT_CORE,
        })
    }"""
new = """    pub fn gap(self) -> Option<&'static [Pin]> {
        None
    }"""
if old not in text:
    raise SystemExit("gap() block not found")
p.write_text(text.replace(old, new, 1))
print("gap() forced to None")
PY
}

start_stub() {
    local mode="$1"
    : >"$OUT/stub-$mode.port"
    A5_STUB_MODE="$mode" A5_STUB_PORT=0 python3 "$REVIEW_DIR/mutants/stub_operator.py" \
        >"$OUT/stub-$mode.port" 2>"$OUT/stub-$mode.err" &
    echo $! >"$OUT/stub-$mode.pid"
    local i=0
    while [ ! -s "$OUT/stub-$mode.port" ] && [ "$i" -lt 80 ]; do
        sleep 0.05
        i=$((i + 1))
    done
    tr -d '\n' <"$OUT/stub-$mode.port"
}

stop_stub() {
    local mode="$1"
    if [ -f "$OUT/stub-$mode.pid" ]; then
        kill "$(cat "$OUT/stub-$mode.pid")" 2>/dev/null || true
        wait "$(cat "$OUT/stub-$mode.pid")" 2>/dev/null || true
        rm -f "$OUT/stub-$mode.pid"
    fi
}

write_coords() {
    local port="$1"
    local dest="$2"
    python3 -c "import json,pathlib; pathlib.Path('$dest').write_text(json.dumps({'api_url': 'http://127.0.0.1:$port', 'runtime_kind': 'operator', 'attach_secret': 'forged-attach-secret'}))"
}

echo "=== M-FORGE-TODAY: forged coords + theatre stub, gap() still Some ==="
port=$(start_stub theatre)
write_coords "$port" "$OUT/forged-coords.json"
set +e
A5_RUNTIME_COORDS="$OUT/forged-coords.json" \
    cargo run --locked --quiet --manifest-path "$MANIFEST" --bin acceptance \
    >"$OUT/M-FORGE-TODAY.txt" 2>&1
echo "exit=$?" >>"$OUT/M-FORGE-TODAY.txt"
set -e
stop_stub theatre

echo "=== unblock gap() for live-path mutants ==="
unblock_gaps

echo "=== M-SKIP-NO-COORDS: gaps cleared, no A5_RUNTIME_COORDS ==="
unset A5_RUNTIME_COORDS || true
set +e
cargo run --locked --quiet --manifest-path "$MANIFEST" --bin acceptance \
    >"$OUT/M-SKIP-NO-COORDS.txt" 2>&1
echo "exit=$?" >>"$OUT/M-SKIP-NO-COORDS.txt"
set -e

for mode in theatre allow-all prefix empty-id hide-end public-ok other-root reason-sub; do
    echo "=== M-STUB-$mode ==="
    port=$(start_stub "$mode")
    write_coords "$port" "$OUT/coords-$mode.json"
    set +e
    A5_RUNTIME_COORDS="$OUT/coords-$mode.json" \
        cargo run --locked --quiet --manifest-path "$MANIFEST" --bin acceptance \
        >"$OUT/M-STUB-$mode.txt" 2>&1
    echo "exit=$?" >>"$OUT/M-STUB-$mode.txt"
    set -e
    stop_stub "$mode"
done

echo "done" | tee "$OUT/DONE"
