#!/bin/bash
# Live-path mutants against a copy of #334. Requires /tmp/a5-review-copy.
set -eu
REVIEW_DIR=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
COPY=/tmp/a5-review-copy
OUT="$REVIEW_DIR/mutants/results"
HARNESS="$COPY/lab/a5-binding-harness"
MANIFEST="$HARNESS/Cargo.toml"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$HARNESS/target/host"
mkdir -p "$OUT"

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
if "pub fn gap(self) -> Option<&'static [Pin]> {\n        None" in text:
    print("gap() already None")
elif old not in text:
    raise SystemExit("gap() block not found")
else:
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
# ensure gap is Some
if grep -q 'Some(match self' "$HARNESS/src/capability.rs"; then
    echo "gap() is Some (blocked)"
else
    echo "WARNING: gap already None; restore from SRC"
    cp /tmp/a5-334-wt/lab/a5-binding-harness/src/capability.rs "$HARNESS/src/capability.rs"
fi
port=$(start_stub theatre)
write_coords "$port" "$OUT/forged-coords.json"
set +e
A5_RUNTIME_COORDS="$OUT/forged-coords.json" \
    cargo run --locked --quiet --manifest-path "$MANIFEST" --bin acceptance \
    >"$OUT/M-FORGE-TODAY.txt" 2>&1
echo "exit=$?" >>"$OUT/M-FORGE-TODAY.txt"
set -e
stop_stub theatre
tail -5 "$OUT/M-FORGE-TODAY.txt"

echo "=== unblock gap() ==="
unblock_gaps

echo "=== M-SKIP-NO-COORDS ==="
unset A5_RUNTIME_COORDS || true
set +e
cargo run --locked --quiet --manifest-path "$MANIFEST" --bin acceptance \
    >"$OUT/M-SKIP-NO-COORDS.txt" 2>&1
echo "exit=$?" >>"$OUT/M-SKIP-NO-COORDS.txt"
set -e
tail -8 "$OUT/M-SKIP-NO-COORDS.txt"

for mode in theatre allow-all prefix empty-id hide-end public-ok other-root reason-sub; do
    echo "=== M-STUB-$mode ==="
    port=$(start_stub "$mode")
    echo "port=$port"
    write_coords "$port" "$OUT/coords-$mode.json"
    set +e
    A5_RUNTIME_COORDS="$OUT/coords-$mode.json" \
        cargo run --locked --quiet --manifest-path "$MANIFEST" --bin acceptance \
        >"$OUT/M-STUB-$mode.txt" 2>&1
    echo "exit=$?" >>"$OUT/M-STUB-$mode.txt"
    set -e
    stop_stub "$mode"
    rg -n 'PASS|FAIL|BLOCKED|SKIPPED|accepted|exit=' "$OUT/M-STUB-$mode.txt" | tail -20
done

echo done
