#!/usr/bin/env bash
# C1-C7 Mac runner. Lists, then runs, the 32 named sandbox-exec tests.
# Writes evidence.txt in this folder. Called from the one-paste fence
# after a fresh clone whose HEAD is a descendant of ea25c4d6.
set -euo pipefail

lane=$(cd -- "$(dirname -- "$0")" && pwd -P)
root=$(cd -- "$lane/../.." && pwd -P)
evidence="$lane/evidence.txt"
probe_dir="$lane/probe"
pin=ea25c4d6d58f1dc08d29173b45349bfeb80903f3

# Exactly the 32 named macOS sandbox-exec tests (ignored on Linux).
# The did ignored fixture is not in this list.
wallet_tests='
confined_provider_serves_wallet_operations_under_its_root
confined_outside_write_is_denied
confined_outside_read_is_denied
planted_key_beneath_storage_parent_is_not_read
account_operations_beneath_storage_parent_are_refused
startup_is_refused_when_the_profile_cannot_be_applied
unbound_copy_is_refused_under_profile
bound_copy_serves_under_profile
startup_denial_reports_its_reason
the_bare_value_fixture_loads_under_sandbox_exec
the_string_fixture_loads_under_sandbox_exec
'
model_tests='
model_provider_ops_under_profile
model_outside_write_denied
model_outside_read_denied
model_outside_create_reports_access_denied
model_local_offer_fails_closed_under_profile
model_hosted_run_fails_closed_under_profile
model_hosted_run_reaches_runtime_socket_when_unconfined
model_unbound_program_refused_under_profile
model_bound_copy_serves_under_profile
byte_different_file_at_bound_path_starts
startup_is_refused_when_the_profile_cannot_be_applied
'
did_tests='
confined_provider_serves_did_operations_under_its_root
verify_did_recovery_under_profile
outside_write_denied
outside_read_denied
planted_file_beneath_storage_parent_is_neither_read_nor_written
persona_key_beneath_storage_parent_is_not_adopted
startup_denial_reports_its_reason
startup_is_refused_when_the_profile_cannot_be_applied
unbound_copy_is_refused_under_profile
bound_copy_serves_under_profile
'

c17_names() {
  printf '%s\n' "$1" | awk 'NF { print }'
}

c17_write_evidence() {
  {
    printf 'C1-C7 mac sandbox-exec\n'
    printf 'pin: %s\n' "$pin"
    if [ -n "${c17_reason:-}" ]; then
      printf 'reason: %s\n' "$c17_reason"
    fi
    printf '%s\n' "$c17_rows"
    printf 'passed: %s\n' "${c17_passed:-0}"
    printf 'failed: %s\n' "${c17_failed:-0}"
    printf 'ignored: %s\n' "${c17_ignored:-0}"
    printf 'SBPL_PROBE: %s\n' "${c17_probe:-NOT MEASURED}"
    if [ -n "${c17_probe_detail:-}" ]; then
      printf 'SBPL_PROBE_DETAIL: %s\n' "$c17_probe_detail"
    fi
  } > "$evidence"
}

c17_list_names() {
  manifest=$1
  list_out=$2
  CARGO_TERM_COLOR=never cargo test --manifest-path "$manifest" --test confine -- --list > "$list_out" 2>&1
}

c17_require_listed() {
  crate=$1
  list_out=$2
  shift 2
  python3 -I - "$list_out" "$crate" "$@" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
crate = sys.argv[2]
wanted = sys.argv[3:]
listed = set()
for line in text.splitlines():
    raw = line.strip()
    if raw.endswith(": test") or raw.endswith(": test (ignored)"):
        listed.add(raw.split(":", 1)[0].strip())
missing = [name for name in wanted if name not in listed]
if missing:
    print("cargo --list did not name " + crate + ": " + ",".join(missing))
    raise SystemExit(2)
print("listed " + crate + " " + str(len(wanted)))
PY
}

c17_score_cargo() {
  crate=$1
  cargo_out=$2
  shift 2
  python3 -I - "$crate" "$cargo_out" "$@" <<'PY'
import pathlib
import sys

crate = sys.argv[1]
text = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace")
wanted = sys.argv[3:]
rows = {}
for line in text.splitlines():
    stripped = line.strip()
    if not stripped.startswith("test "):
        continue
    rest = stripped[len("test ") :]
    if " ... " not in rest:
        continue
    name, result = rest.split(" ... ", 1)
    name = name.strip()
    if name not in wanted:
        continue
    result = result.strip()
    if result == "ok":
        status = "PASS"
    elif result.startswith("ignored"):
        status = "IGNORED"
    elif result.startswith("FAILED") or result.startswith("failed"):
        status = "FAIL"
    else:
        status = "UNKNOWN"
    if name in rows:
        rows[name] = "DUPLICATE"
    else:
        rows[name] = status
for name in wanted:
    print(f"{crate}/{name}: {rows.get(name, 'MISSING')}")
PY
}

cd -- "$root"
export CARGO_TERM_COLOR=never
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"

mkdir -p -- "$probe_dir"
c17_rows=""
c17_passed=0
c17_failed=0
c17_ignored=0
c17_probe="NOT MEASURED"
c17_probe_detail=""
c17_reason=""
c17_rc=0

wallet_list="$probe_dir/wallet.list"
model_list="$probe_dir/model.list"
did_list="$probe_dir/did.list"

set +e
c17_list_names "$root/capsules/wallet-provider/Cargo.toml" "$wallet_list"
wallet_list_rc=$?
set -e
if [ "$wallet_list_rc" -ne 0 ]; then
  c17_reason="cargo --list failed for wallet-provider"
  c17_rows="wallet/confined_provider_serves_wallet_operations_under_its_root: MISSING"
  c17_write_evidence
  exit 1
fi
wallet_names=$(c17_names "$wallet_tests")
set +e
c17_list_msg=$(c17_require_listed wallet "$wallet_list" $wallet_names)
wallet_req_rc=$?
set -e
if [ "$wallet_req_rc" -ne 0 ]; then
  c17_reason=$c17_list_msg
  c17_rows=""
  for name in $wallet_names; do
    c17_rows="${c17_rows}${c17_rows:+
}wallet/${name}: MISSING"
  done
  c17_write_evidence
  exit 2
fi

set +e
c17_list_names "$root/capsules/model-provider/Cargo.toml" "$model_list"
model_list_rc=$?
set -e
if [ "$model_list_rc" -ne 0 ]; then
  c17_reason="cargo --list failed for model-provider"
  c17_write_evidence
  exit 1
fi
model_names=$(c17_names "$model_tests")
set +e
c17_list_msg=$(c17_require_listed model "$model_list" $model_names)
model_req_rc=$?
set -e
if [ "$model_req_rc" -ne 0 ]; then
  c17_reason=$c17_list_msg
  c17_rows=""
  for name in $model_names; do
    c17_rows="${c17_rows}${c17_rows:+
}model/${name}: MISSING"
  done
  c17_write_evidence
  exit 2
fi

set +e
c17_list_names "$root/capsules/did-provider/Cargo.toml" "$did_list"
did_list_rc=$?
set -e
if [ "$did_list_rc" -ne 0 ]; then
  c17_reason="cargo --list failed for did-provider"
  c17_write_evidence
  exit 1
fi
did_names=$(c17_names "$did_tests")
set +e
c17_list_msg=$(c17_require_listed did "$did_list" $did_names)
did_req_rc=$?
set -e
if [ "$did_req_rc" -ne 0 ]; then
  c17_reason=$c17_list_msg
  c17_rows=""
  for name in $did_names; do
    c17_rows="${c17_rows}${c17_rows:+
}did/${name}: MISSING"
  done
  c17_write_evidence
  exit 2
fi

wallet_out="$probe_dir/wallet.cargo"
model_out="$probe_dir/model.cargo"
did_out="$probe_dir/did.cargo"

set +e
CARGO_TERM_COLOR=never cargo test --manifest-path "$root/capsules/wallet-provider/Cargo.toml" --test confine -- --exact --include-ignored $wallet_names > "$wallet_out" 2>&1
wallet_rc=$?
CARGO_TERM_COLOR=never cargo test --manifest-path "$root/capsules/model-provider/Cargo.toml" --test confine -- --exact --include-ignored $model_names > "$model_out" 2>&1
model_rc=$?
CARGO_TERM_COLOR=never cargo test --manifest-path "$root/capsules/did-provider/Cargo.toml" --test confine -- --exact --include-ignored $did_names > "$did_out" 2>&1
did_rc=$?
set -e

c17_rows=$(
  c17_score_cargo wallet "$wallet_out" $wallet_names
  c17_score_cargo model "$model_out" $model_names
  c17_score_cargo did "$did_out" $did_names
)

c17_counts=$(printf '%s\n' "$c17_rows" | python3 -I - <<'PY'
import sys
passed = failed = ignored = 0
for line in sys.stdin:
    if ": PASS" in line:
        passed += 1
    elif ": FAIL" in line or ": UNKNOWN" in line or ": DUPLICATE" in line:
        failed += 1
    elif ": IGNORED" in line:
        ignored += 1
print(f"{passed} {failed} {ignored}")
PY
)
c17_passed=$(printf '%s\n' "$c17_counts" | awk '{ print $1 }')
c17_failed=$(printf '%s\n' "$c17_counts" | awk '{ print $2 }')
c17_ignored=$(printf '%s\n' "$c17_counts" | awk '{ print $3 }')

if [ "$wallet_rc" -ne 0 ] || [ "$model_rc" -ne 0 ] || [ "$did_rc" -ne 0 ]; then
  c17_rc=1
  if [ -z "$c17_reason" ]; then
    c17_reason="cargo test exited wallet=${wallet_rc} model=${model_rc} did=${did_rc}"
  fi
fi

# Separate measured fact: does Apple's reader keep `#\; x (allow file*)` live?
probe_sb="$probe_dir/hash-semicolon-atom.sb"
probe_file="$probe_dir/write-target"
rm -f -- "$probe_file"
cat > "$probe_sb" <<'EOF'
(version 1)
(deny default)
(allow process-exec*)
(allow process-fork)
(allow signal)
(allow sysctl-read)
(allow file-read*)
#\; x (allow file*)
EOF

sandbox_bin=""
if [ -x /usr/bin/sandbox-exec ]; then
  sandbox_bin=/usr/bin/sandbox-exec
elif command -v sandbox-exec >/dev/null 2>&1; then
  sandbox_bin=$(command -v sandbox-exec)
fi
touch_bin=""
if [ -x /usr/bin/touch ]; then
  touch_bin=/usr/bin/touch
elif command -v touch >/dev/null 2>&1; then
  touch_bin=$(command -v touch)
fi

if [ -z "$sandbox_bin" ] || [ -z "$touch_bin" ]; then
  c17_probe="NOT MEASURED"
  c17_probe_detail="sandbox-exec or touch is missing"
  c17_rc=1
else
  set +e
  "$sandbox_bin" -f "$probe_sb" "$touch_bin" -- "$probe_file" > "$probe_dir/probe.out" 2> "$probe_dir/probe.err"
  probe_rc=$?
  set -e
  if [ -e "$probe_file" ]; then
    c17_probe="ALLOWED"
    c17_probe_detail="touch exited ${probe_rc}; write target exists"
  elif [ "$probe_rc" -eq 65 ]; then
    c17_probe="NOT MEASURED"
    c17_probe_detail="sandbox-exec exited 65 (profile error); write target absent"
    c17_rc=1
  else
    c17_probe="DENIED"
    c17_probe_detail="touch exited ${probe_rc}; write target absent"
  fi
fi

c17_write_evidence
exit "$c17_rc"
