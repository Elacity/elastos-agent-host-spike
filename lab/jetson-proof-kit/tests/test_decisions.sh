#!/bin/bash
# Simulated-kernel decisions and the ABI-report check.
# Jetson rows stay NOT RUN.
set -eu

kit=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=../lib.sh
. "$kit/lib.sh"

pass=0
fail=0

assert_eq() {
    local name="$1"
    local got="$2"
    local want="$3"
    if [ "$got" = "$want" ]; then
        printf 'PASS %s\n' "$name"
        pass=$((pass + 1))
    else
        printf 'FAIL %s: got %s want %s\n' "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

assert_contains() {
    local name="$1"
    local haystack="$2"
    local needle="$3"
    case "$haystack" in
        *"$needle"*)
            printf 'PASS %s\n' "$name"
            pass=$((pass + 1))
            ;;
        *)
            printf 'FAIL %s: missing %s in %s\n' "$name" "$needle" "$haystack"
            fail=$((fail + 1))
            ;;
    esac
}

cell() {
    local table="$1"
    local provider="$2"
    local floor="$3"
    printf '%s\n' "$table" | awk -F '\t' -v p="$provider" -v f="$floor" '
        $1 == p && $2 == f { print $3; exit }
    '
}

reason() {
    local table="$1"
    local provider="$2"
    local floor="$3"
    printf '%s\n' "$table" | awk -F '\t' -v p="$provider" -v f="$floor" '
        $1 == p && $2 == f { print $4; exit }
    '
}

decide() {
    python3 -I "$kit/decide.py" "$1"
}

# Each fixture is one kernel's answers. All three providers share a floor.
table=$(decide "$kit/fixtures/abi-1-jetson.facts")
for provider in did wallet model; do
    assert_eq "abi1_${provider}_abi5" "$(cell "$table" "$provider" abi5)" REFUSE
    assert_contains "abi1_${provider}_abi5_reason" "$(reason "$table" "$provider" abi5)" "Landlock ABI 1 is below the required 5"
    assert_eq "abi1_${provider}_per_right" "$(cell "$table" "$provider" per_right)" REFUSE
    assert_contains "abi1_${provider}_per_right_reason" "$(reason "$table" "$provider" per_right)" "missing TRUNCATE, IOCTL_DEV"
done

table=$(decide "$kit/fixtures/abi-absent.facts")
assert_eq "absent_did_abi5" "$(cell "$table" did abi5)" REFUSE
assert_contains "absent_did_abi5_reason" "$(reason "$table" did abi5)" "Landlock is not available (absent)"
assert_eq "absent_did_per_right" "$(cell "$table" did per_right)" REFUSE
assert_contains "absent_did_per_right_reason" "$(reason "$table" did per_right)" "missing TRUNCATE, IOCTL_DEV"

table=$(decide "$kit/fixtures/abi-3.facts")
assert_eq "abi3_did_abi5" "$(cell "$table" did abi5)" REFUSE
assert_contains "abi3_did_abi5_reason" "$(reason "$table" did abi5)" "Landlock ABI 3 is below the required 5"
assert_eq "abi3_did_per_right" "$(cell "$table" did per_right)" REFUSE
assert_eq "abi3_did_per_right_reason" "$(reason "$table" did per_right)" "missing IOCTL_DEV"

table=$(decide "$kit/fixtures/abi-5.facts")
for provider in did wallet model; do
    assert_eq "abi5_${provider}_abi5" "$(cell "$table" "$provider" abi5)" LAUNCH
    assert_eq "abi5_${provider}_per_right" "$(cell "$table" "$provider" per_right)" LAUNCH
done

table=$(decide "$kit/fixtures/abi-6.facts")
assert_eq "abi6_wallet_abi5" "$(cell "$table" wallet abi5)" LAUNCH
assert_eq "abi6_wallet_per_right" "$(cell "$table" wallet per_right)" LAUNCH

table=$(decide "$kit/fixtures/abi-5-userns-off.facts")
assert_eq "userns_off_model_abi5" "$(cell "$table" model abi5)" REFUSE
assert_contains "userns_off_model_abi5_reason" "$(reason "$table" model abi5)" "unprivileged user namespace unavailable"
assert_eq "userns_off_model_per_right" "$(cell "$table" model per_right)" REFUSE

# A lying ABI number does not change the per-right column.
table=$(decide "$kit/fixtures/abi-lie-5-rights-1.facts")
assert_eq "lie_did_abi5" "$(cell "$table" did abi5)" LAUNCH
assert_eq "lie_did_per_right" "$(cell "$table" did per_right)" REFUSE
assert_contains "lie_did_per_right_reason" "$(reason "$table" did per_right)" "missing TRUNCATE, IOCTL_DEV"

# JPK_FACTS reprints the fixture ABI unchanged.
reprinted=$(JPK_FACTS="$kit/fixtures/abi-1-jetson.facts" python3 -I "$kit/probe_host.py")
reprinted_abi=$(printf '%s\n' "$reprinted" | awk '/^landlock_abi / { print $2; exit }')
assert_eq "facts_reprint_keeps_abi1" "$reprinted_abi" 1

# Live ABI probes must agree. This is the check F-JPK-ABI plants against.
live_ll=$(python3 -I "$kit/probe_landlock.py" | awk '/^landlock_abi / { print $2; exit }')
live_host=$(python3 -I "$kit/probe_host.py" | awk '/^landlock_abi / { print $2; exit }')
assert_eq "live_abi_probes_agree" "$live_host" "$live_ll"

# Record path: fixture ABI 1 is stored as 1, and both floors refuse.
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
export HOME="$scratch/home"
mkdir -p -- "$HOME/$JPK_ROOT_NAME"
root=$(jpk_allowed_root)
cp -- "$kit/evidence.txt" "$root/evidence.txt"
export JPK_EVIDENCE="$root/evidence.txt"
export JPK_FACTS="$kit/fixtures/abi-1-jetson.facts"
export JPK_MEMINFO="$scratch/meminfo-high"
printf 'MemTotal:        7773952 kB\nMemAvailable:    2000000 kB\n' >"$JPK_MEMINFO"
JPK_SOURCE_ONLY=1
# shellcheck source=../run-on-jetson.sh
. "$kit/run-on-jetson.sh"
jpk_record_host >/dev/null
recorded_abi=$(awk -F '\t' '$1 == "host.landlock_abi" { print $3; exit }' "$JPK_EVIDENCE")
assert_eq "recorded_abi_is_fixture_1" "$recorded_abi" 1
did_abi5=$(awk -F '\t' '$1 == "decision.did.abi5" { print $2; exit }' "$JPK_EVIDENCE")
did_per=$(awk -F '\t' '$1 == "decision.did.per_right" { print $2; exit }' "$JPK_EVIDENCE")
assert_eq "recorded_did_abi5_refused" "$did_abi5" REFUSED
assert_eq "recorded_did_per_right_refused" "$did_per" REFUSED

printf 'summary %s passed %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
