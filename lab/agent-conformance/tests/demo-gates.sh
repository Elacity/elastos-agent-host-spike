#!/bin/bash
# Checks when demo.sh stops and what it exits with, without running the suite.
#
#   demo-gates.sh <report-binary> <new-folder>
#
# Under <new-folder> it lays out a stand-in checkout holding a copy of demo.sh,
# the given report tool and a stub run.sh, beside a stand-in installed Runtime.
# The stub records that it ran, names a prepared receipt and exits as told, so
# each case decides what the suite "did". Every case runs with a throwaway HOME
# and names both install paths, so no real installation is read or written.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    printf 'usage: demo-gates.sh <report-binary> <new-folder>\n' >&2
    exit 2
fi
report=$1
lane=$(cd -- "$(dirname -- "$0")/.." && pwd -P)

mkdir "$2"
root=$(cd -- "$2" && pwd -P)
checkout="$root/checkout"
stand_in="$checkout/lab/agent-conformance"
installed="$root/installed"
mkdir -p "$stand_in/target/host/debug" "$root/home" "$root/tmp" "$installed/bin" "$installed/data"
# A work tree that ignores everything is clean without a commit.
env -i PATH="$PATH" HOME="$root/home" git init -q "$checkout"
printf '*\n' >"$checkout/.gitignore"
cp "$lane/demo.sh" "$stand_in/demo.sh"
cp "$report" "$stand_in/target/host/debug/report"
cat >"$stand_in/run.sh" <<'STUB'
#!/bin/bash
: >"$STUB_RAN"
if [ -n "$STUB_RECEIPT" ]; then
    printf 'versions receipt: %s\n' "$STUB_RECEIPT"
fi
exit "$STUB_EXIT"
STUB
printf '#!/bin/sh\nexit 0\n' >"$installed/bin/elastos"
chmod 755 "$stand_in/demo.sh" "$stand_in/run.sh" "$installed/bin/elastos"
printf '[]\n' >"$root/reviews.json"
before=$(cd -- "$installed" && find . | sort)

# receipt <name> <table> [<hashed-table>]: a receipt in its own folder whose
# recorded hash is that of <hashed-table>, the table itself unless given.
receipt() {
    local table=$2 hashed=${3:-$2} hash
    hash=$(printf '%s' "$hashed" | shasum -a 256 | cut -d ' ' -f 1)
    mkdir "$root/receipt-$1"
    printf '{"report":{"table":"%s","sha256":"%s"}}\n' "${table//$'\n'/\\n}" "$hash" \
        >"$root/receipt-$1/VERSIONS.json"
}
four=$'versions_receipt (A14) | PASS\nreview_binding (A14) | PASS\nstaged_bundle (A14) | PASS\ninstalled_runtime (A14) | PASS\n'
five="$four"$'installed_runtime_ran (A14) | PASS\n'
receipt pass "$five"
receipt missing "$four"
receipt edited "$five" "${five/review_binding (A14) | PASS/review_binding (A14) | FAIL}"

# demo <case> <receipt-name or ""> <suite-exit>: one run of the stand-in
# demo.sh. `receipts` and `temporary` name where it may write; unset, they are
# folders of the case's own. Leaves `status` and the files out-<case>,
# err-<case> and, when the stub ran, ran-<case>.
receipts=""
temporary=""
demo() {
    local name=$1 named=""
    if [ -n "$2" ]; then
        named="$root/receipt-$2/VERSIONS.json"
    fi
    status=0
    env -i PATH="$PATH" HOME="$root/home" TMPDIR="${temporary:-$root/tmp}" \
        AGENT_CONFORMANCE_INSTALLED_BINARY="$installed/bin/elastos" \
        AGENT_CONFORMANCE_INSTALLED_DATA="$installed/data" \
        ELASTOS_DEMO_RECEIPTS="${receipts:-$root/kept-$name}" \
        STUB_RAN="$root/ran-$name" STUB_RECEIPT="$named" STUB_EXIT="$3" \
        "$stand_in/demo.sh" "$root/reviews.json" >"$root/out-$name" 2>"$root/err-$name" || status=$?
    receipts=""
    temporary=""
}
fail() {
    printf 'demo-gates: FAIL: %s: %s\n' "$1" "$2" >&2
    exit 1
}
# failed <case> <text>: the run failed, said <text>, and did not print PASS.
failed() {
    if [ "$status" -eq 0 ]; then
        fail "$1" "exit 0"
    fi
    if grep -q 'demo: PASS' "$root/out-$1"; then
        fail "$1" "printed the PASS line"
    fi
    if ! grep -qF -- "$2" "$root/out-$1" "$root/err-$1"; then
        fail "$1" "did not say: $2"
    fi
}
# refused <case> <text>: it failed as above before the suite was started.
refused() {
    failed "$1" "$2"
    if [ -e "$root/ran-$1" ]; then
        fail "$1" "the suite ran"
    fi
}

# The one way to exit 0: the suite passed and all five rows read PASS.
demo pass pass 0
if [ "$status" -ne 0 ] || ! grep -qx 'demo: PASS; every A14 row passes' "$root/out-pass"; then
    fail pass "exit $status without the PASS line"
fi
if [ ! -e "$root/ran-pass" ] || [ -z "$(find "$root/kept-pass" -name VERSIONS.json)" ]; then
    fail pass "the suite did not run or no receipt was kept"
fi

# A suite that fails, whatever the receipt says.
demo suite-fails pass 1
failed suite-fails 'demo: FAIL; the suite did not pass (run.sh exit 1)'

# A receipt with one of the five rows missing.
demo row-missing missing 0
failed row-missing 'installed_runtime_ran (A14) | FAIL | row missing from the receipt'
failed row-missing 'demo: FAIL; not every A14 row passes'

# A receipt whose table no longer matches the hash recorded for it.
demo table-edited edited 0
failed table-edited 'A14 rows: receipt table does not match its recorded hash'
failed table-edited 'demo: FAIL; not every A14 row passes'

# A suite that names no receipt.
demo no-receipt "" 0
failed no-receipt 'demo: FAIL; run.sh wrote no receipt'

# Nothing is written under the install paths: each of these stops first.
receipts="$installed/data/receipts"
demo receipts-in-data pass 0
refused receipts-in-data "refused: the receipts folder is inside the installed data folder"

receipts="$installed/bin"
demo receipts-in-binary-folder pass 0
refused receipts-in-binary-folder "refused: the receipts folder is inside the folder holding the installed binary"

ln -s "$installed/data" "$root/link"
receipts="$root/link/new/deeper"
demo receipts-through-a-link pass 0
refused receipts-through-a-link "refused: the receipts folder is inside the installed data folder"

receipts="$root/absent/../installed/data"
demo receipts-through-dots pass 0
refused receipts-through-dots 'refused: cannot tell where the receipts folder would be'

temporary="$installed/data"
demo temporary-in-data pass 0
refused temporary-in-data "refused: the temporary folder is inside the installed data folder"

if [ "$before" != "$(cd -- "$installed" && find . | sort)" ]; then
    fail installed "the stand-in installed Runtime changed"
fi
printf 'demo-gates: every case holds\n'
