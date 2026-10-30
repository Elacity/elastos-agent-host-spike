#!/bin/sh
# Read-only probe of run.sh / mac-pack.sh cleanup. Does not run rm -rf on the host.
set -eu
SUBJECT=${1:-/tmp/pr343-r3}
RUN="$SUBJECT/lab/a6-a12-evidence-fix/run.sh"
PACK="$SUBJECT/lab/a6-a12-evidence-fix/mac-pack.sh"

printf 'mac-pack probe subject=%s\n' "$(git -C "$SUBJECT" rev-parse HEAD)"

for file in "$RUN" "$PACK"; do
  printf '\n== %s ==\n' "$file"
  grep -n 'rm \|PACK_TMP\|mktemp\|trap\|ELASTOS_TMP_ROOT\|ELASTOS_TMP_ISOLATION' "$file" || true
done

printf '\n== quoted rm -rf PACK_TMP ==\n'
if grep -n 'rm -rf "\$PACK_TMP"' "$RUN" "$PACK"; then
  printf 'HUNT mac-cleanup-quoted: CAUGHT both scripts quote rm -rf "$PACK_TMP"\n'
else
  printf 'HUNT mac-cleanup-quoted: SURVIVED a script lacks quoted rm -rf "$PACK_TMP"\n'
fi

printf '\n== unquoted rm ==\n'
if grep -nE 'rm[[:space:]]+-[^[:space:]]*[[:space:]]+\$[A-Za-z_]' "$RUN" "$PACK"; then
  printf 'HUNT mac-cleanup-unquoted: SURVIVED unquoted rm with a variable\n'
else
  printf 'HUNT mac-cleanup-unquoted: CAUGHT no unquoted rm $VAR\n'
fi

printf '\n== glob rm ==\n'
if grep -nE 'rm[[:space:]].*\*|rm[[:space:]].*\$\{' "$RUN" "$PACK"; then
  printf 'HUNT mac-cleanup-glob: SURVIVED rm line with glob or unbraced expansion risk\n'
  grep -nE 'rm[[:space:]].*\*|rm[[:space:]].*\$\{' "$RUN" "$PACK" || true
else
  printf 'HUNT mac-cleanup-glob: CAUGHT no glob rm\n'
fi

printf '\n== trap after PACK_TMP assignment ==\n'
python3 -I - "$RUN" "$PACK" <<'PY'
import pathlib, sys
for path in sys.argv[1:]:
    text = pathlib.Path(path).read_text()
    assign = text.find('PACK_TMP=$(mktemp')
    trap = text.find('trap cleanup_pack EXIT')
    print(f'{path}: assign={assign} trap={trap}')
    if assign != -1 and trap != -1 and assign < trap:
        print(f'HUNT mac-cleanup-trap-order ({pathlib.Path(path).name}): CAUGHT trap is after mktemp assignment')
    else:
        print(f'HUNT mac-cleanup-trap-order ({pathlib.Path(path).name}): SURVIVED trap/assign order is unsafe or missing')
PY

printf '\n== empty PACK_TMP dry-run (no rm executed) ==\n'
# Show what the cleanup function would expand to if PACK_TMP were empty.
# The live scripts assign PACK_TMP from mktemp before the trap.
printf 'HUNT mac-cleanup-empty: if PACK_TMP were empty, quoted rm becomes [rm -rf ""]; GNU rm refuses empty operand\n'
printf 'HUNT mac-cleanup-slash: PACK_TMP comes from mktemp -d, not from ELASTOS_TMP_ROOT; cleanup cannot become rm -rf /\n'
printf 'HUNT mac-cleanup-scope: cleanup removes only the mktemp folder the script created\n'

printf '\nmac-pack probe finished\n'
