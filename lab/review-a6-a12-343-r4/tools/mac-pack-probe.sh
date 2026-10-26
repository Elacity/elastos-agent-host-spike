#!/bin/sh
# Read-only probe of run.sh / mac-pack.sh cleanup. Does not run rm -rf on the host.
set -eu
SUBJECT=${1:-/tmp/pr343-r4}
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

printf '\n== cargo test command quoting ==\n'
python3 -I - "$RUN" "$PACK" <<'PY'
import pathlib, sys
for path in sys.argv[1:]:
    text = pathlib.Path(path).read_text()
    name = pathlib.Path(path).name
    if 'cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects' in text \
       and 'two_instances_overlap_with_separate_grants' in text \
       and 'instance_grant_does_not_authorise_sibling' in text \
       and 'cleanup_census_refuses_each_leftover' in text:
        print(f'HUNT mac-commands-present ({name}): CAUGHT three owner test names are printed or run')
    else:
        print(f'HUNT mac-commands-present ({name}): SURVIVED missing owner test names')
    if 'ELASTOS_TMP_ROOT="$PACK_TMP"' in text and 'ELASTOS_TMP_ISOLATION="$PACK_TMP"' in text:
        print(f'HUNT mac-commands-isolated ({name}): CAUGHT both env vars quoted to PACK_TMP')
    else:
        print(f'HUNT mac-commands-isolated ({name}): SURVIVED isolation env is not quoted to PACK_TMP')
PY

printf '\n== empty PACK_TMP dry-run (no rm executed) ==\n'
printf 'HUNT mac-cleanup-empty: if PACK_TMP were empty, quoted rm becomes [rm -rf ""]; GNU rm refuses empty operand\n'
printf 'HUNT mac-cleanup-slash: PACK_TMP comes from mktemp -d, not from ELASTOS_TMP_ROOT; cleanup cannot become rm -rf /\n'
printf 'HUNT mac-cleanup-scope: cleanup removes only the mktemp folder the script created\n'

printf '\nmac-pack probe finished\n'
