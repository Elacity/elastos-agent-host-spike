#!/bin/sh
# Run the exact morning block from RUNBOOK.md at e6651b29 on a fresh Linux path.
# Isolates HOME so Library/XDG writes stay under this review folder.
set -eu

ROOT=/workspace/lab/review-a14-289-r2
EVIDENCE=$ROOT/evidence
SCRATCH=$ROOT/scratch/morning
BLOCK=$ROOT/tools/morning-block.sh
rm -rf "$SCRATCH"
mkdir -p "$EVIDENCE" "$SCRATCH/home"

# Confirm the extracted block matches RUNBOOK.md at the reviewed head.
python3 - <<'PY'
from pathlib import Path
runbook = Path("/tmp/a14-289-head/lab/demo-a14/RUNBOOK.md").read_text(encoding="utf-8")
start = runbook.index("```bash\n") + len("```bash\n")
end = runbook.index("```", start)
block = runbook[start:end]
extracted = Path("/workspace/lab/review-a14-289-r2/tools/morning-block.sh").read_text(encoding="utf-8")
if block != extracted:
    raise SystemExit("extracted morning-block.sh does not match RUNBOOK.md fence")
print("RUNBOOK fence matches tools/morning-block.sh")
PY

export HOME=$SCRATCH/home
export A14_CLONE=$SCRATCH/clone
unset A14_REMOTE || true
unset DEMO_A14_HOME || true
unset CARGO_TARGET_DIR || true

{
  printf 'HEAD claimed e6651b29; worktree %s\n' "$(git -C /tmp/a14-289-head rev-parse HEAD)"
  printf 'HOME=%s\nA14_CLONE=%s\nA14_REMOTE unset\n' "$HOME" "$A14_CLONE"
  printf '%s\n' '--- begin exact morning block under bash ---'
} > "$EVIDENCE/morning-block.txt"

set +e
bash "$BLOCK" > "$EVIDENCE/morning-block-stdout.txt" 2> "$EVIDENCE/morning-block-stderr.txt"
code=$?
set -e

{
  printf 'bash block exit: %s\n' "$code"
  printf 'clone dest exists: %s\n' "$( [ -d "$A14_CLONE" ] && echo yes || echo no )"
  if [ -d "$A14_CLONE" ]; then
    printf 'clone HEAD: %s\n' "$(git -C "$A14_CLONE" rev-parse HEAD)"
    printf 'clone branch: %s\n' "$(git -C "$A14_CLONE" rev-parse --abbrev-ref HEAD)"
    printf 'clone porcelain empty: %s\n' "$( [ -z "$(git -C "$A14_CLONE" status --porcelain=v1)" ] && echo yes || echo no )"
    printf 'install.sh present: %s\n' "$( [ -f "$A14_CLONE/lab/demo-a14/install.sh" ] && echo yes || echo no )"
  fi
  printf 'Library this-run: %s\n' "$( [ -f "$HOME/Library/Application Support/elastos-demo-a14/this-run" ] && echo present || echo absent )"
  printf 'XDG this-run: %s\n' "$( [ -f "$HOME/.local/share/elastos-demo-a14/this-run" ] && echo present || echo absent )"
  printf 'any summary.txt under HOME: %s\n' "$(find "$HOME" -name summary.txt 2>/dev/null | wc -l | tr -d ' ')"
} >> "$EVIDENCE/morning-block.txt"

printf 'morning block bash exit %s\n' "$code"
exit 0
