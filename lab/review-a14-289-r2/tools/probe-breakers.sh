#!/bin/sh
# New morning-breaker probes. Writes evidence/*.txt. Does not edit PR 289.
set -eu

ROOT=/workspace/lab/review-a14-289-r2
EV=$ROOT/evidence
SC=$ROOT/scratch/probes
rm -rf "$SC"
mkdir -p "$EV" "$SC"

log() { printf '%s\n' "$*"; }

# --- 1. zsh: set -euo pipefail and the dest line with unset A14_* ---
{
  printf 'zsh version: '; zsh --version
  printf '\n--- set -euo pipefail with unset A14_CLONE / A14_REMOTE ---\n'
  zsh -c '
set -euo pipefail
branch=cursor/demo-a14-installed-demo-83e1
url=${A14_REMOTE:-https://github.com/Elacity/elastos-agent-host-spike.git}
dest=${A14_CLONE:-"$HOME/a14-run-$(date +%Y%m%d-%H%M%S)"}
printf "url=%s\n" "$url"
printf "dest=%s\n" "$dest"
printf "branch=%s\n" "$branch"
printf "zsh dest-line: OK\n"
'
  printf '\n--- zsh last-line && chain when this-run is missing (set -e) ---\n'
  zsh -c '
set -euo pipefail
demo_home="$HOME/Library/Application Support/elastos-demo-a14-missing"
run=$(sed -n "1p" "$demo_home/this-run" 2>/dev/null || true)
test -n "$run" && test -d "$run" && test -f "$run/summary.txt" && open "$run/summary.txt"
printf "zsh reached after failed step-5 chain\n"
' || printf 'zsh step-5 chain exited %s\n' "$?"

  printf '\n--- bash same dest-line ---\n'
  bash -c '
set -euo pipefail
url=${A14_REMOTE:-https://github.com/Elacity/elastos-agent-host-spike.git}
dest=${A14_CLONE:-"$HOME/a14-run-$(date +%Y%m%d-%H%M%S)"}
printf "url=%s\n" "$url"
printf "dest=%s\n" "$dest"
printf "bash dest-line: OK\n"
'
} > "$EV/zsh-set-u.txt" 2>&1 || true

# --- 2. date format (GNU here; note BSD on the Mac) ---
{
  printf 'date +%%Y%%m%%d-%%H%%M%%S -> %s\n' "$(date +%Y%m%d-%H%M%S)"
  printf 'GNU date --version:\n'
  date --version 2>&1 | head -1 || true
} > "$EV/date-format.txt"

# --- 3. A14_CLONE reuse ---
{
  set +e
  dest=$SC/reuse-dest
  mkdir -p "$dest"
  bash -c '
set -euo pipefail
dest="$1"
if [ -e "$dest" ]; then
  printf "REFUSED: %s already exists. This runbook never reuses a folder.\n" "$dest" >&2
  exit 3
fi
printf UNREACHABLE\n
' _ "$dest"
  printf 'reuse-existing exit %s\n' "$?"
  dest2=$SC/reuse-missing
  bash -c '
set -euo pipefail
dest="$1"
if [ -e "$dest" ]; then
  printf "REFUSED: %s already exists. This runbook never reuses a folder.\n" "$dest" >&2
  exit 3
fi
printf "missing dest accepted (would clone here)\n"
' _ "$dest2"
  printf 'reuse-missing exit %s\n' "$?"
} > "$EV/a14-clone-reuse.txt" 2>&1

# --- 4. this-run stale pointer ---
{
  home=$SC/stale-home
  mkdir -p "$home/Library/Application Support/elastos-demo-a14/runs/old" \
           "$home/Library/Application Support/elastos-demo-a14/runs/new"
  printf 'OLD SUMMARY\n' > "$home/Library/Application Support/elastos-demo-a14/runs/old/summary.txt"
  printf 'NEW SUMMARY\nA14: NOT RUN.\n' > "$home/Library/Application Support/elastos-demo-a14/runs/new/summary.txt"
  printf '%s\n' "$home/Library/Application Support/elastos-demo-a14/runs/old" \
    > "$home/Library/Application Support/elastos-demo-a14/this-run"
  demo_home="$home/Library/Application Support/elastos-demo-a14"
  run=$(sed -n '1p' "$demo_home/this-run" 2>/dev/null || true)
  printf 'this-run points at: %s\n' "$run"
  printf 'summary first line: %s\n' "$(sed -n '1p' "$run/summary.txt")"
  printf 'step 5 would open that path if open existed\n'
} > "$EV/this-run-stale.txt"

# --- 5. set -e stops the pasted block at preflight FAIL (no this-run) ---
{
  printf 'A failing preflight is exit 1. With set -e the pasted block never reaches install.sh.\n'
  printf 'install.sh is the writer of this-run/summary.txt on a machine-not-ready refusal.\n'
  HOME=$SC/e-home
  mkdir -p "$HOME"
  bash -c '
set -euo pipefail
printf "before preflight\n"
sh -c "printf \"preflight: FAIL\n\"; exit 1"
printf "after preflight — should not print\n"
printf "would run install.sh here\n"
' || printf 'block stopped with exit %s\n' "$?"
} > "$EV/set-e-stops-before-install.txt" 2>&1

# --- 6. open on a .txt ---
{
  command -v open >/dev/null 2>&1 && printf 'open: present\n' || printf 'open: ABSENT on this Linux VM\n'
  command -v xdg-open >/dev/null 2>&1 && printf 'xdg-open: present\n' || printf 'xdg-open: absent\n'
  printf 'macOS open on a .txt opens the default editor. The block calls open, not open -t or open -e.\n'
} > "$EV/open-txt.txt"

# --- 7. HTTPS clone without this VM token rewrite ---
{
  printf 'Default runbook URL is https://github.com/Elacity/elastos-agent-host-spike.git\n'
  printf 'Repo is private. This VM rewrites github.com via insteadOf (token). Sash Mac may not.\n'
  tmpcfg=$SC/gitconfig-empty
  : > "$tmpcfg"
  GIT_CONFIG_GLOBAL=$tmpcfg
  GIT_CONFIG_SYSTEM=/dev/null
  export GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM
  unset GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 || true
  GIT_TERMINAL_PROMPT=0
  export GIT_TERMINAL_PROMPT
  dest=$SC/unauth-clone
  set +e
  git -c 'url.https://github.com/.insteadOf=' clone --branch cursor/demo-a14-installed-demo-83e1 \
    https://github.com/Elacity/elastos-agent-host-spike.git "$dest" > "$SC/unauth-out.txt" 2>&1
  code=$?
  set -e
  printf 'unauth clone exit: %s\n' "$code"
  sed 's/x-access-token:[^@]*@/x-access-token:[REDACTED]@/g' "$SC/unauth-out.txt"
  printf 'dest exists: %s\n' "$( [ -e "$dest" ] && echo yes || echo no )"
} > "$EV/clone-unauth.txt" 2>&1 || true

# --- 8. continue past preflight (what the author dry-ran) using the fresh clone if present ---
CLONE=/workspace/lab/review-a14-289-r2/scratch/morning/clone
if [ ! -d "$CLONE" ]; then
  printf 'morning clone not present yet; skip continue-past-preflight\n' > "$EV/continue-past-preflight.txt"
else
  DEMO=$SC/demo-home
  mkdir -p "$DEMO"
  {
    printf 'cwd=%s\n' "$CLONE"
    printf 'HEAD=%s\n' "$(git -C "$CLONE" rev-parse HEAD)"
    printf '--- install.sh --sign with isolated DEMO_A14_HOME ---\n'
    set +e
    DEMO_A14_HOME=$DEMO bash "$CLONE/lab/demo-a14/install.sh" --sign
    icode=$?
    set -e
    printf 'install exit: %s\n' "$icode"
    printf 'signing key: %s\n' "$( [ -e "$DEMO/signing/receipt-signing.key" ] && echo present || echo absent )"
    printf 'current/: %s\n' "$( [ -d "$DEMO/current" ] && echo present || echo absent )"
    printf 'this-run: %s\n' "$( [ -f "$DEMO/this-run" ] && echo present || echo absent )"
    if [ -f "$DEMO/this-run" ]; then
      printf 'this-run value: %s\n' "$(sed -n '1p' "$DEMO/this-run")"
      run=$(sed -n '1p' "$DEMO/this-run")
      printf 'summary exists: %s\n' "$( [ -f "$run/summary.txt" ] && echo yes || echo no )"
      if [ -f "$run/summary.txt" ]; then
        printf '--- summary.txt ---\n'
        cat "$run/summary.txt"
      fi
    fi
    printf '--- run.sh ---\n'
    set +e
    DEMO_A14_HOME=$DEMO bash "$CLONE/lab/demo-a14/run.sh"
    rcode=$?
    set -e
    printf 'run exit: %s\n' "$rcode"
    if [ -f "$DEMO/this-run" ]; then
      run=$(sed -n '1p' "$DEMO/this-run")
      printf 'this-run after run.sh: %s\n' "$run"
      printf 'summary exists: %s\n' "$( [ -f "$run/summary.txt" ] && echo yes || echo no )"
    fi
    printf '--- step 5 as written (Library path under isolated HOME) ---\n'
    HOME=$SC/e-home
    demo_home="$HOME/Library/Application Support/elastos-demo-a14"
    run=$(sed -n '1p' "$demo_home/this-run" 2>/dev/null || true)
    printf 'Library this-run=%s\n' "${run:-EMPTY}"
    if [ -n "${run:-}" ] && [ -d "$run" ] && [ -f "$run/summary.txt" ]; then
      printf 'would open %s\n' "$run/summary.txt"
    else
      printf 'open not invoked (Library this-run missing or stale)\n'
    fi
  } > "$EV/continue-past-preflight.txt" 2>&1 || true
fi

printf 'probes written under %s\n' "$EV"
