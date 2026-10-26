#!/bin/sh
# Walk the five morning steps from RUNBOOK.md as a fresh operator.
# Isolated under lab/review-a14-289/. Does not touch other working trees.
set -eu

ROOT=/workspace/lab/review-a14-289
SCRATCH=$ROOT/scratch
MORNING=$ROOT/morning
TRANSCRIPT=$SCRATCH/dryrun.txt
DEMO_HOME=$SCRATCH/demo-home
mkdir -p "$SCRATCH" "$DEMO_HOME"
: > "$TRANSCRIPT"

log() {
  printf '%s\n' "$*" | tee -a "$TRANSCRIPT"
}

run_step() {
  name=$1
  shift
  log ""
  log "===== $name ====="
  log "command: $*"
  log "cwd: $PWD"
  log "start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  set +e
  start=$(date +%s)
  # shellcheck disable=SC2068
  eval "$@" >>"$TRANSCRIPT" 2>&1
  code=$?
  end=$(date +%s)
  set -e
  log "exit: $code"
  log "seconds: $((end - start))"
  return 0
}

ORIGIN=$(git -C /workspace remote get-url origin)

log "Review walk of PR 289 morning steps"
log "machine: $(uname -s) $(uname -m)"
log "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "origin: (redacted host github.com/Elacity/elastos-agent-host-spike)"

if [ -d "$MORNING/.git" ]; then
  log "reusing existing morning clone"
else
  log "cloning spike/agent-host into morning/ (fresh operator clone)"
  git clone --branch spike/agent-host --single-branch --reference /workspace "$ORIGIN" "$MORNING"
fi

cd "$MORNING"
log "morning clone HEAD before step 1: $(git rev-parse HEAD) $(git rev-parse --abbrev-ref HEAD)"
log "install.sh before step 1: $(test -f lab/demo-a14/install.sh && echo PRESENT || echo ABSENT)"

# Step 1 exactly as RUNBOOK.md, in this fresh clone only.
run_step "step 1 fetch" "git fetch origin cursor/demo-a14-installed-demo-83e1"
run_step "step 1 checkout" "git checkout cursor/demo-a14-installed-demo-83e1"
run_step "step 1 pull" "git pull --ff-only"
run_step "step 1 porcelain" "git status --porcelain=v1"
run_step "step 1 install.sh present" "test -f lab/demo-a14/install.sh && echo INSTALL_SH_PRESENT || echo INSTALL_SH_ABSENT"

log "HEAD after step 1: $(git rev-parse HEAD) $(git rev-parse --abbrev-ref HEAD)"

# Step 2
run_step "step 2 preflight" "sh lab/demo-a14/preflight.sh"

# Step 3 with isolated demo home so we do not write the default XDG path.
export DEMO_A14_HOME="$DEMO_HOME"
run_step "step 3 install --sign" "bash lab/demo-a14/install.sh --sign"

# Step 4
run_step "step 4 run" "bash lab/demo-a14/run.sh"

# Step 5 as written (Library path — will miss on Linux)
run_step "step 5 as written" '
run=$(ls -dt "$HOME/Library/Application Support/elastos-demo-a14/runs/"*/ | head -1)
printf "run_var=%s\n" "${run-}"
if test -n "$run" && test -d "$run" && open "$run"; then
  printf "open_invoked=yes path=%s\n" "$run"
else
  printf "open_invoked=no\n"
fi
'

# Step 5 pointed at the isolated demo home (the path run.sh actually used)
run_step "step 5 isolated demo home" '
run=$(ls -dt "$DEMO_A14_HOME/runs/"*/ | head -1)
printf "run_var=%s\n" "${run-}"
if test -n "$run" && test -d "$run"; then
  printf "guard_would_open=yes path=%s\n" "$run"
  printf "summary_exists=%s\n" "$(test -f "$run/summary.txt" && echo yes || echo no)"
  if test -f "$run/summary.txt"; then
    printf "--- summary.txt ---\n"
    cat "$run/summary.txt"
    printf "--- end summary ---\n"
  fi
else
  printf "guard_would_open=no\n"
fi
'

# Prove the unguarded form still fires open with an empty path.
run_step "step 5 unguarded empty path (old runbook)" '
run=$(ls -dt "$HOME/Library/Application Support/elastos-demo-a14/runs/"*/ | head -1)
printf "run_var=%s\n" "${run-}"
command -v open >/dev/null && open_cmd=open || open_cmd=true
# Record whether the unguarded command would run with an empty argument.
if [ -z "${run:-}" ]; then
  printf "unguarded_would_call_open_with_empty_path=yes\n"
else
  printf "unguarded_would_call_open_with_empty_path=no\n"
fi
'

log ""
log "===== leftover writes ====="
log "default XDG demo home exists? $(test -e "$HOME/.local/share/elastos-demo-a14" && echo YES || echo NO)"
log "Library demo home exists? $(test -e "$HOME/Library/Application Support/elastos-demo-a14" && echo YES || echo NO)"
log "isolated signing key exists? $(test -e "$DEMO_HOME/signing/receipt-signing.key" && echo YES || echo NO)"
log "isolated current/ exists? $(test -e "$DEMO_HOME/current" && echo YES || echo NO)"
if [ -d "$DEMO_HOME" ]; then
  find "$DEMO_HOME" -printf '%m %y %p\n' | sort | tee -a "$TRANSCRIPT"
fi
log "morning clone porcelain: $(git -C "$MORNING" status --porcelain=v1 | wc -l) lines"
log "DONE"
