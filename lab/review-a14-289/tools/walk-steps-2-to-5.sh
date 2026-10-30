#!/bin/sh
# Continue the morning walk on the full-refspec clone that step 1 actually left
# on cursor/demo-a14-installed-demo-83e1 at 39b4b47e.
set -eu

ROOT=/workspace/lab/review-a14-289
CLONE=$ROOT/scratch/fetch-experiment/full
TRANSCRIPT=$ROOT/scratch/dryrun-full-clone.txt
DEMO_HOME=$ROOT/scratch/demo-home-full
mkdir -p "$DEMO_HOME"
: > "$TRANSCRIPT"

log() { printf '%s\n' "$*" | tee -a "$TRANSCRIPT"; }

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
  eval "$@" >>"$TRANSCRIPT" 2>&1
  code=$?
  end=$(date +%s)
  set -e
  log "exit: $code"
  log "seconds: $((end - start))"
}

cd "$CLONE"
log "Full-clone morning walk after successful step 1"
log "HEAD: $(git rev-parse HEAD) $(git rev-parse --abbrev-ref HEAD)"
log "porcelain bytes: $(git status --porcelain=v1 | wc -c)"
log "install.sh: $(test -f lab/demo-a14/install.sh && echo PRESENT || echo ABSENT)"

run_step "step 2 preflight" "sh lab/demo-a14/preflight.sh"

export DEMO_A14_HOME="$DEMO_HOME"
# Record whether cargo fetch starts: watch the isolated home and default XDG.
before_xdg=$(ls -la "$HOME/.local/share/elastos-demo-a14" 2>/dev/null || echo ABSENT)
run_step "step 3 install --sign" "bash lab/demo-a14/install.sh --sign"

run_step "step 4 run" "bash lab/demo-a14/run.sh"

run_step "step 5 as written" '
run=$(ls -dt "$HOME/Library/Application Support/elastos-demo-a14/runs/"*/ | head -1)
printf "run_var=%s\n" "${run-}"
if test -n "$run" && test -d "$run" && open "$run"; then
  printf "open_invoked=yes path=%s\n" "$run"
else
  printf "open_invoked=no\n"
fi
'

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

log ""
log "===== leftover writes ====="
log "default XDG demo home exists? $(test -e "$HOME/.local/share/elastos-demo-a14" && echo YES || echo NO)"
log "Library demo home exists? $(test -e "$HOME/Library/Application Support/elastos-demo-a14" && echo YES || echo NO)"
log "isolated signing key exists? $(test -e "$DEMO_HOME/signing/receipt-signing.key" && echo YES || echo NO)"
log "isolated current/ exists? $(test -e "$DEMO_HOME/current" && echo YES || echo NO)"
if [ -d "$DEMO_HOME" ]; then
  find "$DEMO_HOME" -printf '%m %y %p\n' | sort | tee -a "$TRANSCRIPT"
fi
log "clone porcelain lines: $(git status --porcelain=v1 | wc -l)"
log "DONE"
