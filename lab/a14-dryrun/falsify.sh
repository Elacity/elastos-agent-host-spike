#!/bin/sh
# Plant one missing prerequisite and require preflight.sh to name it.
# The plant is a PATH that can run the other tools and has no ssh-keygen.
# Nothing in the repository is written. The temporary PATH is removed on exit.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
preflight=$here/preflight.sh
repo=$(cd "$here/../.." && pwd -P)
line='missing: ssh-keygen is not on PATH (install.sh --sign uses it to sign the receipts)'

if [ ! -f "$preflight" ]; then
  printf 'falsifier: preflight.sh is not beside this script\n' >&2
  exit 2
fi

if ! command -v ssh-keygen >/dev/null 2>&1; then
  printf 'falsifier: ssh-keygen is already missing, so the plant is not a change\n' >&2
  exit 2
fi

index=$(git -C "$repo" rev-parse --git-path index)
before=$(GIT_OPTIONAL_LOCKS=0 git --no-optional-locks -C "$repo" status --porcelain=v1 --untracked-files=all)
mtime_before=$(python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_mtime_ns)' "$index")

run_preflight() {
  # stdout is the preflight text plus a final FALSIFY_EXIT marker.
  set +e
  /bin/sh "$1" "$repo"
  code=$?
  set -e
  printf 'FALSIFY_EXIT:%s\n' "$code"
}

split_out() {
  # $1 is the body file. $2 is the exit-code file.
  text=$(cat)
  printf '%s\n' "$text" | awk '/^FALSIFY_EXIT:/ { next } { print }' > "$1"
  printf '%s\n' "$text" | awk '/^FALSIFY_EXIT:/ { print substr($0, 14) }' > "$2"
}

plant=$(mktemp -d "${TMPDIR:-/tmp}/a14-preflight-plant.XXXXXX")
trap 'rm -rf "$plant"' EXIT
for cmd in uname git python3 cargo rustc rustup curl df awk sysctl xattr xcode-select bash; do
  path=$(command -v "$cmd" 2>/dev/null || true)
  if [ -n "$path" ]; then
    ln -s "$path" "$plant/$cmd"
  fi
done

control=$(mktemp)
planted=$(mktemp)
restored=$(mktemp)
trap 'rm -rf "$plant" "$control" "$planted" "$restored"' EXIT

start=$(python3 -c 'import time; print("%.3f" % time.time())')
run_preflight "$preflight" > "$control.raw"
end=$(python3 -c 'import time; print("%.3f" % time.time())')
seconds=$(python3 -c 'import sys; print("%.3f" % (float(sys.argv[2]) - float(sys.argv[1])))' "$start" "$end")
split_out "$control" "$control.code" < "$control.raw"
rm -f "$control.raw"

if grep -F "$line" "$control" >/dev/null 2>&1; then
  printf 'falsifier: the control run already reports a missing ssh-keygen\n' >&2
  exit 1
fi

if awk -v s="$seconds" 'BEGIN { exit (s+0 < 10) ? 0 : 1 }'; then
  printf 'falsifier: control preflight took %s seconds\n' "$seconds"
else
  printf 'falsifier: control preflight took %s seconds, which is over 10\n' "$seconds" >&2
  exit 1
fi

start=$(python3 -c 'import time; print("%.3f" % time.time())')
PATH=$plant run_preflight "$preflight" > "$planted.raw"
end=$(python3 -c 'import time; print("%.3f" % time.time())')
plant_seconds=$(python3 -c 'import sys; print("%.3f" % (float(sys.argv[2]) - float(sys.argv[1])))' "$start" "$end")
split_out "$planted" "$planted.code" < "$planted.raw"
rm -f "$planted.raw"
plant_code=$(cat "$planted.code")

if [ "$plant_code" != 1 ] || ! grep -F "$line" "$planted" >/dev/null 2>&1; then
  printf 'falsifier: the planted PATH did not produce the ssh-keygen line (exit %s)\n' "$plant_code" >&2
  printf '%s\n' '--- planted output ---' >&2
  cat "$planted" >&2
  exit 1
fi

PATH=$plant command -v ssh-keygen >/dev/null 2>&1 && hidden=no || hidden=yes
if [ "$hidden" != yes ]; then
  printf 'falsifier: the plant still finds ssh-keygen\n' >&2
  exit 1
fi

run_preflight "$preflight" > "$restored.raw"
split_out "$restored" "$restored.code" < "$restored.raw"
rm -f "$restored.raw"
if grep -F "$line" "$restored" >/dev/null 2>&1; then
  printf 'falsifier: after restoring PATH, ssh-keygen is still reported missing\n' >&2
  exit 1
fi

after=$(GIT_OPTIONAL_LOCKS=0 git --no-optional-locks -C "$repo" status --porcelain=v1 --untracked-files=all)
mtime_after=$(python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_mtime_ns)' "$index")
if [ "$before" != "$after" ]; then
  printf 'falsifier: git status changed while preflight ran\n' >&2
  exit 1
fi
if [ "$mtime_before" != "$mtime_after" ]; then
  printf 'falsifier: the git index mtime changed while preflight ran\n' >&2
  exit 1
fi

printf 'falsifier: CAUGHT\n'
printf 'plant: PATH with no ssh-keygen (hidden=%s)\n' "$hidden"
printf 'planted exit: %s in %s seconds\n' "$plant_code" "$plant_seconds"
printf 'caught line: %s\n' "$line"
printf 'restored PATH does not report that line\n'
printf 'git status and the index mtime stayed the same\n'
