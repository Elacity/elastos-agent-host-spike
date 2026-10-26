set -euo pipefail

# 1. Brand-new folder. Refuse if that path already exists. Stop if install.sh is missing.
branch=cursor/demo-a14-installed-demo-83e1
url=${A14_REMOTE:-https://github.com/Elacity/elastos-agent-host-spike.git}
dest=${A14_CLONE:-"$HOME/a14-run-$(date +%Y%m%d-%H%M%S)"}
if [ -e "$dest" ]; then
  printf 'REFUSED: %s already exists. This runbook never reuses a folder.\n' "$dest" >&2
  exit 3
fi
git clone --branch "$branch" "$url" "$dest"
cd "$dest"
test -f lab/demo-a14/install.sh
if [ -n "$(git status --porcelain=v1)" ]; then
  printf 'REFUSED: the new clone has local changes. Stop and ask an engineer.\n' >&2
  exit 3
fi

# 2. Read-only check of this Mac. Stop on "preflight: FAIL".
sh lab/demo-a14/preflight.sh

# 3. Install and sign (30 minutes or more the first time)
bash lab/demo-a14/install.sh --sign

# 4. Run every step against the installed versions
bash lab/demo-a14/run.sh

# 5. Open only this run's summary.txt. Book A14 only on "A14: PASS."
demo_home="$HOME/Library/Application Support/elastos-demo-a14"
run=$(sed -n '1p' "$demo_home/this-run" 2>/dev/null || true)
test -n "$run" && test -d "$run" && test -f "$run/summary.txt" && open "$run/summary.txt"
