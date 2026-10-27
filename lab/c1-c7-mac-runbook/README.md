# C1-C7 Mac runbook

One paste so Sash can run the 32 named macOS `sandbox-exec` tests
from draft PR #323 (`ea25c4d6d58f1dc08d29173b45349bfeb80903f3`) on
native Apple Silicon, plus a separate probe that measures whether
Apple's SBPL reader keeps `#\; x (allow file*)` as a live grant.

This folder is new. It does not edit `capsules/`, `lab/redteam/`,
other lab lanes, or any 0.8.0 runtime code.

Linux already booked the lab-check half of C1-C7. The 32 sandbox-exec
tests stay **NOT RUN ON MAC** until this paste's `summary.txt` ends
with `C1-C7: PASS.` The probe line comes from `probe/sbpl.out` after the same
regular-file, ASCII, and once-written checks as `evidence.txt`.
Exactly one `SBPL_PROBE` line with `ALLOWED` or `DENIED` is a
measured fact. Any other probe file is `SBPL_PROBE: NOT RUN`.
That line does not write the last booking line.

## Paste block

The only ` ```bash ` fence in this file:

- sha256: bfd28dcdd2d8823e31c3d151bf63d0fd84944437c9c104cbfcddb0553ebe1569
- bytes: 27143

Those numbers are of the fence body, including its trailing newline,
and not of the markdown fences.

## Linux dry-run

```sh
python3 -I lab/c1-c7-mac-runbook/dryrun.py
```

The recorder pastes that exact block under zsh with a macOS `uname`,
`xcode-select`, and `sandbox-exec` shim. It does not compile the
confine suites. It plants these cases:

| Case | Last line | Plant |
| --- | --- | --- |
| happy path | `C1-C7: PASS.` | 32 PASS rows; clone is a descendant of `ea25c4d6` |
| missing test | `C1-C7: NOT RUN.` | `model/model_outside_write_denied` row missing |
| duplicate row | `C1-C7: FAIL.` | two `wallet/confined_outside_write_is_denied: PASS` lines |
| ignored count >0 | `C1-C7: FAIL.` | all-PASS rows and `ignored: 1` |
| exit 1 with PASS rows | `C1-C7: FAIL.` | 32 PASS rows and `run.sh` exit 1 |
| late rewrite | `C1-C7: FAIL.` | `run.sh` backgrounds an 8s rewrite to FAIL |
| stale summary | `C1-C7: NOT RUN.` | `C17_SUMMARY` already holds `C1-C7: PASS.` |
| missing pin | `C1-C7: NOT RUN.` | clone has the lab files but no `ea25c4d6` |
| planted failing row | `C1-C7: FAIL.` | `wallet/confined_outside_write_is_denied: FAIL` |
| created `~/.elastos` | `C1-C7: FAIL.` | `run.sh` creates `$HOME/.elastos` |
| missing sandbox-exec | `C1-C7: NOT RUN.` | Darwin shim without `sandbox-exec` |
| PASS then FAIL | `C1-C7: FAIL.` | same row `PASS` then `FAIL` |
| `setsid` rewrite | `C1-C7: FAIL.` | `setsid` daemon sleeps 12s, then writes FAIL |
| Python double-fork | `C1-C7: FAIL.` | `os.setsid` plus double fork, then writes FAIL |
| evidence symlink | `C1-C7: FAIL.` | `evidence.txt` is a symlink outside the clone |
| lookalike row | `C1-C7: FAIL.` | non-ASCII lookalike FAIL plus a real PASS |
| CR in a row | `C1-C7: FAIL.` | CR splits FAIL and PASS on one physical line |
| `HOME` redirect | `C1-C7: FAIL.` | dummy `HOME`; `run.sh` creates the login-home `~/.elastos` |
| existing `~/.elastos` write | `C1-C7: FAIL.` | `run.sh` writes into a pre-existing `~/.elastos` |
| probe symlink | `C1-C7: FAIL.` | `probe/sbpl.out` is a symlink outside the clone |
| probe non-ASCII | `C1-C7: FAIL.` | probe file holds a non-ASCII byte |
| missing probe file | `C1-C7: PASS.` | 32 PASS rows and no `probe/sbpl.out`; probe is NOT RUN |
| duplicate probe line | `C1-C7: PASS.` | two `SBPL_PROBE` lines; probe is NOT RUN |
| invalid probe value | `C1-C7: PASS.` | `SBPL_PROBE: MAYBE`; probe is NOT RUN |

Recorded on this Linux x86_64 host, zsh 5.9, with the macOS shim.
C1-C7 on macOS is **NOT RUN ON MAC** until Sash pastes the block on
Apple Silicon and that run's `summary.txt` ends with `C1-C7: PASS.`

| Case | Last line | Plant | Result |
| --- | --- | --- | --- |
| happy path | `C1-C7: PASS.` | 32 PASS rows; descendant of `ea25c4d6` | CAUGHT |
| missing test | `C1-C7: NOT RUN.` | `model/model_outside_write_denied` missing | CAUGHT |
| duplicate row | `C1-C7: FAIL.` | two PASS lines for one wallet test | CAUGHT |
| ignored count >0 | `C1-C7: FAIL.` | all-PASS rows and `ignored: 1` | CAUGHT |
| exit 1 with PASS rows | `C1-C7: FAIL.` | 32 PASS rows and `run.sh` exit 1 | CAUGHT |
| late rewrite | `C1-C7: FAIL.` | background 8s rewrite to FAIL | CAUGHT |
| stale summary | `C1-C7: NOT RUN.` | `C17_SUMMARY` already holds PASS | CAUGHT |
| missing pin | `C1-C7: NOT RUN.` | no `ea25c4d6` object | CAUGHT |
| planted failing row | `C1-C7: FAIL.` | one wallet row FAIL | CAUGHT |
| created `~/.elastos` | `C1-C7: FAIL.` | `run.sh` creates `$HOME/.elastos` | CAUGHT |
| missing sandbox-exec | `C1-C7: NOT RUN.` | Darwin shim without `sandbox-exec` | CAUGHT |
| PASS then FAIL | `C1-C7: FAIL.` | same row `PASS` then `FAIL` | CAUGHT |
| `setsid` rewrite | `C1-C7: FAIL.` | `setsid` daemon sleeps 12s, then writes FAIL | CAUGHT |
| Python double-fork | `C1-C7: FAIL.` | `os.setsid` plus double fork, then writes FAIL | CAUGHT |
| evidence symlink | `C1-C7: FAIL.` | `evidence.txt` is a symlink outside the clone | CAUGHT |
| lookalike row | `C1-C7: FAIL.` | non-ASCII lookalike FAIL plus a real PASS | CAUGHT |
| CR in a row | `C1-C7: FAIL.` | CR splits FAIL and PASS on one physical line | CAUGHT |
| `HOME` redirect | `C1-C7: FAIL.` | dummy `HOME`; login-home `~/.elastos` created | CAUGHT |
| existing `~/.elastos` write | `C1-C7: FAIL.` | write into a pre-existing `~/.elastos` | CAUGHT |
| probe symlink | `C1-C7: FAIL.` | `probe/sbpl.out` is a symlink outside the clone | CAUGHT |
| probe non-ASCII | `C1-C7: FAIL.` | probe file holds a non-ASCII byte | CAUGHT |
| missing probe file | `C1-C7: PASS.` | no `probe/sbpl.out`; `SBPL_PROBE: NOT RUN` | CAUGHT |
| duplicate probe line | `C1-C7: PASS.` | two `SBPL_PROBE` lines; `SBPL_PROBE: NOT RUN` | CAUGHT |
| invalid probe value | `C1-C7: PASS.` | `SBPL_PROBE: MAYBE`; `SBPL_PROBE: NOT RUN` | CAUGHT |

## Before Sash pastes

- Native Apple Silicon Terminal. Rosetta is a named NOT RUN.
- `xcode-select --install` already done in another window. The paste
  never runs it and never uses `sudo`.
- `rustup --version` already works. The paste skips
  `toolchain install` when 1.91.0 is present. It never curls rustup.rs.
- `/usr/bin/sandbox-exec` is present (macOS seatbelt).
- `lsof` is on PATH. Apple Silicon Terminal already has it.
- Do not clone first. The paste uses `mktemp` and a trap.
- About 20 GiB free on the `/tmp` volume. First real run compiles the
  wallet, model, and did confine suites. Keep the Mac awake.
- Sign in to GitHub the usual way. If `git clone` asks for a
  password, Ctrl-C and paste again with
  `C17_REMOTE=git@github.com:Elacity/elastos-agent-host-spike.git`.
- The paste never runs `elastos serve`, never writes Sash's real
  Home, and refuses if it creates or changes `~/.elastos` under
  `$HOME` or the login home.

Book the macOS half of C1-C7 only on `C1-C7: PASS.` from that Mac
`summary.txt`. Send the `SBPL_PROBE` line with it. `ALLOWED` or
`DENIED` is a measured fact, not a booking line.

## What you need, one time

The paste does not install these, and it does not run `sudo`.

- A Mac with Apple Silicon (native arm64, not Rosetta).
- The Terminal app.
- Apple's command line tools. In a **different** window type
  `xcode-select --install` and follow the dialog.
- Rust via rustup. If `rustup --version` already works, skip this.
  Otherwise go to <https://rustup.rs> and run the install command on
  that page. Then close Terminal and open it again.
- About 20 GiB free on the disk that holds `/tmp`.
- `lsof` on PATH. Apple Silicon Terminal already has it.
- Your usual GitHub sign-in. This repository is private.

Do not clone first. The paste makes a fresh `mktemp` directory and
clones into that. Leave `/Users/sash/code/wt-agent-host` and
`~/code/elastos-agent-host-spike` as they are.

## Sash's morning steps

Paste this whole block into zsh. It is one script. A failed check
stops the rest and writes `summary.txt`. The last line of that file
is the only booking line: `C1-C7: PASS.`, `C1-C7: FAIL.`, or
`C1-C7: NOT RUN.`

If git asks for a password, press Ctrl-C and paste again with:

`C17_REMOTE=git@github.com:Elacity/elastos-agent-host-spike.git`

```bash
set -euo pipefail

# 1. Temp folder, quoted paths, trap. Never reuse a folder or summary.
c17_finished=0
c17_workdir=""
c17_summary=""
c17_login_home=""
c17_elastos_home_before=""
c17_elastos_login_before=""
c17_elastos_home_snap=""
c17_elastos_login_snap=""
c17_row_lines=""
c17_pin_c17=ea25c4d6d58f1dc08d29173b45349bfeb80903f3

c17_cleanup() {
  if [ "${C17_CLEAN:-0}" = 1 ] && [ -n "${c17_workdir:-}" ] && [ -d "$c17_workdir" ]; then
    rm -rf -- "$c17_workdir"
  fi
}

c17_write_summary() {
  c17_verdict=$1
  c17_reason=$2
  if [ -z "${c17_summary:-}" ]; then
    printf 'reason: %s\nC1-C7: %s.\n' "$c17_reason" "$c17_verdict" >&2
    return 0
  fi
  {
    printf 'C1-C7 mac runbook\n'
    printf 'when: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'os: %s %s\n' "$(uname -s)" "$(uname -m)"
    printf 'workdir: %s\n' "${c17_workdir:-}"
    printf 'reason: %s\n' "$c17_reason"
    if [ -n "${c17_row_lines:-}" ]; then
      printf '%s\n' "$c17_row_lines"
    fi
    printf 'C1-C7: %s.\n' "$c17_verdict"
  } > "$c17_summary"
  cat "$c17_summary"
}

c17_finish() {
  c17_finished=1
  c17_write_summary "$1" "$2"
  case "$1" in
    PASS) exit 0 ;;
    FAIL) exit 1 ;;
    *) exit 2 ;;
  esac
}

c17_on_exit() {
  if [ "$c17_finished" != 1 ] && [ -n "${c17_summary:-}" ]; then
    c17_write_summary "NOT RUN" "the paste stopped before a verdict"
  fi
  c17_cleanup
}

trap c17_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

c17_hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" | awk '{ print $1 }'
  else
    shasum -a 256 -- "$1" | awk '{ print $1 }'
  fi
}

c17_snapshot_tree() {
  python3 -I -c '
import os
import sys

root = sys.argv[1]
if not os.path.exists(root):
    raise SystemExit(0)
rows = []

def add(kind, path, rel):
    try:
        st = os.lstat(path)
    except OSError:
        return
    mtime = getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000))
    rows.append("%s\t%d\t%d\t%s" % (kind, mtime, st.st_size, rel))

if os.path.isdir(root) and not os.path.islink(root):
    add("d", root, ".")
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        for name in dirnames:
            path = os.path.join(dirpath, name)
            add("d", path, os.path.relpath(path, root))
        for name in filenames:
            path = os.path.join(dirpath, name)
            kind = "l" if os.path.islink(path) else "f"
            add(kind, path, os.path.relpath(path, root))
else:
    kind = "l" if os.path.islink(root) else "f"
    add(kind, root, ".")
rows.sort(key=lambda line: line.split("\t")[-1])
sys.stdout.write("\n".join(rows) + ("\n" if rows else ""))
' "$1"
}

c17_same_path() {
  python3 -I -c '
import os, sys
raise SystemExit(0 if os.path.realpath(sys.argv[1]) == os.path.realpath(sys.argv[2]) else 1)
' "$1" "$2"
}

c17_lsof_writers() {
  python3 -I -c '
import os
import subprocess
import sys

directory, evidence = sys.argv[1], sys.argv[2]
self_pid = os.getpid()
parent_pid = os.getppid()
lines = []
cmds = []
if os.path.isdir(directory):
    cmds.append(["lsof", "+D", directory])
if os.path.exists(evidence):
    cmds.append(["lsof", evidence])
if not cmds:
    raise SystemExit(0)
for cmd in cmds:
    try:
        done = subprocess.run(cmd, capture_output=True, text=True)
    except OSError:
        sys.stdout.write("lsof-missing\n")
        raise SystemExit(0)
    for line in (done.stdout or "").splitlines():
        if not line or line.startswith("COMMAND"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        if pid in (self_pid, parent_pid) or parts[0] == "lsof":
            continue
        lines.append(line)
sys.stdout.write("\n".join(lines) + ("\n" if lines else ""))
' "$1" "$2"
}

c17_regular_inside() {
  python3 -I -c '
import os, sys
path, root = sys.argv[1], sys.argv[2]
if os.path.islink(path) or not os.path.isfile(path):
    raise SystemExit(1)
resolved = os.path.realpath(path)
base = os.path.realpath(root)
raise SystemExit(0 if resolved.startswith(base + os.sep) else 1)
' "$1" "$2"
}

if [ -n "${C17_SUMMARY:-}" ] && [ -e "$C17_SUMMARY" ]; then
  c17_summary=$C17_SUMMARY
  c17_workdir=${C17_WORKDIR:-}
  c17_finish "NOT RUN" "C17_SUMMARY already exists. This runbook never reuses a summary."
fi

if [ -n "${C17_WORKDIR:-}" ]; then
  if [ -e "$C17_WORKDIR" ]; then
    c17_summary=${C17_SUMMARY:-}
    c17_workdir=$C17_WORKDIR
    c17_finish "NOT RUN" "C17_WORKDIR already exists. This runbook never reuses a folder."
  fi
  mkdir -p -- "$C17_WORKDIR"
  c17_workdir=$(cd -- "$C17_WORKDIR" && pwd -P)
else
  c17_workdir=$(mktemp -d "${TMPDIR:-/tmp}/c1-c7-mac-runbook.XXXXXX")
fi
c17_summary=${C17_SUMMARY:-"$c17_workdir/summary.txt"}
mkdir -p -- "$c17_workdir/xdg/data" "$c17_workdir/xdg/config" "$c17_workdir/xdg/cache" "$c17_workdir/xdg/state"
printf 'WORKDIR %s\n' "$c17_workdir"
printf 'SUMMARY %s\n' "$c17_summary"

case $c17_workdir in
  *' '*)
    c17_finish "NOT RUN" "missing: temp workdir path contains a space"
    ;;
esac
case $c17_workdir in
  "$HOME/.elastos"|"$HOME/.elastos"/*)
    c17_finish "NOT RUN" "missing: workdir is under ~/.elastos"
    ;;
esac

# 2. Prerequisites. Named NOT RUN if one is missing.
c17_os=$(uname -s)
c17_mach=$(uname -m)
c17_missing=""

c17_add_missing() {
  if [ -n "$c17_missing" ]; then
    c17_missing="$c17_missing; missing: $1"
  else
    c17_missing="missing: $1"
  fi
}

if [ "$c17_os" != Darwin ]; then
  c17_add_missing "operating system is $c17_os; C1-C7 Mac needs macOS (Darwin)"
fi
if [ "$c17_os" = Darwin ]; then
  c17_translated=0
  if command -v sysctl >/dev/null 2>&1; then
    c17_translated=$(sysctl -n sysctl.proc_translated 2>/dev/null || printf '0')
  fi
  if [ "$c17_translated" = 1 ]; then
    c17_add_missing "this shell is Rosetta (sysctl.proc_translated=1); open a native arm64 Terminal"
  fi
  if ! command -v xcode-select >/dev/null 2>&1 || ! xcode-select -p >/dev/null 2>&1; then
    c17_add_missing "Xcode command line tools are not installed; run xcode-select --install in another window, then paste again"
  fi
  if ! command -v sandbox-exec >/dev/null 2>&1 && [ ! -x /usr/bin/sandbox-exec ]; then
    c17_add_missing "sandbox-exec is not on PATH; C1-C7 Mac needs /usr/bin/sandbox-exec"
  fi
fi
if [ "$c17_mach" != arm64 ]; then
  c17_add_missing "architecture is $c17_mach; C1-C7 Mac needs native Apple Silicon (arm64)"
fi
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  c17_add_missing "CARGO_TARGET_DIR is set; unset it so cargo output stays in the temp clone"
fi

c17_need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    c17_add_missing "$1 is not on PATH"
  fi
}
c17_need_cmd git
c17_need_cmd python3
c17_need_cmd rustup
c17_need_cmd rustc
c17_need_cmd cargo
c17_need_cmd bash
c17_need_cmd lsof

if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  c17_add_missing "neither sha256sum nor shasum is on PATH"
fi
if command -v python3 >/dev/null 2>&1; then
  if ! python3 -I -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)'; then
    c17_add_missing "python3 is older than 3.9"
  fi
fi

c17_kb=$(df -Pk "$c17_workdir" 2>/dev/null | awk 'NR==2 { print $4 }')
case $c17_kb in
  ''|*[!0-9]*)
    c17_add_missing "free space for the temp workdir could not be read"
    ;;
  *)
    if ! awk -v a="$c17_kb" 'BEGIN { exit (a+0 >= 20971520) ? 0 : 1 }'; then
      c17_add_missing "free space for the temp workdir is below 20 GiB"
    fi
    ;;
esac

if [ -n "$c17_missing" ]; then
  c17_finish "NOT RUN" "$c17_missing"
fi

c17_login_home=$(eval echo ~$(id -un))
case $c17_login_home in
  ''|"~$(id -un)")
    if command -v dscl >/dev/null 2>&1; then
      c17_login_home=$(dscl . -read "/Users/$(id -un)" NFSHomeDirectory 2>/dev/null | awk '{ print $2 }')
    fi
    ;;
esac
if [ -z "$c17_login_home" ]; then
  c17_login_home=$HOME
fi
c17_elastos_home_snap="$c17_workdir/elastos-home.snap"
c17_elastos_login_snap="$c17_workdir/elastos-login.snap"
if [ -e "$HOME/.elastos" ]; then
  c17_elastos_home_before=PRESENT
  c17_snapshot_tree "$HOME/.elastos" > "$c17_elastos_home_snap"
else
  c17_elastos_home_before=ABSENT
fi
if [ -e "$c17_login_home/.elastos" ]; then
  c17_elastos_login_before=PRESENT
  if [ -n "$HOME" ] && c17_same_path "$HOME/.elastos" "$c17_login_home/.elastos"; then
    cp -- "$c17_elastos_home_snap" "$c17_elastos_login_snap"
  else
    c17_snapshot_tree "$c17_login_home/.elastos" > "$c17_elastos_login_snap"
  fi
else
  c17_elastos_login_before=ABSENT
fi

# 3. rustup skip-if-present. The paste never curls rustup.rs.
c17_tc=$(rustup toolchain list 2>/dev/null || true)
case $c17_tc in
  *1.91.0*)
    printf 'rustup toolchain 1.91.0 already present; skip install\n'
    ;;
  *)
    rustup toolchain install 1.91.0
    ;;
esac

# 4. Isolate ElastOS data. Keep HOME so rustup and cargo still work.
export XDG_DATA_HOME="$c17_workdir/xdg/data"
export XDG_CONFIG_HOME="$c17_workdir/xdg/config"
export XDG_CACHE_HOME="$c17_workdir/xdg/cache"
export XDG_STATE_HOME="$c17_workdir/xdg/state"
unset ELASTOS_LIVE_HOME
unset ELASTOS_LIVE_XDG_DATA_HOME
unset ELASTOS_LIVE_LOCAL_URL
unset ELASTOS_LIVE_PUBLIC_URL
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"

# 5. Fresh clone in the temp folder. Do not clone first.
c17_branch=${C17_BRANCH:-cursor/c1-c7-mac-runbook-5f39}
c17_url=${C17_REMOTE:-https://github.com/Elacity/elastos-agent-host-spike.git}
c17_clone="$c17_workdir/src"
if [ -e "$c17_clone" ]; then
  c17_finish "NOT RUN" "clone path already exists inside the temp workdir"
fi
printf 'CLONE branch %s\n' "$c17_branch"
if ! git clone --branch "$c17_branch" "$c17_url" "$c17_clone"; then
  c17_finish "NOT RUN" "git clone failed; if git asked for a password, set C17_REMOTE=git@github.com:Elacity/elastos-agent-host-spike.git and paste again"
fi
cd -- "$c17_clone"
if [ ! -f lab/c1-c7-mac-runbook/run.sh ] \
  || [ ! -f capsules/wallet-provider/tests/confine.rs ] \
  || [ ! -f capsules/model-provider/tests/confine/main.rs ] \
  || [ ! -f capsules/did-provider/tests/confine.rs ]; then
  c17_finish "NOT RUN" "missing: C1-C7 confine tests or lab/c1-c7-mac-runbook/run.sh; stay on cursor/c1-c7-mac-runbook-5f39"
fi
if [ -n "$(git status --porcelain=v1)" ]; then
  c17_finish "NOT RUN" "the new clone has local changes"
fi
if ! git cat-file -e "${c17_pin_c17}^{commit}" 2>/dev/null; then
  git fetch --unshallow >/dev/null 2>&1 || true
fi
if ! git cat-file -e "${c17_pin_c17}^{commit}" 2>/dev/null; then
  git fetch -- "$c17_url" "$c17_pin_c17" >/dev/null 2>&1 || true
fi
if ! git cat-file -e "${c17_pin_c17}^{commit}" 2>/dev/null \
  || ! git merge-base --is-ancestor "$c17_pin_c17" HEAD; then
  c17_finish "NOT RUN" "clone is not a descendant of C1-C7 pin ${c17_pin_c17}"
fi

# 6. Run the 32 named tests plus the SBPL probe. Wait for run.sh children.
c17_journey_out="$c17_workdir/journey.out"
c17_wait_py="$c17_workdir/wait_journey.py"
cat > "$c17_wait_py" <<'C17WAIT'
import os
import subprocess
import sys
import time


def group_pids(pgid):
    found = []
    if os.path.isdir("/proc"):
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            path = os.path.join("/proc", name, "stat")
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            rparen = text.rfind(")")
            if rparen < 0:
                continue
            fields = text[rparen + 2 :].split()
            if len(fields) < 3:
                continue
            try:
                if int(fields[2]) == pgid:
                    found.append(int(name))
            except ValueError:
                continue
        return found
    try:
        out = subprocess.check_output(["ps", "-ax", "-o", "pid=", "-o", "pgid="], text=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            if int(parts[1]) == pgid:
                found.append(int(parts[0]))
        except ValueError:
            continue
    return found


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def argv_mentions(needle):
    found = []
    try:
        out = subprocess.check_output(["ps", "-ax", "-o", "pid,command"], text=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    self_pid = os.getpid()
    for line in out.splitlines():
        if needle not in line:
            continue
        parts = line.split(None, 1)
        if not parts:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        if pid == self_pid:
            continue
        found.append(pid)
    return found


workdir = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.getcwd()
clone = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.getcwd()
lane = os.path.abspath("lab/c1-c7-mac-runbook")
needles = []
for item in (workdir, clone, lane):
    if item not in needles:
        needles.append(item)

child = os.fork()
if child == 0:
    try:
        os.setpgrp()
    except PermissionError:
        pass
    os.execvp("bash", ["bash", "lab/c1-c7-mac-runbook/run.sh"])
_, status = os.waitpid(child, 0)
rc = os.waitstatus_to_exitcode(status)
deadline = time.time() + 7200
empty = 0
while time.time() < deadline:
    live = group_pids(child)
    if live is None:
        sys.stderr.write("cannot list run.sh process group\n")
        raise SystemExit(1)
    named = []
    for needle in needles:
        extra = argv_mentions(needle)
        if extra is None:
            sys.stderr.write("cannot list processes that name the temp clone dir\n")
            raise SystemExit(1)
        named.extend(extra)
    still = [pid for pid in live if pid != child and alive(pid)]
    named = [pid for pid in named if pid != child and alive(pid)]
    if not still and not named:
        empty += 1
        if empty >= 2:
            raise SystemExit(rc)
    else:
        empty = 0
    time.sleep(0.2)
sys.stderr.write("run.sh or one of its children was still running after 7200s\n")
raise SystemExit(1)
C17WAIT
set +e
python3 -I "$c17_wait_py" "$c17_workdir" "$c17_clone" > "$c17_journey_out" 2>&1
c17_journey_rc=$?
set -e
cat "$c17_journey_out"
printf 'JOURNEY run.sh -> %s\n' "$c17_journey_rc"

c17_evidence="$c17_clone/lab/c1-c7-mac-runbook/evidence.txt"
c17_evidence_dir="$c17_clone/lab/c1-c7-mac-runbook"
c17_probe_out="$c17_clone/lab/c1-c7-mac-runbook/probe/sbpl.out"
c17_evidence_snap="$c17_workdir/evidence.snap"
c17_probe_snap="$c17_workdir/sbpl.snap"
c17_score_path=$c17_evidence
c17_evidence_hash=""
c17_probe_hash=""
if [ -L "$c17_evidence" ] || [ -e "$c17_evidence" ]; then
  if [ -L "$c17_evidence" ] || [ ! -f "$c17_evidence" ] || ! c17_regular_inside "$c17_evidence" "$c17_clone"; then
    if [ -L "$c17_evidence" ] || [ ! -f "$c17_evidence" ]; then
      c17_finish "FAIL" "evidence.txt is not a regular file in the clone"
    fi
    c17_finish "FAIL" "evidence.txt resolves outside the temp clone"
  fi
fi
if [ -L "$c17_probe_out" ] || [ -e "$c17_probe_out" ]; then
  if [ -L "$c17_probe_out" ] || [ ! -f "$c17_probe_out" ] || ! c17_regular_inside "$c17_probe_out" "$c17_clone"; then
    if [ -L "$c17_probe_out" ] || [ ! -f "$c17_probe_out" ]; then
      c17_finish "FAIL" "SBPL probe output is not a regular file in the clone"
    fi
    c17_finish "FAIL" "SBPL probe output resolves outside the temp clone"
  fi
fi
if [ -f "$c17_evidence" ] || [ -f "$c17_probe_out" ]; then
  c17_writers=$(c17_lsof_writers "$c17_evidence_dir" "$c17_evidence")
  if [ -n "$c17_writers" ]; then
    c17_finish "FAIL" "evidence still has a live writer before the quiet period"
  fi
  if [ -e "$c17_probe_out" ]; then
    c17_probe_writers=$(c17_lsof_writers "$c17_evidence_dir/probe" "$c17_probe_out")
    if [ -n "$c17_probe_writers" ]; then
      c17_finish "FAIL" "SBPL probe output still has a live writer before the quiet period"
    fi
  fi
  c17_quiet_hash=""
  c17_probe_quiet=""
  if [ -f "$c17_evidence" ]; then
    c17_quiet_hash=$(c17_hash_file "$c17_evidence")
  fi
  if [ -f "$c17_probe_out" ]; then
    c17_probe_quiet=$(c17_hash_file "$c17_probe_out")
  fi
  sleep 15
  c17_writers=$(c17_lsof_writers "$c17_evidence_dir" "$c17_evidence")
  if [ -n "$c17_writers" ]; then
    c17_finish "FAIL" "evidence still has a live writer after the quiet period"
  fi
  if [ -e "$c17_probe_out" ]; then
    c17_probe_writers=$(c17_lsof_writers "$c17_evidence_dir/probe" "$c17_probe_out")
    if [ -n "$c17_probe_writers" ]; then
      c17_finish "FAIL" "SBPL probe output still has a live writer after the quiet period"
    fi
  fi
  if [ -n "$c17_quiet_hash" ] && [ "$(c17_hash_file "$c17_evidence")" != "$c17_quiet_hash" ]; then
    c17_finish "FAIL" "evidence.txt changed during the quiet period; C1-C7 cannot PASS on a moving file"
  fi
  if [ -n "$c17_probe_quiet" ]; then
    if [ ! -f "$c17_probe_out" ] || [ "$(c17_hash_file "$c17_probe_out")" != "$c17_probe_quiet" ]; then
      c17_finish "FAIL" "SBPL probe output changed during the quiet period; C1-C7 cannot PASS on a moving file"
    fi
  fi
  if [ -f "$c17_evidence" ]; then
    cp -- "$c17_evidence" "$c17_evidence_snap"
    c17_evidence_hash=$(c17_hash_file "$c17_evidence")
    if [ "$(c17_hash_file "$c17_evidence_snap")" != "$c17_evidence_hash" ]; then
      c17_finish "FAIL" "evidence snapshot did not match the live file"
    fi
    c17_score_path=$c17_evidence_snap
  fi
  if [ -f "$c17_probe_out" ]; then
    cp -- "$c17_probe_out" "$c17_probe_snap"
    c17_probe_hash=$(c17_hash_file "$c17_probe_out")
    if [ "$(c17_hash_file "$c17_probe_snap")" != "$c17_probe_hash" ]; then
      c17_finish "FAIL" "SBPL probe snapshot did not match the live file"
    fi
  fi
fi

c17_score=$(python3 -I - "$c17_score_path" <<'PY'
import pathlib
import sys

rows_order = (
    "wallet/confined_provider_serves_wallet_operations_under_its_root",
    "wallet/confined_outside_write_is_denied",
    "wallet/confined_outside_read_is_denied",
    "wallet/planted_key_beneath_storage_parent_is_not_read",
    "wallet/account_operations_beneath_storage_parent_are_refused",
    "wallet/startup_is_refused_when_the_profile_cannot_be_applied",
    "wallet/unbound_copy_is_refused_under_profile",
    "wallet/bound_copy_serves_under_profile",
    "wallet/startup_denial_reports_its_reason",
    "wallet/the_bare_value_fixture_loads_under_sandbox_exec",
    "wallet/the_string_fixture_loads_under_sandbox_exec",
    "model/model_provider_ops_under_profile",
    "model/model_outside_write_denied",
    "model/model_outside_read_denied",
    "model/model_outside_create_reports_access_denied",
    "model/model_local_offer_fails_closed_under_profile",
    "model/model_hosted_run_fails_closed_under_profile",
    "model/model_hosted_run_reaches_runtime_socket_when_unconfined",
    "model/model_unbound_program_refused_under_profile",
    "model/model_bound_copy_serves_under_profile",
    "model/byte_different_file_at_bound_path_starts",
    "model/startup_is_refused_when_the_profile_cannot_be_applied",
    "did/confined_provider_serves_did_operations_under_its_root",
    "did/verify_did_recovery_under_profile",
    "did/outside_write_denied",
    "did/outside_read_denied",
    "did/planted_file_beneath_storage_parent_is_neither_read_nor_written",
    "did/persona_key_beneath_storage_parent_is_not_adopted",
    "did/startup_denial_reports_its_reason",
    "did/startup_is_refused_when_the_profile_cannot_be_applied",
    "did/unbound_copy_is_refused_under_profile",
    "did/bound_copy_serves_under_profile",
)
evidence = pathlib.Path(sys.argv[1])
if not evidence.is_file():
    print("NOT RUN")
    print("run.sh wrote no evidence.txt")
    print("")
    raise SystemExit(0)
raw = evidence.read_bytes()
if b"\r" in raw or any(byte > 127 for byte in raw):
    print("FAIL")
    print("evidence rows contain a CR or non-ASCII byte")
    print("")
    raise SystemExit(0)
rows = {}
conflict = False
ignored_count = None
failed_count = None
passed_count = None
for line in raw.decode("ascii").splitlines():
    if line.startswith("ignored:"):
        ignored_count = line.split(":", 1)[1].strip()
        continue
    if line.startswith("failed:"):
        failed_count = line.split(":", 1)[1].strip()
        continue
    if line.startswith("passed:"):
        passed_count = line.split(":", 1)[1].strip()
        continue
    if line.startswith("SBPL_PROBE:"):
        continue
    for name in rows_order:
        prefix = name + ": "
        if line.startswith(prefix):
            rest = line[len(prefix):]
            if rest.startswith("PASS"):
                result = "PASS"
            elif rest.startswith("FAIL"):
                result = "FAIL"
            elif rest.startswith("IGNORED"):
                result = "IGNORED"
            elif rest.startswith("NOT RUN") or rest.startswith("MISSING"):
                result = "NOT RUN"
            else:
                result = "UNKNOWN"
            if name in rows:
                conflict = True
            rows[name] = result
body = "\n".join(f"{name}: {rows.get(name, 'MISSING')}" for name in rows_order)
if conflict:
    print("FAIL")
    print("evidence has duplicate or disagreeing rows")
    print(body)
    raise SystemExit(0)
fails = [name for name in rows_order if rows.get(name) == "FAIL"]
unknown = [name for name in rows_order if rows.get(name) == "UNKNOWN"]
ignored_rows = [name for name in rows_order if rows.get(name) == "IGNORED"]
if fails or unknown:
    print("FAIL")
    print("computed FAIL or unreadable row: " + ", ".join(fails + unknown))
    print(body)
    raise SystemExit(0)
try:
    ignored_n = int(ignored_count) if ignored_count is not None else 0
    failed_n = int(failed_count) if failed_count is not None else 0
    passed_n = int(passed_count) if passed_count is not None else None
except ValueError:
    print("FAIL")
    print("evidence counts are not integers")
    print(body)
    raise SystemExit(0)
if ignored_n > 0 or ignored_rows:
    print("FAIL")
    print("ignored count >0: ignored=" + str(ignored_n) + " rows=" + ",".join(ignored_rows))
    print(body)
    raise SystemExit(0)
if failed_n > 0:
    print("FAIL")
    print("failed count >0: failed=" + str(failed_n))
    print(body)
    raise SystemExit(0)
missing = [name for name in rows_order if name not in rows]
notruns = [name for name in rows_order if rows.get(name) == "NOT RUN"]
if missing or notruns or any(rows.get(name) != "PASS" for name in rows_order):
    why = []
    if missing:
        why.append("missing rows " + ",".join(missing))
    if notruns:
        why.append("NOT RUN " + ",".join(notruns))
    print("NOT RUN")
    print("; ".join(why) if why else "test rows were not all computed PASS")
    print(body)
    raise SystemExit(0)
if passed_n is not None and passed_n != 32:
    print("FAIL")
    print("passed count is " + str(passed_n) + "; C1-C7 needs 32")
    print(body)
    raise SystemExit(0)
print("PASS")
print("every named test is computed PASS exactly once with zero failed/ignored")
print(body)
PY
)

c17_verdict=$(printf '%s\n' "$c17_score" | awk 'NR==1 { print; exit }')
c17_reason=$(printf '%s\n' "$c17_score" | awk 'NR==2 { print; exit }')
c17_row_lines=$(printf '%s\n' "$c17_score" | awk 'NR>=3 { print }')

c17_probe_src=""
if [ -n "$c17_probe_hash" ] && [ -f "$c17_probe_snap" ]; then
  c17_probe_src=$c17_probe_snap
fi
c17_probe_score=$(python3 -I - "$c17_probe_src" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not sys.argv[1] or not path.is_file():
    print("SBPL_PROBE: NOT RUN")
    raise SystemExit(0)
raw = path.read_bytes()
if b"\r" in raw or any(byte > 127 for byte in raw):
    print("FAIL")
    raise SystemExit(0)
try:
    text = raw.decode("ascii")
except UnicodeDecodeError:
    print("FAIL")
    raise SystemExit(0)
lines = [line for line in text.splitlines() if line.startswith("SBPL_PROBE:")]
if len(lines) != 1:
    print("SBPL_PROBE: NOT RUN")
    raise SystemExit(0)
value = lines[0].split(":", 1)[1].strip()
if value in ("ALLOWED", "DENIED"):
    print("SBPL_PROBE: " + value)
else:
    print("SBPL_PROBE: NOT RUN")
PY
)
if [ "$c17_probe_score" = FAIL ]; then
  c17_finish "FAIL" "SBPL probe output contains a CR or non-ASCII byte"
fi
if [ -n "$c17_row_lines" ]; then
  c17_row_lines="${c17_row_lines}
${c17_probe_score}"
else
  c17_row_lines=$c17_probe_score
fi

if [ -n "$c17_evidence_hash" ]; then
  if [ ! -f "$c17_evidence" ] || [ "$(c17_hash_file "$c17_evidence")" != "$c17_evidence_hash" ]; then
    c17_finish "FAIL" "evidence.txt changed after the snapshot; C1-C7 cannot PASS on a moving file"
  fi
  if [ "$(c17_hash_file "$c17_evidence_snap")" != "$c17_evidence_hash" ]; then
    c17_finish "FAIL" "evidence snapshot was altered after it was taken"
  fi
fi
if [ -n "$c17_probe_hash" ]; then
  if [ ! -f "$c17_probe_out" ] || [ "$(c17_hash_file "$c17_probe_out")" != "$c17_probe_hash" ]; then
    c17_finish "FAIL" "SBPL probe output changed after the snapshot; C1-C7 cannot PASS on a moving file"
  fi
  if [ "$(c17_hash_file "$c17_probe_snap")" != "$c17_probe_hash" ]; then
    c17_finish "FAIL" "SBPL probe snapshot was altered after it was taken"
  fi
fi
if [ "$c17_elastos_home_before" = ABSENT ] && [ -e "$HOME/.elastos" ]; then
  c17_finish "FAIL" "this run created $HOME/.elastos; C1-C7 must stay inside the temp workdir"
fi
if [ "$c17_elastos_login_before" = ABSENT ] && [ -e "$c17_login_home/.elastos" ]; then
  c17_finish "FAIL" "this run created $c17_login_home/.elastos; C1-C7 must stay inside the temp workdir"
fi
if [ "$c17_elastos_home_before" = PRESENT ]; then
  c17_snapshot_tree "$HOME/.elastos" > "$c17_workdir/elastos-home.after"
  if ! cmp -s "$c17_elastos_home_snap" "$c17_workdir/elastos-home.after"; then
    c17_finish "FAIL" "this run changed $HOME/.elastos; C1-C7 must stay inside the temp workdir"
  fi
fi
if [ "$c17_elastos_login_before" = PRESENT ]; then
  c17_snapshot_tree "$c17_login_home/.elastos" > "$c17_workdir/elastos-login.after"
  if ! cmp -s "$c17_elastos_login_snap" "$c17_workdir/elastos-login.after"; then
    c17_finish "FAIL" "this run changed $c17_login_home/.elastos; C1-C7 must stay inside the temp workdir"
  fi
fi
if [ "$c17_verdict" != "PASS" ] && [ "$c17_verdict" != "FAIL" ] && [ "$c17_verdict" != "NOT RUN" ]; then
  c17_finish "NOT RUN" "scorer printed no verdict"
fi
if [ "$c17_verdict" = PASS ] && [ "${c17_journey_rc:-1}" -ne 0 ]; then
  c17_finish "FAIL" "run.sh exited ${c17_journey_rc}; C1-C7 cannot PASS while the journey failed"
fi
c17_survived=0
if grep -q SURVIVED "$c17_journey_out" 2>/dev/null; then
  c17_survived=1
fi
if [ "$c17_verdict" = PASS ] && [ "$c17_survived" -eq 1 ]; then
  c17_finish "FAIL" "run.sh printed SURVIVED; C1-C7 cannot PASS while a falsifier survived"
fi
c17_finish "$c17_verdict" "$c17_reason"
```

The default clone is branch `cursor/c1-c7-mac-runbook-5f39`. That
branch starts at the reviewed #323 head `ea25c4d6` and adds only this
folder.

Keep the temp folder until you have copied `summary.txt`. The paste
does not delete it. It never deletes anything outside that folder.

`run.sh` refuses if `cargo test --test confine -- --list` does not
name all 32 tests. On Darwin those tests are live (the `#[ignore]`
applies only off macOS). The runner still passes `--exact
--include-ignored` so a leftover ignore cannot silently drop a name.
`ignored_falsifier_fixture` is not in the list.

The SBPL probe writes a deny-default profile that also holds
`#\; x (allow file*)`, then asks `sandbox-exec` to `touch` a file
under the temp folder. `run.sh` writes one `SBPL_PROBE` line to
`probe/sbpl.out`. The paste checks that file the same way as
`evidence.txt`: regular file inside the temp clone, ASCII without
CR, no live writer, and a 15s quiet re-hash. `SBPL_PROBE: ALLOWED`
means the write landed. `SBPL_PROBE: DENIED` means the file stayed
absent. Missing, duplicate, or any other value is
`SBPL_PROBE: NOT RUN`. That line is a measured fact. It does not
write `C1-C7: PASS.`

## What the last line means

| Last line | Meaning |
| --- | --- |
| `C1-C7: PASS.` | Each of the 32 named tests appears exactly once as a **computed** PASS, `failed` and `ignored` are 0, `run.sh` and any process that still names the temp clone dir exited 0, `evidence.txt` is a regular file inside the temp clone with no CR or non-ASCII byte, `lsof` showed no writer, and a 15s quiet re-hash stayed still. |
| `C1-C7: FAIL.` | A test failed, a name appeared twice, `ignored` was greater than 0, `run.sh` exited nonzero, `evidence.txt` or the probe file was a symlink or lived outside the clone, a quiet-period hash moved, a live writer remained, a CR or non-ASCII byte appeared, or the run created or changed `~/.elastos` under `$HOME` or the login home. |
| `C1-C7: NOT RUN.` | A named prerequisite was missing, the clone is not a descendant of `ea25c4d6`, `cargo --list` did not name all 32, a row was skipped, or a stale summary was reused. C1-C7 is not booked. |

This paste does not print `C1-C7: PASS.` unless it parsed the 32
rows from a snapshot of `lab/c1-c7-mac-runbook/evidence.txt` taken
after `run.sh`, any process that still names the temp clone dir, and
a 15s quiet re-hash. The `SBPL_PROBE` line comes from
`probe/sbpl.out` after the same checks. Exactly one `ALLOWED` or
`DENIED` line is a measured fact. Anything else is
`SBPL_PROBE: NOT RUN` and does not write the booking line.

## What this paste does not do

- It does not run `elastos serve`.
- It does not use Sash's real Home. `XDG_*` points at the temp folder.
  `HOME` stays your login home so rustup and cargo keep working. The
  paste watches both `$HOME/.elastos` and the login-home `~/.elastos`
  (`eval echo ~$(id -un)`, or `dscl` on a Mac). It refuses if it
  creates either path, and it refuses if an already-present tree
  changes.
- It does not run `sudo`, `xcode-select --install`, or the rustup.rs
  installer, and it does not pipe `curl` to `sh`.
- It does not delete `/Users/sash/code/wt-agent-host` or any other
  path outside the temp folder.
- It does not book C1-C7 from a Linux dry-run.

## After a PASS

Send that `summary.txt`, including the 32 rows and the `SBPL_PROBE`
line. Book the macOS half of C1-C7 only from that file's last line.

## Linux dry-run of this fence

This cloud session is Linux. It cannot book C1-C7. The recorder at
`lab/c1-c7-mac-runbook/dryrun.py` pastes the same fence with a macOS
shim and a stub `run.sh`.

```sh
python3 -I lab/c1-c7-mac-runbook/dryrun.py
```

Label every Linux result **NOT RUN ON MAC**.
