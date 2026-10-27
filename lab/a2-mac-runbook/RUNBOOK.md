# A2 Mac runbook

One paste for Sash's Mac. It rebuilds the guest, shows the old pin
next to the new hash, writes the new pin only inside a temp folder,
and runs the A2 resume journey from draft PR #351
(`9e7a85d631aec12de8c1da4fc4958bce18252d21`).

Book A2 on this Mac only when this run's `summary.txt` ends with
`A2: PASS.`

## What you need, one time

The paste does not install these, and it does not run `sudo`.

- A Mac with Apple Silicon (native arm64, not Rosetta).
- The Terminal app.
- Apple's command line tools. In a **different** window type
  `xcode-select --install` and follow the dialog. If it says they are
  already installed, that is fine. The paste only checks; it never
  starts that installer.
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
is the only booking line: `A2: PASS.`, `A2: FAIL.`, or `A2: NOT RUN.`

If git asks for a password, press Ctrl-C and paste again with:

`A2_REMOTE=git@github.com:Elacity/elastos-agent-host-spike.git`

```bash
set -euo pipefail

# 1. Temp folder, quoted paths, trap. Never reuse a folder.
a2_finished=0
a2_workdir=""
a2_summary=""
a2_login_home=""
a2_elastos_home_before=""
a2_elastos_login_before=""
a2_elastos_home_snap=""
a2_elastos_login_snap=""
a2_row_lines=""
a2_pin_a2=9e7a85d631aec12de8c1da4fc4958bce18252d21

a2_cleanup() {
  if [ "${A2_CLEAN:-0}" = 1 ] && [ -n "${a2_workdir:-}" ] && [ -d "$a2_workdir" ]; then
    rm -rf -- "$a2_workdir"
  fi
}

a2_write_summary() {
  a2_verdict=$1
  a2_reason=$2
  if [ -z "${a2_summary:-}" ]; then
    printf 'reason: %s\nA2: %s.\n' "$a2_reason" "$a2_verdict" >&2
    return 0
  fi
  {
    printf 'A2 mac runbook\n'
    printf 'when: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'os: %s %s\n' "$(uname -s)" "$(uname -m)"
    printf 'workdir: %s\n' "${a2_workdir:-}"
    printf 'reason: %s\n' "$a2_reason"
    if [ -n "${a2_row_lines:-}" ]; then
      printf '%s\n' "$a2_row_lines"
    fi
    printf 'A2: %s.\n' "$a2_verdict"
  } > "$a2_summary"
  cat "$a2_summary"
}

a2_finish() {
  a2_finished=1
  a2_write_summary "$1" "$2"
  case "$1" in
    PASS) exit 0 ;;
    FAIL) exit 1 ;;
    *) exit 2 ;;
  esac
}

a2_on_exit() {
  if [ "$a2_finished" != 1 ] && [ -n "${a2_summary:-}" ]; then
    a2_write_summary "NOT RUN" "the paste stopped before a verdict"
  fi
  a2_cleanup
}

trap a2_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

a2_hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" | awk '{ print $1 }'
  else
    shasum -a 256 -- "$1" | awk '{ print $1 }'
  fi
}

a2_snapshot_tree() {
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

a2_same_path() {
  python3 -I -c '
import os, sys
raise SystemExit(0 if os.path.realpath(sys.argv[1]) == os.path.realpath(sys.argv[2]) else 1)
' "$1" "$2"
}

a2_lsof_writers() {
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

if [ -n "${A2_WORKDIR:-}" ]; then
  if [ -e "$A2_WORKDIR" ]; then
    a2_summary=${A2_SUMMARY:-}
    a2_workdir=$A2_WORKDIR
    a2_finish "NOT RUN" "A2_WORKDIR already exists. This runbook never reuses a folder."
  fi
  mkdir -p -- "$A2_WORKDIR"
  a2_workdir=$(cd -- "$A2_WORKDIR" && pwd -P)
else
  a2_workdir=$(mktemp -d "${TMPDIR:-/tmp}/a2-mac-runbook.XXXXXX")
fi
a2_summary=${A2_SUMMARY:-"$a2_workdir/summary.txt"}
mkdir -p -- "$a2_workdir/xdg/data" "$a2_workdir/xdg/config" "$a2_workdir/xdg/cache" "$a2_workdir/xdg/state"
printf 'WORKDIR %s\n' "$a2_workdir"
printf 'SUMMARY %s\n' "$a2_summary"

case $a2_workdir in
  *' '*)
    a2_finish "NOT RUN" "missing: temp workdir path contains a space; the guest build puts paths in RUSTFLAGS"
    ;;
esac
case $a2_workdir in
  "$HOME/.elastos"|"$HOME/.elastos"/*)
    a2_finish "NOT RUN" "missing: workdir is under ~/.elastos"
    ;;
esac

# 2. Prerequisites. Named NOT RUN if one is missing.
a2_os=$(uname -s)
a2_mach=$(uname -m)
a2_missing=""

a2_add_missing() {
  if [ -n "$a2_missing" ]; then
    a2_missing="$a2_missing; missing: $1"
  else
    a2_missing="missing: $1"
  fi
}

if [ "$a2_os" != Darwin ]; then
  a2_add_missing "operating system is $a2_os; A2 Mac needs macOS (Darwin)"
fi
if [ "$a2_os" = Darwin ]; then
  a2_translated=0
  if command -v sysctl >/dev/null 2>&1; then
    a2_translated=$(sysctl -n sysctl.proc_translated 2>/dev/null || printf '0')
  fi
  if [ "$a2_translated" = 1 ]; then
    a2_add_missing "this shell is Rosetta (sysctl.proc_translated=1); open a native arm64 Terminal"
  fi
  if ! command -v xcode-select >/dev/null 2>&1 || ! xcode-select -p >/dev/null 2>&1; then
    a2_add_missing "Xcode command line tools are not installed; run xcode-select --install in another window, then paste again"
  fi
fi
if [ "$a2_mach" != arm64 ]; then
  a2_add_missing "architecture is $a2_mach; A2 Mac needs native Apple Silicon (arm64)"
fi
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  a2_add_missing "CARGO_TARGET_DIR is set; unset it so cargo output stays in the temp clone"
fi

a2_need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    a2_add_missing "$1 is not on PATH"
  fi
}
a2_need_cmd git
a2_need_cmd python3
a2_need_cmd rustup
a2_need_cmd rustc
a2_need_cmd cargo
a2_need_cmd bash
a2_need_cmd lsof

if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  a2_add_missing "neither sha256sum nor shasum is on PATH"
fi
if command -v python3 >/dev/null 2>&1; then
  if ! python3 -I -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)'; then
    a2_add_missing "python3 is older than 3.9; lab/a2-e2e-resume/harness.py needs 3.9+"
  fi
fi

a2_kb=$(df -Pk "$a2_workdir" 2>/dev/null | awk 'NR==2 { print $4 }')
case $a2_kb in
  ''|*[!0-9]*)
    a2_add_missing "free space for the temp workdir could not be read"
    ;;
  *)
    if ! awk -v a="$a2_kb" 'BEGIN { exit (a+0 >= 20971520) ? 0 : 1 }'; then
      a2_add_missing "free space for the temp workdir is below 20 GiB"
    fi
    ;;
esac

if [ -n "$a2_missing" ]; then
  a2_finish "NOT RUN" "$a2_missing"
fi

a2_login_home=$(eval echo ~$(id -un))
case $a2_login_home in
  ''|"~$(id -un)")
    if command -v dscl >/dev/null 2>&1; then
      a2_login_home=$(dscl . -read "/Users/$(id -un)" NFSHomeDirectory 2>/dev/null | awk '{ print $2 }')
    fi
    ;;
esac
if [ -z "$a2_login_home" ]; then
  a2_login_home=$HOME
fi
a2_elastos_home_snap="$a2_workdir/elastos-home.snap"
a2_elastos_login_snap="$a2_workdir/elastos-login.snap"
if [ -e "$HOME/.elastos" ]; then
  a2_elastos_home_before=PRESENT
  a2_snapshot_tree "$HOME/.elastos" > "$a2_elastos_home_snap"
else
  a2_elastos_home_before=ABSENT
fi
if [ -e "$a2_login_home/.elastos" ]; then
  a2_elastos_login_before=PRESENT
  if [ -n "$HOME" ] && a2_same_path "$HOME/.elastos" "$a2_login_home/.elastos"; then
    cp -- "$a2_elastos_home_snap" "$a2_elastos_login_snap"
  else
    a2_snapshot_tree "$a2_login_home/.elastos" > "$a2_elastos_login_snap"
  fi
else
  a2_elastos_login_before=ABSENT
fi

# 3. rustup skip-if-present. The paste never curls rustup.rs.
a2_tc=$(rustup toolchain list 2>/dev/null || true)
case $a2_tc in
  *1.91.0*)
    printf 'rustup toolchain 1.91.0 already present; skip install\n'
    ;;
  *)
    rustup toolchain install 1.91.0
    ;;
esac
a2_targets=$(rustup target list --installed --toolchain 1.91.0 2>/dev/null || true)
case $a2_targets in
  *wasm32-unknown-unknown*)
    printf 'wasm32-unknown-unknown already present; skip add\n'
    ;;
  *)
    rustup target add wasm32-unknown-unknown --toolchain 1.91.0
    ;;
esac

# 4. Isolate ElastOS data. Keep HOME so rustup and cargo still work.
export XDG_DATA_HOME="$a2_workdir/xdg/data"
export XDG_CONFIG_HOME="$a2_workdir/xdg/config"
export XDG_CACHE_HOME="$a2_workdir/xdg/cache"
export XDG_STATE_HOME="$a2_workdir/xdg/state"
unset ELASTOS_LIVE_HOME
unset ELASTOS_LIVE_XDG_DATA_HOME
unset ELASTOS_LIVE_LOCAL_URL
unset ELASTOS_LIVE_PUBLIC_URL
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"

# 5. Fresh clone in the temp folder. Do not clone first.
a2_branch=${A2_BRANCH:-cursor/a2-mac-runbook-f873}
a2_url=${A2_REMOTE:-https://github.com/Elacity/elastos-agent-host-spike.git}
a2_clone="$a2_workdir/src"
if [ -e "$a2_clone" ]; then
  a2_finish "NOT RUN" "clone path already exists inside the temp workdir"
fi
printf 'CLONE branch %s\n' "$a2_branch"
if ! git clone --branch "$a2_branch" "$a2_url" "$a2_clone"; then
  a2_finish "NOT RUN" "git clone failed; if git asked for a password, set A2_REMOTE=git@github.com:Elacity/elastos-agent-host-spike.git and paste again"
fi
cd -- "$a2_clone"
if [ ! -f lab/a2-e2e-resume/run.sh ] || [ ! -f lab/a2-e2e-resume/harness.py ] || [ ! -f lab/a2-e2e-resume/guest.sha256 ] || [ ! -f examples/agent-host/build.sh ]; then
  a2_finish "NOT RUN" "missing: lab/a2-e2e-resume scripts are not in this clone; stay on cursor/a2-mac-runbook-f873"
fi
if [ -n "$(git status --porcelain=v1)" ]; then
  a2_finish "NOT RUN" "the new clone has local changes"
fi
if ! git cat-file -e "${a2_pin_a2}^{commit}" 2>/dev/null; then
  git fetch --unshallow >/dev/null 2>&1 || true
fi
if ! git cat-file -e "${a2_pin_a2}^{commit}" 2>/dev/null; then
  git fetch -- "$a2_url" "$a2_pin_a2" >/dev/null 2>&1 || true
fi
if ! git cat-file -e "${a2_pin_a2}^{commit}" 2>/dev/null \
  || ! git merge-base --is-ancestor "$a2_pin_a2" HEAD; then
  a2_finish "NOT RUN" "clone is not a descendant of A2 head ${a2_pin_a2}"
fi

# 6. Rebuild the guest. Show old pin vs new hash. Write the pin only here.
printf 'BUILD guest\n'
if ! bash examples/agent-host/build.sh; then
  a2_finish "FAIL" "examples/agent-host/build.sh failed"
fi
a2_wasm="$a2_clone/examples/agent-host/agent-host.component.wasm"
if [ ! -f "$a2_wasm" ]; then
  a2_finish "FAIL" "guest wasm missing after build"
fi
a2_pin="$a2_clone/lab/a2-e2e-resume/guest.sha256"
a2_old=$(tr -d ' \t\r\n' < "$a2_pin")
a2_new=$(a2_hash_file "$a2_wasm")
printf 'GUEST_PIN old=%s\n' "$a2_old"
printf 'GUEST_PIN new=%s\n' "$a2_new"
if [ "$a2_old" = "$a2_new" ]; then
  printf 'GUEST_PIN unchanged after rebuild\n'
else
  printf 'GUEST_PIN differs; writing the new pin only inside the temp workdir\n'
fi
if ! python3 -I -c '
import os, sys
pin_r = os.path.realpath(sys.argv[1])
work_r = os.path.realpath(sys.argv[2])
raise SystemExit(0 if (pin_r == work_r or pin_r.startswith(work_r + os.sep)) else 1)
' "$a2_pin" "$a2_workdir"; then
  a2_finish "FAIL" "guest.sha256 resolves outside the temp workdir; pin not written"
fi
case $a2_new in
  *[!0-9a-f]*|'')
    a2_finish "FAIL" "built guest hash is not lowercase hex"
    ;;
esac
if [ "${#a2_new}" -ne 64 ]; then
  a2_finish "FAIL" "built guest hash is not a 64-char sha256"
fi
printf '%s\n' "$a2_new" > "$a2_pin"
if [ "$(tr -d ' \t\r\n' < "$a2_pin")" != "$a2_new" ] || [ "$(a2_hash_file "$a2_wasm")" != "$a2_new" ]; then
  a2_finish "FAIL" "guest hash does not match the workdir pin after write"
fi
if [ -n "$(git diff --cached --name-only)" ]; then
  a2_finish "FAIL" "the paste staged files; it must not"
fi

# 7. A2 journey in this clone only. Wait for run.sh and its children.
a2_journey_out="$a2_workdir/journey.out"
a2_wait_py="$a2_workdir/wait_journey.py"
cat > "$a2_wait_py" <<'A2WAIT'
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
lane = os.path.abspath("lab/a2-e2e-resume")
needles = []
for item in (workdir, lane, "lab/a2-e2e-resume"):
    if item not in needles:
        needles.append(item)

child = os.fork()
if child == 0:
    try:
        os.setpgrp()
    except PermissionError:
        pass
    os.execvp("bash", ["bash", "lab/a2-e2e-resume/run.sh"])
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
            sys.stderr.write("cannot list processes that name the A2 workdir\n")
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
A2WAIT
set +e
python3 -I "$a2_wait_py" "$a2_workdir" > "$a2_journey_out" 2>&1
a2_journey_rc=$?
set -e
cat "$a2_journey_out"
printf 'JOURNEY run.sh -> %s\n' "$a2_journey_rc"

a2_live=$(a2_hash_file "$a2_wasm")
a2_pin_now=$(tr -d ' \t\r\n' < "$a2_pin")
a2_tamper=""
if [ "$a2_live" != "$a2_pin_now" ]; then
  a2_tamper="tampered guest hash: wasm=${a2_live} pin=${a2_pin_now}"
fi
a2_evidence="$a2_clone/lab/a2-e2e-resume/evidence.txt"
a2_evidence_dir="$a2_clone/lab/a2-e2e-resume"
a2_evidence_snap="$a2_workdir/evidence.snap"
a2_score_path=$a2_evidence
a2_evidence_hash=""
if [ -L "$a2_evidence" ] || [ -e "$a2_evidence" ]; then
  if [ -L "$a2_evidence" ] || [ ! -f "$a2_evidence" ]; then
    a2_finish "FAIL" "evidence.txt is not a regular file in the clone"
  fi
  if ! python3 -I -c '
import os, sys
ev = os.path.realpath(sys.argv[1])
root = os.path.realpath(sys.argv[2])
raise SystemExit(0 if ev.startswith(root + os.sep) else 1)
' "$a2_evidence" "$a2_clone"; then
    a2_finish "FAIL" "evidence.txt resolves outside the temp clone"
  fi
  a2_writers=$(a2_lsof_writers "$a2_evidence_dir" "$a2_evidence")
  if [ -n "$a2_writers" ]; then
    a2_finish "FAIL" "evidence still has a live writer before the quiet period"
  fi
  a2_quiet_hash=$(a2_hash_file "$a2_evidence")
  sleep 15
  a2_writers=$(a2_lsof_writers "$a2_evidence_dir" "$a2_evidence")
  if [ -n "$a2_writers" ]; then
    a2_finish "FAIL" "evidence still has a live writer after the quiet period"
  fi
  if [ "$(a2_hash_file "$a2_evidence")" != "$a2_quiet_hash" ]; then
    a2_finish "FAIL" "evidence.txt changed during the quiet period; A2 cannot PASS on a moving file"
  fi
  cp -- "$a2_evidence" "$a2_evidence_snap"
  a2_evidence_hash=$(a2_hash_file "$a2_evidence")
  if [ "$(a2_hash_file "$a2_evidence_snap")" != "$a2_evidence_hash" ]; then
    a2_finish "FAIL" "evidence snapshot did not match the live file"
  fi
  a2_score_path=$a2_evidence_snap
fi

a2_score=$(python3 -I - "$a2_score_path" "$a2_tamper" <<'PY'
import pathlib
import sys

rows_order = ("WRITE", "STALE", "STOP", "START", "RESUME", "WRITE2")
evidence = pathlib.Path(sys.argv[1])
tamper = sys.argv[2]
if tamper:
    print("FAIL")
    print(tamper)
    print("")
    raise SystemExit(0)
if not evidence.is_file():
    print("FAIL")
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
counted = None
conflict = False
for line in raw.decode("ascii").splitlines():
    if line == "log:":
        break
    for name in rows_order:
        prefix = name + ": "
        if line.startswith(prefix):
            rest = line[len(prefix):]
            if rest.startswith("PASS"):
                result = "PASS"
            elif rest.startswith("FAIL"):
                result = "FAIL"
            elif rest.startswith("NOT RUN"):
                result = "NOT RUN"
            else:
                result = "UNKNOWN"
            if name in rows:
                conflict = True
            rows[name] = result
    if line.startswith("A2_counted:"):
        counted = line.split(":", 1)[1].strip()
body = "\n".join(f"{name}: {rows.get(name, 'MISSING')}" for name in rows_order)
if conflict:
    print("FAIL")
    print("evidence has duplicate or disagreeing rows")
    print(body)
    raise SystemExit(0)
fails = [name for name in rows_order if rows.get(name) == "FAIL"]
unknown = [name for name in rows_order if rows.get(name) == "UNKNOWN"]
if fails or unknown:
    print("FAIL")
    print("computed FAIL or unreadable row: " + ", ".join(fails + unknown))
    print(body)
    raise SystemExit(0)
missing = [name for name in rows_order if name not in rows]
notruns = [name for name in rows_order if rows.get(name) == "NOT RUN"]
if missing or notruns or counted != "yes" or any(rows.get(name) != "PASS" for name in rows_order):
    why = []
    if missing:
        why.append("missing rows " + ",".join(missing))
    if notruns:
        why.append("NOT RUN " + ",".join(notruns))
    if counted != "yes":
        why.append("A2_counted=" + str(counted))
    print("NOT RUN")
    print("; ".join(why) if why else "journey rows were not all computed PASS")
    print(body)
    raise SystemExit(0)
print("PASS")
print("every row is computed PASS and A2_counted is yes")
print(body)
PY
)

a2_verdict=$(printf '%s\n' "$a2_score" | sed -n '1p')
a2_reason=$(printf '%s\n' "$a2_score" | sed -n '2p')
a2_row_lines=$(printf '%s\n' "$a2_score" | sed -n '3,$p')

if [ -n "$a2_evidence_hash" ]; then
  if [ ! -f "$a2_evidence" ] || [ "$(a2_hash_file "$a2_evidence")" != "$a2_evidence_hash" ]; then
    a2_finish "FAIL" "evidence.txt changed after the snapshot; A2 cannot PASS on a moving file"
  fi
  if [ "$(a2_hash_file "$a2_evidence_snap")" != "$a2_evidence_hash" ]; then
    a2_finish "FAIL" "evidence snapshot was altered after it was taken"
  fi
fi
if [ "$a2_elastos_home_before" = ABSENT ] && [ -e "$HOME/.elastos" ]; then
  a2_finish "FAIL" "this run created $HOME/.elastos; A2 must stay inside the temp workdir"
fi
if [ "$a2_elastos_login_before" = ABSENT ] && [ -e "$a2_login_home/.elastos" ]; then
  a2_finish "FAIL" "this run created $a2_login_home/.elastos; A2 must stay inside the temp workdir"
fi
if [ "$a2_elastos_home_before" = PRESENT ]; then
  a2_snapshot_tree "$HOME/.elastos" > "$a2_workdir/elastos-home.after"
  if ! cmp -s "$a2_elastos_home_snap" "$a2_workdir/elastos-home.after"; then
    a2_finish "FAIL" "this run changed $HOME/.elastos; A2 must stay inside the temp workdir"
  fi
fi
if [ "$a2_elastos_login_before" = PRESENT ]; then
  a2_snapshot_tree "$a2_login_home/.elastos" > "$a2_workdir/elastos-login.after"
  if ! cmp -s "$a2_elastos_login_snap" "$a2_workdir/elastos-login.after"; then
    a2_finish "FAIL" "this run changed $a2_login_home/.elastos; A2 must stay inside the temp workdir"
  fi
fi
if [ "$a2_verdict" != "PASS" ] && [ "$a2_verdict" != "FAIL" ] && [ "$a2_verdict" != "NOT RUN" ]; then
  a2_finish "NOT RUN" "scorer printed no verdict"
fi
if [ "$a2_verdict" = PASS ] && [ "${a2_journey_rc:-1}" -ne 0 ]; then
  a2_finish "FAIL" "run.sh exited ${a2_journey_rc}; A2 cannot PASS while the journey or its falsifiers failed"
fi
a2_survived=0
if grep -q SURVIVED "$a2_journey_out" 2>/dev/null; then
  a2_survived=1
fi
if [ "$a2_verdict" = PASS ] && [ "$a2_survived" -eq 1 ]; then
  a2_finish "FAIL" "run.sh printed SURVIVED; A2 cannot PASS while a falsifier survived"
fi
a2_finish "$a2_verdict" "$a2_reason"
```

The default clone is branch `cursor/a2-mac-runbook-f873`. That branch
starts at the reviewed A2 head `9e7a85d6` and adds only this folder.
`spike/agent-host` does not have `lab/a2-e2e-resume` yet.

Keep the temp folder until you have copied `summary.txt`. The paste
does not delete it. It never deletes anything outside that folder.

## What the last line means

| Last line | Meaning |
| --- | --- |
| `A2: PASS.` | Every journey row is a **computed** PASS, each of the six names appears exactly once, `A2_counted` is yes, `run.sh` and any process that still names the temp dir or `lab/a2-e2e-resume` exited 0 with no SURVIVED line, `evidence.txt` is a regular file inside the temp clone with no CR or non-ASCII byte, `lsof` showed no writer, a 15s quiet re-hash stayed still, and the guest bytes still match the pin written in the temp folder. |
| `A2: FAIL.` | A row failed, a row name appeared twice, `run.sh` exited nonzero, a falsifier printed SURVIVED, the guest hash was tampered, `evidence.txt` was a symlink or lived outside the clone, a quiet-period hash moved, a live writer remained, or the run created or changed `~/.elastos` under `$HOME` or the login home. |
| `A2: NOT RUN.` | A named prerequisite was missing, the clone is not a descendant of A2 head `9e7a85d6`, or a row was skipped. A2 is not booked. |

`Proof.row` on the A2 harness still refuses a hardcoded PASS. This
paste does not print `A2: PASS.` unless it parsed the six rows from a
snapshot of `lab/a2-e2e-resume/evidence.txt` taken after `run.sh`, any
process that still names the temp dir, and a 15s quiet re-hash.

## What this paste does not do

- It does not run `elastos serve`.
- It does not use Sash's real Home. `XDG_*` points at the temp folder.
  `HOME` stays your login home so rustup and cargo keep working. The
  paste watches both `$HOME/.elastos` and the login-home `~/.elastos`
  (`eval echo ~$(id -un)`, or `dscl` on a Mac). It refuses if it
  creates either path, and it refuses if an already-present tree
  changes.
- It does not overwrite `guest.sha256` in any checkout you already
  have. The new pin is written only under the temp clone.
- It does not run `sudo`, `xcode-select --install`, or the rustup.rs
  installer.
- It does not delete `/Users/sash/code/wt-agent-host` or any other
  path outside the temp folder.

## After a PASS

Send that `summary.txt`, plus the two `GUEST_PIN` lines (old and new).
The Linux pin from #351 will not match a Mac rebuild. That is
expected. Do not copy the new pin back into a committed file unless
you mean to re-pin for Mac.

## Linux dry-run of this fence

This cloud session is Linux. It cannot book A2. The recorder at
`lab/a2-mac-runbook/dryrun.py` pastes the same fence with a macOS
`uname` / `xcode-select` shim and a stub guest.

```sh
python3 -I lab/a2-mac-runbook/dryrun.py
```

A14-style booking still needs Sash's Mac. Label every Linux result
**NOT RUN ON MAC**.
