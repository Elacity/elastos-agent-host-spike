#!/bin/sh
# Read-only checks. Morning step 2 in lab/demo-a14/RUNBOOK.md.
# One "missing:" line per gap, then "preflight: OK" or "preflight: FAIL".
# Exit 0 when nothing is missing, 1 when something is, 2 on bad usage.
# This file creates nothing, deletes nothing, and installs nothing.
# macOS /bin/sh is Bash 3.2. This script stays within that shell.
# Usage: preflight.sh [repository]

set -eu

status=0

missing() {
  printf 'missing: %s\n' "$1"
  status=1
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    missing "$2"
  fi
}

need_exec() {
  if [ ! -x "$1" ]; then
    missing "$2"
  fi
}

avail_kb() {
  df -Pk "$1" 2>/dev/null | awk 'NR==2 { print $4 }'
}

device_of() {
  df -Pk "$1" 2>/dev/null | awk 'NR==2 { print $1 }'
}

enough_space() {
  # 40 GiB in 1 KiB blocks. The runbook says 40 GB; this is the larger reading.
  awk -v a="$1" 'BEGIN { exit (a+0 >= 41943040) ? 0 : 1 }'
}

gib() {
  awk -v a="$1" 'BEGIN { printf "%.1f GiB", a/1024/1024 }'
}

check_space() {
  path=$1
  label=$2
  kb=$(avail_kb "$path" || true)
  case $kb in
    ''|*[!0-9]*)
      missing "free space for $label ($path) could not be read"
      ;;
    *)
      if ! enough_space "$kb"; then
        missing "free space for $label ($path) is $(gib "$kb"); the runbook asks for 40 GB"
      fi
      ;;
  esac
}

has_space() {
  case $2 in
    *' '*)
      missing "$1 contains a space ($2); the guest build puts that path in RUSTFLAGS, and rustc splits RUSTFLAGS on spaces"
      ;;
  esac
}

if [ "$#" -gt 1 ]; then
  printf 'usage: preflight.sh [repository]\n' >&2
  exit 2
fi

if [ "$#" -eq 1 ]; then
  start=$1
else
  start=$(pwd)
fi

repo=
if [ -d "$start" ]; then
  dir=$(cd "$start" && pwd -P) || dir=
  while [ -n "$dir" ] && [ "$dir" != "/" ]; do
    if [ -e "$dir/.git" ]; then
      repo=$dir
      break
    fi
    dir=$(dirname "$dir")
  done
fi

os=$(uname -s)
mach=$(uname -m)

if [ "$os" != Darwin ]; then
  missing "operating system is $os; A14's VERSIONS.json is produced on macOS"
fi

if [ "$os" = Darwin ]; then
  translated=0
  if command -v sysctl >/dev/null 2>&1; then
    translated=$(sysctl -n sysctl.proc_translated 2>/dev/null || printf '0')
  fi
  case $translated in
    1)
      missing "this shell is Rosetta (sysctl.proc_translated=1); open a native arm64 Terminal"
      ;;
  esac
fi

if [ "$mach" != arm64 ]; then
  missing "architecture is $mach; A14 needs native Apple Silicon (arm64)"
fi

if [ -z "$repo" ]; then
  missing "no git checkout at $start"
else
  for rel in \
    lab/demo-a14/install.sh \
    lab/demo-a14/run.sh \
    lab/demo-a14/demo.py \
    lab/demo-a14/RUNBOOK.md \
    lab/demo-a14/journeys.json \
    lab/demo-a14/preflight.sh
  do
    if [ ! -f "$repo/$rel" ]; then
      missing "$rel is not in this checkout; stay on cursor/demo-a14-installed-demo-83e1 until the demo is on spike/agent-host"
    fi
  done

  if ! dirty=$(GIT_OPTIONAL_LOCKS=0 git --no-optional-locks -C "$repo" status --porcelain=v1 --untracked-files=all 2>/dev/null); then
    missing "git status failed in $repo"
  elif [ -n "$dirty" ]; then
    count=$(printf '%s\n' "$dirty" | awk 'END { print NR }')
    missing "this checkout has local changes ($count paths); install.sh refuses a dirty tree"
  fi

  check_space "$repo" "the checkout"

  channel=
  toolchain=
  if [ -f "$repo/rust-toolchain.toml" ]; then
    channel=$(awk -F '"' '/^channel = / { print $2; exit }' "$repo/rust-toolchain.toml")
  fi
  if [ -z "$channel" ]; then
    missing "rust-toolchain.toml has no channel pin"
  fi

  case $os:$mach in
    Darwin:arm64) triple=aarch64-apple-darwin ;;
    Darwin:x86_64) triple=x86_64-apple-darwin ;;
    Linux:x86_64) triple=x86_64-unknown-linux-gnu ;;
    Linux:aarch64|Linux:arm64) triple=aarch64-unknown-linux-gnu ;;
    *) triple= ;;
  esac

  if [ -n "${RUSTUP_HOME:-}" ]; then
    rustup_home=$RUSTUP_HOME
  elif command -v rustup >/dev/null 2>&1; then
    rustup_home=$(RUSTUP_AUTO_INSTALL=0 rustup show home 2>/dev/null || true)
  else
    rustup_home=$HOME/.rustup
  fi
  if [ -z "$rustup_home" ]; then
    rustup_home=$HOME/.rustup
  fi
  if [ -n "$channel" ] && [ -n "$triple" ]; then
    toolchain=$rustup_home/toolchains/$channel-$triple
    if [ ! -x "$toolchain/bin/rustc" ] || [ ! -x "$toolchain/bin/cargo" ]; then
      missing "Rust toolchain $channel for $triple is not installed under $rustup_home; preflight does not install it"
    elif [ ! -d "$toolchain/lib/rustlib/wasm32-unknown-unknown" ]; then
      missing "wasm32-unknown-unknown is not installed for $channel; the guest build needs it, and the five morning steps do not add it"
    fi
  fi

  has_space "the checkout path" "$repo"
  if [ -n "$toolchain" ] && [ -d "$toolchain" ]; then
    has_space "the Rust sysroot" "$toolchain"
  fi

  if [ "$os" = Darwin ] && command -v xattr >/dev/null 2>&1; then
    for rel in lab/demo-a14/install.sh lab/demo-a14/run.sh lab/demo-a14/demo.py; do
      if [ -f "$repo/$rel" ] && xattr -p com.apple.quarantine "$repo/$rel" >/dev/null 2>&1; then
        missing "$rel carries com.apple.quarantine; clone the repository with git so macOS does not treat the built programs as downloaded files"
      fi
    done
  fi
fi

home_phys=$(cd "$HOME" && pwd -P) || home_phys=$HOME
if [ -n "$repo" ]; then
  home_dev=$(device_of "$home_phys" || true)
  repo_dev=$(device_of "$repo" || true)
  if [ -z "$home_dev" ] || [ "$home_dev" != "$repo_dev" ]; then
    check_space "$home_phys" "the home directory"
  fi
else
  check_space "$home_phys" "the home directory"
fi

has_space "HOME" "$home_phys"
cargo_home=${CARGO_HOME:-$HOME/.cargo}
has_space "CARGO_HOME" "$cargo_home"

if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  target=$CARGO_TARGET_DIR
  case $target in
    /*) ;;
    *)
      if [ -n "$repo" ]; then
        target=$repo/$target
      fi
      ;;
  esac
  if [ -d "$target" ]; then
    target=$(cd "$target" && pwd -P) || target=$CARGO_TARGET_DIR
  fi
  outside=1
  if [ -n "$repo" ]; then
    case $target in
      "$repo"|"$repo"/*) outside=0 ;;
    esac
  fi
  if [ "$outside" -eq 1 ]; then
    missing "CARGO_TARGET_DIR=$CARGO_TARGET_DIR is outside the repository; install records test executables only from inside the checkout and refuses these"
  fi
fi

case ${CARGO_TERM_COLOR:-} in
  always)
    missing "CARGO_TERM_COLOR=always; run.sh reads Cargo's plain 'Running' line for A8, so the variable needs to be unset or set to never"
    ;;
esac

if [ -n "${DEMO_A14_HOME:-}" ]; then
  demo_home=$DEMO_A14_HOME
  case $demo_home in
    '~') demo_home=$HOME ;;
    '~'/*) demo_home=$HOME/${DEMO_A14_HOME#\~/} ;;
  esac
  if [ -d "$demo_home" ]; then
    demo_home=$(cd "$demo_home" && pwd -P) || demo_home=$DEMO_A14_HOME
  fi
  if [ -n "$repo" ]; then
    case $demo_home in
      "$repo"|"$repo"/*)
        missing "DEMO_A14_HOME=$DEMO_A14_HOME is inside the repository; install.sh refuses that"
        ;;
    esac
  fi
fi

need_cmd git "git is not on PATH"
need_cmd bash "bash is not on PATH (install.sh and run.sh are bash scripts)"
need_cmd python3 "python3 is not on PATH"
need_cmd ssh-keygen "ssh-keygen is not on PATH (install.sh --sign uses it to sign the receipts)"
need_cmd rustup "rustup is not on PATH"
need_cmd curl "curl is not on PATH (this check uses it only to see whether crates.io answers)"

if command -v python3 >/dev/null 2>&1; then
  py=$(python3 -I -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null) || py=
  if [ -z "$py" ]; then
    missing "python3 -I does not run; install.sh starts the demo with python3 -I"
  else
    py_major=$(printf '%s' "$py" | awk -F. '{ print $1 }')
    py_minor=$(printf '%s' "$py" | awk -F. '{ print $2 }')
    if [ "$py_major" -lt 3 ] || { [ "$py_major" -eq 3 ] && [ "$py_minor" -lt 9 ]; }; then
      missing "python3 is $py; install.sh was tested on Python 3.9 and newer"
    fi
  fi
fi

if command -v ssh-keygen >/dev/null 2>&1; then
  yout=$(ssh-keygen -Y verify -f /dev/null -I demo-a14 -n demo-a14-receipt -s /dev/null </dev/null 2>&1) || true
  case $yout in
    *unknown\ option*|*illegal\ option*|*invalid\ option*|*unrecognized\ option*)
      missing "ssh-keygen has no -Y sign support; the receipt signature needs OpenSSH 8.1 or newer"
      ;;
  esac
fi

need_exec /usr/bin/shasum "/usr/bin/shasum is missing; the conformance run hashes binaries with this path"
need_exec /usr/bin/sandbox-exec "/usr/bin/sandbox-exec is missing; the C1-C7 steps run provider profiles with this macOS program"
need_exec /usr/sbin/lsof "/usr/sbin/lsof is missing; the conformance run checks earlier homes with this path"

if [ "$os" = Darwin ]; then
  if ! command -v xcode-select >/dev/null 2>&1 || ! xcode-select -p >/dev/null 2>&1; then
    missing "Xcode command line tools are not installed; run xcode-select --install"
  fi
  need_cmd open "open is not on PATH; morning step 5 uses it to show the run folder"
fi

if command -v curl >/dev/null 2>&1; then
  if ! curl -fsS --max-time 2 --retry 0 -o /dev/null https://index.crates.io/; then
    missing "crates.io did not answer within 2 seconds; install step 1 runs cargo fetch"
  fi
fi

if [ "$status" -eq 0 ]; then
  printf 'preflight: OK\n'
  exit 0
fi

printf 'preflight: FAIL\n'
exit 1
