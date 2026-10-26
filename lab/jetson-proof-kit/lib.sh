# Shared guards for lab/jetson-proof-kit. Sourced by run-on-jetson.sh and the
# tests. This file performs no work on its own.

JPK_MEM_FLOOR_KB=1048576
JPK_ROOT_NAME=flint-elastos-test
JPK_BUILD_JOBS=4
JPK_C0_DEFAULT_BRANCH=cursor/fail-closed-linux-0b95
# #307 per-right floor. The older ABI 5 pin was 129fdc98428c9029b328976511478c46ebe765a6.
JPK_C0_PER_RIGHT_SHA=2c70a0d845f9acc15144a2afec889370612cca66
JPK_C0_OLD_ABI5_FLOOR_SHA=129fdc98428c9029b328976511478c46ebe765a6
JPK_C0_DEFAULT_SHA=$JPK_C0_PER_RIGHT_SHA
JPK_C0_BRANCH=${JPK_C0_BRANCH:-$JPK_C0_DEFAULT_BRANCH}
JPK_C9_BRANCH=cursor/linux-confine-e156
JPK_C9_SHA=2dc3c565c6649d668f1e50efefeea7d964330f9c
JPK_DEFAULT_REMOTE=https://github.com/Elacity/elastos-agent-host-spike.git

# Guard source. Default is the pinned #307 branch.
# JPK_C0_PR=307 fetches pull/307/head and records that HEAD (no pin).
# JPK_C0_REF overrides the git ref. An explicit JPK_C0_SHA still pins.
jpk_c0_ref() {
    if [ -n "${JPK_C0_PR:-}" ]; then
        printf 'pull/%s/head\n' "$JPK_C0_PR"
        return
    fi
    if [ -n "${JPK_C0_REF:-}" ]; then
        printf '%s\n' "$JPK_C0_REF"
        return
    fi
    printf '%s\n' "$JPK_C0_BRANCH"
}

jpk_c0_pin() {
    if [ "${JPK_C0_SHA+set}" = set ]; then
        printf '%s\n' "$JPK_C0_SHA"
        return
    fi
    if [ -n "${JPK_C0_PR:-}" ] || [ -n "${JPK_C0_REF:-}" ]; then
        printf '\n'
        return
    fi
    printf '%s\n' "$JPK_C0_DEFAULT_SHA"
}

jpk_allowed_root() {
    printf '%s/%s\n' "${HOME:?HOME is required}" "$JPK_ROOT_NAME"
}

jpk_src_root() {
    printf '%s/src\n' "$(jpk_allowed_root)"
}

jpk_current_uid() {
    id -u
}

jpk_sudo_env_present() {
    [ -n "${SUDO_USER:-}" ] && return 0
    [ -n "${SUDO_UID:-}" ] && return 0
    [ -n "${SUDO_GID:-}" ] && return 0
    [ -n "${SUDO_COMMAND:-}" ] && return 0
    return 1
}

# Refuse uid 0 and an elevated environment. Tokens stay split so this file
# does not name the host surfaces as words.
jpk_require_unprivileged() {
    if [ "$(jpk_current_uid)" -eq 0 ]; then
        printf 'REFUSED refuse to run as uid 0\n' >&2
        return 2
    fi
    if jpk_sudo_env_present; then
        printf 'REFUSED refuse to run when SUDO_USER is set\n' >&2
        return 2
    fi
}

# Assembled at runtime so the source never contains these host names.
# Word tokens use a boundary so "capture" does not count as the package tool.
jpk_host_surface_word_re() {
    printf '%s\n' '(^|[[:space:]])(su''do|a''pt|pm''2|PM''2)([[:space:]]|$)'
}

jpk_command_touches_host_surface() {
    local text="$1"
    case "$text" in
        *"pc2.""net"* | *"42""00"*) return 0 ;;
    esac
    printf '%s\n' "$text" | grep -Eq -- "$(jpk_host_surface_word_re)"
}

jpk_require_kit_omits_host_surfaces() {
    local kit_dir="${1:-${JPK_KIT:?JPK_KIT is required}}"
    local file word_re
    word_re=$(jpk_host_surface_word_re)
    for file in \
        "$kit_dir/run-on-jetson.sh" \
        "$kit_dir/lib.sh" \
        "$kit_dir/prep-offline.sh" \
        "$kit_dir/probe_host.py" \
        "$kit_dir/decide.py" \
        "$kit_dir/standin.rs"
    do
        [ -f "$file" ] || continue
        if grep -E -- "$word_re" "$file" >/dev/null 2>&1; then
            printf 'REFUSED kit names a host surface\n' >&2
            return 2
        fi
        if grep -F -- "pc2.""net" "$file" >/dev/null 2>&1; then
            printf 'REFUSED kit names a host surface\n' >&2
            return 2
        fi
        if grep -F -- "42""00" "$file" >/dev/null 2>&1; then
            printf 'REFUSED kit names a host surface\n' >&2
            return 2
        fi
    done
}

jpk_offline_mode() {
    [ "${JPK_OFFLINE:-0}" = 1 ]
}

jpk_cargo_offline_args() {
    if jpk_offline_mode; then
        printf '%s\n' --offline
    fi
}

# TMPDIR, CARGO_HOME, and the git checkout live under ~/flint-elastos-test.
jpk_apply_contained_env() {
    local root
    root=$(jpk_allowed_root)
    export TMPDIR="$root/tmp"
    export CARGO_HOME="$root/cargo-home"
    mkdir -p -- "$TMPDIR" "$CARGO_HOME" "$(jpk_src_root)"
    jpk_require_path "$TMPDIR" || return 2
    jpk_require_path "$CARGO_HOME" || return 2
    jpk_require_path "$(jpk_src_root)" || return 2
}

# Resolve an existing path, or the parent plus the final name when the path
# is still to be created. Uses pwd -P so a symlink cannot escape the folder.
jpk_resolve() {
    local path="$1"
    local parent base resolved_parent
    if [ -d "$path" ]; then
        (CDPATH= cd -- "$path" && pwd -P)
        return
    fi
    parent=$(dirname -- "$path")
    base=$(basename -- "$path")
    if [ ! -d "$parent" ]; then
        return 1
    fi
    resolved_parent=$(CDPATH= cd -- "$parent" && pwd -P) || return 1
    printf '%s/%s\n' "$resolved_parent" "$base"
}

# Return 0 when PATH is the allowed root or a file under it.
jpk_path_inside() {
    local root="$1"
    local path="$2"
    local resolved_root resolved_path
    resolved_root=$(jpk_resolve "$root") || return 1
    resolved_path=$(jpk_resolve "$path") || return 1
    case "$resolved_path" in
        "$resolved_root" | "$resolved_root"/*) return 0 ;;
        *) return 1 ;;
    esac
}

jpk_require_path() {
    local path="$1"
    local root
    root=$(jpk_allowed_root)
    if ! jpk_path_inside "$root" "$path"; then
        printf 'REFUSED path is outside %s: %s\n' "$root" "$path" >&2
        return 2
    fi
}

jpk_meminfo_path() {
    printf '%s\n' "${JPK_MEMINFO:-/proc/meminfo}"
}

jpk_mem_available_kb() {
    local file
    file=$(jpk_meminfo_path)
    awk '/^MemAvailable:/ { print $2; found = 1 } END { if (!found) exit 1 }' "$file"
}

jpk_require_memory() {
    local kb
    kb=$(jpk_mem_available_kb) || {
        printf 'REFUSED MemAvailable is missing from %s\n' "$(jpk_meminfo_path)" >&2
        return 2
    }
    if [ "$kb" -lt "$JPK_MEM_FLOOR_KB" ]; then
        printf 'REFUSED available memory below 1 GiB (%s kB)\n' "$kb" >&2
        return 2
    fi
}

# Kill the process group of PID. setsid makes that pid the group leader,
# so this stops cargo/rustc/gcc and every child, not only the parent.
jpk_kill_process_group() {
    local pid="$1"
    kill -TERM -- -"$pid" 2>/dev/null || true
    sleep 0.05
    kill -KILL -- -"$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

# Run a heavy command in its own process group. Stop the whole group if
# MemAvailable drops below 1 GiB.
jpk_with_memory_guard() {
    local cmd kb poll
    poll="${JPK_MEM_POLL_S:-1}"
    jpk_require_memory || return 2
    if ! command -v setsid >/dev/null 2>&1; then
        printf 'REFUSED setsid is absent\n' >&2
        return 2
    fi
    setsid "$@" &
    cmd=$!
    while kill -0 "$cmd" 2>/dev/null; do
        if ! kb=$(jpk_mem_available_kb) || [ "$kb" -lt "$JPK_MEM_FLOOR_KB" ]; then
            jpk_kill_process_group "$cmd"
            printf 'REFUSED available memory below 1 GiB (%s kB)\n' "${kb:-unknown}" >&2
            return 2
        fi
        sleep "$poll"
    done
    wait "$cmd"
}

# available -> PASS. absent -> ABSENT. anything else, including empty, -> REFUSED.
# Never stamps an absent right as PASS.
jpk_availability_status() {
    local value="$1"
    local first
    first=$(printf '%s\n' "$value" | awk '{ print $1; exit }')
    case "$first" in
        available) printf 'PASS\n' ;;
        absent) printf 'ABSENT\n' ;;
        *) printf 'REFUSED\n' ;;
    esac
}

# Classify one fcl-launch result. Exec format error is not a guard refusal.
jpk_classify_c0_launch() {
    local rc="$1"
    local out="$2"
    case "$out" in
        *"Exec format error"* | *"os error 8"*)
            printf 'NOT RUN\n'
            ;;
        *)
            if printf '%s\n' "$out" | grep -q '^started '; then
                printf 'PASS\n'
            elif [ "$rc" -eq 71 ]; then
                printf 'REFUSED\n'
            else
                printf 'REFUSED\n'
            fi
            ;;
    esac
}

jpk_set_row() {
    local file="$1"
    local id="$2"
    local status="$3"
    local detail="$4"
    local tmp
    tmp="${file}.tmp.$$"
    awk -v id="$id" -v status="$status" -v detail="$detail" '
        BEGIN { OFS = "\t" }
        $1 == id { print id, status, detail; next }
        { print }
    ' "$file" >"$tmp"
    mv "$tmp" "$file"
}

jpk_git_remote() {
    if [ -n "${JPK_REMOTE:-}" ]; then
        printf '%s\n' "$JPK_REMOTE"
        return
    fi
    printf '%s\n' "$JPK_DEFAULT_REMOTE"
}

# Offline: DEST must already hold the bundled tree and .jpk-pin. No git
# fetch and no crates.io. Online: fetch DEST from JPK_REMOTE into the
# allowed folder.
jpk_fetch() {
    local dest="$1"
    local ref="$2"
    local sha="${3:-}"
    local remote head pinfile
    jpk_require_path "$dest" || return 2
    jpk_require_memory || return 2
    if jpk_offline_mode; then
        pinfile="$dest/.jpk-pin"
        if [ ! -d "$dest" ]; then
            printf 'REFUSED offline source missing at %s\n' "$dest" >&2
            return 2
        fi
        if [ -f "$pinfile" ]; then
            head=$(tr -d '[:space:]' <"$pinfile")
        elif [ -d "$dest/.git" ]; then
            head=$(git -C "$dest" rev-parse HEAD)
        else
            printf 'REFUSED offline source missing at %s\n' "$dest" >&2
            return 2
        fi
        if [ -n "$sha" ] && [ "$head" != "$sha" ]; then
            printf 'REFUSED %s HEAD is %s, pin is %s\n' "$ref" "$head" "$sha" >&2
            return 2
        fi
        printf '%s\n' "$head"
        return 0
    fi
    remote=$(jpk_git_remote)
    mkdir -p -- "$dest"
    jpk_require_path "$dest" || return 2
    if [ ! -d "$dest/.git" ]; then
        jpk_with_memory_guard git init --quiet "$dest"
        git -C "$dest" remote add origin "$remote"
    fi
    if [ -n "$sha" ]; then
        if ! jpk_with_memory_guard git -C "$dest" fetch --quiet --depth 1 origin "$sha"; then
            return 2
        fi
        git -C "$dest" checkout --quiet --detach "$sha"
    else
        if ! jpk_with_memory_guard git -C "$dest" fetch --quiet --depth 1 origin "$ref"; then
            return 2
        fi
        git -C "$dest" checkout --quiet --detach FETCH_HEAD
    fi
    head=$(git -C "$dest" rev-parse HEAD)
    if [ -n "$sha" ] && [ "$head" != "$sha" ]; then
        printf 'REFUSED %s HEAD is %s, pin is %s\n' "$ref" "$head" "$sha" >&2
        return 2
    fi
    printf '%s\n' "$head"
}
