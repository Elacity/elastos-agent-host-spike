# Shared guards for lab/jetson-proof-kit. Sourced by run-on-jetson.sh and the
# tests. This file performs no work on its own.

JPK_MEM_FLOOR_KB=1048576
JPK_ROOT_NAME=flint-elastos-test
JPK_BUILD_JOBS=4
JPK_C0_BRANCH=cursor/fail-closed-linux-0b95
JPK_C0_SHA=129fdc98428c9029b328976511478c46ebe765a6
JPK_C9_BRANCH=cursor/linux-confine-e156
JPK_C9_SHA=2dc3c565c6649d668f1e50efefeea7d964330f9c
JPK_DEFAULT_REMOTE=https://github.com/Elacity/elastos-agent-host-spike.git

jpk_allowed_root() {
    printf '%s/%s\n' "${HOME:?HOME is required}" "$JPK_ROOT_NAME"
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

# Run a heavy command and stop it if MemAvailable drops below 1 GiB.
jpk_with_memory_guard() {
    local cmd kb
    jpk_require_memory || return 2
    "$@" &
    cmd=$!
    while kill -0 "$cmd" 2>/dev/null; do
        if ! kb=$(jpk_mem_available_kb) || [ "$kb" -lt "$JPK_MEM_FLOOR_KB" ]; then
            kill "$cmd" 2>/dev/null || true
            wait "$cmd" 2>/dev/null || true
            printf 'REFUSED available memory below 1 GiB (%s kB)\n' "${kb:-unknown}" >&2
            return 2
        fi
        sleep 1
    done
    wait "$cmd"
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
