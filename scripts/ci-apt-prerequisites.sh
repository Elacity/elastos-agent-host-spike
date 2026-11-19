#!/usr/bin/env bash
# CI caches Ubuntu's authenticated indexes with the package archives they name.
set -euo pipefail

started=$SECONDS
mirror_used=none
as_root() {
    if (( EUID == 0 )); then "$@"; else sudo "$@"; fi
}

read -r -a packages <<< "${CI_APT_PACKAGES:-${ENGINE_BUILD_TOOLS:?Set CI_APT_PACKAGES or ENGINE_BUILD_TOOLS}}"
(( ${#packages[@]} > 0 ))
archives=/var/cache/apt/archives
lists=/var/cache/apt/ci-lists
marker=/var/cache/apt/ci-mirror
manifest=/var/cache/apt/ci-packages
sources="$(mktemp -d)"
# ShellCheck does not track functions called by EXIT traps.
# shellcheck disable=SC2329
finish() {
    rm -rf "$sources"
    echo "apt: mirror=${mirror_used}, elapsed=$((SECONDS - started))s"
}
trap finish EXIT
mkdir -p "$sources/default" "$sources/fallback"
# Read only Ubuntu sources. Runner-added repositories stay outside this step.
for file in /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources; do
    if [[ -f "$file" ]]; then
        name=$(basename "$file")
        [[ "$name" != sources.list ]] || name=ubuntu.list
        cp "$file" "$sources/default/$name"
        cp "$file" "$sources/fallback/$name"
    fi
done
[[ -n "$(ls -A "$sources/default")" ]]

if [[ "$(dpkg --print-architecture)" == arm64 ]]; then
    fallback_url=http://ftp.ports.ubuntu.com/ubuntu-ports
    if grep -qr 'ftp\.ports\.ubuntu\.com' "$sources/default"; then
        fallback_url=http://ports.ubuntu.com/ubuntu-ports
    fi
    for file in "$sources/fallback"/*; do
        sed -i -e "s#mirror+file:/etc/apt/apt-mirrors.txt#$fallback_url#g" \
            -e "s#https\?://\(ftp\.\)\?ports\.ubuntu\.com/ubuntu-ports#$fallback_url#g" "$file"
    done
else
    fallback_url=http://azure.archive.ubuntu.com/ubuntu
    if grep -EqR 'azure\.archive\.ubuntu\.com|mirror\+file:' "$sources/default"; then
        fallback_url=http://archive.ubuntu.com/ubuntu
    fi
    for file in "$sources/fallback"/*; do
        sed -i -e "s#mirror+file:/etc/apt/apt-mirrors.txt#$fallback_url#g" \
            -e "s#https\?://\(azure\.\)\?archive\.ubuntu\.com/ubuntu#$fallback_url#g" \
            -e "s#https\?://security\.ubuntu\.com/ubuntu#$fallback_url#g" "$file"
    done
fi

options=(-o "Dir::Etc::sourcelist=/dev/null" -o "Dir::State::lists=$lists"
         -o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30
         -o Acquire::AllowInsecureRepositories=false -o APT::Get::AllowUnauthenticated=false
         -o APT::Keep-Downloaded-Packages=true -o Binary::apt::APT::Keep-Downloaded-Packages=true
         -o APT::Update::Error-Mode=any)
as_root install -d -m 755 "$archives" "$lists"
as_root install -d -o _apt -g root -m 700 "$archives/partial" "$lists/partial"

verify_archives() {
    # APT can reuse a .deb by size. Check its full hash against the index
    # authenticated when the trusted cache writer fetched it.
    local strict=$1 archive metadata package version arch digest
    # dpkg-deb expands these fields; the shell must keep them literal.
    # shellcheck disable=SC2016
    local showformat='${Package} ${Version} ${Architecture}\n'
    shift
    for archive in "$archives"/*.deb; do
        [[ -e "$archive" || -L "$archive" ]] || continue
        if [[ -f "$archive" && ! -L "$archive" ]] &&
           metadata=$(as_root dpkg-deb --show --showformat="$showformat" "$archive") &&
           read -r package version arch <<< "$metadata" &&
           [[ -n "$package" && -n "$version" && -n "$arch" ]] &&
           digest=$(as_root sha256sum "$archive") &&
           as_root apt-cache "$@" show "$package:$arch=$version" |
               awk -v hash="${digest%% *}" '$1 == "SHA256:" && $2 == hash { found=1 } END { exit !found }'; then
            continue
        fi
        as_root rm -f -- "$archive"
        echo "Removed unverified apt archive: ${archive##*/}" >&2
        if [[ "$strict" == strict ]]; then
            echo 'Downloaded apt archive failed its signed-index SHA-256 check' >&2
            return 1
        fi
    done
}

verify_cached_lists() {
    # APT may store Packages as local LZ4; apt-helper expands it to the bytes
    # whose SHA-256 appears in the verified InRelease.
    local inrelease base package_file suffix component rest arch expected digest actual matched
    local inreleases=("$lists"/*_InRelease) package_files=("$lists"/*_Packages*)
    [[ -f "${inreleases[0]}" && -f "${package_files[0]}" ]] || return 1
    for inrelease in "${inreleases[@]}"; do
        [[ -f "$inrelease" && ! -L "$inrelease" ]] || return 1
        as_root gpgv --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg "$inrelease" >/dev/null 2>&1 || return 1
    done
    for package_file in "${package_files[@]}"; do
        [[ -f "$package_file" && ! -L "$package_file" ]] || return 1
        matched=false
        for inrelease in "${inreleases[@]}"; do
            base=${inrelease%_InRelease}
            [[ "$package_file" == "$base"_* ]] || continue
            suffix=${package_file#"$base"_}
            component=${suffix%%_*}
            rest=${suffix#*_binary-}
            [[ "$rest" != "$suffix" && "$rest" == *_Packages* ]] || return 1
            arch=${rest%%_Packages*}
            [[ -n "$component" && -n "$arch" ]] || return 1
            expected="$component/binary-$arch/Packages"
            digest=$(awk -v path="$expected" '
                $0 == "SHA256:" { section=1; next }
                section && /^[A-Za-z0-9-]+:/ { exit }
                section && $3 == path { print $1; count++ }
                END { if (count != 1) exit 1 }
            ' "$inrelease") || return 1
            actual=$(as_root /usr/lib/apt/apt-helper cat-file "$package_file" | sha256sum | awk '{ print $1 }') || return 1
            [[ "$actual" == "$digest" ]] || return 1
            matched=true
            break
        done
        [[ "$matched" == true ]] || return 1
    done
}

archive_manifest() {
    local archive metadata package version arch
    # shellcheck disable=SC2016
    local showformat='${Package} ${Version} ${Architecture}\n'
    for archive in "$archives"/*.deb; do
        [[ -f "$archive" && ! -L "$archive" ]] || continue
        metadata=$(as_root dpkg-deb --show --showformat="$showformat" "$archive") || return 1
        read -r package version arch <<< "$metadata"
        [[ -n "$package" && -n "$version" && -n "$arch" ]] || return 1
        printf '%s:%s=%s\n' "$package" "$arch" "$version"
    done | sort -u
}

install_offline() {
    local source_dir=$1
    local apt_options=("${options[@]}" -o "Dir::Etc::sourceparts=$source_dir")
    # --download-only --no-download checks the full dependency plan before
    # installation. A partial archive cache fails without a network request.
    as_root apt-get "${apt_options[@]}" install --download-only --no-download -y --no-install-recommends "${packages[@]}" &&
        as_root env DEBIAN_FRONTEND=noninteractive timeout --kill-after=5s 180s \
            apt-get "${apt_options[@]}" install --no-download -y --no-install-recommends "${packages[@]}"
}

refresh=false
if [[ "${GITHUB_EVENT_NAME:-}" == push &&
      ( "${GITHUB_REF:-}" == refs/heads/spike/agent-host || "${GITHUB_REF:-}" == refs/heads/develop ) ]] ||
   [[ "${GITHUB_EVENT_NAME:-}" == schedule && "${GITHUB_REF:-}" == refs/heads/spike/agent-host ]]; then
    refresh=true
fi

cache_valid=false
previous_manifest=
if [[ -f "$marker" ]]; then
    cached_mirror=$(cat "$marker")
    if [[ "$cached_mirror" == default || "$cached_mirror" == fallback ]] &&
       [[ -n "$(find "$lists" -maxdepth 1 -name '*_InRelease' -print -quit)" ]]; then
        cached_sources="$sources/$cached_mirror"
        cached_options=("${options[@]}" -o "Dir::Etc::sourceparts=$cached_sources")
        if verify_cached_lists; then
            cache_valid=true
            [[ ! -f "$manifest" ]] || previous_manifest=$(cat "$manifest")
            verify_archives restore "${cached_options[@]}"
            # A cache hit installs the versions from the last trusted refresh.
            if [[ "$refresh" == false ]] && install_offline "$cached_sources"; then
                mirror_used="cache ($cached_mirror)"
                echo 'apt: cache hit, downloaded 0 packages'
                exit 0
            fi
            if [[ "$refresh" == true ]]; then
                echo 'apt: trusted cache writer; refreshing Ubuntu indexes'
            else
                echo 'apt: partial cache; fetching missing packages'
            fi
        else
            echo 'apt: cached Ubuntu indexes failed verification; fetching signed indexes' >&2
            as_root find "$lists" -maxdepth 1 -type f -delete
        fi
    fi
fi

echo 'apt: using runner default Ubuntu mirror'
grep -hE '^(URIs:|deb )' "$sources/default"/* || true
if grep -qR 'mirror+file:/etc/apt/apt-mirrors.txt' "$sources/default" &&
   [[ -f /etc/apt/apt-mirrors.txt ]]; then
    echo 'apt: runner mirror list:'
    cat /etc/apt/apt-mirrors.txt
fi
for mirror in default fallback; do
    if [[ "$mirror" == fallback ]]; then echo "apt: trying fallback mirror $fallback_url"; fi
    mirror_used=$mirror
    source_dir="$sources/$mirror"
    apt_options=("${options[@]}" -o "Dir::Etc::sourceparts=$source_dir")
    # A failed update can leave incomplete lists. The next mirror starts clean.
    as_root find "$lists" -maxdepth 1 -type f -delete
    if ! as_root timeout --kill-after=5s 135s apt-get "${apt_options[@]}" update; then
        echo "apt: $mirror update failed" >&2
        continue
    fi
    verify_archives restore "${apt_options[@]}"
    if ! as_root timeout --kill-after=5s 135s apt-get "${apt_options[@]}" install \
        --download-only -y --no-install-recommends "${packages[@]}"; then
        echo "apt: $mirror download failed" >&2
        continue
    fi
    verify_archives strict "${apt_options[@]}"
    archives_to_save=$(find "$archives" -maxdepth 1 -type f -name '*.deb' -print | sort)
    if ! install_offline "$source_dir"; then
        echo "apt: $mirror offline install failed" >&2
        exit 1
    fi
    if [[ "$(find "$archives" -maxdepth 1 -type f -name '*.deb' -print | sort)" != "$archives_to_save" ]]; then
        echo 'apt: install removed a downloaded archive; refusing an incomplete cache' >&2
        exit 1
    fi
    printf '%s\n' "$mirror" | as_root tee "$marker" >/dev/null
    current_manifest=$(archive_manifest)
    printf '%s\n' "$current_manifest" | as_root tee "$manifest" >/dev/null
    if [[ "$cache_valid" == false || "$current_manifest" != "$previous_manifest" ]]; then
        [[ -z "${GITHUB_OUTPUT:-}" ]] || echo 'changed=true' >> "$GITHUB_OUTPUT"
    else
        echo 'apt: package versions unchanged; retaining existing cache'
    fi
    echo "apt: downloaded missing packages from $mirror"
    as_root chown -R "$(id -u):$(id -g)" "$archives" "$lists" "$marker" "$manifest"
    as_root install -d -o _apt -g root -m 700 "$archives/partial" "$lists/partial"
    # The cache action runs as the runner user and traverses the list directory.
    as_root chmod 755 "$lists/partial"
    exit 0
done
echo 'apt: both Ubuntu mirrors failed' >&2
exit 1
