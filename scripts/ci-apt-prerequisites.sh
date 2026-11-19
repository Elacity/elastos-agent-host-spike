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
    fallback_url=https://ftp.ports.ubuntu.com/ubuntu-ports
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
    as_root python3 - "$@" <<'PY'
import hashlib
from pathlib import Path
import subprocess
import sys

strict, options = sys.argv[1] == 'strict', sys.argv[2:]
for archive in Path('/var/cache/apt/archives').glob('*.deb'):
    try:
        if archive.is_symlink() or not archive.is_file():
            raise ValueError('apt archive requires a regular file')
        package, version, arch = subprocess.check_output([
            'dpkg-deb', '--show', '--showformat=${Package}\n${Version}\n${Architecture}\n',
            str(archive)], text=True).splitlines()
        index = subprocess.check_output(['apt-cache', *options, 'show', f'{package}:{arch}={version}'], text=True)
        hashes = [line.removeprefix('SHA256: ') for line in index.splitlines() if line.startswith('SHA256: ')]
        value = hashlib.sha256()
        with archive.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                value.update(chunk)
        if value.hexdigest() in hashes:
            continue
    except (subprocess.CalledProcessError, ValueError):
        pass
    archive.unlink()
    print(f'Removed unverified apt archive: {archive.name}', file=sys.stderr)
    if strict:
        raise SystemExit('Downloaded apt archive failed its signed-index SHA-256 check')
PY
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

if [[ -f "$marker" ]]; then
    cached_mirror=$(cat "$marker")
    if [[ "$cached_mirror" == default || "$cached_mirror" == fallback ]] &&
       [[ -n "$(find "$lists" -maxdepth 1 -name '*_InRelease' -print -quit)" ]]; then
        cached_sources="$sources/$cached_mirror"
        cached_options=("${options[@]}" -o "Dir::Etc::sourceparts=$cached_sources")
        verify_archives restore "${cached_options[@]}"
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
    [[ -z "${GITHUB_OUTPUT:-}" ]] || echo 'changed=true' >> "$GITHUB_OUTPUT"
    echo "apt: downloaded missing packages from $mirror"
    as_root chown -R "$(id -u):$(id -g)" "$archives" "$lists" "$marker"
    as_root install -d -o _apt -g root -m 700 "$archives/partial" "$lists/partial"
    # The cache action runs as the runner user and traverses the list directory.
    as_root chmod 755 "$lists/partial"
    exit 0
done
echo 'apt: both Ubuntu mirrors failed' >&2
exit 1
