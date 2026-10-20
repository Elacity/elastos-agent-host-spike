#!/usr/bin/env bash
# Build photo-viewer.component.wasm in one pinned Linux container, so every
# machine (Mac, cloud, CI) produces the same bytes. See README.md here.
set -euo pipefail

REPRO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${REPRO_DIR}/../../.." && pwd)"

# rust:1.91.0-slim-bookworm, index digest as pulled on 2026-10-20. Always
# linux/amd64: Cargo hashes `rustc -vV` (which names the host triple) into
# every crate's metadata, and that hash changes symbol names, LTO function
# order, and so the code bytes. One platform means one host triple.
IMAGE="rust:1.91.0-slim-bookworm@sha256:81c97592d519ba7397e8adccb0345fb5a91965c0a44b82af83bd1ef06c36cef5"
PLATFORM="linux/amd64"
# The same path the builder remaps the repository to, so no host path differs.
SRC="/src/elastos-runtime"

# A host that reaches the network through a proxy with its own CA (the cloud
# sessions) passes both in; a plain host (a Mac) passes nothing.
proxy_args=()
if [[ -n "${HTTPS_PROXY:-}" ]]; then
    proxy_args+=(--network host -e "HTTPS_PROXY=${HTTPS_PROXY}" -e "https_proxy=${HTTPS_PROXY}")
    proxy_args+=(-e "HTTP_PROXY=${HTTP_PROXY:-${HTTPS_PROXY}}" -e "http_proxy=${HTTP_PROXY:-${HTTPS_PROXY}}")
fi
if [[ -n "${ELASTOS_REPRO_CA:-}" ]]; then
    proxy_args+=(-v "${ELASTOS_REPRO_CA}:/etc/ssl/certs/repro-proxy-ca.crt:ro")
    proxy_args+=(-e "SSL_CERT_FILE=/etc/ssl/certs/repro-proxy-ca.crt")
    proxy_args+=(-e "CARGO_HTTP_CAINFO=/etc/ssl/certs/repro-proxy-ca.crt")
fi

# `${a[@]+"${a[@]}"}`: macOS bash 3.2 treats an empty array as unset under -u.
docker run --rm --platform "${PLATFORM}" \
    ${proxy_args[@]+"${proxy_args[@]}"} \
    -v "${REPO_ROOT}:${SRC}" \
    -w "${SRC}" \
    -e HOME=/home/builder \
    -e CARGO_BUILD_BUILD_DIR=/tmp/elastos-build-dir \
    "${IMAGE}" \
    bash -euo pipefail -c '
        # python3 runs the builder checks and prints the hash; it does not
        # touch the artifact bytes. HTTPS mirror: some proxies refuse plain HTTP.
        sed -i "s|http://deb.debian.org|https://deb.debian.org|g" /etc/apt/sources.list.d/debian.sources
        apt_ca=()
        if [[ -n "${SSL_CERT_FILE:-}" ]]; then apt_ca=(-o "Acquire::https::CAInfo=${SSL_CERT_FILE}"); fi
        apt-get -qq "${apt_ca[@]}" update >/dev/null
        apt-get -qq "${apt_ca[@]}" install -y --no-install-recommends python3 >/dev/null
        rustup target add wasm32-unknown-unknown >/dev/null 2>&1
        rustc -vV | sed -n "1p;/^host/p"
        scripts/build-component-capsule.sh examples/photo-viewer
    '
