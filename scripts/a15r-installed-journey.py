#!/usr/bin/env python3
"""Stage one disposable signed Home for the A15-R installed journey.

The release envelope matches scripts/holder-canary-fixture.py sign_install:
one 32-byte key, elastos sign-payload for elastos.release.v1 and
elastos.release.head.v1, then the key is unlinked. This script also signs the
Agent Host capsule with that same key. holder-canary-fixture.py is unchanged
because its sign-install deletes the key before a caller could sign the capsule.
"""

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def raw_cid(digest):
    return "b" + base64.b32encode(b"\x01\x55\x12\x20" + digest).decode().lower().rstrip("=")


def descriptor(path):
    digest = bytes.fromhex(sha256(path))
    return {"cid": raw_cid(digest), "sha256": digest.hex(), "size": path.stat().st_size}


def release_platform():
    names = {
        ("Linux", "x86_64"): "x86_64-linux",
        ("Linux", "aarch64"): "aarch64-linux",
        ("Linux", "arm64"): "aarch64-linux",
        ("Darwin", "x86_64"): "x86_64-darwin",
        ("Darwin", "arm64"): "aarch64-darwin",
    }
    return names[(platform.system(), platform.machine())]


def component_platform():
    return {
        "x86_64-linux": "linux-amd64",
        "aarch64-linux": "linux-arm64",
        "x86_64-darwin": "darwin-amd64",
        "aarch64-darwin": "darwin-arm64",
    }[release_platform()]


def canonical(payload):
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def run(cmd, env, cwd, data=None):
    reply = subprocess.run(
        cmd, input=data, capture_output=True, env=env, cwd=cwd, timeout=60
    )
    if reply.returncode != 0:
        raise SystemExit(reply.stderr.decode(errors="replace").strip() or "elastos command failed")
    return reply.stdout


def parse_json(stdout):
    for line in reversed(stdout.decode().splitlines()):
        text = line.strip()
        if text.startswith("{"):
            return json.loads(text)
    raise SystemExit("elastos returned no JSON")


def sign_payload(runtime, key, payload, domain, env, home):
    signature = parse_json(run(
        [str(runtime), "sign-payload", "--domain", domain, "--key", str(key)],
        env, home, canonical(payload),
    ))
    return {
        "payload": payload,
        "signature": signature["signature"],
        "signer_did": signature["signer_did"],
    }


def chmod(path, mode):
    path.chmod(mode)


def write_bytes(path, payload, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    chmod(path, mode)


def stage(args):
    home = args.home.resolve()
    data = args.data.resolve()
    built = args.runtime.resolve()
    provider = args.provider.resolve()
    did = args.did.resolve()
    shell_bin = args.shell.resolve()
    wasm_src = args.wasm.resolve()
    manifest_src = args.manifest.resolve()
    home.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)
    os.umask(0o022)
    # The principal-root parent must have no group or other bits. 0755 is
    # refused when the owner creates the first passkey.
    chmod(data, 0o700)

    runtime = data / "bin" / "elastos"
    runtime.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built, runtime)
    chmod(runtime, 0o755)
    def install_bin(src, name):
        dest = data / "bin" / name
        shutil.copy2(src, dest)
        chmod(dest, 0o755)
        return dest

    provider_dest = install_bin(provider, "localhost-provider")
    did_dest = install_bin(did, "did-provider")
    shell_dest = install_bin(shell_bin, "shell")

    capsule = data / "capsules" / "agent-host"
    capsule.mkdir(parents=True, exist_ok=True)
    shutil.copy2(manifest_src, capsule / "capsule.json")
    shutil.copy2(wasm_src, capsule / "agent-host.component.wasm")
    chmod(capsule / "capsule.json", 0o644)
    chmod(capsule / "agent-host.component.wasm", 0o644)

    key = data / ".a15r-publisher.key"
    key.unlink(missing_ok=True)
    env = os.environ.copy()
    env["HOME"] = str(home)
    env.pop("XDG_DATA_HOME", None)
    env.pop("XDG_CONFIG_HOME", None)
    env.pop("XDG_STATE_HOME", None)
    try:
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(os.urandom(32).hex())
        run([str(runtime), "sign", str(capsule), "--key", str(key)], env, home)
        cid = parse_json(run([str(runtime), "stage-bundle", str(capsule)], env, home))["cid"]
        wasm_hash = sha256(capsule / "agent-host.component.wasm")
        (capsule / ".elastos-cid").write_text(cid + "\n")
        (capsule / ".elastos-artifact-sha256").write_text(wasm_hash + "\n")
        chmod(capsule / ".elastos-cid", 0o644)
        chmod(capsule / ".elastos-artifact-sha256", 0o644)

        platform_key = component_platform()
        wasm_size = (capsule / "agent-host.component.wasm").stat().st_size
        provider_hash = sha256(provider_dest)
        did_hash = sha256(did_dest)
        shell_hash = sha256(shell_dest)

        def file_component(name, digest, size, description, provides=None):
            entry = {
                "version": "0.1.0",
                "install_path": f"bin/{name}",
                "description": description,
                "platforms": {
                    platform_key: {
                        "install_path": f"bin/{name}",
                        "checksum": "sha256:" + digest,
                        "size": size,
                    }
                },
            }
            if provides:
                entry["provider_runtime"] = {
                    "role": "provider",
                    "substrate": "native",
                    "runtime_abi": "elastos.provider-stdio/v1",
                    "execution": "native-provider",
                    "provides": provides,
                }
            return entry

        def ui_component(name):
            # No checksum and no capsule-registry CID: the files are present,
            # so Home can serve them, and launch does not try to fetch a release.
            relative = f"capsules/{name}"
            return {
                "version": "0.1.0",
                "install_path": relative,
                "description": "Home page capsule copied for this disposable Home",
                "platforms": {platform_key: {"install_path": relative}},
            }

        components = {
            "schema": "elastos.components/v1",
            "external": {
                "localhost-provider": file_component(
                    "localhost-provider", provider_hash, provider_dest.stat().st_size,
                    "Localhost provider for this disposable Home", "localhost://*",
                ),
                "did-provider": file_component(
                    "did-provider", did_hash, did_dest.stat().st_size,
                    "DID provider required by the managed Home runtime", "elastos://did/*",
                ),
                "shell": file_component(
                    "shell", shell_hash, shell_dest.stat().st_size,
                    "Shell binary required by the managed Home runtime",
                ),
                "agent-host": {
                    "version": "0.1.0",
                    "install_path": "capsules/agent-host",
                    "description": "Signed Agent Host guest",
                    "platforms": {
                        platform_key: {
                            "install_path": "capsules/agent-host",
                            "extract_path": "capsules/agent-host",
                            "checksum": "sha256:" + wasm_hash,
                            "size": wasm_size,
                        }
                    },
                },
                "home": ui_component("home"),
                "system": ui_component("system"),
                "inbox": ui_component("inbox"),
                "home-gui": ui_component("home-gui"),
            },
            "capsules": {
                "agent-host": {
                    "cid": cid,
                    "sha256": wasm_hash,
                    "size": wasm_size,
                    "platforms": [platform_key],
                }
            },
            "profiles": {},
        }
        components_path = data / "components.json"
        components_path.write_text(json.dumps(components, sort_keys=True) + "\n")
        chmod(components_path, 0o644)

        version = run([str(runtime), "--version"], env, home).decode().strip().removeprefix("elastos ")
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version) is None:
            raise SystemExit("runtime version is not a release version")
        channel = "stable"
        release_body = canonical(sign_payload(runtime, key, {
            "schema": "elastos.release/v1",
            "version": version,
            "channel": channel,
            "platforms": {
                release_platform(): {
                    "binary": descriptor(runtime),
                    "components": descriptor(components_path),
                }
            },
        }, "elastos.release.v1", env, home))
        head_body = canonical(sign_payload(runtime, key, {
            "schema": "elastos.release.head/v1",
            "version": version,
            "channel": channel,
            "latest_release_cid": raw_cid(hashlib.sha256(release_body).digest()),
            "release_sha256": hashlib.sha256(release_body).hexdigest(),
        }, "elastos.release.head.v1", env, home))
        publisher = data / "ElastOS" / "SystemServices" / "Publisher"
        write_bytes(publisher / "release.json", release_body, 0o644)
        write_bytes(publisher / "release-head.json", head_body, 0o644)
        for directory in (data / "ElastOS", data / "ElastOS" / "SystemServices", publisher):
            chmod(directory, 0o700)
        signer_did = json.loads(head_body)["signer_did"]
        if re.fullmatch(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}", signer_did) is None:
            raise SystemExit("signer is not a canonical Ed25519 did:key")
        head_cid = raw_cid(hashlib.sha256(head_body).digest())
        sources = {
            "schema": "elastos.trusted-sources/v1",
            "default_source": "a15r-s9b",
            "sources": [{
                "name": "a15r-s9b",
                "publisher_dids": [signer_did],
                "channel": channel,
                "installed_version": version,
                "install_path": str(runtime),
                "head_cid": head_cid,
            }],
        }
        sources_path = data / "sources.json"
        sources_path.write_text(json.dumps(sources))
        chmod(sources_path, 0o644)
        install = {
            "runtime_path": str(runtime),
            "runtime_sha256": sha256(runtime),
            "provider_sha256": provider_hash,
            "did_sha256": did_hash,
            "shell_sha256": shell_hash,
            "wasm_sha256": wasm_hash,
            "capsule_dir": str(capsule),
            "bundle_cid": cid,
            "components_sha256": sha256(components_path),
            "release_sha256": hashlib.sha256(release_body).hexdigest(),
            "release_head_sha256": hashlib.sha256(head_body).hexdigest(),
            "sources_sha256": sha256(sources_path),
            "signer_did": signer_did,
            "version": version,
            "release_platform": release_platform(),
            "component_platform": platform_key,
            "key_deleted": False,
        }
    finally:
        key.unlink(missing_ok=True)
    install["key_deleted"] = not key.exists()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(install, sort_keys=True) + "\n")
    chmod(args.out, 0o644)
    if key.exists():
        raise SystemExit("disposable signing key was not deleted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--provider", type=Path, required=True)
    parser.add_argument("--did", type=Path, required=True)
    parser.add_argument("--shell", type=Path, required=True)
    parser.add_argument("--wasm", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    stage(parser.parse_args())


if __name__ == "__main__":
    main()
