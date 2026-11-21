#!/usr/bin/env python3
"""Give the custody-host simulation the signed release a real install has.

A real custody host installs ElastOS from a publisher's signed release (the
stamped installer, then `elastos setup` from that trusted source), so its data
root holds the publisher's signed release head and release envelope plus a
`sources.json` that pins the publisher. Installed component starts, custody
provisioning included, verify that signed release before they run anything.

This harness builds its binaries from source instead, so it plays the
publisher itself: at image build time it makes a throwaway Ed25519 publisher
key, signs one release binding the exact `elastos` binary and
`components.json` this image ships, pins that publisher as the default
trusted source, and deletes the key. No private key reaches the image. It is
the "create your own trusted source" step the Runtime asks a source build for,
and it changes nothing in the Runtime's checks.

Usage (from the Dockerfile builder stage, after binaries are stripped and
components.json is stamped):

    sign-harness-release.py --data-root DIR --platform x86_64-linux --version 2.0.1

Needs python3 and the openssl CLI (Ed25519 with -rawin, OpenSSL >= 3.0).
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SOURCE_NAME = "custody-harness"
CHANNEL = "stable"


def canonical(value):
    # The Runtime verifies serde_json::to_string(payload): sorted keys, no spaces.
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def raw_cid(data):
    """CIDv1, raw codec, sha2-256, base32 lower: what admit_descriptor accepts."""
    multihash = b"\x12\x20" + hashlib.sha256(data).digest()
    encoded = base64.b32encode(b"\x01\x55" + multihash).decode("ascii")
    return "b" + encoded.lower().rstrip("=")


def descriptor(data):
    return {"cid": raw_cid(data), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def did_key(public_key):
    number, encoded = int.from_bytes(b"\xed\x01" + public_key, "big"), ""
    while number:
        number, digit = divmod(number, 58)
        encoded = BASE58[digit] + encoded
    return "did:key:z" + encoded


class Publisher:
    def __init__(self, workdir):
        self.key = workdir / "publisher.pem"
        self.workdir = workdir
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(self.key)],
                       check=True, capture_output=True)
        der = subprocess.run(["openssl", "pkey", "-in", str(self.key), "-pubout", "-outform", "DER"],
                             check=True, capture_output=True).stdout
        # SubjectPublicKeyInfo for Ed25519 ends with the 32-byte raw key.
        if len(der) != 44:
            raise SystemExit(f"FAIL: unexpected Ed25519 public key encoding ({len(der)} bytes)")
        self.did = did_key(der[-32:])

    def envelope(self, payload, domain):
        # crypto::domain_separated_sign: Ed25519 over SHA-256(domain || 0 || payload).
        message = self.workdir / "message.bin"
        message.write_bytes(hashlib.sha256(domain.encode("utf-8") + b"\0" + canonical(payload)).digest())
        signature = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.key), "-in", str(message)],
            check=True, capture_output=True).stdout
        if len(signature) != 64:
            raise SystemExit("FAIL: openssl did not return a 64-byte Ed25519 signature")
        return canonical({"payload": payload, "signature": signature.hex(), "signer_did": self.did}) + b"\n"


def write_private(path, data):
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.replace(tmp, path)


def private_dirs(root, relative):
    path = root
    for part in relative.parts:
        path = path / part
        path.mkdir(mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--platform", required=True,
                        help="the Runtime's release platform key, e.g. x86_64-linux or aarch64-linux")
    parser.add_argument("--version", required=True, help="the Runtime's semver version")
    args = parser.parse_args()

    data_root = args.data_root.resolve()
    runtime = data_root / "bin" / "elastos"
    components = (data_root / "components.json").read_bytes()

    with tempfile.TemporaryDirectory(prefix="custody-harness-publisher-") as workdir:
        publisher = Publisher(Path(workdir))
        release = publisher.envelope({
            "schema": "elastos.release/v1", "version": args.version, "channel": CHANNEL,
            "platforms": {args.platform: {"binary": descriptor(runtime.read_bytes()),
                                          "components": descriptor(components)}},
        }, "elastos.release.v1")
        head = publisher.envelope({
            "schema": "elastos.release.head/v1", "version": args.version, "channel": CHANNEL,
            "latest_release_cid": raw_cid(release),
            "release_sha256": hashlib.sha256(release).hexdigest(),
        }, "elastos.release.head.v1")
        did = publisher.did
    # The private key is gone with the temporary directory.

    # publisher_release_head_path / publisher_release_manifest_path
    publisher_root = private_dirs(data_root, Path("ElastOS/SystemServices/Publisher"))
    write_private(publisher_root / "release-head.json", head)
    write_private(publisher_root / "release.json", release)
    write_private(data_root / "sources.json", json.dumps({
        "schema": "elastos.trusted-sources/v1",
        "default_source": SOURCE_NAME,
        "sources": [{
            "name": SOURCE_NAME, "publisher_dids": [did], "channel": CHANNEL,
            "install_path": str(runtime), "installed_version": args.version,
            "head_cid": raw_cid(head),
        }],
    }, indent=2).encode("utf-8") + b"\n")
    print(f"signed custody-harness release {args.version} for {args.platform} by {did}")


if __name__ == "__main__":
    main()
