#!/usr/bin/env python3
"""Shared signed-install and native-provider checks for the Linux holder canary."""

import base64
import errno
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def raw_cid(digest):
    return "b" + base64.b32encode(b"\x01\x55\x12\x20" + digest).decode().lower().rstrip("=")


def descriptor(path):
    digest = bytes.fromhex(sha(path))
    return {"cid": raw_cid(digest), "sha256": digest.hex(), "size": path.stat().st_size}


def sign_install(home, data, runtime, environment):
    """Install a release trusted only by this fixture Home; discard its signing key."""
    key = data / ".ci-publisher.key"
    key.write_text(os.urandom(32).hex())
    key.chmod(0o600)

    def sign(payload, domain):
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode()
        reply = subprocess.run([str(runtime), "sign-payload", "--domain", domain, "--key", str(key)],
                               input=canonical, capture_output=True, env=environment(home), cwd=home, timeout=30)
        assert reply.returncode == 0, "fixture release signing failed"
        signature = json.loads(reply.stdout)
        return {"payload": payload, "signature": signature["signature"], "signer_did": signature["signer_did"]}

    try:
        version = subprocess.run([str(runtime), "--version"], capture_output=True, text=True,
                                 env=environment(home), cwd=home, timeout=30, check=True).stdout.strip().removeprefix("elastos ")
        assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version)
        release = json.dumps(sign({"schema": "elastos.release/v1", "version": version, "channel": "stable",
            "platforms": {"x86_64-linux": {"binary": descriptor(runtime),
                                           "components": descriptor(data / "components.json")}}},
            "elastos.release.v1"), sort_keys=True, separators=(",", ":")).encode()
        head = json.dumps(sign({"schema": "elastos.release.head/v1", "version": version, "channel": "stable",
            "latest_release_cid": raw_cid(hashlib.sha256(release).digest()),
            "release_sha256": hashlib.sha256(release).hexdigest()},
            "elastos.release.head.v1"), sort_keys=True, separators=(",", ":")).encode()
        publisher = data / "ElastOS/SystemServices/Publisher"
        publisher.mkdir(mode=0o700, parents=True, exist_ok=True)
        (publisher / "release.json").write_bytes(release)
        (publisher / "release-head.json").write_bytes(head)
        (data / "sources.json").write_text(json.dumps({"schema": "elastos.trusted-sources/v1",
            "default_source": "holder-ci", "sources": [{"name": "holder-ci",
            "publisher_dids": [json.loads(head)["signer_did"]], "channel": "stable",
            "installed_version": version, "install_path": str(runtime),
            "head_cid": raw_cid(hashlib.sha256(head).digest())}]}))
    finally:
        key.unlink(missing_ok=True)


def runs_provider(row, provider):
    """Identify a native provider exec'd by path or checked /proc/self/fd/N."""
    if row["command"].split(" ", 1)[0] == str(provider):
        return True
    try:
        executable = os.readlink(Path("/proc") / str(row["pid"]) / "exe")
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ESRCH):
            return False
        raise
    return os.path.realpath(executable) == os.path.realpath(str(provider))
