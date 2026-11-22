#!/usr/bin/env python3
"""Disposable signed installs for source Home and holder CI fixtures."""

import argparse
import base64
import errno
import hashlib
import json
import os
import platform
import re
import stat
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


def release_platform():
    system = platform.system()
    machine = platform.machine()
    names = {
        ("Linux", "x86_64"): "x86_64-linux",
        ("Linux", "aarch64"): "aarch64-linux",
        ("Linux", "arm64"): "aarch64-linux",
        ("Darwin", "x86_64"): "x86_64-darwin",
        ("Darwin", "arm64"): "aarch64-darwin",
    }
    return names[(system, machine)]


def component_platform():
    return {
        "x86_64-linux": "linux-amd64",
        "aarch64-linux": "linux-arm64",
        "x86_64-darwin": "darwin-amd64",
        "aarch64-darwin": "darwin-arm64",
    }[release_platform()]


def prepare_installed_components(data):
    """Give installed fixture components the receipts written by release setup."""
    catalogue = data / "components.json"
    manifest = json.loads(catalogue.read_bytes())
    platform_key = component_platform()

    def digest(value, name):
        assert value, f"{name} has a blank catalogue checksum"
        assert isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value), \
            f"{name} requires a signed SHA-256 digest"
        return value[7:]

    def receipt(path, expected):
        if path.exists() or path.is_symlink():
            assert path.is_file() and not path.is_symlink(), f"invalid fixture receipt: {path}"
            assert path.read_text().strip().removeprefix("sha256:") == expected, \
                f"fixture receipt differs from catalogue: {path}"
        else:
            path.write_text(expected + "\n")

    changed = False
    for name, component in manifest.get("external", {}).items():
        platforms = component.get("platforms", {})
        info = platforms.get(platform_key, platforms.get("*"))
        if info is None:
            continue
        relative = info.get("install_path") or component.get("install_path")
        if not relative:
            continue
        parts = Path(relative).parts
        assert parts and all(part not in ("", ".", "..") for part in parts) \
            and not Path(relative).is_absolute(), f"invalid fixture install path for {name}"
        installed = data / relative
        if not installed.exists() and not installed.is_symlink():
            continue
        expected = digest(info.get("checksum"), name)
        if info.get("extract_path"):
            if installed.is_dir() and not installed.is_symlink():
                receipt(installed / ".elastos-artifact-sha256", expected)
            elif installed.is_file() and not installed.is_symlink():
                # A release can extract one binary and keep its archive
                # metadata in a separate capsule (for example, Kubo).
                metadata = component.get("capsule_metadata", {})
                metadata_info = metadata.get("platforms", {}).get(
                    platform_key, metadata.get("platforms", {}).get("*"))
                if metadata_info:
                    metadata_root = data / (metadata_info.get("install_path")
                                            or metadata.get("install_path"))
                    assert metadata_root.is_dir() and not metadata_root.is_symlink(), \
                        f"{name} archive metadata is missing"
                    receipt(metadata_root / ".elastos-artifact-sha256",
                            digest(metadata_info.get("checksum"), f"{name} metadata"))
                    prefix = metadata_info.get("extract_path", "") + "/"
                    extracted = info["extract_path"]
                    assert extracted.startswith(prefix), f"{name} archive metadata path differs"
                    executable = metadata_root / extracted[len(prefix):]
                    assert executable.is_file() and not executable.is_symlink() \
                        and sha(executable) == sha(installed), \
                        f"{name} installed executable differs from archive metadata"
                    receipt(metadata_root / ".elastos-executable-sha256", sha(installed))
                else:
                    # A source fixture can stage only an extracted helper.
                    # Record its installed bytes as a direct asset, using the
                    # same checksum/size fields as record_direct_asset in
                    # publish-release.sh, before signing this catalogue.
                    info["checksum"] = "sha256:" + sha(installed)
                    info["size"] = installed.stat().st_size
                    info.pop("extract_path", None)
                    info.pop("strategy", None)
                    changed = True
            else:
                raise AssertionError(f"{name} requires an installed archive component")
            if name == "home-cli":
                executable = installed / "bin/home-cli"
                assert executable.is_file() and not executable.is_symlink(), \
                    "Home CLI renderer is missing"
                executable_digest = sha(executable)
                signed = info.get("executable_checksum")
                if signed:
                    assert digest(signed, "Home CLI executable") == executable_digest, \
                        "Home CLI renderer differs from catalogue digest"
                else:
                    # publish-release.sh records the renderer digest separately
                    # from the archive digest in the platform catalogue entry.
                    info["executable_checksum"] = "sha256:" + executable_digest
                    changed = True
                receipt(installed / ".elastos-executable-sha256", executable_digest)
        else:
            assert installed.is_file() and not installed.is_symlink() and sha(installed) == expected, \
                f"{name} installed bytes differ from catalogue digest"

    if changed:
        catalogue.write_text(json.dumps(manifest, sort_keys=True) + "\n")


def sign_install(home, data, runtime, environment, preserve_source=False):
    """Install a release trusted only by this fixture Home; discard its signing key."""
    sources = json.loads((data / "sources.json").read_text()) if preserve_source else None
    selected = None
    if sources is not None:
        assert sources["schema"] == "elastos.trusted-sources/v1"
        selected, = [row for row in sources["sources"] if row["name"] == sources["default_source"]]
    channel = selected["channel"] if selected is not None else "stable"
    key = data / ".ci-publisher.key"
    with os.fdopen(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w") as output:
        output.write(os.urandom(32).hex())

    def sign(payload, domain):
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode()
        reply = subprocess.run([str(runtime), "sign-payload", "--domain", domain, "--key", str(key)],
                               input=canonical, capture_output=True, env=environment(home), cwd=home, timeout=30)
        assert reply.returncode == 0, \
            f"fixture release signing failed: {reply.stderr.decode(errors='replace').strip()}"
        signature = json.loads(reply.stdout)
        return {"payload": payload, "signature": signature["signature"], "signer_did": signature["signer_did"]}

    try:
        prepare_installed_components(data)
        version = subprocess.run([str(runtime), "--version"], capture_output=True, text=True,
                                 env=environment(home), cwd=home, timeout=30, check=True).stdout.strip().removeprefix("elastos ")
        assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version)
        release = json.dumps(sign({"schema": "elastos.release/v1", "version": version, "channel": channel,
            "platforms": {release_platform(): {"binary": descriptor(runtime),
                                               "components": descriptor(data / "components.json")}}},
            "elastos.release.v1"), sort_keys=True, separators=(",", ":")).encode()
        head = json.dumps(sign({"schema": "elastos.release.head/v1", "version": version, "channel": channel,
            "latest_release_cid": raw_cid(hashlib.sha256(release).digest()),
            "release_sha256": hashlib.sha256(release).hexdigest()},
            "elastos.release.head.v1"), sort_keys=True, separators=(",", ":")).encode()
        publisher = data / "ElastOS/SystemServices/Publisher"
        publisher.mkdir(mode=0o700, parents=True, exist_ok=True)
        (publisher / "release.json").write_bytes(release)
        (publisher / "release-head.json").write_bytes(head)
        installation = data / "installation"
        if installation.exists():
            assert installation.is_dir() and not installation.is_symlink()
            for name, contents in (("release.json", release), ("release-head.json", head)):
                path = installation / name
                metadata = path.lstat()
                assert stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                assert metadata.st_mode & 0o077 == 0
                path.write_bytes(contents)
        signer_did = json.loads(head)["signer_did"]
        head_cid = raw_cid(hashlib.sha256(head).digest())
        if sources is None:
            sources = {"schema": "elastos.trusted-sources/v1",
                "default_source": "holder-ci", "sources": [{"name": "holder-ci",
                "publisher_dids": [signer_did], "channel": "stable"}]}
            selected = sources["sources"][0]
        else:
            selected["publisher_dids"] = list(dict.fromkeys([*selected["publisher_dids"], signer_did]))
        selected.update(installed_version=version, install_path=str(runtime), head_cid=head_cid)
        (data / "sources.json").write_text(json.dumps(sources))
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


def restrict_components(data, published, names):
    """Keep a publisher's full catalogue separate from its installed launch set."""
    manifest = json.loads(published.read_bytes())
    selected = {}
    for name in names:
        entry = manifest["external"][name]
        info = entry["platforms"][component_platform()]
        path = data / (info.get("install_path") or entry["install_path"])
        assert path.is_file() and not path.is_symlink()
        assert info["checksum"] == "sha256:" + sha(path)
        if name == "kubo":
            assert info["extract_path"] and entry.get("capsule_metadata")
        else:
            assert entry["provider_runtime"]["execution"] == "native-provider"
        selected[name] = entry
    manifest["external"] = selected
    manifest["capsules"] = {}
    manifest["profiles"] = {}
    (data / "components.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    signing = commands.add_parser("sign-install")
    signing.add_argument("home", type=Path)
    signing.add_argument("data", type=Path)
    signing.add_argument("runtime", type=Path)
    signing.add_argument("--preserve-source", action="store_true")
    restricting = commands.add_parser("restrict-components")
    restricting.add_argument("data", type=Path)
    restricting.add_argument("published", type=Path)
    restricting.add_argument("names", nargs="+")
    args = parser.parse_args()
    if args.command == "sign-install":
        def environment(home):
            return {**os.environ, "HOME": str(home), "XDG_DATA_HOME": str(args.data.parent)}
        sign_install(args.home.resolve(), args.data.resolve(), args.runtime.resolve(), environment,
                     preserve_source=args.preserve_source)
    else:
        restrict_components(args.data.resolve(), args.published.resolve(), args.names)
