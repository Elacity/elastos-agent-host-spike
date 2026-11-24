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


def blank_catalogue_checksum(value):
    """A missing, JSON-null, or empty checksum. The Runtime stores those as no digest."""
    return value is None or value == ""


def source_capsule_without_release_checksum(name, component, info, installed, capsules):
    """An installed source capsule whose catalogue names no release digest.

    Source setup copies the capsule tree and clears the release checksum
    (`strategy` `source-build`, or the unpublished `*` entry). The Runtime
    does not read `.elastos-artifact-sha256` unless that checksum or the
    capsule registry sha256 is non-empty, so the fixture must not invent one.
    """
    if not isinstance(component, dict) or not isinstance(info, dict):
        return False
    if not blank_catalogue_checksum(info.get("checksum")):
        return False
    if info.get("strategy") not in (None, "source-build"):
        return False
    if component.get("capsule_metadata") is not None:
        return False
    platform_cid = info.get("cid")
    if not isinstance(platform_cid, (str, type(None))) or platform_cid not in (None, ""):
        return False
    if installed.is_symlink() or not installed.is_dir():
        return False
    relative = info.get("install_path") or component.get("install_path")
    if not isinstance(relative, str) or Path(relative).as_posix() != f"capsules/{name}":
        return False
    capsule_manifest = installed / "capsule.json"
    if capsule_manifest.is_symlink() or not capsule_manifest.is_file():
        return False
    try:
        declared = json.loads(capsule_manifest.read_text())
    except (OSError, json.JSONDecodeError, UnicodeError):
        return False
    if not isinstance(declared, dict) or declared.get("name") != name:
        return False
    if not isinstance(capsules, dict):
        return False
    entry = capsules.get(name)
    if entry is None:
        return True
    if not isinstance(entry, dict):
        return False
    for field in ("sha256", "cid"):
        value = entry.get(field)
        if not isinstance(value, (str, type(None))) or value not in (None, ""):
            return False
    return True


def local_model_engine_bundle(name, info, installed):
    """The preinstalled llama.cpp directory, checked by its engine receipt.

    With `binary_path` set, Runtime install state calls
    `local_model_engine_receipt::verify` on `.elastos-engine.json` and does
    not read `.elastos-artifact-sha256` in this folder. Cache setup writes
    that receipt and returns. The scan inventories every other file, and
    source setup rejects an unexpected file in the bundle before it locks
    the directory at mode 0o500. The archive digest is `archive_sha256`.
    The same digest is already on the capsule copy.
    """
    if name != "llama-server" or not isinstance(info, dict):
        return False
    if not isinstance(info.get("binary_path"), str):
        return False
    return installed.is_dir() and not installed.is_symlink()


def engine_receipt_body(path):
    """The installed `.elastos-engine.json` object, or a fixture failure."""
    if path.is_symlink() or not path.is_file():
        raise AssertionError(f"invalid fixture receipt: {path}")
    try:
        body = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError, UnicodeError) as error:
        raise AssertionError(f"invalid fixture receipt: {path}") from error
    if not isinstance(body, dict) or body.get("schema") != "elastos.local-model-engine/v2":
        raise AssertionError(f"invalid fixture receipt: {path}")
    return body


def capsule_archive_checksum(component, platform_key):
    """The capsule-copy archive digest, when metadata names one."""
    if not isinstance(component, dict):
        return None
    metadata = component.get("capsule_metadata")
    if not isinstance(metadata, dict):
        return None
    platforms = metadata.get("platforms")
    if not isinstance(platforms, dict):
        return None
    info = platforms.get(platform_key, platforms.get("*"))
    if not isinstance(info, dict) or blank_catalogue_checksum(info.get("checksum")):
        return None
    relative = info.get("install_path") or metadata.get("install_path")
    return relative, info.get("checksum")


def prepare_installed_components(data):
    """Give installed fixture components the receipts written by release setup."""
    catalogue = data / "components.json"
    manifest = json.loads(catalogue.read_bytes())
    platform_key = component_platform()

    def digest(value, name):
        if blank_catalogue_checksum(value):
            raise AssertionError(f"{name} has a blank catalogue checksum")
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
        if source_capsule_without_release_checksum(
            name, component, info, installed, manifest.get("capsules", {})
        ):
            continue
        expected = digest(info.get("checksum"), name)
        if info.get("extract_path"):
            if installed.is_dir() and not installed.is_symlink():
                if local_model_engine_bundle(name, info, installed):
                    # Do not create `.elastos-artifact-sha256` here. The
                    # Runtime compares `archive_sha256` to the catalogue
                    # checksum exactly, and an extra file fails that inventory.
                    receipt_path = installed / ".elastos-engine.json"
                    body = engine_receipt_body(receipt_path)
                    version = component.get("version") if isinstance(component, dict) else None
                    if not isinstance(version, str) or version == "":
                        raise AssertionError("llama-server bundle version is missing")
                    if (body.get("version") != version
                            or body.get("platform") != platform_key
                            or body.get("archive_sha256") != "sha256:" + expected):
                        raise AssertionError(
                            f"fixture receipt differs from catalogue: {receipt_path}")
                    artifact = installed / ".elastos-artifact-sha256"
                    if artifact.exists() or artifact.is_symlink():
                        receipt(artifact, expected)
                    named = capsule_archive_checksum(component, platform_key)
                    if named is not None:
                        metadata_relative, checksum = named
                        metadata_parts = Path(metadata_relative).parts \
                            if isinstance(metadata_relative, str) else ()
                        assert isinstance(metadata_relative, str) and metadata_parts and all(
                            part not in ("", ".", "..") for part in metadata_parts
                        ) and not Path(metadata_relative).is_absolute(), \
                            f"{name} archive metadata is missing"
                        metadata_root = data / metadata_relative
                        assert metadata_root.is_dir() and not metadata_root.is_symlink(), \
                            f"{name} archive metadata is missing"
                        marker = metadata_root / ".elastos-artifact-sha256"
                        if not (marker.exists() or marker.is_symlink()):
                            raise AssertionError(f"invalid fixture receipt: {marker}")
                        receipt(marker, digest(checksum, f"{name} metadata"))
                else:
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


def canonical_publisher_did(value):
    """True for the one Ed25519 did:key shape decode_did_key admits.

    The length and z6Mk prefix are the check that bails
    "DID must be one canonical Ed25519 did:key". The Runtime still checks the
    point; this filter only drops spellings that cannot be that key.
    """
    return isinstance(value, str) and re.fullmatch(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}", value) is not None


# admit() reads capsules/<name>/capsule.json for these three. A signed binary
# row without that file makes `elastos serve` exit before the helper is fenced.
ADMITTED_NATIVE_PROVIDERS = ("localhost-provider", "object-provider", "chain-provider")


def install_source_capsule_manifests(data, source_root):
    """Copy each admitted provider's source capsule.json into this Home.

    The holder fixture installs the native binary and a signed components row.
    Admission still requires the manifest beside that row. A missing file is
    `cannot admit '<name>'`, and serve exits with that name. This copies the
    source manifest the product tree already ships.
    """
    catalogue = json.loads((data / "components.json").read_bytes())
    external = catalogue.get("external", {})
    for name in ADMITTED_NATIVE_PROVIDERS:
        if name not in external:
            continue
        source = None
        for relative in (
            Path("elastos/capsules") / name / "capsule.json",
            Path("capsules") / name / "capsule.json",
        ):
            candidate = source_root / relative
            if candidate.is_symlink():
                raise AssertionError(f"{name} source capsule.json is a symlink")
            if candidate.is_file():
                source = candidate
                break
        if source is None:
            raise AssertionError(f"{name} is installed but {source_root} has no capsule.json for it")
        dest_dir = data / "capsules" / name
        if dest_dir.is_symlink():
            raise AssertionError(f"{name} capsule directory is a symlink")
        dest_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        dest = dest_dir / "capsule.json"
        if dest.is_symlink() or (dest.exists() and not dest.is_file()):
            raise AssertionError(f"{name} capsule.json is not a regular file")
        dest.write_bytes(source.read_bytes())
        dest.chmod(0o600)


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
        assert canonical_publisher_did(signer_did), "fixture signer is not a canonical Ed25519 did:key"
        head_cid = raw_cid(hashlib.sha256(head).digest())
        if sources is None:
            sources = {"schema": "elastos.trusted-sources/v1",
                "default_source": "holder-ci", "sources": [{"name": "holder-ci",
                "publisher_dids": [signer_did], "channel": "stable"}]}
            selected = sources["sources"][0]
        else:
            # install_path below makes this an installed release, and the Runtime
            # decodes every publisher DID. A setup label such as
            # did:key:local-carrier-test is not a key. Keep real anchors.
            prior = selected["publisher_dids"]
            assert isinstance(prior, list), "preserved publisher DIDs must be a list"
            kept = [did for did in prior if canonical_publisher_did(did)]
            selected["publisher_dids"] = list(dict.fromkeys([*kept, signer_did]))
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
