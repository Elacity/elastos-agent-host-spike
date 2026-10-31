#!/usr/bin/env python3
"""Builds the release folder a desktop app carries (ELASTOS-DESKTOP-APP).

The folder holds the signed release pair, the publisher's sources.json and every
artifact for Apple silicon Macs, each checked against the signed release and saved
under its CID. `elastos install --from <folder>` then installs it with the same checks
as the online installer.

    make-release-folder.py --sources SOURCES.json --out DIR

LAB ONLY: --lab-runtime BIN --lab-key KEY --signer ELASTOS swaps in a locally built
Runtime and re-signs the release pair with a throwaway lab key, trusted next to the
publisher's key. A folder built that way must never ship.
"""

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

RELEASE_PLATFORM = "aarch64-darwin"
COMPONENT_PLATFORMS = ("darwin-arm64", "*")


def raw_cid(digest):
    return "b" + base64.b32encode(bytes([0x01, 0x55, 0x12, 0x20]) + digest).decode().lower().rstrip("=")


def fetch(url, out, cid, sha256=None, size=None):
    """Downloads `url` into out/cid unless it is already there with the right hash."""
    path = os.path.join(out, cid)
    if os.path.isfile(path) and (sha256 is None or file_sha256(path) == sha256):
        return path
    hasher, total = hashlib.sha256(), 0
    with urllib.request.urlopen(url, timeout=60) as response, tempfile.NamedTemporaryFile(dir=out, delete=False) as tmp:
        while chunk := response.read(1 << 20):
            hasher.update(chunk)
            total += len(chunk)
            tmp.write(chunk)
    digest = hasher.hexdigest()
    if (sha256 is not None and digest != sha256) or (size is not None and total != int(size)):
        os.unlink(tmp.name)
        sys.exit(f"{url}: bytes differ from the signed release")
    if sha256 is None and cid.startswith("bafkrei") and raw_cid(bytes.fromhex(digest)) != cid:
        os.unlink(tmp.name)
        sys.exit(f"{url}: bytes differ from pinned CID {cid}")
    os.replace(tmp.name, path)
    return path


def file_sha256(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            hasher.update(chunk)
    return hasher.hexdigest()


def sign(signer, key, domain, payload):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    out = subprocess.run([signer, "sign-payload", "--domain", domain, "--key", key],
                         input=canonical, capture_output=True, check=True).stdout
    signed = json.loads(out.decode().strip().splitlines()[-1])
    envelope = {"payload": payload, "signature": signed["signature"], "signer_did": signed["signer_did"]}
    return json.dumps(envelope, indent=2).encode() + b"\n", signed["signer_did"]


def pack_capsule(source, capsule):
    """<capsule>.tar.gz as the release packs it: `<capsule>/` holding capsules/<capsule> without its README."""
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as tar:
        for root, dirs, files in os.walk(source):
            dirs.sort()
            for name in [""] + sorted(files):
                path = os.path.join(root, name) if name else root
                rel = os.path.relpath(path, source)
                if rel == "README.md":
                    continue
                info = tar.gettarinfo(path, arcname=capsule if rel == "." else f"{capsule}/{rel}")
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                if info.isfile():
                    with open(path, "rb") as f:
                        tar.addfile(info, f)
                else:
                    tar.addfile(info)
    return buffer.getvalue()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", required=True, help="sources.json written by the official installer")
    parser.add_argument("--out", required=True)
    parser.add_argument("--lab-runtime")
    parser.add_argument("--lab-key")
    parser.add_argument("--signer")
    parser.add_argument("--lab-capsule", action="append", default=[],
                        help="capsules/<name> folder to pack as <name>.tar.gz (with --lab-runtime; repeatable)")
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    sources = json.load(open(args.sources))
    gateway = sources["sources"][0]["gateways"][0].rstrip("/")
    get = lambda path: urllib.request.urlopen(f"{gateway}/{path}", timeout=60).read()
    head_bytes, release_bytes = get("release-head.json"), get("release.json")
    head, release = json.loads(head_bytes), json.loads(release_bytes)
    if head["payload"]["release_sha256"] != hashlib.sha256(release_bytes).hexdigest():
        sys.exit("release.json differs from the signed head")
    version = head["payload"]["version"]
    if version != sources["sources"][0]["installed_version"]:
        sys.exit(f"the source names {sources['sources'][0]['installed_version']}, the gateway serves {version}")
    platform = release["payload"]["platforms"][RELEASE_PLATFORM]

    binary = platform["binary"]
    runtime = fetch(f"{gateway}/artifacts/elastos-{RELEASE_PLATFORM}", args.out, binary["cid"], binary["sha256"], binary["size"])
    os.chmod(runtime, 0o755)
    descriptor = platform["components"]
    components_path = fetch(f"{gateway}/artifacts/components-{RELEASE_PLATFORM}.json", args.out,
                            descriptor["cid"], descriptor["sha256"], descriptor["size"])
    manifest = json.load(open(components_path))
    # Setup installs the release's signed capsule records where they exist, else
    # the component rows; the folder carries both for this platform.
    wanted = {}
    for name, component in manifest["external"].items():
        info = next((component["platforms"][p] for p in COMPONENT_PLATFORMS if p in component.get("platforms", {})), None)
        if info and info.get("cid") and info.get("release_path"):
            wanted[info["cid"]] = (name, info["release_path"], info["checksum"].removeprefix("sha256:"), info["size"])
    for record in release["payload"].get("capsule_records", []):
        p = record["payload"]
        if p.get("platform") in COMPONENT_PLATFORMS and p.get("cid") and p.get("release_path"):
            wanted[p["cid"]] = (p["name"], p["release_path"], p["sha256"], p["size"])
    for cid, (name, release_path, checksum, size) in wanted.items():
        print(f"  {name}: {release_path} ({int(size) // (1 << 20)} MiB)", flush=True)
        fetch(f"{gateway}/artifacts/{release_path}", args.out, cid, checksum, size)
    count = len(wanted)
    fetch(f"{gateway}/artifacts/model-catalog.json", args.out, manifest["model_catalog"]["head_cid"])
    fetch(f"{gateway}/artifacts/collaboration-network-release-v1.json", args.out,
          manifest["collaboration_network"]["head_cid"])

    for source in sources["sources"]:
        source["install_path"] = ""
    if args.lab_runtime:
        if not os.path.exists(args.lab_key):
            with open(os.open(args.lab_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                f.write(secrets.token_hex(32) + "\n")
        data = open(args.lab_runtime, "rb").read()
        digest = hashlib.sha256(data).digest()
        cid = raw_cid(digest)
        shutil.copyfile(args.lab_runtime, os.path.join(args.out, cid))
        os.chmod(os.path.join(args.out, cid), 0o755)
        payload = release["payload"]
        payload["platforms"][RELEASE_PLATFORM]["binary"] = {"cid": cid, "sha256": digest.hex(), "size": len(data)}
        for folder in args.lab_capsule:
            name = os.path.basename(os.path.normpath(folder))
            packed = pack_capsule(folder, name)
            packed_sha = hashlib.sha256(packed).hexdigest()
            packed_cid = raw_cid(hashlib.sha256(packed).digest())
            with open(os.path.join(args.out, packed_cid), "wb") as f:
                f.write(packed)
            manifest["external"][name]["platforms"]["*"].update(
                cid=packed_cid, checksum=f"sha256:{packed_sha}", size=len(packed))
            for record in payload.get("capsule_records", []):
                if record["payload"]["name"] == name:
                    record["payload"].update(cid=packed_cid, sha256=packed_sha, size=len(packed))
            print(f"LAB {name} capsule {packed_cid} from {folder}")
        if args.lab_capsule:
            components = json.dumps(manifest, indent=2).encode() + b"\n"
            components_cid = raw_cid(hashlib.sha256(components).digest())
            with open(os.path.join(args.out, components_cid), "wb") as f:
                f.write(components)
            payload["platforms"][RELEASE_PLATFORM]["components"] = {
                "cid": components_cid, "sha256": hashlib.sha256(components).hexdigest(), "size": len(components)}
        # One publisher signs the whole release, capsule records included.
        _, lab_did = sign(args.signer, args.lab_key, "elastos.lab.probe.v1", {})
        for i, record in enumerate(payload.get("capsule_records", [])):
            record["payload"]["signer_did"] = lab_did
            signed, _ = sign(args.signer, args.lab_key, "elastos.capsule.record.v1", record["payload"])
            payload["capsule_records"][i] = json.loads(signed)
        release_bytes, _ = sign(args.signer, args.lab_key, "elastos.release.v1", payload)
        head_payload = head["payload"]
        head_payload["latest_release_cid"] = raw_cid(hashlib.sha256(release_bytes).digest())
        head_payload["release_sha256"] = hashlib.sha256(release_bytes).hexdigest()
        head_payload["signer_did"] = lab_did
        head_bytes, _ = sign(args.signer, args.lab_key, "elastos.release.head.v1", head_payload)
        for source in sources["sources"]:
            source["publisher_dids"] = [lab_did]
            source["head_cid"] = raw_cid(hashlib.sha256(head_bytes).digest())
        print(f"LAB release: Runtime {cid}, signed by {lab_did}")
    for name, data in (("release-head.json", head_bytes), ("release.json", release_bytes),
                       ("sources.json", json.dumps(sources, indent=2).encode() + b"\n")):
        with open(os.path.join(args.out, name), "wb") as f:
            f.write(data)
    print(f"Release folder for {version}: {count} artifacts in {args.out}")


if __name__ == "__main__":
    main()
