#!/usr/bin/env python3
"""Builds the release folder a desktop app carries (ELASTOS-DESKTOP-APP).

The folder holds the signed release pair, the publisher's sources.json and every
artifact for one platform (Apple silicon Macs unless --platform says otherwise), each
fetched by CID, checked against the signed release and saved under its CID.
`elastos install --from <folder>` then installs it with the same checks as the online
installer.

    make-release-folder.py --sources SOURCES.json --out DIR [--platform aarch64-linux]

LAB ONLY: --lab-runtime BIN --lab-key KEY --signer ELASTOS swaps in a locally built
Runtime and re-signs the release pair with a throwaway lab key, trusted next to the
publisher's key. A folder built that way must never ship. Lab releases carry that one
platform only. For a lab publisher (experiment P7) it can also set the version and
the previous publication, write the flat signed set `elastos publish-release` takes,
and name that publisher in sources.json as install.sh does.
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
import time
import urllib.request

PLATFORMS = {"aarch64-darwin": ("darwin-arm64", "*"),
             "aarch64-linux": ("linux-arm64", "*"),
             "x86_64-linux": ("linux-amd64", "*")}
RELEASE_PLATFORM = "aarch64-darwin"
COMPONENT_PLATFORMS = PLATFORMS[RELEASE_PLATFORM]


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


def name_file(out, path, kubo):
    """Moves `path` into out/ under its CID: kubo's default import CID, as releases name
    their files, with --kubo; else the raw-bytes CID."""
    if kubo:
        cid = subprocess.run([kubo, "add", "--only-hash", "-Q", path],
                             capture_output=True, text=True, check=True).stdout.strip()
    else:
        cid = raw_cid(bytes.fromhex(file_sha256(path)))
    os.replace(path, os.path.join(out, cid))
    return cid


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
    global RELEASE_PLATFORM, COMPONENT_PLATFORMS
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", required=True, help="sources.json written by the official installer")
    parser.add_argument("--out", required=True)
    parser.add_argument("--base", help="folder with the official release-head.json and release.json (default: the gateway)")
    parser.add_argument("--installer", help="the official install.sh of that release (default: the gateway)")
    parser.add_argument("--lab-runtime")
    parser.add_argument("--lab-key")
    parser.add_argument("--signer")
    parser.add_argument("--lab-capsule", action="append", default=[],
                        help="capsules/<name> folder to pack as <name>.tar.gz (with --lab-runtime; repeatable)")
    parser.add_argument("--kubo", help="kubo binary; lab files are then named by their import CID, as releases are")
    parser.add_argument("--lab-version", help="release version (with --lab-runtime; the Runtime must report it)")
    parser.add_argument("--lab-previous", nargs=2, metavar=("HEAD_CID", "RELEASE_CID"),
                        help="the lab publisher's last publication (publish-state.json); default none")
    parser.add_argument("--publication", help="also write the flat signed set for `elastos publish-release`")
    parser.add_argument("--publisher-node", help="lab publisher's Carrier node id, stamped into sources.json")
    parser.add_argument("--connect-ticket", help="lab publisher's Carrier ticket, stamped into sources.json")
    parser.add_argument("--gateway", help="lab publisher's gateway URL, stamped into sources.json")
    parser.add_argument("--platform", choices=sorted(PLATFORMS), default=RELEASE_PLATFORM)
    args = parser.parse_args()
    RELEASE_PLATFORM, COMPONENT_PLATFORMS = args.platform, PLATFORMS[args.platform]
    os.makedirs(args.out, exist_ok=True)

    sources = json.load(open(args.sources))
    gateway = sources["sources"][0]["gateways"][0].rstrip("/")
    get = lambda path: urllib.request.urlopen(f"{gateway}/{path}", timeout=60).read()
    if args.base:
        head_bytes, release_bytes = (open(os.path.join(args.base, name), "rb").read()
                                     for name in ("release-head.json", "release.json"))
    else:
        head_bytes, release_bytes = get("release-head.json"), get("release.json")
    head, release = json.loads(head_bytes), json.loads(release_bytes)
    if head["payload"]["release_sha256"] != hashlib.sha256(release_bytes).hexdigest():
        sys.exit("release.json differs from the signed head")
    version = head["payload"]["version"]
    if version != sources["sources"][0]["installed_version"]:
        sys.exit(f"the source names {sources['sources'][0]['installed_version']}, the gateway serves {version}")
    platform = release["payload"]["platforms"][RELEASE_PLATFORM]

    binary = platform["binary"]
    if not args.lab_runtime:
        runtime = fetch(f"{gateway}/ipfs/{binary['cid']}", args.out, binary["cid"], binary["sha256"], binary["size"])
        os.chmod(runtime, 0o755)
    descriptor = platform["components"]
    components_path = fetch(f"{gateway}/ipfs/{descriptor['cid']}", args.out,
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
        fetch(f"{gateway}/ipfs/{cid}", args.out, cid, checksum, size)
    count = len(wanted)
    fetch(f"{gateway}/ipfs/{manifest['model_catalog']['head_cid']}", args.out, manifest["model_catalog"]["head_cid"])
    fetch(f"{gateway}/ipfs/{manifest['collaboration_network']['head_cid']}", args.out,
          manifest["collaboration_network"]["head_cid"])
    installer = open(args.installer, "rb").read() if args.installer else get("install.sh")
    if hashlib.sha256(installer).hexdigest() != release["payload"]["installer_sha256"]:
        sys.exit("install.sh differs from the signed release")

    for source in sources["sources"]:
        source["install_path"] = ""
    if args.lab_runtime:
        if not os.path.exists(args.lab_key):
            with open(os.open(args.lab_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                f.write(secrets.token_hex(32) + "\n")
        if args.kubo:
            os.environ["IPFS_PATH"] = tempfile.mkdtemp(prefix="lab-kubo-")
            subprocess.run([args.kubo, "init", "--profile=test"], capture_output=True, check=True)
        data = open(args.lab_runtime, "rb").read()
        digest = hashlib.sha256(data).digest()
        staged = os.path.join(args.out, ".lab-runtime")
        shutil.copyfile(args.lab_runtime, staged)
        os.chmod(staged, 0o755)
        cid = name_file(args.out, staged, args.kubo)
        payload = release["payload"]
        payload["platforms"] = {RELEASE_PLATFORM: payload["platforms"][RELEASE_PLATFORM]}
        payload["platforms"][RELEASE_PLATFORM]["binary"] = {"cid": cid, "sha256": digest.hex(), "size": len(data)}
        def one_platform(value):
            if isinstance(value, dict):
                if isinstance(value.get("platforms"), dict):
                    value["platforms"] = {p: v for p, v in value["platforms"].items() if p in COMPONENT_PLATFORMS}
                for child in value.values():
                    one_platform(child)
        one_platform(manifest["external"])
        payload["capsule_records"] = [r for r in payload.get("capsule_records", [])
                                      if r["payload"].get("platform") in COMPONENT_PLATFORMS]
        head_payload = head["payload"]
        if args.lab_version:
            payload["version"] = head_payload["version"] = version = args.lab_version
            payload["released_at"] = head_payload["updated_at"] = int(time.time())
        payload["prev_release_cid"] = args.lab_previous[1] if args.lab_previous else None
        head_payload["prev_head_cid"] = args.lab_previous[0] if args.lab_previous else None
        for folder in args.lab_capsule:
            name = os.path.basename(os.path.normpath(folder))
            packed = pack_capsule(folder, name)
            packed_sha = hashlib.sha256(packed).hexdigest()
            staged = os.path.join(args.out, ".lab-capsule")
            with open(staged, "wb") as f:
                f.write(packed)
            packed_cid = name_file(args.out, staged, args.kubo)
            manifest["external"][name]["platforms"]["*"].update(
                cid=packed_cid, checksum=f"sha256:{packed_sha}", size=len(packed))
            for record in payload.get("capsule_records", []):
                if record["payload"]["name"] == name:
                    record["payload"].update(cid=packed_cid, sha256=packed_sha, size=len(packed))
            print(f"LAB {name} capsule {packed_cid} from {folder}")
        components = json.dumps(manifest, indent=2).encode() + b"\n"
        staged = os.path.join(args.out, ".lab-components")
        with open(staged, "wb") as f:
            f.write(components)
        components_cid = name_file(args.out, staged, args.kubo)
        payload["platforms"][RELEASE_PLATFORM]["components"] = {
            "cid": components_cid, "sha256": hashlib.sha256(components).hexdigest(), "size": len(components)}
        # One publisher signs the whole release, capsule records included.
        _, lab_did = sign(args.signer, args.lab_key, "elastos.lab.probe.v1", {})
        for i, record in enumerate(payload.get("capsule_records", [])):
            record["payload"]["signer_did"] = lab_did
            signed, _ = sign(args.signer, args.lab_key, "elastos.capsule.record.v1", record["payload"])
            payload["capsule_records"][i] = json.loads(signed)
        release_bytes, _ = sign(args.signer, args.lab_key, "elastos.release.v1", payload)
        staged = os.path.join(args.out, ".lab-release")
        with open(staged, "wb") as f:
            f.write(release_bytes)
        head_payload["latest_release_cid"] = name_file(args.out, staged, args.kubo)
        head_payload["release_sha256"] = hashlib.sha256(release_bytes).hexdigest()
        head_payload["signer_did"] = lab_did
        head_bytes, _ = sign(args.signer, args.lab_key, "elastos.release.head.v1", head_payload)
        for source in sources["sources"]:
            source["publisher_dids"] = [lab_did]
            source["discovery_uri"] = (f"elastos://source/{source['channel']}/"
                                       f"{hashlib.sha256(lab_did.encode()).hexdigest()[:32]}")
            source["head_cid"] = raw_cid(hashlib.sha256(head_bytes).digest())
        print(f"LAB release: Runtime {cid}, signed by {lab_did}")
        if args.publication:
            write_publication(args.publication, args.out, head_bytes, release_bytes, installer,
                              payload, manifest)
    for source in sources["sources"]:
        if args.publisher_node:
            source["publisher_node_id"] = args.publisher_node
        if args.connect_ticket:
            source["connect_ticket"] = args.connect_ticket
        if args.gateway:
            source["gateways"] = [args.gateway]
    for name, data in (("release-head.json", head_bytes), ("release.json", release_bytes),
                       ("sources.json", json.dumps(sources, indent=2).encode() + b"\n")):
        with open(os.path.join(args.out, name), "wb") as f:
            f.write(data)
    print(f"Release folder for {version}: {count} artifacts in {args.out}")


def write_publication(target, folder, head_bytes, release_bytes, installer, payload, manifest):
    """The flat signed set: metadata plus every file under the name the release gives it."""
    os.makedirs(target)
    platform = payload["platforms"][RELEASE_PLATFORM]
    names = {f"elastos-{RELEASE_PLATFORM}": platform["binary"]["cid"],
             f"components-{RELEASE_PLATFORM}.json": platform["components"]["cid"],
             "model-catalog.json": manifest["model_catalog"]["head_cid"],
             "collaboration-network-release-v1.json": manifest["collaboration_network"]["head_cid"]}
    def walk(value):
        if isinstance(value, dict):
            if value.get("cid") and value.get("release_path"):
                names[value["release_path"]] = value["cid"]
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(manifest)
    for name, cid in names.items():
        subprocess.run(["cp", "-c", os.path.join(folder, cid), os.path.join(target, name)], check=True)
    for name, data in (("release-head.json", head_bytes), ("release.json", release_bytes),
                       ("install.sh", installer)):
        with open(os.path.join(target, name), "wb") as f:
            f.write(data)
    print(f"LAB publication: {len(names)} artifacts in {target}")


if __name__ == "__main__":
    main()
