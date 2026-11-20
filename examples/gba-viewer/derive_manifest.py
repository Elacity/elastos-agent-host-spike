#!/usr/bin/env python3
"""Derive the by-CID manifest of a GBA bundle from the product capsule.json.

The product manifests are read in place and never copied into the repository.
For a bundle that is admitted by CID, this mapping keeps exactly the keys that
admission allows, drops exactly the named keys, and adds exactly one `requires`
pin supplied on the command line. Anything else in the product manifest is
refused by name: the mapping is an allowlist and it fails closed.

Allowlist source: `BUNDLE_MANIFEST_KEYS` at
elastos/crates/elastos-server/src/bundle_admission.rs:451-491, copied literally.
Dropped keys source: the same file's doc comment (:441-448 names `interfaces`,
`permissions` and `viewer` as off the list on purpose) and ruling r2 section 1
(page drops `interfaces` and `permissions`; content drops `viewer`,
`interfaces` and `permissions`).
CID form source: `cid_form` at elastos/crates/elastos-common/src/cid_form.rs:21-26.
Plain requirement name source: `plain` at
elastos/crates/elastos-server/src/bundle_admission.rs:659-663 and the pin shape at
elastos/crates/elastos-common/src/pinned_manifest.rs:104-129.
"""
import argparse
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent

# elastos/crates/elastos-server/src/bundle_admission.rs:451-491, in its order.
ALLOWED_KEYS = (
    "schema",
    "name",
    "version",
    "description",
    "author",
    "role",
    "type",
    "execution",
    "runtime_abi",
    "bus_contract",
    "wit_world_sha256",
    "entrypoint",
    "projections",
    "window_policy",
    "icon",
    "resources",
    "requires",
    "asks",
)

# ruling r2 section 1, per role. A key on neither list is refused by name.
DROPPED_KEYS = {
    "page": ("interfaces", "permissions"),
    "content": ("viewer", "interfaces", "permissions"),
}

ROLE_KIND = {"viewer": "page", "content": "content"}

BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
ROOT_PREFIX = b"\x01\x70\x12\x20"


def refuse(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def plain_name(text):
    """bundle_admission.rs:659-663: a requirement's name is plain."""
    if text in ("", ".", ".."):
        return False
    return all(c.isascii() and (c.isalnum() or c in "._-") for c in text)


def cid_form(text):
    """cid_form at elastos/crates/elastos-common/src/cid_form.rs:21-26."""
    if not text.startswith("b"):
        return False
    digits = text[1:]
    bits = held = 0
    decoded = bytearray()
    for character in digits:
        value = BASE32_ALPHABET.find(character)
        if value < 0:
            return False
        bits = (bits << 5) | value
        held += 5
        if held >= 8:
            held -= 8
            decoded.append((bits >> held) & 0xFF)
        bits &= (1 << held) - 1
    if bytes(decoded[:4]) != ROOT_PREFIX or len(decoded) != 36:
        return False
    return encode_base32(bytes(decoded)) == digits


def encode_base32(data):
    bits = held = 0
    digits = []
    for byte in data:
        bits = (bits << 8) | byte
        held += 8
        while held >= 5:
            held -= 5
            digits.append(BASE32_ALPHABET[(bits >> held) & 31])
        bits &= (1 << held) - 1
    if held:
        digits.append(BASE32_ALPHABET[(bits << (5 - held)) & 31])
    return "".join(digits)


def refuse_output_inside_repo(out):
    """The output folder is outside the checkout, by real path."""
    root = os.path.realpath(str(REPO_ROOT))
    real = os.path.realpath(str(out))
    if real == root or real.startswith(root + os.sep):
        refuse(f"derive_manifest_output_inside_repo: {out}")


def refuse_symlink_below(base, path, code):
    """No component of `path` below `base`, nor `path` itself, is a symlink.

    Checked by lstat before every read of a product file and every write under
    the output folder. A same-user process racing the check is outside this
    examples script's boundary (it could read the inputs directly).
    """
    base = pathlib.Path(base)
    current = base
    for part in pathlib.Path(path).relative_to(base).parts:
        current = current / part
        if current.is_symlink():
            refuse(f"{code}: {current}")


def derive(manifest, kind, cid, requires_name):
    if kind == "content":
        # The edge is the one the product manifest already states: the
        # content's `viewer` names the page its pin must reach.
        viewer = manifest.get("viewer")
        if not isinstance(viewer, str) or not plain_name(viewer):
            refuse("derive_manifest_viewer_missing")
        if requires_name is None:
            requires_name = viewer
        elif requires_name != viewer:
            refuse(f"derive_manifest_requires_name_not_viewer: {requires_name}")
    elif requires_name is None:
        refuse("derive_manifest_requires_name_missing")
    elif not plain_name(requires_name):
        refuse(f"derive_manifest_requires_name_invalid: {requires_name}")
    if not cid_form(cid):
        refuse(f"derive_manifest_cid_invalid: {cid}")
    refused = sorted(set(manifest) - set(ALLOWED_KEYS) - set(DROPPED_KEYS[kind]))
    if refused:
        refuse(f"derive_manifest_unknown_key: {refused[0]}")
    derived = {key: manifest[key] for key in ALLOWED_KEYS if key in manifest}
    derived.pop("requires", None)
    derived["requires"] = [
        {"name": requires_name, "kind": "capsule", "cid": cid}
    ]
    return derived


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--capsule", required=True,
                        help="product capsule.json, read in place")
    parser.add_argument("--out", required=True,
                        help="output folder outside the checkout")
    parser.add_argument("--cid", required=True,
                        help="core's CID for a page; the page's CID for content")
    parser.add_argument("--requires-name", default=None,
                        help="the pinned bundle's name; required for a page, "
                             "and for content it is the manifest's viewer")
    args = parser.parse_args(argv)

    refuse_output_inside_repo(args.out)
    source = pathlib.Path(os.path.abspath(args.capsule))
    # Every component of the manifest's absolute path, from the filesystem
    # root down, is lstat-checked: a symlinked parent cannot lead the read
    # elsewhere (#1670 Codex r2 Medium).
    refuse_symlink_below(source.anchor, source, "derive_manifest_manifest_symlink")
    try:
        manifest = json.loads(source.read_bytes())
    except (OSError, ValueError):
        refuse(f"derive_manifest_manifest_unreadable: {args.capsule}")
    if not isinstance(manifest, dict):
        refuse(f"derive_manifest_manifest_unreadable: {args.capsule}")
    kind = ROLE_KIND.get(manifest.get("role"))
    if kind is None:
        refuse(f"derive_manifest_role_unsupported: {manifest.get('role')}")

    derived = derive(manifest, kind, args.cid, args.requires_name)

    out = pathlib.Path(os.path.abspath(args.out))
    target = out / "capsule.json"
    # Every component of the output's absolute path, from the filesystem root
    # down to the file, is lstat-checked before mkdir and the write (#1670
    # Codex r3 Medium: a symlinked parent of --out).
    refuse_symlink_below(out.anchor, out, "derive_manifest_output_symlink")
    if target.is_symlink():
        refuse(f"derive_manifest_output_symlink: {target}")
    out.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    with os.fdopen(os.open(target, flags, 0o644), "w") as handle:
        handle.write(json.dumps(derived, indent=2, sort_keys=True) + "\n")
    print(f"derive_manifest: {kind} {source} -> {target}")


if __name__ == "__main__":
    main(sys.argv[1:])
