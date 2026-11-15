#!/usr/bin/env python3
"""Build the two bundle SOURCE folders for the GBA page and one game.

The page folder holds the product page assets byte-for-byte
(`capsules/gba-emulator/browser/**`, `browser/UPSTREAM.md` included) and a
by-CID manifest derived by `derive_manifest.py`. The content folder holds the
product ROM byte-for-byte at the path its product folder has it
(`capsules/gba-ucity/ucity.gba`) and a by-CID manifest derived the same way.

No product byte is copied into the checkout; the output folder is named on the
command line and must be outside it. Each staged byte is compared with the
product byte it came from, and the sha256 of every staged file and of every
product original is written to the receipt. This script does not run
`elastos stage-bundle`. The core's CID and name, and the page's CID, are
arguments. The core's bundle SOURCE folder is staged only when its built
component is present; otherwise the output is unchanged and the run says so.
"""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import derive_manifest as mapping  # noqa: E402

PAGE_SOURCE = pathlib.Path("capsules/gba-emulator/browser")
PAGE_MANIFEST = pathlib.Path("capsules/gba-emulator/capsule.json")
CONTENT_SOURCE = pathlib.Path("capsules/gba-ucity/ucity.gba")
CONTENT_MANIFEST = pathlib.Path("capsules/gba-ucity/capsule.json")
CORE_SOURCE = pathlib.Path("examples/gba-viewer/core")


def refuse(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage_file(repo, source, out, destination, name, receipt):
    """Copies a product file once; every later run verifies the staged bytes.

    Neither the product path below the checkout nor the staged path below the
    output folder may pass through a symlink (lstat on every component).
    """
    mapping.refuse_symlink_below(repo, source, "prepare_bundles_source_symlink")
    mapping.refuse_symlink_below(out, destination, "prepare_bundles_output_symlink")
    product = source.read_bytes()
    if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        with os.fdopen(os.open(destination, flags, 0o644), "wb") as handle:
            handle.write(product)
    staged = destination.read_bytes()
    staged_sha = hashlib.sha256(staged).hexdigest()
    product_sha = hashlib.sha256(product).hexdigest()
    receipt.append(f"{name} staged={staged_sha} product={product_sha}")
    if staged_sha != product_sha:
        refuse(f"prepare_bundles_sha256_differs: {name}")


def stage_page_assets(repo, out, page_out, receipt):
    source_dir = repo / PAGE_SOURCE
    mapping.refuse_symlink_below(repo, source_dir, "prepare_bundles_source_symlink")
    if not source_dir.is_dir():
        refuse(f"prepare_bundles_source_missing: {PAGE_SOURCE}")
    count = 0
    for source in sorted(source_dir.rglob("*")):
        if source.is_symlink():
            refuse(f"prepare_bundles_not_regular_file: {source.relative_to(repo)}")
        if source.is_dir():
            continue
        if not source.is_file():
            refuse(f"prepare_bundles_not_regular_file: {source.relative_to(repo)}")
        # The bundle keeps the product layout: `browser/index.html` is the
        # entrypoint, so the page folder mirrors `capsules/gba-emulator/`.
        relative = source.relative_to(source_dir.parent)
        name = f"page/{relative}"
        stage_file(repo, source, out, page_out / relative, name, receipt)
        count += 1
    return count


def derive(repo, manifest, out, cid, requires_name, receipt):
    mapping.refuse_symlink_below(repo, repo / manifest, "prepare_bundles_source_symlink")
    command = [
        sys.executable, "-I", str(HERE / "derive_manifest.py"),
        "--capsule", str(repo / manifest),
        "--out", str(out),
        "--cid", cid,
    ]
    if requires_name is not None:
        command += ["--requires-name", requires_name]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(result.returncode)
    derived = out / "capsule.json"
    receipt.append(f"{out.name}/capsule.json staged={sha256(derived)} product=derived")


def stage_core(repo, out, core_name, receipt):
    """The core's bundle SOURCE folder, when the component has been built.

    The core manifest is its own, not derived: a program pins nothing and is
    the page's one pin. The built component and that manifest are copied
    byte-for-byte. Without the component the output is unchanged and the run
    says so.
    """
    source_dir = repo / CORE_SOURCE
    manifest_path = source_dir / "capsule.json"
    mapping.refuse_symlink_below(repo, manifest_path, "prepare_bundles_source_symlink")
    if not manifest_path.is_file():
        print(f"prepare_bundles: core manifest absent at {CORE_SOURCE}; staging unchanged")
        return False
    try:
        manifest = json.loads(manifest_path.read_bytes())
    except (OSError, ValueError):
        refuse(f"prepare_bundles_core_manifest_unreadable: {CORE_SOURCE / 'capsule.json'}")
    if not isinstance(manifest, dict):
        refuse(f"prepare_bundles_core_manifest_unreadable: {CORE_SOURCE / 'capsule.json'}")
    if manifest.get("name") != core_name:
        refuse(f"prepare_bundles_core_name_differs: {manifest.get('name')}")
    entrypoint = manifest.get("entrypoint")
    if (
        not isinstance(entrypoint, str)
        or not entrypoint
        or pathlib.PurePosixPath(entrypoint).is_absolute()
        or ".." in pathlib.PurePosixPath(entrypoint).parts
    ):
        refuse(f"prepare_bundles_core_entrypoint_invalid: {entrypoint}")
    component = source_dir / entrypoint
    if not component.is_file():
        print(
            f"prepare_bundles: core not built ({CORE_SOURCE / entrypoint}); "
            "staging unchanged"
        )
        return False
    core_out = out / "core"
    for source in (manifest_path, component):
        stage_file(repo, source, out, core_out / source.name, f"core/{source.name}", receipt)
    return True


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True,
                        help="output folder outside the checkout")
    parser.add_argument("--core-cid", required=True,
                        help="the core's CID: the page's one pin")
    parser.add_argument("--core-name", required=True,
                        help="the core's manifest name: the page's pin name")
    parser.add_argument("--page-cid", required=True,
                        help="the page's CID: the content's one pin")
    args = parser.parse_args(argv)

    repo = mapping.REPO_ROOT
    out = pathlib.Path(args.out).resolve()
    mapping.refuse_output_inside_repo(args.out)

    page_out = out / "page"
    content_out = out / "content"
    receipt = []

    mapping.refuse_symlink_below(out, page_out, "prepare_bundles_output_symlink")
    mapping.refuse_symlink_below(out, content_out, "prepare_bundles_output_symlink")
    page_count = stage_page_assets(repo, out, page_out, receipt)
    derive(repo, PAGE_MANIFEST, page_out, args.core_cid, args.core_name, receipt)

    stage_file(repo, repo / CONTENT_SOURCE, out, content_out / CONTENT_SOURCE.name,
               f"content/{CONTENT_SOURCE.name}", receipt)
    derive(repo, CONTENT_MANIFEST, content_out, args.page_cid, None, receipt)

    core_staged = stage_core(repo, out, args.core_name, receipt)

    out.mkdir(parents=True, exist_ok=True)
    mapping.refuse_symlink_below(out, out / "receipt.txt", "prepare_bundles_output_symlink")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    with os.fdopen(os.open(out / "receipt.txt", flags, 0o644), "w") as handle:
        handle.write("\n".join(sorted(receipt)) + "\n")
    core = "core staged" if core_staged else "core not built, staging unchanged"
    print(f"prepare_bundles: page {page_count} files, content 1 file, {core}, "
          f"manifests derived, receipt {out / 'receipt.txt'}")


if __name__ == "__main__":
    main(sys.argv[1:])
