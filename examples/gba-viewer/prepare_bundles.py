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
`elastos stage-bundle` and does not build the core: the core's CID and name,
and the page's CID, are arguments.
"""
import argparse
import hashlib
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


def refuse(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage_file(source, destination, name, receipt):
    """Copies a product file once; every later run verifies the staged bytes."""
    product = source.read_bytes()
    if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(product)
    staged = destination.read_bytes()
    staged_sha = hashlib.sha256(staged).hexdigest()
    product_sha = hashlib.sha256(product).hexdigest()
    receipt.append(f"{name} staged={staged_sha} product={product_sha}")
    if staged_sha != product_sha:
        refuse(f"prepare_bundles_sha256_differs: {name}")


def stage_page_assets(repo, page_out, receipt):
    source_dir = repo / PAGE_SOURCE
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
        stage_file(source, page_out / relative, name, receipt)
        count += 1
    return count


def derive(repo, manifest, out, cid, requires_name, receipt):
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

    page_count = stage_page_assets(repo, page_out, receipt)
    derive(repo, PAGE_MANIFEST, page_out, args.core_cid, args.core_name, receipt)

    stage_file(repo / CONTENT_SOURCE, content_out / CONTENT_SOURCE.name,
               f"content/{CONTENT_SOURCE.name}", receipt)
    derive(repo, CONTENT_MANIFEST, content_out, args.page_cid, None, receipt)

    out.mkdir(parents=True, exist_ok=True)
    (out / "receipt.txt").write_text("\n".join(sorted(receipt)) + "\n")
    print(f"prepare_bundles: page {page_count} files, content 1 file, "
          f"manifests derived, receipt {out / 'receipt.txt'}")


if __name__ == "__main__":
    main(sys.argv[1:])
