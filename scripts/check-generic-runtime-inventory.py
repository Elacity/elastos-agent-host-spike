#!/usr/bin/env python3
"""Pin the product footprint in the resolved Runtime workspace graph and sources.

This is an inventory gate, not a bare-build claim. The cargo metadata
resolution includes normal, build, and development dependencies for the workspace.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


PRODUCT_PACKAGE = re.compile(
    r"elacity|protected[-_]content|(?:^|[-_])ddrm(?:[-_]|$)"
    r"|(?:^|[-_])dkms(?:[-_]|$)"
    r"|^(?:custody|rights|key|decrypt|protect|drm)[-_]provider$",
    re.IGNORECASE,
)
SOURCE_MARKERS = {
    "protected-content": re.compile(r"protected[-_]content", re.IGNORECASE),
    "ddrm": re.compile(r"(?<![A-Za-z0-9])ddrm(?![A-Za-z0-9])", re.IGNORECASE),
    "dkms": re.compile(r"(?<![A-Za-z0-9])dkms(?![A-Za-z0-9])", re.IGNORECASE),
    **{
        name: re.compile(rf"(?<![A-Za-z0-9]){name.replace('-', '[-_]')}(?![A-Za-z0-9])", re.IGNORECASE)
        for name in (
            "custody-provider", "rights-provider", "key-provider",
            "decrypt-provider", "protect-provider", "drm-provider",
        )
    },
}
BRAND = re.compile(r"elacity(labs|[-_][a-z]+)?", re.IGNORECASE)
QUOTED_NAME = re.compile(
    r"""["']((?:elacity|protected[-_]content|ddrm|dkms)(?:[-_][A-Za-z0-9]+)+)["']""",
    re.IGNORECASE,
)


def relative(root, value):
    return Path(value).relative_to(root).as_posix()


def package_location(root, package):
    if package["source"]:
        return package["source"]
    try:
        return relative(root, package["manifest_path"])
    except ValueError as error:
        raise RuntimeError(
            f"local product package {package['name']} is outside the repository"
        ) from error


def source_names(text):
    found = {name for name, pattern in SOURCE_MARKERS.items() if pattern.search(text)}
    for match in BRAND.finditer(text):
        suffix = (match.group(1) or "").lower().replace("_", "-")
        found.add("elacity" + suffix)
    for match in QUOTED_NAME.finditer(text):
        found.add("literal:" + match.group(1))
    return found


def observed(root):
    command = [
        "cargo", "metadata", "--locked", "--no-default-features",
        "--format-version", "1",
        "--manifest-path", str(root / "elastos/Cargo.toml"),
    ]
    result = subprocess.run(command, cwd=root, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"cargo metadata failed:\n{result.stderr.strip()}")
    metadata = json.loads(result.stdout)
    packages = {package["id"]: package for package in metadata["packages"]}
    members = set(metadata["workspace_members"])
    product_ids = {
        package_id for package_id, package in packages.items()
        if PRODUCT_PACKAGE.search(package["name"])
    }
    product_packages = {
        (package["name"], package_location(root, package))
        for package_id, package in packages.items() if package_id in product_ids
    }
    product_edges = set()
    for node in metadata["resolve"]["nodes"]:
        for dependency in node["deps"]:
            if dependency["pkg"] not in product_ids:
                continue
            for kind in dependency["dep_kinds"]:
                product_edges.add((
                    packages[node["id"]]["name"],
                    packages[dependency["pkg"]]["name"],
                    dependency["name"],
                    kind["kind"] or "normal",
                    kind["target"] or "all",
                ))
    names = set()
    for package_id in members - product_ids:
        package = packages[package_id]
        manifest = Path(package["manifest_path"])
        source_dir = manifest.parent / "src"
        paths = [manifest]
        if source_dir.is_dir():
            paths.extend(source_dir.rglob("*.rs"))
        for path in paths:
            for name in source_names(path.read_text()):
                names.add((relative(root, path), name))
    return product_packages, product_edges, names


def rows(inventory, key, fields):
    result = set()
    for row in inventory[key]:
        if set(row) != set(fields) | {"slice"}:
            raise ValueError(f"{key}: invalid row {row!r}")
        if row["slice"] not in (2, 3, 4, 5):
            raise ValueError(f"{key}: invalid move slice in {row!r}")
        value = tuple(row[field] for field in fields)
        if value in result:
            raise ValueError(f"{key}: duplicate row {value!r}")
        result.add(value)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    inventory = json.loads((root / "scripts/generic-runtime-inventory.json").read_text())
    actual = observed(root)
    expected = (
        rows(inventory, "packages", ("name", "manifest")),
        rows(inventory, "dependencies", ("from", "to", "alias", "kind", "target")),
        rows(inventory, "names", ("file", "name")),
    )
    errors = []
    for label, current, listed in zip(("packages", "dependencies", "names"), actual, expected):
        for item in sorted(current - listed):
            errors.append(f"unlisted product {label}: {item!r}")
        for item in sorted(listed - current):
            errors.append(f"stale product {label}: {item!r}")
    if errors:
        print("Generic Runtime product inventory failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print("Generic Runtime product inventory OK: " + ", ".join(
        f"{label} {len(items)}" for label, items in zip(
            ("packages", "dependencies", "names"), actual,
        )
    ))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, ValueError, KeyError) as error:
        print(f"Generic Runtime product inventory failed: {error}", file=sys.stderr)
        sys.exit(1)
