#!/usr/bin/env python3
"""Rows for AP4 slice 1a: the by-CID mapping and the staging script.

Every row drives the real script as a subprocess. Expected values are written
here as literals: the product manifests' own keys, the uCity ROM's sha256, and
two CIDs of valid form. Nothing is compared with a value the code under test
produced.
"""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
DERIVE = HERE / "derive_manifest.py"
PREPARE = HERE / "prepare_bundles.py"

PAGE_MANIFEST = REPO_ROOT / "capsules" / "gba-emulator" / "capsule.json"
CONTENT_MANIFEST = REPO_ROOT / "capsules" / "gba-ucity" / "capsule.json"
PAGE_SOURCE = REPO_ROOT / "capsules" / "gba-emulator" / "browser"
CORE_SOURCE = REPO_ROOT / "examples" / "gba-viewer" / "core"
CORE_COMPONENT = CORE_SOURCE / "gba-viewer-core.component.wasm"
CORE_FILES = {"capsule.json", "gba-viewer-core.component.wasm"}

# CIDs of valid form (CIDv1, dag-pb, sha2-256, base32), made by hand for these
# rows. They pin nothing in the store; slice 3 stages the real bundles.
CORE_CID = "bafybeigijtnr7xsdt43yd6gmd32aut4zsnhypc4plrr3vz5wsnn5z2bdde"
PAGE_CID = "bafybeigg4bqmwko7ft4lkehcd6hvuzi2wx3w4kix7xgvkoheyrvbcc4nry"
CORE_NAME = "gba-viewer-core"

# facts.md section 1.3, read back with `shasum -a 256` when these rows were written.
UCITY_SHA256 = "069230a67939896c15cba86f0bffe31d12655597e2ac4cfed5b832e216b57bff"

PAGE_KEYS = {
    "schema", "name", "version", "description", "author", "role", "type",
    "execution", "runtime_abi", "bus_contract", "entrypoint", "projections",
    "window_policy", "icon", "resources", "requires",
}
CONTENT_KEYS = {
    "schema", "name", "version", "description", "author", "role", "type",
    "entrypoint", "icon", "requires",
}
PAGE_FILES = {
    "browser/UPSTREAM.md",
    "browser/assets/fonts/Inter-latin-var.woff2",
    "browser/elastos-accent-picker.js",
    "browser/elastos-theme.js",
    "browser/elastos-ui.css",
    "browser/emulator.js",
    "browser/favicon.svg",
    "browser/gba-input.js",
    "browser/icons/icon-32.png",
    "browser/icons/icon-64.png",
    "browser/icons/icon-128.png",
    "browser/icons/icon-256.png",
    "browser/index.html",
    "browser/mgba.js",
    "browser/mgba.wasm",
    "browser/style.css",
}


def run(script, *arguments):
    return subprocess.run(
        [sys.executable, "-I", str(script), *arguments],
        capture_output=True, text=True, timeout=120,
    )


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def derive(capsule, out, cid, name=None):
    arguments = ["--capsule", str(capsule), "--out", str(out), "--cid", cid]
    if name is not None:
        arguments += ["--requires-name", name]
    return run(DERIVE, *arguments)


def prepare(out):
    return run(
        PREPARE,
        "--out", str(out),
        "--core-cid", CORE_CID,
        "--core-name", CORE_NAME,
        "--page-cid", PAGE_CID,
    )


def fake_checkout(base):
    """A throwaway checkout: the two scripts and the two product manifests
    and page folder copied; the ROM is left for the row to place."""
    fake = base / "repo"
    (fake / "examples" / "gba-viewer").mkdir(parents=True)
    for script in ("derive_manifest.py", "prepare_bundles.py"):
        shutil.copy(HERE / script, fake / "examples" / "gba-viewer" / script)
    shutil.copytree(REPO_ROOT / "capsules" / "gba-emulator",
                    fake / "capsules" / "gba-emulator", symlinks=True)
    (fake / "capsules" / "gba-ucity").mkdir(parents=True)
    shutil.copy(CONTENT_MANIFEST, fake / "capsules" / "gba-ucity" / "capsule.json")
    return fake


class Rows(unittest.TestCase):
    def test_r1_the_page_manifest_is_derived_by_the_mapping(self):
        """r1 the derived page manifest has no interfaces or permissions"""
        with tempfile.TemporaryDirectory(prefix="gba-r1-") as temporary:
            out = pathlib.Path(temporary).resolve() / "page"
            result = derive(PAGE_MANIFEST, out, CORE_CID, CORE_NAME)
            self.assertEqual(result.returncode, 0, result.stderr)
            derived = json.loads((out / "capsule.json").read_text())
            product = json.loads(PAGE_MANIFEST.read_text())

            self.assertNotIn("interfaces", derived)
            self.assertNotIn("permissions", derived)
            self.assertEqual(set(derived), PAGE_KEYS)
            self.assertEqual(derived["requires"], [
                {"name": CORE_NAME, "kind": "capsule", "cid": CORE_CID},
            ])
            for key in PAGE_KEYS - {"requires"}:
                self.assertEqual(derived[key], product[key], key)

    def test_r2_the_content_manifest_is_derived_by_the_mapping(self):
        """r2 the derived content manifest has no viewer interfaces or permissions"""
        with tempfile.TemporaryDirectory(prefix="gba-r2-") as temporary:
            out = pathlib.Path(temporary).resolve() / "content"
            result = derive(CONTENT_MANIFEST, out, PAGE_CID)
            self.assertEqual(result.returncode, 0, result.stderr)
            derived = json.loads((out / "capsule.json").read_text())
            product = json.loads(CONTENT_MANIFEST.read_text())

            for key in ("viewer", "interfaces", "permissions"):
                self.assertNotIn(key, derived)
            self.assertEqual(set(derived), CONTENT_KEYS)
            self.assertEqual(derived["requires"], [
                {"name": "gba-emulator", "kind": "capsule", "cid": PAGE_CID},
            ])
            for key in CONTENT_KEYS - {"requires"}:
                self.assertEqual(derived[key], product[key], key)

    def test_r3_an_unknown_key_is_refused_by_name(self):
        """r3 an unknown key in a product manifest copy is refused"""
        with tempfile.TemporaryDirectory(prefix="gba-r3-") as temporary:
            root = pathlib.Path(temporary).resolve()
            copy = root / "capsule.json"
            manifest = json.loads(PAGE_MANIFEST.read_text())
            manifest["agent"] = {"id": "nobody"}
            manifest["capabilities"] = ["x"]
            copy.write_text(json.dumps(manifest))
            out = root / "page"
            result = derive(copy, out, CORE_CID, CORE_NAME)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(result.stderr, "derive_manifest_unknown_key: agent\n")
            self.assertFalse(out.exists())

    def test_r4_staged_bytes_equal_the_product_files(self):
        """r4 staged bytes hash to the product bytes, and a changed byte fails"""
        with tempfile.TemporaryDirectory(prefix="gba-r4-") as temporary:
            out = pathlib.Path(temporary) / "out"
            result = prepare(out)
            self.assertEqual(result.returncode, 0, result.stderr)

            staged_rom = out / "content" / "ucity.gba"
            product_rom = REPO_ROOT / "capsules" / "gba-ucity" / "ucity.gba"
            self.assertEqual(sha256(staged_rom), UCITY_SHA256)
            self.assertEqual(staged_rom.read_bytes(), product_rom.read_bytes())

            staged_pages = {
                str(path.relative_to(out / "page"))
                for path in (out / "page").rglob("*") if path.is_file()
            }
            self.assertEqual(staged_pages, PAGE_FILES | {"capsule.json"})
            for name in PAGE_FILES:
                self.assertEqual(
                    (out / "page" / name).read_bytes(),
                    (PAGE_SOURCE / name[len("browser/"):]).read_bytes(), name,
                )

            # The core's SOURCE folder is staged only when it has been built.
            core_built = CORE_COMPONENT.is_file()
            if core_built:
                staged_core = {path.name for path in (out / "core").iterdir()}
                self.assertEqual(staged_core, CORE_FILES)
                for name in CORE_FILES:
                    self.assertEqual(
                        (out / "core" / name).read_bytes(),
                        (CORE_SOURCE / name).read_bytes(), name,
                    )
            else:
                self.assertFalse((out / "core").exists())

            receipt = (out / "receipt.txt").read_text().splitlines()
            self.assertEqual(
                f"content/ucity.gba staged={UCITY_SHA256} product={UCITY_SHA256}",
                next(line for line in receipt if line.startswith("content/ucity.gba ")),
            )
            products = {
                f"page/{name}": PAGE_SOURCE / name[len("browser/"):]
                for name in PAGE_FILES
            }
            products["content/ucity.gba"] = product_rom
            recorded = {}
            expected = set(products) | {"page/capsule.json", "content/capsule.json"}
            if core_built:
                expected |= {f"core/{name}" for name in CORE_FILES}
            for line in receipt:
                name, rest = line.split(" ", 1)
                recorded[name] = dict(
                    part.split("=", 1) for part in rest.split(" ") if "=" in part
                )
                self.assertEqual(recorded[name]["staged"], sha256(out / name), name)
                if name.startswith("core/"):
                    self.assertEqual(
                        recorded[name]["product"],
                        sha256(CORE_SOURCE / name[len("core/"):]), name,
                    )
                elif name.endswith("capsule.json"):
                    self.assertEqual(recorded[name]["product"], "derived", name)
                else:
                    self.assertEqual(
                        recorded[name]["product"], sha256(products[name]), name,
                    )
            self.assertEqual(set(recorded), expected)

            # One changed staged byte is caught before anything else is written.
            staged_rom.write_bytes(staged_rom.read_bytes()[:-1] + b"\x00")
            again = prepare(out)
            self.assertEqual(again.returncode, 1, again.stdout)
            self.assertEqual(
                again.stderr, "prepare_bundles_sha256_differs: content/ucity.gba\n",
            )

    def test_r5_an_output_folder_inside_the_repo_is_refused(self):
        """r5 an output folder inside the checkout is refused"""
        # Run in a throwaway checkout, so a planted (removed) refusal writes
        # only there and never inside the real checkout (#1670 Codex r1 Low).
        with tempfile.TemporaryDirectory(prefix="gba-r5-") as temporary:
            fake = fake_checkout(pathlib.Path(temporary).resolve())
            viewer = fake / "examples" / "gba-viewer"
            inside = viewer / "probe-inside-repo"
            self.assertFalse(inside.exists())
            result = run(
                viewer / "derive_manifest.py",
                "--capsule", str(fake / "capsules" / "gba-emulator" / "capsule.json"),
                "--out", str(inside), "--cid", CORE_CID,
                "--requires-name", CORE_NAME,
            )
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(
                result.stderr, f"derive_manifest_output_inside_repo: {inside}\n",
            )
            self.assertFalse(inside.exists())

            result = run(
                viewer / "prepare_bundles.py",
                "--out", str(inside), "--core-cid", CORE_CID,
                "--core-name", CORE_NAME, "--page-cid", PAGE_CID,
            )
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(
                result.stderr, f"derive_manifest_output_inside_repo: {inside}\n",
            )
            self.assertFalse(inside.exists())

    def test_r6_a_symlinked_output_folder_is_refused(self):
        """r6 a symlink at out/page is refused and nothing is written through it"""
        with tempfile.TemporaryDirectory(prefix="gba-r6-") as temporary:
            base = pathlib.Path(temporary).resolve()
            victim = base / "victim"
            victim.mkdir()
            out = base / "out"
            out.mkdir()
            (out / "page").symlink_to(victim)
            result = prepare(out)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(
                result.stderr, f"prepare_bundles_output_symlink: {out / 'page'}\n",
            )
            self.assertEqual(list(victim.iterdir()), [])

    def test_r7_a_symlinked_derived_manifest_is_refused(self):
        """r7 a symlink at out/page/capsule.json is refused and its target kept"""
        with tempfile.TemporaryDirectory(prefix="gba-r7-") as temporary:
            base = pathlib.Path(temporary).resolve()
            victim = base / "victim.txt"
            victim.write_bytes(b"keep\n")
            out = base / "out"
            (out / "page").mkdir(parents=True)
            (out / "page" / "capsule.json").symlink_to(victim)
            result = prepare(out)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(
                result.stderr,
                f"derive_manifest_output_symlink: {out / 'page' / 'capsule.json'}\n",
            )
            self.assertEqual(victim.read_bytes(), b"keep\n")

    def test_r8_a_symlinked_product_rom_is_refused(self):
        """r8 a product ROM that is a symlink is refused before it is read"""
        with tempfile.TemporaryDirectory(prefix="gba-r8-") as temporary:
            base = pathlib.Path(temporary).resolve()
            # A throwaway checkout: the two scripts and the product folders,
            # with the ROM replaced by a symlink to the real ROM.
            fake = fake_checkout(base)
            rom = fake / "capsules" / "gba-ucity" / "ucity.gba"
            rom.symlink_to(REPO_ROOT / "capsules" / "gba-ucity" / "ucity.gba")
            out = base / "out"
            result = run(
                fake / "examples" / "gba-viewer" / "prepare_bundles.py",
                "--out", str(out), "--core-cid", CORE_CID,
                "--core-name", CORE_NAME, "--page-cid", PAGE_CID,
            )
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(
                result.stderr, f"prepare_bundles_source_symlink: {rom}\n",
            )
            self.assertFalse((out / "content" / "ucity.gba").exists())

    def test_r9_a_manifest_under_a_symlinked_folder_is_refused(self):
        """r9 derive_manifest refuses a product manifest reached through a symlinked folder"""
        with tempfile.TemporaryDirectory(prefix="gba-r9-") as temporary:
            base = pathlib.Path(temporary).resolve()
            real = base / "elsewhere"
            real.mkdir()
            shutil.copy(PAGE_MANIFEST, real / "capsule.json")
            (base / "linked").symlink_to(real)
            capsule = base / "linked" / "capsule.json"
            out = base / "out"
            result = derive(capsule, out, CORE_CID, CORE_NAME)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(
                result.stderr, f"derive_manifest_manifest_symlink: {base / 'linked'}\n",
            )
            self.assertFalse(out.exists())

    def test_r10_an_output_under_a_symlinked_folder_is_refused(self):
        """r10 derive_manifest refuses an output folder under a symlinked folder"""
        with tempfile.TemporaryDirectory(prefix="gba-r10-") as temporary:
            base = pathlib.Path(temporary).resolve()
            victim = base / "victim"
            victim.mkdir()
            (base / "linked").symlink_to(victim)
            out = base / "linked" / "page"
            result = derive(PAGE_MANIFEST, out, CORE_CID, CORE_NAME)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(
                result.stderr, f"derive_manifest_output_symlink: {base / 'linked'}\n",
            )
            self.assertEqual(list(victim.iterdir()), [])

    def test_r11_a_cid_that_is_not_cid_form_is_refused(self):
        """r11 a cid that is not CIDv1 base32 is refused by name"""
        with tempfile.TemporaryDirectory(prefix="gba-r11-") as temporary:
            out = pathlib.Path(temporary).resolve() / "page"
            result = derive(PAGE_MANIFEST, out, "not-a-cid", CORE_NAME)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(result.stderr, "derive_manifest_cid_invalid: not-a-cid\n")
            self.assertFalse(out.exists())

    def test_r12_a_requires_name_that_is_not_plain_is_refused(self):
        """r12 a requires name that is not plain is refused by name"""
        with tempfile.TemporaryDirectory(prefix="gba-r12-") as temporary:
            out = pathlib.Path(temporary).resolve() / "page"
            result = derive(PAGE_MANIFEST, out, CORE_CID, "bad name")
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(
                result.stderr, "derive_manifest_requires_name_invalid: bad name\n",
            )
            self.assertFalse(out.exists())

    def test_r13_a_content_requires_name_that_is_not_the_viewer_is_refused(self):
        """r13 content refuses a requires name that is not the manifest's viewer"""
        with tempfile.TemporaryDirectory(prefix="gba-r13-") as temporary:
            out = pathlib.Path(temporary).resolve() / "content"
            result = derive(CONTENT_MANIFEST, out, PAGE_CID, "not-the-viewer")
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(
                result.stderr,
                "derive_manifest_requires_name_not_viewer: not-the-viewer\n",
            )
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
