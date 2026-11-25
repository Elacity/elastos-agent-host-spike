#!/usr/bin/env python3
"""Break each GBA core rule and each derive_manifest rule, see its test fail.

Usage: python3 -I falsify.py [--check] [name-part ...]

Each case replaces one exact text, runs the named test, and requires that
test to FAIL. A Rust case must compile. The file is restored afterwards,
also on error. The script exits non-zero if any case is not caught or its
text is not found exactly once.

The runner is the capsule kit's (examples/capsule-kit/falsify).
"""
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
CORE = HERE / "core"
sys.path.insert(0, str(HERE.parent / "capsule-kit" / "falsify"))
import falsify_kit as kit  # noqa: E402

# Cargo's colour codes hide the "Compiling <crate>" line the runner requires.
os.environ["CARGO_TERM_COLOR"] = "never"

LIB = CORE / "src" / "lib.rs"
DERIVE = HERE / "derive_manifest.py"

# (name, file, [(old, new)], [test])
CORE_CASES = [
    (
        "MAX_ROM_BYTES is not checked",
        LIB,
        [(
            "    if rom.size > MAX_ROM_BYTES {\n",
            "    if false && rom.size > MAX_ROM_BYTES {\n",
        )],
        ["tests::c2_a_rom_one_byte_over_the_cap_is_refused_by_name"],
    ),
    (
        "a digest size that differs is accepted",
        LIB,
        [(
            "    if digest.size != rom.size {\n",
            "    if false && digest.size != rom.size {\n",
        )],
        ["tests::r2_a_digest_size_that_differs_from_the_listing_is_refused_by_name"],
    ),
    (
        "a digest algorithm other than sha256 is accepted",
        LIB,
        [(
            '    if digest.algorithm != "sha256" {\n',
            '    if false && digest.algorithm != "sha256" {\n',
        )],
        ["tests::r4_a_digest_algorithm_other_than_sha256_is_refused"],
    ),
    (
        "a digest that is not 64 lowercase hex is accepted",
        LIB,
        [(
            "    if !lowercase_hex64(&digest.sha256) {\n",
            "    if false && !lowercase_hex64(&digest.sha256) {\n",
        )],
        ["tests::r3_a_digest_sha256_that_is_not_64_lowercase_hex_is_refused"],
    ),
    (
        "RomEmpty is not checked",
        LIB,
        [(
            "    if rom.size == 0 {\n",
            "    if false && rom.size == 0 {\n",
        )],
        ["tests::c3_a_missing_or_empty_rom_is_refused_by_name"],
    ),
    (
        "RomAmbiguous keeps the first ROM",
        LIB,
        [(
            "        count => Err(CoreError::RomAmbiguous(count)),\n",
            "        _ => Ok(roms.remove(0)),\n",
        )],
        ["tests::c6_two_roms_are_refused_by_name"],
    ),
]

DERIVE_CASES = [
    (
        "an unknown manifest key is kept",
        DERIVE,
        [(
            "    if refused:\n        refuse(f\"derive_manifest_unknown_key: {refused[0]}\")\n",
            "    if False and refused:\n        refuse(f\"derive_manifest_unknown_key: {refused[0]}\")\n",
        )],
        ["Rows.test_r3_an_unknown_key_is_refused_by_name"],
    ),
    (
        "a dropped key is copied into the derived manifest",
        DERIVE,
        [(
            "    derived = {key: manifest[key] for key in ALLOWED_KEYS if key in manifest}\n",
            "    derived = {key: manifest[key] for key in (*ALLOWED_KEYS, *DROPPED_KEYS[kind]) if key in manifest}\n",
        )],
        ["Rows.test_r1_the_page_manifest_is_derived_by_the_mapping"],
    ),
    (
        "the requires pin drops the cid",
        DERIVE,
        [(
            '        {"name": requires_name, "kind": "capsule", "cid": cid}\n',
            '        {"name": requires_name, "kind": "capsule", "cid": "b"}\n',
        )],
        ["Rows.test_r1_the_page_manifest_is_derived_by_the_mapping"],
    ),
    (
        "cid_form is not checked",
        DERIVE,
        [(
            "    if not cid_form(cid):\n",
            "    if False and not cid_form(cid):\n",
        )],
        ["Rows.test_r11_a_cid_that_is_not_cid_form_is_refused"],
    ),
    (
        "plain_name is not checked",
        DERIVE,
        [(
            "    elif not plain_name(requires_name):\n",
            "    elif False and not plain_name(requires_name):\n",
        )],
        ["Rows.test_r12_a_requires_name_that_is_not_plain_is_refused"],
    ),
    (
        "a content requires name need not be the viewer",
        DERIVE,
        [(
            "        elif requires_name != viewer:\n",
            "        elif False and requires_name != viewer:\n",
        )],
        ["Rows.test_r13_a_content_requires_name_that_is_not_the_viewer_is_refused"],
    ),
    (
        "an output folder inside the checkout is accepted",
        DERIVE,
        [(
            "    if real == root or real.startswith(root + os.sep):\n",
            "    if False and (real == root or real.startswith(root + os.sep)):\n",
        )],
        ["Rows.test_r5_an_output_folder_inside_the_repo_is_refused"],
    ),
    (
        "a symlink on the manifest or output path is followed",
        DERIVE,
        [(
            "        if current.is_symlink():\n",
            "        if False and current.is_symlink():\n",
        )],
        ["Rows.test_r10_an_output_under_a_symlinked_folder_is_refused"],
    ),
]


def core_fails(name):
    return kit.cargo_test_fails(
        CORE, ["--manifest-path", str(CORE / "Cargo.toml")], name,
    )


def rows_fail(name):
    result = kit.run(
        [sys.executable, "-I", str(HERE / "rows_test.py"), name], HERE,
    )
    output = result.stderr + result.stdout
    if "Ran 1 test" not in output:
        raise SystemExit(f"{name} did not run:\n{output[-2000:]}")
    if "ERROR:" in output:
        raise SystemExit(f"{name} did not run cleanly:\n{output[-2000:]}")
    return result.returncode != 0 and "FAILED (failures=1)" in output


def prepare_derive():
    compile(DERIVE.read_text(), str(DERIVE), "exec")


def prepare_core():
    kit.cargo_compiles(CORE, ["--manifest-path", str(CORE / "Cargo.toml")])


if __name__ == "__main__":
    count = len(CORE_CASES) + len(DERIVE_CASES)
    kit.main(
        [
            (CORE_CASES, prepare_core, core_fails, None, False),
            (DERIVE_CASES, prepare_derive, rows_fail, None, False),
        ],
        done=f"all {count} gba rule falsifiers caught",
    )
