#!/usr/bin/env python3
"""Break each refusal, see its test fail, restore it.

Usage: python3 -I falsify.py            # guest falsifiers (host tests, fast)
       python3 -I falsify.py --runtime  # also rebuild the component once per
                                        # runtime falsifier and run host-test

Each falsifier replaces one exact line, runs the named tests, and requires
them to FAIL. The file is restored from its saved bytes afterwards, also on
error or Ctrl-C. The script exits non-zero if any falsifier is not caught or
its line is not found exactly once.
"""
import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent

# (name, file, exact old text, new text, guest test filters)
GUEST = [
    (
        "album read without a grant",
        "src/lib.rs",
        'let album_grant = grant(bus, ALBUM_URI, "read", "read the album to play")?;',
        'let album_grant = grant(bus, ALBUM_URI, "read", "read the album to play").unwrap_or_default();',
        ["album_without_a_read_grant_is_denied_before_any_read"],
    ),
    (
        "image read without a grant",
        "src/lib.rs",
        'let item_grant = grant(bus, uri, "read", "read an image named in the album")?;',
        'let item_grant = grant(bus, uri, "read", "read an image named in the album").unwrap_or_default();',
        ["image_without_a_read_grant_is_denied_before_any_read_of_it"],
    ),
    (
        "playlist write without a grant",
        "src/lib.rs",
        'let write_grant = grant(bus, PLAYLIST_URI, "write", "write the checked playlist")?;',
        'let write_grant = grant(bus, PLAYLIST_URI, "write", "write the checked playlist").unwrap_or_default();',
        ["playlist_without_a_write_grant_is_denied_and_not_written"],
    ),
    (
        "wrong type accepted as PNG",
        "src/image.rs",
        "    Err(HeaderError::UnknownType)\n}",
        "    Ok(Kind::Png)\n}",
        ["wrong_type_is_refused_and_the_body_is_not_read"],
    ),
    (
        "truncated magic treated as unknown",
        "src/image.rs",
        "if is_prefix_of_magic(header) {",
        "if false && is_prefix_of_magic(header) {",
        ["truncated_magic_is_refused"],
    ),
    (
        "size checked only after reading the body",
        "src/lib.rs",
        "if extends_past(bus, uri, &item_grant, MAX_OBJECT_BYTES)? {",
        "if false && extends_past(bus, uri, &item_grant, MAX_OBJECT_BYTES)? {",
        ["oversize_is_refused_without_reading_the_body"],
    ),
    (
        "side limit removed",
        "src/lib.rs",
        "if width > MAX_SIDE || height > MAX_SIDE ||",
        "if height > MAX_SIDE ||",
        ["dimension_limits_are_enforced_at_the_boundary"],
    ),
    (
        "album body budget not spent",
        "src/lib.rs",
        "check_item(bus, index, item, MAX_ALBUM_BODY_BYTES - body_bytes)?",
        "check_item(bus, index, item, MAX_ALBUM_BODY_BYTES)?",
        ["album_whose_images_exceed_the_body_budget_is_refused_at_the_item_that_crosses_it"],
    ),
    (
        "provider status ignored",
        "src/bus.rs",
        'Some("ok") if parsed.has_data => Ok(parsed),',
        '_ if parsed.has_data => Ok(parsed),',
        ["an_error_answer_that_also_carries_data_is_still_an_error"],
    ),
    (
        "unknown album fields allowed",
        "src/album.rs",
        '.find(|key| !matches!(key.as_str(), "schema" | "items"))',
        '.find(|key| !matches!(key.as_str(), "schema" | "items" | "x"))',
        ["malformed_albums_are_refused_before_any_image_is_read"],
    ),
    (
        "dot-dot segments allowed",
        "src/album.rs",
        '.any(|part| part.is_empty() || part == "." || part == "..")',
        '.any(|part| part.is_empty() || part == ".")',
        ["malformed_albums_are_refused_before_any_image_is_read"],
    ),
]

# Built into the component and caught by host-test inside ComponentProvider.
RUNTIME = [
    (
        "wrong type accepted as PNG (in the component)",
        "src/image.rs",
        "    Err(HeaderError::UnknownType)\n}",
        "    Ok(Kind::Png)\n}",
        ["wrong_type_is_refused_through_the_runtime"],
    ),
    (
        "image read without a grant (in the component)",
        "src/lib.rs",
        'let item_grant = grant(bus, uri, "read", "read an image named in the album")?;',
        'let item_grant = grant(bus, uri, "read", "read an image named in the album").unwrap_or_default();',
        ["no_grant_is_denied_through_the_runtime"],
    ),
]


def env():
    environment = dict(os.environ)
    environment.setdefault("RUST_TEST_THREADS", "2")
    return environment


def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, env=env(), capture_output=True, text=True)


def guest_tests_fail(filters):
    for name in filters:
        result = run(["cargo", "test", "--locked", "--lib", "--", "--exact", f"tests::{name}"], HERE)
        if result.returncode == 0:
            return False
    return True


def runtime_tests_fail(filters):
    build = run([str(HERE / "build.sh")], HERE)
    if build.returncode != 0:
        print(build.stderr[-2000:])
        raise SystemExit("component build failed under a falsifier")
    for name in filters:
        result = run(
            ["cargo", "test", "--locked", "--test", "component", "--", "--exact", name],
            HERE / "host-test",
        )
        if result.returncode == 0:
            return False
    return True


def falsify(cases, failing):
    missed = []
    for name, relative, old, new, filters in cases:
        path = HERE / relative
        saved = path.read_bytes()
        text = saved.decode()
        if text.count(old) != 1:
            raise SystemExit(f"{name}: expected the line once in {relative}, found {text.count(old)}")
        try:
            path.write_text(text.replace(old, new))
            caught = failing(filters)
        finally:
            path.write_bytes(saved)
        print(f"{'caught' if caught else 'MISSED'}: {name} -> {', '.join(filters)}")
        if not caught:
            missed.append(name)
    return missed


def main():
    missed = falsify(GUEST, guest_tests_fail)
    if "--runtime" in sys.argv[1:]:
        try:
            missed += falsify(RUNTIME, runtime_tests_fail)
        finally:
            # Leave the unmutated component in place.
            if run([str(HERE / "build.sh")], HERE).returncode != 0:
                raise SystemExit("restoring the component build failed")
    if missed:
        raise SystemExit(f"{len(missed)} falsifier(s) not caught: {missed}")
    print("all falsifiers caught")


if __name__ == "__main__":
    main()
