#!/usr/bin/env python3
"""Break each refusal, see its test fail, restore it.

Usage: python3 -I falsify.py            # guest falsifiers (host tests, fast)
       python3 -I falsify.py --runtime  # also rebuild the component once per
                                        # runtime falsifier and run host-test
       --check                          # only confirm every anchor occurs once
       name parts                       # run only the falsifiers they match

Each falsifier replaces one exact line, runs the named tests, and requires
them to FAIL. The file is restored from its saved bytes afterwards, also on
error or Ctrl-C. The script exits non-zero if any falsifier is not caught or
its line is not found exactly once. The runner is the capsule kit's
(examples/capsule-kit/falsify).
"""
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "capsule-kit" / "falsify"))
import falsify_kit as kit  # noqa: E402

# (name, file, exact old text, new text, guest test filters)
GUEST = [
    # Authority failures stop the run.
    (
        "album read without a grant",
        "src/lib.rs",
        'let album_grant = grant(bus, ALBUM_URI, "read", "read the album to play")?;',
        'let album_grant = grant(bus, ALBUM_URI, "read", "read the album to play").unwrap_or_default();',
        ["album_without_a_read_grant_stops_before_any_read"],
    ),
    (
        "image read without a grant",
        "src/lib.rs",
        'let item_grant = grant(bus, uri, "read", "read the header of an image in the album")?;',
        'let item_grant = grant(bus, uri, "read", "read the header of an image in the album").unwrap_or_default();',
        ["image_without_a_read_grant_stops_the_run_and_is_not_skipped"],
    ),
    (
        "playlist write without a grant",
        "src/lib.rs",
        'let write_grant = grant(bus, PLAYLIST_URI, "write", "write the checked playlist")?;',
        'let write_grant = grant(bus, PLAYLIST_URI, "write", "write the checked playlist").unwrap_or_default();',
        ["playlist_without_a_write_grant_stops_and_is_not_written"],
    ),
    (
        "provider error on a header read skipped instead of stopping",
        "src/lib.rs",
        "let header = read_at(bus, uri, &item_grant, 0, HEADER_BYTES)?;",
        "let header = read_at(bus, uri, &item_grant, 0, HEADER_BYTES).unwrap_or_default();",
        ["a_provider_error_stops_the_run_and_is_not_skipped"],
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
        ["malformed_albums_stop_before_any_image_is_read"],
    ),
    (
        "dot-dot segments allowed",
        "src/album.rs",
        '.any(|part| part.is_empty() || part == "." || part == "..")',
        '.any(|part| part.is_empty() || part == ".")',
        ["malformed_albums_stop_before_any_image_is_read"],
    ),
    # Content failures skip the item.
    (
        "content failure stops the run instead of skipping",
        "src/lib.rs",
        "match check_item(bus, order, item)? {",
        "match check_item(bus, order, item)?.map_err(|_| Refusal::AlbumTooLarge).map(Ok)? {",
        ["a_bad_item_is_skipped_and_the_rest_play_in_order"],
    ),
    (
        "wrong type accepted as PNG",
        "src/image.rs",
        "    Err(HeaderError::UnknownType)\n}",
        "    Ok(Kind::Png)\n}",
        ["wrong_type_is_skipped_after_reading_only_its_header"],
    ),
    (
        "truncated magic treated as unknown",
        "src/image.rs",
        "if is_prefix_of_magic(header) {",
        "if false && is_prefix_of_magic(header) {",
        ["truncated_magic_is_skipped"],
    ),
    (
        "size limit not checked",
        "src/lib.rs",
        "if !read_at(bus, uri, &item_grant, MAX_OBJECT_BYTES, 1)?.is_empty() {",
        "if false && !read_at(bus, uri, &item_grant, MAX_OBJECT_BYTES, 1)?.is_empty() {",
        ["oversize_is_skipped_without_reading_the_body"],
    ),
    (
        "side limit removed",
        "src/lib.rs",
        "if width > MAX_SIDE || height > MAX_SIDE ||",
        "if height > MAX_SIDE ||",
        ["dimension_limits_are_enforced_at_the_boundary"],
    ),
    (
        "JPEG segment cap doubled",
        "src/image.rs",
        "for _ in 0..MAX_JPEG_SEGMENTS {",
        "for _ in 0..MAX_JPEG_SEGMENTS * 2 {",
        ["malformed_headers_are_skipped"],
    ),
    (
        "JPEG segment payloads read",
        "src/image.rs",
        "let marker = read(at, 4)?;",
        "let _payload = read(at, 70_000)?;\n        let marker = read(at, 4)?;",
        ["a_jpeg_frame_header_after_large_exif_is_found_without_reading_the_payloads"],
    ),
    # Body shapes the localhost provider accepts.
    (
        "playlist written as a string without append (the P1 shape)",
        "src/bus.rs",
        'json!({ "path": uri, "content": content, "append": false })',
        'json!({ "path": uri, "content": String::from_utf8_lossy(content) })',
        ["the_playlist_is_written_as_bytes_with_append_false", "plays_png_jpeg_and_webp_in_album_order"],
    ),
]

# Built into the component and caught by host-test inside ComponentProvider.
RUNTIME = [
    (
        "wrong type accepted as PNG (in the component)",
        "src/image.rs",
        "    Err(HeaderError::UnknownType)\n}",
        "    Ok(Kind::Png)\n}",
        ["content_failures_are_skipped_and_listed_through_the_runtime"],
    ),
    (
        "image read without a grant (in the component)",
        "src/lib.rs",
        'let item_grant = grant(bus, uri, "read", "read the header of an image in the album")?;',
        'let item_grant = grant(bus, uri, "read", "read the header of an image in the album").unwrap_or_default();',
        ["no_grant_stops_the_run_through_the_runtime"],
    ),
    (
        "playlist written as a string (in the component)",
        "src/bus.rs",
        'json!({ "path": uri, "content": content, "append": false })',
        'json!({ "path": uri, "content": String::from_utf8_lossy(content) })',
        ["album_plays_and_the_playlist_is_written"],
    ),
]


def cases(listed):
    return [(name, HERE / relative, [(old, new)], tests) for name, relative, old, new, tests in listed]


def guest_tests_fail(filters):
    kit.cargo_compiles(HERE, ["--lib"])
    return any(kit.cargo_test_fails(HERE, ["--lib"], f"tests::{name}") for name in filters)


def runtime_tests_fail(filters):
    build = kit.run([str(HERE / "build.sh")], HERE)
    if build.returncode != 0:
        print(build.stderr[-2000:])
        raise SystemExit("component build failed under a falsifier")
    return any(kit.cargo_test_fails(HERE / "host-test", ["--test", "component"], name) for name in filters)


def main():
    try:
        kit.main(
            [
                (cases(GUEST), guest_tests_fail, None, True),
                (cases(RUNTIME), runtime_tests_fail, "--runtime", True),
            ]
        )
    finally:
        if "--runtime" in sys.argv[1:]:
            # Leave the unmutated component in place.
            if kit.run([str(HERE / "build.sh")], HERE).returncode != 0:
                raise SystemExit("restoring the component build failed")


if __name__ == "__main__":
    main()
