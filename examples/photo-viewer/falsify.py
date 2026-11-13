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
(examples/capsule-kit/falsify). Cases on `../capsule-kit/guest/src/` break
the kit crate's code and require the photo viewer's own tests to notice; the
kit's own falsifiers are in `examples/capsule-kit/guest/falsify.py`.
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
        'None => grant(bus, uri, "read", "read the header of an image in the album")?,',
        'None => grant(bus, uri, "read", "read the header of an image in the album").unwrap_or_default(),',
        ["image_without_a_read_grant_stops_the_run_and_is_not_skipped"],
    ),
    (
        "playlist write without a grant",
        "src/lib.rs",
        'let write_grant = grant(bus, granted, "write", "write the checked playlist")?;',
        'let write_grant = grant(bus, granted, "write", "write the checked playlist").unwrap_or_default();',
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
        "unknown album fields allowed",
        "../capsule-kit/guest/src/list.rs",
        '.find(|key| !matches!(key.as_str(), "schema" | "items"))',
        '.find(|key| !matches!(key.as_str(), "schema" | "items" | "x"))',
        ["malformed_albums_stop_before_any_image_is_read"],
    ),
    (
        "dot-dot segments allowed",
        "../capsule-kit/guest/src/uri.rs",
        '.any(|part| part.is_empty() || part == "." || part == "..")',
        '.any(|part| part.is_empty() || part == ".")',
        ["malformed_albums_stop_before_any_image_is_read"],
    ),
    # Content failures skip the item.
    (
        "content failure stops the run instead of skipping",
        "src/lib.rs",
        "match check_item(bus, order, item, launch.as_deref())? {",
        "match check_item(bus, order, item, launch.as_deref())?.map_err(|_| Refusal::InputTooLarge).map(Ok)? {",
        ["a_bad_item_is_skipped_and_the_rest_play_in_order"],
    ),
    (
        "wrong type accepted as PNG",
        "../capsule-kit/guest/src/image.rs",
        "    Err(HeaderError::UnknownType)\n}",
        "    Ok(Kind::Png)\n}",
        ["wrong_type_is_skipped_after_reading_only_its_header"],
    ),
    (
        "truncated magic treated as unknown",
        "../capsule-kit/guest/src/image.rs",
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
        "../capsule-kit/guest/src/image.rs",
        "for _ in 0..MAX_JPEG_SEGMENTS {",
        "for _ in 0..MAX_JPEG_SEGMENTS * 2 {",
        ["malformed_headers_are_skipped"],
    ),
    (
        "JPEG segment payloads read",
        "../capsule-kit/guest/src/image.rs",
        "let marker = read(at, 4)?;",
        "let _payload = read(at, 70_000)?;\n        let marker = read(at, 4)?;",
        ["a_jpeg_frame_header_after_large_exif_is_found_without_reading_the_payloads"],
    ),
    # Body shapes the localhost provider accepts.
    (
        "playlist written without append (the P1 shape)",
        "../capsule-kit/guest/src/bus.rs",
        'body.push_str(r#"{"append":false,"content":["#);',
        'body.push_str(r#"{"content":["#);',
        ["the_playlist_is_written_as_bytes_with_append_false", "plays_png_jpeg_and_webp_in_album_order"],
    ),
    # A content launch (the launch question, then the set and the launch's output).
    (
        "any failure of the launch question taken as no launch",
        "src/lib.rs",
        "Err(BusFailure::NotFound(_)) => None,",
        "Err(_) => None,",
        ["any_other_answer_to_the_launch_question_ends_the_run"],
    ),
    (
        "a launched picture asked for on its own",
        "src/lib.rs",
        "Some(content) => content.to_string(),",
        'Some(_) => grant(bus, uri, "read", "read the header of an image in the album")?,',
        ["a_launched_photo_set_plays_from_the_launch_and_its_output"],
    ),
    (
        "the playlist of a launched set written to the person's storage",
        "src/lib.rs",
        "Some(_) => (LAUNCH_OUTPUT_PATTERN, LAUNCH_PLAYLIST_URI),",
        "Some(_) => (PLAYLIST_URI, PLAYLIST_URI),",
        ["a_launched_photo_set_plays_from_the_launch_and_its_output"],
    ),
    (
        "every file of a launched set taken as a picture",
        "src/lib.rs",
        ".filter(|path| path.starts_with(LAUNCH_IMAGES))",
        ".filter(|_| true)",
        ["a_launched_photo_set_plays_from_the_launch_and_its_output"],
    ),
    (
        "a launched set with no pictures played",
        "src/lib.rs",
        "if images.is_empty() || images.len() > MAX_ALBUM_ITEMS {",
        "if images.len() > MAX_ALBUM_ITEMS {",
        ["a_launched_set_with_no_pictures_or_too_many_is_refused"],
    ),
    (
        "a launch's listing read up to the Runtime's cap, past the fuel the album's cap bounds",
        "src/lib.rs",
        "pub const MAX_LISTING_BYTES: u64 = MAX_ALBUM_BYTES;",
        "pub const MAX_LISTING_BYTES: u64 = 256 * 1024;",
        ["a_launched_set_whose_listing_passes_the_cap_is_refused"],
    ),
]

# The kit's straight writer and the `json!` serializer it replaced. The JSON
# bytes are the same, so only the fuel gate can tell them apart.
WRITE_BODY = '''pub fn write_body(uri: &str, content: &[u8]) -> String {
    let path = serde_json::to_string(uri).expect("a string always serializes");
    let mut body = String::with_capacity(content.len() * 4 + path.len() + 40);
    body.push_str(r#"{"append":false,"content":["#);
    for (index, byte) in content.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        if *byte >= 100 {
            body.push(char::from(b'0' + byte / 100));
        }
        if *byte >= 10 {
            body.push(char::from(b'0' + byte / 10 % 10));
        }
        body.push(char::from(b'0' + byte % 10));
    }
    body.push_str(r#"],"path":"#);
    body.push_str(&path);
    body.push('}');
    body
}'''
JSON_WRITE_BODY = '''pub fn write_body(uri: &str, content: &[u8]) -> String {
    json!({ "path": uri, "content": content, "append": false }).to_string()
}'''

# Built into the component and caught by host-test inside ComponentProvider.
RUNTIME = [
    (
        "wrong type accepted as PNG (in the component)",
        "../capsule-kit/guest/src/image.rs",
        "    Err(HeaderError::UnknownType)\n}",
        "    Ok(Kind::Png)\n}",
        ["content_failures_are_skipped_and_listed_through_the_runtime"],
    ),
    (
        "image read without a grant (in the component)",
        "src/lib.rs",
        'None => grant(bus, uri, "read", "read the header of an image in the album")?,',
        'None => grant(bus, uri, "read", "read the header of an image in the album").unwrap_or_default(),',
        ["no_grant_stops_the_run_through_the_runtime"],
    ),
    (
        "playlist written without append (in the component)",
        "../capsule-kit/guest/src/bus.rs",
        'body.push_str(r#"{"append":false,"content":["#);',
        'body.push_str(r#"{"content":["#);',
        ["album_plays_and_the_playlist_is_written"],
    ),
    (
        "the write builds a value per byte (in the component)",
        "../capsule-kit/guest/src/bus.rs",
        WRITE_BODY,
        JSON_WRITE_BODY,
        ["the_worst_case_album_is_written_without_a_value_per_byte"],
    ),
]


def cases(listed):
    return [(name, HERE / relative, [(old, new)], tests) for name, relative, old, new, tests in listed]


def build_guest():
    kit.cargo_compiles(HERE, ["--lib"])


def guest_test_fails(name):
    return kit.cargo_test_fails(HERE, ["--lib"], f"tests::{name}")


def build_component():
    kit.build([str(HERE / "build.sh")], HERE, "component build failed under a falsifier")


def runtime_test_fails(name):
    return kit.cargo_test_fails(HERE / "host-test", ["--test", "component"], name)


def main():
    try:
        kit.main(
            [
                (cases(GUEST), build_guest, guest_test_fails, None, True),
                (cases(RUNTIME), build_component, runtime_test_fails, "--runtime", True),
            ]
        )
    finally:
        if "--runtime" in sys.argv[1:]:
            # Leave the unmutated component in place.
            if kit.run([str(HERE / "build.sh")], HERE).returncode != 0:
                raise SystemExit("restoring the component build failed")


if __name__ == "__main__":
    main()
