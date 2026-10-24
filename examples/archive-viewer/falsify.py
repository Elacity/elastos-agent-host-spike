#!/usr/bin/env python3
"""Break each rule of the archive viewer's core, see its test fail, restore it.

Usage: RUST_TEST_THREADS=2 python3 -I falsify.py [--check] [name-part ...]

Each falsifier replaces one exact text (it must occur once), requires the
mutant to compile, runs every named test, and requires every one to fail. The
file is restored from its saved bytes afterwards, also on error or Ctrl-C.
The runner is the capsule kit's (`examples/capsule-kit/falsify`).

F-numbers here are the design's (examples/archive-viewer/DESIGN.md, "Falsifier
plan"); this slice's core covers F6, F6b, F6c, F7 to F17, F19 to F25, F29 to
F31, F40 to F42. The lettered cases F6d to F6f, F21b to F21e, F23b to
F23d, F25b to F25f and F30b cover bounds and comparisons DESIGN states but
gives no row, and F32 covers the whole view's cap. F18 (Bus v2 depth) and the
preview falsifiers F1 to F5 and F26 to F28 wait for their slices.
"""
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "capsule-kit" / "falsify"))
import falsify_kit as kit  # noqa: E402

# (name, file under the crate, exact old text, new text, tests that must fail)
CASES = [
    # B4, B4a and B4c: records that share bytes.
    ("F6 overlapping records are accepted",
     "src/zip.rs",
     "        if second.local_offset < first.local_end {",
     "        if false {",
     ["entries_that_share_data_refuse_the_archive"]),
    ("F6b the local extra field is ignored",
     "src/zip.rs",
     "            .checked_add(LOCAL_HEADER_BYTES + u64::from(name_len) + u64::from(extra_len));",
     "            .checked_add(LOCAL_HEADER_BYTES + u64::from(name_len));",
     ["entries_that_overlap_only_after_the_local_extra_field_refuse_the_archive"]),
    ("F6c the overlap check uses only the payload",
     "src/zip.rs",
     "    let mut order: Vec<usize> = (0..entries.len()).collect();\n"
     "    order.sort_by_key(|index| entries[*index].local_offset);\n"
     "    for pair in order.windows(2) {\n"
     "        let (first, second) = (&entries[pair[0]], &entries[pair[1]]);\n"
     "        if second.local_offset < first.local_end {",
     "    let mut order: Vec<usize> = (0..entries.len()).collect();\n"
     "    order.sort_by_key(|index| entries[*index].data_start);\n"
     "    for pair in order.windows(2) {\n"
     "        let (first, second) = (&entries[pair[0]], &entries[pair[1]]);\n"
     "        if second.data_start < first.local_end {",
     ["entries_that_share_a_local_header_region_refuse_the_archive"]),
    # P1 to P9: the names.
    ("F7 absolute names pass",
     "src/zip.rs",
     "    if bytes.first() == Some(&b'/') {\n        return Err(\"absolute_name\");\n    }\n"
     "    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {\n"
     "        return Err(\"absolute_name\");\n    }",
     "    if false {\n        return Err(\"absolute_name\");\n    }\n"
     "    if false && bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {\n"
     "        return Err(\"absolute_name\");\n    }",
     ["absolute_names_are_blocked"]),
    ("F8 dot segments pass",
     "src/zip.rs",
     'part.is_empty() || part == "." || part == ".."',
     'part.is_empty() || part == "."',
     ["dot_and_empty_segments_are_blocked"]),
    ("F9 a backslash passes",
     "src/zip.rs",
     "    if path.contains('\\\\') {\n        return Err(\"backslash\");\n    }",
     "    if false {\n        return Err(\"backslash\");\n    }",
     ["a_backslash_is_blocked"]),
    ("F10 the bidi range is dropped",
     "src/zip.rs",
     "matches!(c, '\\u{202a}'..='\\u{202e}' | '\\u{2066}'..='\\u{2069}')",
     "false",
     ["control_and_bidi_characters_are_blocked"]),
    ("F11 an unmarked non-ASCII name passes",
     "src/zip.rs",
     "    } else if name.iter().all(|byte| (0x20..=0x7e).contains(byte)) {",
     "    } else if true {",
     ["names_are_utf8_when_marked_and_ascii_otherwise"]),
    ("F12 duplicates keep the first",
     "src/zip.rs",
     "        if seen.get(&entry.name).copied().unwrap_or(0) > 1",
     "        if seen.get(&entry.name).copied().unwrap_or(0) > 100",
     ["duplicate_names_are_both_blocked"]),
    ("F13 look-alikes are merged by a lower-cased key",
     "src/zip.rs",
     "        *seen.entry(entry.name.clone()).or_insert(0) += 1;",
     "        *seen.entry(entry.name.to_ascii_lowercase()).or_insert(0) += 1;",
     ["names_that_differ_only_in_case_are_both_listed"]),
    ("F14 the directory hides the file of its path",
     "src/zip.rs",
     "        *seen.entry(entry.name.clone()).or_insert(0) += 1;",
     "        *seen.entry(entry.name.strip_suffix(b\"/\").unwrap_or(&entry.name).to_vec()).or_insert(0) += 1;",
     ["a_file_and_a_directory_of_one_path_are_both_listed"]),
    ("F15 the caps are doubled",
     "src/lib.rs",
     "pub const MAX_ENTRIES: usize = 256;",
     "pub const MAX_ENTRIES: usize = 512;",
     ["too_many_entries_refuse_the_archive"]),
    ("F15 the name cap is doubled",
     "src/lib.rs",
     "pub const MAX_NAME_BYTES: usize = 255;",
     "pub const MAX_NAME_BYTES: usize = 510;",
     ["a_name_over_its_cap_is_blocked"]),
    ("F16 the mode check is removed",
     "src/zip.rs",
     "    let other = !matches!(unix, 0 | 0o100000 | 0o040000);",
     "    let other = false && !matches!(unix, 0 | 0o100000 | 0o040000);",
     ["a_symlink_entry_is_blocked", "other_entry_kinds_are_blocked"]),
    ("F17 a nested archive is not listed as one",
     "src/zip.rs",
     "    if archive_name(name) {",
     "    if false {",
     ["a_nested_archive_is_listed_not_opened"]),
    # L1 to L4.
    ("F19 the tail search reads 64 KiB",
     "src/lib.rs",
     "pub const MAX_COMMENT_BYTES: u64 = 1024;",
     "pub const MAX_COMMENT_BYTES: u64 = 64 * 1024;",
     ["a_comment_over_1_kib_refuses_the_archive_without_reading_it"]),
    ("F20 the last end record wins",
     "src/zip.rs",
     "    match candidates.len() {\n        1 => {}",
     "    match candidates.len() {\n        1 | 2 => {}",
     ["two_end_records_refuse_the_archive"]),
    ("F21 the gap check is removed",
     "src/zip.rs",
     "    if directory_offset + directory_size != end_offset {",
     "    if false {",
     ["a_directory_that_does_not_end_at_the_end_record_refuses_the_archive"]),
    ("F22 the counts come from the end record",
     "src/zip.rs",
     [("    if on_disk != count {", "    if false {"),
      ("    if entries.len() != usize::from(count) {", "    if false {")],
     ["a_count_that_differs_from_the_records_refuses_the_archive"]),
    ("F23 the record lengths are not bounded",
     "src/zip.rs",
     "        if next > end {",
     "        if next > end && false {",
     ["a_record_that_runs_past_the_directory_refuses_the_archive"]),
    # L5: the local header before an entry is shown.
    ("F24 the local name compare is removed",
     "src/zip.rs",
     "    if name != entry.name.as_slice() {",
     "    if false {",
     ["a_local_name_that_differs_skips_the_entry"]),
    ("F25 the local method compare is removed",
     "src/zip.rs",
     "    if u16_at(header, 8) != Some(entry.method) {",
     "    if false {",
     ["a_local_header_that_differs_skips_the_entry"]),
    # Methods and encryption.
    ("F29 method 12 is treated as stored",
     "src/zip.rs",
     "    if method != 0 && method != 8 {",
     "    if false {",
     ["other_methods_are_listed_unsupported"]),
    ("F30 encryption flag bit 0 is ignored",
     "src/zip.rs",
     "    if flags & 1 != 0 {",
     "    if false {",
     ["encrypted_entries_are_listed_not_read"]),
    # The read budget.
    ("F31 a read is not counted",
     "src/zip.rs",
     "        read_counted(self.bus, self.uri, self.grant, self.left, offset, length)",
     "        capsule_kit_guest::read_at(self.bus, self.uri, self.grant, offset, length)",
     ["every_read_counts_toward_the_budget"]),
    # L9: a directory with bytes.
    ("F40 a directory's size is not checked",
     "src/zip.rs",
     "    if kind == Kind::Directory && (uncompressed_size != 0 || compressed_size != 0) {",
     "    if false {",
     ["a_nonempty_directory_is_blocked_and_the_valid_entry_still_lists"]),
    # The request's authority.
    ("F41 the .AppData/ refusal is removed",
     "src/request.rs",
     "    if uri.starts_with(APP_DATA_PREFIX) {",
     "    if false {",
     ["a_request_for_an_appdata_uri_is_refused"]),
    # Authority stops, never skips.
    ("F42 a denied read becomes a content skip",
     "src/zip.rs",
     "        read_counted(self.bus, self.uri, self.grant, self.left, offset, length)\n"
     "            .map_err(ReadError::Refusal)",
     "        read_counted(self.bus, self.uri, self.grant, self.left, offset, length)\n"
     "            .map_err(|_| ReadError::Budget)",
     ["a_provider_error_while_listing_stops_the_run_and_writes_nothing"]),
    # Bounds DESIGN states but gives no row: an end record and a directory
    # that lie about where their bytes are must refuse the archive.
    ("F6d a local header outside the object is accepted",
     "src/zip.rs",
     "        if header.len() < LOCAL_HEADER_BYTES as usize {",
     "        if false && header.len() < LOCAL_HEADER_BYTES as usize {",
     ["a_local_header_outside_the_object_refuses_the_archive"]),
    ("F6e an entry record passes the directory",
     "src/zip.rs",
     "        if end > directory_offset {",
     "        if false && end > directory_offset {",
     ["an_entry_record_that_passes_the_directory_refuses_the_archive"]),
    ("F6f a local header signature is ignored",
     "src/zip.rs",
     "        if u32_at(&header, 0) != Some(LOCAL_SIGNATURE) {",
     "        if false && u32_at(&header, 0) != Some(LOCAL_SIGNATURE) {",
     ["a_local_header_without_its_signature_refuses_the_archive"]),
    ("F21b a directory outside the object is accepted",
     "src/zip.rs",
     "    if directory_offset > end_offset {",
     "    if false && directory_offset > end_offset {",
     ["a_directory_outside_the_object_is_refused"]),
    ("F21c a multi-disk archive is accepted",
     "src/zip.rs",
     "    if disk != 0 || directory_disk != 0 {",
     "    if false && (disk != 0 || directory_disk != 0) {",
     ["a_multi_disk_archive_is_refused"]),
    ("F21d a zip64 end record is accepted",
     "src/zip.rs",
     "    if count == u16::MAX",
     "    if false && count == u16::MAX",
     ["a_zip64_end_record_is_refused"]),
    ("F23b a record signature is ignored",
     "src/zip.rs",
     "        if u32_at(directory, at) != Some(DIRECTORY_SIGNATURE) {",
     "        if false && u32_at(directory, at) != Some(DIRECTORY_SIGNATURE) {",
     ["a_record_without_its_signature_refuses_the_archive"]),
    ("F23c the directory cap is removed",
     "src/zip.rs",
     "    if directory_size > MAX_DIRECTORY_BYTES {",
     "    if false && directory_size > MAX_DIRECTORY_BYTES {",
     ["a_directory_over_its_cap_is_refused"]),
    # A skipped entry keeps its own status as the reason.
    ("F30b an entry's own status is not its skip reason",
     "src/zip.rs",
     "    match entry.status {\n"
     "        Status::Listed => {}\n"
     "        Status::Blocked(reason) => return Ok(Err(reason)),\n"
     "        Status::Unsupported => return Ok(Err(\"unsupported\")),\n"
     "        Status::Encrypted => return Ok(Err(\"encrypted\")),\n"
     "    }",
     "    if entry.status != Status::Listed {\n"
     "        return Ok(Err(entry.status.reason().unwrap_or(\"not_listed\")));\n"
     "    }",
     ["a_requested_encrypted_entry_is_skipped_with_its_status",
      "a_requested_unsupported_entry_is_skipped_with_its_status"]),
    # The whole view's cap.
    ("F32 a view over its cap is written",
     "src/lib.rs",
     "    if over > MAX_VIEW_BYTES {",
     "    if false {",
     ["no_view_is_longer_than_its_cap"]),
    # Answers that do not hold what the end record promised.
    ("F21e an object larger than 2^32 is accepted",
     "src/zip.rs",
     "    if low > MAX_ARCHIVE_BYTES {",
     "    if false {",
     ["an_object_larger_than_the_supported_size_is_refused"]),
    ("F23d a short directory answer is parsed",
     "src/zip.rs",
     "    if directory.len() as u64 != directory_size {",
     "    if false {",
     ["a_short_directory_response_refuses_the_archive"]),
    # L5: the remaining local-header comparisons.
    ("F25b the local lengths compare is removed",
     "src/zip.rs",
     "    if name_len != entry.name_len || extra_len != entry.extra_len {",
     "    if false {",
     ["a_local_length_that_differs_skips_the_entry"]),
    ("F25c the local flags compare is removed",
     "src/zip.rs",
     "    if flags & !(1 << 3) != entry.flags & !(1 << 3) {",
     "    if false {",
     ["a_local_flag_that_differs_skips_the_entry"]),
    ("F25d the local CRC compare is removed",
     "src/zip.rs",
     "        if u32_at(header, 14) != Some(entry.crc) {",
     "        if false {",
     ["a_local_crc_that_differs_skips_the_entry"]),
    ("F25e the local sizes compare is removed",
     "src/zip.rs",
     "        if local_compressed != entry.compressed_size\n"
     "            || local_uncompressed != entry.uncompressed_size\n"
     "        {",
     "        if false {",
     ["a_local_size_that_differs_skips_the_entry"]),
    ("F25f the data-descriptor guard is ignored",
     "src/zip.rs",
     "    if entry.flags & (1 << 3) == 0 {",
     "    if true {",
     ["a_data_descriptor_flag_is_ignored"]),
]


def build():
    kit.cargo_compiles(HERE, ["--lib"])


def test_fails(name):
    return kit.cargo_test_fails(HERE, ["--lib"], f"tests::{name}")


def main():
    cases = [
        (case[0], HERE / case[1], case[2] if isinstance(case[2], list) else [(case[2], case[3])], case[-1])
        for case in CASES
    ]
    kit.main([(cases, build, test_fails, None, True)], done=f"all {len(CASES)} archive falsifiers caught")


if __name__ == "__main__":
    main()
