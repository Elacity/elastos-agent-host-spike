#!/usr/bin/env python3
"""Break each rule of the archive viewer's core, see its test fail, restore it.

Usage: RUST_TEST_THREADS=2 python3 -I falsify.py [--check] [name-part ...]

Each falsifier replaces one exact text (it must occur once), requires the
mutant to compile, runs every named test, and requires every one to fail.
Then the whole suite runs under the mutant: every test the case does not name
must still pass, so a mutant proves its own rule only. The file is restored
from its saved bytes afterwards, also on error or Ctrl-C.
The runner is the capsule kit's (`examples/capsule-kit/falsify`).

F-numbers here are the design's (examples/archive-viewer/DESIGN.md, "Falsifier
plan"); the core covers F1, F2, F4, F5, F6, F6b, F6c, F7 to F17, F19 to F25,
F26 to F28, F29 to F31, F32, F33, F40 to F42. The lettered cases F6d to F6f,
F15b, F16b, F19b, F21b to F21g, F22b, F23b to F23d, F25b to F25f, F30b, F30c,
F41b to F41e, F5b to F5e and F26b cover bounds, comparisons and request fields DESIGN states
but gives no row, and F32 covers the whole view's cap. F3 (the B2 streaming
ratio check) and F18 (Bus v2 depth) run in the component and wait for the
host-test task; F35, F36 and F43 wait for the same task.
"""
import pathlib
import re
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
     ["entries_that_share_data_refuse_the_archive",
      "entries_that_overlap_only_after_the_local_extra_field_refuse_the_archive",
      "entries_that_share_a_local_header_region_refuse_the_archive"]),
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
     ["entries_that_share_a_local_header_region_refuse_the_archive",
      "entries_that_overlap_only_after_the_local_extra_field_refuse_the_archive"]),
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
    ("F15 the segment cap is doubled",
     "src/lib.rs",
     "pub const MAX_SEGMENTS: usize = 32;",
     "pub const MAX_SEGMENTS: usize = 64;",
     ["a_name_with_33_segments_is_blocked"]),
    ("F15 the trailing slash counts as a segment",
     "src/zip.rs",
     "    if trimmed.split('/').count() > MAX_SEGMENTS {",
     "    if path.split('/').count() > MAX_SEGMENTS {",
     ["a_directory_with_32_segments_is_listed"]),
    ("F16 the mode check is removed",
     "src/zip.rs",
     "    let other = !matches!(unix, 0 | 0o100000 | 0o040000);",
     "    let other = false && !matches!(unix, 0 | 0o100000 | 0o040000);",
     ["a_symlink_entry_is_blocked", "other_entry_kinds_are_blocked"]),
    ("F16b the DOS directory attribute is ignored",
     "src/zip.rs",
     '    if name.ends_with(b"/") || unix == 0o040000 || dos_directory {',
     '    if name.ends_with(b"/") || unix == 0o040000 {',
     ["a_dos_directory_entry_is_listed_as_a_directory",
      "a_dos_directory_with_data_is_blocked"]),
    ("F17 a nested archive is opened",
     "src/zip.rs",
     "    let length = LOCAL_HEADER_BYTES + u64::from(entry.name_len);",
     "    if entry.kind == Kind::Archive {\n"
     "        let _ = reader.read(entry.data_start, entry.compressed_size);\n"
     "    }\n"
     "    let length = LOCAL_HEADER_BYTES + u64::from(entry.name_len);",
     ["a_nested_archive_is_listed_not_opened"]),
    # L1 to L4.
    ("F19 the tail search reads 2 KiB",
     "src/lib.rs",
     "pub const MAX_COMMENT_BYTES: u64 = 1024;",
     "pub const MAX_COMMENT_BYTES: u64 = 2048;",
     ["a_comment_over_1_kib_refuses_the_archive_without_reading_it"]),
    ("F19b a short tail answer is accepted",
     "src/zip.rs",
     "    if tail.len() as u64 != tail_length {",
     "    if false {",
     ["a_short_tail_response_refuses_the_archive"]),
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
    ("F22 the record count is not checked",
     "src/zip.rs",
     "    if entries.len() != usize::from(count) {",
     "    if false {",
     ["a_count_that_differs_from_the_records_refuses_the_archive"]),
    ("F22b the on-disk count is not checked",
     "src/zip.rs",
     "    if on_disk != count {",
     "    if false {",
     ["an_on_disk_count_that_differs_refuses_the_archive"]),
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
     ["other_methods_are_listed_unsupported",
      "a_requested_unsupported_entry_is_skipped_with_its_status"]),
    ("F30 encryption flag bit 0 is ignored",
     "src/zip.rs",
     "    if flags & 1 != 0 {",
     "    if false {",
     ["encrypted_entries_are_listed_not_read",
      "a_requested_encrypted_entry_is_skipped_with_its_status"]),
    ("F30c the encrypted payload is read before its status",
     "src/zip.rs",
     "        entry.data_start = data;",
     "        entry.data_start = data;\n"
     "        if entry.flags & 1 != 0 {\n"
     "            let _ = read(reader, data, entry.compressed_size)?;\n"
     "        }",
     ["encrypted_entries_are_listed_not_read",
      "a_requested_encrypted_entry_is_skipped_with_its_status"]),
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
     ["a_nonempty_directory_is_blocked_and_the_valid_entry_still_lists",
      "a_dos_directory_with_data_is_blocked"]),
    # The request's authority.
    ("F41 the .AppData/ refusal is removed",
     "src/request.rs",
     "    if is_app_data(uri) {",
     "    if false {",
     ["a_request_for_an_appdata_uri_is_refused",
      "a_request_for_an_appdata_case_alias_is_refused"]),
    ("F41b the request schema is not checked",
     "src/request.rs",
     "    if request.get(\"schema\").and_then(Value::as_str) != Some(REQUEST_SCHEMA) {",
     "    if false {",
     ["a_request_with_a_wrong_schema_is_refused"]),
    ("F41c the request index cap is removed",
     "src/request.rs",
     "            if list.len() > MAX_REQUEST_SHOW {",
     "            if false {",
     ["a_request_with_too_many_indexes_is_refused"]),
    ("F41d the kit URI check is removed",
     "src/request.rs",
     "    check_object_uri(uri, USERS_PREFIX)",
     "    Ok(())",
     ["a_request_outside_the_users_folders_is_refused"]),
    ("F41e the request cap is doubled",
     "src/lib.rs",
     "pub const MAX_REQUEST_BYTES: u64 = 4 * 1024;",
     "pub const MAX_REQUEST_BYTES: u64 = 8 * 1024;",
     ["a_request_at_its_cap_is_accepted_and_one_byte_over_is_refused"]),
    # Authority stops, never skips.
    ("F42 a denied read becomes a content skip",
     "src/zip.rs",
     "        read_counted(self.bus, self.uri, self.grant, self.left, offset, length)\n"
     "            .map_err(ReadError::Refusal)",
     "        read_counted(self.bus, self.uri, self.grant, self.left, offset, length)\n"
     "            .map_err(|_| ReadError::Budget)",
     ["a_provider_error_while_listing_stops_the_run_and_writes_nothing",
      "a_denied_read_during_the_directory_read_stops_the_run"]),
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
    ("F21f an entry on another disk is accepted",
     "src/zip.rs",
     "        if start_disk != 0 {",
     "        if false && start_disk != 0 {",
     ["an_entry_on_another_disk_refuses_the_archive"]),
    ("F21g a central zip64 sentinel is accepted",
     "src/zip.rs",
     "        if compressed == u64::from(u32::MAX)\n"
     "            || uncompressed == u64::from(u32::MAX)\n"
     "            || local == u64::from(u32::MAX)\n"
     "        {",
     "        if false\n"
     "            && (compressed == u64::from(u32::MAX)\n"
     "                || uncompressed == u64::from(u32::MAX)\n"
     "                || local == u64::from(u32::MAX))\n"
     "        {",
     ["an_entry_with_a_zip64_sentinel_refuses_the_archive"]),
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
    # B1 to B3: the preview window and the bomb caps.
    ("F1 the preview window grows to 64 KiB",
     "src/preview.rs",
     "pub const OUTPUT_WINDOW_BYTES: u64 = MAX_PREVIEW_BYTES + 1;",
     "pub const OUTPUT_WINDOW_BYTES: u64 = 64 * 1024;",
     ["an_entry_over_the_preview_cap_is_skipped_after_one_byte_past_it"]),
    ("F2 the declared size is not checked first",
     "src/preview.rs",
     "    if entry.uncompressed_size > MAX_PREVIEW_BYTES {",
     "    if false && entry.uncompressed_size > MAX_PREVIEW_BYTES {",
     ["an_entry_declared_over_the_cap_is_not_read"]),
    ("F4 the declared ratio is not checked",
     "src/preview.rs",
     "    if entry.uncompressed_size\n"
     "        > entry\n"
     "            .compressed_size\n"
     "            .saturating_mul(MAX_RATIO)\n"
     "            .saturating_add(RATIO_SLACK_BYTES)\n"
     "    {",
     "    if false\n"
     "        && entry.uncompressed_size\n"
     "            > entry\n"
     "                .compressed_size\n"
     "                .saturating_mul(MAX_RATIO)\n"
     "                .saturating_add(RATIO_SLACK_BYTES)\n"
     "    {",
     ["an_entry_declared_past_the_ratio_is_not_read"]),
    ("F5 the output of skipped entries is not counted",
     "src/lib.rs",
     "                        budget.take(&outcome);",
     "                        if outcome.blocks.is_ok() {\n"
     "                            budget.take(&outcome);\n"
     "                        }",
     ["no_run_inflates_more_than_its_total"]),
    ("F5c the remaining allowance is not counted down",
     "src/preview.rs",
     "        let left = allowance.saturating_sub(produced);",
     "        let left = allowance;",
     ["no_run_inflates_more_than_its_total",
      "a_preview_stops_for_its_budget_before_any_corruption_reason"]),
    ("F5d an exact-fit stream is refused before it can end",
     "src/preview.rs",
     "        let ask = room.min(left);\n"
     "        // The decompressor does not wrap",
     "        let ask = room.min(left);\n"
     "        if ask == 0 {\n"
     "            return Err((produced, \"inflate_budget\"));\n"
     "        }\n"
     "        // The decompressor does not wrap",
     ["an_exact_fit_stream_ends_within_its_budget"]),
    ("F5e the total inflate cap is raised",
     "src/preview.rs",
     "pub const MAX_INFLATE_BYTES: u64 = 64 * 1024;",
     "pub const MAX_INFLATE_BYTES: u64 = 65 * 1024;",
     ["no_run_inflates_more_than_its_total"]),
    ("F1b the byte past the cap is judged after the stream's own verdict",
     "src/preview.rs",
     "        if produced > MAX_PREVIEW_BYTES {",
     "        if produced > OUTPUT_WINDOW_BYTES {",
     ["a_preview_stops_for_its_budget_before_any_corruption_reason"]),
    ("F5b the compressed cap is not checked",
     "src/preview.rs",
     "    if entry.compressed_size > budget.compressed {",
     "    if false && entry.compressed_size > budget.compressed {",
     ["no_run_reads_more_compressed_data_than_its_cap"]),
    # L6 to L8: the bytes, not the declaration.
    ("F26 the output length is not the declared size",
     "src/preview.rs",
     "                if consumed != data.len() || produced != declared {",
     "                if consumed != data.len() || produced > declared {",
     ["an_entry_longer_or_shorter_than_declared_is_skipped"]),
    ("F26b the compressed stream boundary is ignored",
     "src/preview.rs",
     "                if consumed != data.len() || produced != declared {",
     "                if produced != declared {",
     ["an_entry_with_junk_after_the_stream_is_skipped"]),
    ("F27 the CRC compare is removed",
     "src/preview.rs",
     "    if crc32(&output) != entry.crc {",
     "    if false {",
     ["a_crc_mismatch_skips_the_entry"]),
    ("F28 the stored sizes compare is removed",
     "src/preview.rs",
     "    if entry.method == 0 && entry.compressed_size != entry.uncompressed_size {",
     "    if false {",
     ["a_stored_entry_with_two_sizes_is_skipped"]),
    ("F33 the whole-text check is removed",
     "src/preview.rs",
     '        Err(_) => return Ok(skipped_after(produced, read, "not_text")),',
     '        Err(_) => "",',
     ["a_text_entry_that_is_not_text_is_skipped"]),
    ("F33b the block cap is ignored",
     "src/preview.rs",
     '        Err(ModelError::TooLong) => return Ok(skipped_after(produced, read, "too_long")),',
     '        Err(ModelError::TooLong) => Vec::new(),',
     ["a_text_entry_with_too_many_blocks_is_skipped"]),
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


SUITES = []

SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;",
    re.M,
)
RESULT = re.compile(r"^test (tests::\S+) \.\.\. (ok|FAILED)$", re.M)


def suite():
    """Runs the whole lib suite and returns its exit code, summary and results."""
    result = kit.run(["cargo", "test", "--locked", "--lib"], HERE)
    summaries = SUMMARY.findall(result.stdout)
    results = dict(RESULT.findall(result.stdout))
    return result.returncode, summaries, results


def baseline():
    """The test names the unmutated suite runs, or stop the run."""
    code, summaries, results = suite()
    if code != 0 or len(summaries) != 1 or summaries[0][0] != "ok":
        raise SystemExit(f"the baseline suite did not pass cleanly:\n{summaries}\n")
    passed = sum(1 for state in results.values() if state == "ok")
    if len(results) != passed or int(summaries[0][1]) != passed:
        raise SystemExit(
            f"the baseline suite ran {len(results)} tests, summary says {summaries[0]}"
        )
    return set(results)


def build():
    kit.cargo_compiles(HERE, ["--lib"])
    # A mutant must change only its own rule: the whole suite runs under it,
    # and every test the case does not name must still pass.
    code, summaries, results = suite()
    SUITES.append({"code": code, "summaries": summaries, "results": results})


def test_fails(name):
    return kit.cargo_test_fails(HERE, ["--lib"], f"tests::{name}")


def check_isolation(cases, args, every_test):
    parts = [arg for arg in args if not arg.startswith("--")]
    executed = [case for case in cases if not parts or any(part in case[0] for part in parts)]
    if len(executed) != len(SUITES):
        raise SystemExit(f"{len(executed)} cases ran, {len(SUITES)} suites were recorded")
    leaked = []
    for case, suite in zip(executed, SUITES):
        named = {"tests::" + name for name in case[-1]}
        summaries = suite["summaries"]
        results = suite["results"]
        problems = []
        if len(summaries) != 1:
            problems.append("the suite did not complete")
        else:
            state, passed, failed, ignored = summaries[0]
            if state != "FAILED" or suite["code"] == 0:
                problems.append("the mutant did not fail the suite")
            if int(ignored) != 0:
                problems.append(f"the suite ignored {ignored} tests")
            if int(passed) + int(failed) != len(results):
                problems.append(f"the summary counts {passed}+{failed} but {len(results)} ran")
            if int(failed) != len(named):
                problems.append(f"{failed} tests failed, {len(named)} are named")
        if set(results) != every_test:
            problems.append("the suite did not run every test")
        failed = {name for name, state in results.items() if state == "FAILED"}
        passed = {name for name, state in results.items() if state == "ok"}
        if failed != named:
            problems.append(f"failed {sorted(failed - named)} beyond the named tests"
                            if failed - named else f"named tests passed: {sorted(named - failed)}")
        unnamed_not_passed = (every_test - named) - passed
        if unnamed_not_passed:
            problems.append(f"unnamed tests did not pass: {sorted(unnamed_not_passed)}")
        if problems:
            leaked.append((case[0], problems))
    if leaked:
        for name, problems in leaked:
            print(f"LEAKED: {name}: {', '.join(problems)}", flush=True)
        raise SystemExit(f"{len(leaked)} falsifier(s) break a test they do not name")
    print(f"all {len(executed)} mutants leave every unnamed test passing")


def main():
    cases = [
        (case[0], HERE / case[1], case[2] if isinstance(case[2], list) else [(case[2], case[3])], case[-1])
        for case in CASES
    ]
    check = "--check" in sys.argv[1:]
    every_test = set() if check else baseline()
    kit.main([(cases, build, test_fails, None, True)], done=f"all {len(CASES)} archive falsifiers caught")
    if not check:
        check_isolation(CASES, sys.argv[1:], every_test)


if __name__ == "__main__":
    main()
