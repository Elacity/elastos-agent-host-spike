#!/usr/bin/env python3
"""Break each check of the Photos seam, see its test fail, restore it.

Usage: RUST_TEST_THREADS=2 python3 -I falsify-seam.py [--check] [name-part ...]

--check only confirms every anchor occurs once. Name parts run only the
falsifiers whose name contains one of them.

The seam is Runtime code (elastos-server). Each falsifier replaces one exact
line, rebuilds the crate's tests (a mutant that does not compile proves
nothing, so the run stops), runs the named tests from
`api::gateway::gateway_tests::photos`, and requires them to FAIL. The file is
restored from its saved bytes afterwards, also on error or Ctrl-C. Each
mutant recompiles elastos-server, so a full run takes a while.
"""
import os
import pathlib
import subprocess

REPO = pathlib.Path(__file__).resolve().parents[2]
ELASTOS = REPO / "elastos"
API = "crates/elastos-server/src/api"
VIEWER = f"{API}/viewer_gateway.rs"
TESTS = "api::gateway::gateway_tests::photos::"

# (name, file under elastos/, exact old text, new text, tests that must fail)
CASES = [
    (
        "a launch bound to something else reads the playlist",
        VIEWER,
        "if launch.launch_context.selected_resource != PHOTOS_PLAYLIST_URI {",
        "if false && launch.launch_context.selected_resource != PHOTOS_PLAYLIST_URI {",
        ["photos_refuses_a_launch_not_bound_to_its_playlist"],
    ),
    (
        "another viewer's token is accepted",
        VIEWER,
        "super::gateway::require_home_viewer_launch(data_dir, headers, PHOTOS_VIEWER)",
        'super::gateway::require_home_viewer_launch(data_dir, headers, "documents")',
        ["photos_refuses_another_viewers_launch_token"],
    ),
    (
        "a position matches any item",
        VIEWER,
        "if item_order != order {",
        "if false && item_order != order {",
        ["photos_refuses_a_position_out_of_range_or_not_listed"],
    ),
    (
        "items outside Pictures/ are served",
        VIEWER,
        "let Some(rest) = uri.strip_prefix(PHOTOS_PICTURES_PREFIX) else {",
        'let Some(rest) = uri.strip_prefix("localhost://Users/self/") else {',
        ["photos_refuses_items_outside_pictures_or_not_viewable"],
    ),
    (
        "dot segments are allowed",
        VIEWER,
        '.any(|part| part.is_empty() || part == "." || part == "..")\n    {\n        return Err(refuse("has an empty, . or .. segment"));',
        '.any(|part| part.is_empty())\n    {\n        return Err(refuse("has an empty, . or .. segment"));',
        ["photos_refuses_items_outside_pictures_or_not_viewable"],
    ),
    (
        "items the Photos viewer cannot open are served",
        VIEWER,
        "    if viewable {\n",
        "    if false && viewable {\n",
        ["photos_refuses_items_outside_pictures_or_not_viewable"],
    ),
    (
        "the playlist cap is ten times larger",
        VIEWER,
        "const MAX_PHOTOS_PLAYLIST_BYTES: u64 = 64 * 1024;",
        "const MAX_PHOTOS_PLAYLIST_BYTES: u64 = 10 * 64 * 1024;",
        ["photos_refuses_a_malformed_or_oversize_playlist"],
    ),
    (
        "duplicate positions are allowed",
        VIEWER,
        "        if found.is_some() {\n",
        "        if false && found.is_some() {\n",
        ["photos_refuses_a_malformed_or_oversize_playlist"],
    ),
    (
        "reads are not audited",
        VIEWER,
        "    let context = &launch.context;\n    crate::auth::append_audit_event(",
        "    let context = &launch.context;\n    let _ = (&reason, &event_type, sequence, context, result);\n    if true {\n        return Ok(());\n    }\n    crate::auth::append_audit_event(",
        ["photos_serves_its_bound_playlist_and_the_items_it_lists"],
    ),
    (
        "the internal stat audits again",
        VIEWER,
        'let stat = object_provider_request(state, context, "stat", json!({ "uri": uri }))',
        'let stat = viewer_object_provider_request(state, context, PHOTOS_VIEWER, "stat", json!({ "uri": uri }))',
        ["each_photos_request_leaves_exactly_one_audit_record"],
    ),
    (
        "the record id uses the second, not a counter",
        VIEWER,
        'let sequence = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;\n    let event_type = format!("photos.viewer.{route}");',
        'let sequence = crate::auth::now_ts() + 0 * COUNTER.load(std::sync::atomic::Ordering::Relaxed);\n    let event_type = format!("photos.viewer.{route}");',
        ["each_photos_request_leaves_exactly_one_audit_record"],
    ),
    (
        "a launch does not keep its first playlist",
        VIEWER,
        "Some((pinned, _)) if pinned != sha256 =>",
        "Some((pinned, _)) if false && pinned != sha256 =>",
        ["a_launch_keeps_the_playlist_it_read_first"],
    ),
    (
        "the pin table has no limit",
        VIEWER,
        "if self.entries.len() >= self.cap {",
        "if false && self.entries.len() >= self.cap {",
        ["a_full_pin_table_refuses_a_new_launch_and_keeps_live_pins"],
    ),
    (
        "a launch with no playlist gets the short token",
        VIEWER,
        "None => Ok((target.to_string(), None)),",
        "None => Ok((target.to_string(), Some(PHOTOS_LAUNCH_TOKEN_TTL_SECS))),",
        ["home_binds_the_photos_playlist_with_a_short_lived_token"],
    ),
    (
        "an unknown route or code creates its own key",
        VIEWER,
        '    known\n        .iter()\n        .find(|known| **known == name)\n        .copied()\n        .unwrap_or("other")',
        "    let _ = known;\n    Box::leak(name.to_string().into_boxed_str())",
        ["an_unknown_route_or_code_cannot_create_a_key"],
    ),
    (
        "each refusal before the token writes its own event",
        VIEWER,
        "let finished = (start > window.start).then(|| {",
        "let finished = (start >= window.start).then(|| {",
        ["refusals_before_the_token_leave_one_event_per_window"],
    ),
    (
        "past the key cap a refusal still makes a key",
        VIEWER,
        "} else if self.counts.len() < self.cap {",
        "} else if true || self.counts.len() < self.cap {",
        ["past_the_key_cap_refusals_are_counted_as_overflow"],
    ),
    (
        "the playlist route also takes POST",
        f"{API}/gateway.rs",
        "get(super::viewer_gateway::photos_playlist_get),",
        "get(super::viewer_gateway::photos_playlist_get)\n                .post(super::viewer_gateway::photos_playlist_get),",
        ["photos_has_no_write_route"],
    ),
    (
        "Home may bind any resource for Photos",
        VIEWER,
        'Some(_) => anyhow::bail!("Photos can bind only its playlist"),',
        "Some(other) => Ok((other.to_string(), Some(PHOTOS_LAUNCH_TOKEN_TTL_SECS))),",
        ["home_cannot_bind_anything_else"],
    ),
    (
        "Home may bind a resource for other targets",
        VIEWER,
        "        if requested.is_some() {\n",
        "        if false && requested.is_some() {\n",
        ["home_cannot_bind_anything_else"],
    ),
    (
        "Photos gets the default 12-hour token",
        f"{API}/gateway_home_runtime.rs",
        "launch_ttl_secs.unwrap_or(HOME_LAUNCH_TOKEN_TTL_SECS),",
        "launch_ttl_secs.map(|_| HOME_LAUNCH_TOKEN_TTL_SECS).unwrap_or(HOME_LAUNCH_TOKEN_TTL_SECS),",
        ["home_binds_the_photos_playlist_with_a_short_lived_token"],
    ),
]


def env():
    environment = dict(os.environ)
    environment.setdefault("RUST_TEST_THREADS", "2")
    return environment


def cargo(*args):
    return subprocess.run(
        ["cargo", "test", "-p", "elastos-server", "--lib", *args],
        cwd=ELASTOS,
        env=env(),
        capture_output=True,
        text=True,
    )


def tests_fail(filters):
    build = cargo("--no-run")
    if build.returncode != 0:
        print(build.stderr[-3000:])
        raise SystemExit("a falsifier does not compile")
    for name in filters:
        result = cargo("--", "--exact", TESTS + name)
        if result.returncode == 0:
            return False
    return True


def main():
    import sys
    args = sys.argv[1:]
    check_only = "--check" in args
    parts = [arg for arg in args if arg != "--check"]
    missed = []
    for name, relative, old, new, filters in CASES:
        path = ELASTOS / relative
        saved = path.read_bytes()
        text = saved.decode()
        if text.count(old) != 1:
            raise SystemExit(f"{name}: expected the line once in {relative}, found {text.count(old)}")
        if check_only or (parts and not any(part in name for part in parts)):
            continue
        try:
            path.write_text(text.replace(old, new))
            caught = tests_fail(filters)
        finally:
            path.write_bytes(saved)
        print(f"{'caught' if caught else 'MISSED'}: {name} -> {', '.join(filters)}", flush=True)
        if not caught:
            missed.append(name)
    if missed:
        raise SystemExit(f"{len(missed)} falsifier(s) not caught: {missed}")
    if check_only:
        print(f"all {len(CASES)} anchors found once")
    else:
        print("all selected seam falsifiers caught")


if __name__ == "__main__":
    main()
