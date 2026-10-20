#!/usr/bin/env python3
"""Break each check of the Photos seam, see its test fail, restore it.

Usage: RUST_TEST_THREADS=2 python3 -I falsify-seam.py

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
        "if selected_resource != PHOTOS_PLAYLIST_URI {",
        "if false && selected_resource != PHOTOS_PLAYLIST_URI {",
        ["photos_refuses_a_launch_not_bound_to_its_playlist"],
    ),
    (
        "another viewer's token is accepted",
        VIEWER,
        "require_home_viewer_launch_token_context(data_dir, headers, PHOTOS_VIEWER)",
        'require_home_viewer_launch_token_context(data_dir, headers, "documents")',
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
        "    append_viewer_library_audit(\n        data_dir,\n        context,\n        PHOTOS_VIEWER,",
        "    let _ = (data_dir, context, &request_id, result, &reason);\n    if true {\n        return Ok(());\n    }\n    append_viewer_library_audit(\n        data_dir,\n        context,\n        PHOTOS_VIEWER,",
        ["photos_serves_its_bound_playlist_and_the_items_it_lists"],
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
    missed = []
    for name, relative, old, new, filters in CASES:
        path = ELASTOS / relative
        saved = path.read_bytes()
        text = saved.decode()
        if text.count(old) != 1:
            raise SystemExit(f"{name}: expected the line once in {relative}, found {text.count(old)}")
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
    print("all seam falsifiers caught")


if __name__ == "__main__":
    main()
