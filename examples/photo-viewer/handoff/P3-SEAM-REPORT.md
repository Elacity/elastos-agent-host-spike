# P3 seam report: Photos read-only Runtime routes

Slice P3 code, part one: the Runtime seam only, as approved (review answers 1, 2, 4, 5). **It stops here for a
review before anything builds on it.** The surface page is not written.

Branch `claude/photo-p3-seam`, stacked on `claude/photo-p3`. Shipping Runtime changes, all approved for this
item. Paths under `elastos/crates/elastos-server/src/` are shortened to `server/`.

## What changed

| File | Change | Answer |
|---|---|---|
| `server/api/viewer_gateway.rs` | The seam ("Photos surface" section): two GET routes, `photos_launch_binding`, refusals, audit | 1, 2, 5 |
| `server/api/gateway.rs` | Mounts the two routes, GET only; re-exports the new token issuer | 1 |
| `server/api/gateway_home_token.rs` | The issuer takes a lifetime (1 to 12 hours); new `issue_home_projection_launch_token_with_ttl`; test-only expired-token helper | 5 |
| `server/api/gateway_models.rs` | `HomeLaunchRequest.selected_resource` (optional) | 2 |
| `server/api/gateway_home_runtime.rs` | `home_launch` checks the binding before any side effect and mints with its selected resource and lifetime; title "Photos" | 2, 4, 5 |
| `server/library.rs` | Viewer label `image-viewer` → "Photos" | 4 |
| `capsules/home/browser/home-shell-host.js` | Home asks to bind the playlist when Photos is opened as an app (5 lines) | 2 |
| `server/api/gateway_tests/photos.rs`, `gateway_tests/mod.rs` | 16 tests | all |
| `scripts/home-photos-launch.test.mjs`, `justfile` | 3 Home tests, added to `just verify` | 2 |
| `examples/photo-viewer/falsify-seam.py` | 13 seam falsifiers | all |

## The seam

| Route | Returns |
|---|---|
| `GET /api/viewers/image-viewer/playlist` | The playlist bound to this launch, at most 64 KiB |
| `GET /api/viewers/image-viewer/playlist/item/:order` | The bytes of the item at `order`, at most 64 MiB |

Both answer `no-store` and `nosniff`. There is no other method; anything else is 405.

Checks, in order. The first failure refuses with a reason:

1. **Gateway front door.** Without a valid launch token, the request is refused before any route runs
   (`server/api/gateway_frontdoor.rs:258-265`, 403). This is existing behaviour.
2. **Installed.** The Photos viewer (`image-viewer`, role `viewer`) is installed (404).
3. **Token.** The launch token's executable actor is `image-viewer` (401 otherwise, for example a Documents
   token).
4. **Binding.** The token's signed `selected_resource` is the Photos playlist,
   `localhost://Users/self/.AppData/App/photo-viewer/playlist.json`. Otherwise 403 "this Photos launch is not
   bound to a playlist", which covers a Library open of one image, a playlist from another launch, or any other
   resource. The path is resolved under the token's own principal root.
5. **Position.** `:order` is a whole number (400). The playlist is read through the Library object provider
   with the size checked first (413 over 64 KiB). Its schema must be `elastos.photo-viewer.playlist/v1`. The
   item is found by `items[].order` only, so a skipped entry is not an item. Not found → 404. Malformed, or the
   same position twice → 422.
6. **Item.** The item `uri` must be `localhost://Users/self/Pictures/<rest>`, with no empty, `.` or `..`
   segment and no `?`, `#`, `\` or control character (403). A rooted `Users/<root>` path is refused too, so
   the alias is the only form. It is mapped to the token's principal root. Then the Library stat must say the
   Photos viewer may open it (403, the extension table), its size must be at most 64 MiB (413), and the read
   is checked again after.
7. **Audit.** Every read after a valid launch token, served or refused, appends one
   `photos.viewer.playlist` or `photos.viewer.item` event. It records the result, the position and the URI. If
   the event cannot be written, the read fails.

What a Photos token cannot do: use the generic viewer read. `/api/viewers/image-viewer/library-object`
refuses it, because its selected resource is the playlist, not the viewer
(`a_photos_token_cannot_use_the_generic_viewer_read`). A Photos frame therefore has exactly these two routes.

## Home binding and the token (answers 2, 4, 5)

- Home's host page adds `selected_resource: <playlist>` when it launches `image-viewer` with no `objectUri`
  (`capsules/home/browser/home-shell-host.js`, `launchHomeTarget`).
- Runtime accepts a selected resource only for `image-viewer`, and only that playlist. Anything else is
  refused with 400 before any launch side effect (`photos_launch_binding`, called at the top of `home_launch`).
- Every `image-viewer` launch gets a **15-minute** token. Other targets keep 12 hours.
- **Phase 2:** the launch ends when the window closes, so the token cannot outlive it. That is not built; the
  short lifetime stands in.
- Home and the Library show the name **Photos**. The id stays `image-viewer`.

## Tests run and results

`export RUST_TEST_THREADS=2`:

| Suite | Result |
|---|---|
| `cargo test -p elastos-server --lib gateway_tests::photos` | 16 passed |
| `node --test scripts/home-photos-launch.test.mjs` | 3 passed |
| `node scripts/home-library-picker-smoke.mjs`, `node --test scripts/browser-window-close-handshake.test.mjs` (both read `launchHomeTarget`) | 18 passed, 29 passed |
| `cargo fmt -p elastos-server -- --check`, `cargo clippy -p elastos-server --all-targets -- -D warnings` | clean |
| Full `cargo test -p elastos-server --lib` on this branch | 3015 passed, 14 failed, 22 ignored |
| The same 14, run on the base `spike/photo-viewer` in a separate worktree | 13 fail there too; 1 passes |
| That one (`gateway_server::trusted_gateway_tests::term_drains_gateway_streams_and_separate_owned_child_groups`) run alone on this branch, with the Photos, GBA and token tests | passes (34 passed) |

The 13 that also fail on the base are in protected content, rooms, update readiness, remote-model denial and
gateway child processes. None is in code this slice touches. Several assert a failed replace or save, which
running as root here defeats; I did not root-cause each.

The shutdown test failed once inside the full parallel run and passes alone, on both branches. I did not
reproduce or root-cause it. It does not exercise the code changed here.

Refusals covered, each with its test:

| Refusal | Test |
|---|---|
| no token or a bad token | `photos_refuses_without_a_launch_token` |
| expired token | `photos_refuses_an_expired_launch_token` |
| another viewer's token, also with the playlist bound | `photos_refuses_another_viewers_launch_token` |
| launch not bound to the playlist (Library open, another launch's playlist, an image) | `photos_refuses_a_launch_not_bound_to_its_playlist` |
| another person's token | `photos_reads_only_the_playlist_of_the_launching_person` (their own principal, no playlist, never this one) |
| missing playlist | `photos_refuses_when_the_playlist_is_missing` |
| position out of range, the skipped position, non-numeric, negative, overflow | `photos_refuses_a_position_out_of_range_or_not_listed` |
| no path input (query ignored, extra segment 404) | `photos_has_no_path_input` |
| outside `Pictures/`, `..`, `.`, empty segment, query, another principal, `elastos://`, rooted path, not viewable | `photos_refuses_items_outside_pictures_or_not_viewable` |
| malformed playlist, duplicate position, oversize | `photos_refuses_a_malformed_or_oversize_playlist` |
| write methods | `photos_has_no_write_route` |
| viewer not installed | `photos_requires_the_installed_photos_viewer` |
| Home binds anything else | `home_cannot_bind_anything_else` |
| served path, plus audit of served and refused reads | `photos_serves_its_bound_playlist_and_the_items_it_lists` |

## Falsifiers

`RUST_TEST_THREADS=2 python3 -I examples/photo-viewer/falsify-seam.py`: **13 of 13 caught**. Each mutant must
compile and is restored from saved bytes; a grep after the run found no mutant text.

| Falsifier | Caught by |
|---|---|
| a launch bound to something else reads the playlist | `photos_refuses_a_launch_not_bound_to_its_playlist` |
| another viewer's token accepted | `photos_refuses_another_viewers_launch_token` |
| a position matches any item | `photos_refuses_a_position_out_of_range_or_not_listed` |
| items outside `Pictures/` served | `photos_refuses_items_outside_pictures_or_not_viewable` |
| dot segments allowed | `photos_refuses_items_outside_pictures_or_not_viewable` |
| items the viewer cannot open served | `photos_refuses_items_outside_pictures_or_not_viewable` |
| playlist cap ten times larger | `photos_refuses_a_malformed_or_oversize_playlist` |
| duplicate positions allowed | `photos_refuses_a_malformed_or_oversize_playlist` |
| reads not audited | `photos_serves_its_bound_playlist_and_the_items_it_lists` |
| playlist route also takes POST | `photos_has_no_write_route` |
| Home may bind any resource for Photos | `home_cannot_bind_anything_else` |
| Home may bind a resource for other targets | `home_cannot_bind_anything_else` |
| Photos gets the default 12-hour token | `home_binds_the_photos_playlist_with_a_short_lived_token` |

Not falsified separately, and said plainly:

- **The second size check after the read.** It backs up the stat check. With only the stat check removed,
  the post-read check still refuses, so no test fails.
- **The 64 MiB item cap at full size.** Not tested at full size. It is the same `read_photos_object` limit
  that the playlist cap test exercises.
- **The `..` falsifier.** With the seam's own check removed, the Library's own URI check
  (`server/library.rs:3299-3301`) still refuses, so the test fails on its expected 403 against a 404 rather
  than on a served file.

## Findings while testing

1. **The test fixture `passkey_authority_with_name` always uses the same credential**
   (`gateway_tests/support_runtime.rs:483-493`). Two calls give the same person. My first cross-person test
   passed for the wrong reason. It now uses its own credential and asserts the principals differ.
2. **A projection token's session grant must include Home** (`server/api/gateway_home_token.rs` principal and
   grant check). That holds in production, where Home's own launch mints Photos tokens.

## Principles checked

- **3 (no ambient authority).** The surface's only authority is a 15-minute, non-delegatable token for two
  read routes on one playlist; the generic viewer read refuses it.
- **10 (one path).** Items are reached by position only, with no path input and no second route.
- **11 (fail closed, then explain).** Every refusal has a reason and a test, and is audited after the token
  check.
- **13 (objects vs capsules).** The playlist and images are the person's objects.
- **16 (UI is not authority).** Home asks, Runtime checks and signs; Home can bind nothing else.
- **18 (isolated instances).** A short launch; window-close ending is Phase 2.

## Roadmap milestone

2.5 (first app, photo viewer). The binding in the signed launch context is the Phase 2 mechanism (P3 design
section 4), used here for the fixed spike playlist.

## Questions for the review

1. The seam reads through the Library object provider (`viewer_object_provider_request`). That provider also
   writes its own `library.viewer.*` events, so each Photos read leaves two kinds of audit event. Keep both,
   or only the `photos.viewer.*` one?
2. The playlist is still a fixed path any capsule with matching storage bounds could write (P3 design,
   section 3). Is that acceptable until Phase 2 binds the run output?
3. Should the 13 failures that also fail on the base, and the one shutdown test that fails only under full
   load, be looked at separately? I made no change for them.

## Next slice

None until the review. After it: the `image-viewer` surface page (P3 design section 6, item 1).
