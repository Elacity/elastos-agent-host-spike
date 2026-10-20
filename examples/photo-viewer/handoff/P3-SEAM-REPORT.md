# P3 seam report: Photos read-only Runtime routes

Slice P3 code, part one: the Runtime seam only, as approved (review answers 1, 2, 4, 5). **It stops here for a
review before anything builds on it.** The surface page is not written.

**Round 2** (review of 7c5ad641): each Photos request now leaves exactly one audit record, and the internal
stat and read are not audited apart. Record ids are the launch id plus a counter. The 15-minute token is for
the playlist launch only. A launch pins the playlist's sha256 at its first read. See "Round 2 changes".

Branch `claude/photo-p3-seam`, stacked on `claude/photo-p3`. Shipping Runtime changes, all approved for this
item. Paths under `elastos/crates/elastos-server/src/` are shortened to `server/`.

## What changed

| File | Change | Answer |
|---|---|---|
| `server/api/viewer_gateway.rs` | The seam ("Photos surface" section): two GET routes, `photos_launch_binding`, refusals, audit | 1, 2, 5 |
| `server/api/gateway.rs` | Mounts the two routes, GET only; re-exports the new token issuer | 1 |
| `server/api/gateway_home_token.rs` | The issuer takes a lifetime (1 to 12 hours); new `issue_home_projection_launch_token_with_ttl`; test-only expired-token helper; `require_home_viewer_launch` (round 2) | 5 |
| `server/api/gateway_models.rs` | `HomeLaunchRequest.selected_resource` (optional) | 2 |
| `server/api/gateway_home_runtime.rs` | `home_launch` checks the binding before any side effect and mints with its selected resource and lifetime; title "Photos" | 2, 4, 5 |
| `server/library.rs` | Viewer label `image-viewer` → "Photos" | 4 |
| `capsules/home/browser/home-shell-host.js` | Home asks to bind the playlist when Photos is opened as an app (5 lines) | 2 |
| `server/api/gateway_tests/photos.rs`, `gateway_tests/mod.rs` | 24 tests | all |
| `server/api/gateway_server.rs` | Writes the open pre-token refusal window at shutdown (round 3) | Sasha, round 3 |
| `scripts/home-photos-launch.test.mjs`, `justfile` | 3 Home tests, added to `just verify` | 2 |
| `examples/photo-viewer/falsify-seam.py` | 21 seam falsifiers; `--check` and name filters (round 3) | all |

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
7. **Pin.** The first playlist read of a launch pins the playlist's sha256 to that launch id. A later read,
   playlist or item, that finds other bytes is refused, 409 "the playlist changed during this launch".
8. **Audit.** Every request after a valid launch token, served or refused, appends exactly one
   `photos.viewer.playlist` or `photos.viewer.item` event. The stat and read inside it write none. If the
   event cannot be written, the request fails (500).

What a Photos token cannot do: use the generic viewer read. `/api/viewers/image-viewer/library-object`
refuses it, because its selected resource is the playlist, not the viewer
(`a_photos_token_cannot_use_the_generic_viewer_read`). A Photos frame therefore has exactly these two routes.

## Home binding and the token (answers 2, 4, 5)

- Home's host page adds `selected_resource: <playlist>` when it launches `image-viewer` with no `objectUri`
  (`capsules/home/browser/home-shell-host.js`, `launchHomeTarget`).
- Runtime accepts a selected resource only for `image-viewer`, and only that playlist. Anything else is
  refused with 400 before any launch side effect (`photos_launch_binding`, called at the top of `home_launch`).
- The launch that binds the playlist gets a **15-minute** token. Every other launch, including an
  `image-viewer` launch with no selected resource (a Library open of one image), keeps 12 hours (round 2).
- **Phase 2:** the launch ends when the window closes, so the token cannot outlive it. That is not built; the
  short lifetime stands in.
- Home and the Library show the name **Photos**. The id stays `image-viewer`.

## Round 2 changes

### One record per Photos request (change 1, answer 1)

- The seam calls the Library object provider through a new non-auditing helper, `object_provider_request`.
  The generic viewer read, `viewer_object_provider_request`, keeps its own `library.viewer.*` events and now
  wraps that helper. So a Photos item read, which is a playlist stat, a playlist read, an item stat and an
  item read, leaves one event, not nine.
- The record (`photos_audit`):

  | Field | Value |
  |---|---|
  | `event_type` | `photos.viewer.playlist` or `photos.viewer.item` |
  | `event_id` | `audit:<event_type>:<launch_id>:<boot>:<n>`. `n` is a per-process counter; `boot` is 8 random bytes per Runtime process, so ids stay unique after a restart. |
  | `challenge_id` | the launch id |
  | `capsule_id` | `image-viewer` |
  | `result` | `served` or `refused` |
  | `reason` | `playlist=<uri> sha256=<hex> position=<n> item=<uri> result=served <N> bytes` or `result=refused <status>: <reason>`; `-` for a field not reached |

  Principal, proof binding and session come from the launch token, as before.
- A request refused before the token check (no token, a bad or expired token, another viewer's token) has
  no launch to name. Round 3 counts it, one event per window (below). The gateway front door refuses most of
  these before the route runs.

### The 15-minute token is for the playlist launch only (change 2)

`photos_launch_binding` returns no lifetime when `image-viewer` is launched with no selected resource, so that
launch keeps the default 12 hours. Only the launch bound to the playlist gets 15 minutes.

### The playlist is pinned for its launch (optional item)

- At the first playlist read of a launch, the seam stores `launch_id → sha256` in memory. A later read in the
  same launch, of the playlist or an item, with other bytes is refused (409). A new launch reads and pins the
  new playlist.
- Entries are pruned once older than the 15-minute lifetime, which a pin cannot outlive: the token expires
  first. Round 3 bounds the table (below).
- **Limit:** the pins are in memory. After a Runtime restart, a token that is still valid pins again at its
  next read. Keeping them across restarts would need a store; I did not add one.

### Known limit: the fixed playlist path (answer 2)

The playlist is a fixed path, `localhost://Users/self/.AppData/App/photo-viewer/playlist.json`. Any capsule
whose storage grant matches it could write it (P3 design, section 3). This is accepted for the spike. Phase 2
binds the core's run output to the launch, so the surface reads only what that run wrote. The constant's doc
comment says so too.

## Round 3 changes

### Refusals before the token check are counted, one event per window (Sasha)

The shape Sasha approved, with one change: ONE event per window carrying all the counts.
- **Key:** `(route, code)`.
  - The route is the matched route's fixed name, `playlist` or `item`, passed by the handler, never taken
    from the request path.
  - The code comes from a fixed list: `missing_token` (Runtime's own "missing home launch token" message),
    `token_refused` (any other token refusal), and `other`.
  - Any name off those lists becomes `other`. Request text never becomes a key.
- **Window:** fixed 60-second windows, counted in memory, one open window per data root.
- **Record:** one `photos.viewer.unadmitted` event per window, with no principal. Reason
  `window=<start>-<end> counts=<route>/<code>:<n>,... overflow=<n> total=<n>`. A steady flood therefore
  costs one event a minute of the 512-event audit tail, not 17.
- **Cap:** at most 16 keys per window, then an overflow count. Counters saturate at `u32::MAX`. With the
  fixed lists today there are at most 6 keys (2 routes x 3 codes), so the cap is a backstop that is not
  reached.
- **Written:** at the first request of a later window, or at gateway shutdown (`gateway_server.rs`, after
  the connections drain). A crash loses the open window. If the write fails, the request is still refused
  and a warning is logged. A clock that steps back keeps counting into the open window.
- At the seam only. The front door's refusals are not counted; that is a separate decision.

### The pin table is bounded (Codex finding 3)

- At most `PHOTOS_MAX_PINS` = 1024 launches hold a pin.
- A new launch is refused while the table is full: 503, "too many Photos launches are open (1024); try
  again when one ends". A live pin is never evicted to make room.
- Expired pins are pruned only when a new launch pins. A request from a launch already pinned does a single
  lookup and no scan. The scan is at most 1024 entries.

## Tests run and results

`export RUST_TEST_THREADS=2`:

| Suite | Result |
|---|---|
| `cargo test -p elastos-server --lib gateway_tests::photos` | 24 passed (round 3) |
| `node --test scripts/home-photos-launch.test.mjs` | 3 passed |
| `node scripts/home-library-picker-smoke.mjs`, `node --test scripts/browser-window-close-handshake.test.mjs` (both read `launchHomeTarget`) | 18 passed, 29 passed |
| `cargo test -p elastos-server --lib viewer` (the generic viewer read, now a wrapper) | 51 passed |
| `cargo fmt -p elastos-server -- --check`, `cargo clippy -p elastos-server --all-targets -- -D warnings` | clean |
| Full `cargo test -p elastos-server --lib` on this branch (round 1) | 3015 passed, 14 failed, 22 ignored |
| The same 14, run on the base `spike/photo-viewer` in a separate worktree | 13 fail there too; 1 passes |
| That one (`gateway_server::trusted_gateway_tests::term_drains_gateway_streams_and_separate_owned_child_groups`) run alone on this branch, with the Photos, GBA and token tests | passes (34 passed) |

### The 13 that also fail on the base, and the shutdown flake (answer 3)

Not fixed here, as asked. None is in code this slice touches. Causes as far as I traced them in this
container:

| Test (`elastos-server --lib`) | Cause |
|---|---|
| `api::gateway::gateway_tests::library::test_runtime_custody_two_runtime_portable_listing_gateway_journey` | "missing test binary env: ELASTOS_TEST_PROTECT_PROVIDER_BIN" (`protected_content_runtime/tests.rs:667`). The protect provider is not built here. |
| `api::gateway::gateway_tests::library::test_runtime_custody_typed_publish_buy_open_read_segment_and_close` | The same |
| `protected_content_runtime::tests::runtime_custody_library_publish_fails_closed_without_chain_policy` | The same |
| `protected_content_runtime::tests::runtime_custody_library_publish_retries_exactly_when_protect_never_dispatches` | The same |
| `protected_content_runtime::tests::runtime_custody_registry_adapter_process_happy_path_uses_public_provision_receipt` | "missing test binary env: ELASTOS_TEST_CUSTODY_PROVIDER_BIN". The custody provider is not built here. |
| `protected_content_runtime::tests::runtime_decrypt_registry_adapter_process_reconstructs_for_prepared_recipient_and_closes_cleanly` | The same |
| `protected_content_runtime::tests::runtime_release_coordinator_process_two_of_three_success_stops_before_third_node` | The same |
| `protected_content_runtime::tests::runtime_custody_open_pending_survives_active_write_failure_and_failed_cleanup` | Makes a write fail by setting its directory to `0o500` (`tests.rs:11682`). This container runs as uid 0, which ignores that, so the write succeeds. |
| `protected_content_runtime::tests::write_owner_only_bytes_failed_replace_preserves_previous_runtime_storage_record` | The same (`tests.rs:5675`) |
| `room_service::tests::attachment_upload_finish_preserves_retry_state_when_final_state_save_fails` | The same (`room_service.rs:7531`) |
| `api::gateway::gateway_tests::remote_model::denial_authority::a_denial_that_could_not_be_saved_cancels_nothing` | The same (`gateway_tests/remote_model.rs:1683`): the save succeeds as root, so "no cancel may follow" fails |
| `runtime_control::gateway_children::tests::cancelled_start_reaps_group_and_other_gateway_generation_is_preserved` | `assert!(!pid_is_alive(pid))` (`gateway_children.rs:1059`): the killed child is still present when checked. I think nothing reaps it in this container (no init); not proven. |
| `update_controller::tests::readiness_uses_the_reported_ipv6_home_listener_and_checks_its_served_bytes` | Binding `[::1]` fails, `os error 97` (address family not supported): this container has no IPv6 |

All 13 are environment causes, not product bugs, as far as I traced them. Each should pass on a Mac with the
provider binaries built, as a normal user, with IPv6. The child-reaping one is the least certain.

**The flake:** `gateway_server::trusted_gateway_tests::term_drains_gateway_streams_and_separate_owned_child_groups`
failed once in the full parallel run and passes alone on both branches. It sends SIGTERM and waits for child
process groups to drain, so it is timing-sensitive under load. I did not root-cause it further.

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
| one record per request, N reads give N records, none from the inner stat and read; ids hold the launch id and are unique | `each_photos_request_leaves_exactly_one_audit_record` |
| a refusal after the token leaves exactly one record | `a_refusal_after_the_token_leaves_one_record` |
| a playlist changed during a launch (409); a new launch sees the new one | `a_launch_keeps_the_playlist_it_read_first` |
| 15 minutes for the playlist launch only, 12 hours for the unbound launch | `home_binds_the_photos_playlist_with_a_short_lived_token` |

## Falsifiers

`RUST_TEST_THREADS=2 python3 -I examples/photo-viewer/falsify-seam.py`: **21 of 21 caught** (round 3). Each mutant must
compile and is restored from saved bytes; `git status` after the run was clean.

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
| the internal stat audits again | `each_photos_request_leaves_exactly_one_audit_record` |
| the record id uses the second, not a counter | `each_photos_request_leaves_exactly_one_audit_record` |
| a launch does not keep its first playlist | `a_launch_keeps_the_playlist_it_read_first` |
| a launch with no playlist gets the short token | `home_binds_the_photos_playlist_with_a_short_lived_token` |
| playlist route also takes POST | `photos_has_no_write_route` |
| Home may bind any resource for Photos | `home_cannot_bind_anything_else` |
| Home may bind a resource for other targets | `home_cannot_bind_anything_else` |
| Photos gets the default 12-hour token | `home_binds_the_photos_playlist_with_a_short_lived_token` |
| round 3: an unknown route or code creates its own key | `an_unknown_route_or_code_cannot_create_a_key` |
| round 3: each refusal before the token writes its own event | `refusals_before_the_token_leave_one_event_per_window` |
| round 3: past the key cap a refusal still makes a key | `past_the_key_cap_refusals_are_counted_as_overflow` |
| round 3: the pin table has no limit | `a_full_pin_table_refuses_a_new_launch_and_keeps_live_pins` |

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
  read routes on one playlist, pinned to its first bytes; the generic viewer read refuses it.
- **10 (one path).** Items are reached by position only, with no path input and no second route.
- **11 (fail closed, then explain).** Every refusal has a reason and a test. After the token check, each
  request leaves one record naming the playlist, position, item and result.
- **13 (objects vs capsules).** The playlist and images are the person's objects.
- **16 (UI is not authority).** Home asks, Runtime checks and signs; Home can bind nothing else.
- **15 (content-addressed).** The launch pins the playlist's sha256; Phase 2 binds the run output by CID.
- **18 (isolated instances).** A short launch; window-close ending is Phase 2.

## Roadmap milestone

2.5 (first app, photo viewer). The binding in the signed launch context is the Phase 2 mechanism (P3 design
section 4), used here for the fixed spike playlist.

## Phase 2 decisions (Sasha's answers to round 2)

1. **Pins in memory are fine for the spike.** In the Runtime, the playlist's sha256 is written into the
   launch's signed token, or its launch record, when the launch is issued. The seam then compares against
   that, and pins nothing on first read. A restart cannot re-pin, and there are no pins to store.
2. **Refusals before the token check:** built in round 3 at the seam, counted by fixed route and code and
   written as one event per window. Per peer address was dropped, because every local caller is
   127.0.0.1. Counting at the front door is a separate decision.

Item 1 has no code yet.

## Next slice

The Codex review of this branch with #21. Not the Photos surface page yet (Sasha).
