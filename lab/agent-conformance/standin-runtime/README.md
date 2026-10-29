# Live-grant stand-in

This value is the lab stand-in for the shell view of every session's live grants. The real route can replace it later because the JSON matches (M1-R).

`StandIn::get_capability_list` answers `GET /api/capability/list`. `scope: None` is the plain route. `scope: Some("all_sessions_live")` is `GET /api/capability/list?scope=all_sessions_live`. The caller is `Shell` or `Client { session_id }`, a method argument for the authenticated session. It is not a JSON field.

A shell caller receives one body on both forms. The body's keys are `scope` and `capabilities`. `scope` is `all_sessions_live`. Each entry's keys are `request_id`, `session_id`, `resource`, `action`, `duration` and `granted_at`. Entries are sorted by `session_id`, then `request_id`.

A client caller with the plain route receives a body whose only key is `capabilities`. Entries are that session only, sorted by `request_id`. Each entry's keys are `request_id`, `resource`, `action`, `duration` and `granted_at`. A client session with no grant receives `capabilities: []`.

`seed_grant` is a lab test seam, not a route. It stores `request_id`, `session_id`, `resource`, `action`, `duration`, the seeded `granted_at`, a life, and `session_ended`. The four lives are `Live`, `Exhausted`, `Revoked` and `Expired`. One filter keeps a grant whose life is `Live`. `session_ended` leaves that grant in the view.

A scope other than `all_sessions_live` is status 400. The reason starts with `unknown capability list scope:` and contains that scope text. A client that asks for `all_sessions_live` is status 403 with the reason `This endpoint requires shell privileges`.

`run_leaves_no_live_grant` stays blocked on the real Runtime (`AC-021-GRANTS`). A passing `standin_` row gives the Runtime no credit.

`StandIn::post_capsules` answers `POST /api/capsules`. `StandIn::get_capsules` answers `GET /api/capsules`. A shell caller receives status 200. A client receives status 403 and the reason `This endpoint requires shell privileges`.

The launch body's only key is `path`. The launch value's keys are `id`, `name`, `status` and `session_id`. `session_id` equals `id`. The list body's only key is `capsules`. Each entry's keys are `id`, `name`, `status`, `session_id` and `cause`. Entries are sorted by `id`.

The status strings are `starting`, `running`, `stopping`, `stopped` and `failed`. This stand-in stores `starting`, `running`, `stopped` and `failed`. `cause` is empty while `starting` or `running`. A `failed` entry stays while the test-supplied instant is less than 60 seconds after it failed, and the list omits it at 60 seconds. A `starting` or `running` entry stays at every instant.

`admit_resident` stores one path with its name, its `Start`, and the world name `resident-capsule`. `admit_resident`, `finish_start` and `set_instant` are lab test seams, not routes. `finish_start` is the one call to `resident.start`. Launch answers `starting` before that call returns.

`StandIn::delete_capsule` answers `DELETE /api/capsules/:id`. The body's only key is `reason`. The Ok value is null. `cause` is `stopped: ` joined with that reason. A `stopped` entry stays while the test-supplied instant is less than 60 seconds after the stop, and the list omits it at 60 seconds. Each `Live` grant whose session is that instance becomes `Revoked` and drops out through the one life filter. The sibling instance stays.

An accepted stop and a failed start deny that session's pending requests through `settle_pending`. `settled_by` is `runtime`, and `decision_reason` is the stop cause or the failure cause. An `Ok` start does not settle. The request can be stored while the instance is `starting`. A PASS gives the Runtime no A10 credit and no A11 credit.

`authorise` is a lab test seam, not a route. A sibling is refused with `wrong capsule`. A stop removes that session's live grant through the one filter. This value is the lab stand-in and the real route can replace it later because the refusal matches (M1-R). `instance_grant_does_not_authorise_sibling` stays the process-isolation row.

This value is the lab stand-in and the real route can replace it later because the JSON matches (M1-R). `parallel_capsules_complete_independently` stays `#[ignore = "blocked: RT4"]`. `run_leaves_no_live_grant` stays blocked on the real Runtime.
