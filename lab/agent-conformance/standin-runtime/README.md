# Live-grant stand-in

This value is the lab stand-in for the shell view of every session's live grants. The real route can replace it later because the JSON matches (M1-R).

`StandIn::get_capability_list` answers `GET /api/capability/list`. `scope: None` is the plain route. `scope: Some("all_sessions_live")` is `GET /api/capability/list?scope=all_sessions_live`. The caller is `Shell` or `Client { session_id }`, a method argument for the authenticated session. It is not a JSON field.

A shell caller receives one body on both forms. The body's keys are `scope` and `capabilities`. `scope` is `all_sessions_live`. Each entry's keys are `request_id`, `session_id`, `resource`, `action`, `duration` and `granted_at`. Entries are sorted by `session_id`, then `request_id`.

A client caller with the plain route receives a body whose only key is `capabilities`. Entries are that session only, sorted by `request_id`. Each entry's keys are `request_id`, `resource`, `action`, `duration` and `granted_at`. A client session with no grant receives `capabilities: []`.

`seed_grant` is a lab test seam, not a route. It stores `request_id`, `session_id`, `resource`, `action`, `duration`, the seeded `granted_at`, a life, and `session_ended`. The four lives are `Live`, `Exhausted`, `Revoked` and `Expired`. One filter keeps a grant whose life is `Live`. `session_ended` leaves that grant in the view.

A scope other than `all_sessions_live` is status 400. The reason starts with `unknown capability list scope:` and contains that scope text. A client that asks for `all_sessions_live` is status 403 with the reason `This endpoint requires shell privileges`.

`run_leaves_no_live_grant` stays blocked on the real Runtime (`AC-021-GRANTS`). A passing `standin_` row gives the Runtime no credit.
