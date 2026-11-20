# Core calls proposal
Pinned commit: 1cc3e47b9dcd965d003c504ac79d027b4f2a0d15

LAB DRAFT for Sash and Anders. This file is the proposal. It stays in the lab. It is design input for M1 checks A3, A5, A7 and B2, and it leaves those checks open.

## 0. What this proposes
This section states each core-call proposal once; section 7 holds its evidence.

### A3. Agent identity
propose: the agent DID is a separate DID, not the person principal person:local:. Name: agent principal. Inputs: the verified agent identity. Refusal: an identity that is not the bound agent principal. Owner: Runtime. A3 stays open.
Evidence: section 7, A3.

propose: the owned journal root moves to that agent principal's UsersAI path. Name: owned journal root. Inputs: the agent principal. Refusal: a root that is not under that principal. Owner: Runtime. A3 stays open.
Evidence: section 7, A3.

### A4. Model operations
propose: the model operation uses the hosted-effect socket, and the five model operations stay on the remote model service behind that socket. Name: hosted model call. Inputs: the granted effect request. Refusal: a call the Runtime did not grant. Owner: Runtime model service. A4 stays open.
Evidence: section 7, A4.

### A5. Grant handle
propose: the Bus v2 host-side handle is an opaque handle, and the guest does not read its binding. Name: grant handle. Inputs: the verified agent identity, the session, the capsule instance, and the owned storage root. Refusal: an unknown handle. Owner: Runtime. A5 stays open.
Evidence: section 7, A5.

### A7. Usage reservation
propose: the Runtime reserves one bounded usage amount before each dispatch, a cancellation releases the unused hold, and an uncertain outcome keeps the hold until a measured settle, because a due timeout records the uncertainty and keeps the hold. Name: usage reservation. Inputs: the admitted ceiling and the dispatch. Refusal: a reserve above the ceiling. Owner: Runtime. A7 stays open.
Evidence: section 7, A7.

### B2. Typed operations
propose: the contract names are run, child, init, hosted, and journal-append. Name: typed operation. Inputs: the granted ask. Refusal: an ask the grant does not carry. Owner: the contract. B2 stays open.
Evidence: section 7, B2.

## 1. Agent identity
This section is design input for A3. A3 stays open. This section cites no lab/grant-binding test.

The principal is who the agent runs as. Admission is a separate Runtime decision. A budget is a separate Runtime decision.

The guest names the launching person as `Users/self`.

`examples/agent-host/src/lib.rs:8162` defines the marker a declared pattern may hold. The value is `<principal>`. That marker stands for the user-namespace root. The declaration names no person and no host path. The constant is compiled in tests.

    /// The one marker a declared pattern may hold: the user-namespace root,
    /// `Users/<one name>`. The declaration names no person and no host path.
    #[cfg(test)]
    const PRINCIPAL_MARKER: &str = "<principal>";

`examples/agent-host/src/lib.rs:8168` defines the one principal a declared pattern may name. The value is `Users/self`. The guest names that principal, and the Runtime scopes it to the launching person. The constant is compiled in tests.

    /// The one principal a declared pattern may name. The guest names only
    /// `Users/self`, which the Runtime scopes to the launching person, so the
    /// declaration covers that person and no other `Users/<name>`.
    #[cfg(test)]
    const LAUNCHING_PRINCIPAL: &str = "Users/self";

`examples/agent-host/src/lib.rs:3754` states that the guest names only `Users/self`. `examples/agent-host/src/lib.rs:3755` states that the Runtime scopes that name to the launching person.

    /// The one place a task journal lives. The guest names only `Users/self`.
    /// The Runtime scopes that to the launching person.

The Runtime resolves `Users/self` to a person principal and a localhost root. The launch context carries the principal id. With no principal id, the alias is refused.

`elastos/crates/elastos-server/src/auth.rs::local_person_principal_id` builds the person principal from a proof-binding id. The body hashes that id with SHA-256 and returns `person:local:` plus the hex of the first 16 bytes of the digest. Reference: `elastos/crates/elastos-server/src/auth.rs:7071`.

The Runtime reaches the person principal through `elastos/crates/elastos-server/src/auth.rs::upsert_principal_for_binding`. That function asks the binding for its id at `elastos/crates/elastos-server/src/auth.rs:4743`, and it derives the principal id from that proof-binding id at `elastos/crates/elastos-server/src/auth.rs:4744` through `local_person_principal_id`. The `ProofBinding` record at `elastos/crates/elastos-auth/src/lib.rs:41` is the evidence the Runtime accepted as control of a principal, and it is not the principal. The derivation writes no grant and admits nothing; it names the principal that a later admission decision may use, and the agent principal stays a separate question in section 7.

`elastos/crates/elastos-server/src/auth.rs::principal_localhost_root` builds the localhost root from a principal id. The body hashes that id with SHA-256 and returns `localhost://Users/` plus the hex of the first 12 bytes of the digest. Reference: `elastos/crates/elastos-server/src/auth.rs:7090`.

`elastos/crates/elastos-server/src/resource_bridge.rs::scope_current_user_alias` rewrites the guest alias to that root. The body returns a value that is not a rooted localhost URI unchanged. For an unscoped `Users/self` alias with no principal id, it returns the error at `elastos/crates/elastos-server/src/resource_bridge.rs:814`: localhost://Users/self requires a principal-scoped launch context. With a principal id, `localhost://Users/self` becomes the principal root, and a path under `localhost://Users/self/` becomes that root plus the remainder. A remainder that is not under the alias returns Invalid current-user alias. A `localhost://Users/` path with no principal id is refused. With a principal id, that path is kept when it is the active principal root or a path under that root, and any other Users root is refused. Any other rooted localhost URI is returned in rooted form.

    fn scope_current_user_alias(
        uri_or_resource: &str,
        principal_id: Option<&str>,
    ) -> Result<String, String> {
        let Some(rooted) = rooted_localhost_uri(uri_or_resource) else {
            return Ok(uri_or_resource.to_string());
        };

        if is_unscoped_current_user_alias(&rooted) {
            let Some(principal_id) = principal_id else {
                return Err(
                    "localhost://Users/self requires a principal-scoped launch context".to_string(),
                );
            };
            let principal_root = crate::auth::principal_localhost_root(principal_id);
            if rooted == "localhost://Users/self" {
                return Ok(principal_root);
            }
            let rest = rooted
                .strip_prefix("localhost://Users/self/")
                .ok_or_else(|| format!("Invalid current-user alias: {uri_or_resource}"))?;
            return Ok(format!("{principal_root}/{rest}"));
        }

        if rooted.starts_with("localhost://Users/") {
            let Some(principal_id) = principal_id else {
                return Err("localhost://Users requires a principal-scoped launch context".to_string());
            };
            let principal_root = crate::auth::principal_localhost_root(principal_id);
            if rooted == principal_root || rooted.starts_with(&format!("{principal_root}/")) {
                return Ok(rooted);
            }
            return Err(
                "localhost://Users roots must use Users/self or the active principal root".to_string(),
            );
        }

        Ok(rooted)
    }

`elastos/crates/elastos-server/src/resource_bridge.rs::manifest_bound_users_self_matches_active_principal_root_only_with_context` shows a `Users/self` bound matching the active principal root only when the principal context is present. The body uses the principal id `person:local:abc123`, builds a resource under `principal_localhost_root` of that id, and allows the bound `localhost://Users/self/.AppData/LocalHost/Chat/*` when that principal id is passed in. The same call with no principal id returns false. Reference: `elastos/crates/elastos-server/src/resource_bridge.rs:1658`.

The journal path sits under the `Users/self` alias. `examples/agent-host/src/lib.rs:3757` sets `JOURNAL_ROOT` to `localhost://Users/self/.AppData/Agents/`. The constant is compiled in tests and in the wasm32 guest.

    #[cfg(any(test, target_arch = "wasm32"))]
    const JOURNAL_ROOT: &str = "localhost://Users/self/.AppData/Agents/";

`examples/agent-host/src/lib.rs::journal_resource` returns that root plus the agent id, `/tasks/`, the task id, and `/journal`. The body returns the error journal id when either id fails its check. Otherwise it returns the joined path. The alias rewrite above places that journal under the launching person's localhost root: the principal root, then `.AppData/Agents/`, the agent id, `tasks`, the task id, and `journal`. Reference: `examples/agent-host/src/lib.rs:3760`.

## 2. Signed declarations
This section is design input for A3 and A5. Both stay open.

The signature covers the printed lab CID and names the signer DID.

`lab/capsule-identity/src/lib.rs::name_signature_message` hashes the printed lab CID. The body calls domain_separated_digest with NAME_SIGNATURE_DOMAIN and the UTF-8 bytes of the name. Signing and verifying both call this, and nothing else builds the message. The whole printed lab CID, its b prefix included, is the signed name. Reference: `lab/capsule-identity/src/lib.rs:1383`.

Reference: `lab/capsule-identity/tests/encoding.rs:107` `lab_cid_prints_with_the_lab_label`.

`lab/capsule-identity/src/lib.rs::sign_bundle` signs that message and sets signer_did from the signing key. The name comes from lab_cid. That name is the printed lab CID. The body hashes it with name_signature_message and signs the digest. signer_did is signer_did_of of the signing key. The function returns the signature and writes no file. Reference: `lab/capsule-identity/src/lib.rs:1393`.

Reference: `lab/capsule-identity/tests/encoding.rs:140` `single_block_at_the_chunk_limit_has_the_pinned_cid`.
Reference: `lab/capsule-identity/tests/location.rs:142` `file_times_and_modes_do_not_change_the_lab_cid`.
Reference: `lab/capsule-identity/tests/encoding.rs:256` `long_utf8_name_has_the_pinned_cid`.
Reference: `lab/capsule-identity/tests/encoding.rs:59` `path_and_content_boundaries_cannot_collide`.
Reference: `lab/capsule-identity/tests/encoding.rs:247` `empty_file_has_the_pinned_cid`.
Reference: `lab/capsule-identity/tests/encoding.rs:273` `encoder_refuses_file_directory_conflict`.
Reference: `lab/capsule-identity/tests/refusals.rs:157` `symlink_in_bundle_is_refused_with_its_path`.
Reference: `lab/capsule-identity/tests/walk.rs:237` `link_at_the_bundle_root_is_refused`.
Reference: `lab/capsule-identity/tests/walk.rs:260` `root_path_through_a_link_loop_keeps_the_system_reason`.
Reference: `lab/capsule-identity/tests/walk.rs:55` `entry_swapped_for_a_link_before_open_is_refused`.
Reference: `lab/capsule-identity/tests/refusals.rs:45` `manifest_with_an_unknown_field_is_refused`.
Reference: `lab/capsule-identity/tests/bytes.rs:41` `one_byte_change_in_the_manifest_changes_the_lab_cid`.
Reference: `lab/capsule-identity/tests/location.rs:106` `changing_the_url_or_store_row_keeps_the_lab_cid`.
Reference: `lab/capsule-identity/tests/bytes.rs:65` `one_byte_change_in_any_payload_file_changes_the_lab_cid`.
Reference: `lab/capsule-identity/tests/bytes.rs:102` `adding_or_removing_a_payload_file_changes_the_lab_cid`.
Reference: `lab/capsule-identity/tests/refusals.rs:261` `unreadable_folder_is_refused_with_its_path`.
Reference: `lab/capsule-identity/tests/walk.rs:84` `entry_swapped_for_a_fifo_before_open_is_refused_without_blocking`.
Reference: `lab/capsule-identity/tests/location.rs:64` `renaming_the_bundle_folder_keeps_the_lab_cid`.
Reference: `lab/capsule-identity/tests/encoding.rs:33` `lab_cid_does_not_depend_on_listing_order`.
Reference: `lab/capsule-identity/tests/encoding.rs:318` `encoder_refuses_a_duplicate_path`.
Reference: `lab/capsule-identity/tests/encoding.rs:149` `file_over_one_leaf_has_the_pinned_cid`.
Reference: `lab/capsule-identity/tests/refusals.rs:28` `bundle_without_capsule_json_is_refused`.
Reference: `lab/capsule-identity/tests/encoding.rs:224` `directory_over_the_hamt_threshold_is_refused`.
Reference: `lab/capsule-identity/tests/walk.rs:111` `entry_swapped_for_a_folder_before_open_is_refused`.
Reference: `lab/capsule-identity/tests/refusals.rs:66` `manifest_that_fails_runtime_validate_is_refused`.
Reference: `lab/capsule-identity/tests/encoding.rs:298` `encoder_refuses_a_path_with_an_empty_or_dot_part`.
Reference: `lab/capsule-identity/tests/refusals.rs:234` `non_utf8_path_is_refused`.

A passing signature is the name check and grants nothing. The signature is a separate fact from the Runtime's grant.

`lab/capsule-identity/src/lib.rs::verify_checked_signature` checks the DID, the accepted list, the name, and the signature. The body decodes the signer DID, requires that DID as an exact member of the accepted list, checks the name, and verifies the signature. Ok(()) means all four passed. Reference: `lab/capsule-identity/src/lib.rs:1428`.

`lab/capsule-identity/src/lib.rs:1425` states that this result is not a trust, admission or launch.

    /// `Ok(())` means all four passed. It is not a trust, admission or launch
    /// value. A wrong key, a changed signature and a name moved onto other bytes
    /// all fail step 4 with one reason.

The capsule-identity README states M1 check B1. `lab/capsule-identity/README.md:946` states that a valid signature grants nothing by itself. This section cites that statement.

    The rule: a valid signature grants nothing by itself. A bundle whose test-key
    signature verifies is still not admitted, and it gets no grant. This library
    checks identity only, and it sits in no Runtime admission or launch path; the
    lab's stand-in launcher, in test code, calls it
    ([below](#lab-stand-in-launcher-m1-check-b1)).

Reference: `lab/capsule-identity/tests/name_signature.rs:135` `checked_signature_judges_the_checked_bytes`.

This citation is design input for A3. `lab/capsule-identity/src/lib.rs::package_record_payload` is the only builder of the bytes the package-record signature covers. Those bytes are compact JSON, keys in this order, no spaces and no trailing newline: cid, schema `lab.capsule-identity.record/v1`, and signer_did. The signature is not in them, and there is no name field. sign_package_record sets the signature over package_record_message of that payload and writes no file. `lab/capsule-identity/src/lib.rs::verify_checked_package_record` decodes the signer DID, requires that DID in the accepted list, checks the record cid, hashes package_record_message, and verifies the signature. Ok(()) means all four passed. It is not a trust, admission, or launch value, and it grants nothing. This package record is the lab reference model, and the lab model is not the Runtime. This paragraph does not answer the agent DID question. A3 stays open. Reference: `lab/capsule-identity/tests/package_record.rs:93` `package_record_binds_the_cid_and_verifies`.

Reference: `lab/capsule-identity/tests/package_record.rs:160` `record_signed_under_the_wrong_domain_is_refused`.

This citation is design input for A3. `lab/capsule-identity/src/lib.rs::variant_binding_payload` is the only builder of the bytes the variant-binding signature covers, and the one place the pairs are sorted by platform label. Those bytes are compact JSON, keys in this order, no spaces and no trailing newline: recipe, schema `lab.capsule-identity.variant-binding/v1`, signer_did, and variants. Each variant object has cid then platform. The signature is not in them, and there is no name or group identity field. sign_variant_binding sets the signature over variant_binding_message of that payload and writes no file. `lab/capsule-identity/src/lib.rs::verify_checked_variant_binding` decodes the signer DID, requires that DID in the accepted list, checks the binding shape and the given shape, checks that the platforms match, checks each variant CID, checks that a wasm bundle is bound only under the portable label, checks the recipe CID, and verifies the signature. Ok(()) means all eight passed. It is not a trust, admission, or launch value, and it grants nothing. Each label is the signer's claim. No check reads a label from a manifest, a path, or the payload. This variant binding is the lab reference model, and the lab model is not the Runtime. This paragraph does not answer the agent DID question. A3 stays open. Reference: `lab/capsule-identity/tests/variant_binding.rs:280` `variant_binding_binds_each_variant_cid_and_verifies`.

Reference: `lab/capsule-identity/tests/variant_binding.rs:699` `variant_binding_stays_outside_the_bundles`.
Reference: `lab/capsule-identity/tests/variant_binding.rs:476` `variant_binding_signed_under_another_domain_is_refused`.

The asks file is the declaration and the Runtime enforces each grant.

`examples/agent-host/src/lib.rs:8149` states that the Runtime enforces each grant. The declared per-step asks are compiled in from asks.json. That file is an auditable declaration.

    /// The declared per-step asks, compiled in from `asks.json` in this lane. The
    /// file is an auditable declaration, not the policy check: the Runtime
    /// enforces each grant (P4, P18). It is a lane-local stand-in for the Runtime
    /// manifest and retires into that one place when the Runtime defines per-step
    /// asks (P10). It is read by this module's tests only, so the shipped guest
    /// keeps no new production path.
    #[cfg(test)]
    const ASKS_JSON: &str = include_str!("../asks.json");

The guest denies a step with no grant id and does not mint one.

`examples/agent-host/src/lib.rs::authorize` denies the step when the grant id is missing. `examples/agent-host/src/lib.rs:3526` states that a missing grant denies the step. A missing or empty grant sets the step to Denied and stores no grant. A grant id is recorded and does not run the step.

    /// A missing grant denies the step. A grant id is recorded and does not run it.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn authorize(journal: &mut Journal, id: u64, grant: Option<&str>) -> bool {
        let Some(step) = journal.steps.iter_mut().find(|step| step.id == id) else {
            return false;
        };
        if step.state != StepState::Prepared {
            return false;
        }
        match grant {
            None | Some("") => {
                step.state = StepState::Denied;
                step.grant = None;
                false
            }
            Some(grant_id) => {
                step.grant = Some(grant_id.to_string());
                true
            }
        }
    }

`examples/agent-host/src/lib.rs:3549` states that the guest does not mint one. Allow once, allow for the session, and standing all fail closed when no grant id was sent.

    /// An inbox answer. Allow once, allow for the session, and standing all fail
    /// closed when no grant id was sent. The guest does not mint one. Deny stores
    /// no grant. A second answer does not replace the first, and it does not
    /// authorize another step. A child cannot be answered with the parent's
    /// grant. The answer name is kept in the log. The grant string is not.

Reference: `lab/capsule-identity/tests/package_record.rs:117` `package_record_stays_outside_the_bundle`.
Reference: `lab/capsule-identity/tests/package_record.rs:236` `checked_record_judges_the_checked_bytes`.
Reference: `lab/capsule-identity/tests/location.rs:83` `moving_the_bundle_to_another_parent_keeps_the_lab_cid`.
Reference: `lab/capsule-identity/tests/walk.rs:139` `entry_swapped_after_its_handle_is_checked_names_the_checked_bytes`.
Reference: `lab/capsule-identity/tests/walk.rs:156` `checked_entries_are_the_bytes_the_walk_checked`.
Reference: `lab/capsule-identity/tests/walk.rs:194` `folder_swapped_after_its_handle_is_checked_names_the_checked_bytes`.

## 3. Grant requests and A5 binding
This section is design input for A5. A5 stays open.

The verified agent identity is who the launch runs as. The grant is the Runtime's admission of one step. A budget stays a separate Runtime decision.

For the agent identity, a capability request calls `scope_current_user_alias` with `BridgeContext.principal_id` (`elastos/crates/elastos-server/src/resource_bridge.rs:42-43`) before the pending request is stored. The identity host reports that same `principal_id`.

`elastos/crates/elastos-server/src/resource_bridge.rs:43` is the `principal_id` field on `BridgeContext`. The field holds the Runtime principal used to resolve a capsule-facing `Users/self` alias.

`elastos/crates/elastos-server/src/resource_bridge.rs:925` is the call in `handle_request`. The body handles a `request_capability` request. It calls `scope_current_user_alias` with the requested resource and `ctx.principal_id.as_deref()`. When the call returns an error, the body returns `principal_context_required` before it stores a pending request. When the call returns a name, the body runs `agents_area_capability_refusal`, parses the action, runs the wallet check, and runs the manifest check on that name. The body stores a pending request only after those checks pass, and the stored resource is the returned name.

`elastos/crates/elastos-compute/src/providers/component.rs:350` is the identity host `context`. The body returns an `IdentityContext` whose `principal` is `self.principal_id.clone()`.

    impl elastos::bus::identity::Host for ComponentState {
        fn context(&mut self) -> elastos::bus::types::IdentityContext {
            elastos::bus::types::IdentityContext {
                principal: self.principal_id.clone(),
                capsule: self.capsule_id.clone(),
                session: self.capsule_id.clone(),
                device: None,
            }
        }
    }

For the session, the pending request's session id is the bridge capsule id. The identity host copies `capsule_id` into `session`. A status read of another session is refused. The shell grant passes `request.session_id` (`elastos/crates/elastos-server/src/resource_bridge.rs:984-985`) into `grant`.

`elastos/crates/elastos-server/src/resource_bridge.rs:984` is the session id stored by that same `handle_request` body. The body builds a resource id from the scoped name and calls `create_request_with_reason`. The session argument is `SessionId` of `ctx.capsule_id.clone()`.

`elastos/crates/elastos-compute/src/providers/component.rs:352` is the `session` field in that same `context` body. The body sets `session` to `self.capsule_id.clone()`.

This citation is design input for resident A3. The `start` body sets the activation running, starts the host call, and removes the activation when the run finishes, whether that run succeeded, failed, or panicked. `elastos/crates/elastos-compute/src/providers/component.rs:218` is that removal.
            self.instances.write().await.remove(&handle.id);

`elastos/crates/elastos-compute/src/providers/component.rs:232` is the contract error that `elastos/crates/elastos-compute/src/providers/component.rs::stop` returns for a running activation. That body reads the stored status and returns that error when the activation is running. It does not stop that activation, so a running activation keeps running until its run finishes.
                    "component/v1 is a bounded activation contract and has no resident stop operation"

`elastos/wit/elastos-bus-v1.wit:87` is the one export the capsule kernel provides. The capsule exports `lifecycle.run`, and that export returns one result.
      run: func() -> result<_, bus-error>;

Resident A3 credit depends on the RA-6 path. `lab/agent-conformance/standin-runtime/mod.rs::delete_capsule` is that path's stop: it stops one resident instance and revokes that instance's live grants. The stand-in is the lab path, and the lab path is not the Runtime. A3 stays open. Reference: `lab/agent-conformance/standin-runtime/mod.rs:689`.

`elastos/crates/elastos-server/src/api/handlers/capability.rs:182` is the refusal in `request_status`. The body loads the pending request by id. When `request.session_id` differs from the caller session id, the body returns Forbidden and the text Cannot access another session's request. Otherwise the body returns that request's status.

`elastos/crates/elastos-server/src/api/handlers/capability.rs:339` is the comment on the shell grant. `elastos/crates/elastos-server/src/api/handlers/capability.rs:341` is the capsule id passed into `grant`. `grant_request` loads the pending request, requires it to be pending, and calls `capability_manager.grant`. The capsule id argument is `request.session_id.to_string()`. The resource argument is `request.resource`. The body then marks that pending request granted with the token `grant` returns.

For the capsule instance, `grant` stores its capsule id argument on the token. `validate` refuses a caller whose capsule id differs, and `test_wrong_capsule` shows that refusal. The component invoke passes `BridgeContext.capsule_id` (`elastos/crates/elastos-server/src/resource_bridge.rs:40-41`) as that caller. The bridge comment says this field is the capsule identity for token minting, a session id or a capsule name.

`elastos/crates/elastos-server/src/resource_bridge.rs:40` is that comment on `BridgeContext.capsule_id`.

`elastos/crates/elastos-runtime/src/capability/manager.rs:326` is the capsule argument in `grant`. The body passes `capsule_id.to_string()` to `CapabilityToken::new`, signs the token, and returns the token.

`elastos/crates/elastos-runtime/src/capability/token.rs:203` is the token field that holds the capsule id. The field is the capsule that can use the token.

`elastos/crates/elastos-runtime/src/capability/manager.rs:409` is the caller check. `validate` passes the caller capsule id to `validate_recurring`. That body returns WrongCapsule when `token.capsule` differs from `caller_capsule_id`, and it audits the failure as wrong_capsule.

`elastos/crates/elastos-runtime/src/capability/manager.rs::test_wrong_capsule` shows that refusal. The body grants a token for capsule-a, calls `validate` with capsule-b, and requires WrongCapsule. Reference: `elastos/crates/elastos-runtime/src/capability/manager.rs:699`.

`elastos/crates/elastos-server/src/resource_bridge.rs:394` is the caller in `authorize_and_dispatch_resource_invoke`. The body decodes the presented token and calls `validate` with `&bridge_ctx.capsule_id`. When `validate` returns an error, the body denies the invoke with `capability_denied`.

For the owned storage root, the same scope call rewrites `Users/self` onto the principal root before the request is stored, so the resource on the grant is that scoped name. The guest's `JournalGrant` is one id, held in memory, for its own journal. `request_journal_grants` asks write, then read, on that resource.

The body of `scope_current_user_alias`, quoted in section 1, returns the principal root for the `Users/self` alias and that root plus the remainder for a path under the alias. `handle_request` stores that returned string on the pending request. `grant_request` passes the stored resource into `grant`, so the resource on the token is that scoped name.

`examples/agent-host/src/lib.rs:3767` is `JournalGrant`. The comment says it is a grant the Runtime gave this guest for its own journal, one resource and one action, held in memory. `new` stores one non-empty id. `id` returns that string. `Debug` prints the type and does not print the id.

    /// A grant the Runtime gave this guest for its own journal, one resource and
    /// one action. It is held in memory only: the journal format has no field for
    /// it, and `Debug` does not print it.
    #[cfg(any(test, target_arch = "wasm32"))]
    struct JournalGrant(String);

    #[cfg(any(test, target_arch = "wasm32"))]
    impl JournalGrant {
        fn new(id: &str) -> Option<Self> {
            (!id.is_empty()).then(|| Self(id.to_string()))
        }

        fn id(&self) -> &str {
            &self.0
        }
    }

`examples/agent-host/src/lib.rs:3849` asks write. `examples/agent-host/src/lib.rs:3850` asks read. Both lines are in `request_journal_grants`. The body returns empty grants when the resource does not start with the journal root or when `host_path` reports a host path. Otherwise the body asks the bus for write, then read, on `cursor.resource`, and keeps each returned id in a `JournalGrant`. The journal resource sits under `Users/self`.

    /// Ask the Runtime for exactly two grants on this agent's own journal: write,
    /// then read. Nothing else is asked for. A refusal leaves that grant empty, so
    /// nothing is sent with it.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn request_journal_grants(bus: &mut impl ResourceBus, cursor: &JournalCursor) -> JournalGrants {
        if !cursor.resource.starts_with(JOURNAL_ROOT) || host_path(&cursor.resource) {
            return JournalGrants {
                write: None,
                read: None,
            };
        }
        let mut ask = |action: &str| {
            bus.request_grant(&cursor.resource, action, "Agent Host task journal")
                .ok()
                .and_then(|id| JournalGrant::new(&id))
        };
        let write = ask("write");
        let read = ask("read");
        JournalGrants { write, read }
    }

The required binding is a grant bound to the verified agent identity, the session, the capsule instance, and the owned storage root, and a host-side handle bound to the capsule instance and the session. The guest presents a handle. The host binds that handle to the verified agent identity, the session, the capsule instance, and the owned storage root. Identity, session, and instance come from the host record of the handle. `elastos/crates/elastos-compute/src/providers/component.rs:384` sets `CapabilityGrant.id` to the token string. The body of `request` on the capabilities host requires one action, asks the bridge, and returns a `CapabilityGrant` whose id is the token string from that response. `elastos/wit/elastos-bus-v1.wit:10` defines `grant-id` as a string, and the capability-grant record uses that type for its id. The cited functions return the token string as the grant id. The cited functions do not show a separate handle table. A5 stays open.

Reference: `lab/grant-binding/src/lib.rs:421` `model_different_identity_is_refused`.

This citation is design input for A5. For the path check, `lab/grant-binding/src/lib.rs::use_path` resolves the grant, then checks the path against the stored owned root. The guest's claims are not read. The doc line is `Uses a grant for one path.` The body calls resolve, then resource_name. The body lines are `let record = self.resolve(*call, request.handle)?;` and `resource_name(&record.identity, path, Some(&record.owned_root))?;`. The refusal references are `lab/grant-binding/src/lib.rs:975` `model_use_path_dotdot_is_refused`, `lab/grant-binding/src/lib.rs:993` `model_use_path_outside_the_owned_root_is_refused`, `lab/grant-binding/src/lib.rs:1011` `model_symlink_shaped_use_path_is_refused`, and `lab/grant-binding/src/lib.rs:1052` `model_use_path_on_a_sibling_instance_is_refused`. These use-path functions are the lab reference model, and the lab model is not the Runtime. A5 stays open.

Reference: `lab/grant-binding/src/lib.rs:736` `model_public_storage_read_is_refused`.
Reference: `lab/grant-binding/src/lib.rs:573` `model_unknown_handle_is_refused`.
Reference: `lab/grant-binding/src/lib.rs:597` `model_unknown_instance_is_refused`.
Reference: `lab/grant-binding/src/lib.rs:762` `model_public_prefix_is_not_a_public_read`.
Reference: `lab/grant-binding/src/lib.rs:654` `model_host_path_root_is_refused`.
Reference: `lab/grant-binding/src/lib.rs:790` `model_use_path_under_the_owned_root_is_allowed`.
Reference: `lab/grant-binding/src/lib.rs:438` `model_extended_identity_is_refused`.
Reference: `lab/grant-binding/src/lib.rs:488` `model_extended_session_is_refused`.

## 4. Model operations
This section is design input for A4. A4 stays open. This section cites no lab/grant-binding test.

The guest proposes the hosted step. The Runtime's grant admits the call. A budget stays a separate Runtime decision.

The guest proposes. `examples/agent-host/src/lib.rs::propose_hosted` records a hosted step. `examples/agent-host/src/lib.rs:3339` says this does not call a provider. The body stores the resource on a Hosted step when the resource starts with `localhost://`, contains no whitespace, and `host_path` returns false. Every other resource returns the error host path. The guest does not open a model URL.

    /// Record a hosted model proposal. The resource names the model. There is
    /// no secret field. This does not call a provider.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn propose_hosted(journal: &mut Journal, resource: &str) -> Result<u64, &'static str> {
        if !resource.starts_with("localhost://")
            || resource.chars().any(char::is_whitespace)
            || host_path(resource)
        {
            return Err("host path");
        }
        let id = propose_step(journal);
        let step = journal
            .steps
            .iter_mut()
            .find(|step| step.id == id)
            .expect("just pushed");
        step.kind = ProposalKind::Hosted;
        step.resource = resource.to_string();
        Ok(id)
    }

The asks file declares two hosted resources. `examples/agent-host/asks.json:10` declares `Models/`. `examples/agent-host/asks.json:11` declares `<principal>/.AppData/Models/`.

The caller opens the model URL. `capsules/model-provider/src/adapters.rs::effect_request` is the one function that chooses the URL. A present `runtime_socket` uses `RUNTIME_HOSTED_EFFECT_URL`. The other branch uses `direct_url`. `capsules/model-provider/src/adapters.rs:44` sets that constant to `http://runtime.invalid/v1/hosted-effect`. `capsules/model-provider/src/adapters.rs:58` is `RUNTIME_HOSTED_EFFECT_URL`. The `direct_url` arm is `capsules/model-provider/src/adapters.rs:60`. That branch is request construction.

    fn effect_request(
        client: &reqwest::Client,
        method: reqwest::Method,
        direct_url: &str,
        runtime_socket: Option<&str>,
        offer_id: &str,
        run_id: &str,
        request_id: &str,
        effect: &'static str,
    ) -> reqwest::RequestBuilder {
        let url = if runtime_socket.is_some() {
            RUNTIME_HOSTED_EFFECT_URL
        } else {
            direct_url
        };
        let builder = client.request(method, url);
        if runtime_socket.is_some() {
            builder
                .header("x-elastos-offer-id", offer_id)
                .header("x-elastos-run-id", run_id)
                .header("x-elastos-request-id", request_id)
                .header("x-elastos-effect", effect)
        } else {
            builder
        }
    }

The artifact-create worker, `run_http_artifact_create_worker_inner`, calls `require_external_http_containment` before `effect_request`. A production call with no Runtime socket is refused there, and `queued_external_workers_refuse_before_create_status_cancel_or_text_sockets` asserts zero requests in that case. The Runtime hosted transport is the production path. `capsules/model-provider/src/adapters.rs:1670` is `if hosted_socket.is_none() {`. The authorization header is added at `capsules/model-provider/src/adapters.rs:1672`. The bearer is request construction on the `direct_url` branch.

The Runtime names the socket. `capsules/model-provider/src/config.rs:111` says the Runtime-owned hosted HTTPS effect socket carries no provider key. `capsules/model-provider/src/config.rs:113` is the field `runtime_hosted_socket`.

The macOS bridge writes that field into the provider config in `spawn_confined_model_with_engine_bundle`. `elastos/crates/elastos-runtime/src/provider/bridge.rs:774` is that write.

On macOS, apply_local_model_sockets copies the stored hosted socket into the same field. `elastos/crates/elastos-runtime/src/provider/registry.rs:841` is that copy.

`capsules/model-provider/src/adapters.rs:127` is the error in require_external_http_containment: Hosted external HTTPS is paused. On macOS, a present runtime socket returns `Ok(())`. The error arm also says Runtime network authority is not available.

The error arm is this fault.

The Runtime grants the call and carries it. `elastos/crates/elastos-server/src/api/model_provider_egress.rs::handle` calls `create_grant_after_decision` and `current_grant`. `elastos/crates/elastos-server/src/api/model_provider_egress.rs:494` is the `create_grant_after_decision` call. `elastos/crates/elastos-server/src/api/model_provider_egress.rs:503` is the `current_grant` check. An error denies the stream. `elastos/crates/elastos-server/src/api/model_provider_egress.rs:509` calls `forward`, and that call is the carry.

The grant check denies the stream, and `forward` carries the call.

The model service is a separate Runtime path. `elastos/crates/elastos-server/src/api/gateway_model_service.rs:1` calls it the remote model service, the destination side of a `remote_model` grant. `elastos/crates/elastos-server/src/api/gateway_model_service.rs:4` says this Runtime owns the decision and verifies the grant. `elastos/crates/elastos-server/src/api/gateway_model_service.rs:32` names `MODEL_OPERATIONS`. The five strings are `offers_list`, `runs_create`, `runs_get`, `runs_events` and `runs_cancel`.

    //! Remote model service: the destination side of a `remote_model` grant.
    //!
    //! A seed Runtime routes typed model operations over Carrier `provider_invoke`
    //! with target `model`. This Runtime owns the decision. It verifies the grant

`MODEL_OPERATIONS` names the five strings.

"The caller opens the model URL" is the `direct_url` bearer path, and that path is request construction. "The Runtime grants the call and carries it" is the hosted-effect URL, the Runtime socket, the grant check and `forward`. The Runtime hosted transport is the production path. A4 stays open.

## 5. Budgets
This section is design input for A7. A7 stays open.

Identity is who the agent runs as. Admission is the Runtime's permission to execute. Allowance is the usage account. Identity, admission, and allowance stay separate decisions.

The guest keeps no usage total. `examples/agent-host/src/lib.rs::step_payload` writes the step budget fields as zeros. `examples/agent-host/src/lib.rs:471-476` is that write. The comment at the start of the range says "Room for OMP idea 2, empty until it is built". The four zero writes are `out.push(0)`, the slice `[0; 1 + 4 + 8]`, `&0_u32.to_le_bytes()`, and `out.push(0)`. Line 474 is the slice write. Line 476 contains `out.push(0)`.

    fn step_payload(step: &Step) -> Option<Vec<u8>> {
        let mut out = step.id.to_le_bytes().to_vec();
        out.push(state_tag(step.state));
        out.push(kind_tag(step.kind));
        put_str(&mut out, &step.resource)?;
        out.extend_from_slice(&step.effect_id.to_le_bytes());
        out.push(u8::from(step.has_result));
        put_str(&mut out, &step.old)?;
        put_str(&mut out, &step.new)?;
        out.extend_from_slice(&u32::try_from(step.argv.len()).ok()?.to_le_bytes());
        for arg in &step.argv {
            put_str(&mut out, arg)?;
        }
        put_opt(&mut out, step.parent_id);
        put_str(&mut out, &step.seat)?;
        put_opt(&mut out, step.seen_version);
        put_str(&mut out, &step.inbox)?;
        // Room for OMP idea 2, empty until it is built: depth, budget (flag,
        // requests, seconds), requests_used, stop.
        out.push(0);
        out.extend_from_slice(&[0; 1 + 4 + 8]);
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.push(0);
        Some(out)
    }

`examples/agent-host/src/lib.rs::encode_journal` writes the header fields after the cited comment as zeros. `examples/agent-host/src/lib.rs:532` contains `task_budget (flag, requests, seconds)`. The comment says "Room for OMP idea 2, empty until it is built". After that comment the body writes `out.extend_from_slice(&[0; 1 + 8])`, `out.extend_from_slice(&[0; 1 + 4 + 8])`, and `out.push(0)`.

        // Room for OMP idea 2, empty until it is built: cancelled_from (flag and
        // step id), task_budget (flag, requests, seconds), depth.
        out.extend_from_slice(&[0; 1 + 8]);
        out.extend_from_slice(&[0; 1 + 4 + 8]);
        out.push(0);

`examples/agent-host/src/lib.rs::decode_step` returns `Err("record")` when depth, any budget byte, `requests_used`, or stop is non-zero. `examples/agent-host/src/lib.rs:754` contains `requests_used != 0`.

        // OMP idea 2's fields must be empty until it is built.
        let depth = reader.byte().map_err(fail)?;
        let budget = reader.take(1 + 4 + 8).map_err(fail)?;
        let requests_used = reader.u32().map_err(fail)?;
        let stop = reader.byte().map_err(fail)?;
        if depth != 0 || budget.iter().any(|byte| *byte != 0) || requests_used != 0 || stop != 0 {
            return Err("record");
        }

Journal admission is room for run history. On a new run, `capsules/model-provider/src/journal.rs::store_run` refuses when census entries are at `MAX_NEW_JOURNAL_ENTRIES` or charged bytes would pass `MAX_JOURNAL_GROWTH_BYTES`. `capsules/model-provider/src/journal.rs:391-397` holds both comparisons, `usage.entries >= MAX_NEW_JOURNAL_ENTRIES` and `total > MAX_JOURNAL_GROWTH_BYTES`. The cited comment says this check precedes the durable Prepared record and dispatch. The refusal is `capsules/model-provider/src/journal.rs::journal_budget_fault`. `capsules/model-provider/src/journal.rs:921` contains `Model run history is full`. This ceiling is journal room. The else arm is the new run.

            } else {
                let usage = self.visit_census(&census, |_, _, _| Ok(()))?;
                if usage.entries >= MAX_NEW_JOURNAL_ENTRIES
                    || usage
                        .charged_bytes
                        .checked_add(charge)
                        .is_none_or(|total| total > MAX_JOURNAL_GROWTH_BYTES)
                {
                    // This check precedes the durable Prepared record and dispatch.
                    return Err(journal_budget_fault());
                }
            }

    fn journal_budget_fault() -> ProviderFault {
        ProviderFault::policy_limit(
            "Model run history is full. Retained outcomes expire after their history window; then try again.",
            "model run journal admission or growth limit exceeded",
        )
    }

When a run for the request is already stored and the fingerprint matches, `capsules/model-provider/src/state.rs::handle_runs_create` returns that run's view at the cited return. `capsules/model-provider/src/state.rs:530` is `return serialize_run_view(&existing);`. The fingerprint check above that return compares the stored run with the request fingerprint. This return is before `self.adapters.dispatch`.

            // A retained request owns its original result, including legacy IDs and
            // results whose offer has since changed or retired.
            if let Some(mut existing) = self.journal.load_run_if_present(&run_id)? {
                if request_fingerprint(&existing.runtime_binding, &existing.input_hash)? != fingerprint
                {
                    return Err(ProviderFault::invalid_request(
                        "request_id conflicts with an existing model run",
                    ));
                }
                self.project_archived_run(&mut existing)?;
                if !existing.status.is_terminal() {
                    let current_offer = self.current_execution_offer_for_run(&existing)?;
                    self.refresh_run_if_needed(current_offer.as_ref(), &mut existing)?;
                }
                return serialize_run_view(&existing);
            }

For a new run, the same function stores the run, then compares `active_run_count` with `concurrency_limit`, then calls `dispatch`. Those sites, in order, are `self.journal.store_run`, `capsules/model-provider/src/state.rs:609`, and `self.adapters.dispatch`. When the count is above the limit, the body returns the busy view before `dispatch`.

            self.journal.store_run(&run)?;

            let active_runs = self.journal.active_run_count(&offer.id)?;
            if active_runs > offer.policy.concurrency_limit as usize {
                transition_error(
                    &offer,
                    &mut run,
                    RunError {
                        class: ErrorClass::RateLimited,
                        code: "model_busy".to_string(),
                        message: "Model is busy.".to_string(),
                    },
                )?;
                self.journal.store_run(&run)?;
                return serialize_run_view(&run);
            }

            match self.adapters.dispatch(
                &offer.adapter,
                &offer,
                &request.runtime_binding,
                &request.input,
                run.deadline_ms,
            ) {

`capsules/model-provider/src/journal.rs::active_run_count` adds one when the offer matches and `is_terminal` is false. The condition is `run.offer.id == offer_id && !run.status.is_terminal()`. Reference: `capsules/model-provider/src/journal.rs:409`.

`capsules/model-provider/src/contract.rs::is_terminal` is true for Completed, Failed, Cancelled, and SettlementUnknown. `capsules/model-provider/src/contract.rs:134` is the match line. A cancelled run and an uncertain outcome are terminal, so they leave that count.

        pub fn is_terminal(&self) -> bool {
            matches!(
                self,
                Self::Completed | Self::Failed | Self::Cancelled | Self::SettlementUnknown
            )
        }

`elastos/crates/elastos-server/src/api/gateway_model_service.rs::reserve_run_slot` holds one pending key. The doc says the check and the hold happen under the same lock and land in the same index write. `elastos/crates/elastos-server/src/api/gateway_model_service.rs:355` is the pending insert. The inserted value is the time.

    /// Hold one slot for a create, or recognise that the request already has a
    /// record. The check and the hold happen under the same lock and land in the
    /// same index write, so two creates cannot both take the last slot.
    fn reserve_run_slot(
        data_dir: &Path,
        now: u64,
        key: &str,
        grant_id: &str,
        remote_principal_id: &str,
        capsule_id: &str,
        request_id: &str,
    ) -> anyhow::Result<RunSlot> {
        update_run_index(data_dir, now, |index| {
            if let Some((run_id, record)) = index.runs.iter().find(|(_, record)| {
                record.grant_id == grant_id
                    && record.remote_principal_id == remote_principal_id
                    && record_capsule_id(record) == capsule_id
                    && record.request_id == request_id
            }) {
                return Ok(RunSlot::Existing {
                    run_id: run_id.clone(),
                    record: Box::new(record.clone()),
                });
            }
            if index.pending.contains_key(key) {
                anyhow::bail!("model run reservation is already held");
            }
            anyhow::ensure!(
                index.runs.len() + index.pending.len() < MODEL_RUN_INDEX_MAX,
                "model run index is full"
            );
            index.pending.insert(key.to_string(), now);
            Ok(RunSlot::Reserved)
        })

`elastos/crates/elastos-server/src/api/gateway_model_service.rs:1452-1454` says a create holds its record slot before any model work starts, a retry of an already recorded request is answered from that record, and a full index refuses there.

        // A create holds its record slot before any model work starts. A retry of
        // an already recorded request is answered from that record before another
        // create. A full index refuses here.

A reported figure is not a hold, and the required account stays open. `capsules/model-provider/src/journal.rs::validate_backend_usage` returns an error when input tokens, output tokens, and total tokens are all absent. The function body has no ceiling and no subtraction. Reference: `capsules/model-provider/src/journal.rs:1877`.

The account A7 asks for is this account. Admission sets the ceiling. The Runtime reserves a bounded usage amount before each dispatch. The pinned lab shows two concurrent reservations that share one ceiling, it shows an uncertain outcome that keeps the hold, and it holds no test for a retry and none for a cancellation. The contract must add a retry and a cancellation, and the Runtime owns the account that adds them. A due timeout records the uncertainty and keeps the hold, and a measured settle ends the hold. In the pinned timeout test model_timeout_ends_an_uncertain_hold (`lab/grant-binding/src/ledger.rs:1406`) the held total stays 7 with `assert_eq!(after.held, 7);`. The pinned release-after-unknown test model_release_after_unknown_is_refused (`lab/grant-binding/src/ledger.rs:1374`) ends the hold with `.expect("measured settle ends the uncertain hold");`. A reported figure does not lower the hold. The guest writes zeros. The journal check is room for history. The concurrency check counts non-terminal runs. The slot stores a time under one lock. The usage function refuses an empty report. A7 stays open.

This section cites no lab/grant-binding test.

## 6. B2 mapping
This section is design input for B2. B2 stays open.

The proposal is the guest's record of the step. Admission is the Runtime's grant. Allowance is the Runtime's budget.

The asks file declares three file asks. Each resource pattern is `<principal>/`. `examples/agent-host/asks.json:4` declares read. `examples/agent-host/asks.json:5` declares edit. `examples/agent-host/asks.json:6` declares restore.

        {"kind": "read", "resource": "<principal>/"},
        {"kind": "edit", "resource": "<principal>/"},
        {"kind": "restore", "resource": "<principal>/"},

`examples/agent-host/src/lib.rs::ask_kind_name` names Read as `read`, Edit as `edit`, and Restore as `restore`. `examples/agent-host/src/lib.rs:8187` is the Read arm. `examples/agent-host/src/lib.rs:8188` is the Edit arm. `examples/agent-host/src/lib.rs:8190` is the Restore arm.

    /// The declared name of one kind. The match has no wildcard, so a new
    /// `ProposalKind` does not compile until it is named here or marked as the
    /// placeholder. `Unspecified` marks a step opened without a proposal and is
    /// not an ask.
    #[cfg(test)]
    fn ask_kind_name(kind: ProposalKind) -> Option<&'static str> {
        match kind {
            ProposalKind::Unspecified => None,
            ProposalKind::Read => Some("read"),
            ProposalKind::Edit => Some("edit"),
            ProposalKind::Run => Some("run"),
            ProposalKind::Restore => Some("restore"),
            ProposalKind::Hosted => Some("hosted"),
            ProposalKind::Child => Some("child"),
            ProposalKind::Init => Some("init"),
            ProposalKind::JournalAppend => Some("journal-append"),
        }
    }

`examples/agent-host/src/lib.rs::declared_ask` is true when the kind matches and ask_covers is true. `examples/agent-host/src/lib.rs:8488` is that condition. ask_covers applies the declared pattern to the resource. The three patterns are `<principal>/`.

    /// The declaration's answer for one proposal. `Unspecified` matches nothing.
    #[cfg(test)]
    fn declared_ask(kind: ProposalKind, resource: &str) -> bool {
        declared_asks()
            .iter()
            .any(|ask| ask.kind == kind && ask_covers(ask, resource))
    }

Read records a step. `examples/agent-host/src/lib.rs::propose_read` sets the kind to Read and stores the resource. The body has no bus call. Reference: `examples/agent-host/src/lib.rs:2382`.

`examples/agent-host/src/lib.rs::observe` records text the guest already holds. `examples/agent-host/src/lib.rs:2067` ends the doc sentence. That sentence says this does not read a file.

    /// Append a read. A path that `path_refusal` refuses, or the version
    /// u64::MAX, adds nothing. A higher version is a new read. An older version is allowed only when the
    /// text still matches that version, so a reread can make it current again
    /// without replacing the page. This does not start a series and does not
    /// read a file.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn observe(journal: &mut Journal, resource: &str, version: u64, text: &str) -> bool {
        if path_refusal(resource).is_some()
            || version == u64::MAX
            || version_bound_elsewhere(&journal.events, resource, version, None)
        {
            return false;
        }
        if let Some(row) = current_observation(&journal.events, resource) {
            if version <= row.version
                && observed_text_at(&journal.events, resource, version).as_deref() != Some(text)
            {
                return false;
            }
        }
        let epoch = journal.epoch;
        journal
            .events
            .push(observation_record(resource, version, text));
        journal.epoch == epoch
    }

The typed localhost operation `read` maps to `Action::Read` on `elastos/crates/elastos-server/src/provider_resource.rs:189`.

            "read" | "list" | "stat" | "exists" | "resolve" | "ping" => Some(Action::Read),

Edit and restore replace shown text. `examples/agent-host/src/lib.rs::propose_edit` creates no write. `examples/agent-host/src/lib.rs:2421-2422` carries that statement. The start line contains `This does not` and the end line contains `write.`

    /// Record an edit proposal. An unread target, a stale version, empty old
    /// text, old text that is not exactly once in what that version has shown
    /// (a read that showed a window covers only that window), or a no-op edit
    /// repeated past the limit creates no step. A path that is not canonical or
    /// not NFC is refused. Every refusal writes one refusal record. This does not
    /// write.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn propose_edit(
        journal: &mut Journal,
        resource: &str,
        old: &str,
        new: &str,
        seen: Option<u64>,
    ) -> Result<u64, &'static str> {
        let result = propose_edit_checked(journal, resource, old, new, seen);
        result.map_err(|refusal| {
            record_refusal(journal, refusal, &refused_path(resource));
            refusal.reason()
        })
    }

`examples/agent-host/src/lib.rs::propose_restore` records a Restore step. The body sets the kind to Restore and stores the observed text and the version. `bind_change` and `note_change_wrote` belong to later granted dispatch. The body does not call them. `examples/agent-host/src/lib.rs:3308` contains `This does not write.`

    /// Propose restoring an observed version. An unknown version, or a version
    /// that is no longer current, creates no step. The step keeps the observed
    /// text as the text to replace and as the text to write, so a granted
    /// dispatch sends the restore through the same `bind_change` and
    /// `note_change_wrote` path an edit uses. This does not write.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn propose_restore(
        journal: &mut Journal,
        resource: &str,
        version: u64,
    ) -> Result<u64, &'static str> {
        let Some(text) = observed_text_at(&journal.events, resource, version) else {
            return Err("unknown");
        };
        let Some(current) = current_observation(&journal.events, resource) else {
            return Err("unknown");
        };
        if current.version != version {
            return Err("stale");
        }
        let id = propose_step(journal);
        let step = journal
            .steps
            .iter_mut()
            .find(|step| step.id == id)
            .expect("just pushed");
        step.kind = ProposalKind::Restore;
        step.resource = resource.to_string();
        step.old = text.clone();
        step.new = text;
        step.seen_version = Some(version);
        Ok(id)
    }

`examples/agent-host/src/lib.rs::is_write` is true for Edit and Restore. `examples/agent-host/src/lib.rs:3290` is that match.

    #[cfg(any(test, target_arch = "wasm32"))]
    fn is_write(kind: ProposalKind) -> bool {
        matches!(kind, ProposalKind::Edit | ProposalKind::Restore)
    }

`examples/agent-host/src/lib.rs::edit_request` is the one provider request for a change or a restore. `examples/agent-host/src/lib.rs:2720` says that.

    /// The one provider request for a change or a restore: every file, each with
    /// the Runtime revision it was read at (`if_revision`), the lines it may
    /// touch, and the text to replace there. The provider applies all files or
    /// none. A change that does not bind sends nothing and writes one refusal
    /// record.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn edit_request(journal: &mut Journal, effect_id: u64) -> Result<Vec<u8>, &'static str> {
        let result = bind_change(journal, effect_id);
        result.map(|bound| request_body(&bound)).map_err(|refusal| {
            record_refusal(journal, refusal, &format!("change {effect_id}"));
            refusal.reason()
        })
    }

`examples/agent-host/src/lib.rs::request_body` sets `if_revision` to the revision the file was read at, and sets `op` to `edit` with `all_or_none` true. `examples/agent-host/src/lib.rs:2741` is the revision field. `examples/agent-host/src/lib.rs:2749` is the op field. That body replaces shown text under the revision the read carried. The constraint on that replacement is the revision the read carried.

    #[cfg(any(test, target_arch = "wasm32"))]
    fn request_body(bound: &[BoundEdit]) -> Vec<u8> {
        let files: Vec<serde_json::Value> = bound
            .iter()
            .map(|edit| {
                serde_json::json!({
                    "path": edit.resource,
                    "if_revision": edit.revision,
                    "first_line": edit.first_line,
                    "line_count": line_count(&edit.run),
                    "old": edit.old,
                    "new": edit.new,
                })
            })
            .collect();
        serde_json::json!({ "op": "edit", "all_or_none": true, "files": files })
            .to_string()
            .into_bytes()
    }

The typed map is the operation-to-action map. `elastos/crates/elastos-server/src/provider_resource.rs::provider_operation_action` is that map. For scheme `localhost` the arm calls `localhost_op_required_action`. The same arm names webspace. `elastos/crates/elastos-server/src/provider_resource.rs:123` is that arm.

    /// Canonical capability action for provider operations where the Runtime owns
    /// the operation-to-action contract directly.
    pub fn provider_operation_action(scheme: &str, op: &str) -> Option<Action> {
        #[cfg(test)]
        if scheme == "test" {
            return (op == "read").then_some(Action::Read);
        }

        match scheme {
            "localhost" | "webspace" => localhost_op_required_action(op),
            "did" => execute_op_required_action(op),
            "availability" => match op {
                "status" => Some(Action::Read),
                "ensure" => Some(Action::Write),
                _ => None,
            },
            "block-graph" => match op {
                "status" | "export_graph" => Some(Action::Read),
                "import_graph" => Some(Action::Write),
                _ => None,
            },
            "chain" => chain_op_required_action(op),
            "content" => match op {
                "status" | "fetch" => Some(Action::Read),
                "publish" | "ensure" | "repair" | "unpublish" => Some(Action::Write),
                _ => None,
            },
            "drm" | "rights" | "key" | "decrypt" => read_only_provider_action(op),
            "net" => match op {
                "status" | "resolve" => Some(Action::Read),
                "connect" | "stream" | "http" => Some(Action::Write),
                _ => None,
            },
            "exit" => match op {
                "status" | "discover_remote_carrier_exits" | "quote" => Some(Action::Read),
                "open_stream" | "close_stream" | "http_fetch" => Some(Action::Write),
                _ => None,
            },
            "browser-engine" => match op {
                "status" | "readiness" | "page_status" | "diagnostics" | "inspect" => {
                    Some(Action::Read)
                }
                "launch" | "attach_stream" | "input" | "webrtc_signal" => Some(Action::Write),
                "close_page" => Some(Action::Delete),
                _ => None,
            },
            "wallet" => wallet_op_required_action(op),
            "ipfs" => ipfs_op_required_action(op),
            "model" => match op {
                "offers_list" | "runs_get" | "runs_events" => Some(Action::Read),
                "runs_create" | "runs_cancel" => Some(Action::Execute),
                _ => None,
            },
            "object" => object_op_required_action(op),
            "operator-drive-adapter" => match op {
                "status" | "metadata_index" | "read_bytes" => Some(Action::Read),
                "write_bytes" => Some(Action::Write),
                _ => None,
            },
            "peer" => match op {
                "init" | "connect" | "remember_peer" | "gossip_join" | "gossip_leave"
                | "gossip_send" | "get_ticket" | "get_node_id" | "list_peers" | "list_topics"
                | "list_topic_peers" | "gossip_join_peers" | "gossip_recv" => Some(Action::Message),
                _ => None,
            },
            "tunnel" => {
                Some(Action::Admin).filter(|_| matches!(op, "start" | "stop" | "status" | "ping"))
            }
            "inspect" => inspect_op_required_action(op),
            _ => None,
        }
    }

`elastos/crates/elastos-server/src/provider_resource.rs::localhost_op_required_action` maps the read group to `Action::Read`, `write` and `mkdir` to `Action::Write`, and `delete` to `Action::Delete`. An unmatched name maps to `None`. `elastos/crates/elastos-server/src/provider_resource.rs:190` is the write arm. `elastos/crates/elastos-server/src/provider_resource.rs:192` is the unmatched arm. The read group is the arm cited above. The delete arm, on line 191 of that file, maps `delete` to `Action::Delete`.

    fn localhost_op_required_action(op: &str) -> Option<Action> {
        match op {
            "read" | "list" | "stat" | "exists" | "resolve" | "ping" => Some(Action::Read),
            "write" | "mkdir" => Some(Action::Write),
            "delete" => Some(Action::Delete),
            _ => None,
        }
    }

localhost_resource holds the supported-operation list. `elastos/crates/elastos-server/src/provider_resource.rs:422` is that list: `read`, `write`, `list`, `delete`, `stat`, `mkdir`, `exists`, `resolve`, `ping`.

                "read", "write", "list", "delete", "stat", "mkdir", "exists", "resolve", "ping",

The extension B2 leaves open is the guest body's operation. The guest body carries `op` `edit`. A typed localhost operation for that body is a name on that list and on a match arm. B2 stays open.

This group is design input for B2. B2 stays open.

The asks file declares three project asks. Each resource pattern is `<principal>/Projects/`. `examples/agent-host/asks.json:7` declares run. `examples/agent-host/asks.json:8` declares child. `examples/agent-host/asks.json:9` declares init.

        {"kind": "run", "resource": "<principal>/Projects/"},
        {"kind": "child", "resource": "<principal>/Projects/"},
        {"kind": "init", "resource": "<principal>/Projects/"},

ask_kind_name names Run as `run`, Child as `child`, and Init as `init`. `examples/agent-host/src/lib.rs:8189` is the Run arm.

            ProposalKind::Run => Some("run"),

`examples/agent-host/src/lib.rs:8192` is the Child arm.

            ProposalKind::Child => Some("child"),

`examples/agent-host/src/lib.rs:8193` is the Init arm.

            ProposalKind::Init => Some("init"),

declared_ask is true when the kind matches and ask_covers is true. ask_covers applies the declared pattern to the resource. The three patterns are `<principal>/Projects/`.

Run records a step. `examples/agent-host/src/lib.rs::propose_run` sets the kind to Run, stores the resource and the argv, and sets the seat to `microvm`. The body sets `step.kind = ProposalKind::Run`, `step.resource = resource.to_string()`, `step.argv = argv.to_vec()`, and `step.seat = "microvm".to_string();`. The body returns `Err("host path")` when the resource does not start with `localhost://`, when the resource contains whitespace, or when the resource or an argument is a host path. `examples/agent-host/src/lib.rs:2958` says `This does not start a process.` `examples/agent-host/src/lib.rs:2981` is the seat line.

    /// Record a run proposal. The resource is a `localhost://` project. Arguments
    /// stay data. A host path creates no step. This does not start a process.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn propose_run(
        journal: &mut Journal,
        resource: &str,
        argv: &[String],
    ) -> Result<u64, &'static str> {
        if !resource.starts_with("localhost://")
            || resource.chars().any(char::is_whitespace)
            || host_path(resource)
            || argv.iter().any(|arg| host_path(arg))
        {
            return Err("host path");
        }
        let id = propose_step(journal);
        let step = journal
            .steps
            .iter_mut()
            .find(|step| step.id == id)
            .expect("just pushed");
        step.kind = ProposalKind::Run;
        step.resource = resource.to_string();
        step.argv = argv.to_vec();
        step.seat = "microvm".to_string();
        Ok(id)
    }

`elastos/crates/elastos-compute/src/exec_vm.rs::decide_exec` returns `Refuse("missing grant")` when the grant is missing or empty. `elastos/crates/elastos-compute/src/exec_vm.rs:49` is that return. `elastos/crates/elastos-compute/src/exec_vm.rs:43` says `A ready decision still does not boot.`

    /// Refuse a missing grant, a cancel, a host path, a missing Linux rootfs,
    /// or a host that has no adapter. A ready decision still does not boot.
    pub fn decide_exec(request: &ExecRequest<'_>) -> ExecDecision {
        if request.cancelled {
            return ExecDecision::Refuse("cancelled");
        }
        if request.grant.is_none_or(|grant| grant.is_empty()) {
            return ExecDecision::Refuse("missing grant");
        }
        if !request.workspace.starts_with("localhost://")
            || request.workspace.chars().any(char::is_whitespace)
            || host_path(request.workspace)
        {
            return ExecDecision::Refuse("host path");
        }
        if request.argv.is_empty() || request.argv.iter().any(|arg| host_path(arg)) {
            return ExecDecision::Refuse("host path");
        }
        if request.rootfs.file_name().and_then(|name| name.to_str()) != Some("rootfs.ext4")
            || !request.rootfs.is_file()
        {
            return ExecDecision::Refuse("rootfs missing");
        }
        match request.host {
            ExecHost::Macos => ExecDecision::Admit {
                adapter: ExecAdapter::AppleVirtualization,
            },
            ExecHost::Linux => ExecDecision::Admit {
                adapter: ExecAdapter::Crosvm,
            },
            ExecHost::Other => ExecDecision::Refuse("unsupported host"),
        }
    }

`elastos/crates/elastos-compute/src/exec_vm.rs::admit_project_files` splits the workspace at `/Projects/`. `elastos/crates/elastos-compute/src/exec_vm.rs:130` is that `split_once` line. Its doc says a workspace other than `localhost://Users/<root>/Projects/<name>` is refused, and the function copies no directory from the host.

    /// Files that may be placed in the machine for one project. Paths stay
    /// relative. A host path, a `..` segment, or a workspace that is not
    /// `localhost://Users/<root>/Projects/<name>` is refused. This does not copy
    /// a directory from the host.
    pub fn admit_project_files(workspace: &str, files: &[(&str, &str)]) -> Result<(), &'static str> {
        let Some(rest) = workspace.strip_prefix("localhost://Users/") else {
            return Err("host path");
        };
        let Some((root, name)) = rest.split_once("/Projects/") else {
            return Err("host path");
        };
        if root.is_empty()
            || name.is_empty()
            || root.contains('/')
            || name.contains('/')
            || root.contains('\\')
            || name.contains('\\')
            || host_path(workspace)
            || host_path(root)
            || host_path(name)
            || workspace.chars().any(char::is_whitespace)
            || files.is_empty()
        {
            return Err("host path");
        }
        for (path, text) in files {
            if path.is_empty()
                || path.starts_with('/')
                || host_path(path)
                || path.chars().any(char::is_whitespace)
                || path
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
            {
                return Err("host path");
            }
            if host_path(text) {
                return Err("host path");
            }
        }
        Ok(())
    }

decide_exec and admit_project_files are the checks in exec_vm.rs. provider_operation_action is the operation-to-action map. For the localhost scheme that map calls localhost_op_required_action. The typed localhost operation list is the one section 6 already quoted. A typed operation for this ask is a name on that list and on a match arm.

A child copies no parent grant, and the child host is a second journal. `examples/agent-host/src/lib.rs::propose_child` calls narrower_resource. `examples/agent-host/src/lib.rs:3360` says `It does not copy the parent's grant.` `examples/agent-host/src/lib.rs:3370` is that call. The step sets `step.grant = None`. `examples/agent-host/src/lib.rs:3382` is that store.

    /// A child is a separate step. Its resource must sit under the parent's
    /// resource. It does not copy the parent's grant.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn propose_child(
        journal: &mut Journal,
        parent_id: u64,
        resource: &str,
    ) -> Result<u64, &'static str> {
        let Some(parent) = journal.steps.iter().find(|step| step.id == parent_id) else {
            return Err("no parent");
        };
        if parent.resource.is_empty() || !narrower_resource(&parent.resource, resource) {
            return Err("not a subset");
        }
        let id = propose_step(journal);
        let step = journal
            .steps
            .iter_mut()
            .find(|step| step.id == id)
            .expect("just pushed");
        step.kind = ProposalKind::Child;
        step.resource = resource.to_string();
        step.parent_id = Some(parent_id);
        step.grant = None;
        Ok(id)
    }

`examples/agent-host/src/lib.rs::authorize_child` returns false when no step has the child id, when that step is not a Child step, or when the offered grant is absent, empty, or equal to the parent grant. An empty grant unequal to the parent grant still returns false. The function calls authorize only after it finds a Child step and that grant guard passes. `examples/agent-host/src/lib.rs:3449` is the comparison `parent_grant.as_deref() == grant`.

    /// Give a child its own grant. The parent's grant string is refused, and the
    /// child stays prepared. This does not start a process.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn authorize_child(journal: &mut Journal, child_id: u64, grant: Option<&str>) -> bool {
        let Some(child) = journal.steps.iter().find(|step| step.id == child_id) else {
            return false;
        };
        if child.kind != ProposalKind::Child {
            return false;
        }
        let parent_grant = child.parent_id.and_then(|parent_id| {
            journal
                .steps
                .iter()
                .find(|step| step.id == parent_id)
                .and_then(|step| step.grant.clone())
        });
        if grant.is_none() || grant == Some("") || parent_grant.as_deref() == grant {
            return false;
        }
        authorize(journal, child_id, grant)
    }

`examples/agent-host/src/lib.rs::open_child_host` starts from empty_journal, calls admit_system with SYSTEM_HEAD, calls propose_run on that journal, and returns `Err("inherited")` when any step has a grant. `examples/agent-host/src/lib.rs:3455` says `A child host is a second journal.` `examples/agent-host/src/lib.rs:3470` is the empty_journal line. `examples/agent-host/src/lib.rs:3471` is the admit_system line.

    /// A child host is a second journal. It keeps the system head and does not
    /// copy the parent's log or the parent's grant. This is not a second loaded
    /// component, and it does not start a process.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn open_child_host(
        parent: &Journal,
        parent_id: u64,
        resource: &str,
    ) -> Result<Journal, &'static str> {
        let Some(parent_step) = parent.steps.iter().find(|step| step.id == parent_id) else {
            return Err("no parent");
        };
        if parent_step.resource.is_empty() || !narrower_resource(&parent_step.resource, resource) {
            return Err("not a subset");
        }
        let mut child = empty_journal();
        admit_system(&mut child, SYSTEM_HEAD, true);

The body calls propose_run on that journal. `examples/agent-host/src/lib.rs:3474` is the inherited line.

        if child.steps.iter().any(|step| step.grant.is_some()) {
            return Err("inherited");
        }
        Ok(child)
    }

`examples/agent-host/src/lib.rs::grant_child_host` returns false when the offered grant is absent, empty, or equal to the parent grant. An empty grant unequal to the parent grant still returns false. When the guard passes, the function looks for a prepared Run step that has no grant. It returns false when no such step exists. When that step exists, the function calls authorize. `examples/agent-host/src/lib.rs:3482` is the comparison `grant == parent_grant`.

    /// Give the child host its own grant. The parent's grant is refused.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn grant_child_host(child: &mut Journal, parent_grant: Option<&str>, grant: Option<&str>) -> bool {
        if grant.is_none() || grant == Some("") || grant == parent_grant {
            return false;
        }
        let Some(id) = child
            .steps
            .iter()
            .find(|step| {
                step.kind == ProposalKind::Run
                    && step.grant.is_none()
                    && step.state == StepState::Prepared
            })
            .map(|step| step.id)
        else {
            return false;
        };
        authorize(child, id, grant)
    }

This second journal is the child-journal operation the guest keeps: its own head, its own run step, and its own grant.

Init stores a project resource. `examples/agent-host/src/lib.rs::propose_init` builds `localhost://Users/{root}/Projects/{name}` and stores that resource. `examples/agent-host/src/lib.rs:3403` is that format. `examples/agent-host/src/lib.rs:3387` says `A host path or a slash inside the root or the name creates no step.` The body has no bus call.

    /// Record a project proposal. The resource is a `localhost://` project name.
    /// A host path or a slash inside the root or the name creates no step.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn propose_init(journal: &mut Journal, root: &str, name: &str) -> Result<u64, &'static str> {
        if root.is_empty()
            || name.is_empty()
            || root
                .chars()
                .any(|ch| ch.is_whitespace() || ch == '/' || ch == '\\')
            || name
                .chars()
                .any(|ch| ch.is_whitespace() || ch == '/' || ch == '\\')
            || host_path(root)
            || host_path(name)
        {
            return Err("host path");
        }
        let resource = format!("localhost://Users/{root}/Projects/{name}");
        let id = propose_step(journal);
        let step = journal
            .steps
            .iter_mut()
            .find(|step| step.id == id)
            .expect("just pushed");
        step.kind = ProposalKind::Init;
        step.resource = resource;
        Ok(id)
    }

On the peer scheme, provider_operation_action maps the operation `init` to `Action::Message`. `elastos/crates/elastos-server/src/provider_resource.rs:174` is the `init` alternative. `elastos/crates/elastos-server/src/provider_resource.rs:176` is the `Action::Message` arm.

            "peer" => match op {
                "init" | "connect" | "remember_peer" | "gossip_join" | "gossip_leave"
                | "gossip_send" | "get_ticket" | "get_node_id" | "list_peers" | "list_topics"
                | "list_topic_peers" | "gossip_join_peers" | "gossip_recv" => Some(Action::Message),
                _ => None,
            },

The project ask is the resource propose_init stores. The contract must be extended for a typed operation for run, for child, and for init.

The two hosted asks point at section 4. ask_kind_name names Hosted as `hosted`. `examples/agent-host/src/lib.rs:8191` is that match arm.

            ProposalKind::Hosted => Some("hosted"),

The two resources are `Models/` and `<principal>/.AppData/Models/`. propose_hosted records the hosted step. declared_ask is true when the kind matches and ask_covers is true. ask_covers applies the declared pattern to the resource. Section 4 already maps those asks: the guest records a hosted step and the Runtime grants the call and carries it. The hosted rows point at section 4 and do not restate it.

On the `model` scheme, provider_operation_action maps `offers_list`, `runs_get`, and `runs_events` to `Action::Read`, and `runs_create` and `runs_cancel` to `Action::Execute`. `elastos/crates/elastos-server/src/provider_resource.rs:163` is the read arm. `elastos/crates/elastos-server/src/provider_resource.rs:164` is the execute arm. `elastos/crates/elastos-server/src/provider_resource.rs:165` is the `_ => None` that closes the model match. MODEL_OPERATIONS names those five strings. Section 4 names those five strings. The ask name is `hosted`. localhost_resource holds the supported-operation list. localhost_op_required_action maps a name on that list to an action. The localhost operation list section 6 already quoted has no `hosted`.

                "offers_list" | "runs_get" | "runs_events" => Some(Action::Read),
                "runs_create" | "runs_cancel" => Some(Action::Execute),
                _ => None,

The journal-append ask writes the whole encoding. `examples/agent-host/asks.json:12` is that row.

        {"kind": "journal-append", "resource": "<principal>/.AppData/Agents/agent-host/"}

ask_kind_name names JournalAppend as `journal-append`. `examples/agent-host/src/lib.rs:8194` is that match arm. declared_ask is true when the kind matches and ask_covers is true. ask_covers applies the declared pattern to the resource. The pattern is `<principal>/.AppData/Agents/agent-host/`.

            ProposalKind::JournalAppend => Some("journal-append"),

journal_write_body puts the whole encoding in `content`. A missing revision sets `create_only` true. A present revision sets `if_revision`. `examples/agent-host/src/lib.rs::journal_write_body` is that function. `examples/agent-host/src/lib.rs:3961` is the doc line. `examples/agent-host/src/lib.rs:3966` is the missing-revision arm. `examples/agent-host/src/lib.rs:3967` is the present-revision arm.

    /// The write body the Runtime bridge reads: the whole encoding as `content`,
    /// and `create_only` for the first version or `if_revision` after that.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn journal_write_body(bytes: &[u8], revision: Option<&str>) -> Vec<u8> {
        let body = match revision {
            None => serde_json::json!({ "content": bytes, "create_only": true }),
            Some(revision) => serde_json::json!({ "content": bytes, "if_revision": revision }),
        };
        body.to_string().into_bytes()
    }

append_journal calls propose_journal_append, and that call's error returns `AppendOutcome::Held`. `examples/agent-host/src/lib.rs::append_journal` is that function. `examples/agent-host/src/lib.rs:4023` is the doc line: no grant, an open append, or a journal over the cap sends nothing. `examples/agent-host/src/lib.rs:4032-4033` is the call and the held return. The invoke uses the operation `write` and passes the grant id. `examples/agent-host/src/lib.rs:4061` is that invoke.

    /// Write the whole journal as the next version, with the journal write grant.
    /// No grant, an open append, or a journal over the cap sends nothing. The
    /// stored copy shows this step as dispatched with no result.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn append_journal(
        bus: &mut impl ResourceBus,
        journal: &mut Journal,
        cursor: &mut JournalCursor,
        grant: Option<&JournalGrant>,
    ) -> AppendOutcome {
        let Ok(id) = propose_journal_append(journal, cursor) else {
            return AppendOutcome::Held;
        };

        let reply = bus.invoke(&cursor.resource, "write", &body, grant.id());

propose_journal_append returns host path when the resource fails the JOURNAL_ROOT check. `examples/agent-host/src/lib.rs::propose_journal_append` is that function. `examples/agent-host/src/lib.rs:3935` is the condition. `examples/agent-host/src/lib.rs:3936` is that return. The condition uses JOURNAL_ROOT and host_path. It returns held when the cursor is pending, the cursor is stale, or `open` is true. `open` is a JournalAppend step with no result in Prepared, Dispatched, or SettlementUnknown. `examples/agent-host/src/lib.rs:3947` is the held return. journal_write_body sends the whole encoding with create_only or if_revision, and append_journal invokes write.

    /// An append records a step. It waits while an earlier append has no result,
    /// so a lost reply is never followed by a second write.
    #[cfg(any(test, target_arch = "wasm32"))]
    fn propose_journal_append(
        journal: &mut Journal,
        cursor: &JournalCursor,
    ) -> Result<u64, &'static str> {
        if !cursor.resource.starts_with(JOURNAL_ROOT) || host_path(&cursor.resource) {
            return Err("host path");
        }
        let open = journal.steps.iter().any(|step| {
            step.kind == ProposalKind::JournalAppend
                && !step.has_result
                && matches!(
                    step.state,
                    StepState::Prepared | StepState::Dispatched | StepState::SettlementUnknown
                )
        });
        if cursor.pending.is_some() || cursor.stale || open {
            return Err("held");
        }
        let id = propose_step(journal);
        let step = journal
            .steps
            .iter_mut()
            .find(|step| step.id == id)
            .expect("just pushed");
        step.kind = ProposalKind::JournalAppend;
        step.resource = cursor.resource.clone();
        step.old = cursor.revision.clone().unwrap_or_default();
        Ok(id)
    }

Today's checks on an agent journal. agents_area_refusal allows `read` and `write` under `.AppData/Agents/`. `elastos/crates/elastos-server/src/provider_resource.rs::agents_area_refusal` is that function. `elastos/crates/elastos-server/src/provider_resource.rs:379` is the match. `elastos/crates/elastos-server/src/provider_resource.rs:382` is the message. agent_path_refusal calls agents_area_refusal. protected_principal_root_resource_response holds the write arm for a principal-root object.

    pub(crate) fn agents_area_refusal(
        rooted: &str,
        operation: &str,
    ) -> Option<(&'static str, &'static str)> {
        if !in_agents_area(rooted) {
            return None;
        }
        if !matches!(operation, "read" | "write") {
            return Some((
                "operation_not_allowed",
                "only read and write are allowed under .AppData/Agents/",
            ));
        }

write_precondition returns an error when `create_only` and `if_revision` are both set, `WritePrecondition::Absent` when only `create_only` is set, `WritePrecondition::Revision` when only `if_revision` is set, and `None` when neither is set. `elastos/crates/elastos-server/src/resource_bridge.rs::write_precondition` is that function. `elastos/crates/elastos-server/src/resource_bridge.rs:696` is the error arm. `elastos/crates/elastos-server/src/resource_bridge.rs:697` is the absent arm. `elastos/crates/elastos-server/src/resource_bridge.rs:698` is the revision arm. `elastos/crates/elastos-server/src/resource_bridge.rs:699` is the none arm.

    fn write_precondition(request: &serde_json::Value) -> Result<Option<WritePrecondition>, String> {
        let create_only = match request.get("create_only") {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::Bool(value)) => *value,
            Some(_) => return Err("create_only must be a boolean".to_string()),
        };
        let if_revision = match request.get("if_revision") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(value)) if !value.is_empty() => Some(value.clone()),
            Some(_) => return Err("if_revision must be a non-empty string".to_string()),
        };
        match (create_only, if_revision) {
            (true, Some(_)) => Err("create_only and if_revision cannot both be set".to_string()),
            (true, None) => Ok(Some(WritePrecondition::Absent)),
            (false, Some(revision)) => Ok(Some(WritePrecondition::Revision(revision))),
            (false, None) => Ok(None),
        }
    }

In the write arm of protected_principal_root_resource_response, an agent journal whose request has the append flag returns `append_not_allowed`. `elastos/crates/elastos-server/src/resource_bridge.rs:570` is that code. `elastos/crates/elastos-server/src/resource_bridge.rs:571` is the message that agent journals are written whole with a revision precondition.

                if agent_journal && append {
                    return Some(resource_error_response(
                        "append_not_allowed",
                        "append is read-then-write; Agent journals are written whole with a revision precondition",
                    ));
                }

An agent journal with no precondition returns `revision_required`. `elastos/crates/elastos-server/src/resource_bridge.rs:582` is that code. `elastos/crates/elastos-server/src/resource_bridge.rs:583` is the message that agent journal writes need `create_only` or `if_revision`.

                if agent_journal && precondition.is_none() {
                    return Some(resource_error_response(
                        "revision_required",
                        "Agent journal writes need create_only or if_revision",
                    ));
                }

When the append flag is false, the bytes are `content.clone()`. `elastos/crates/elastos-server/src/resource_bridge.rs:603` is that line.

                    content.clone()

A precondition that is present calls `write_principal_root_object_if_revision`. `elastos/crates/elastos-server/src/resource_bridge.rs:606` is that call.

                    Some(precondition) => crate::auth::write_principal_root_object_if_revision(

The guest ask is `journal-append`. The invoked operation is `write`, which is on the localhost list section 6 already quoted, and that list's `write` arm maps to `Action::Write` (`elastos/crates/elastos-server/src/provider_resource.rs:189-190`). The body is the whole encoding. The bridge refuses the append flag on an agent journal and stores `content.clone()` (`elastos/crates/elastos-server/src/resource_bridge.rs:602-603`) when that flag is false. Today's checks write the whole journal under create_only or if_revision, and they refuse append on an agent journal. The child-journal operation stays the second journal in the project-ask paragraphs. The contract must be extended for a typed operation named hosted, and for a typed operation that names journal-append apart from write. Every ask in the asks file is mapped in this section.

This citation is design input for B2. `lab/grant-binding/src/ops.rs::create_child_journal` calls operate with ChildJournal, checks the path with resource_name against the stored owned root, and returns bind_grant of that path. The fn line is `pub fn create_child_journal(`. The operate line is `self.operate(call, request, Operation::ChildJournal)?;`. The path check is `super::resource_name(&grant.identity, path, Some(&grant.owned_root))`. The return is `self.bind_grant(grant.instance, path, grant.rights)`. The doc line reads: The new handle is `bind_grant` of that path. The test references are `lab/grant-binding/src/ops.rs:425` `model_child_journal_create_without_the_right_is_refused` and `lab/grant-binding/src/ops.rs:540` `model_child_journal_returns_its_own_handle`. These create-child-journal functions are the lab reference model, and the lab model is not the Runtime. ChildJournal stays the lab variant. This paragraph does not choose it as the contract name for the child ask. B2 stays open.

This group is design input for B2. B2 stays open.

`lab/grant-binding/src/ops.rs::model_overwrite_grant_does_not_permit_append` is the lab reference model. The lab model is not the Runtime. The body expects a refusal because the operation is an append. An overwrite grant returns AppendNotGranted, and the text is overwrite does not permit append. Reference: `lab/grant-binding/src/ops.rs:162`.

Reference: `lab/grant-binding/src/ops.rs:181` `model_forged_overwrite_right_has_no_effect`.
Reference: `lab/grant-binding/src/ops.rs:588` `model_forged_rights_do_not_widen_the_child_grant`.
Reference: `lab/grant-binding/src/ops.rs:625` `model_refused_child_journal_stores_no_grant`.
Reference: `lab/grant-binding/src/ops.rs:759` `model_forged_identity_does_not_move_the_child_path`.
Reference: `lab/grant-binding/src/ops.rs:787` `model_forged_instance_does_not_move_the_child_grant`.
Reference: `lab/grant-binding/src/ops.rs:824` `model_forged_session_does_not_move_the_child_path`.
Reference: `lab/grant-binding/src/ops.rs:309` `model_append_and_overwrite_do_not_permit_child_journal`.
Reference: `lab/grant-binding/src/ops.rs:380` `model_child_journal_under_the_owned_root_is_allowed`.
Reference: `lab/capsule-identity/tests/bytes.rs:132` `one_byte_change_in_asks_json_changes_the_lab_cid`.

## 7. Open questions
`lab/grant-binding/README.md:12` says the crate is a reference model, not the Runtime.

    reference model, not the Runtime; counts toward no M1 check; the Runtime half is Anders's (#464, #463, #181)

The cited lab functions are the lab reference model, and the lab model is not the Runtime. This section is design input for A3, A4, A5, A7 and B2. Those checks stay open.

Section 1 shows the guest names `Users/self`. local_person_principal_id builds `person:local:`. The journal root is `localhost://Users/self/.AppData/Agents/`. Section 2 shows signer_did is the bundle signer's `did:key`, and a valid signature grants nothing. `examples/agent-host/src/lib.rs` contains no `did:`.

`docs/AGENT_ARCHITECTURE.md:19` says a human and an agent are both represented by Runtime principals.

    - A human and an agent are both represented by Runtime principals.

`docs/AGENT_ARCHITECTURE.md:21` says the human product identity is a signed Profile document with a stable Profile DID.

      signed Profile document with a stable Profile DID, controlled from a

`docs/AGENT_ARCHITECTURE.md:24` says executable agent software is a capsule, separate from the agent principal.

    - Executable agent software is a capsule, separate from the agent principal

`docs/AGENT_ARCHITECTURE.md:332` says agent state is rooted under the agent principal's `UsersAI/...` space.

    - Agent state is rooted under the agent principal's `UsersAI/...` space.

`lab/grant-binding/src/lib.rs::register_instance` stores the identity string and the session string. The body writes `identity: identity.to_owned()` and `session: session.to_owned()`. The body does not parse a DID. Reference: `lab/grant-binding/src/lib.rs:144`.

`lab/grant-binding/src/lib.rs::resource_name` is the name check. `lab/grant-binding/src/lib.rs:280` is the guard `if parts.len() < 3 || parts[0] != "UsersAI" || parts[1] != agent`. The body returns OutsidePrincipal when that guard is true.

    fn resource_name(agent: &str, name: &str, owned_root: Option<&str>) -> Result<String, Refuse> {
        if name.contains('\\') || name.starts_with('/') {
            return Err(Refuse::HostPath);
        }
        let parts: Vec<&str> = name.split('/').collect();
        if parts
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
        {
            return Err(Refuse::HostPath);
        }
        if parts.first() == Some(&"Public") {
            return Err(Refuse::PublicRead);
        }
        if parts.len() < 3 || parts[0] != "UsersAI" || parts[1] != agent {
            return Err(Refuse::OutsidePrincipal);
        }
        if !parts.iter().skip(2).all(|part| {
            part.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
        }) {
            return Err(Refuse::SymlinkShaped);
        }
        if let Some(root) = owned_root {
            let inside = name
                .strip_prefix(root)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
            if !inside {
                return Err(Refuse::OutsideRoot);
            }
        }
        Ok(name.to_owned())
    }

Is the agent DID the person principal (person:local:), or a separate DID? Does the owned journal root stay on the launching person's Users/self path, or move to the agent principal's UsersAI path?

Proposal: section 0, A3, agent principal.
Proposal: section 0, A3, owned journal root.

Section 3 shows the cited functions return the token string as the grant id. grant-id is a string. Those functions do not show a separate handle table.

`lab/grant-binding/src/lib.rs:23` says an opaque grant handle. The guest holds only this. `lab/grant-binding/src/lib.rs:25` is the struct. Handle is an opaque value and the guest holds only that.

    /// An opaque grant handle. The guest holds only this.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Handle(u64);

`lab/grant-binding/src/lib.rs::bind_grant` binds the instance's identity and session, the owned root, and the rights to a fresh handle. `lab/grant-binding/src/lib.rs:162` is the doc line for that binding. The body loads the instance record, asks resource_name for the owned root, and stores the identity, the session, the instance, the owned root, and the rights on a new handle.

`lab/grant-binding/src/lib.rs::use_grant` uses the handle. The guest's claims are not read. `lab/grant-binding/src/lib.rs:244` says the call uses a grant and the guest's claims are not read. The body resolves the handle and returns the stored identity, session, instance, owned root, and rights.

Is the Bus v2 host-side handle the token string, or an opaque handle whose binding the guest does not read?

Proposal: section 0, A5, grant handle.

Section 4 keeps the hosted-effect path apart from the direct URL path and leaves A4 open. The names in that section are propose_hosted, effect_request, runtime_hosted_socket, MODEL_OPERATIONS, handle, and forward. The five strings section 4 lists are `offers_list`, `runs_create`, `runs_get`, `runs_events`, and `runs_cancel`.

Which path does the model operation use: the hosted-effect socket, or the five model operations on the remote model service?

Proposal: section 0, A4, hosted model call.

Section 5 shows the guest writes zeros, the journal check is room for history, the concurrency check counts non-terminal runs, the slot stores a time, and the usage function refuses an empty report. Section 5 states the account A7 asks for and cites no lab/grant-binding test.

`lab/grant-binding/src/ledger.rs::reserve` holds an amount when the outstanding total plus the amount stays at or under the ceiling. `lab/grant-binding/src/ledger.rs:167` is the line that states that hold. The comparison is `total <= ledger.ceiling`.

`lab/grant-binding/src/ledger.rs::model_reserve_over_the_ceiling_is_refused` expects the refusal when the asked amount is past the ceiling, and the held total stays unchanged. The body admits a ceiling of 5, asks for 6, and the held total stays 0. Reference: `lab/grant-binding/src/ledger.rs:504`.

`lab/grant-binding/src/ledger.rs::model_reported_usage_does_not_lower_the_hold` expects the held total to stay at the reserved amount. The body reserves 10 while the request reports a usage of 1, and the held total stays 10. Reference: `lab/grant-binding/src/ledger.rs:580`.

reserve, model_reserve_over_the_ceiling_is_refused, and model_reported_usage_does_not_lower_the_hold do not name a unit, and they do not settle or release a hold.

What unit does the Runtime reserve before each dispatch, and does a cancellation or an uncertain outcome release that hold?

Proposal: section 0, A7, usage reservation.

Open question for A7 (Rong I-1369-b): with no verifier deadline on the propose line, an uncertain hold ends only on a measured settle, so a provider that never reports would pin that budget for the grant's life. Proposal: the Runtime ends an uncertain hold at grant end or revoke and charges it in full, the same rule as session holds, which are settled at end or revoke and never refunded. The lab does not implement this. A7 stays open.

`lab/grant-binding/src/ledger.rs::settle` resolves the call first, then charges the measured figure. A known SettleOutcome uses that measured figure as the charge. `lab/grant-binding/src/ledger.rs:249` contains `let charge = measured;`. `lab/grant-binding/src/ledger.rs::model_settle_known_outcome_charges_the_measured_figure` expects that charge to equal the measured figure, the charged total to gain it, and the held total to return to zero. `lab/grant-binding/src/ledger.rs::model_reported_usage_does_not_lower_the_settled_charge` sets reported_usage to 1 and still expects the charge to equal the measured figure. The unknown arm of settle returns before it changes the held total or the charged total. `lab/grant-binding/src/ledger.rs:234` contains `return Err(SettleRefuse::UnknownOutcome);`. `lab/grant-binding/src/ledger.rs::model_unknown_outcome_keeps_the_hold` expects that refusal, with `expect_err("unknown outcome")` and `unknown outcome keeps the hold`. The held total stays at the reserved amount. `lab/grant-binding/src/ledger.rs::release` resolves the call first, removes the open hold, and subtracts the stored amount from the held total. It does not change the charged total. `lab/grant-binding/src/ledger.rs:295` contains `ledger.held -= amount;`. `lab/grant-binding/src/ledger.rs::model_release_returns_the_unused_hold` expects `Ok(())`, a held total of zero, and a charged total of zero. This citation is design input for A7. These settle and release functions are the lab reference model, and the lab model is not the Runtime. An unknown outcome in this lab model keeps the hold. Release in this lab model returns the unused hold and charges nothing. This paragraph does not answer the question above. A7 stays open.

`lab/grant-binding/src/ledger.rs::admit` sets the ledger ceiling and leaves outstanding holds as they are. The fn line is `pub fn admit(&self, ceiling: u64) {`. The doc line is `Sets the allowance ceiling. Outstanding holds stay as they are.` The assignment is `.ceiling = ceiling`. The function returns no refusal. `lab/grant-binding/src/ledger.rs::model_reserve_before_admit_is_refused` reserves 1 before any admit. The fn line is `fn model_reserve_before_admit_is_refused() {`. The expect_err line is `expect_err("reserve before admit")`. The refusal is OverCeiling with ceiling 0, held 0, and asked 1. The fields are `ReserveRefuse::OverCeiling { ceiling: 0, held: 0, asked: 1 }`. The text is `reservation exceeds the ceiling`. The held total stays 0 and the open set stays empty. The assert is `assert!(after_refusal.open.is_empty());`. admit of 1 then lets a reserve of 1 succeed, and the held total is 1. The admit line is `verifier.admit(1);`. The expect line is `expect("admit opens the ceiling")`. The held assert is `assert_eq!(books(&verifier).held, 1);`. `lab/grant-binding/src/ledger.rs::model_lower_ceiling_leaves_the_hold` admits 10, reserves 8, then admits 4. The fn line is `fn model_lower_ceiling_leaves_the_hold() {`. The admit line is `verifier.admit(10);`. The reserve of 8 is `verifier.reserve(&call, &guest(handle), 8).expect("reserve");`. The later admit is `verifier.admit(4);`. The held total stays 8. The assert is `assert_eq!(after.held, 8);`. A further reserve of 1 is refused with OverCeiling ceiling 4, held 8, and asked 1, and the held total stays 8. The expect_err line is `expect_err("lower ceiling")`. The fields are `ReserveRefuse::OverCeiling { ceiling: 4, held: 8, asked: 1 }`. The text is `reservation exceeds the ceiling`. This citation is design input for A7. These admit functions are the lab reference model, and the lab model is not the Runtime. A reserve before admit meets a ceiling of zero. A later admit leaves an outstanding hold in place. This paragraph does not answer the budget question. A7 stays open. Reference: `lab/grant-binding/src/ledger.rs:231` `lab/grant-binding/src/ledger.rs:1203` `lab/grant-binding/src/ledger.rs:1082`.

Reference: `lab/grant-binding/src/ask.rs:92` `model_over_budget_ask_is_refused`.
Reference: `lab/grant-binding/src/ask.rs:127` `model_ask_at_the_cap_is_admitted`.
Reference: `lab/grant-binding/src/ask.rs:64` `model_admitted_ask_sets_the_ceiling`.
Reference: `lab/grant-binding/src/ledger.rs:1696` `model_second_agent_does_not_raise_the_ceiling`.
Reference: `lab/grant-binding/src/ledger.rs:1751` `model_lower_admit_binds_an_asked_agent`.
Reference: `lab/grant-binding/src/ledger.rs:1785` `model_unasked_agent_reads_the_last_admit`.
Reference: `lab/grant-binding/src/ledger.rs:1842` `model_other_agent_hold_does_not_fill_the_ceiling`.
Reference: `lab/grant-binding/src/ledger.rs:1900` `model_second_agent_hold_past_the_shared_u64_total_is_refused`.

`lab/grant-binding/src/ledger.rs::model_concurrent_reserves_keep_one_ceiling` admits a ceiling of 5, then runs two reserves of 3 at the same time on one call and one request. Exactly one reserve is allowed. The fn line is `fn model_concurrent_reserves_keep_one_ceiling() {`. The admit line is `verifier.admit(5);`. The two reserves run inside `std::thread::scope`. The first reserve is `let first = scope.spawn(|| verifier.reserve(&call, &request, 3));`. The second reserve is `let second = scope.spawn(|| verifier.reserve(&call, &request, 3));`. The joins are `(first.join().expect("first"), second.join().expect("second"))`. The allowed assert is `assert_eq!(allowed, 1);`. Any other outcome panics with `panic!("exactly one reserve must be allowed")`. The other reserve is OverCeiling with ceiling 5, held 3, and asked 3, and the text is `reservation exceeds the ceiling`. The fields are `ReserveRefuse::OverCeiling { ceiling: 5, held: 3, asked: 3 }`. The text assert is `assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");`. The held total stays 3, the charged total stays 0, and one hold stays open. The held assert is `assert_eq!(books.held, 3);`. The charged assert is `assert_eq!(books.charged, 0);`. The open assert is `assert_eq!(books.open.len(), 1);`. This citation is design input for A7. These concurrent reserves are the lab reference model, and the lab model is not the Runtime. This is the lab account across concurrent calls. Exactly one of the two reserves is allowed. Section 5 counts non-terminal runs, and this paragraph cites a different rule. This paragraph does not answer the budget question. A7 stays open. Reference: `lab/grant-binding/src/ledger.rs:862`.

`lab/grant-binding/src/ledger.rs::model_settle_on_another_handle_is_refused` and `lab/grant-binding/src/ledger.rs::model_release_on_another_handle_is_refused` each register two instances with identity agent-1 and session session-a. The fn line of the settle test is `fn model_settle_on_another_handle_is_refused() {`. The fn line of the release test is `fn model_release_on_another_handle_is_refused() {`. bind_grant of UsersAI/agent-1/notes on each instance returns a handle, and the handles differ. The assert in each test is `assert_ne!(holder, other);`. admit sets 10. The admit line in each test is `verifier.admit(10);`. reserve of 4 runs on the first handle, with the call opened on the first instance. The reserve line in each test is `verifier.reserve(&call, &request, 4).expect("reserve");`. settle through the second handle opens the call on the second instance and the request carries the second handle. The fn line of handles_match is `fn handles_match(bound: Handle, presented: Handle) -> bool {`. The body is `bound == presented`. The settle line is `if !handles_match(bound, request.handle)`. resolve has succeeded for that second handle. handles_match then refuses because the open hold stores the first handle. The refusal is SettleRefuse::OtherHandle and the text is `reservation is bound to another handle`. The expect_err line inside the settle test is `.expect_err("another handle");`. The refusal assert is `assert_eq!(refusal, SettleRefuse::OtherHandle);`. The text assert is `assert_eq!(refusal.to_string(), "reservation is bound to another handle");`. release through the second handle uses the same two instances, the same two handles, admit of 10, and reserve of 4. The release line is `if !handles_match(bound, request.handle)`. The refusal is ReleaseRefuse::OtherHandle and the text is `reservation is bound to another handle`. The expect_err line inside the release test is `.expect_err("another handle");`. The refusal assert is `assert_eq!(refusal, ReleaseRefuse::OtherHandle);`. The text assert is `assert_eq!(refusal.to_string(), "reservation is bound to another handle");`. After each refusal, held stays 4, charged stays 0, and the open reservation stays 4. The held assert inside each test is `assert_eq!(after_refusal.held, 4);`. The charged assert inside each test is `assert_eq!(after_refusal.charged, 0);`. The open assert inside each test is `assert_eq!(after_refusal.open.get(&reservation.id), Some(&4));`. The settle test then settles that reservation through the first handle and gets Ok(4). Charged becomes 4 and held becomes 0. The settle call inside the settle test is `verifier.settle(&call, &request, reservation, SettleOutcome::Known(4)),` and the result is `Ok(4)`. The release test then releases that reservation through the first handle and gets Ok(()). Charged stays 0 and held becomes 0. The release assert inside the release test is `assert_eq!(verifier.release(&call, &request, reservation), Ok(()));`. This citation is design input for A7. These handle-bound reservations are the lab reference model, and the lab model is not the Runtime. A reservation stays bound to the handle that reserved it. This paragraph does not answer the budget question. A7 stays open. Reference: `lab/grant-binding/src/ledger.rs:971` `lab/grant-binding/src/ledger.rs:1014` `lab/grant-binding/src/ledger.rs:32`.

Reference: `lab/grant-binding/src/ledger.rs:898` `model_settle_above_the_reservation_is_refused`.
Reference: `lab/grant-binding/src/ledger.rs:1488` `model_forged_instance_does_not_move_the_settle`.
Reference: `lab/grant-binding/src/ledger.rs:612` `model_forged_instance_does_not_move_the_reserve`.
Reference: `lab/grant-binding/src/ledger.rs:788` `model_forged_instance_does_not_move_the_release`.
Reference: `lab/grant-binding/src/ledger.rs:1049` `model_forged_ceiling_does_not_raise_the_ceiling`.
Reference: `lab/grant-binding/src/ledger.rs:814` `model_settle_below_the_hold_returns_the_rest`.
Reference: `lab/grant-binding/src/ledger.rs:931` `model_settle_past_the_u64_charge_is_refused`.
Reference: `lab/grant-binding/src/ledger.rs:1313` `model_lower_ceiling_does_not_refuse_the_settle`.
Reference: `lab/grant-binding/src/ledger.rs:525` `model_reserve_past_the_u64_total_is_refused`.
Reference: `lab/grant-binding/src/ledger.rs:1155` `model_one_settle_drops_only_that_hold`.
Reference: `lab/grant-binding/src/ledger.rs:1137` `model_one_release_returns_only_that_hold`.
Reference: `lab/grant-binding/src/ledger.rs:839` `model_release_twice_is_refused`.
Reference: `lab/grant-binding/src/ledger.rs:1287` `model_reported_usage_does_not_keep_the_released_hold`.
Reference: `lab/grant-binding/src/ledger.rs:1374` `model_release_after_unknown_is_refused`.
Reference: `lab/grant-binding/src/ledger.rs:1659` `model_unknown_from_another_handle_does_not_mark_the_hold`.
Reference: `lab/grant-binding/src/ledger.rs:1627` `model_forged_instance_does_not_move_the_timeout`.

Section 6 contains the sentence Every ask in the asks file is mapped in this section. Section 6 names model_overwrite_grant_does_not_permit_append.

`lab/grant-binding/src/ops.rs::operate` performs one operation when the resolved grant carries its right. The doc line says the function performs one operation when the resolved grant carries its right. The match arms are Operation::Append, Operation::Overwrite, and Operation::ChildJournal. The body resolves the grant, refuses an arm whose right is absent, and returns Ok when the grant carries that right. Reference: `lab/grant-binding/src/ops.rs:47`.

The Operation enum names Append, Overwrite, and ChildJournal. None of those variant names is the ask string `run`, `child`, `init`, `hosted`, or `journal-append`. ChildJournal is the lab variant. This section does not choose it as the contract name for the child ask. This section does not choose a name for those five asks.

Which typed operation names does the contract use for run, for child, for init, for hosted, and for journal-append?

Proposal: section 0, B2, typed operation.

This section asks these questions and does not answer them.

A propose line is a proposal for Anders. It is not a citation. It does not close A3, A4, A5, A7, or B2.
