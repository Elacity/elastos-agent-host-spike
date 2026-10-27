# Core calls proposal

LAB DRAFT for Sash and Anders. This file is the proposal. It stays in the lab. It is design input for M1 checks A3, A5, A7 and B2, and it leaves those checks open.

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

`elastos/crates/elastos-server/src/auth.rs::local_person_principal_id` builds the person principal from a proof-binding id. The body hashes that id with SHA-256 and returns `person:local:` plus the hex of the first 16 bytes of the digest.

    pub fn local_person_principal_id(proof_binding_id: &str) -> String {
        let digest = Sha256::digest(proof_binding_id.as_bytes());
        format!("person:local:{}", hex::encode(&digest[..16]))
    }

`elastos/crates/elastos-server/src/auth.rs::principal_localhost_root` builds the localhost root from a principal id. The body hashes that id with SHA-256 and returns `localhost://Users/` plus the hex of the first 12 bytes of the digest.

    pub fn principal_localhost_root(principal_id: &str) -> String {
        let digest = Sha256::digest(principal_id.as_bytes());
        format!("localhost://Users/{}", hex::encode(&digest[..12]))
    }

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

`elastos/crates/elastos-server/src/resource_bridge.rs::manifest_bound_users_self_matches_active_principal_root_only_with_context` shows a `Users/self` bound matching the active principal root only when the principal context is present. The body uses the principal id `person:local:abc123`, builds a resource under `principal_localhost_root` of that id, and allows the bound `localhost://Users/self/.AppData/LocalHost/Chat/*` when that principal id is passed in. The same call with no principal id returns false.

    fn manifest_bound_users_self_matches_active_principal_root_only_with_context() {
        let principal_id = "person:local:abc123";
        let resource = format!(
            "{}/.AppData/LocalHost/Chat/state.json",
            crate::auth::principal_localhost_root(principal_id)
        );
        let bounds = vec!["localhost://Users/self/.AppData/LocalHost/Chat/*".to_string()];

        assert!(manifest_allows_resource(
            &bounds,
            &resource,
            Some(principal_id)
        ));
        assert!(!manifest_allows_resource(&bounds, &resource, None));
    }

The journal path sits under the `Users/self` alias. `examples/agent-host/src/lib.rs:3757` sets `JOURNAL_ROOT` to `localhost://Users/self/.AppData/Agents/`. The constant is compiled in tests and in the wasm32 guest.

    #[cfg(any(test, target_arch = "wasm32"))]
    const JOURNAL_ROOT: &str = "localhost://Users/self/.AppData/Agents/";

`examples/agent-host/src/lib.rs::journal_resource` returns that root plus the agent id, `/tasks/`, the task id, and `/journal`. The body returns the error journal id when either id fails its check. Otherwise it returns the joined path. The alias rewrite above places that journal under the launching person's localhost root: the principal root, then `.AppData/Agents/`, the agent id, `tasks`, the task id, and `journal`.

    fn journal_resource(agent_id: &str, task_id: &str) -> Result<String, &'static str> {
        if !journal_id_ok(agent_id) || !journal_id_ok(task_id) {
            return Err("journal id");
        }
        Ok(format!("{JOURNAL_ROOT}{agent_id}/tasks/{task_id}/journal"))
    }

## 2. Signed declarations

This section is design input for A3 and A5. Both stay open.

The signature covers the printed lab CID and names the signer DID.

`lab/capsule-identity/src/lib.rs::name_signature_message` hashes the printed lab CID. The body calls domain_separated_digest with NAME_SIGNATURE_DOMAIN and the UTF-8 bytes of the name. Signing and verifying both call this, and nothing else builds the message. The whole printed lab CID, its b prefix included, is the signed name.

    /// Signing and verifying both call this, and nothing else builds the message.
    /// The whole printed lab CID, its `b` prefix included, is the signed name.
    pub fn name_signature_message(name: &str) -> [u8; 32] {
        domain_separated_digest(NAME_SIGNATURE_DOMAIN, name.as_bytes())
    }

`lab/capsule-identity/src/lib.rs::sign_bundle` signs that message and sets signer_did from the signing key. The name comes from lab_cid. That name is the printed lab CID. The body hashes it with name_signature_message and signs the digest. signer_did is signer_did_of of the signing key. The function returns the signature and writes no file.

    pub fn sign_bundle(key: &SigningKey, bundle: &Path) -> Result<NameSignature, Refusal> {
        let name = lab_cid(bundle)?.to_string();
        let digest = name_signature_message(&name);
        let signature = key.sign(&digest).to_bytes();
        Ok(NameSignature {
            name,
            signer_did: signer_did_of(key),
            signature,
        })
    }

A passing signature is the name check and grants nothing. The signature is a separate fact from the Runtime's grant.

`lab/capsule-identity/src/lib.rs::verify_checked_signature` checks the DID, the accepted list, the name, and the signature. The body decodes the signer DID, requires that DID as an exact member of the accepted list, checks the name, and verifies the signature. Ok(()) means all four passed.

    pub fn verify_checked_signature(
        checked: &CheckedBundle,
        sig: &NameSignature,
        accepted: &[String],
    ) -> Result<(), Refusal> {
        let key = decode_signer(&sig.signer_did)?;
        require_accepted(&sig.signer_did, accepted)?;
        checked.check_name(&sig.name)?;
        verify_signature(&key, sig)?;
        Ok(())
    }

`lab/capsule-identity/src/lib.rs:1248` states that this result is not a trust, admission or launch.

    /// `Ok(())` means all four passed. It is not a trust, admission or launch
    /// value. A wrong key, a changed signature and a name moved onto other bytes
    /// all fail step 4 with one reason.

The capsule-identity README states M1 check B1. `lab/capsule-identity/README.md:697` states that a valid signature grants nothing by itself. This section cites that statement.

    The rule: a valid signature grants nothing by itself. A bundle whose test-key
    signature verifies is still not admitted, and it gets no grant. This library
    checks identity only, and it sits in no admission or launch path.

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

## 3. Grant requests and A5 binding

This section is design input for A5. A5 stays open.

The verified agent identity is who the launch runs as. The grant is the Runtime's admission of one step. A budget stays a separate Runtime decision.

For the agent identity, a capability request calls `scope_current_user_alias` with `BridgeContext.principal_id` before the pending request is stored. The identity host reports that same `principal_id`.

`elastos/crates/elastos-server/src/resource_bridge.rs:43` is the `principal_id` field on `BridgeContext`. The field holds the Runtime principal used to resolve a capsule-facing `Users/self` alias.

    /// Runtime principal used to resolve capsule-facing `Users/self` aliases.
    pub principal_id: Option<String>,

`elastos/crates/elastos-server/src/resource_bridge.rs:925` is the call in `handle_request`. The body handles a `request_capability` request. It calls `scope_current_user_alias` with the requested resource and `ctx.principal_id.as_deref()`. When the call returns an error, the body returns `principal_context_required` before it stores a pending request. When the call returns a name, the body runs `agents_area_capability_refusal`, parses the action, runs the wallet check, and runs the manifest check on that name. The body stores a pending request only after those checks pass, and the stored resource is the returned name.

                let scoped_resource =
                    match scope_current_user_alias(resource, ctx.principal_id.as_deref()) {
                        Ok(resource) => resource,
                        Err(message) => {
                            return Ok(serde_json::json!({
                                "id": id,
                                "response": {
                                    "type": "error",
                                    "code": "principal_context_required",
                                    "message": message,
                                },
                            }));
                        }
                    };
                let resource = scoped_resource.as_str();

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

For the session, the pending request's session id is the bridge capsule id. The identity host copies `capsule_id` into `session`. A status read of another session is refused. The shell grant passes `request.session_id` into `grant`.

`elastos/crates/elastos-server/src/resource_bridge.rs:984` is the session id stored by that same `handle_request` body. The body builds a resource id from the scoped name and calls `create_request_with_reason`. The session argument is `SessionId` of `ctx.capsule_id.clone()`.

                let resource_id = elastos_runtime::capability::ResourceId::new(resource);

                // Create a pending request — the shell decides whether to grant.
                let pending = ctx
                    .pending_store
                    .create_request_with_reason(
                        elastos_runtime::session::SessionId(ctx.capsule_id.clone()),
                        resource_id.clone(),
                        action,
                        reason,
                    )
                    .await;

`elastos/crates/elastos-compute/src/providers/component.rs:352` is the `session` field in that same `context` body. The body sets `session` to `self.capsule_id.clone()`.

            session: self.capsule_id.clone(),

`elastos/crates/elastos-server/src/api/handlers/capability.rs:182` is the refusal in `request_status`. The body loads the pending request by id. When `request.session_id` differs from the caller session id, the body returns Forbidden and the text Cannot access another session's request. Otherwise the body returns that request's status.

    // Verify the request belongs to this session
    if request.session_id != session.id {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot access another session's request".to_string(),
        ));
    }

`elastos/crates/elastos-server/src/api/handlers/capability.rs:339` is the comment on the shell grant. `elastos/crates/elastos-server/src/api/handlers/capability.rs:341` is the capsule id passed into `grant`. `grant_request` loads the pending request, requires it to be pending, and calls `capability_manager.grant`. The capsule id argument is `request.session_id.to_string()`. The resource argument is `request.resource`. The body then marks that pending request granted with the token `grant` returns.

    // Use session ID as capsule ID for now
    let token = state.capability_manager.grant(
        &request.session_id.to_string(),
        request.resource.clone(),
        request.action,
        constraints,
        None, // No expiry for now (session-scoped)
    );

For the capsule instance, `grant` stores its capsule id argument on the token. `validate` refuses a caller whose capsule id differs, and `test_wrong_capsule` shows that refusal. The component invoke passes `BridgeContext.capsule_id` as that caller. The bridge comment says this field is the capsule identity for token minting, a session id or a capsule name.

`elastos/crates/elastos-server/src/resource_bridge.rs:40` is that comment on `BridgeContext.capsule_id`.

    /// Capsule identity for token minting (session ID or capsule name)
    pub capsule_id: String,

`elastos/crates/elastos-runtime/src/capability/manager.rs:326` is the capsule argument in `grant`. The body passes `capsule_id.to_string()` to `CapabilityToken::new`, signs the token, and returns the token.

    /// Grant a new capability token
    pub fn grant(
        &self,
        capsule_id: &str,
        resource: ResourceId,
        action: Action,
        constraints: TokenConstraints,
        expiry: Option<SecureTimestamp>,
    ) -> CapabilityToken {
        let issued_at = SecureTimestamp::now();

        // Ensure token epoch is at least current epoch
        let mut constraints = constraints;
        if constraints.epoch < self.store.current_epoch() {
            constraints.epoch = self.store.current_epoch();
        }

        let mut token = CapabilityToken::new(
            capsule_id.to_string(),
            self.public_key_bytes(),
            resource.clone(),
            action,
            constraints,
            issued_at,
            expiry,
        );

        // Sign the token
        token.sign(&self.signing_key);

        // Record metrics
        self.metrics.record_capability_request(capsule_id);

        // Audit log
        self.audit_log
            .capability_grant(&token.id, capsule_id, &resource, action, expiry);

        token
    }

`elastos/crates/elastos-runtime/src/capability/token.rs:203` is the token field that holds the capsule id. The field is the capsule that can use the token.

    /// Who can use this token (capsule ID)
    pub(crate) capsule: String,

`elastos/crates/elastos-runtime/src/capability/manager.rs:409` is the caller check. `validate` passes the caller capsule id to `validate_recurring`. That body returns WrongCapsule when `token.capsule` differs from `caller_capsule_id`, and it audits the failure as wrong_capsule.

    pub async fn validate(
        &self,
        token: &CapabilityToken,
        caller_capsule_id: &str,
        requested_action: Action,
        requested_resource: &ResourceId,
        resource_classification: Option<u8>,
    ) -> Result<(), ValidationError> {
        self.validate_recurring(
            token,
            caller_capsule_id,
            requested_action,
            requested_resource,
            resource_classification,
            true,
        )
        .await
    }

        // 4. Caller verification
        if token.capsule != caller_capsule_id {
            self.audit_validation_failure(token, caller_capsule_id, "wrong_capsule");
            return Err(ValidationError::WrongCapsule {
                expected: token.capsule.clone(),
                got: caller_capsule_id.to_string(),
            });
        }

`elastos/crates/elastos-runtime/src/capability/manager.rs::test_wrong_capsule` shows that refusal. The body grants a token for capsule-a, calls `validate` with capsule-b, and requires WrongCapsule.

    #[tokio::test]
    async fn test_wrong_capsule() {
        let manager = create_test_manager();

        let token = manager.grant(
            "capsule-a",
            ResourceId::new("localhost://Users/self/Documents/test.txt"),
            Action::Read,
            TokenConstraints::default(),
            None,
        );

        // Wrong capsule trying to use it
        let result = manager
            .validate(
                &token,
                "capsule-b",
                Action::Read,
                &ResourceId::new("localhost://Users/self/Documents/test.txt"),
                None,
            )
            .await;

        assert!(matches!(result, Err(ValidationError::WrongCapsule { .. })));
    }

`elastos/crates/elastos-server/src/resource_bridge.rs:394` is the caller in `authorize_and_dispatch_resource_invoke`. The body decodes the presented token and calls `validate` with `&bridge_ctx.capsule_id`. When `validate` returns an error, the body denies the invoke with `capability_denied`.

    if bridge_ctx
        .capability_manager
        .validate(
            &token,
            &bridge_ctx.capsule_id,
            dispatch.required_action,
            &resource_id,
            None,
        )
        .await
        .is_err()
    {
        return finish_component_invoke(
            bridge_ctx,
            &audit_id,
            &dispatch,
            "denied",
            resource_error_response("capability_denied", "Capability validation failed"),
        );
    }

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

    fn request(
        &mut self,
        request: elastos::bus::types::CapabilityRequest,
    ) -> std::result::Result<elastos::bus::types::CapabilityGrant, elastos::bus::types::BusError>
    {
        if request.actions.len() != 1 {
            return Err(elastos::bus::types::BusError::Invalid(
                "component capability requests currently require exactly one action".into(),
            ));
        }
        let resource = request.resource;
        let action = request.actions[0].clone();
        let response = self.call_bridge(
            guest_bus::capability_request(guest_bus::CapabilityRequest {
                resource: resource.clone(),
                actions: vec![action.clone()],
                reason: request.reason,
            })
            .map_err(|err| bus_error("invalid", err))?,
        )?;
        let token = match response {
            RuntimeResponse::CapabilityToken { token } => token,
            response => return Err(response_error(&response)),
        };
        Ok(elastos::bus::types::CapabilityGrant {
            id: token,
            resource,
            actions: vec![action],
            expires_at_ms: None,
        })
    }

    type grant-id = string;

    record capability-grant {
      id: grant-id,
      %resource: resource-uri,
      actions: list<action>,
      expires-at-ms: option<u64>,
    }

This citation is design input for A5. For the identity, `lab/grant-binding/src/lib.rs::model_different_identity_is_refused` changes the registry identity after the bind and expects the use to fail. The body calls bind_grant, then host_set_identity, then use_grant. The expect_err line is `expect_err("different identity")` and the assert_eq of the refusal string is `identity does not match the grant`. For the session, `lab/grant-binding/src/lib.rs::model_new_session_is_refused` changes the registry session after the bind and expects the use to fail. The body calls bind_grant, then host_set_session, then use_grant. The expect_err line is `expect_err("new session")` and the assert_eq of the refusal string is `session does not match the grant`. For the capsule instance, `lab/grant-binding/src/lib.rs::model_sibling_instance_is_refused` binds the first instance and opens the call on the other instance. The body calls bind_grant and use_grant. The expect_err line is `expect_err("sibling instance")` and the assert_eq of the refusal string is `instance does not match the grant`. For the owned storage root, `lab/grant-binding/src/lib.rs::model_owned_root_must_sit_under_the_agent` binds `UsersAI/other/notes` and expects the bind to fail. The body calls bind_grant. The expect_err line is `expect_err("outside principal")` and the assert_eq of the refusal string is `owned root is outside the agent principal`. These four functions are the lab reference model, and the lab model is not the Runtime. A5 stays open.

This citation is design input for A5. For the path check, `lab/grant-binding/src/lib.rs::use_path` resolves the grant, then checks the path against the stored owned root. The guest's claims are not read. The doc line is `Uses a grant for one path.` The body calls resolve, then resource_name. The body lines are `let record = self.resolve(*call, request.handle)?;` and `resource_name(&record.identity, path, Some(&record.owned_root))?;`. For a .. segment, `lab/grant-binding/src/lib.rs::model_use_path_dotdot_is_refused` binds UsersAI/agent-1/notes and uses UsersAI/agent-1/notes/../other. The expect_err line is `expect_err("dotdot use path")` and the assert_eq of the refusal string is `owned root is a host path`. For a path outside the owned root, `lab/grant-binding/src/lib.rs::model_use_path_outside_the_owned_root_is_refused` uses UsersAI/agent-1/other and UsersAI/agent-1/notes-extra. The expect_err line is `expect_err("outside the owned root")` and the assert_eq of the refusal string is `use path leaves the owned root`. For a symlink-shaped segment, `lab/grant-binding/src/lib.rs::model_symlink_shaped_use_path_is_refused` uses UsersAI/agent-1/notes/link->out. The expect_err line is `expect_err("symlink-shaped segment")` and the assert_eq of the refusal string is `use path has a symlink-shaped segment`. The same test also uses UsersAI/agent-1/notes/. and UsersAI/agent-1/notes/.., and the expect_err line is `expect_err("host-shaped segment")` and the assert_eq of the refusal string is `owned root is a host path` for those two paths. For a sibling instance, `lab/grant-binding/src/lib.rs::model_use_path_on_a_sibling_instance_is_refused` registers two instances with the same identity and the same session, binds the first, and opens the call on the other. The path is the owned root UsersAI/agent-1/notes. Both instances use agent-1 and session-a. The expect_err line is `expect_err("sibling instance")` and the assert_eq of the refusal string is `instance does not match the grant`. These use-path functions are the lab reference model, and the lab model is not the Runtime. A5 stays open.

This citation is design input for A5. `lab/grant-binding/src/lib.rs::model_public_storage_read_is_refused` registers agent-1 and session-a, then bind_grant of Public/notes fails. The fn line is `fn model_public_storage_read_is_refused() {`. The body calls register_instance, then bind_grant. The call is `bind_grant(instance, "Public/notes", rights())`. The expect_err line is `expect_err("public storage read")`, the assert_eq of the refusal is `Refuse::PublicRead`, and the assert_eq of the refusal string is `public storage read does not bind`. That call returns no handle. The same test then bind_grant of UsersAI/agent-1/notes. use_path of Public/notes and use_path of Public/notes/page.md each fail with the same text. The loop line is `for path in ["Public/notes", "Public/notes/page.md"]`. The expect_err line on use_path is `expect_err("public storage read")` and the second assert_eq of the refusal string is `public storage read does not bind`. use_path of UsersAI/agent-1/notes/Public is allowed. The call is `use_path(&call, &request, "UsersAI/agent-1/notes/Public")` and the expect line is `expect("a later Public segment is a normal child path")`. This public-storage test is the lab reference model, and the lab model is not the Runtime. A5 stays open.

This citation is design input for A5. `lab/grant-binding/src/lib.rs::model_unknown_handle_is_refused` registers agent-1 and session-a on this verifier, then bind_grant of UsersAI/agent-1/notes. The fn line is `fn model_unknown_handle_is_refused() {`. The body calls register_instance, then bind_grant. The expect line is `.expect("bind first grant");`. That call returns a handle. The refused call is not this bind. A second verifier bind_grant of UsersAI/agent-1/notes twice. The unknown handle is the second of those binds. The expect line is `.expect("bind elsewhere");` and the expect line is `.expect("bind elsewhere again");`. The comment is `This verifier mints its own handles from one; a handle minted by the other verifier is unknown here even when both count from one.` The test does not call use_grant on the first handle from that other verifier. use_grant of that unknown handle, on this verifier, with the call opened on this verifier's instance, fails. The expect_err line is `.expect_err("unknown handle");`, the assert_eq of the refusal is `assert_eq!(refusal, Refuse::UnknownHandle);`, and the assert_eq of the refusal string is `assert_eq!(refusal.to_string(), "unknown handle");`. That call returns no decision. This unknown-handle test is the lab reference model, and the lab model is not the Runtime. A handle this verifier did not bind is refused. This paragraph does not answer the handle question. A5 stays open.

This citation is design input for A5. The use test `lab/grant-binding/src/lib.rs::model_unknown_instance_is_refused` registers agent-1 and session-a. The fn line is `fn model_unknown_instance_is_refused() {`. The body calls register_instance, then bind_grant, then use_grant. The instance is not InstanceId(0). The assert line is `assert_ne!(instance, InstanceId(0));`. bind_grant of UsersAI/agent-1/notes returns a handle. The expect line is `.expect("bind");`. The request sets forged_instance to that instance. The request line is `forged_instance: Some(instance),`. use_grant of the call opened on InstanceId(0) fails. The call is `.use_grant(verifier.open_call(InstanceId(0)), &request)`. open_call stores the instance id and does not consult the registry. The fn line is `pub fn open_call(&self, instance: InstanceId) -> Call {`. The body line is `Call { instance }`. resolve loads the registry with the call's instance and returns UnknownInstance before it compares identity, session, or the grant's instance. The fn line is `pub(crate) fn resolve(&self, call: Call, handle: Handle) -> Result<GrantRecord, Refuse> {`. The body line is `.get(&call.instance)`. The refusal is Refuse::UnknownInstance and the text is `unknown instance`. The expect_err line is `.expect_err("unknown instance");`, the assert_eq of the refusal is `assert_eq!(refusal, Refuse::UnknownInstance);`, and the assert_eq of the refusal string is `assert_eq!(refusal.to_string(), "unknown instance");`. The same request, with the call opened on the registered instance, succeeds. The expect line is `.expect("the registered instance still uses the grant");`. The decision's instance is that instance, and the owned root is UsersAI/agent-1/notes. The assert_eq of the instance is `assert_eq!(decision.instance, instance);` and the assert_eq of the owned root is `assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");`. The bind test `lab/grant-binding/src/lib.rs::model_bind_unknown_instance_is_refused` registers agent-1 and session-a. The fn line is `fn model_bind_unknown_instance_is_refused() {`. The body calls register_instance, then bind_grant, then use_grant. The instance is not InstanceId(0). The assert line is `assert_ne!(instance, InstanceId(0));`. bind_grant of InstanceId(0) for UsersAI/agent-1/notes fails with the same refusal. The call is `.bind_grant(InstanceId(0), "UsersAI/agent-1/notes", rights())`. The expect_err line is `.expect_err("unknown instance");`, the assert_eq of the refusal is `assert_eq!(refusal, Refuse::UnknownInstance);`, and the assert_eq of the refusal string is `assert_eq!(refusal.to_string(), "unknown instance");`. bind_grant loads the registry and returns UnknownInstance before it stores a grant. The fn line is `pub fn bind_grant(`. The body line is `.get(&instance)`. A bind of the registered instance then returns a handle, and use_grant of that handle on the registered instance succeeds. The expect line is `.expect("a registered instance still binds");` and the expect line is `.expect("grant");`. The decision's instance is that instance. The owned root is UsersAI/agent-1/notes. The assert_eq of the instance is `assert_eq!(decision.instance, instance);` and the assert_eq of the owned root is `assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");`. These unknown-instance tests are the lab reference model, and the lab model is not the Runtime. An instance the registry does not hold is refused. A guest forged instance does not select the call. This paragraph does not answer the handle question. A5 stays open.

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

    {"kind": "hosted", "resource": "Models/"},
    {"kind": "hosted", "resource": "<principal>/.AppData/Models/"},

The caller opens the model URL. `capsules/model-provider/src/adapters.rs::effect_request` is the one function that chooses the URL. A present `runtime_socket` uses `RUNTIME_HOSTED_EFFECT_URL`. The other branch uses `direct_url`. `capsules/model-provider/src/adapters.rs:42` sets that constant to `http://runtime.invalid/v1/hosted-effect`. `capsules/model-provider/src/adapters.rs:58` is the `direct_url` branch. That branch is request construction.

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

The artifact-create worker, `run_http_artifact_create_worker_inner`, calls `require_external_http_containment` before `effect_request`. A production call with no Runtime socket is refused there, and `queued_external_workers_refuse_before_create_status_cancel_or_text_sockets` asserts zero requests in that case. The Runtime hosted transport is the production path. `capsules/model-provider/src/adapters.rs:1670` adds the authorization bearer. That line sits inside `if hosted_socket.is_none()`. The bearer is request construction on the `direct_url` branch.

    require_external_http_containment(hosted_socket)?;
    let client = backend_client_with_socket(offer.policy.runtime_ms_limit, hosted_socket)?;
    let request = {
        let mut builder = effect_request(
            &client,
            reqwest::Method::POST,
            create_url,
            hosted_socket,
            &offer.id,
            &deterministic_run_id(binding),
            &binding.request_id,
            "job_create",
        )
        .header("content-type", "application/json")
        .json(&json!({
            "request_id": binding.request_id,
            "offer_id": offer.id,
            "operation": offer.operation,
            "input": input,
        }));
        if hosted_socket.is_none() {
            if let Some(bearer_token) = bearer_token {
                builder = builder.header("authorization", format!("Bearer {bearer_token}"));
            }
        }
        builder
    };

The Runtime names the socket. `capsules/model-provider/src/config.rs:111` says the Runtime-owned hosted HTTPS effect socket carries no provider key. `capsules/model-provider/src/config.rs:113` is the field `runtime_hosted_socket`.

    /// Runtime-owned hosted HTTPS effect socket. It carries no provider key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_hosted_socket: Option<String>,

The macOS bridge writes that field into the provider config in `spawn_confined_model_with_engine_bundle`. `elastos/crates/elastos-runtime/src/provider/bridge.rs:774` is that write.

        config.extra["runtime_hosted_socket"] = serde_json::json!(hosted_socket);

On macOS, apply_local_model_sockets copies the stored hosted socket into the same field. `elastos/crates/elastos-runtime/src/provider/registry.rs:841` is that copy.

        #[cfg(target_os = "macos")]
        if let Some(socket) = self.hosted_model_socket.read().await.as_deref() {
            config.extra["runtime_hosted_socket"] = serde_json::json!(socket);
        }

`capsules/model-provider/src/adapters.rs:125` is the error in require_external_http_containment: Hosted external HTTPS is paused. On macOS, a present runtime socket returns `Ok(())`. The error arm also says Runtime network authority is not available.

    fn require_external_http_containment(
        runtime_socket: Option<&str>,
    ) -> std::result::Result<(), AdapterFault> {
        #[cfg(target_os = "macos")]
        if runtime_socket.is_some() {
            return Ok(());
        }

The error arm is this fault.

    Err(AdapterFault::context(
        "Hosted external HTTPS is paused.",
        "Runtime network authority is not available",
    ))

The Runtime grants the call and carries it. `elastos/crates/elastos-server/src/api/model_provider_egress.rs::handle` calls `create_grant_after_decision` and `current_grant`. `elastos/crates/elastos-server/src/api/model_provider_egress.rs:493` is the `create_grant_after_decision` call. `elastos/crates/elastos-server/src/api/model_provider_egress.rs:503` is the `current_grant` check. An error denies the stream. `elastos/crates/elastos-server/src/api/model_provider_egress.rs:509` calls `forward`, and that call is the carry.

    async fn handle(
        mut stream: UnixStream,
        bridge: &ProviderBridge,
        provider_pid: u32,
        data_dir: &Path,
    ) -> io::Result<()> {

The grant check denies the stream, and `forward` carries the call.

    if !operator_route
        && create_grant_after_decision(
            data_dir,
            &request.offer_id,
            &request.effect,
            request.method.as_str(),
            &destination,
            None,
            Some((&request.run_id, &request.request_id)),
        )
        .is_err()
        || current_grant(data_dir, &request, &destination).is_err()
    {
        return deny(&mut stream).await;
    }
    let result = {
        let mut monitor = tokio::time::interval(Duration::from_millis(250));
        let outbound = forward(&mut stream, data_dir, &request, &destination, || {
            bridge.confined_model_run_matches(
                &request.offer_id,
                &request.run_id,
                &request.request_id,
            )
        });

The model service is a separate Runtime path. `elastos/crates/elastos-server/src/api/gateway_model_service.rs:1` calls it the remote model service, the destination side of a `remote_model` grant. `elastos/crates/elastos-server/src/api/gateway_model_service.rs:4` says this Runtime owns the decision and verifies the grant. `elastos/crates/elastos-server/src/api/gateway_model_service.rs:32` names `MODEL_OPERATIONS`. The five strings are `offers_list`, `runs_create`, `runs_get`, `runs_events` and `runs_cancel`.

    //! Remote model service: the destination side of a `remote_model` grant.
    //!
    //! A seed Runtime routes typed model operations over Carrier `provider_invoke`
    //! with target `model`. This Runtime owns the decision. It verifies the grant

`MODEL_OPERATIONS` names the five strings.

    pub(crate) const MODEL_OPERATIONS: [&str; 5] = [
        "offers_list",
        "runs_create",
        "runs_get",
        "runs_events",
        "runs_cancel",
    ];

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

`capsules/model-provider/src/journal.rs::active_run_count` adds one when the offer matches and `is_terminal` is false. The condition is `run.offer.id == offer_id && !run.status.is_terminal()`.

        pub fn active_run_count(&self, offer_id: &str) -> Result<usize, ProviderFault> {
            let mut total = 0usize;
            self.visit_runs(|_, run, _| {
                if run.offer.id == offer_id && !run.status.is_terminal() {
                    total = total.saturating_add(1);
                }
                Ok(())
            })?;
            Ok(total)
        }

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

`elastos/crates/elastos-server/src/api/gateway_model_service.rs:1444-1446` says a create holds its record slot before any model work starts, a retry of an already recorded request is answered from that record, and a full index refuses there.

        // A create holds its record slot before any model work starts. A retry of
        // an already recorded request is answered from that record before another
        // create. A full index refuses here.

A reported figure is not a hold, and the required account stays open. `capsules/model-provider/src/journal.rs::validate_backend_usage` returns an error when input tokens, output tokens, and total tokens are all absent. The function body has no ceiling and no subtraction.

    fn validate_backend_usage(usage: &BackendTokenUsage) -> anyhow::Result<()> {
        if usage.input_tokens.is_none() && usage.output_tokens.is_none() && usage.total_tokens.is_none()
        {
            anyhow::bail!("reported backend usage is empty");
        }
        Ok(())
    }

The account A7 asks for is this account. Admission sets the ceiling. The Runtime reserves a bounded usage amount before each dispatch. That account covers concurrent calls, a retry, a cancellation, and an uncertain outcome. A reported figure does not lower the hold. The guest writes zeros. The journal check is room for history. The concurrency check counts non-terminal runs. The slot stores a time under one lock. The usage function refuses an empty report. A7 stays open.

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

Read records a step. `examples/agent-host/src/lib.rs::propose_read` sets the kind to Read and stores the resource. The body has no bus call.

    #[cfg(any(test, target_arch = "wasm32"))]
    fn propose_read(journal: &mut Journal, resource: &str) -> u64 {
        let id = propose_step(journal);
        let step = journal
            .steps
            .iter_mut()
            .find(|step| step.id == id)
            .expect("just pushed");
        step.kind = ProposalKind::Read;
        step.resource = resource.to_string();
        id
    }

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

In the write arm of protected_principal_root_resource_response, an agent journal whose request has the append flag returns `append_not_allowed`. `elastos/crates/elastos-server/src/resource_bridge.rs:564` is that code. `elastos/crates/elastos-server/src/resource_bridge.rs:565` is the message that agent journals are written whole with a revision precondition.

                if agent_journal && append {
                    return Some(resource_error_response(
                        "append_not_allowed",
                        "append is read-then-write; Agent journals are written whole with a revision precondition",
                    ));
                }

An agent journal with no precondition returns `revision_required`. `elastos/crates/elastos-server/src/resource_bridge.rs:576` is that code. `elastos/crates/elastos-server/src/resource_bridge.rs:577` is the message that agent journal writes need `create_only` or `if_revision`.

                if agent_journal && precondition.is_none() {
                    return Some(resource_error_response(
                        "revision_required",
                        "Agent journal writes need create_only or if_revision",
                    ));
                }

When the append flag is false, the bytes are `content.clone()`. `elastos/crates/elastos-server/src/resource_bridge.rs:597` is that line.

                    content.clone()

A precondition that is present calls `write_principal_root_object_if_revision`. `elastos/crates/elastos-server/src/resource_bridge.rs:600` is that call.

                    Some(precondition) => crate::auth::write_principal_root_object_if_revision(

The guest ask is `journal-append`. The invoked operation is `write`, which is on the localhost list section 6 already quoted, and that list's `write` arm maps to `Action::Write`. The body is the whole encoding. The bridge refuses the append flag on an agent journal and stores `content.clone()` when that flag is false. Today's checks write the whole journal under create_only or if_revision, and they refuse append on an agent journal. The child-journal operation stays the second journal in the project-ask paragraphs. The contract must be extended for a typed operation named hosted, and for a typed operation that names journal-append apart from write. Every ask in the asks file is mapped in this section.

This citation is design input for B2. `lab/grant-binding/src/ops.rs::create_child_journal` calls operate with ChildJournal, checks the path with resource_name against the stored owned root, and returns bind_grant of that path. The fn line is `pub fn create_child_journal(`. The operate line is `self.operate(call, request, Operation::ChildJournal)?;`. The path check is `super::resource_name(&grant.identity, path, Some(&grant.owned_root))`. The return is `self.bind_grant(grant.instance, path, grant.rights)`. The doc line reads: The new handle is `bind_grant` of that path. `lab/grant-binding/src/ops.rs::model_child_journal_create_without_the_right_is_refused` binds append and overwrite with child_journal false, then create_child_journal of UsersAI/agent-1/journal/page.md fails. The fn line is `fn model_child_journal_create_without_the_right_is_refused() {`. The expect_err line is `expect_err("child journal is its own right")`. The assert_eq of the refusal is `OperateRefuse::ChildJournalNotGranted`, and the assert_eq of the refusal string is `child journal is its own right`. That call returns no handle. `lab/grant-binding/src/ops.rs::model_child_journal_returns_its_own_handle` binds the parent at UsersAI/agent-1/journal and creates UsersAI/agent-1/journal/page.md. The fn line is `fn model_child_journal_returns_its_own_handle() {`. The child handle is not the parent handle. The assert_ne line is `assert_ne!(child, parent);`. use_grant of the child handle reads owned root UsersAI/agent-1/journal/page.md, identity agent-1, session session-a, and the same instance. The owned-root assert_eq is `assert_eq!(child_decision.owned_root, "UsersAI/agent-1/journal/page.md");`. The identity assert_eq is `assert_eq!(child_decision.identity, "agent-1");`. The session assert_eq is `assert_eq!(child_decision.session, "session-a");`. The instance assert_eq is `assert_eq!(child_decision.instance, instance);`. The child rights stay append false, overwrite false, and child_journal true. The child rights assert compares child_decision.rights with append false, overwrite false, and child_journal true. use_path of UsersAI/agent-1/journal/page.md on the child handle is allowed. The expect line is `expect("the child handle binds its own root")`. use_path of UsersAI/agent-1/journal on the child handle is refused with `use path leaves the owned root`. The expect_err line is `expect_err("the parent root leaves the child root")` and the assert_eq of the refusal string is `use path leaves the owned root`. use_grant of the parent handle still reads owned root UsersAI/agent-1/journal. The assert_eq line is `assert_eq!(parent_decision.owned_root, "UsersAI/agent-1/journal");`. use_path of UsersAI/agent-1/journal/page.md on the parent handle is allowed. The expect line is `expect("the parent handle keeps the parent root")`. These create-child-journal functions are the lab reference model, and the lab model is not the Runtime. ChildJournal stays the lab variant. This paragraph does not choose it as the contract name for the child ask. B2 stays open.

This group is design input for B2. B2 stays open.

`lab/grant-binding/src/ops.rs::model_overwrite_grant_does_not_permit_append` is the lab reference model. The lab model is not the Runtime. The body expects a refusal because the operation is an append. An overwrite grant returns AppendNotGranted, and the text is overwrite does not permit append.

    #[test]
    fn model_overwrite_grant_does_not_permit_append() {
        let mut verifier = Verifier::new();
        let (instance, handle) = bound_with(
            &mut verifier,
            Rights {
                append: false,
                overwrite: true,
                child_journal: false,
            },
        );
        let call = verifier.open_call(instance);
        let refusal = verifier
            .operate(&call, &guest(handle), Operation::Append)
            .expect_err("overwrite grant refuses append");
        assert_eq!(refusal, OperateRefuse::AppendNotGranted);
        assert_eq!(refusal.to_string(), "overwrite does not permit append");
    }

This citation is design input for B2. The overwrite flag. `lab/grant-binding/src/ops.rs::model_forged_overwrite_right_has_no_effect` stores append true, overwrite false, and child_journal false, then sets forged_overwrite true. operate of Overwrite fails. The fn line is `fn model_forged_overwrite_right_has_no_effect() {`. The Rights block is `append: true,`, `overwrite: false,`, and `child_journal: false,`. The forged line is `forged_overwrite: true,`. The expect_err line is `.expect_err("guest claim does not grant overwrite");`. The assert_eq of the refusal is `assert_eq!(refusal, OperateRefuse::OverwriteNotGranted);`, and the assert_eq of the refusal string is `assert_eq!(refusal.to_string(), "append does not permit overwrite");`. That call returns no success. The stored overwrite right stays false. The append flag. `lab/grant-binding/src/ops.rs::model_forged_append_right_has_no_effect` stores append false, overwrite true, and child_journal false, then sets forged_append true. operate of Append fails. The fn line is `fn model_forged_append_right_has_no_effect() {`. The Rights block is `append: false,`, `overwrite: true,`, and `child_journal: false,`. The forged line is `forged_append: true,`. The assert line is `assert!(request.forged_append);`. The expect_err line is `.expect_err("guest claim does not grant append");`. The assert_eq of the refusal is `assert_eq!(refusal, OperateRefuse::AppendNotGranted);`, and the assert_eq of the refusal string is `assert_eq!(refusal.to_string(), "overwrite does not permit append");`. That call returns no success. The stored append right stays false. These forged-flag tests are the lab reference model, and the lab model is not the Runtime. A guest forged flag does not grant the missing right. This paragraph does not choose the contract name for the child ask. B2 stays open.

This citation is design input for B2. The stored rights and the forged flags. `lab/grant-binding/src/ops.rs::model_forged_rights_do_not_widen_the_child_grant` binds append false, overwrite false, and child_journal true. The request sets forged_append true and forged_overwrite true. The fn line is `fn model_forged_rights_do_not_widen_the_child_grant() {`. The bound_with Rights block is `append: false,`, `overwrite: false,`, and `child_journal: true,`. The forged lines are `forged_append: true,` and `forged_overwrite: true,`. The assert lines are `assert!(request.forged_append);` and `assert!(request.forged_overwrite);`. The child handle. create_child_journal of UsersAI/agent-1/journal/page.md returns a handle. The child handle is not the parent handle. create_child_journal calls bind_grant with the stored rights. The fn line is `pub fn create_child_journal(`. The call is `.create_child_journal(&call, &request, "UsersAI/agent-1/journal/page.md")`. The expect line is `.expect("child journal");`. The assert_ne line is `assert_ne!(child, parent);`. The bind_grant line is `self.bind_grant(grant.instance, path, grant.rights)`. The rights on the child handle. use_grant of the child handle reads append false, overwrite false, and child_journal true, and owned root UsersAI/agent-1/journal/page.md. The expect line is `.expect("child grant");`. The child_decision.rights block is `append: false,`, `overwrite: false,`, and `child_journal: true,`. The owned-root assert_eq is `assert_eq!(child_decision.owned_root, "UsersAI/agent-1/journal/page.md");`. These stored child rights are the lab reference model, and the lab model is not the Runtime. A guest forged flag does not widen the rights stored on the child handle. This paragraph does not choose the contract name for the child ask. B2 stays open.

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

`lab/grant-binding/src/lib.rs::register_instance` stores the identity string and the session string. The body writes `identity: identity.to_owned()` and `session: session.to_owned()`. The body does not parse a DID.

    /// Registers an instance and returns its registry id.
    pub fn register_instance(&mut self, identity: &str, session: &str) -> InstanceId {
        self.next_instance += 1;
        let instance = InstanceId(self.next_instance);
        self.registry.insert(
            instance,
            InstanceRecord {
                identity: identity.to_owned(),
                session: session.to_owned(),
            },
        );
        instance
    }

`lab/grant-binding/src/lib.rs::resource_name` is the name check. `lab/grant-binding/src/lib.rs:277` is the guard `if parts.len() < 3 || parts[0] != "UsersAI" || parts[1] != agent`. The body returns OutsidePrincipal when that guard is true.

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

Section 3 shows the cited functions return the token string as the grant id. grant-id is a string. Those functions do not show a separate handle table.

`lab/grant-binding/src/lib.rs:20` says an opaque grant handle. The guest holds only this. `lab/grant-binding/src/lib.rs:22` is the struct. Handle is an opaque value and the guest holds only that.

    /// An opaque grant handle. The guest holds only this.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Handle(u64);

`lab/grant-binding/src/lib.rs::bind_grant` binds the instance's identity and session, the owned root, and the rights to a fresh handle. `lab/grant-binding/src/lib.rs:159` is the doc line for that binding. The body loads the instance record, asks resource_name for the owned root, and stores the identity, the session, the instance, the owned root, and the rights on a new handle.

    /// Binds the instance's identity and session, the owned root and the rights
    /// to a fresh handle.
    pub fn bind_grant(
        &mut self,
        instance: InstanceId,
        resource: &str,
        rights: Rights,
    ) -> Result<Handle, Refuse> {
        let record = self
            .registry
            .get(&instance)
            .ok_or(Refuse::UnknownInstance)?;
        let owned_root = resource_name(&record.identity, resource, None)?;
        self.next_handle += 1;
        let handle = Handle(self.next_handle);
        self.grants.insert(
            handle,
            GrantRecord {
                identity: record.identity.clone(),
                session: record.session.clone(),
                instance,
                owned_root,
                rights,
            },
        );
        Ok(handle)
    }

`lab/grant-binding/src/lib.rs::use_grant` uses the handle. The guest's claims are not read. `lab/grant-binding/src/lib.rs:241` says the call uses a grant and the guest's claims are not read. The body resolves the handle and returns the stored identity, session, instance, owned root, and rights.

    /// Uses a grant. The guest's claims are not read.
    pub fn use_grant(&self, call: Call, request: &GuestRequest) -> Result<Decision, Refuse> {
        let record = self.resolve(call, request.handle)?;
        Ok(Decision {
            identity: record.identity,
            session: record.session,
            instance: record.instance,
            owned_root: record.owned_root,
            rights: record.rights,
        })
    }

Is the Bus v2 host-side handle the token string, or an opaque handle whose binding the guest does not read?

Section 4 keeps the hosted-effect path apart from the direct URL path and leaves A4 open. The names in that section are propose_hosted, effect_request, runtime_hosted_socket, MODEL_OPERATIONS, handle, and forward. The five strings section 4 lists are `offers_list`, `runs_create`, `runs_get`, `runs_events`, and `runs_cancel`.

Which path does the model operation use: the hosted-effect socket, or the five model operations on the remote model service?

Section 5 shows the guest writes zeros, the journal check is room for history, the concurrency check counts non-terminal runs, the slot stores a time, and the usage function refuses an empty report. Section 5 states the account A7 asks for and cites no lab/grant-binding test.

`lab/grant-binding/src/ledger.rs::reserve` holds an amount when the outstanding total plus the amount stays at or under the ceiling. `lab/grant-binding/src/ledger.rs:139` is the line that states that hold. The comparison is `total <= ledger.ceiling`.

    /// Holds `amount` on the ledger when the outstanding total plus `amount`
    /// stays at or under the ceiling. A binding refusal records nothing, a sum
    /// that does not fit in `u64` is over the ceiling, and the request's
    /// reported usage does not lower the hold.
    pub fn reserve(
        &self,
        call: &Call,
        request: &GuestRequest,
        amount: u64,
    ) -> Result<Reservation, ReserveRefuse> {
        self.resolve(*call, request.handle)
            .map_err(ReserveRefuse::Binding)?;
        let mut ledger = self.ledger.lock().expect("ledger lock");
        let held = ledger.held;
        let ledger: &mut Ledger = &mut ledger;
        let total = match held.checked_add(amount) {
            Some(total) if total <= ledger.ceiling => total,
            _ => {
                return Err(ReserveRefuse::OverCeiling {
                    ceiling: ledger.ceiling,
                    held,
                    asked: amount,
                })
            }
        };
        ledger.held = total;
        ledger.next_reservation += 1;
        ledger.open.insert(
            ledger.next_reservation,
            OpenHold {
                handle: request.handle,
                amount,
            },
        );
        Ok(Reservation {
            id: ledger.next_reservation,
        })
    }

`lab/grant-binding/src/ledger.rs::model_reserve_over_the_ceiling_is_refused` expects the refusal when the asked amount is past the ceiling, and the held total stays unchanged. The body admits a ceiling of 5, asks for 6, and the held total stays 0.

    #[test]
    fn model_reserve_over_the_ceiling_is_refused() {
        let mut verifier = Verifier::new();
        let (instance, handle) = bound(&mut verifier);
        verifier.admit(5);
        let call = verifier.open_call(instance);
        let refusal = verifier
            .reserve(&call, &guest(handle), 6)
            .expect_err("over the ceiling");
        assert_eq!(
            refusal,
            ReserveRefuse::OverCeiling {
                ceiling: 5,
                held: 0,
                asked: 6,
            }
        );
        assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
        assert_eq!(books(&verifier).held, 0);
    }

`lab/grant-binding/src/ledger.rs::model_reported_usage_does_not_lower_the_hold` expects the held total to stay at the reserved amount. The body reserves 10 while the request reports a usage of 1, and the held total stays 10.

    #[test]
    fn model_reported_usage_does_not_lower_the_hold() {
        let mut verifier = Verifier::new();
        let (instance, handle) = bound(&mut verifier);
        verifier.admit(10);
        let call = verifier.open_call(instance);
        let request = GuestRequest {
            reported_usage: 1,
            ..guest(handle)
        };
        verifier.reserve(&call, &request, 10).expect("reserve");
        assert_eq!(books(&verifier).held, 10);
    }

reserve, model_reserve_over_the_ceiling_is_refused, and model_reported_usage_does_not_lower_the_hold do not name a unit, and they do not settle or release a hold.

What unit does the Runtime reserve before each dispatch, and does a cancellation or an uncertain outcome release that hold?

`lab/grant-binding/src/ledger.rs::settle` resolves the call first, then charges the measured figure. A known SettleOutcome uses that measured figure as the charge. `lab/grant-binding/src/ledger.rs:212` contains `let charge = measured;`. `lab/grant-binding/src/ledger.rs::model_settle_known_outcome_charges_the_measured_figure` expects that charge to equal the measured figure, the charged total to gain it, and the held total to return to zero. `lab/grant-binding/src/ledger.rs::model_reported_usage_does_not_lower_the_settled_charge` sets reported_usage to 1 and still expects the charge to equal the measured figure. The unknown arm of settle returns before it changes the held total or the charged total. `lab/grant-binding/src/ledger.rs:197` contains `return Err(SettleRefuse::UnknownOutcome);`. `lab/grant-binding/src/ledger.rs::model_unknown_outcome_keeps_the_hold` expects that refusal, with `expect_err("unknown outcome")` and `unknown outcome keeps the hold`. The held total stays at the reserved amount. `lab/grant-binding/src/ledger.rs::release` resolves the call first, removes the open hold, and subtracts the stored amount from the held total. It does not change the charged total. `lab/grant-binding/src/ledger.rs:242` contains `ledger.held -= amount;`. `lab/grant-binding/src/ledger.rs::model_release_returns_the_unused_hold` expects `Ok(())`, a held total of zero, and a charged total of zero. This citation is design input for A7. These settle and release functions are the lab reference model, and the lab model is not the Runtime. An unknown outcome in this lab model keeps the hold. Release in this lab model returns the unused hold and charges nothing. This paragraph does not answer the question above. A7 stays open.

`lab/grant-binding/src/ledger.rs::admit` sets the ledger ceiling and leaves outstanding holds as they are. The fn line is `pub fn admit(&self, ceiling: u64) {`. The doc line is `Sets the allowance ceiling. Outstanding holds stay as they are.` The assignment is `.ceiling = ceiling`. The function returns no refusal. `lab/grant-binding/src/ledger.rs::model_reserve_before_admit_is_refused` reserves 1 before any admit. The fn line is `fn model_reserve_before_admit_is_refused() {`. The expect_err line is `expect_err("reserve before admit")`. The refusal is OverCeiling with ceiling 0, held 0, and asked 1. The fields are `ReserveRefuse::OverCeiling { ceiling: 0, held: 0, asked: 1 }`. The text is `reservation exceeds the ceiling`. The held total stays 0 and the open set stays empty. The assert is `assert!(after_refusal.open.is_empty());`. admit of 1 then lets a reserve of 1 succeed, and the held total is 1. The admit line is `verifier.admit(1);`. The expect line is `expect("admit opens the ceiling")`. The held assert is `assert_eq!(books(&verifier).held, 1);`. `lab/grant-binding/src/ledger.rs::model_lower_ceiling_leaves_the_hold` admits 10, reserves 8, then admits 4. The fn line is `fn model_lower_ceiling_leaves_the_hold() {`. The admit line is `verifier.admit(10);`. The reserve of 8 is `verifier.reserve(&call, &guest(handle), 8).expect("reserve");`. The later admit is `verifier.admit(4);`. The held total stays 8. The assert is `assert_eq!(after.held, 8);`. A further reserve of 1 is refused with OverCeiling ceiling 4, held 8, and asked 1, and the held total stays 8. The expect_err line is `expect_err("lower ceiling")`. The fields are `ReserveRefuse::OverCeiling { ceiling: 4, held: 8, asked: 1 }`. The text is `reservation exceeds the ceiling`. This citation is design input for A7. These admit functions are the lab reference model, and the lab model is not the Runtime. A reserve before admit meets a ceiling of zero. A later admit leaves an outstanding hold in place. This paragraph does not answer the budget question. A7 stays open.

`lab/grant-binding/src/ledger.rs::model_concurrent_reserves_keep_one_ceiling` admits a ceiling of 5, then runs two reserves of 3 at the same time on one call and one request. Exactly one reserve is allowed. The fn line is `fn model_concurrent_reserves_keep_one_ceiling() {`. The admit line is `verifier.admit(5);`. The two reserves run inside `std::thread::scope`. The first reserve is `let first = scope.spawn(|| verifier.reserve(&call, &request, 3));`. The second reserve is `let second = scope.spawn(|| verifier.reserve(&call, &request, 3));`. The joins are `(first.join().expect("first"), second.join().expect("second"))`. The allowed assert is `assert_eq!(allowed, 1);`. Any other outcome panics with `panic!("exactly one reserve must be allowed")`. The other reserve is OverCeiling with ceiling 5, held 3, and asked 3, and the text is `reservation exceeds the ceiling`. The fields are `ReserveRefuse::OverCeiling { ceiling: 5, held: 3, asked: 3 }`. The text assert is `assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");`. The held total stays 3, the charged total stays 0, and one hold stays open. The held assert is `assert_eq!(books.held, 3);`. The charged assert is `assert_eq!(books.charged, 0);`. The open assert is `assert_eq!(books.open.len(), 1);`. This citation is design input for A7. These concurrent reserves are the lab reference model, and the lab model is not the Runtime. This is the lab account across concurrent calls. Exactly one of the two reserves is allowed. Section 5 counts non-terminal runs, and this paragraph cites a different rule. This paragraph does not answer the budget question. A7 stays open.

`lab/grant-binding/src/ledger.rs::model_settle_on_another_handle_is_refused` and `lab/grant-binding/src/ledger.rs::model_release_on_another_handle_is_refused` each register two instances with identity agent-1 and session session-a. The fn line of the settle test is `fn model_settle_on_another_handle_is_refused() {`. The fn line of the release test is `fn model_release_on_another_handle_is_refused() {`. bind_grant of UsersAI/agent-1/notes on each instance returns a handle, and the handles differ. The assert in each test is `assert_ne!(holder, other);`. admit sets 10. The admit line in each test is `verifier.admit(10);`. reserve of 4 runs on the first handle, with the call opened on the first instance. The reserve line in each test is `verifier.reserve(&call, &request, 4).expect("reserve");`. settle through the second handle opens the call on the second instance and the request carries the second handle. The fn line of handles_match is `fn handles_match(bound: Handle, presented: Handle) -> bool {`. The body is `bound == presented`. The settle line is `if !handles_match(bound, request.handle)`. resolve has succeeded for that second handle. handles_match then refuses because the open hold stores the first handle. The refusal is SettleRefuse::OtherHandle and the text is `reservation is bound to another handle`. The expect_err line inside the settle test is `.expect_err("another handle");`. The refusal assert is `assert_eq!(refusal, SettleRefuse::OtherHandle);`. The text assert is `assert_eq!(refusal.to_string(), "reservation is bound to another handle");`. release through the second handle uses the same two instances, the same two handles, admit of 10, and reserve of 4. The release line is `if !handles_match(bound, request.handle)`. The refusal is ReleaseRefuse::OtherHandle and the text is `reservation is bound to another handle`. The expect_err line inside the release test is `.expect_err("another handle");`. The refusal assert is `assert_eq!(refusal, ReleaseRefuse::OtherHandle);`. The text assert is `assert_eq!(refusal.to_string(), "reservation is bound to another handle");`. After each refusal, held stays 4, charged stays 0, and the open reservation stays 4. The held assert inside each test is `assert_eq!(after_refusal.held, 4);`. The charged assert inside each test is `assert_eq!(after_refusal.charged, 0);`. The open assert inside each test is `assert_eq!(after_refusal.open.get(&reservation.id), Some(&4));`. The settle test then settles that reservation through the first handle and gets Ok(4). Charged becomes 4 and held becomes 0. The settle call inside the settle test is `verifier.settle(&call, &request, reservation, SettleOutcome::Known(4)),` and the result is `Ok(4)`. The release test then releases that reservation through the first handle and gets Ok(()). Charged stays 0 and held becomes 0. The release assert inside the release test is `assert_eq!(verifier.release(&call, &request, reservation), Ok(()));`. This citation is design input for A7. These handle-bound reservations are the lab reference model, and the lab model is not the Runtime. A reservation stays bound to the handle that reserved it. This paragraph does not answer the budget question. A7 stays open.

This citation is design input for A7. `lab/grant-binding/src/ledger.rs::model_settle_above_the_reservation_is_refused` admits 10. The request sets reported_usage to 100. reserve of 4 succeeds. The fn line is `fn model_settle_above_the_reservation_is_refused() {`. The admit line inside this test is `verifier.admit(10);`. The reported_usage field inside this test is `reported_usage: 100,`. The reserve line inside this test is `let reservation = verifier.reserve(&call, &request, 4).expect("reserve");`. Settle of Known(9) fails. The fn line of settle is `pub fn settle(`. measured comes from the Known outcome. stored is the open hold amount. The comparison is `if measured > stored`. The line is `if measured > stored {`. The refusal return is `return Err(SettleRefuse::AboveReservation);`. The refusal is SettleRefuse::AboveReservation and the text is `measured figure exceeds the reservation`. The settle line inside this test is `.settle(&call, &request, reservation, SettleOutcome::Known(9))`. The expect_err line inside this test is `.expect_err("above the reservation");`. The refusal assert inside this test is `assert_eq!(refusal, SettleRefuse::AboveReservation);`. The text assert inside this test is `assert_eq!(refusal.to_string(), "measured figure exceeds the reservation");`. After the refusal, held stays 4, charged stays 0, and the open reservation stays 4. The held assert inside this test is `assert_eq!(after_refusal.held, 4);`. The charged assert inside this test is `assert_eq!(after_refusal.charged, 0);`. The open assert inside this test is `assert_eq!(after_refusal.open.get(&reservation.id), Some(&4));`. Settle of Known(4) returns 4. Charged becomes 4 and held becomes 0. The reservation is no longer open. The expect line inside this test is `.expect("settle at the reservation");`. The charge assert inside this test is `assert_eq!(charge, 4);`. The charged assert inside this test is `assert_eq!(after_settle.charged, 4);`. The held assert inside this test is `assert_eq!(after_settle.held, 0);`. The open assert inside this test is `assert!(!after_settle.open.contains_key(&reservation.id));`. These above-reservation settles are the lab reference model, and the lab model is not the Runtime. The reported usage is not the figure settle compares. This paragraph does not answer the budget question. A7 stays open.

Section 6 contains the sentence Every ask in the asks file is mapped in this section. Section 6 names model_overwrite_grant_does_not_permit_append.

`lab/grant-binding/src/ops.rs::operate` performs one operation when the resolved grant carries its right. The doc line says the function performs one operation when the resolved grant carries its right. The match arms are Operation::Append, Operation::Overwrite, and Operation::ChildJournal. The body resolves the grant, refuses an arm whose right is absent, and returns Ok when the grant carries that right.

    /// Performs one operation when the resolved grant carries its right.
    pub fn operate(
        &mut self,
        call: &Call,
        request: &GuestRequest,
        operation: Operation,
    ) -> Result<(), OperateRefuse> {
        let grant = self
            .resolve(*call, request.handle)
            .map_err(OperateRefuse::Binding)?;
        match operation {
            Operation::Append if !grant.rights.append => Err(OperateRefuse::AppendNotGranted),
            Operation::Overwrite if !grant.rights.overwrite => {
                Err(OperateRefuse::OverwriteNotGranted)
            }
            Operation::ChildJournal if !grant.rights.child_journal => {
                Err(OperateRefuse::ChildJournalNotGranted)
            }
            _ => Ok(()),
        }
    }

The Operation enum names Append, Overwrite, and ChildJournal. None of those variant names is the ask string `run`, `child`, `init`, `hosted`, or `journal-append`. ChildJournal is the lab variant. This section does not choose it as the contract name for the child ask. This section does not choose a name for those five asks.

Which typed operation names does the contract use for run, for child, for init, for hosted, and for journal-append?

This section asks these questions and does not answer them.
