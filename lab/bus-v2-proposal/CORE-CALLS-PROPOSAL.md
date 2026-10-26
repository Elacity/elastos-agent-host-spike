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

This section is design input for A5. A5 stays open. This section cites no lab/grant-binding test.

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
