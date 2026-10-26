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

The project ask is the resource propose_init stores. The contract must be extended for a typed operation for run, for child, and for init. The two hosted rows and journal-append are not mapped in this section.

This section cites no lab/grant-binding test.
