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
