//! Corrected A6 check: a session token stays with its instance.
//!
//! The agent-conformance A6 rows never present instance-1's token as
//! instance-2. This check is the missing journey: owner use succeeds,
//! sibling presentation is refused with `wrong_capsule`. Removing the
//! comparison is a CAUGHT falsifier.

/// Same rule as Runtime `CapabilityManager::validate` step 4
/// (`elastos/crates/elastos-runtime/src/capability/manager.rs`).
pub fn session_token_binds_caller(token_capsule: &str, caller_capsule: &str) -> Result<(), String> {
    if token_capsule != caller_capsule {
        return Err(format!(
            "wrong_capsule expected:{token_capsule} got:{caller_capsule}"
        ));
    }
    Ok(())
}

pub fn owner_may_use_own_token() -> Result<String, String> {
    session_token_binds_caller("instance-1", "instance-1")
        .map(|()| "A6 journey: instance-1 may use its session token".to_string())
        .map_err(|reason| format!("A6 owner use refused: {reason}"))
}

pub fn sibling_presenting_owner_token_is_refused() -> Result<String, String> {
    match session_token_binds_caller("instance-1", "instance-2") {
        Err(reason)
            if reason.contains("wrong_capsule")
                && reason.contains("expected:instance-1")
                && reason.contains("got:instance-2") =>
        {
            Ok(format!("A6 refusal: {reason}"))
        }
        other => Err(format!(
            "A6 expected wrong_capsule refusal with a reason, got {other:?}"
        )),
    }
}

/// The Runtime source still has validate step 4. Absence fails this check.
pub fn runtime_step4_present(source: &str) -> Result<String, String> {
    let has_check = source.contains("if token.capsule != caller_capsule_id");
    let has_error = source.contains("ValidationError::WrongCapsule");
    let has_audit = source.contains("\"wrong_capsule\"");
    if has_check && has_error && has_audit {
        Ok("Runtime validate step 4 (session-token / capsule bind) is present".into())
    } else {
        Err("Runtime session-token check is absent".into())
    }
}
