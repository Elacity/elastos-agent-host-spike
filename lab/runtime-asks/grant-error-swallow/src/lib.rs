//! Trial rule for a Runtime grant-request Internal that the guest swallows.
//! Not the Runtime, and not a change to `examples/agent-host`.
//!
//! Three shipped sites turn an Internal grant failure into an ordinary deny:
//!
//! 1. Runtime `bus_error` maps an unknown code, including
//!    `manifest_capability_denied`, to `BusError::Internal`
//!    (`elastos-compute` `component.rs`).
//! 2. Guest `WasmBus::request_grant` maps that Internal to `BusFailure::Other`
//!    (`examples/agent-host/src/lib.rs`).
//! 3. `request_journal_grants` uses `.ok()`, so Other becomes an empty grant.
//!    `run()` treats `(None, Denied)` as a normal deny and returns `Ok(())`.
//!
//! A genuine `denied` also becomes an empty grant and `Ok(())`. The caller
//! cannot tell the two apart.
//!
//! The trial keeps a genuine deny as `Ok` (empty grants). It returns `Err`
//! for Internal / Other / Invalid.

/// Plant: set to true to treat Internal like a deny.
/// `trial_propagates_internal_and_keeps_deny` must then fail.
pub const SWALLOW_INTERNAL: bool = false;

/// The Runtime `bus_error` kinds that reach a grant request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusErrorKind {
    Denied,
    Invalid,
    Internal,
    NotFound,
    Timeout,
    Unavailable,
}

/// The guest `BusFailure` kinds `WasmBus` returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusFailure {
    Denied,
    Invalid,
    Other,
}

/// What `run()` returns to the Runtime after the grant request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerOutcome {
    /// `Ok(())`: empty grants, append denied, treated as a normal deny.
    OkDeny,
    /// A loud failure (`BusError::Internal` / `Invalid` from `run()`).
    Err,
}

/// Runtime `bus_error` (`component.rs`). Same Denied list and Internal default
/// on Elacity `develop` `92aeea44` and on this tree. Unknown codes, including
/// `manifest_capability_denied`, are Internal.
pub fn bus_error(code: &str) -> BusErrorKind {
    match code {
        "denied" | "capability_denied" | "missing_token" | "invalid_token" => BusErrorKind::Denied,
        "not_found" => BusErrorKind::NotFound,
        "timeout" => BusErrorKind::Timeout,
        "unavailable" => BusErrorKind::Unavailable,
        "invalid"
        | "invalid_action"
        | "invalid_resource_invoke"
        | "revision_required"
        | "revision_conflict"
        | "principal_root_protection_required"
        | "invalid_localhost_path"
        | "append_not_allowed"
        | "operation_not_allowed"
        | "invalid_content" => BusErrorKind::Invalid,
        _ => BusErrorKind::Internal,
    }
}

/// `WasmBus::request_grant` (`examples/agent-host/src/lib.rs`). Internal and
/// every unlisted variant become Other. The message text is dropped.
pub fn wasm_bus_map(err: BusErrorKind) -> BusFailure {
    match err {
        BusErrorKind::Denied => BusFailure::Denied,
        BusErrorKind::Invalid => BusFailure::Invalid,
        BusErrorKind::Internal
        | BusErrorKind::NotFound
        | BusErrorKind::Timeout
        | BusErrorKind::Unavailable => BusFailure::Other,
    }
}

/// `request_journal_grants` `.ok()` (`examples/agent-host/src/lib.rs`).
/// Any BusFailure, including Other from Internal, becomes an empty grant.
pub fn shipped_ask(result: Result<String, BusFailure>) -> Option<String> {
    result.ok().and_then(|id| (!id.is_empty()).then_some(id))
}

/// `run()` after empty grants: `(None, AppendOutcome::Denied)` is `followed`,
/// then `Ok(())`.
pub fn run_after_grants(write: Option<&str>) -> CallerOutcome {
    match write {
        None => CallerOutcome::OkDeny,
        Some(_) => CallerOutcome::Err,
    }
}

/// Shipped path: Runtime code → WasmBus → `.ok()` → `run()`.
pub fn shipped_caller(code: &str) -> CallerOutcome {
    let failure = wasm_bus_map(bus_error(code));
    let grant = shipped_ask(Err(failure));
    run_after_grants(grant.as_deref())
}

/// Trial ask: a genuine deny stays an empty grant. Other and Invalid fail.
pub fn trial_ask(result: Result<String, BusFailure>) -> Result<Option<String>, BusFailure> {
    match result {
        Ok(id) if !id.is_empty() => Ok(Some(id)),
        Ok(_) => Ok(None),
        Err(BusFailure::Denied) => Ok(None),
        Err(err) => {
            if SWALLOW_INTERNAL {
                Ok(None)
            } else {
                Err(err)
            }
        }
    }
}

/// Trial `run()`: empty grant is still a deny; a failed ask is an error.
pub fn trial_run(ask: Result<Option<String>, BusFailure>) -> CallerOutcome {
    match ask {
        Ok(None) => CallerOutcome::OkDeny,
        Ok(Some(_)) => CallerOutcome::Err,
        Err(_) => CallerOutcome::Err,
    }
}

/// Trial path: Runtime code → WasmBus → trial ask → trial run.
pub fn trial_caller(code: &str) -> CallerOutcome {
    let failure = wasm_bus_map(bus_error(code));
    trial_run(trial_ask(Err(failure)))
}
