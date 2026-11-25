#![cfg(all(feature = "prototype-agents", target_os = "macos"))]
//! Asks the HTTP hosted gate with a context built for one principal.
//! The seven hosted rows call this. A featureless build does not compile it.

use std::path::Path;

use super::gateway_provider_proxy::hosted_run_refusal;
use super::HomeLaunchTokenContext;

pub(crate) fn http_hosted_run_with_principal_for_test(
    data_dir: &Path,
    principal_id: &str,
    request: &serde_json::Value,
) -> bool {
    let Ok(root) = crate::auth::ResolvedPrincipalRoot::resolve(data_dir, data_dir, principal_id)
    else {
        return false;
    };
    let proof = crate::auth::stored_principal_record(data_dir, principal_id)
        .ok()
        .flatten()
        .map(|principal| principal.proof_binding_id);
    let context =
        HomeLaunchTokenContext::resolved(root, "s8-http".to_string(), proof, "s8-http".to_string());
    hosted_run_refusal(data_dir, &context, request, false).is_none()
}
