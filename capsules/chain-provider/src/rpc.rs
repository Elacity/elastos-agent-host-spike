use super::*;

pub(super) fn backend_url(network: &ChainNetwork, path: &str) -> Result<String, Response> {
    let base = network.rpc_url.trim().trim_end_matches('/');
    if base.is_empty() {
        return Err(Response::error(
            "backend_not_configured",
            &format!("backend URL is not configured for {}", network.id),
        ));
    }
    Ok(format!("{}/{}", base, path.trim_start_matches('/')))
}

pub(super) fn bitcoin_rpc_auth(
    user: Option<&str>,
    password: Option<&str>,
) -> Option<(String, String)> {
    let user = user?;
    let password = password?;
    if user.trim().is_empty() || password.is_empty() {
        return None;
    }
    Some((user.to_string(), password.to_string()))
}
