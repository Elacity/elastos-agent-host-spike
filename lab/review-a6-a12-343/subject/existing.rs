//! Proof that the existing A6/A12 evidence is still the #294 gap.
//! These checks fail if the owner lane later starts presenting tokens
//! or walking `/tmp/elastos/storage` — then this folder can skip that half.

const CENSUS: &str = include_str!("../../agent-conformance/src/census.rs");
const CLEANUP_TEST: &str = include_str!("../../agent-conformance/tests/runtime.rs");
const EFFECTS: &str = include_str!("../../agent-conformance/tests/effects.rs");
const GRANTS: &str = include_str!("../../agent-conformance/tests/common/grants.rs");
const REQUEST: &str =
    include_str!("../../../elastos/crates/elastos-server/src/api/handlers/capability.rs");
const VALIDATE: &str =
    include_str!("../../../elastos/crates/elastos-runtime/src/capability/manager.rs");

pub fn runtime_validate_source() -> &'static str {
    VALIDATE
}

pub fn a6_journeys_omit_token_presentation() -> Result<String, String> {
    for needle in [
        "two_instances_overlap_with_separate_grants",
        "instance_grant_does_not_authorise_sibling",
    ] {
        if !EFFECTS.contains(needle) {
            return Err(format!("effects.rs no longer names {needle}"));
        }
    }
    for (name, source) in [("effects.rs", EFFECTS), ("grants.rs", GRANTS)] {
        for forbidden in [
            "token.capsule",
            "WrongCapsule",
            "from_base64",
            "caller_capsule_id",
        ] {
            if source.contains(forbidden) {
                return Err(format!(
                    "{name} now mentions {forbidden}; existing A6 rows may present a token"
                ));
            }
        }
    }
    Ok(
        "existing A6 journeys still refuse the sibling by fixture deny, not by presenting a session token"
            .into(),
    )
}

pub fn request_path_sends_every_request_to_pending() -> Result<String, String> {
    if !REQUEST.contains("For now, all requests go to pending") {
        return Err("request_capability no longer says every request goes to pending".into());
    }
    Ok(
        "request_capability still sends every request to pending, so a live grant does not change the answer"
            .into(),
    )
}

pub fn census_ignores_runtime_storage() -> Result<String, String> {
    if CENSUS.contains("/tmp/elastos/storage") {
        return Err("census.rs now names /tmp/elastos/storage".into());
    }
    if !CENSUS.contains("outside-root:BLOCKED(AC-006-STORAGE)") {
        return Err("census.rs dropped the AC-006-STORAGE block label".into());
    }
    if !CENSUS.contains("home.temp()") {
        return Err("census.rs no longer inspects home.temp()".into());
    }
    if !CENSUS.contains("pub fn cleanup(") {
        return Err("census.rs no longer exports cleanup".into());
    }
    Ok(
        "existing cleanup census still inspects only the throwaway TMPDIR and labels outside-root BLOCKED"
            .into(),
    )
}

pub fn cleanup_leftover_test_plants_only_in_home_temp() -> Result<String, String> {
    if !CLEANUP_TEST.contains("fn cleanup_census_refuses_each_leftover") {
        return Err("cleanup_census_refuses_each_leftover is gone".into());
    }
    if !CLEANUP_TEST.contains("home.temp().join(\"planted\")") {
        return Err("leftover test no longer plants under home.temp()".into());
    }
    if CLEANUP_TEST.contains("/tmp/elastos/storage") {
        return Err("leftover test now mentions /tmp/elastos/storage".into());
    }
    Ok("cleanup_census_refuses_each_leftover still plants only under the throwaway TMPDIR".into())
}
