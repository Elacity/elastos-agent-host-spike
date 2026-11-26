//! Census of production code entries that start or prepare executable bytes.
//! Each row names its authority inputs as they are today. A source call without
//! a row and a row whose enclosing function moves both fail this test.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use crate::start_census_tests as source;

struct Row {
    file: &'static str,
    function: &'static str,
    call: String,
    kind: &'static str,
    checks: &'static str,
    check_id: &'static str,
    count: usize,
}

fn row(
    file: &'static str,
    function: &'static str,
    call: impl Into<String>,
    kind: &'static str,
    checks: &'static str,
    check_id: &'static str,
    count: usize,
) -> Row {
    Row {
        file,
        function,
        call: call.into(),
        kind,
        checks,
        check_id,
        count,
    }
}

/// The authority input is local to the entry, not inherited from a caller's
/// name. `none` and `checksum` document paths that later slices must gate.
fn own_command_checks() -> &'static str {
    #[cfg(windows)]
    {
        "installed release no-follow file admission is unsupported on Windows; No trusted source configured on a source Home"
    }
    #[cfg(not(windows))]
    {
        "checksum"
    }
}

fn managed_runtime_checks() -> &'static str {
    #[cfg(windows)]
    {
        "managed Runtime process ownership is unsupported on Windows"
    }
    #[cfg(not(windows))]
    {
        "checksum"
    }
}

fn rows() -> Vec<Row> {
    let confined_spawn = ["ProviderBridge::spawn", "_confined"].concat();
    vec![
        row(
            "elastos-runtime/src/capsule/manager.rs",
            "launch_internal",
            "compute.load",
            "legacy module; component refused",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-runtime/src/capsule/manager.rs",
            "launch_internal",
            "compute.start",
            "legacy module; component refused",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_command",
            "spawn()",
            "host process",
            "CID+DID",
            "P2-8",
            1,
        ),
        row(
            "elastos-runtime/src/provider/failure_record.rs",
            "launch",
            "libc::fexecve",
            "confined provider",
            "admitted rights+checked directory+bound executable",
            "B3 S10",
            1,
        ),
        row(
            "elastos-server/src/setup/verified_executable.rs",
            "attach_std",
            "libc::fexecve",
            "installed component",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_confined_model_linux",
            "command",
            "host process",
            "CID+DID",
            "P2-8",
            1,
        ),
        row(
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_confined_model_with_engine_bundle",
            "command",
            "host process",
            "CID+DID",
            "P2-8",
            1,
        ),
        row(
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_with_owned_helpers",
            "command",
            "host process",
            "CID+DID",
            "P2-8",
            1,
        ),
        row(
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_with_timeouts",
            "command",
            "host process",
            "CID+DID",
            "P2-8",
            1,
        ),
        row(
            "elastos-runtime/src/provider/os_entry.rs",
            "macos_command",
            "command",
            "native provider",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-runtime/src/provider/os_entry.rs",
            "macos_start",
            "spawn()",
            "native provider",
            "checked storage+Seatbelt profile",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/agent_admission.rs",
            "verify_agent_host",
            "release capsule",
            "release capsule",
            "CID+DID",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/api/gateway_home_runtime.rs",
            "ensure_home_target_package",
            "Home install",
            "Home app",
            "CID+DID",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/api/gateway_home_terminal.rs",
            "start_home_terminal_session",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/api/gateway_home_terminal.rs",
            "start_home_terminal_session",
            "spawn()",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/api/gateway_server.rs",
            "detect_advertisable_ips",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/carrier.rs",
            "start_carrier_node_with_network",
            "spawn()",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/carrier_service.rs",
            "send_raw_blocking",
            "spawn()",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/carrier_service.rs",
            "spawn",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/carrier_service.rs",
            "spawn",
            "spawn()",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/chat_cmd.rs",
            "return_to_home_if_requested",
            "command",
            "host process",
            own_command_checks(),
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/gateway_cmd.rs",
            "register_installed_ipfs_provider",
            "ProviderBridge::spawn",
            "native provider",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/home_cmd.rs",
            "run_action",
            "command",
            "host process",
            own_command_checks(),
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/home_cmd.rs",
            "run_capsule_action",
            "command",
            "host process",
            own_command_checks(),
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/home_cmd.rs",
            "run_home_cli_renderer",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/main.rs",
            "get_content_registry_with_local_ipfs_backend",
            "ProviderBridge::spawn",
            "native provider",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/main.rs",
            "get_operator_ipfs_bridge",
            "ProviderBridge::spawn",
            "native provider",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/main.rs",
            "get_tunnel_bridge",
            "ProviderBridge::spawn",
            "native provider",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/main.rs",
            "open_browser",
            "command",
            "host process",
            "none",
            "P2-8",
            2,
        ),
        row(
            "elastos-server/src/main.rs",
            "open_browser",
            "spawn()",
            "host process",
            "none",
            "P2-8",
            2,
        ),
        row(
            "elastos-server/src/main.rs",
            "serve_web_capsule",
            "spawn()",
            "host process",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/page_launch.rs",
            "start_and_fill",
            "bundle start",
            "WASM bundle",
            "CID+DID+closure",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/protected_content_config.rs",
            "provision_custody_node_with_installed_provider",
            "command",
            "host process",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/protected_content_config.rs",
            "provision_custody_node_with_installed_provider",
            "spawn()",
            "host process",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/protected_content_runtime.rs",
            "register_inactive_custody_provider",
            "ProviderBridge::spawn",
            "native provider",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/protected_content_runtime.rs",
            "register_protect_provider",
            "ProviderBridge::spawn",
            "native provider",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/protected_content_runtime.rs",
            "register_protected_content_decrypt_provider",
            "ProviderBridge::spawn",
            "native provider",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/publish.rs",
            "run_publish_release",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/publish.rs",
            "run_signed_publication",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/publish.rs",
            "start",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/publish.rs",
            "start",
            "spawn()",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/publish.rs",
            "validate_publish_inputs",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/run_cmd.rs",
            "resolve_capsule_dir",
            "content import",
            "content import",
            "CID",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/run_cmd.rs",
            "run_bundle",
            "bundle start",
            "WASM bundle",
            "CID+DID+closure",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/run_cmd.rs",
            "run_staged_component",
            "staged folder start",
            "WASM bundle",
            "CID+DID+closure",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/runtime.rs",
            "run_by_bundle_observed",
            "bundle start",
            "WASM bundle",
            "CID+DID+closure",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/runtime.rs",
            "run_local_admitted_mode",
            "folder start",
            "folder capsule",
            "none",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/runtime.rs",
            "run_local_with_signer",
            "folder start",
            "folder capsule",
            "none",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/runtime.rs",
            "load_dev_unsigned_component",
            "component.load_admitted",
            "WASM component; dev-only explicit opt-in (dev_mode = true)",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/runtime.rs",
            "run_signer",
            "component.load_admitted",
            "WASM component; folder closure is the root, requires refused",
            "CID+DID+closure",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/runtime.rs",
            "run_signer",
            "provider.load",
            "capsule compute",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/runtime.rs",
            "start_by_bundle",
            "component.load_admitted",
            "WASM component",
            "CID+DID+closure",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/runtime.rs",
            "start_by_bundle",
            "component.load_admitted_sealed",
            "WASM component",
            "CID+DID+closure",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/runtime.rs",
            "start_loaded",
            "provider.start",
            "capsule compute",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/runtime.rs",
            "start_local_with_signer",
            "folder start",
            "folder capsule",
            "none",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/runtime.rs",
            "verify_capsule_signature",
            "release capsule",
            "release capsule",
            "CID+DID",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/runtime.rs",
            "watch_activation",
            "component.start_resident",
            "WASM component",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/runtime_control.rs",
            "current_process_child_pids",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/runtime_control.rs",
            "ensure_managed_runtime",
            "command",
            "host process",
            managed_runtime_checks(),
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/runtime_control.rs",
            "ensure_managed_runtime",
            "spawn()",
            "host process",
            managed_runtime_checks(),
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/runtime_control.rs",
            "process_env_contains_runtime_kind",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/serve_cmd.rs",
            "run_serve",
            "content import",
            "content import",
            "CID",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/serve_cmd.rs",
            "run_serve",
            "spawn()",
            "host process",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/serve_cmd.rs",
            "load_microvm_capsule",
            "provider.load",
            "VM capsule; image check pending 4b-2",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/serve_cmd.rs",
            "run_serve",
            "vm_provider.start",
            "VM capsule; image check pending 4b-2",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/serve_cmd.rs",
            "shell_capsule_command",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/server_infra.rs",
            "register_availability_provider_plane",
            "ProviderBridge::spawn",
            "native provider",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/server_infra.rs",
            "register_chain_provider_plane",
            "ProviderBridge::spawn",
            "native provider",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/server_infra.rs",
            "register_ipfs_provider_plane_with_role",
            "ProviderBridge::spawn",
            "native provider",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/server_infra.rs",
            "setup_server_infrastructure_impl",
            "ProviderBridge::spawn",
            "native provider",
            "checksum",
            "P2-8",
            15,
        ),
        row(
            "elastos-server/src/server_infra.rs",
            "start_did_provider",
            confined_spawn.clone(),
            "native provider",
            "admitted binary+OS gate+confined storage",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/server_infra.rs",
            "start_wallet_provider",
            confined_spawn,
            "native provider",
            "admitted binary+OS gate+confined storage",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/server_infra.rs",
            "spawn_browser_local_exit",
            "command",
            "host process",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/server_infra.rs",
            "spawn_browser_local_exit",
            "spawn()",
            "host process",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/setup.rs",
            "ensure_browser_vm_image_in_context_for_platform",
            "component install",
            "signed release image or source Home dev-pinned image",
            "CID+DID",
            "P2-2",
            2,
        ),
        row(
            "elastos-server/src/setup.rs",
            "ensure_capsule_component_for_home_launch",
            "component install",
            "release component",
            "CID+DID",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/setup.rs",
            "ensure_component_capsule_metadata",
            "component install",
            "release component",
            "CID+DID",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/setup.rs",
            "extract_from_tarball",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/setup.rs",
            "prepare_selected_component_prerequisites",
            "component install",
            "release component",
            "CID+DID",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/setup.rs",
            "probe_arm64_model_engine",
            "command",
            "host process",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/setup.rs",
            "probe_arm64_model_engine",
            "spawn()",
            "host process",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/setup.rs",
            "refresh_support",
            "component install",
            "release component",
            "CID+DID",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/setup.rs",
            "run_with_data_dir",
            "component install",
            "release component",
            "CID+DID",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/setup/browser_config.rs",
            "ensure_host_components",
            "component install",
            "release component",
            "CID+DID",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/setup/browser_config.rs",
            "generate_with_migration",
            "command",
            "host process",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/setup/browser_config.rs",
            "generate_with_migration",
            "spawn()",
            "host process",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/setup/browser_config.rs",
            "probe_native_host",
            "command",
            "host process",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/setup/browser_config.rs",
            "probe_native_host",
            "spawn()",
            "host process",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/setup/browser_linux.rs",
            "enable",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/setup/browser_linux.rs",
            "run_host_command",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/setup/browser_linux.rs",
            "run_host_command",
            "spawn()",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/share_cmd.rs",
            "run_open",
            "content import",
            "content import",
            "CID",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/site_cmd.rs",
            "get_site_bridge",
            "ProviderBridge::spawn",
            "native provider",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/site_cmd.rs",
            "get_tunnel_bridge",
            "ProviderBridge::spawn",
            "native provider",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/stage_cmd.rs",
            "run_staged_folder",
            "bundle start",
            "WASM bundle",
            "CID+DID+closure",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/stage_cmd.rs",
            "stage_bundle",
            "signed stage",
            "bundle stage",
            "CID+DID",
            "P2-2",
            1,
        ),
        row(
            "elastos-server/src/supervisor.rs",
            "handle_request",
            "launch_capsule",
            "VM capsule; image check pending 4b-2",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/supervisor.rs",
            "launch_capsule",
            "vm.start",
            "VM capsule; image check pending 4b-2",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/update.rs",
            "verify_installed_binary_version",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/update.rs",
            "verify_installed_binary_version",
            "spawn()",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/update_controller.rs",
            "command",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/update_controller.rs",
            "exec_controller",
            "command",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/update_controller/child.rs",
            "spawn",
            "spawn()",
            "host process",
            "none",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/webspace_cmd.rs",
            "spawn_webspace_bridge",
            "ProviderBridge::spawn",
            "native provider",
            "checksum",
            "P2-8",
            1,
        ),
        row(
            "elastos-server/src/main.rs",
            "run",
            "release install",
            "release executable",
            "CID+DID",
            "P2-8",
            1,
        ),
    ]
}

/// The spawn census supplies all process starts and compute-provider calls.
/// Add content, Home, install and release entries that can reach such starts.
fn found(sources: &BTreeMap<String, String>) -> BTreeMap<(String, String, String), usize> {
    let mut found = BTreeMap::new();
    for (file, text) in sources {
        for site in source::sites(file, text) {
            if site.label == "register_capsule" {
                continue;
            }
            *found
                .entry((site.file, site.function, site.label))
                .or_default() += 1;
        }
        let code = source::code_only(text);
        // Joined at run time, so this file never holds the literal call that
        // bundle_start_tests counts across the server sources.
        let bundle_start = [".start_by", "_bundle("].concat();
        let bundle_run = [".run_by", "_bundle("].concat();
        let staged_folder = ["::run_staged", "_folder("].concat();
        for (label, needle) in [
            ("command", "Command::new("),
            ("content import", "prepare_capsule_from_content_provider("),
            ("bundle start", bundle_start.as_str()),
            ("bundle start", bundle_run.as_str()),
            ("staged folder start", staged_folder.as_str()),
            ("folder start", ".run_signer("),
            ("Home install", "ensure_capsule_component_for_home_launch("),
            ("release capsule", "verify_installed_release_capsule("),
            ("component install", "download_component("),
            ("signed stage", "stage_bundle_observed("),
            ("release install", "install_release("),
        ] {
            for (at, _) in code.match_indices(needle) {
                // A declaration names an entry, but is not a call. The calls
                // and the generic process/compute sites bind its row below.
                let line = code[..at].rsplit('\n').next().unwrap_or("");
                if line.trim_end().ends_with("fn") {
                    continue;
                }
                let function = source::enclosing_fn(&code, at);
                *found
                    .entry((file.clone(), function, label.to_string()))
                    .or_default() += 1;
            }
        }
    }
    found
}

#[test]
fn every_executable_loader_has_an_authority_row() {
    let mut sources = source::production_sources();
    if let Some(scratch) = std::env::var_os("LOADER_CENSUS_SCRATCH_RUNTIME") {
        sources.insert(
            "elastos-server/src/runtime.rs".to_string(),
            source::without_test_items(
                &fs::read_to_string(scratch).expect("scratch runtime source"),
            ),
        );
    }
    let found = found(&sources);
    let mut listed = BTreeSet::new();
    for row in rows() {
        assert!(matches!(row.check_id, "P2-2" | "P2-8" | "B3 S10"));
        assert!(matches!(
            row.checks,
            "CID+DID+closure"
                | "CID+DID"
                | "CID"
                | "DID"
                | "checksum"
                | "installed release no-follow file admission is unsupported on Windows; No trusted source configured on a source Home"
                | "managed Runtime process ownership is unsupported on Windows"
                | "admitted binary+OS gate+confined storage"
                | "checked storage+Seatbelt profile"
                | "none"
                | "admitted rights+checked directory+bound executable"
        ));
        assert!(!row.kind.is_empty());
        let key = (row.file.to_string(), row.function.to_string(), row.call);
        assert!(listed.insert(key.clone()), "duplicate loader row: {key:?}");
        assert_eq!(
            found.get(&key).copied().unwrap_or(0),
            row.count,
            "stale loader row: {key:?}"
        );
    }
    let missing: Vec<_> = found
        .iter()
        .filter(|(key, _)| !listed.contains(*key))
        .collect();
    assert!(missing.is_empty(), "unlisted loaders: {missing:#?}");
}
mod trust_columns;

#[test]
fn native_provider_spawn_routes_keep_the_checked_executable() {
    let sources = source::production_sources();
    for (file, function, needle) in [
        (
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_command",
            "prepared.configure_command(&mut command)",
        ),
        (
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_confined_model_linux",
            "verify_at_spawn()",
        ),
        (
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_confined_model_linux",
            "Command::new(prepared.exec_path())",
        ),
        (
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_confined_model_linux",
            "Self::spawn_command(",
        ),
        (
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_confined_model_with_engine_bundle",
            "verify_at_spawn()",
        ),
        (
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_confined_model_with_engine_bundle",
            "command.arg(\"-p\").arg(policy).arg(prepared.exec_path())",
        ),
        (
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_confined_model_with_engine_bundle",
            "Self::spawn_command(",
        ),
        (
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_with_owned_helpers",
            "verify_at_spawn()",
        ),
        (
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_with_owned_helpers",
            "Command::new(prepared.exec_path())",
        ),
        (
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_with_owned_helpers",
            "Self::spawn_command(",
        ),
        (
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_with_timeouts",
            "verify_at_spawn()",
        ),
        (
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_with_timeouts",
            "Command::new(prepared.exec_path())",
        ),
        (
            "elastos-runtime/src/provider/bridge.rs",
            "spawn_with_timeouts",
            "Self::spawn_command(",
        ),
        (
            "elastos-runtime/src/provider/failure_record.rs",
            "launch",
            "verify_at_spawn()\n        .map_err(LaunchError::BeforeFork)",
        ),
        (
            "elastos-runtime/src/provider/failure_record.rs",
            "launch",
            "libc::fexecve(executable_fd, argv.as_ptr(), envp.as_ptr())",
        ),
        (
            "elastos-server/src/binaries.rs",
            "checked_native_provider_with_data_dir",
            "verify_installed_component_start(",
        ),
        (
            "elastos-server/src/binaries.rs",
            "checked_executable",
            "verify_installed_component_start(",
        ),
        (
            "elastos-server/src/binaries.rs",
            "checked_executable",
            "signed_checksum()",
        ),
        // A hosted plane admits against the Home it serves, never the
        // default Home.
        (
            "elastos-server/src/server_infra.rs",
            "register_ipfs_provider_plane_with_role",
            "checked_native_provider_with_data_dir(data_dir, binary_path)",
        ),
        (
            "elastos-server/src/server_infra.rs",
            "register_availability_provider_plane",
            "checked_native_provider_with_data_dir(data_dir, binary_path)",
        ),
        (
            "elastos-server/src/server_infra.rs",
            "register_chain_provider_plane",
            "checked_native_provider_with_data_dir(data_dir, binary_path)",
        ),
        (
            "elastos-server/src/protected_content_runtime.rs",
            "register_inactive_custody_provider",
            "checked_native_provider_with_data_dir(data_dir, binary_path)",
        ),
    ] {
        let text = &sources[file];
        let code = source::code_only(text);
        assert!(
            text.match_indices(needle)
                .any(|(at, _)| source::enclosing_fn(&code, at) == function),
            "checked executable route missing: {file}::{function} -> {needle}"
        );
    }
}

fn decl_prefix(prefix: &str) -> bool {
    prefix.split_whitespace().all(|word| {
        word.starts_with("pub")
            || matches!(word, "async" | "unsafe" | "const" | "extern" | "default")
    })
}

fn brace_body(code: &str, from: usize) -> Option<String> {
    let bytes = code.as_bytes();
    let mut depth = 0i32;
    let mut i = from;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"->") {
            i += 2;
            continue;
        }
        match bytes[i] {
            b'(' | b'[' | b'<' => depth += 1,
            b')' | b']' | b'>' if depth > 0 => depth -= 1,
            // A signature that ends in `;` has no body. The `{` of the next
            // item is that item's body. A `;` inside `()` or `[]` (an array
            // length) is not the end of the signature.
            b';' if depth == 0 => return None,
            b'{' if depth == 0 => {
                let open = i;
                let mut braces = 0usize;
                for (at, byte) in bytes[open..].iter().enumerate() {
                    match byte {
                        b'{' => braces += 1,
                        b'}' => {
                            braces -= 1;
                            if braces == 0 {
                                return Some(code[open..=open + at].to_string());
                            }
                        }
                        _ => {}
                    }
                }
                return None;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Production functions, by name. A name that two files define stays a list,
/// and a caller follows it only when one definition is the one in reach.
fn function_index(sources: &BTreeMap<String, String>) -> BTreeMap<String, Vec<(String, String)>> {
    let mut index: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for (file, text) in sources {
        if file == WINDOWS_WALK {
            continue;
        }
        let code = source::code_only(text);
        let bytes = code.as_bytes();
        let mut at = 0;
        while let Some(rel) = code[at..].find("fn ") {
            let fn_at = at + rel;
            let ident_before = fn_at > 0 && {
                let prev = bytes[fn_at - 1];
                prev.is_ascii_alphanumeric() || prev == b'_'
            };
            let line_start = code[..fn_at]
                .rfind('\n')
                .map(|index| index + 1)
                .unwrap_or(0);
            if !ident_before && decl_prefix(code[line_start..fn_at].trim()) {
                let name_at = fn_at + 3;
                let name_len = code[name_at..]
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(code.len() - name_at);
                if name_len > 0 {
                    if let Some(body) = brace_body(&code, name_at + name_len) {
                        index
                            .entry(code[name_at..name_at + name_len].to_string())
                            .or_default()
                            .push((file.clone(), body));
                    }
                }
            }
            at = fn_at + 3;
        }
    }
    index
}

fn calls(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut found = Vec::new();
    for (paren, _) in body.match_indices('(') {
        let mut end = paren;
        while end > 0 && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        let mut start = end;
        while start > 0 && {
            let prev = bytes[start - 1];
            prev.is_ascii_alphanumeric() || prev == b'_'
        } {
            start -= 1;
        }
        if start < end {
            found.push(body[start..end].to_string());
        }
    }
    found
}

fn choose<'a>(
    index: &'a BTreeMap<String, Vec<(String, String)>>,
    name: &str,
    file: &str,
) -> Option<&'a str> {
    let defs = index.get(name)?;
    let same: Vec<_> = defs
        .iter()
        .filter(|(def_file, _)| def_file == file)
        .collect();
    if same.len() == 1 {
        Some(same[0].1.as_str())
    } else if defs.len() == 1 {
        Some(defs[0].1.as_str())
    } else {
        None
    }
}

fn reachable(
    index: &BTreeMap<String, Vec<(String, String)>>,
    file: &str,
    function: &str,
) -> String {
    let mut seen = BTreeSet::new();
    let mut queue = vec![(file.to_string(), function.to_string())];
    let mut text = String::new();
    while let Some((file, name)) = queue.pop() {
        if !seen.insert((file.clone(), name.clone())) {
            continue;
        }
        let Some(body) = choose(index, &name, &file) else {
            continue;
        };
        text.push_str(body);
        text.push('\n');
        let here = index.get(&name).and_then(|defs| {
            let same = defs
                .iter()
                .filter(|(def_file, _)| def_file == &file)
                .count();
            if same == 1 {
                Some(file.clone())
            } else if defs.len() == 1 {
                Some(defs[0].0.clone())
            } else {
                None
            }
        });
        let Some(def_file) = here else {
            continue;
        };
        for called in calls(body) {
            if choose(index, &called, &def_file).is_some() {
                queue.push((def_file.clone(), called));
            }
        }
    }
    text
}

const WINDOWS_WALK: &str = "elastos-bundle-identity/src/windows_walk.rs";

struct Bind {
    file: &'static str,
    function: &'static str,
    /// Census `row.call`, so two rows that share a function stay distinct
    /// binds (for example `start_by_bundle`'s two load calls). Empty when
    /// the bind is not a census row.
    call: String,
    needle: &'static str,
}

/// Every bound row and the needle its code must still hold. A function name
/// of `""` is the whole file, which is how the Windows walk is bound. The
/// bound set is the install and launch paths this slice's checks cover:
/// closure starts that admit a pin, `run_signer`'s folder walk plus its
/// signature and slot-accept checks, the stage walk, and the Windows walk.
fn binds() -> Vec<Bind> {
    let mut binds = Vec::new();
    for row in rows() {
        if row.checks == "CID+DID+closure" && row.function != "run_signer" {
            binds.push(Bind {
                file: row.file,
                function: row.function,
                call: row.call.clone(),
                needle: ".admit_closure_member(data_dir, &pinned",
            });
        }
    }
    // Folder walk, the unpinned-requirement name, the publisher DID check,
    // and the slot-accept check. The refusal text is a string, so code-only
    // blanks it; `requirement.name` is the value that refusal formats.
    for needle in [
        "walk_folder_start(",
        "requirement.name",
        "verify_capsule_signature(",
        "accept_folder_start(",
    ] {
        binds.push(Bind {
            file: "elastos-server/src/runtime.rs",
            function: "run_signer",
            call: String::new(),
            needle,
        });
    }
    binds.push(Bind {
        file: "elastos-server/src/runtime.rs",
        function: "walk_folder_start",
        call: String::new(),
        needle: "checked_bundle_within(",
    });
    for needle in [
        "checked_bundle_within_reported(",
        "empty_folders",
        "check_bundle_signature(",
    ] {
        binds.push(Bind {
            file: "elastos-server/src/stage_cmd.rs",
            function: "stage_bundle",
            call: String::new(),
            needle,
        });
    }
    binds.push(Bind {
        file: WINDOWS_WALK,
        function: "",
        call: String::new(),
        needle: "tally.note_empty(",
    });
    binds
}

fn binding_sources() -> BTreeMap<String, String> {
    let mut sources = source::production_sources();
    let windows = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../elastos-bundle-identity/src/windows_walk.rs"),
    )
    .expect("windows walk")
    .replace("\r\n", "\n");
    sources.insert(WINDOWS_WALK.to_string(), windows);
    sources
}

/// One bind against its needle. Comments and strings are masked through
/// `function_index` / `code_only`, including in `windows_walk.rs`. A miss
/// panics naming this bind's file, function, call, and needle so a plant
/// can tell which bind refused.
fn check_bind(
    index: &BTreeMap<String, Vec<(String, String)>>,
    sources: &BTreeMap<String, String>,
    bind: &Bind,
) {
    let haystack = if bind.function.is_empty() {
        let text = sources
            .get(bind.file)
            .unwrap_or_else(|| panic!("missing {}", bind.file));
        source::code_only(text)
    } else {
        reachable(index, bind.file, bind.function)
    };
    assert!(
        haystack.contains(bind.needle),
        "{}::{} [{}] does not contain {}",
        bind.file,
        bind.function,
        bind.call,
        bind.needle
    );
}

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else {
        String::from("<non-string panic>")
    }
}

/// One check of every bound row against its needles. A miss panics.
fn bind_closure_and_stage(sources: &BTreeMap<String, String>) {
    let pinned = ".admit_closure_member(data_dir, &pinned";
    let binds = binds();
    let closure = binds.iter().filter(|bind| bind.needle == pinned).count();
    assert_eq!(closure, 7, "a closure row was added or dropped");
    let closure_calls: BTreeSet<_> = binds
        .iter()
        .filter(|bind| bind.needle == pinned)
        .map(|bind| (bind.file, bind.function, bind.call.as_str()))
        .collect();
    assert_eq!(
        closure_calls.len(),
        7,
        "a closure bind dropped its call key: {closure_calls:?}"
    );
    assert_eq!(
        rows()
            .iter()
            .filter(|row| row.function == "run_signer" && row.checks == "CID+DID+closure")
            .count(),
        1
    );
    assert_eq!(
        rows()
            .iter()
            .filter(|row| row.function == "stage_bundle" && row.checks == "CID+DID")
            .count(),
        1
    );
    let index = function_index(sources);
    for bind in &binds {
        check_bind(&index, sources, bind);
    }
    let signer = choose(&index, "run_signer", "elastos-server/src/runtime.rs").expect("run_signer");
    assert!(
        !signer.contains("admit_closure_member("),
        "run_signer now admits a pinned member; bind the row to that call"
    );
}

/// The closure rows reach the one pinned walk, and the stage row reaches the
/// report, the empty-folder name, and the signature check. `run_signer`
/// walks the folder, checks the publisher DID, accepts the slot, and names
/// the loose requirement; it does not admit a pin.
#[test]
fn closure_and_stage_rows_bind_to_their_checks() {
    bind_closure_and_stage(&binding_sources());
}

/// Each bound needle, removed from a copy of the source, makes that bind's
/// own check refuse. One plant per bind (not per unique needle), and the
/// panic must name that bind's file, function, call, and needle: a shared
/// pin needle still proves every closure row, and no plant shares another's
/// assertion. The text stays inside a comment, so a raw search would still
/// pass.
#[test]
fn each_bound_needle_stripped_from_a_copy_makes_the_binder_refuse() {
    let sources = binding_sources();
    let binds = binds();
    assert_eq!(
        binds.len(),
        16,
        "a bound row or needle was added or dropped"
    );
    for bind in &binds {
        let planted = sources
            .iter()
            .map(|(file, text)| {
                (
                    file.clone(),
                    text.replace(bind.needle, &format!("/*{}*/", bind.needle)),
                )
            })
            .collect();
        let index = function_index(&planted);
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_bind(&index, &planted, bind);
        }));
        let Err(payload) = refused else {
            panic!(
                "binder still accepts after planting {}::{} [{}] needle {}",
                bind.file, bind.function, bind.call, bind.needle
            );
        };
        let msg = panic_text(payload);
        let call_marker = format!("[{}]", bind.call);
        assert!(
            msg.contains(bind.file)
                && msg.contains(bind.function)
                && msg.contains(&call_marker)
                && msg.contains(bind.needle),
            "plant for {}::{} [{}] needle {} panicked as a different bind: {}",
            bind.file,
            bind.function,
            bind.call,
            bind.needle,
            msg
        );
    }
}

#[test]
fn a_bodiless_signature_does_not_take_the_next_body() {
    let mut sources = BTreeMap::new();
    sources.insert(
        "sample.rs".into(),
        [
            "trait T {",
            "    fn foo();",
            "    fn bar() {",
            "        bar_body()",
            "    }",
            "}",
            "fn array(x: [u8; 4]) {",
            "    array_body()",
            "}",
            "fn returned() -> [u8; 4] {",
            "    returned_body()",
            "}",
            "",
        ]
        .join("\n"),
    );
    let index = function_index(&sources);
    assert!(
        !index.contains_key("foo"),
        "a bodiless signature took a body"
    );
    assert!(index["bar"][0].1.contains("bar_body"));
    assert!(!index["bar"][0].1.contains("array_body"));
    assert!(index["array"][0].1.contains("array_body"));
    assert!(index["returned"][0].1.contains("returned_body"));
}
