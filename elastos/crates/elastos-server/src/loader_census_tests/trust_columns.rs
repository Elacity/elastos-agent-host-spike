//! Source-bound trust columns for the loader census. Values record current checks.

use std::collections::{BTreeMap, BTreeSet};

use super::rows;
use crate::start_census_tests as source;

#[derive(Clone)]
struct TrustColumn {
    file: &'static str,
    function: &'static str,
    call: &'static str,
    class: &'static str,
    trust_root: &'static str,
    verified_when: &'static str,
    evidence: String,
    os_path: &'static str,
}

fn columns() -> Vec<TrustColumn> {
    vec![
        TrustColumn {
            file: "elastos-runtime/src/capsule/manager.rs",
            function: "launch_internal",
            call: "compute.load",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: ["comput", "e.load"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-runtime/src/capsule/manager.rs",
            function: "launch_internal",
            call: "compute.start",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: ["comput", "e.start"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-runtime/src/provider/failure_record.rs",
            function: "launch",
            call: "libc::fexecve",
            class: "n/a",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["libc::fexecve", "(executable_fd"].concat(),
            os_path: "",
        },
        // Installed-component start (slice 2): the held descriptor matched the
        // signed release digest in VerifiedExecutable::prepare.
        TrustColumn {
            file: "elastos-server/src/setup/verified_executable.rs",
            function: "attach_std",
            call: "libc::fexecve",
            class: "n/a",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["libc::fexecve", "(fd, argv_ptrs"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-runtime/src/provider/bridge.rs",
            function: "spawn_command",
            call: "spawn()",
            class: "other",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["prepared.configure_", "command(&mut command)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-runtime/src/provider/bridge.rs",
            function: "spawn_confined_model_linux",
            call: "command",
            class: "other",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["Command::new", "(prepared.exec_path())"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-runtime/src/provider/bridge.rs",
            function: "spawn_confined_model_with_engine_bundle",
            call: "command",
            class: "os-tool",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["Command::new(\"/usr", "/bin/sandbox-exec\")"].concat(),
            os_path: "/usr/bin/sandbox-exec",
        },
        TrustColumn {
            file: "elastos-runtime/src/provider/bridge.rs",
            function: "spawn_with_owned_helpers",
            call: "command",
            class: "other",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["Command::new", "(prepared.exec_path())"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-runtime/src/provider/bridge.rs",
            function: "spawn_with_timeouts",
            call: "command",
            class: "other",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["Command::new", "(prepared.exec_path())"].concat(),
            os_path: "",
        },
        // The macOS confined start checks the storage root's identity and
        // wraps the provider in a Seatbelt profile. Neither checks the
        // executable's bytes; the caller's admission does that.
        TrustColumn {
            file: "elastos-runtime/src/provider/os_entry.rs",
            function: "macos_command",
            call: "command",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::new", "(launcher)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-runtime/src/provider/os_entry.rs",
            function: "macos_start",
            call: "spawn()",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: [".spa", "wn()"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/agent_admission.rs",
            function: "verify_agent_host",
            call: "release capsule",
            class: "n/a",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["verify_installed", "_release_capsule("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/api/gateway_home_runtime.rs",
            function: "ensure_home_target_package",
            call: "Home install",
            class: "n/a",
            trust_root: "components-json-in-data-dir",
            verified_when: "at-every-start",
            evidence: ["ensure_capsule_compo", "nent_for_home_launch("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/api/gateway_home_terminal.rs",
            function: "start_home_terminal_session",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::new(&com", "mand_spec.program)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/api/gateway_home_terminal.rs",
            function: "start_home_terminal_session",
            call: "spawn()",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::new(&com", "mand_spec.program)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/api/gateway_server.rs",
            function: "detect_advertisable_ips",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::new", "(\"hostname\")"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/carrier.rs",
            function: "start_carrier_node_with_network",
            call: "spawn()",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: [".spa", "wn()"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/carrier_service.rs",
            function: "send_raw_blocking",
            call: "spawn()",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["self.s", "pawn()?"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/carrier_service.rs",
            function: "spawn",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::new(&s", "elf.binary_path)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/carrier_service.rs",
            function: "spawn",
            call: "spawn()",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::new(&s", "elf.binary_path)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/chat_cmd.rs",
            function: "return_to_home_if_requested",
            call: "command",
            class: "own-binary",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command:", ":new(exe)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/gateway_cmd.rs",
            function: "register_installed_ipfs_provider",
            call: "ProviderBridge::spawn",
            class: "n/a",
            trust_root: "components-json-in-data-dir",
            verified_when: "at-every-start",
            evidence: ["ProviderBr", "idge::spawn"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/home_cmd.rs",
            function: "run_action",
            call: "command",
            class: "own-binary",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command:", ":new(exe)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/home_cmd.rs",
            function: "run_capsule_action",
            call: "command",
            class: "own-binary",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command:", ":new(exe)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/home_cmd.rs",
            function: "run_home_cli_renderer",
            call: "command",
            class: "release-component",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["Command::ne", "w(prepared.exec_path())"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/main.rs",
            function: "get_content_registry_with_local_ipfs_backend",
            call: "ProviderBridge::spawn",
            class: "n/a",
            trust_root: "components-json-in-data-dir",
            verified_when: "at-every-start",
            evidence: ["ProviderBr", "idge::spawn"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/main.rs",
            function: "get_operator_ipfs_bridge",
            call: "ProviderBridge::spawn",
            class: "n/a",
            trust_root: "components-json-in-data-dir",
            verified_when: "at-every-start",
            evidence: ["ProviderBr", "idge::spawn"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/main.rs",
            function: "get_tunnel_bridge",
            call: "ProviderBridge::spawn",
            class: "n/a",
            trust_root: "components-json-in-data-dir",
            verified_when: "at-every-start",
            evidence: ["ProviderBr", "idge::spawn"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/main.rs",
            function: "open_browser",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command:", ":new(cmd)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/main.rs",
            function: "open_browser",
            call: "spawn()",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command:", ":new(cmd)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/main.rs",
            function: "serve_web_capsule",
            call: "spawn()",
            class: "release-component",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["find_installed_prov", "ider_binary(\"shell\")"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/page_launch.rs",
            function: "start_and_fill",
            call: "bundle start",
            class: "n/a",
            trust_root: "staged-cid",
            verified_when: "at-stage-and-start",
            evidence: [".start_b", "y_bundle("].concat(),
            os_path: "",
        },
        // Custody provisioning requires a signed digest before command
        // creation; the source-Home dev_mode path is refused before spawn.
        TrustColumn {
            file: "elastos-server/src/protected_content_config.rs",
            function: "provision_custody_node_with_installed_provider",
            call: "command",
            class: "release-component",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["Command::n", "ew(prepared.exec_path())"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/protected_content_config.rs",
            function: "provision_custody_node_with_installed_provider",
            call: "spawn()",
            class: "release-component",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["Command::n", "ew(prepared.exec_path())"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/protected_content_runtime.rs",
            function: "register_inactive_custody_provider",
            call: "ProviderBridge::spawn",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: ["ProviderBr", "idge::spawn; verified via setup_server_infrastructure_impl; not verified via ProviderPlane::register"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/protected_content_runtime.rs",
            function: "register_protect_provider",
            call: "ProviderBridge::spawn",
            class: "n/a",
            trust_root: "components-json-in-data-dir",
            verified_when: "at-every-start",
            evidence: ["ProviderBr", "idge::spawn"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/protected_content_runtime.rs",
            function: "register_protected_content_decrypt_provider",
            call: "ProviderBridge::spawn",
            class: "n/a",
            trust_root: "components-json-in-data-dir",
            verified_when: "at-every-start",
            evidence: ["ProviderBr", "idge::spawn"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/publish.rs",
            function: "run_publish_release",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::n", "ew(\"bash\")"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/publish.rs",
            function: "run_signed_publication",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::n", "ew(\"bash\")"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/publish.rs",
            function: "start",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::ne", "w(provider)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/publish.rs",
            function: "start",
            call: "spawn()",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::ne", "w(provider)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/publish.rs",
            function: "validate_publish_inputs",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::ne", "w(\"python3\")"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/run_cmd.rs",
            function: "resolve_capsule_dir",
            call: "content import",
            class: "n/a",
            trust_root: "content-cid",
            verified_when: "at-every-start",
            evidence: ["prepare_capsule_fro", "m_content_provider("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/run_cmd.rs",
            function: "run_bundle",
            call: "bundle start",
            class: "n/a",
            trust_root: "staged-cid",
            verified_when: "at-stage-and-start",
            evidence: [".run_b", "y_bundle(&data_dir"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/run_cmd.rs",
            function: "run_staged_component",
            call: "staged folder start",
            class: "n/a",
            trust_root: "staged-cid",
            verified_when: "at-stage-and-start",
            evidence: ["::run_staged", "_folder("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime.rs",
            function: "run_by_bundle_observed",
            call: "bundle start",
            class: "n/a",
            trust_root: "staged-cid",
            verified_when: "at-stage-and-start",
            evidence: [".start_b", "y_bundle("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime.rs",
            function: "run_local_admitted_mode",
            call: "folder start",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: [".run_s", "igner("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime.rs",
            function: "run_local_with_signer",
            call: "folder start",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: [".run_s", "igner("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime.rs",
            function: "run_signer",
            call: "component.load_admitted",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: ["component.l", "oad_admitted"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime.rs",
            function: "run_signer",
            call: "provider.load",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: ["provid", "er.load"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime.rs",
            function: "start_by_bundle",
            call: "component.load_admitted",
            class: "n/a",
            trust_root: "staged-cid",
            verified_when: "at-stage-and-start",
            evidence: ["component.l", "oad_admitted"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime.rs",
            function: "start_by_bundle",
            call: "component.load_admitted_sealed",
            class: "n/a",
            trust_root: "staged-cid",
            verified_when: "at-stage-and-start",
            evidence: ["component.load_", "admitted_sealed"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime.rs",
            function: "start_loaded",
            call: "provider.start",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: ["provide", "r.start"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime.rs",
            function: "start_local_with_signer",
            call: "folder start",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: [".run_s", "igner("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime.rs",
            function: "verify_capsule_signature",
            call: "release capsule",
            class: "n/a",
            trust_root: "publisher-did-signature",
            verified_when: "at-every-start",
            evidence: ["verify_installed", "_release_capsule("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime.rs",
            function: "watch_activation",
            call: "component.start_resident",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: ["component.st", "art_resident"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime_control.rs",
            function: "current_process_child_pids",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::", "new(\"ps\")"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime_control.rs",
            function: "ensure_managed_runtime",
            call: "command",
            class: "own-binary",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::ne", "w(&self_exe)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime_control.rs",
            function: "ensure_managed_runtime",
            call: "spawn()",
            class: "own-binary",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::ne", "w(&self_exe)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/runtime_control.rs",
            function: "process_env_contains_runtime_kind",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::", "new(\"ps\")"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/serve_cmd.rs",
            function: "run_serve",
            call: "content import",
            class: "n/a",
            trust_root: "content-cid",
            verified_when: "at-every-start",
            evidence: ["prepare_capsule_fro", "m_content_provider("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/serve_cmd.rs",
            function: "run_serve",
            call: "spawn()",
            class: "release-component",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["find_installed_prov", "ider_binary(\"shell\")"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/serve_cmd.rs",
            function: "load_microvm_capsule",
            call: "provider.load",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: [".load(capsule_", "dir, manifest)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/serve_cmd.rs",
            function: "run_serve",
            call: "vm_provider.start",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: [".start(", "&handle)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/serve_cmd.rs",
            function: "shell_capsule_command",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::new", "(shell_path)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/server_infra.rs",
            function: "register_availability_provider_plane",
            call: "ProviderBridge::spawn",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: ["ProviderBr", "idge::spawn; verified via setup_server_infrastructure_impl; not verified via ProviderPlane::register"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/server_infra.rs",
            function: "register_chain_provider_plane",
            call: "ProviderBridge::spawn",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: ["ProviderBr", "idge::spawn; separate verified spawn via setup_server_infrastructure_impl; not verified via ProviderPlane::register"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/server_infra.rs",
            function: "register_ipfs_provider_plane_with_role",
            call: "ProviderBridge::spawn",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: ["ProviderBr", "idge::spawn; verified via setup_server_infrastructure_impl; not verified via register_ipfs_provider_plane through ProviderPlane::register"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/server_infra.rs",
            function: "setup_server_infrastructure_impl",
            call: "ProviderBridge::spawn",
            class: "n/a",
            trust_root: "components-json-in-data-dir",
            verified_when: "at-every-start",
            evidence: ["ProviderBr", "idge::spawn"].concat(),
            os_path: "",
        },
        // AdmittedProvider::admit checks the binary's checksum against the
        // data-dir components.json at each start. It reads the release
        // signer but does not check the binary against it.
        TrustColumn {
            file: "elastos-server/src/server_infra.rs",
            function: "start_did_provider",
            call: concat!("ProviderBridge::spawn", "_confined"),
            class: "n/a",
            trust_root: "components-json-in-data-dir",
            verified_when: "at-every-start",
            evidence: ["ProviderBridge::", "spawn_confined("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/server_infra.rs",
            function: "spawn_browser_local_exit",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::", "new(path)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/server_infra.rs",
            function: "spawn_browser_local_exit",
            call: "spawn()",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::", "new(path)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup.rs",
            function: "ensure_browser_vm_image_in_context",
            call: "component install",
            class: "n/a",
            trust_root: "release-signature",
            verified_when: "at-install-only",
            evidence: ["download_", "component("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup.rs",
            function: "ensure_capsule_component_for_home_launch",
            call: "component install",
            class: "n/a",
            trust_root: "release-signature",
            verified_when: "at-install-only",
            evidence: ["download_", "component("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup.rs",
            function: "ensure_component_capsule_metadata",
            call: "component install",
            class: "n/a",
            trust_root: "release-signature",
            verified_when: "at-install-only",
            evidence: ["download_", "component("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup.rs",
            function: "extract_from_tarball",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::", "new(\"tar\")"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup.rs",
            function: "prepare_selected_component_prerequisites",
            call: "component install",
            class: "n/a",
            trust_root: "release-signature",
            verified_when: "at-install-only",
            evidence: ["download_", "component("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup.rs",
            function: "probe_arm64_model_engine",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::", "new(path)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup.rs",
            function: "probe_arm64_model_engine",
            call: "spawn()",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::", "new(path)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup.rs",
            function: "refresh_support",
            call: "component install",
            class: "n/a",
            trust_root: "release-signature",
            verified_when: "at-install-only",
            evidence: ["download_", "component("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup.rs",
            function: "run_with_data_dir",
            call: "component install",
            class: "n/a",
            trust_root: "release-signature",
            verified_when: "at-install-only",
            evidence: ["download_", "component("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup/browser_config.rs",
            function: "ensure_host_components",
            call: "component install",
            class: "n/a",
            trust_root: "release-signature",
            verified_when: "at-install-only",
            evidence: ["download_", "component("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup/browser_config.rs",
            function: "generate_with_migration",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::", "new(node)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup/browser_config.rs",
            function: "generate_with_migration",
            call: "spawn()",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::", "new(node)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup/browser_config.rs",
            function: "probe_native_host",
            call: "command",
            class: "other",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["Command::n", "ew(prepared.exec_path())"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup/browser_config.rs",
            function: "probe_native_host",
            call: "spawn()",
            class: "other",
            trust_root: "release-signature",
            verified_when: "at-every-start",
            evidence: ["Command::n", "ew(prepared.exec_path())"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup/browser_linux.rs",
            function: "enable",
            call: "command",
            class: "os-tool",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::new(", "\"/usr/bin/id\")"].concat(),
            os_path: "/usr/bin/id",
        },
        TrustColumn {
            file: "elastos-server/src/setup/browser_linux.rs",
            function: "run_host_command",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::n", "ew(program)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/setup/browser_linux.rs",
            function: "run_host_command",
            call: "spawn()",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::n", "ew(program)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/share_cmd.rs",
            function: "run_open",
            call: "content import",
            class: "n/a",
            trust_root: "content-cid",
            verified_when: "at-every-start",
            evidence: ["prepare_capsule_fro", "m_content_provider("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/site_cmd.rs",
            function: "get_site_bridge",
            call: "ProviderBridge::spawn",
            class: "n/a",
            trust_root: "components-json-in-data-dir",
            verified_when: "at-every-start",
            evidence: ["ProviderBr", "idge::spawn"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/site_cmd.rs",
            function: "get_tunnel_bridge",
            call: "ProviderBridge::spawn",
            class: "n/a",
            trust_root: "components-json-in-data-dir",
            verified_when: "at-every-start",
            evidence: ["ProviderBr", "idge::spawn"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/stage_cmd.rs",
            function: "run_staged_folder",
            call: "bundle start",
            class: "n/a",
            trust_root: "staged-cid",
            verified_when: "at-stage-and-start",
            evidence: ["runtime.run_b", "y_bundle(data_dir, &cid"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/stage_cmd.rs",
            function: "stage_bundle",
            call: "signed stage",
            class: "n/a",
            trust_root: "publisher-did-signature",
            verified_when: "at-stage-and-start",
            evidence: ["stage_bundl", "e_observed("].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/supervisor.rs",
            function: "handle_request",
            call: "launch_capsule",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: ["launch_", "capsule"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/supervisor.rs",
            function: "launch_capsule",
            call: "vm.start",
            class: "n/a",
            trust_root: "none",
            verified_when: "never",
            evidence: ["vm.s", "tart"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/update.rs",
            function: "verify_installed_binary_version",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::ne", "w(bin_path)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/update.rs",
            function: "verify_installed_binary_version",
            call: "spawn()",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::ne", "w(bin_path)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/update_controller.rs",
            function: "command",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::n", "ew(binary)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/update_controller.rs",
            function: "exec_controller",
            call: "command",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["Command::new", "(controller)"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/update_controller/child.rs",
            function: "spawn",
            call: "spawn()",
            class: "other",
            trust_root: "none",
            verified_when: "never",
            evidence: ["command", ".spawn()"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/webspace_cmd.rs",
            function: "spawn_webspace_bridge",
            call: "ProviderBridge::spawn",
            class: "n/a",
            trust_root: "components-json-in-data-dir",
            verified_when: "at-every-start",
            evidence: ["ProviderBr", "idge::spawn"].concat(),
            os_path: "",
        },
        TrustColumn {
            file: "elastos-server/src/main.rs",
            function: "run",
            call: "release install",
            class: "n/a",
            trust_root: "release-signature",
            verified_when: "at-install-only",
            evidence: ["install_", "release("].concat(),
            os_path: "",
        },
    ]
}

/// The caller-side check a row relies on. The row's function spawns a program
/// path it receives as a parameter, so the row records what that function
/// checks (none), and the caller named here performs the check. `check` must
/// appear in `caller_function` in `caller_file`.
struct Handoff {
    file: &'static str,
    function: &'static str,
    call: &'static str,
    caller_file: &'static str,
    caller_function: &'static str,
    check: String,
}

fn handoffs() -> Vec<Handoff> {
    vec![
        Handoff {
            file: "elastos-server/src/serve_cmd.rs",
            function: "shell_capsule_command",
            call: "command",
            caller_file: "elastos-server/src/serve_cmd.rs",
            caller_function: "run_serve",
            check: ["verify_installed_", "component_start("].concat(),
        },
        Handoff {
            file: "elastos-server/src/serve_cmd.rs",
            function: "shell_capsule_command",
            call: "command",
            caller_file: "elastos-server/src/main.rs",
            caller_function: "serve_web_capsule",
            check: ["verify_installed_", "component_start("].concat(),
        },
        Handoff {
            file: "elastos-server/src/server_infra.rs",
            function: "spawn_browser_local_exit",
            call: "command",
            caller_file: "elastos-server/src/server_infra.rs",
            caller_function: "setup_server_infrastructure_impl",
            check: ["verify_provider_", "binary(\"browser-local-exit\""].concat(),
        },
        Handoff {
            file: "elastos-server/src/server_infra.rs",
            function: "spawn_browser_local_exit",
            call: "spawn()",
            caller_file: "elastos-server/src/server_infra.rs",
            caller_function: "setup_server_infrastructure_impl",
            check: ["verify_provider_", "binary(\"browser-local-exit\""].concat(),
        },
        Handoff {
            file: "elastos-server/src/setup.rs",
            function: "probe_arm64_model_engine",
            call: "command",
            caller_file: "elastos-server/src/setup.rs",
            caller_function: "write_cache_metadata",
            check: ["local_model_engine_", "receipt_args("].concat(),
        },
        Handoff {
            file: "elastos-server/src/setup.rs",
            function: "probe_arm64_model_engine",
            call: "spawn()",
            caller_file: "elastos-server/src/setup.rs",
            caller_function: "write_cache_metadata",
            check: ["local_model_engine_", "receipt_args("].concat(),
        },
        Handoff {
            file: "elastos-server/src/setup/browser_config.rs",
            function: "generate_with_migration",
            call: "command",
            caller_file: "elastos-server/src/setup/browser_config.rs",
            caller_function: "configure",
            check: ["host_program(data, ", "\"node\")"].concat(),
        },
        Handoff {
            file: "elastos-server/src/setup/browser_config.rs",
            function: "generate_with_migration",
            call: "spawn()",
            caller_file: "elastos-server/src/setup/browser_config.rs",
            caller_function: "configure",
            check: ["host_program(data, ", "\"node\")"].concat(),
        },
        Handoff {
            file: "elastos-server/src/setup/browser_config.rs",
            function: "probe_native_host",
            call: "command",
            caller_file: "elastos-server/src/setup/browser_config.rs",
            caller_function: "native_host_available",
            check: ["verify_installed_", "component_start("].concat(),
        },
        Handoff {
            file: "elastos-server/src/setup/browser_config.rs",
            function: "probe_native_host",
            call: "spawn()",
            caller_file: "elastos-server/src/setup/browser_config.rs",
            caller_function: "native_host_available",
            check: ["verify_installed_", "component_start("].concat(),
        },
    ]
}

/// Direct production callers for rows whose binary check can be in a caller.
/// An absent check records the value of that caller's path to the spawn.
struct CallerPath {
    row_file: &'static str,
    row_function: &'static str,
    caller_file: &'static str,
    caller_function: &'static str,
    check: Option<String>,
}

fn caller_paths() -> Vec<CallerPath> {
    let infra = "elastos-server/src/server_infra.rs";
    let host = "elastos-server/src/provider_host.rs";
    let runtime = "elastos-server/src/protected_content_runtime.rs";
    vec![
        CallerPath {
            row_file: runtime,
            row_function: "register_inactive_custody_provider",
            caller_file: infra,
            caller_function: "setup_server_infrastructure_impl",
            check: Some(["verify_provider_", "binary(\"custody-provider\""].concat()),
        },
        CallerPath {
            row_file: runtime,
            row_function: "register_inactive_custody_provider",
            caller_file: host,
            caller_function: "register",
            check: None,
        },
        CallerPath {
            row_file: runtime,
            row_function: "register_protect_provider",
            caller_file: infra,
            caller_function: "setup_server_infrastructure_impl",
            check: Some(
                [
                    "verify_provider_",
                    "binary(\"protected-content-protect-provider\"",
                ]
                .concat(),
            ),
        },
        CallerPath {
            row_file: runtime,
            row_function: "register_protected_content_decrypt_provider",
            caller_file: infra,
            caller_function: "setup_server_infrastructure_impl",
            check: Some(
                [
                    "verify_provider_",
                    "binary(\"protected-content-decrypt-provider\"",
                ]
                .concat(),
            ),
        },
        CallerPath {
            row_file: infra,
            row_function: "register_availability_provider_plane",
            caller_file: infra,
            caller_function: "setup_server_infrastructure_impl",
            check: Some(["verify_provider_", "binary(\"availability-provider\""].concat()),
        },
        CallerPath {
            row_file: infra,
            row_function: "register_availability_provider_plane",
            caller_file: host,
            caller_function: "register",
            check: None,
        },
        CallerPath {
            row_file: infra,
            row_function: "register_chain_provider_plane",
            caller_file: host,
            caller_function: "register",
            check: None,
        },
        CallerPath {
            row_file: infra,
            row_function: "register_ipfs_provider_plane_with_role",
            caller_file: infra,
            caller_function: "setup_server_infrastructure_impl",
            check: Some(
                [
                    "resolve_verified_native_provider_",
                    "binary(\"ipfs-provider\"",
                ]
                .concat(),
            ),
        },
        CallerPath {
            row_file: infra,
            row_function: "register_ipfs_provider_plane_with_role",
            caller_file: infra,
            caller_function: "register_ipfs_provider_plane",
            check: None,
        },
    ]
}

fn production_callers(
    sources: &BTreeMap<String, String>,
    function: &str,
) -> BTreeSet<(String, String)> {
    let mut found = BTreeSet::new();
    for (file, text) in sources {
        if !file.starts_with("elastos-server/src/") {
            continue;
        }
        let code = source::code_only(text);
        for (at, _) in code.match_indices(function) {
            let before = &code[..at];
            if before
                .as_bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                || before.trim_end().ends_with("fn")
                || !code[at + function.len()..].trim_start().starts_with('(')
            {
                continue;
            }
            let caller = source::enclosing_fn(&code, at);
            if !caller.is_empty() {
                found.insert((file.clone(), caller));
            }
        }
    }
    found
}

fn assert_caller_paths(sources: &BTreeMap<String, String>) {
    let paths = caller_paths();
    for row in paths
        .iter()
        .map(|path| (path.row_file, path.row_function))
        .collect::<BTreeSet<_>>()
    {
        let listed: BTreeSet<_> = paths
            .iter()
            .filter(|path| (path.row_file, path.row_function) == row)
            .map(|path| {
                (
                    path.caller_file.to_string(),
                    path.caller_function.to_string(),
                )
            })
            .collect();
        assert_eq!(
            production_callers(sources, row.1),
            listed,
            "production callers changed for {}::{}",
            row.0,
            row.1
        );
        let column = columns()
            .into_iter()
            .find(|column| (column.file, column.function) == row)
            .unwrap();
        let all_checked = paths
            .iter()
            .filter(|path| (path.row_file, path.row_function) == row)
            .all(|path| path.check.is_some());
        assert_eq!(
            column.trust_root == "components-json-in-data-dir",
            all_checked,
            "weakest caller path changed for {}::{}",
            row.0,
            row.1
        );
    }
    for path in paths.iter().filter(|path| path.check.is_some()) {
        let check = path.check.as_ref().unwrap();
        let text = &sources[path.caller_file];
        let code = source::code_only(text);
        assert!(
            text.match_indices(check.as_str())
                .any(|(at, _)| source::enclosing_fn(&code, at) == path.caller_function),
            "caller check changed in {}::{} for {}::{}",
            path.caller_file,
            path.caller_function,
            path.row_file,
            path.row_function
        );
    }
}

#[test]
fn trust_columns_cover_each_loader_and_bind_to_source() {
    let listed = rows();
    let columns = columns();
    let mut census = BTreeSet::new();
    for row in &listed {
        assert!(
            census.insert((row.file, row.function, row.call.as_str())),
            "duplicate census key"
        );
    }
    let mut overlay = BTreeSet::new();
    for column in &columns {
        let key = (column.file, column.function, column.call);
        assert!(overlay.insert(key), "duplicate overlay key: {key:?}");
        assert!(census.contains(&key), "overlay lacks census row: {key:?}");
        let row = listed
            .iter()
            .find(|row| (row.file, row.function, row.call.as_str()) == key)
            .unwrap();
        if row.kind == "host process" {
            assert!(
                matches!(
                    column.class,
                    "own-binary" | "release-component" | "os-tool" | "other"
                ),
                "host row lacks class: {key:?}"
            );
        } else {
            assert_eq!(column.class, "n/a", "non-host row has class: {key:?}");
        }
    }
    let missing: Vec<_> = census.difference(&overlay).collect();
    assert!(
        missing.is_empty(),
        "census rows lack trust columns: {missing:?}"
    );

    let sources = source::production_sources();
    for column in &columns {
        let text = &sources[column.file];
        let code = source::code_only(text);
        assert!(
            !column.evidence.is_empty(),
            "empty source evidence: {:?}",
            (column.file, column.function, column.call)
        );
        let expression = column.evidence.split(';').next().unwrap();
        assert!(
            text.match_indices(expression).any(|(at, _)| {
                source::enclosing_fn(&code, at) == column.function
                    && code[at..at + expression.len()]
                        .chars()
                        .any(|ch| !ch.is_whitespace())
            }),
            "changed source expression: {:?} in {}::{}",
            column.evidence,
            column.file,
            column.function
        );
        if column.class == "os-tool" {
            assert!(
                column.os_path.starts_with('/'),
                "OS program is relative: {}",
                column.os_path
            );
            assert!(
                column.evidence.contains(column.os_path),
                "OS path is absent from source evidence"
            );
        } else {
            assert!(column.os_path.is_empty(), "unexpected OS path");
        }
        if column.class == "own-binary" {
            let origin = ["current", "_exe("].concat();
            assert!(
                text.match_indices(origin.as_str())
                    .any(|(at, _)| source::enclosing_fn(&code, at) == column.function),
                "own binary path is no longer current_exe: {key:?}",
                key = (column.file, column.function, column.call)
            );
        }
    }

    // Each handoff row records caller input, and the check it names stays in
    // the named caller.
    let handoffs = handoffs();
    let mut handed = BTreeSet::new();
    for handoff in &handoffs {
        let key = (handoff.file, handoff.function, handoff.call);
        assert!(
            handed.insert((key, handoff.caller_file, handoff.caller_function)),
            "duplicate handoff caller: {key:?}"
        );
        assert!(overlay.contains(&key), "handoff lacks overlay row: {key:?}");
        let column = columns
            .iter()
            .find(|column| (column.file, column.function, column.call) == key)
            .unwrap();
        assert_eq!(
            column.class, "other",
            "handoff row no longer records caller input: {key:?}"
        );
        let text = &sources[handoff.caller_file];
        let code = source::code_only(text);
        assert!(
            text.match_indices(handoff.check.as_str())
                .any(|(at, _)| source::enclosing_fn(&code, at) == handoff.caller_function),
            "caller check moved out of {}::{} for {key:?}",
            handoff.caller_file,
            handoff.caller_function
        );
    }
    for row in handoffs
        .iter()
        .map(|handoff| (handoff.file, handoff.function, handoff.call))
        .collect::<BTreeSet<_>>()
    {
        let listed: BTreeSet<_> = handoffs
            .iter()
            .filter(|handoff| (handoff.file, handoff.function, handoff.call) == row)
            .map(|handoff| {
                (
                    handoff.caller_file.to_string(),
                    handoff.caller_function.to_string(),
                )
            })
            .collect();
        assert_eq!(
            production_callers(&sources, row.1),
            listed,
            "production callers changed for handoff {row:?}"
        );
    }

    assert_caller_paths(&sources);

    // Count each expression in the functions with several loader sites. A
    // matching expression elsewhere in the same function cannot stand in for
    // a changed site.
    for (file, function, expression, expected) in [
        (
            "elastos-server/src/main.rs",
            "open_browser",
            ["Command::", "new(cmd)"].concat(),
            1,
        ),
        (
            "elastos-server/src/main.rs",
            "open_browser",
            ["Command::", "new(\"open\")"].concat(),
            1,
        ),
        (
            "elastos-server/src/server_infra.rs",
            "setup_server_infrastructure_impl",
            ["ProviderBridge::", "spawn(&binary_path, config)"].concat(),
            1,
        ),
        (
            "elastos-server/src/server_infra.rs",
            "setup_server_infrastructure_impl",
            ["ProviderBridge::", "spawn(&path, did_config)"].concat(),
            0,
        ),
        (
            "elastos-server/src/server_infra.rs",
            "start_did_provider",
            ["ProviderBridge::", "spawn_confined("].concat(),
            1,
        ),
        (
            "elastos-server/src/server_infra.rs",
            "setup_server_infrastructure_impl",
            ["ProviderBridge::", "spawn(&path, block_graph_config)"].concat(),
            1,
        ),
        (
            "elastos-server/src/server_infra.rs",
            "setup_server_infrastructure_impl",
            ["ProviderBridge::", "spawn(&path, object_config)"].concat(),
            1,
        ),
        (
            "elastos-server/src/server_infra.rs",
            "setup_server_infrastructure_impl",
            ["ProviderBridge::", "spawn(&path, webspace_config)"].concat(),
            1,
        ),
        (
            "elastos-server/src/server_infra.rs",
            "setup_server_infrastructure_impl",
            ["ProviderBridge::", "spawn(&path, media_config)"].concat(),
            1,
        ),
        (
            "elastos-server/src/server_infra.rs",
            "setup_server_infrastructure_impl",
            ["ProviderBridge::", "spawn(&path, generic_chain_config)"].concat(),
            1,
        ),
        (
            "elastos-server/src/server_infra.rs",
            "setup_server_infrastructure_impl",
            ["ProviderBridge::", "spawn(&path, Default::default())"].concat(),
            1,
        ),
        (
            "elastos-server/src/server_infra.rs",
            "setup_server_infrastructure_impl",
            ["&checked_native_provider", "(&path)"].concat(),
            4,
        ),
        (
            "elastos-server/src/server_infra.rs",
            "setup_server_infrastructure_impl",
            ["ProviderBridge::", "spawn(&path, exit_config)"].concat(),
            1,
        ),
        (
            "elastos-server/src/server_infra.rs",
            "setup_server_infrastructure_impl",
            ["ProviderBridge::", "spawn(&path, wallet_config)"].concat(),
            1,
        ),
    ] {
        let text = &sources[file];
        let code = source::code_only(text);
        let found = text
            .match_indices(&expression)
            .filter(|(at, _)| source::enclosing_fn(&code, *at) == function)
            .count();
        assert_eq!(
            found, expected,
            "changed source expression count: {file}::{function} {expression}"
        );
    }
}

#[test]
fn new_unchecked_production_caller_turns_caller_path_red() {
    let mut sources = source::production_sources();
    let file = "elastos-server/src/server_infra.rs";
    sources.get_mut(file).unwrap().push_str(
        "\nfn planted_caller(registry: &std::sync::Arc<elastos_runtime::provider::ProviderRegistry>, path: &std::path::Path) { let _ = elastos_server::protected_content_runtime::register_protect_provider(registry, path); }\n",
    );
    assert!(std::panic::catch_unwind(|| assert_caller_paths(&sources)).is_err());
}

#[test]
fn trust_column_counts_and_chokepoint_queue() {
    let columns = columns();
    let count = |field: fn(&TrustColumn) -> &str| {
        let mut counts = BTreeMap::<&str, usize>::new();
        for column in &columns {
            *counts.entry(field(column)).or_default() += 1;
        }
        counts
    };
    let classes = count(|column| column.class);
    let roots = count(|column| column.trust_root);
    let times = count(|column| column.verified_when);
    let to_gate = columns
        .iter()
        .filter(|column| {
            matches!(column.class, "release-component" | "other")
                && matches!(column.trust_root, "none" | "components-json-in-data-dir")
        })
        .count();
    println!("loader trust rows={} classes={classes:?} roots={roots:?} verified_when={times:?} to_gate={to_gate}", columns.len());
    assert_eq!(columns.len(), 103);
    assert_eq!(classes.get("n/a"), Some(&54));
    assert_eq!(classes.get("os-tool"), Some(&2));
    assert_eq!(classes.get("other"), Some(&37));
    assert_eq!(classes.get("own-binary"), Some(&5));
    assert_eq!(classes.get("release-component"), Some(&5));
    assert_eq!(roots.get("components-json-in-data-dir"), Some(&12));
    assert_eq!(roots.get("content-cid"), Some(&3));
    assert_eq!(roots.get("none"), Some(&56));
    assert_eq!(roots.get("publisher-did-signature"), Some(&2));
    assert_eq!(roots.get("release-signature"), Some(&23));
    assert_eq!(roots.get("staged-cid"), Some(&7));
    assert_eq!(times.get("at-every-start"), Some(&31));
    assert_eq!(times.get("at-install-only"), Some(&8));
    assert_eq!(times.get("at-stage-and-start"), Some(&8));
    assert_eq!(times.get("never"), Some(&56));
    assert_eq!(to_gate, 31);
}

#[test]
fn installed_component_start_callers_keep_the_signed_gate() {
    let sources = source::production_sources();
    let browser = &sources["elastos-server/src/setup/browser_config.rs"];
    let browser_code = source::code_only(browser);
    let start_gate = ["verify_installed_", "component_start("].concat();
    assert!(
        browser
            .match_indices(&start_gate)
            .all(|(at, _)| { source::enclosing_fn(&browser_code, at) != "browser_available" }),
        "browser_available remains pure; the catalogue host check owns release verification"
    );
    for (file, function) in [
        ("elastos-server/src/home_cmd.rs", "run_home_cli_renderer"),
        ("elastos-server/src/main.rs", "serve_web_capsule"),
        (
            "elastos-server/src/protected_content_config.rs",
            "provision_custody_node_with_installed_provider",
        ),
        ("elastos-server/src/serve_cmd.rs", "run_serve"),
        (
            "elastos-server/src/setup/browser_config.rs",
            "native_host_available",
        ),
    ] {
        let text = &sources[file];
        let code = source::code_only(text);
        let gate = ["verify_installed_", "component_start("].concat();
        assert!(
            text.match_indices(&gate)
                .any(|(at, _)| source::enclosing_fn(&code, at) == function),
            "installed component start lost signed gate: {file}::{function}"
        );
    }
    let custody = &sources["elastos-server/src/protected_content_config.rs"];
    let selected = "verify_installed_component_start(data_dir, \"custody-provider\", &binary)";
    assert!(
        custody.match_indices(selected).any(|(at, _)| {
            source::enclosing_fn(&source::code_only(custody), at)
                == "provision_custody_node_with_installed_provider"
        }),
        "custody start must admit the resolver's selected binary"
    );
    let custody_code = source::code_only(custody);
    let guard = "prepared.signed_checksum()?;";
    let guard_at = custody_code
        .find(guard)
        .expect("custody start lost signed-digest guard");
    assert_eq!(
        source::enclosing_fn(&custody_code, guard_at),
        "provision_custody_node_with_installed_provider"
    );
    let spawn_at = custody_code
        .find("let mut child = command")
        .expect("custody spawn moved");
    assert!(
        guard_at < spawn_at,
        "custody digest guard moved after spawn"
    );
}

/// A start path that runs a component with no check, only on an owner's opt-in.
struct DevOptIn {
    file: &'static str,
    function: &'static str,
    evidence: &'static str,
    trust_root: &'static str,
    verified_when: &'static str,
    note: &'static str,
}

fn dev_opt_ins() -> Vec<DevOptIn> {
    vec![DevOptIn {
        file: "elastos-server/src/setup.rs",
        function: "verify_installed_component_start",
        evidence: "VerifiedExecutable::unchecked(path)",
        trust_root: "none",
        verified_when: "never",
        note: "dev-only explicit opt-in: source Home with config.toml dev_mode = true",
    }]
}

#[test]
fn dev_opt_in_start_is_one_honest_row_behind_the_installed_release() {
    let sources = source::production_sources();
    let rows = dev_opt_ins();
    assert_eq!(rows.len(), 1);
    for row in &rows {
        assert_eq!((row.trust_root, row.verified_when), ("none", "never"));
        assert!(row.note.starts_with("dev-only explicit opt-in"));
        let text = &sources[row.file];
        let code = source::code_only(text);
        let at = |needle: &str| {
            let found: Vec<usize> = text
                .match_indices(needle)
                .map(|(at, _)| at)
                .filter(|at| source::enclosing_fn(&code, *at) == row.function)
                .collect();
            assert_eq!(found.len(), 1, "{needle} in {}::{}", row.file, row.function);
            found[0]
        };
        // A Home with a release never reaches the opt-in; the opt-in is
        // asked before the unchecked start.
        let release = at("let Some(source) = installed_release_source(data_dir)? else {");
        let opt_in = at("if !source_home_dev_mode(data_dir) {");
        let unchecked = at(row.evidence);
        let signed = at("read_signed_release(data_dir, &runtime, &source, false, true)");
        assert!(release < opt_in && opt_in < unchecked && unchecked < signed);
    }
    // No other production code starts a component unchecked.
    let callers: Vec<_> = sources
        .iter()
        .flat_map(|(file, text)| {
            let code = source::code_only(text);
            text.match_indices("VerifiedExecutable::unchecked(")
                .map(|(at, _)| (file.clone(), source::enclosing_fn(&code, at)))
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(
        callers,
        [(
            "elastos-server/src/setup.rs".to_string(),
            "verify_installed_component_start".to_string()
        )]
    );
}
