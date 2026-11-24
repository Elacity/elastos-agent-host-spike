use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=ELASTOS_RELEASE_VERSION");

    let version = env::var("ELASTOS_RELEASE_VERSION").unwrap_or_else(|_| {
        let pkg = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.1.0".to_string());
        format!("{pkg}-dev")
    });

    println!("cargo:rustc-env=ELASTOS_VERSION={version}");
    // The agents cargo feature, under a cfg name the one-place reader does not
    // count. Release builds leave the feature off, so the cfg stays unset.
    println!("cargo:rustc-check-cfg=cfg(elastos_prototype_agents)");
    if env::var_os("CARGO_FEATURE_PROTOTYPE_AGENTS").is_some() {
        println!("cargo:rustc-cfg=elastos_prototype_agents");
    }
}
