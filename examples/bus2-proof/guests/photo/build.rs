//! Compiles the guest's own manifest (capsule.json) into constants, so what
//! the manifest pins is part of what the guest is.

fn main() {
    println!("cargo:rerun-if-changed=capsule.json");
    let text = std::fs::read_to_string("capsule.json").expect("capsule.json");
    let manifest: serde_json::Value = serde_json::from_str(&text).expect("capsule.json is JSON");
    let max_bytes = manifest["photo"]["max_bytes"]
        .as_u64()
        .expect("photo.max_bytes");
    let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("manifest.rs");
    std::fs::write(
        out,
        format!("/// From capsule.json `photo.max_bytes`.\npub const MAX_PHOTO_BYTES: usize = {max_bytes};\n"),
    )
    .unwrap();
}
