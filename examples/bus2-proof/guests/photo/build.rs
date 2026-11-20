//! Compiles the guest's own manifest (capsule.json) into constants, so what
//! the manifest pins is part of what the guest is.

fn main() {
    println!("cargo:rerun-if-changed=capsule.json");
    let text = std::fs::read_to_string("capsule.json").expect("capsule.json");
    let manifest: serde_json::Value = serde_json::from_str(&text).expect("capsule.json is JSON");
    let max_bytes = manifest["photo"]["max_bytes"]
        .as_u64()
        .expect("photo.max_bytes");
    let kind = manifest["credential"]["kind"]
        .as_str()
        .expect("credential.kind");
    let signer = manifest["credential"]["signer"]
        .as_str()
        .expect("credential.signer");

    // did:key:z<base58btc(0xed 0x01 || 32-byte Ed25519 public key)>
    let encoded = signer
        .strip_prefix("did:key:z")
        .expect("an Ed25519 did:key");
    let decoded = bs58::decode(encoded).into_vec().expect("base58btc");
    assert!(
        decoded.len() == 34 && decoded[..2] == [0xed, 0x01],
        "an Ed25519 did:key"
    );
    let key: Vec<String> = decoded[2..]
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect();

    let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("manifest.rs");
    std::fs::write(
        out,
        format!(
            "/// From capsule.json `photo.max_bytes`.\n\
             pub const MAX_PHOTO_BYTES: usize = {max_bytes};\n\
             /// From capsule.json `credential.kind`.\n\
             pub const CREDENTIAL_KIND: &str = {kind:?};\n\
             /// From capsule.json `credential.signer`.\n\
             pub const PINNED_SIGNER: &str = {signer:?};\n\
             /// The Ed25519 public key in `credential.signer`.\n\
             pub const PINNED_KEY: [u8; 32] = [{}];\n",
            key.join(", ")
        ),
    )
    .unwrap();
}
