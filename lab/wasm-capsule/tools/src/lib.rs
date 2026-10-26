//! `wasm-capsule-tools`: host-side tooling for the wasm-capsule lab. None of
//! it runs inside a capsule, and no Runtime admission or launch path uses it.
//!
//! [`bundle_identity`] is how every lab tool names a bundle. It is
//! cc-capsule-identity's lab CID function, exported here once and unchanged:
//! that lane owns the hash, the walk and the manifest check, and this crate
//! adds no rule of its own. Callers treat the result as an opaque value:
//! they compare it and print it, and leave its encoding to that lane.
//!
//! [`CAPSULE_MANIFEST`] is this capsule's own `elastos.capsule/v1` manifest.
//!
//! [`bundle`] holds the rules of the `tools/bundle` command, which writes a
//! new bundle of the two and prints its lab CID.
//!
//! [`verify`] is wc-004's one verify path: a checked bundle's in-memory name
//! signature, through cc-capsule-identity, then the cx-wasm-audit crate's
//! `audit` of the checked entrypoint module. It is a lab check, never an
//! admission or launch decision.

pub mod bundle;
pub mod verify;

pub use capsule_identity::lab_cid as bundle_identity;

/// The bytes of `capsule/capsule.json`, this capsule's `elastos.capsule/v1`
/// manifest. A lab bundle is these bytes as `capsule.json` beside
/// `capsule.wasm`. They are compiled in, so nothing reads the file by a path
/// at run time. Only the Runtime's `CapsuleManifest` parses them.
pub const CAPSULE_MANIFEST: &[u8] = include_bytes!("../../capsule/capsule.json");
