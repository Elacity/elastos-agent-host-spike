//! Shared host-side test support: a driver for `tools/build`, a minimal
//! reader for the artifact's shape, wc-009a's importing module and grants
//! files, and (task 064) a run of the Runtime's componentize tool. Each
//! integration test includes this with `mod common;`; a given test uses only
//! part of it, so dead-code warnings for the rest are expected and silenced
//! here.
#![allow(dead_code)]

pub mod build;
pub mod componentize;
pub mod grants;
pub mod wasm_shape;

/// The lab CID of a bundle holding this capsule's `capsule/capsule.json`
/// beside the 8-byte module `00 61 73 6d 01 00 00 00` as `capsule.wasm`.
/// Task 024 recomputed it outside the lab code, with a `python3 -I` script
/// written from cc-capsule-identity's README rules ("The encoding"; the script
/// is quoted in LOG), and pinned it only because it equals what
/// `bundle_identity` prints for the same folder. One pin, used by
/// `this_capsule_bundle_has_the_pinned_lab_cid` and
/// `tools_bundle_name_mode_prints_the_lab_cid`.
pub const MODULE_BUNDLE_LAB_CID: &str =
    "bafybeihtyzfql54i7irft23lg2mk44toqdww53ryuhs2psrknfjw4qhpcy";

/// wc-001's pinned `capsule.wasm` (README, "Claim scope"): the 17,658-byte
/// module `tools/build` makes since task 068, which declares its own memory
/// maximum (1024 pages) and exports the world's `lifecycle.run`. Task 068
/// re-pinned it (it was `2002429e…`, 180 bytes, `no_std` and `digest` only)
/// only because two builds and a `python3 -I` `hashlib` recomputation over
/// the built file agree (LOG). One pin, used by
/// `tools_bundle_builds_a_new_bundle_and_prints_its_lab_cid` and
/// `the_real_capsule_passes_the_verifier`.
pub const PINNED_ARTIFACT_SHA256: &str =
    "e7f17f707a1d12600f5ffe8d0376e1ef8a3fe4b7d89b539f644363556d9b8774";
