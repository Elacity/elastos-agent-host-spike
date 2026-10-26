//! Shared host-side test support: a driver for `tools/build`, a minimal
//! reader for the artifact's shape, and wc-009a's importing module and grants
//! files. Each integration test includes this with
//! `mod common;`; a given test uses only part of it, so dead-code warnings for
//! the rest are expected and silenced here.
#![allow(dead_code)]

pub mod build;
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
