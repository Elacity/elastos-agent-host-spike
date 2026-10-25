//! `wasm-capsule-tools`: host-side tooling for the wasm-capsule lab. None of
//! it runs inside a capsule, and no Runtime admission or launch path uses it.
//!
//! [`lab_name`] is the one rule that names a lab bundle (wc-003a). Every lab
//! tool names a bundle through [`lab_name::name_bundle`].

pub mod lab_name;
