//! Shared host-side test support: a driver for `tools/build`, a minimal
//! reader for the artifact's shape, and wc-009a's importing module and grants
//! files. Each integration test includes this with
//! `mod common;`; a given test uses only part of it, so dead-code warnings for
//! the rest are expected and silenced here.
#![allow(dead_code)]

pub mod build;
pub mod grants;
pub mod wasm_shape;
