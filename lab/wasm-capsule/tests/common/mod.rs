//! Shared host-side test support: a driver for `tools/build`, a minimal
//! reader for the artifact's shape, and a strict reader for the lab manifest's
//! JSON. Each integration test includes this with `mod common;`; a given test
//! uses only part of it, so dead-code warnings for the rest are expected and
//! silenced here.
#![allow(dead_code)]

pub mod build;
pub mod json;
pub mod wasm_shape;
