//! Shared host-side test support: a driver for `tools/build` and a minimal
//! reader for the artifact's shape. Each integration test includes this with
//! `mod common;`; a given test uses only part of it, so dead-code warnings for
//! the rest are expected and silenced here.
#![allow(dead_code)]

pub mod build;
pub mod wasm_shape;
