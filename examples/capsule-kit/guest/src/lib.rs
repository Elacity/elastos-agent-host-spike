//! The capsule kit's guest crate: one copy of what every Bus v1 component
//! capsule here shares, used by the photo and documents viewers as a Cargo
//! path dependency.
//!
//! - [`bus`]: the two Bus calls behind a trait, the read window, the write and
//!   the one-pass answer parser;
//! - [`read`]: the refusals that stop a run, the grant, the bounded and the
//!   counted reads;
//! - [`uri`]: the object URI check of an input list;
//! - [`text`]: is this text (UTF-8, no control character but tab and line ends);
//! - [`image`]: PNG, JPEG and WebP magic bytes and frame dimensions;
//! - [`fake`] (feature `fake`): the fake Runtime for guest tests;
//! - [`component`] (feature `wit`, wasm32 only): the `elastos:bus@v1` glue and
//!   `lifecycle.run`.
//!
//! [`text`], [`image`] and [`uri`] need no feature, so a Bus v2 guest can use
//! them without carrying any Bus v1 binding.

pub mod image;
pub mod text;
pub mod uri;

#[cfg(feature = "bus")]
pub mod bus;
#[cfg(feature = "bus")]
pub mod read;

#[cfg(feature = "bus")]
pub use bus::{Bus, BusFailure, CallError, InvokeReply};
#[cfg(feature = "bus")]
pub use read::{grant, read_at, read_bounded, read_counted, App, Refusal, READ_CHUNK_BYTES};

#[cfg(any(test, feature = "fake"))]
pub mod fake;

/// The bindings of the `product-capsule-v1` world, generated once here. A
/// guest implements `wit::exports::elastos::bus::lifecycle::Guest` and exports
/// it with `capsule_kit_guest::wit::export_lifecycle!(Guest with_types_in
/// capsule_kit_guest::wit)`. The macro also writes the world's component type
/// section into the guest's own crate, so it is always linked.
#[cfg(all(feature = "wit", target_arch = "wasm32"))]
pub mod wit {
    wit_bindgen::generate!({
        path: "../../../elastos/wit",
        world: "product-capsule-v1",
        pub_export_macro: true,
        export_macro_name: "export_lifecycle",
        default_bindings_module: "capsule_kit_guest::wit",
    });
}

#[cfg(all(feature = "wit", target_arch = "wasm32"))]
pub mod component;

#[cfg(test)]
mod tests;
