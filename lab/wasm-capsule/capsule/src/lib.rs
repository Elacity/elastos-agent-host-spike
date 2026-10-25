//! wc-001 capsule: a minimal, zero-import core Wasm module.
//!
//! This is the lab's foundation. The capsule is a small self-contained computer
//! (Rong's "DigitCapsule"): one flat linear memory, its logic compiled in, and
//! no imports — it traps down to nothing. It exports one pure function,
//! `digest`, so later tasks can hash-name it (wc-003), sign that name (wc-004)
//! and run it unchanged on two engines (wc-005).
//!
//! `digest_impl` is the single shared implementation. The Wasm export and the
//! host test both call it, so there is one path for the capsule's behaviour
//! (PRINCIPLES P10): no second copy of the rule.
#![cfg_attr(target_arch = "wasm32", no_std)]

/// A fixed input for the host test. Its expected output is pinned as a literal
/// in [`FIXED_OUTPUT`], so a change to [`digest_impl`] is caught.
pub const FIXED_INPUT: u32 = 0x5EED_0001;

/// The pinned value of `digest_impl(FIXED_INPUT)`, written as a literal and not
/// derived from `digest_impl`, so the test is not a tautology.
pub const FIXED_OUTPUT: u64 = 0x0331_7BB4_875F_B038;

/// The capsule's one pure operation, shared by the Wasm export and the host
/// test. A splitmix64-style mix: total (no panics), deterministic, `core`-only.
pub const fn digest_impl(n: u32) -> u64 {
    let mut z = (n as u64).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The capsule's only export: core Wasm, `(param i32) -> (result i64)`
/// (`u32` lowers to `i32`, `u64` to `i64`).
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn digest(n: u32) -> u64 {
    digest_impl(n)
}

// `digest_impl` is total, so this is never reached; `no_std` still needs a
// handler, and a capsule traps down rather than unwinding a host.
#[cfg(all(target_arch = "wasm32", not(test)))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(test)]
mod tests {
    use super::{digest_impl, FIXED_INPUT, FIXED_OUTPUT};

    #[test]
    fn digest_returns_the_fixed_value() {
        assert_eq!(digest_impl(FIXED_INPUT), FIXED_OUTPUT);
    }
}
