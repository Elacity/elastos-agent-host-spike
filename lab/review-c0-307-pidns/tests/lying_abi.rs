//! Extra crate tests that name the lying-ABI case in one place.

use review_c0_307_pidns::{
    current_guard_launches, lying_abi5_with_abi1_rights, patched_guard_launches,
    probe_needed_rights,
};

#[test]
fn current_launches_patched_refuses_on_the_same_liar() {
    let kernel = lying_abi5_with_abi1_rights();
    assert!(
        current_guard_launches(&kernel),
        "unpatched #307 policy launches when the ABI number is 5"
    );
    assert!(
        !patched_guard_launches(&kernel),
        "the proposed probe must refuse that same kernel"
    );
    let reason = probe_needed_rights(&kernel).unwrap_err();
    assert!(reason.contains("EINVAL"), "{reason}");
}
