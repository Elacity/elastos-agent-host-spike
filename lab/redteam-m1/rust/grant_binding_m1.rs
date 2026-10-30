//! M1 red team: grant-binding reference model.
//!
//! `test_m1_grant_binding.py` copies this file into a scratch clone as
//! `lab/grant-binding/src/redteam_m1.rs` and adds `#[cfg(test)] mod redteam_m1;`
//! to that clone's `src/lib.rs`. Nothing in the lane folder changes.
//!
//! `fm_*` tests assert the property a reader of the lane's README and LOG would
//! expect; they fail on the merged model. `control_*` tests assert refusals the
//! model does make, so the module is live.

use crate::{guest, rights, Refuse, Verifier};
use std::path::PathBuf;

#[test]
fn control_root_under_another_agent_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    assert_eq!(
        verifier.bind_grant(instance, "UsersAI/agent-2/notes", rights()),
        Err(Refuse::OutsidePrincipal)
    );
}

#[test]
fn control_reserve_over_the_ceiling_is_refused_for_one_agent() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .unwrap();
    verifier.admit(5);
    let call = verifier.open_call(instance);
    verifier.reserve(&call, &guest(handle), 5).unwrap();
    assert!(verifier.reserve(&call, &guest(handle), 1).is_err());
}

/// FM-GB1. The ledger holds one ceiling and one outstanding total for the
/// whole verifier, so one agent's hold spends every other agent's allowance.
/// A7 asks for "each agent's model budget ... capped by Runtime admission".
#[test]
fn fm_gb1_one_agents_hold_does_not_spend_another_agents_allowance() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("agent-2", "session-b");
    let first_handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .unwrap();
    let second_handle = verifier
        .bind_grant(second, "UsersAI/agent-2/notes", rights())
        .unwrap();
    verifier.admit(5);
    let first_call = verifier.open_call(first);
    verifier
        .reserve(&first_call, &guest(first_handle), 5)
        .expect("agent-1 reserves up to the ceiling");
    let second_call = verifier.open_call(second);
    verifier
        .reserve(&second_call, &guest(second_handle), 1)
        .expect("agent-2 is refused because agent-1's hold sits on the one shared ledger");
}

/// FM-GB2. `use path has a symlink-shaped segment` is a character-class check
/// on the name. A real symlink with a plain name, inside the owned root and
/// pointing out of it, is accepted: the verifier never sees the file system.
#[test]
fn fm_gb2_a_real_symlink_with_a_plain_name_is_refused() {
    let base: PathBuf = std::env::temp_dir().join(format!(
        "redteam-m1-gb2-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let notes = base.join("UsersAI/agent-1/notes");
    let outside = base.join("outside");
    std::fs::create_dir_all(&notes).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), b"outside the owned root").unwrap();
    std::os::unix::fs::symlink(outside.join("secret.txt"), notes.join("page.md")).unwrap();
    let on_disk_is_symlink = std::fs::symlink_metadata(notes.join("page.md"))
        .unwrap()
        .file_type()
        .is_symlink();

    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .unwrap();
    let decision = verifier.use_path(
        &verifier.open_call(instance),
        &guest(handle),
        "UsersAI/agent-1/notes/page.md",
    );
    std::fs::remove_dir_all(&base).unwrap();
    assert!(on_disk_is_symlink, "fixture: page.md must be a real symlink");
    assert_eq!(decision, Err(Refuse::SymlinkShaped));
}

/// FM-GB3. Agent names are compared byte for byte. Two agents whose names
/// differ only in letter case get roots that are one directory on a
/// case-insensitive file system, the macOS default. The model accepts both as
/// separate principals, so "refuses a root under another agent" depends on the
/// host file system and on the identity format.
#[test]
fn fm_gb3_a_case_variant_agent_root_is_refused() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let second = verifier.register_instance("AGENT-1", "session-b");
    verifier
        .bind_grant(first, "UsersAI/agent-1/notes", rights())
        .unwrap();
    assert!(
        verifier
            .bind_grant(second, "UsersAI/AGENT-1/notes", rights())
            .is_err(),
        "UsersAI/AGENT-1/notes and UsersAI/agent-1/notes are one directory on a case-insensitive file system"
    );
}
