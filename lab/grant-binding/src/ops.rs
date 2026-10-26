//! Operation checks.
//!
//! Append, overwrite and child-journal are distinct rights stored on the grant.
//! An append grant permits append and refuses overwrite; an overwrite grant
//! permits overwrite and refuses append. Append and overwrite do not permit
//! child-journal, and child-journal does not permit either of them. The right
//! comes from the resolved grant, not from the guest's claims.

use crate::{Call, GuestRequest, Refuse, Verifier};

/// The operation the host asks to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Append,
    Overwrite,
    ChildJournal,
}

/// A refused operation with one clear reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperateRefuse {
    Binding(Refuse),
    OverwriteNotGranted,
    AppendNotGranted,
    ChildJournalNotGranted,
}

impl std::fmt::Display for OperateRefuse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperateRefuse::Binding(refusal) => refusal.fmt(formatter),
            OperateRefuse::OverwriteNotGranted => {
                formatter.write_str("append does not permit overwrite")
            }
            OperateRefuse::AppendNotGranted => {
                formatter.write_str("overwrite does not permit append")
            }
            OperateRefuse::ChildJournalNotGranted => {
                formatter.write_str("child journal is its own right")
            }
        }
    }
}

impl Verifier {
    /// Performs one operation when the resolved grant carries its right.
    pub fn operate(
        &mut self,
        call: &Call,
        request: &GuestRequest,
        operation: Operation,
    ) -> Result<(), OperateRefuse> {
        let grant = self
            .resolve(*call, request.handle)
            .map_err(OperateRefuse::Binding)?;
        match operation {
            Operation::Append if !grant.rights.append => Err(OperateRefuse::AppendNotGranted),
            Operation::Overwrite if !grant.rights.overwrite => {
                Err(OperateRefuse::OverwriteNotGranted)
            }
            Operation::ChildJournal if !grant.rights.child_journal => {
                Err(OperateRefuse::ChildJournalNotGranted)
            }
            _ => Ok(()),
        }
    }

    /// Creates a child journal when the grant carries its right and the path
    /// is the owned root or a child under it.
    pub fn create_child_journal(
        &mut self,
        call: &Call,
        request: &GuestRequest,
        path: &str,
    ) -> Result<(), OperateRefuse> {
        self.operate(call, request, Operation::ChildJournal)?;
        #[rustfmt::skip]
        let grant = self.resolve(*call, request.handle).map_err(OperateRefuse::Binding)?;
        super::resource_name(&grant.identity, path, Some(&grant.owned_root))
            .map_err(OperateRefuse::Binding)?;
        Ok(())
    }
}

#[cfg(test)]
use crate::{guest, rights, Handle, InstanceId, Rights};

/// Registers one instance with a grant that carries `rights`.
#[cfg(test)]
fn bound_with(verifier: &mut Verifier, rights: Rights) -> (InstanceId, Handle) {
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/journal", rights)
        .expect("bind");
    (instance, handle)
}

#[test]
fn model_append_right_permits_append() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound_with(
        &mut verifier,
        Rights {
            append: true,
            overwrite: false,
            child_journal: false,
        },
    );
    let call = verifier.open_call(instance);
    verifier
        .operate(&call, &guest(handle), Operation::Append)
        .expect("append right");
}

#[test]
fn model_both_rights_permit_append_and_overwrite() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound_with(
        &mut verifier,
        Rights {
            append: true,
            overwrite: true,
            child_journal: false,
        },
    );
    let call = verifier.open_call(instance);
    verifier
        .operate(&call, &guest(handle), Operation::Append)
        .expect("append right");
    verifier
        .operate(&call, &guest(handle), Operation::Overwrite)
        .expect("overwrite right");
}

#[test]
fn model_append_grant_does_not_permit_overwrite() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound_with(
        &mut verifier,
        Rights {
            append: true,
            overwrite: false,
            child_journal: false,
        },
    );
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_overwrite: false,
        ..guest(handle)
    };
    let refusal = verifier
        .operate(&call, &request, Operation::Overwrite)
        .expect_err("append grant refuses overwrite");
    assert_eq!(refusal, OperateRefuse::OverwriteNotGranted);
    assert_eq!(refusal.to_string(), "append does not permit overwrite");
}

#[test]
fn model_overwrite_grant_does_not_permit_append() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound_with(
        &mut verifier,
        Rights {
            append: false,
            overwrite: true,
            child_journal: false,
        },
    );
    let call = verifier.open_call(instance);
    let refusal = verifier
        .operate(&call, &guest(handle), Operation::Append)
        .expect_err("overwrite grant refuses append");
    assert_eq!(refusal, OperateRefuse::AppendNotGranted);
    assert_eq!(refusal.to_string(), "overwrite does not permit append");
}

#[test]
fn model_forged_overwrite_right_has_no_effect() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound_with(
        &mut verifier,
        Rights {
            append: true,
            overwrite: false,
            child_journal: false,
        },
    );
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_overwrite: true,
        ..guest(handle)
    };
    let refusal = verifier
        .operate(&call, &request, Operation::Overwrite)
        .expect_err("guest claim does not grant overwrite");
    assert_eq!(refusal, OperateRefuse::OverwriteNotGranted);
    assert_eq!(refusal.to_string(), "append does not permit overwrite");
}

#[test]
fn model_operate_on_a_sibling_instance_is_refused() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(first, "UsersAI/agent-1/journal", rights())
        .expect("bind");
    let call = verifier.open_call(sibling);
    let refusal = verifier
        .operate(&call, &guest(handle), Operation::Append)
        .expect_err("sibling instance");
    assert_eq!(refusal, OperateRefuse::Binding(Refuse::Instance));
    assert_eq!(refusal.to_string(), "instance does not match the grant");
}

#[test]
fn model_child_journal_right_permits_child_journal() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound_with(
        &mut verifier,
        Rights {
            append: false,
            overwrite: false,
            child_journal: true,
        },
    );
    let call = verifier.open_call(instance);
    verifier
        .operate(&call, &guest(handle), Operation::ChildJournal)
        .expect("child-journal right");
}

#[test]
fn model_append_and_overwrite_do_not_permit_child_journal() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound_with(
        &mut verifier,
        Rights {
            append: true,
            overwrite: true,
            child_journal: false,
        },
    );
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(handle)
    };
    let refusal = verifier
        .operate(&call, &request, Operation::ChildJournal)
        .expect_err("append and overwrite do not permit child-journal");
    assert_eq!(refusal, OperateRefuse::ChildJournalNotGranted);
    assert_eq!(refusal.to_string(), "child journal is its own right");
}

#[test]
fn model_child_journal_does_not_permit_append_or_overwrite() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound_with(
        &mut verifier,
        Rights {
            append: false,
            overwrite: false,
            child_journal: true,
        },
    );
    let call = verifier.open_call(instance);
    let append = verifier
        .operate(&call, &guest(handle), Operation::Append)
        .expect_err("child-journal does not permit append");
    assert_eq!(append, OperateRefuse::AppendNotGranted);
    assert_eq!(append.to_string(), "overwrite does not permit append");
    let overwrite = verifier
        .operate(&call, &guest(handle), Operation::Overwrite)
        .expect_err("child-journal does not permit overwrite");
    assert_eq!(overwrite, OperateRefuse::OverwriteNotGranted);
    assert_eq!(overwrite.to_string(), "append does not permit overwrite");
}

#[test]
fn model_child_journal_on_a_sibling_instance_is_refused() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(
            first,
            "UsersAI/agent-1/journal",
            Rights {
                append: false,
                overwrite: false,
                child_journal: true,
            },
        )
        .expect("bind");
    let call = verifier.open_call(sibling);
    let refusal = verifier
        .operate(&call, &guest(handle), Operation::ChildJournal)
        .expect_err("sibling instance");
    assert_eq!(refusal, OperateRefuse::Binding(Refuse::Instance));
    assert_eq!(refusal.to_string(), "instance does not match the grant");
}

#[test]
fn model_child_journal_under_the_owned_root_is_allowed() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound_with(
        &mut verifier,
        Rights {
            append: false,
            overwrite: false,
            child_journal: true,
        },
    );
    let call = verifier.open_call(instance);
    for path in ["UsersAI/agent-1/journal", "UsersAI/agent-1/journal/page.md"] {
        verifier
            .create_child_journal(&call, &guest(handle), path)
            .expect("child journal under the owned root");
    }
}

#[test]
fn model_child_journal_outside_the_owned_root_is_refused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound_with(
        &mut verifier,
        Rights {
            append: false,
            overwrite: false,
            child_journal: true,
        },
    );
    let call = verifier.open_call(instance);
    for path in ["UsersAI/agent-1/other", "UsersAI/agent-1/journal-extra"] {
        let refusal = verifier
            .create_child_journal(&call, &guest(handle), path)
            .expect_err("path outside the owned root");
        assert_eq!(refusal, OperateRefuse::Binding(Refuse::OutsideRoot));
        assert_eq!(refusal.to_string(), "use path leaves the owned root");
    }
    let refusal = verifier
        .create_child_journal(&call, &guest(handle), "UsersAI/agent-1/journal/../other")
        .expect_err("a prefix of the owned root does not allow a dotdot path");
    assert_eq!(refusal, OperateRefuse::Binding(Refuse::HostPath));
    assert_eq!(refusal.to_string(), "owned root is a host path");
}

#[test]
fn model_child_journal_create_without_the_right_is_refused() {
    let mut verifier = Verifier::new();
    let (instance, handle) = bound_with(
        &mut verifier,
        Rights {
            append: true,
            overwrite: true,
            child_journal: false,
        },
    );
    let call = verifier.open_call(instance);
    let refusal = verifier
        .create_child_journal(&call, &guest(handle), "UsersAI/agent-1/journal/page.md")
        .expect_err("child journal is its own right");
    assert_eq!(refusal, OperateRefuse::ChildJournalNotGranted);
    assert_eq!(refusal.to_string(), "child journal is its own right");
}

#[test]
fn model_child_journal_create_on_a_sibling_instance_is_refused() {
    let mut verifier = Verifier::new();
    let first = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(
            first,
            "UsersAI/agent-1/journal",
            Rights {
                append: false,
                overwrite: false,
                child_journal: true,
            },
        )
        .expect("bind");
    let call = verifier.open_call(sibling);
    let refusal = verifier
        .create_child_journal(&call, &guest(handle), "UsersAI/agent-1/journal/page.md")
        .expect_err("sibling instance");
    assert_eq!(refusal, OperateRefuse::Binding(Refuse::Instance));
    assert_eq!(refusal.to_string(), "instance does not match the grant");
}
