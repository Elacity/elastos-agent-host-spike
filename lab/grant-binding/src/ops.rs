//! Operation checks.
//!
//! Append, overwrite and child-journal are distinct rights stored on the grant.
//! An append grant permits append and refuses overwrite; an overwrite grant
//! permits overwrite and refuses append. Append and overwrite do not permit
//! child-journal, and child-journal does not permit either of them. The right
//! comes from the resolved grant, not from the guest's claims.

use crate::{Call, GuestRequest, Handle, Refuse, Verifier};

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

    /// Creates a child journal and returns its own handle. The grant must
    /// carry the child-journal right, and the path must be the owned root or
    /// a child under it. The new handle is `bind_grant` of that path.
    #[rustfmt::skip]
    pub fn create_child_journal(
        &mut self,
        call: &Call,
        request: &GuestRequest,
        path: &str,
    ) -> Result<Handle, OperateRefuse> {
        self.operate(call, request, Operation::ChildJournal)?;
        #[rustfmt::skip]
        let grant = self.resolve(*call, request.handle).map_err(OperateRefuse::Binding)?;
        super::resource_name(&grant.identity, path, Some(&grant.owned_root))
            .map_err(OperateRefuse::Binding)?;
        self.bind_grant(grant.instance, path, grant.rights)
            .map_err(OperateRefuse::Binding)
    }
}

#[cfg(test)]
use crate::{guest, rights, InstanceId, Rights};

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
fn model_forged_append_right_has_no_effect() {
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
    let request = GuestRequest {
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    let refusal = verifier
        .operate(&call, &request, Operation::Append)
        .expect_err("guest claim does not grant append");
    assert_eq!(refusal, OperateRefuse::AppendNotGranted);
    assert_eq!(refusal.to_string(), "overwrite does not permit append");
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

#[test]
fn model_child_journal_returns_its_own_handle() {
    let mut verifier = Verifier::new();
    let (instance, parent) = bound_with(
        &mut verifier,
        Rights {
            append: false,
            overwrite: false,
            child_journal: true,
        },
    );
    let call = verifier.open_call(instance);
    let child = verifier
        .create_child_journal(&call, &guest(parent), "UsersAI/agent-1/journal/page.md")
        .expect("child journal handle");
    assert_ne!(child, parent);
    let child_decision = verifier
        .use_grant(call, &guest(child))
        .expect("child grant");
    assert_eq!(child_decision.owned_root, "UsersAI/agent-1/journal/page.md");
    assert_eq!(child_decision.identity, "agent-1");
    assert_eq!(child_decision.session, "session-a");
    assert_eq!(child_decision.instance, instance);
    assert_eq!(
        child_decision.rights,
        Rights {
            append: false,
            overwrite: false,
            child_journal: true,
        }
    );
    verifier
        .use_path(&call, &guest(child), "UsersAI/agent-1/journal/page.md")
        .expect("the child handle binds its own root");
    let refusal = verifier
        .use_path(&call, &guest(child), "UsersAI/agent-1/journal")
        .expect_err("the parent root leaves the child root");
    assert_eq!(refusal, Refuse::OutsideRoot);
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
    let parent_decision = verifier
        .use_grant(call, &guest(parent))
        .expect("parent grant");
    assert_eq!(parent_decision.owned_root, "UsersAI/agent-1/journal");
    verifier
        .use_path(&call, &guest(parent), "UsersAI/agent-1/journal/page.md")
        .expect("the parent handle keeps the parent root");
}

#[test]
fn model_forged_rights_do_not_widen_the_child_grant() {
    let mut verifier = Verifier::new();
    let (instance, parent) = bound_with(
        &mut verifier,
        Rights {
            append: false,
            overwrite: false,
            child_journal: true,
        },
    );
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_append: true,
        forged_overwrite: true,
        ..guest(parent)
    };
    assert!(request.forged_append);
    assert!(request.forged_overwrite);
    let child = verifier
        .create_child_journal(&call, &request, "UsersAI/agent-1/journal/page.md")
        .expect("child journal");
    assert_ne!(child, parent);
    let child_decision = verifier
        .use_grant(call, &guest(child))
        .expect("child grant");
    assert_eq!(
        child_decision.rights,
        Rights {
            append: false,
            overwrite: false,
            child_journal: true,
        }
    );
    assert_eq!(child_decision.owned_root, "UsersAI/agent-1/journal/page.md");
}

#[test]
fn model_owned_root_needs_a_resource_segment() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let refusal = verifier
        .bind_grant(instance, "UsersAI/agent-1", rights())
        .expect_err("agent principal is not a resource");
    assert_eq!(refusal, Refuse::OutsidePrincipal);
    assert_eq!(
        refusal.to_string(),
        "owned root is outside the agent principal"
    );
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", rights())
        .expect("a resource segment still binds");
    let decision = verifier
        .use_grant(verifier.open_call(instance), &guest(handle))
        .expect("grant");
    assert_eq!(decision.owned_root, "UsersAI/agent-1/notes");
}
