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
        path: &str,
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
            _ => {
                if operation != Operation::ChildJournal {
                    {
                        super::resource_name(&grant.identity, path, Some(&grant.owned_root))
                            .map_err(OperateRefuse::Binding)?;
                    }
                }
                let mut grant = grant;
                let mut counted = request.handle;
                while let Some(handle) = grant.parent {
                    let ancestor = self
                        .resolve(*call, handle)
                        .map_err(OperateRefuse::Binding)?;
                    grant.effect_limit = ancestor.effect_limit;
                    grant.effects = ancestor.effects;
                    counted = handle;
                    grant.parent = ancestor.parent;
                }
                #[rustfmt::skip]
                if operation != Operation::ChildJournal {
                    self.open_rate_window(counted)
                        .map_err(OperateRefuse::Binding)?;
                    let rate_handle = counted;
                    if let Some(rate) = self
                        .grants
                        .get(&rate_handle)
                        .and_then(|stored| stored.record.rate)
                    {
                        let used = self
                            .grants
                            .get(&rate_handle)
                            .map(|stored| stored.record.window_effects)
                            .unwrap_or(0);
                        if used >= rate {
                            return Err(OperateRefuse::Binding(Refuse::Rate));
                        }
                    }
                    if let Some(limit) = grant.effect_limit {
                        if grant.effects >= limit {
                            return Err(OperateRefuse::Binding(Refuse::EffectLimit));
                        }
                    }
                    let counting = grant.effect_limit.is_some()
                        || self
                            .grants
                            .get(&counted)
                            .and_then(|stored| stored.record.rate)
                            .is_some();
                    if counting {
                        self.note_effect(counted)
                            .map_err(OperateRefuse::Binding)?;
                    }
                };
                {
                    if operation != Operation::ChildJournal {
                        let ending = counted;
                        if self
                            .grants
                            .get(&ending)
                            .map(|stored| stored.record.once)
                            .unwrap_or(false)
                        {
                            #[rustfmt::skip]
                            self.revoke_grant(ending)
                                .map_err(OperateRefuse::Binding)?;
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Creates a child journal and returns its own handle. The grant must
    /// carry the child-journal right, and the path must be the owned root or
    /// a child under it. The new handle keeps the parent's append and overwrite and does not keep child-journal.
    #[rustfmt::skip]
    pub fn create_child_journal(
        &mut self,
        call: &Call,
        request: &GuestRequest,
        path: &str,
    ) -> Result<Handle, OperateRefuse> {
        self.pending_parent = Some(request.handle);
        match self.mint_child_journal(call, request, path) {
            Ok(handle) => Ok(handle),
            Err(refusal) => {
                self.pending_parent = None;
                Err(refusal)
            }
        }
    }

    #[rustfmt::skip]
    fn mint_child_journal(
        &mut self,
        call: &Call,
        request: &GuestRequest,
        path: &str,
    ) -> Result<Handle, OperateRefuse> {
        self.operate(call, request, Operation::ChildJournal, path)?;
        #[rustfmt::skip]
        let grant = self.resolve(*call, request.handle).map_err(OperateRefuse::Binding)?;
        super::resource_name(&grant.identity, path, Some(&grant.owned_root))
            .map_err(OperateRefuse::Binding)?;
        self.bind_grant(
            grant.instance,
            path,
            crate::Rights {
                append: grant.rights.append,
                overwrite: grant.rights.overwrite,
                child_journal: false,
            },
        )
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
        .operate(
            &call,
            &guest(handle),
            Operation::Append,
            "UsersAI/agent-1/journal",
        )
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
        .operate(
            &call,
            &guest(handle),
            Operation::Append,
            "UsersAI/agent-1/journal",
        )
        .expect("append right");
    verifier
        .operate(
            &call,
            &guest(handle),
            Operation::Overwrite,
            "UsersAI/agent-1/journal",
        )
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
        .operate(
            &call,
            &request,
            Operation::Overwrite,
            "UsersAI/agent-1/journal",
        )
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
        .operate(
            &call,
            &guest(handle),
            Operation::Append,
            "UsersAI/agent-1/journal",
        )
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
        .operate(
            &call,
            &request,
            Operation::Overwrite,
            "UsersAI/agent-1/journal",
        )
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
        .operate(
            &call,
            &request,
            Operation::Append,
            "UsersAI/agent-1/journal",
        )
        .expect_err("guest claim does not grant append");
    assert_eq!(refusal, OperateRefuse::AppendNotGranted);
    assert_eq!(refusal.to_string(), "overwrite does not permit append");
}

#[test]
fn model_forged_identity_does_not_grant_append() {
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
        forged_identity: Some("agent-2".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_identity.as_deref(), Some("agent-2"));
    let refusal = verifier
        .operate(
            &call,
            &request,
            Operation::Append,
            "UsersAI/agent-1/journal",
        )
        .expect_err("guest identity does not grant append");
    assert_eq!(refusal, OperateRefuse::AppendNotGranted);
    assert_eq!(refusal.to_string(), "overwrite does not permit append");
}

#[test]
fn model_forged_session_does_not_grant_append() {
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
        forged_session: Some("session-b".to_owned()),
        ..guest(handle)
    };
    assert_eq!(request.forged_session.as_deref(), Some("session-b"));
    let refusal = verifier
        .operate(
            &call,
            &request,
            Operation::Append,
            "UsersAI/agent-1/journal",
        )
        .expect_err("guest session does not grant append");
    assert_eq!(refusal, OperateRefuse::AppendNotGranted);
    assert_eq!(refusal.to_string(), "overwrite does not permit append");
}

#[test]
fn model_forged_instance_does_not_grant_append() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(
            instance,
            "UsersAI/agent-1/journal",
            Rights {
                append: false,
                overwrite: true,
                child_journal: false,
            },
        )
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_instance: Some(sibling),
        ..guest(handle)
    };
    assert_eq!(request.forged_instance, Some(sibling));
    let refusal = verifier
        .operate(
            &call,
            &request,
            Operation::Append,
            "UsersAI/agent-1/journal",
        )
        .expect_err("guest instance does not grant append");
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
        .operate(
            &call,
            &guest(handle),
            Operation::Append,
            "UsersAI/agent-1/journal",
        )
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
        .operate(
            &call,
            &guest(handle),
            Operation::ChildJournal,
            "UsersAI/agent-1/journal",
        )
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
        .operate(
            &call,
            &request,
            Operation::ChildJournal,
            "UsersAI/agent-1/journal",
        )
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
        .operate(
            &call,
            &guest(handle),
            Operation::Append,
            "UsersAI/agent-1/journal",
        )
        .expect_err("child-journal does not permit append");
    assert_eq!(append, OperateRefuse::AppendNotGranted);
    assert_eq!(append.to_string(), "overwrite does not permit append");
    let overwrite = verifier
        .operate(
            &call,
            &guest(handle),
            Operation::Overwrite,
            "UsersAI/agent-1/journal",
        )
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
        .operate(
            &call,
            &guest(handle),
            Operation::ChildJournal,
            "UsersAI/agent-1/journal",
        )
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
fn model_forged_child_journal_does_not_skip_the_right() {
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
    assert!(request.forged_child_journal);
    let refusal = verifier
        .create_child_journal(&call, &request, "UsersAI/agent-1/journal/page.md")
        .expect_err("forged child journal does not skip the right");
    assert_eq!(refusal, OperateRefuse::ChildJournalNotGranted);
    assert_eq!(refusal.to_string(), "child journal is its own right");
}

#[test]
fn model_forged_append_does_not_skip_the_right() {
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
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    let refusal = verifier
        .create_child_journal(&call, &request, "UsersAI/agent-1/journal/page.md")
        .expect_err("forged append does not skip the right");
    assert_eq!(refusal, OperateRefuse::ChildJournalNotGranted);
    assert_eq!(refusal.to_string(), "child journal is its own right");
}

#[test]
fn model_forged_overwrite_does_not_skip_the_right() {
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
        forged_overwrite: true,
        ..guest(handle)
    };
    assert!(request.forged_overwrite);
    let refusal = verifier
        .create_child_journal(&call, &request, "UsersAI/agent-1/journal/page.md")
        .expect_err("forged overwrite does not skip the right");
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
            child_journal: false,
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
            child_journal: false,
        }
    );
    assert_eq!(child_decision.owned_root, "UsersAI/agent-1/journal/page.md");
}

#[test]
fn model_refused_child_journal_stores_no_grant() {
    let mut verifier = Verifier::new();
    let (instance, parent) = bound_with(
        &mut verifier,
        Rights {
            append: false,
            overwrite: false,
            child_journal: true,
        },
    );
    assert_eq!(parent, Handle(1));
    let call = verifier.open_call(instance);
    let refusal = verifier
        .create_child_journal(&call, &guest(parent), "UsersAI/agent-1/other")
        .expect_err("path outside the owned root");
    assert_eq!(refusal, OperateRefuse::Binding(Refuse::OutsideRoot));
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
    let leaked = verifier
        .use_grant(call, &guest(Handle(2)))
        .expect_err("a refused create stores no grant");
    assert_eq!(leaked, Refuse::UnknownHandle);
    assert_eq!(leaked.to_string(), "unknown handle");
    let child = verifier
        .create_child_journal(&call, &guest(parent), "UsersAI/agent-1/journal/page.md")
        .expect("child journal");
    assert_eq!(child, Handle(2));
    let parent_decision = verifier
        .use_grant(call, &guest(parent))
        .expect("parent grant");
    assert_eq!(parent_decision.owned_root, "UsersAI/agent-1/journal");
}

#[test]
fn model_forged_child_journal_does_not_remove_the_right() {
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
    let request = GuestRequest {
        forged_child_journal: true,
        ..guest(handle)
    };
    assert!(request.forged_child_journal);
    verifier
        .operate(
            &call,
            &request,
            Operation::ChildJournal,
            "UsersAI/agent-1/journal",
        )
        .expect("guest claim does not remove the child-journal right");
}

#[test]
fn model_forged_append_does_not_remove_the_right() {
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
        forged_append: true,
        ..guest(handle)
    };
    assert!(request.forged_append);
    verifier
        .operate(
            &call,
            &request,
            Operation::Append,
            "UsersAI/agent-1/journal",
        )
        .expect("guest claim does not remove the append right");
}

#[test]
fn model_forged_overwrite_does_not_remove_the_right() {
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
        forged_overwrite: true,
        ..guest(handle)
    };
    assert!(request.forged_overwrite);
    verifier
        .operate(
            &call,
            &request,
            Operation::Overwrite,
            "UsersAI/agent-1/journal",
        )
        .expect("guest claim does not remove the overwrite right");
}

#[test]
fn model_forged_child_journal_does_not_narrow_the_child_grant() {
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
        forged_child_journal: true,
        ..guest(parent)
    };
    assert!(request.forged_child_journal);
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
            child_journal: false,
        }
    );
    assert_eq!(child_decision.owned_root, "UsersAI/agent-1/journal/page.md");
}

#[test]
fn model_child_journal_does_not_keep_the_mint_right() {
    let mut verifier = Verifier::new();
    let (instance, parent) = bound_with(
        &mut verifier,
        Rights {
            append: true,
            overwrite: true,
            child_journal: true,
        },
    );
    let call = verifier.open_call(instance);
    let child = verifier
        .create_child_journal(&call, &guest(parent), "UsersAI/agent-1/journal/page.md")
        .expect("child journal");
    assert_ne!(child, parent);
    let child_decision = verifier
        .use_grant(call, &guest(child))
        .expect("child grant");
    assert_eq!(
        child_decision.rights,
        Rights {
            append: true,
            overwrite: true,
            child_journal: false,
        }
    );
    let nested = verifier
        .create_child_journal(&call, &guest(child), "UsersAI/agent-1/journal/page.md/line")
        .expect_err("a child journal does not mint another");
    assert_eq!(nested, OperateRefuse::ChildJournalNotGranted);
    assert_eq!(nested.to_string(), "child journal is its own right");
    let another = verifier
        .create_child_journal(&call, &guest(parent), "UsersAI/agent-1/journal/other")
        .expect("the parent keeps the mint right");
    assert_ne!(another, child);
}

#[test]
fn model_forged_identity_does_not_move_the_child_path() {
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
        forged_identity: Some("agent-2".to_owned()),
        ..guest(parent)
    };
    assert_eq!(request.forged_identity.as_deref(), Some("agent-2"));
    let child = verifier
        .create_child_journal(&call, &request, "UsersAI/agent-1/journal/page.md")
        .expect("forged identity does not move the child path");
    assert_ne!(child, parent);
    let child_decision = verifier
        .use_grant(call, &guest(child))
        .expect("child grant");
    assert_eq!(child_decision.owned_root, "UsersAI/agent-1/journal/page.md");
    assert_eq!(child_decision.identity, "agent-1");
}

#[test]
fn model_forged_instance_does_not_move_the_child_grant() {
    let mut verifier = Verifier::new();
    let (instance, parent) = bound_with(
        &mut verifier,
        Rights {
            append: false,
            overwrite: false,
            child_journal: true,
        },
    );
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_instance: Some(sibling),
        ..guest(parent)
    };
    assert_eq!(request.forged_instance, Some(sibling));
    let child = verifier
        .create_child_journal(&call, &request, "UsersAI/agent-1/journal/page.md")
        .expect("forged instance does not move the child grant");
    assert_ne!(child, parent);
    let child_decision = verifier
        .use_grant(call, &guest(child))
        .expect("child grant");
    assert_eq!(child_decision.instance, instance);
    assert_eq!(child_decision.identity, "agent-1");
    assert_eq!(child_decision.session, "session-a");
    assert_eq!(child_decision.owned_root, "UsersAI/agent-1/journal/page.md");
    let refusal = verifier
        .use_grant(verifier.open_call(sibling), &guest(child))
        .expect_err("child grant stays on the parent instance");
    assert_eq!(refusal, Refuse::Instance);
    assert_eq!(refusal.to_string(), "instance does not match the grant");
}

#[test]
fn model_forged_session_does_not_move_the_child_path() {
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
        forged_session: Some("session-b".to_owned()),
        ..guest(parent)
    };
    assert_eq!(request.forged_session.as_deref(), Some("session-b"));
    let child = verifier
        .create_child_journal(&call, &request, "UsersAI/agent-1/journal/page.md")
        .expect("forged session does not move the child path");
    assert_ne!(child, parent);
    let child_decision = verifier
        .use_grant(call, &guest(child))
        .expect("child grant");
    assert_eq!(child_decision.owned_root, "UsersAI/agent-1/journal/page.md");
    assert_eq!(child_decision.identity, "agent-1");
    assert_eq!(child_decision.session, "session-a");
}

#[test]
fn model_reported_usage_does_not_widen_the_child_root() {
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
        reported_usage: 1,
        ..guest(parent)
    };
    assert!(request.reported_usage > 0);
    let refusal = verifier
        .create_child_journal(&call, &request, "UsersAI/agent-1/other")
        .expect_err("reported usage does not widen the child root");
    assert_eq!(refusal, OperateRefuse::Binding(Refuse::OutsideRoot));
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
}

#[test]
fn model_forged_ceiling_does_not_widen_the_child_root() {
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
        forged_ceiling: 1,
        ..guest(parent)
    };
    assert!(request.forged_ceiling > 0);
    let refusal = verifier
        .create_child_journal(&call, &request, "UsersAI/agent-1/other")
        .expect_err("forged ceiling does not widen the child root");
    assert_eq!(refusal, OperateRefuse::Binding(Refuse::OutsideRoot));
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
}

#[test]
fn model_forged_child_journal_does_not_widen_the_child_root() {
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
        forged_child_journal: true,
        ..guest(parent)
    };
    assert!(request.forged_child_journal);
    let refusal = verifier
        .create_child_journal(&call, &request, "UsersAI/agent-1/other")
        .expect_err("forged child journal does not widen the child root");
    assert_eq!(refusal, OperateRefuse::Binding(Refuse::OutsideRoot));
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
}

#[test]
fn model_forged_append_does_not_widen_the_child_root() {
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
        ..guest(parent)
    };
    assert!(request.forged_append);
    let refusal = verifier
        .create_child_journal(&call, &request, "UsersAI/agent-1/other")
        .expect_err("forged append does not widen the child root");
    assert_eq!(refusal, OperateRefuse::Binding(Refuse::OutsideRoot));
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
}

#[test]
fn model_forged_overwrite_does_not_widen_the_child_root() {
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
        forged_overwrite: true,
        ..guest(parent)
    };
    assert!(request.forged_overwrite);
    let refusal = verifier
        .create_child_journal(&call, &request, "UsersAI/agent-1/other")
        .expect_err("forged overwrite does not widen the child root");
    assert_eq!(refusal, OperateRefuse::Binding(Refuse::OutsideRoot));
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
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

#[test]
fn model_allow_once_ends_after_one_effect() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let library = verifier
        .bind_once(photo, "UsersAI/photo/library", rights())
        .expect("allow once");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal does not end the grant");
    let refused = verifier
        .operate(
            &call,
            &guest(library),
            Operation::Overwrite,
            "UsersAI/photo/library",
        )
        .expect_err("a refused effect does not end the grant");
    assert_eq!(refused, OperateRefuse::OverwriteNotGranted);
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("one append");
    let again = verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the allow-once grant has ended");
    assert_eq!(again, OperateRefuse::Binding(Refuse::UnknownHandle));
    assert_eq!(again.to_string(), "unknown handle");
    let child = verifier
        .use_grant(call, &guest(roll))
        .expect_err("the derived journal ended with the grant");
    assert_eq!(child, Refuse::UnknownHandle);
    assert_eq!(child.to_string(), "unknown handle");
}

#[test]
fn model_session_grant_allows_a_second_effect() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let home = verifier.register_instance("home", "session-a");
    let public = verifier
        .bind_once(photo, "Public/photo/desk", rights())
        .expect_err("public storage does not bind");
    assert_eq!(public, Refuse::PublicRead);
    let home_mint = verifier
        .bind_once(home, "UsersAI/home/desk", rights())
        .expect_err("home does not mint");
    assert_eq!(home_mint, Refuse::HomeMint);
    let library = verifier
        .bind_grant(
            photo,
            "UsersAI/photo/library",
            Rights {
                append: true,
                overwrite: true,
                child_journal: false,
            },
        )
        .expect("standing grant");
    let call = verifier.open_call(photo);
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("first append");
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Overwrite,
            "UsersAI/photo/library",
        )
        .expect("a standing grant allows a second effect");
    let refused = verifier
        .operate(
            &call,
            &guest(library),
            Operation::ChildJournal,
            "UsersAI/photo/library",
        )
        .expect_err("a refused effect does not end the grant");
    assert_eq!(refused, OperateRefuse::ChildJournalNotGranted);
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("the grant is still there");
}

#[test]
fn model_effect_limit_stops_the_next_effect() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let library = verifier
        .bind_grant(
            photo,
            "UsersAI/photo/library",
            Rights {
                append: true,
                overwrite: false,
                child_journal: true,
            },
        )
        .expect("library ask");
    verifier.set_effect_limit(library, 1).expect("limit");
    let call = verifier.open_call(photo);
    verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal does not spend the limit");
    let refused = verifier
        .operate(
            &call,
            &guest(library),
            Operation::Overwrite,
            "UsersAI/photo/library",
        )
        .expect_err("a refused right does not spend the limit");
    assert_eq!(refused, OperateRefuse::OverwriteNotGranted);
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("one effect");
    let again = verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the effect limit is reached");
    assert_eq!(again, OperateRefuse::Binding(Refuse::EffectLimit));
    assert_eq!(again.to_string(), "effect limit is reached");
    verifier
        .use_grant(call, &guest(library))
        .expect("the grant stays in the store");
    let once = verifier
        .bind_once(photo, "UsersAI/photo/frames", rights())
        .expect("allow once");
    verifier
        .operate(
            &call,
            &guest(once),
            Operation::Append,
            "UsersAI/photo/frames",
        )
        .expect("the allow-once grant ends");
    let missing = verifier
        .set_effect_limit(once, 1)
        .expect_err("an ended grant stores no limit");
    assert_eq!(missing, Refuse::UnknownHandle);
    assert_eq!(missing.to_string(), "unknown handle");
}

#[test]
fn model_unset_effect_limit_does_not_stop() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let library = verifier
        .bind_grant(
            photo,
            "UsersAI/photo/library",
            Rights {
                append: true,
                overwrite: true,
                child_journal: false,
            },
        )
        .expect("library ask");
    let call = verifier.open_call(photo);
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("unset limit allows the first effect");
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Overwrite,
            "UsersAI/photo/library",
        )
        .expect("unset limit allows the next effect");
    let frames = verifier
        .bind_grant(
            photo,
            "UsersAI/photo/frames",
            Rights {
                append: true,
                overwrite: false,
                child_journal: false,
            },
        )
        .expect("frames ask");
    verifier.set_effect_limit(frames, 0).expect("zero limit");
    let refusal = verifier
        .operate(
            &call,
            &guest(frames),
            Operation::Append,
            "UsersAI/photo/frames",
        )
        .expect_err("a set limit of 0 stops the first effect");
    assert_eq!(refusal, OperateRefuse::Binding(Refuse::EffectLimit));
    assert_eq!(refusal.to_string(), "effect limit is reached");
    verifier
        .use_grant(call, &guest(frames))
        .expect("a refused effect leaves the grant");
}

#[test]
fn model_child_effect_spends_the_issuing_limit() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let library = verifier
        .bind_grant(
            photo,
            "UsersAI/photo/library",
            Rights {
                append: true,
                overwrite: false,
                child_journal: true,
            },
        )
        .expect("library ask");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal does not spend the limit");
    let other = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/other")
        .expect("sibling journal does not spend the limit");
    let refused = verifier
        .set_effect_limit(roll, 0)
        .expect_err("a derived journal keeps no limit of its own");
    assert_eq!(refused, Refuse::IssuingLimit);
    assert_eq!(
        refused.to_string(),
        "effect limit stays on the issuing grant"
    );
    verifier
        .set_effect_limit(library, 1)
        .expect("issuing limit");
    let wrong = verifier
        .operate(
            &call,
            &guest(roll),
            Operation::Overwrite,
            "UsersAI/photo/library/roll",
        )
        .expect_err("a refused right does not spend the issuing limit");
    assert_eq!(wrong, OperateRefuse::OverwriteNotGranted);
    verifier
        .operate(
            &call,
            &guest(roll),
            Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect("one child effect spends the issuing limit");
    let sibling = verifier
        .operate(
            &call,
            &guest(other),
            Operation::Append,
            "UsersAI/photo/library/other",
        )
        .expect_err("the sibling spends the same issuing limit");
    assert_eq!(sibling, OperateRefuse::Binding(Refuse::EffectLimit));
    assert_eq!(sibling.to_string(), "effect limit is reached");
    let parent = verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the issuing grant has spent its limit");
    assert_eq!(parent, OperateRefuse::Binding(Refuse::EffectLimit));
    verifier
        .use_grant(call, &guest(library))
        .expect("the issuing grant stays in the store");
    verifier
        .use_grant(call, &guest(roll))
        .expect("the child journal stays in the store");
}

#[test]
fn model_unset_issuing_limit_allows_a_child_effect() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let library = verifier
        .bind_grant(
            photo,
            "UsersAI/photo/library",
            Rights {
                append: true,
                overwrite: true,
                child_journal: true,
            },
        )
        .expect("library ask");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal");
    verifier
        .operate(
            &call,
            &guest(roll),
            Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect("an unset issuing limit allows the child effect");
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("an unset issuing limit allows the parent effect");
}

#[test]
fn model_overwrite_outside_the_owned_root_is_refused() {
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
        .operate(
            &call,
            &guest(handle),
            Operation::Overwrite,
            "UsersAI/agent-1/other",
        )
        .expect_err("overwrite leaves the owned root");
    assert_eq!(refusal, OperateRefuse::Binding(Refuse::OutsideRoot));
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
}

#[test]
fn model_append_outside_the_owned_root_is_refused() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let library = verifier
        .bind_once(
            photo,
            "UsersAI/photo/library",
            Rights {
                append: true,
                overwrite: false,
                child_journal: false,
            },
        )
        .expect("allow once");
    verifier.set_effect_limit(library, 1).expect("limit");
    let call = verifier.open_call(photo);
    let refusal = verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/other",
        )
        .expect_err("append leaves the owned root");
    assert_eq!(refusal, OperateRefuse::Binding(Refuse::OutsideRoot));
    assert_eq!(refusal.to_string(), "use path leaves the owned root");
    verifier
        .use_grant(call, &guest(library))
        .expect("an outside path does not end the allow-once grant");
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("an outside path does not spend the limit");
}

#[test]
fn model_child_journal_effect_stays_inside_its_root() {
    let mut verifier = Verifier::new();
    let (instance, parent) = bound_with(
        &mut verifier,
        Rights {
            append: true,
            overwrite: true,
            child_journal: true,
        },
    );
    let call = verifier.open_call(instance);
    let child = verifier
        .create_child_journal(&call, &guest(parent), "UsersAI/agent-1/journal/page.md")
        .expect("child journal");
    assert_ne!(child, parent);
    let child_decision = verifier
        .use_grant(call, &guest(child))
        .expect("child grant");
    assert_eq!(child_decision.owned_root, "UsersAI/agent-1/journal/page.md");
    verifier
        .operate(
            &call,
            &guest(child),
            Operation::Append,
            "UsersAI/agent-1/journal/page.md/line",
        )
        .expect("append inside the journal");
    verifier
        .operate(
            &call,
            &guest(child),
            Operation::Overwrite,
            "UsersAI/agent-1/journal/page.md/line",
        )
        .expect("overwrite inside the journal");
    let append_outside = verifier
        .operate(
            &call,
            &guest(child),
            Operation::Append,
            "UsersAI/agent-1/journal/other",
        )
        .expect_err("append leaves the journal");
    assert_eq!(append_outside, OperateRefuse::Binding(Refuse::OutsideRoot));
    assert_eq!(append_outside.to_string(), "use path leaves the owned root");
    let overwrite_outside = verifier
        .operate(
            &call,
            &guest(child),
            Operation::Overwrite,
            "UsersAI/agent-1/journal/other",
        )
        .expect_err("overwrite leaves the journal");
    assert_eq!(
        overwrite_outside,
        OperateRefuse::Binding(Refuse::OutsideRoot)
    );
    assert_eq!(
        overwrite_outside.to_string(),
        "use path leaves the owned root"
    );
    verifier
        .operate(
            &call,
            &guest(parent),
            Operation::Append,
            "UsersAI/agent-1/journal/other",
        )
        .expect("the parent root still contains that path");
}

#[test]
fn model_rate_stops_the_next_effect_in_the_window() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let library = verifier
        .bind_grant(
            photo,
            "UsersAI/photo/library",
            Rights {
                append: true,
                overwrite: false,
                child_journal: true,
            },
        )
        .expect("library ask");
    verifier.set_rate(library, 1, 10).expect("rate");
    let call = verifier.open_call(photo);
    verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal does not spend the rate");
    let refused = verifier
        .operate(
            &call,
            &guest(library),
            Operation::Overwrite,
            "UsersAI/photo/library",
        )
        .expect_err("a refused right does not spend the rate");
    assert_eq!(refused, OperateRefuse::OverwriteNotGranted);
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("one effect inside the window");
    verifier.set_verifier_now(9);
    let again = verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the rate is reached inside the window");
    assert_eq!(again, OperateRefuse::Binding(Refuse::Rate));
    assert_eq!(again.to_string(), "rate limit is reached");
    verifier
        .use_grant(call, &guest(library))
        .expect("the grant stays in the store");
    let once = verifier
        .bind_once(photo, "UsersAI/photo/frames", rights())
        .expect("allow once");
    verifier
        .operate(
            &call,
            &guest(once),
            Operation::Append,
            "UsersAI/photo/frames",
        )
        .expect("the allow-once grant ends");
    let missing = verifier
        .set_rate(once, 1, 10)
        .expect_err("an ended grant stores no rate");
    assert_eq!(missing, Refuse::UnknownHandle);
    assert_eq!(missing.to_string(), "unknown handle");
}

#[test]
fn model_new_window_allows_one_effect() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let library = verifier
        .bind_grant(
            photo,
            "UsersAI/photo/library",
            Rights {
                append: true,
                overwrite: true,
                child_journal: false,
            },
        )
        .expect("library ask");
    verifier.set_rate(library, 1, 10).expect("rate");
    let call = verifier.open_call(photo);
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("first window");
    let inside = verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("still inside the window");
    assert_eq!(inside, OperateRefuse::Binding(Refuse::Rate));
    verifier.set_verifier_now(10);
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("the window end starts a new count");
    let later = verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the new window has its own rate");
    assert_eq!(later, OperateRefuse::Binding(Refuse::Rate));
    verifier
        .use_grant(call, &guest(library))
        .expect("the grant stays in the store");
}

#[test]
fn model_child_effect_spends_the_issuing_rate() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let library = verifier
        .bind_grant(
            photo,
            "UsersAI/photo/library",
            Rights {
                append: true,
                overwrite: false,
                child_journal: true,
            },
        )
        .expect("library ask");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal does not spend the rate");
    let other = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/other")
        .expect("sibling journal does not spend the rate");
    let refused = verifier
        .set_rate(roll, 0, 10)
        .expect_err("a derived journal keeps no rate of its own");
    assert_eq!(refused, Refuse::IssuingRate);
    assert_eq!(refused.to_string(), "rate stays on the issuing grant");
    verifier.set_rate(library, 1, 10).expect("issuing rate");
    verifier
        .operate(
            &call,
            &guest(roll),
            Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect("one child effect spends the issuing rate");
    let sibling = verifier
        .operate(
            &call,
            &guest(other),
            Operation::Append,
            "UsersAI/photo/library/other",
        )
        .expect_err("the sibling spends the same issuing rate");
    assert_eq!(sibling, OperateRefuse::Binding(Refuse::Rate));
    assert_eq!(sibling.to_string(), "rate limit is reached");
    let parent = verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the issuing grant has spent its rate");
    assert_eq!(parent, OperateRefuse::Binding(Refuse::Rate));
    verifier
        .use_grant(call, &guest(library))
        .expect("the issuing grant stays in the store");
    verifier
        .use_grant(call, &guest(roll))
        .expect("the child journal stays in the store");
}

#[test]
fn model_unset_rate_does_not_stop() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let library = verifier
        .bind_grant(
            photo,
            "UsersAI/photo/library",
            Rights {
                append: true,
                overwrite: true,
                child_journal: false,
            },
        )
        .expect("library ask");
    let call = verifier.open_call(photo);
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("unset rate allows the first effect");
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Overwrite,
            "UsersAI/photo/library",
        )
        .expect("unset rate allows the next effect");
    let frames = verifier
        .bind_grant(
            photo,
            "UsersAI/photo/frames",
            Rights {
                append: true,
                overwrite: false,
                child_journal: false,
            },
        )
        .expect("frames ask");
    verifier.set_rate(frames, 0, 10).expect("zero rate");
    let refusal = verifier
        .operate(
            &call,
            &guest(frames),
            Operation::Append,
            "UsersAI/photo/frames",
        )
        .expect_err("a set rate of 0 stops the first effect");
    assert_eq!(refusal, OperateRefuse::Binding(Refuse::Rate));
    assert_eq!(refusal.to_string(), "rate limit is reached");
    verifier
        .use_grant(call, &guest(frames))
        .expect("a refused effect leaves the grant");
}

#[test]
fn model_child_effect_follows_the_issuing_window() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let library = verifier
        .bind_grant(
            photo,
            "UsersAI/photo/library",
            Rights {
                append: true,
                overwrite: false,
                child_journal: true,
            },
        )
        .expect("issuing grant");
    verifier.set_rate(library, 1, 10).expect("issuing rate");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal does not spend the rate");
    verifier
        .operate(
            &call,
            &guest(roll),
            Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect("one child effect spends the issuing window");
    verifier.set_verifier_now(9);
    let inside = verifier
        .operate(
            &call,
            &guest(roll),
            Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect_err("still inside the issuing window");
    assert_eq!(inside, OperateRefuse::Binding(Refuse::Rate));
    assert_eq!(inside.to_string(), "rate limit is reached");
    verifier.set_verifier_now(10);
    verifier
        .operate(
            &call,
            &guest(roll),
            Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect("the issuing window end starts a new count");
    let later = verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the new window has its own rate");
    assert_eq!(later, OperateRefuse::Binding(Refuse::Rate));
    assert_eq!(later.to_string(), "rate limit is reached");
    verifier
        .use_grant(call, &guest(library))
        .expect("the issuing grant stays");
    verifier
        .use_grant(call, &guest(roll))
        .expect("the child journal stays");
}

#[test]
fn model_child_effect_ends_the_allow_once_grant() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let library = verifier
        .bind_once(photo, "UsersAI/photo/library", rights())
        .expect("allow once");
    let album = verifier
        .bind_grant(photo, "UsersAI/photo/album", rights())
        .expect("standing album");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal does not end the grant");
    let other = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/other")
        .expect("sibling journal does not end the grant");
    let refused = verifier
        .operate(
            &call,
            &guest(roll),
            Operation::Overwrite,
            "UsersAI/photo/library/roll",
        )
        .expect_err("a refused right does not end the grant");
    assert_eq!(refused, OperateRefuse::OverwriteNotGranted);
    verifier
        .use_grant(call, &guest(library))
        .expect("the issuing grant is still there");
    verifier
        .operate(
            &call,
            &guest(roll),
            Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect("one child effect ends the issuing grant");
    let sibling = verifier
        .operate(
            &call,
            &guest(other),
            Operation::Append,
            "UsersAI/photo/library/other",
        )
        .expect_err("the sibling ended with the issuing grant");
    assert_eq!(sibling, OperateRefuse::Binding(Refuse::UnknownHandle));
    assert_eq!(sibling.to_string(), "unknown handle");
    let parent = verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect_err("the issuing grant has ended");
    assert_eq!(parent, OperateRefuse::Binding(Refuse::UnknownHandle));
    let child_stopped = verifier
        .use_grant(call, &guest(roll))
        .expect_err("the child journal has ended");
    assert_eq!(child_stopped, Refuse::UnknownHandle);
    let album_kept = verifier
        .use_grant(call, &guest(album))
        .expect("a standing grant stays");
    assert_eq!(album_kept.owned_root, "UsersAI/photo/album");
}

#[test]
fn model_standing_child_allows_another_effect() {
    let mut verifier = Verifier::new();
    let photo = verifier.register_instance("photo", "session-a");
    let library = verifier
        .bind_grant(photo, "UsersAI/photo/library", rights())
        .expect("standing library");
    let call = verifier.open_call(photo);
    let roll = verifier
        .create_child_journal(&call, &guest(library), "UsersAI/photo/library/roll")
        .expect("child journal");
    verifier
        .operate(
            &call,
            &guest(roll),
            Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect("first child effect");
    verifier
        .operate(
            &call,
            &guest(roll),
            Operation::Append,
            "UsersAI/photo/library/roll",
        )
        .expect("a standing grant allows another child effect");
    verifier
        .operate(
            &call,
            &guest(library),
            Operation::Append,
            "UsersAI/photo/library",
        )
        .expect("the issuing grant stays");
    verifier
        .use_grant(call, &guest(roll))
        .expect("the child journal stays");
}
