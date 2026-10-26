//! Operation checks.
//!
//! Append and overwrite are distinct rights stored on the grant. An append
//! grant permits append and refuses overwrite; an overwrite grant permits
//! overwrite and refuses append. The right comes from the resolved grant, not
//! from the guest's claims.

use crate::{Call, GuestRequest, Refuse, Verifier};

/// The operation the host asks to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Append,
    Overwrite,
}

/// A refused operation with one clear reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperateRefuse {
    Binding(Refuse),
    OverwriteNotGranted,
    AppendNotGranted,
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
            _ => Ok(()),
        }
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
