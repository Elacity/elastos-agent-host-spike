use super::{Call, GuestRequest, Refuse, Verifier};

/// One agent's stated usage amount. This crate's amount is the `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetAsk {
    pub amount: u64,
}

/// A refused budget ask with one clear reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitRefuse {
    OverBudget { cap: u64, asked: u64 },
    Binding(Refuse),
}

impl std::fmt::Display for AdmitRefuse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmitRefuse::OverBudget { .. } => {
                formatter.write_str("budget ask exceeds the admission cap")
            }
            AdmitRefuse::Binding(refusal) => refusal.fmt(formatter),
        }
    }
}

#[cfg(test)]
fn guest_budget_ok(_ask: &BudgetAsk) -> bool {
    true
}

impl Verifier {
    /// Caps one agent's budget ask at `cap`, then stores the granted amount
    /// through the one `admit`. A binding refusal stores nothing, and an ask
    /// above the cap is refused with the cap and the asked amount.
    #[rustfmt::skip]
    pub fn admit_ask(
        &self,
        call: &Call,
        request: &GuestRequest,
        ask: BudgetAsk,
        cap: u64,
    ) -> Result<u64, AdmitRefuse> {
        self.resolve(*call, request.handle).map_err(AdmitRefuse::Binding)?;
        if ask.amount > cap {
            return Err(AdmitRefuse::OverBudget {
                cap,
                asked: ask.amount,
            });
        }
        let identity = self
            .grants
            .get(&request.handle)
            .expect("resolved grant")
            .identity
            .clone();
        self.stage_admitted_identity(&identity);
        self.admit(ask.amount);
        Ok(ask.amount)
    }
}

#[test]
fn model_admitted_ask_sets_the_ceiling() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", super::rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = super::guest(handle);
    let granted = verifier
        .admit_ask(&call, &request, BudgetAsk { amount: 4 }, 10)
        .expect("ask within the cap");
    assert_eq!(granted, 4);
    verifier.reserve(&call, &request, 4).expect("hold the granted ask");
    let refusal = verifier
        .reserve(&call, &request, 1)
        .expect_err("past the granted ceiling");
    assert_eq!(
        refusal,
        crate::ledger::ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 4,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
}

#[test]
fn model_over_budget_ask_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", super::rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 9,
        forged_ceiling: 100,
        ..super::guest(handle)
    };
    let ask = BudgetAsk { amount: 6 };
    assert!(guest_budget_ok(&ask));
    assert!(request.forged_ceiling > 5);
    assert!(request.reported_usage > 0);
    let refusal = verifier
        .admit_ask(&call, &request, ask, 5)
        .expect_err("ask above the cap");
    assert_eq!(refusal, AdmitRefuse::OverBudget { cap: 5, asked: 6 });
    assert_eq!(refusal.to_string(), "budget ask exceeds the admission cap");
    let untouched = verifier
        .reserve(&call, &request, 1)
        .expect_err("ceiling stays unset");
    assert_eq!(
        untouched,
        crate::ledger::ReserveRefuse::OverCeiling {
            ceiling: 0,
            held: 0,
            asked: 1,
        }
    );
}

#[test]
fn model_ask_at_the_cap_is_admitted() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", super::rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = super::guest(handle);
    let granted = verifier
        .admit_ask(&call, &request, BudgetAsk { amount: 5 }, 5)
        .expect("ask at the cap");
    assert_eq!(granted, 5);
    verifier
        .reserve(&call, &request, 5)
        .expect("hold the granted ask");
    let refusal = verifier
        .reserve(&call, &request, 1)
        .expect_err("past the granted ceiling");
    assert_eq!(
        refusal,
        crate::ledger::ReserveRefuse::OverCeiling {
            ceiling: 5,
            held: 5,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
}

#[test]
fn model_admit_ask_on_a_sibling_instance_is_refused() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", super::rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let sibling_call = verifier.open_call(sibling);
    let request = GuestRequest {
        forged_instance: Some(instance),
        ..super::guest(handle)
    };
    assert_eq!(request.forged_instance, Some(instance));
    let refusal = verifier
        .admit_ask(&sibling_call, &request, BudgetAsk { amount: 4 }, 10)
        .expect_err("sibling instance does not admit");
    assert_eq!(refusal, AdmitRefuse::Binding(Refuse::Instance));
    assert_eq!(refusal.to_string(), "instance does not match the grant");
    let untouched = verifier
        .reserve(&call, &super::guest(handle), 1)
        .expect_err("ceiling stays unset");
    assert_eq!(
        untouched,
        crate::ledger::ReserveRefuse::OverCeiling {
            ceiling: 0,
            held: 0,
            asked: 1,
        }
    );
}

#[test]
fn model_forged_ceiling_does_not_replace_the_admitted_amount() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", super::rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_ceiling: 9,
        ..super::guest(handle)
    };
    assert_eq!(request.forged_ceiling, 9);
    let granted = verifier
        .admit_ask(&call, &request, BudgetAsk { amount: 4 }, 10)
        .expect("ask within the cap");
    assert_eq!(granted, 4);
    verifier
        .reserve(&call, &request, 4)
        .expect("hold the granted ask");
    let refusal = verifier
        .reserve(&call, &request, 1)
        .expect_err("past the granted ceiling");
    assert_eq!(
        refusal,
        crate::ledger::ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 4,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
}

#[test]
fn model_reported_usage_does_not_shrink_the_admitted_amount() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", super::rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        reported_usage: 1,
        ..super::guest(handle)
    };
    assert_eq!(request.reported_usage, 1);
    let granted = verifier
        .admit_ask(&call, &request, BudgetAsk { amount: 4 }, 10)
        .expect("ask within the cap");
    assert_eq!(granted, 4);
    verifier
        .reserve(&call, &request, 4)
        .expect("hold the granted ask");
    let refusal = verifier
        .reserve(&call, &request, 1)
        .expect_err("past the granted ceiling");
    assert_eq!(
        refusal,
        crate::ledger::ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 4,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
}

#[test]
fn model_forged_identity_does_not_replace_the_admitted_amount() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", super::rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_identity: Some("agent-2".to_owned()),
        ..super::guest(handle)
    };
    assert_eq!(request.forged_identity.as_deref(), Some("agent-2"));
    let granted = verifier
        .admit_ask(&call, &request, BudgetAsk { amount: 4 }, 10)
        .expect("ask within the cap");
    assert_eq!(granted, 4);
    verifier
        .reserve(&call, &request, 4)
        .expect("hold the granted ask");
    let refusal = verifier
        .reserve(&call, &request, 1)
        .expect_err("past the granted ceiling");
    assert_eq!(
        refusal,
        crate::ledger::ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 4,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
}

#[test]
fn model_forged_session_does_not_replace_the_admitted_amount() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", super::rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_session: Some("session-b".to_owned()),
        ..super::guest(handle)
    };
    assert_eq!(request.forged_session.as_deref(), Some("session-b"));
    let granted = verifier
        .admit_ask(&call, &request, BudgetAsk { amount: 4 }, 10)
        .expect("ask within the cap");
    assert_eq!(granted, 4);
    verifier
        .reserve(&call, &request, 4)
        .expect("hold the granted ask");
    let refusal = verifier
        .reserve(&call, &request, 1)
        .expect_err("past the granted ceiling");
    assert_eq!(
        refusal,
        crate::ledger::ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 4,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
}

#[test]
fn model_forged_instance_does_not_replace_the_admitted_amount() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let sibling = verifier.register_instance("agent-1", "session-a");
    assert_ne!(sibling, instance);
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", super::rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_instance: Some(sibling),
        ..super::guest(handle)
    };
    assert_eq!(request.forged_instance, Some(sibling));
    let granted = verifier
        .admit_ask(&call, &request, BudgetAsk { amount: 4 }, 10)
        .expect("ask within the cap");
    assert_eq!(granted, 4);
    verifier
        .reserve(&call, &request, 4)
        .expect("hold the granted ask");
    let refusal = verifier
        .reserve(&call, &request, 1)
        .expect_err("past the granted ceiling");
    assert_eq!(
        refusal,
        crate::ledger::ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 4,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
}

#[test]
fn model_forged_append_does_not_replace_the_admitted_amount() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", super::rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_append: true,
        ..super::guest(handle)
    };
    assert!(request.forged_append);
    let granted = verifier
        .admit_ask(&call, &request, BudgetAsk { amount: 4 }, 10)
        .expect("ask within the cap");
    assert_eq!(granted, 4);
    verifier
        .reserve(&call, &request, 4)
        .expect("hold the granted ask");
    let refusal = verifier
        .reserve(&call, &request, 1)
        .expect_err("past the granted ceiling");
    assert_eq!(
        refusal,
        crate::ledger::ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 4,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
}

#[test]
fn model_forged_overwrite_does_not_replace_the_admitted_amount() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", super::rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_overwrite: true,
        ..super::guest(handle)
    };
    assert!(request.forged_overwrite);
    let granted = verifier
        .admit_ask(&call, &request, BudgetAsk { amount: 4 }, 10)
        .expect("ask within the cap");
    assert_eq!(granted, 4);
    verifier
        .reserve(&call, &request, 4)
        .expect("hold the granted ask");
    let refusal = verifier
        .reserve(&call, &request, 1)
        .expect_err("past the granted ceiling");
    assert_eq!(
        refusal,
        crate::ledger::ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 4,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
}

#[test]
fn model_forged_identity_does_not_retarget_the_ceiling() {
    let mut verifier = Verifier::new();
    let second = verifier.register_instance("agent-2", "session-a");
    let first = verifier.register_instance("agent-1", "session-a");
    assert_ne!(first, second);
    let second_handle = verifier
        .bind_grant(second, "UsersAI/agent-2/notes", super::rights())
        .expect("bind");
    let first_handle = verifier
        .bind_grant(first, "UsersAI/agent-1/notes", super::rights())
        .expect("bind");
    assert_ne!(first_handle, second_handle);
    let second_call = verifier.open_call(second);
    let first_call = verifier.open_call(first);
    let second_request = super::guest(second_handle);
    let first_request = GuestRequest {
        forged_identity: Some("agent-2".to_owned()),
        ..super::guest(first_handle)
    };
    assert_eq!(first_request.forged_identity.as_deref(), Some("agent-2"));
    verifier
        .admit_ask(
            &second_call,
            &second_request,
            BudgetAsk { amount: 50 },
            80,
        )
        .expect("agent-2 keeps a ceiling of 50");
    let granted = verifier
        .admit_ask(&first_call, &first_request, BudgetAsk { amount: 4 }, 10)
        .expect("agent-1 ask within the cap");
    assert_eq!(granted, 4);
    verifier
        .reserve(&second_call, &second_request, 50)
        .expect("agent-2 ceiling stays 50");
    let refusal = verifier
        .reserve(&second_call, &second_request, 1)
        .expect_err("agent-2 is at its own ceiling");
    assert_eq!(
        refusal,
        crate::ledger::ReserveRefuse::OverCeiling {
            ceiling: 50,
            held: 50,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
}

#[test]
fn model_forged_child_journal_does_not_replace_the_admitted_amount() {
    let mut verifier = Verifier::new();
    let instance = verifier.register_instance("agent-1", "session-a");
    let handle = verifier
        .bind_grant(instance, "UsersAI/agent-1/notes", super::rights())
        .expect("bind");
    let call = verifier.open_call(instance);
    let request = GuestRequest {
        forged_child_journal: true,
        ..super::guest(handle)
    };
    assert!(request.forged_child_journal);
    let granted = verifier
        .admit_ask(&call, &request, BudgetAsk { amount: 4 }, 10)
        .expect("ask within the cap");
    assert_eq!(granted, 4);
    verifier
        .reserve(&call, &request, 4)
        .expect("hold the granted ask");
    let refusal = verifier
        .reserve(&call, &request, 1)
        .expect_err("past the granted ceiling");
    assert_eq!(
        refusal,
        crate::ledger::ReserveRefuse::OverCeiling {
            ceiling: 4,
            held: 4,
            asked: 1,
        }
    );
    assert_eq!(refusal.to_string(), "reservation exceeds the ceiling");
}
