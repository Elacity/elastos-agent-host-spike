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
