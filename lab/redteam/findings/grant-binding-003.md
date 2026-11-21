grant-binding-003 lab/grant-binding/src/ledger.rs 19e5ce4dea7327de18fbc7546efe18faff937116 sha256 3c32d6179842726deec6f98acbd70c5f0f689621917dbae970d2d60afa2e2e1d

probe: test_immediate_timeout_after_unknown_is_refused
observed: timeout_hold returned Ok

## Rerun at 261d7f2d654248902cbcb47fd63655d47cb1a02c

Outcome: PASS (closed at the current target). The verifier deadline is 5;
the immediate timeout is attempted at 4 after an unknown settle. It is refused
as Early, and the outstanding hold still consumes the full ceiling.
Current target: lab/grant-binding/src/ledger.rs at 24bf1f7183797403e50e3db4ceffc5ac1263e386,
sha256 7809db23b7570a3ff79a5d4ff79c5470c7541210d22a13d9d00cfeaf7b0529cd.

Run output:

```text
test test_immediate_timeout_after_unknown_is_refused ... ok
immediate timeout: refused
```
