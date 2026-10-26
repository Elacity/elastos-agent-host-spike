# Review of draft PR #323 (sixth pass, r6)

Independent adversarial review of the lab-side C1-C7 macOS sandbox
profile contract in draft PR #323 (`cursor/redteam-fix-4bfb` at
`65f003aaa67173f7b74a0233232d24c4a5d01b39`).

This folder only adds `lab/review-c1-c7-323-r6/`. It does not edit #323
files or prior `lab/review-323*` runners. Draft only. Do not merge.

- Target: #323 head `65f003aaa67173f7b74a0233232d24c4a5d01b39`
- Binding CTO decisions: (F1) every `#\` character literal is refused
  anywhere; (F2) a citation counts only if the cited file itself holds
  that `#[test]` and the owning crate's cargo list for that file/target
  names it. No union of crate lists.
- Status: pre-testing stub. Results follow in a later commit.

## Verdict

Pending owner suites, r1-r5 reruns, author mutants, and new r6 attacks.

C1-C7 cannot count until the Mac `sandbox-exec` run (32 named tests)
passes. That stay **NOT RUN**. Whether Apple's reader keeps
`#\; x (allow file*)` live is unmeasured.
