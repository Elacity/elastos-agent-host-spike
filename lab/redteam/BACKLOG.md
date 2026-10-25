# cc-redteam — in-repo operating rules (guards a–e)

This is the in-repo copy of the lane's rules, so a probe suite under
`lab/redteam/` is self-contained: a reader (or reviewer) finds the guards it
claims to keep without leaving the repo. The authoritative task queue lives with
the orchestrator; this file carries only the goal, the guards, and the scope the
probes are written against.

## Lane goal

A lab-only red team. It writes adversarial probes and falsifier tests against
work **already merged** on `spike/agent-host`, and keeps every file it writes
under `lab/redteam/`. It changes no owner tree and never patches. It does not
raise a grade; it **independently verifies, or falsifies, the evidence a grade
rests on**. A clean probe says only "this probe did not break it on commit X". A
probe that breaks something is a finding, pinned to the exact merged commit and
PR it attacks, with an exact repro. The owner lane decides the fix.

## Target areas (owner lane in brackets)

- **confine** — `capsules/wallet-provider/confine.sb`,
  `capsules/did-provider/confine.sb`, and the shared contract check
  `capsules/wallet-provider/tests/confine.rs` [confine]. Task 001 probes the
  **wallet** profile.
- **provider** — `capsules/model-provider` behaviour and its `confine.sb` once it
  lands [provider / cc-model-confine].
- **agent-host** — `examples/agent-host` falsifier/asks honesty [agent-host].
- **wasm-capsule lab** — `lab/wasm-capsule` reproducible-build and receipt
  [wasm-capsule-lab].

## Rong's guards (every task repeats the ones it touches)

- **(a) Pin the target.** Every finding pins its target to the merged **commit
  hash and PR number** it attacks, got with
  `git log -1 --format='%H %s' spike/agent-host -- <file>`, plus the sha256 of the
  tested bytes. The full hash and PR go in the finding file's first line.
- **(b) Findings stay here.** Findings go in
  `lab/redteam/findings/<owner-lane>-<nnn>.md`, naming the owner lane. No patches,
  no edit to any `confine.sb`, nothing dropped in an owner tree — the owner
  decides the fix. A probe that reproduces a real defect is kept as a test marked
  `@unittest.expectedFailure` carrying the finding id, so the gates stay green; it
  is never deleted. Expected-failure is reserved for a **confirmed, recorded
  escape** — an unrelated or setup error must still fail.
- **(c) Escapes are CRITICAL and not batched.** A confinement escape, an
  ambient-authority path, or a capability token accepted outside the Runtime is
  CRITICAL: write it at once as its own `findings/CRITICAL-*.md`, append it to
  `lab/redteam/CRITICAL.md`, and put "CRITICAL" in the commit subject.
- **(d) SKIP is never PASS.** A skipped probe is reported SKIPPED with the reason,
  never as a pass. An all-skipped run is not a pass. Positive controls must run,
  or the deny results are vacuous and the suite SKIPs. SKIP is reserved for a
  **genuine platform limitation** (no `sandbox-exec`, no stock binary, or seatbelt
  itself refusing to start a stock binary under a valid profile). A broken fixture
  — a missing or malformed profile, a usage error — is a harness error and must
  **fail**, never skip.
- **(e) No network, no secrets.** No network access. Any test key or seed is
  generated in a temp dir inside the test and never committed (`.gitignore`
  carries `*.key` `*.seed`). Nothing aimed at hosts outside the lab. No Docker.
  Mac toolchain only.

## Scope and hard limits

- Every file this lane writes stays under `lab/redteam/`. Other trees are **READ
  only**; a path dep on them is fine. Round 1 is Python only, so no
  `lab/redteam/Cargo.toml` exists yet and the Cargo gates are deliberate no-ops.
- **Never edit** `capsules/`, `examples/`, `elastos/`, `lab/wasm-capsule/`,
  `lab/agent-conformance/`, `scripts/`, `docs/`, or any Runtime file.
- No security weakness of the shipping product in any task file or finding; the
  targets here are private lab/spike work, pinned by commit.
