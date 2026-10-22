# Review record template

One file per merged slice: `handoff/reviews/<PR>-<short head>.md`, for example `31-b30580f4.md`. Copy the block
below, fill every field, and keep the finding summary to one line. The head is the exact commit that was reviewed;
a review of another head is another file.

```text
PR:        #<number> <title>
Head:      <full 40-character commit the review was run on>
Reviewer:  <name or tool> (<AI family, for example GPT, Claude, or human>)
Verdict:   PASS | FAIL | not recorded
Date:      <day Mon year>
Findings:  <one line: "none", or the count and a short summary; details stay in the PR or a private note>
```

Rules:
- The reviewer is from another AI family than the author for grants, gateway, provider launch, confinement or
  signing (AGENTS.md, HANDOFF section 1).
- A FAIL gets its own file; the fix's later review is a new file on the new head.
- Never claim a verdict the log does not hold: write "not recorded", and "no cross-family record" when only a
  same-family review exists.
- Past records (before 22 Oct) are one file per merged PR, at the merged head; earlier FAIL rounds are named in the
  finding line.
- Security details follow SECURITY.md: a safe summary here, no exploit steps.
