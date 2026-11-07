"""Required M1 evidence rows. audit.py and falsify.py share this list."""

REQUIRED_CHECKS = (
    "A1",
    "A2",
    "A8",
    "C1",
    "C2",
    "C3",
    "C4",
    "C5",
    "C6",
    "C7",
    "S1",
)

# A check fails the catalog if any of these row ids is absent.
REQUIRED_ROWS = {
    "A1": (
        "A1-unit-wasi",
        "A1-lab-probe",
        "A1-draft-301-runtime",
        "A1-review-3",
    ),
    "A2": (
        "A2-e2e-bridge",
        "A2-unit-stale-revision",
        "A2-review-20",
    ),
    "A8": (
        "A8-ac-host-key",
        "A8-redteam-fm-a8",
        "A8-draft-301-runtime",
        "A8-review-179",
    ),
    "C1": (
        "C1-init-requires-storage",
        "C1-review-57",
    ),
    "C2": (
        "C2-store-permission",
        "C2-provider-nickname",
        "C2-review-65",
    ),
    "C3": (
        "C3-outside-write",
        "C3-outside-read",
        "C3-skip-gate",
        "C3-review-66",
    ),
    "C4": (
        "C4-verify-under-profile",
        "C4-skip-gate",
        "C4-review-67",
    ),
    "C5": (
        "C5-missing-storage",
        "C5-review-62",
    ),
    "C6": (
        "C6-outside-write",
        "C6-ops-under-root",
        "C6-skip-gate",
        "C6-review-63",
    ),
    "C7": (
        "C7-ops-under-profile",
        "C7-outside-write",
        "C7-skip-gate",
        "C7-review-88",
    ),
    "S1": (
        "S1-rong-file",
        "S1-booking-note",
    ),
}

VERDICTS = ("holds", "weak", "falsified")
ROW_KINDS = ("journey", "refusal", "review", "skip", "attack", "note")
