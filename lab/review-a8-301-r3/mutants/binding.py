#!/usr/bin/env python3
"""Six-plus mutants of the A8 binding predicates as they exist at 10316585.

This file copies the predicates from lab/a1-a8-hardening/src/lib.rs and
tests/a8_agent_host_host_key.rs. Each mutant asks: would the cargo test
still reach ok, and would run.sh still print NEEDS RUNTIME or PASS?

It does not launch the Runtime. Live hunts are in attacks/.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


RESOURCE = "localhost://Public/../../../../.ssh/id_ed25519"
MANIFEST_DENIED = "manifest_capability_denied"
GUEST_HASH = "f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737"
HONEST_CAPSULE = "component-341af27a-6b9c-4892-a618-808f0b687a9d"
OTHER_CAPSULE = "component-00000000-0000-0000-0000-000000000000"


def optional_string(value: dict, key: str):
    raw = value.get(key)
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    return text if text else None


def parse_record(line: str) -> dict:
    value = json.loads(line)
    return {
        "action": value.get("action"),
        "resource": value.get("resource"),
        "code": value.get("code"),
        "capsule_id": optional_string(value, "capsule_id"),
        "principal_id": optional_string(value, "principal_id"),
        "session_id": optional_string(value, "session_id"),
        "module_hash": optional_string(value, "module_hash")
        or optional_string(value, "guest_hash")
        or optional_string(value, "wasm_hash"),
    }


def denied_actions(records, resource, assigned):
    out = []
    for record in records:
        match_id = True if assigned is None else record["capsule_id"] == assigned
        if record["resource"] == resource and record["code"] == MANIFEST_DENIED and match_id:
            out.append(record["action"])
    return out


def missing_fields(records, assigned, guest_hash):
    missing = []
    if assigned is None:
        missing.append("component id from Runtime [run] output or API")
    if any(record["session_id"] is None for record in records):
        missing.append("session id")
    if any(record["module_hash"] != guest_hash for record in records):
        missing.append("guest module hash")
    return missing


def runsh_result(test_ok: bool, missing):
    if test_ok and missing:
        return "NEEDS RUNTIME"
    if test_ok:
        return "PASS"
    return "FAIL"


def cargo_ok(actions, stderr_has_follow: bool):
    return actions == ["write", "read"] and stderr_has_follow


def honest_runtime_lines():
    return [
        json.dumps(
            {
                "action": action,
                "capsule_id": HONEST_CAPSULE,
                "code": MANIFEST_DENIED,
                "principal_id": None,
                "resource": RESOURCE,
            }
        )
        for action in ("write", "read")
    ]


@dataclass
class Case:
    name: str
    records: list
    assigned: str | None
    follow: bool
    note: str


def evaluate(case: Case, mutate=None):
    assigned = case.assigned
    records = [dict(r) for r in case.records]
    guest_hash = GUEST_HASH
    if mutate:
        assigned, records, guest_hash = mutate(assigned, records, guest_hash)
    actions = denied_actions(records, RESOURCE, assigned)
    missing = missing_fields(records, assigned, guest_hash)
    ok = cargo_ok(actions, case.follow)
    return {
        "case": case.name,
        "cargo_ok": ok,
        "runsh": runsh_result(ok, missing),
        "missing": missing,
        "actions": actions,
        "note": case.note,
    }


HONEST = Case(
    "honest-runtime-today",
    [parse_record(line) for line in honest_runtime_lines()],
    None,
    True,
    "Runtime writes capsule_id only. No [run] id, session, or hash.",
)
FOREIGN_ID = Case(
    "foreign-capsule-id",
    [
        parse_record(
            json.dumps(
                {
                    "action": action,
                    "capsule_id": OTHER_CAPSULE,
                    "code": MANIFEST_DENIED,
                    "principal_id": None,
                    "resource": RESOURCE,
                }
            )
        )
        for action in ("write", "read")
    ],
    None,
    True,
    "Planted lines use another component uuid. assigned is None.",
)
EMPTY_SESSION = Case(
    "empty-session-equals-empty",
    [
        parse_record(
            json.dumps(
                {
                    "action": action,
                    "capsule_id": HONEST_CAPSULE,
                    "code": MANIFEST_DENIED,
                    "principal_id": None,
                    "resource": RESOURCE,
                    "session_id": "",
                    "module_hash": "",
                }
            )
        )
        for action in ("write", "read")
    ],
    None,
    True,
    "Empty session and hash become None via optional_string.",
)
ALIAS_HASH = Case(
    "wasm-hash-alias",
    [
        parse_record(
            json.dumps(
                {
                    "action": action,
                    "capsule_id": HONEST_CAPSULE,
                    "code": MANIFEST_DENIED,
                    "principal_id": None,
                    "resource": RESOURCE,
                    "session_id": "sess-1",
                    "wasm_hash": GUEST_HASH,
                }
            )
        )
        for action in ("write", "read")
    ],
    HONEST_CAPSULE,
    True,
    "module_hash alias wasm_hash plus a printed component id.",
)
EMPTY_RECORDS = Case(
    "empty-records-vacuous",
    [],
    HONEST_CAPSULE,
    True,
    "No rows: session/hash any() is false, so those fields look present.",
)
GUEST_FOLLOW = Case(
    "guest-prints-follow-sentence",
    [parse_record(line) for line in honest_runtime_lines()],
    None,
    True,
    "follow sentence is a stderr substring, not a Runtime field.",
)


def m1_require_assigned(assigned, records, guest_hash):
    """Mutant: treat missing assigned as no match (the opposite of today's unwrap_or(true))."""

    def denied(records_, resource, assigned_):
        out = []
        for record in records_:
            if assigned_ is None:
                continue
            if (
                record["resource"] == resource
                and record["code"] == MANIFEST_DENIED
                and record["capsule_id"] == assigned_
            ):
                out.append(record["action"])
        return out

    global denied_actions
    saved = denied_actions
    denied_actions = denied
    try:
        return assigned, records, guest_hash
    finally:
        denied_actions = saved


def apply_and_score(mutant_name, mutate_eval, cases):
    rows = []
    for case in cases:
        rows.append(mutate_eval(case))
    return mutant_name, rows


def main():
    cases = [HONEST, FOREIGN_ID, EMPTY_SESSION, ALIAS_HASH, EMPTY_RECORDS, GUEST_FOLLOW]
    print("## Baseline (code as shipped at 10316585)")
    for case in cases:
        print(evaluate(case))

    print("\n## M1: assigned=None matches any capsule_id (today's unwrap_or(true))")
    print("Finding: FOREIGN_ID cargo_ok=True. Binding does not need the launch id.")
    print(evaluate(FOREIGN_ID))

    print("\n## M2: authorship missing is println, not assert")
    row = evaluate(HONEST)
    print(row)
    print("Finding: cargo_ok True while missing has all three Runtime-ask fields.")

    print("\n## M3: empty session == empty session")
    row = evaluate(EMPTY_SESSION)
    print(row)
    print("Finding: empty strings become None, so they stay unmet, not a match.")

    print("\n## M4: vacuous any() on empty records")
    row = evaluate(EMPTY_RECORDS)
    print(row)
    print("Finding: with a printed component id and no rows, missing is empty.")
    print("The write-then-read assert still fails, so cargo is not ok.")

    print("\n## M5: wasm_hash / guest_hash aliases count as module_hash")
    row = evaluate(ALIAS_HASH)
    print(row)
    print("Finding: a planted wasm_hash plus a [run] id would make run.sh PASS.")

    print("\n## M6: session check is presence, not equality")

    def presence_only():
        records = [
            parse_record(
                json.dumps(
                    {
                        "action": action,
                        "capsule_id": HONEST_CAPSULE,
                        "code": MANIFEST_DENIED,
                        "resource": RESOURCE,
                        "session_id": "other-session",
                        "module_hash": GUEST_HASH,
                    }
                )
            )
            for action in ("write", "read")
        ]
        return evaluate(Case("other-session", records, HONEST_CAPSULE, True, "any non-empty session"))

    print(presence_only())
    print("Finding: any non-empty session_id clears the field. No expected session.")

    print("\n## M7: require assigned (stronger mutant) would fail today's honest run")

    def stronger(case: Case):
        # assigned None => no actions match
        actions = []
        if case.assigned is not None:
            actions = denied_actions(case.records, RESOURCE, case.assigned)
        missing = missing_fields(case.records, case.assigned, GUEST_HASH)
        ok = cargo_ok(actions, case.follow)
        return {
            "case": case.name,
            "cargo_ok": ok,
            "runsh": runsh_result(ok, missing),
            "actions": actions,
            "missing": missing,
        }

    print(stronger(HONEST))
    print("Finding: if the test required a [run] id before matching rows,")
    print("today's honest Runtime run would FAIL, not NEEDS RUNTIME.")

    print("\n## M8: guest-controlled follow sentence")
    print(evaluate(GUEST_FOLLOW))
    print("Finding: cargo_ok depends on stderr text, not a receipt field.")


if __name__ == "__main__":
    main()
