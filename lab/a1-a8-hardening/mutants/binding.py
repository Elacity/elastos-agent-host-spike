#!/usr/bin/env python3
"""Mutants of the r3 A8 asserts. Each mutant asks: would a hunt reach
cargo ok? The real predicates must kill it.

This copies lab/a1-a8-hardening/src/lib.rs authorship_gaps,
bound_denied_actions, host_sequence_function, and parse_capability_record.
It does not launch the Runtime.
"""

from __future__ import annotations

import json
import sys


RESOURCE = "localhost://Public/../../../../.ssh/id_ed25519"
MANIFEST_DENIED = "manifest_capability_denied"
GUEST_FN = "request_journal_grants"
GUEST_HASH = "f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737"
HONEST_CAPSULE = "component-341af27a-6b9c-4892-a618-808f0b687a9d"
FOREIGN = "component-00000000-0000-0000-0000-000000000000"
SESSION = "0123456789abcdef0123456789abcdef"
FOLLOW = "the journal append did not follow its grants"


def is_session_id(word):
    hex_id = word[8:] if word.startswith("session-") else word
    return len(hex_id) == 32 and all(c in "0123456789abcdef" for c in hex_id)


def optional_string(value: dict, key: str):
    raw = value.get(key)
    if not isinstance(raw, str):
        return None
    return raw if raw else None


def parse_record(line: str, aliases: bool = False) -> dict:
    value = json.loads(line)
    module_hash = optional_string(value, "module_hash")
    if aliases:
        module_hash = (
            module_hash
            or optional_string(value, "guest_hash")
            or optional_string(value, "wasm_hash")
        )
    return {
        "action": value.get("action"),
        "resource": value.get("resource"),
        "code": value.get("code"),
        "capsule_id": optional_string(value, "capsule_id"),
        "session_id": optional_string(value, "session_id"),
        "module_hash": module_hash,
        "guest_function": optional_string(value, "guest_function"),
        "seq": value.get("seq") if isinstance(value.get("seq"), int) else None,
    }


def isolation_actions(records):
    return [
        r["action"]
        for r in records
        if r["resource"] == RESOURCE and r["code"] == MANIFEST_DENIED
    ]


def bound_actions(records, assigned):
    if assigned is None:
        return []
    return [
        r["action"]
        for r in records
        if r["resource"] == RESOURCE
        and r["code"] == MANIFEST_DENIED
        and r["capsule_id"] == assigned
    ]


def host_sequence(records, host_log: str):
    for record in records:
        if record.get("guest_function"):
            return record["guest_function"]
    for line in host_log.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = optional_string(value, "guest_function")
        if name:
            return name
    return None


def authorship_gaps(records, assigned, session, guest_hash):
    if any(
        isinstance(r["capsule_id"], str) and any(c.isspace() for c in r["capsule_id"])
        for r in records
    ):
        return "FAIL", "capsule_id whitespace"
    if any(r["session_id"] is not None and r["session_id"] == r["capsule_id"] for r in records):
        return "FAIL", "session aliases capsule_id"
    if assigned is not None and (
        session == assigned or any(r["session_id"] == assigned for r in records)
    ):
        return "FAIL", "session aliases capsule_id"
    if any(r["session_id"] is not None and not is_session_id(r["session_id"]) for r in records):
        return "FAIL", "session_id must be an unguessable per-launch id"
    if session is not None and not is_session_id(session):
        return "FAIL", "session_id must be an unguessable per-launch id"
    seqs = [r.get("seq") for r in records]
    if any(seq is not None for seq in seqs):
        if any(seq is None for seq in seqs):
            return "FAIL", "seq missing on some lines"
        for first, second in zip(seqs, seqs[1:]):
            if second != first + 1:
                return "FAIL", "seq not strictly increasing"
    if assigned is not None and any(r["capsule_id"] != assigned for r in records):
        return "FAIL", "foreign capsule_id"
    if session is not None and any(r["session_id"] != session for r in records):
        return "FAIL", "session mismatch"
    if any(r["module_hash"] not in (None, guest_hash) for r in records):
        return "FAIL", "hash mismatch"
    if any(
        r["guest_function"] not in (None, GUEST_FN) for r in records
    ):
        return "FAIL", "honest sequence requires request_journal_grants"
    missing = []
    if assigned is None:
        missing.append("component id")
    if session is None or not records or any(r["session_id"] is None for r in records):
        missing.append("session id")
    if not records or any(r["module_hash"] != guest_hash for r in records):
        missing.append("guest module hash")
    if not records or any(r["guest_function"] != GUEST_FN for r in records):
        missing.append("guest function")
    if not records or any(r.get("seq") is None for r in records):
        missing.append("receipt seq")
    if missing:
        return "NEEDS RUNTIME", missing
    return "PASS", []


def cargo_result(records, assigned, session, stderr_follow, host_log, window_ok, **kwargs):
    if not window_ok:
        return "FAIL", "receipts outside launch window"
    actions = isolation_actions(records)
    if actions != ["write", "read"]:
        return "FAIL", "write-then-read"
    sequence = host_sequence(records, host_log)
    if sequence not in (None, GUEST_FN):
        return "FAIL", "honest sequence requires request_journal_grants"
    _ = stderr_follow  # guest stderr is not a sequence proof
    return authorship_gaps(records, assigned, session, kwargs.get("guest_hash", GUEST_HASH))


def lines(capsule=HONEST_CAPSULE, extra=None, seqs=None):
    extra = extra or {}
    out = []
    for index, action in enumerate(("write", "read")):
        row = {
            "action": action,
            "capsule_id": capsule,
            "code": MANIFEST_DENIED,
            "principal_id": None,
            "resource": RESOURCE,
        }
        row.update(extra)
        if seqs is not None:
            row["seq"] = seqs[index]
        out.append(json.dumps(row))
    return [parse_record(line) for line in out]


def score(name, result):
    verdict, detail = result
    return f"{name}: {verdict} {detail}"


def mutant_killed(name, mutant_verdict, real_verdict, hunt):
    killed = mutant_verdict == "PASS" and real_verdict != "PASS"
    label = "KILLED" if killed else "SURVIVED"
    print(f"{name}: mutant={mutant_verdict} real={real_verdict} hunt={hunt} {label}")
    return killed


def main():
    honest = lines()
    foreign = lines(FOREIGN)
    follow_guest = lines()
    alias = [
        parse_record(
            json.dumps(
                {
                    "action": action,
                    "capsule_id": HONEST_CAPSULE,
                    "code": MANIFEST_DENIED,
                    "resource": RESOURCE,
                    "session_id": SESSION,
                    "wasm_hash": GUEST_HASH,
                    "guest_function": GUEST_FN,
                }
            ),
            aliases=True,
        )
        for action in ("write", "read")
    ]
    other_session = lines(extra={"session_id": "other-session", "module_hash": GUEST_HASH, "guest_function": GUEST_FN})
    complete = lines(
        extra={"session_id": SESSION, "module_hash": GUEST_HASH, "guest_function": GUEST_FN},
        seqs=(1, 2),
    )

    print("## Real predicates")
    print(score("honest-today", cargo_result(honest, None, None, True, "", True)))
    print(score("foreign-id-no-assigned", cargo_result(foreign, None, None, True, "", True)))
    print(score("foreign-id-with-assigned", cargo_result(foreign, HONEST_CAPSULE, SESSION, True, "", False)))
    print(score("guest-follow-sentence", cargo_result(follow_guest, None, None, True, FOLLOW, True)))
    print(score("after-snapshot", cargo_result(foreign, None, None, True, FOLLOW, False)))
    print(score("complete-bind", cargo_result(complete, HONEST_CAPSULE, SESSION, True, "", True)))

    killed = []

    # M-sequence-stderr: trust guest stderr as the sequence lock.
    def m_stderr():
        records = follow_guest
        if isolation_actions(records) == ["write", "read"] and True:
            return "PASS"
        return "FAIL"

    real, _ = cargo_result(follow_guest, None, None, True, FOLLOW, True)
    killed.append(mutant_killed("M-sequence-stderr", m_stderr(), real, "H-guest-follow-sentence"))

    # M-assigned-match: missing assigned matches any capsule_id and cargo can ok.
    def m_assigned():
        records = foreign
        actions = isolation_actions(records)
        if actions == ["write", "read"]:
            return "PASS"
        return "FAIL"

    real, _ = cargo_result(foreign, None, None, True, "", True)
    killed.append(mutant_killed("M-assigned-none-match", m_assigned(), real, "foreign capsule_id"))

    # M-window: inode None accepts a file written after the snapshot.
    def m_window():
        return "PASS" if isolation_actions(foreign) == ["write", "read"] else "FAIL"

    real, _ = cargo_result(foreign, None, None, True, FOLLOW, False)
    killed.append(mutant_killed("M-after-snapshot-window", m_window(), real, "H-race-after-snapshot"))

    # M-println: missing Runtime-ask fields still cargo ok.
    def m_println():
        return "PASS" if isolation_actions(honest) == ["write", "read"] else "FAIL"

    real, _ = cargo_result(honest, None, None, True, "", True)
    killed.append(mutant_killed("M-println-not-assert", m_println(), real, "honest missing fields"))

    # M-session-presence: any non-empty session clears the field.
    def m_session():
        records = other_session
        if all(r["session_id"] for r in records) and isolation_actions(records) == ["write", "read"]:
            if all(r["module_hash"] == GUEST_HASH and r["guest_function"] == GUEST_FN for r in records):
                return "PASS"
        return "FAIL"

    real, _ = cargo_result(other_session, HONEST_CAPSULE, SESSION, True, "", True)
    killed.append(mutant_killed("M-session-presence", m_session(), real, "other-session"))

    # M-function-optional: guest_function is not required.
    def m_function():
        records = lines(extra={"session_id": SESSION, "module_hash": GUEST_HASH})
        if isolation_actions(records) == ["write", "read"]:
            if all(r["session_id"] == SESSION and r["module_hash"] == GUEST_HASH for r in records):
                return "PASS"
        return "FAIL"

    optional_records = lines(extra={"session_id": SESSION, "module_hash": GUEST_HASH})
    real, _ = cargo_result(optional_records, HONEST_CAPSULE, SESSION, True, "", True)
    killed.append(mutant_killed("M-guest-function-optional", m_function(), real, "missing guest function"))

    # M-hash-alias: wasm_hash counts as module_hash.
    def m_alias():
        if isolation_actions(alias) == ["write", "read"] and all(
            r["module_hash"] == GUEST_HASH and r["session_id"] == SESSION and r["guest_function"] == GUEST_FN
            for r in alias
        ):
            return "PASS"
        return "FAIL"

    real_alias_records = [
        parse_record(
            json.dumps(
                {
                    "action": action,
                    "capsule_id": HONEST_CAPSULE,
                    "code": MANIFEST_DENIED,
                    "resource": RESOURCE,
                    "session_id": SESSION,
                    "wasm_hash": GUEST_HASH,
                    "guest_function": GUEST_FN,
                }
            ),
            aliases=False,
        )
        for action in ("write", "read")
    ]
    real, _ = cargo_result(real_alias_records, HONEST_CAPSULE, SESSION, True, "", True)
    killed.append(mutant_killed("M-hash-alias", m_alias(), real, "wasm_hash alias"))

    alias_session = lines(
        extra={
            "session_id": HONEST_CAPSULE,
            "module_hash": GUEST_HASH,
            "guest_function": GUEST_FN,
        },
        seqs=(1, 2),
    )

    def m_alias_session():
        return "PASS" if isolation_actions(alias_session) == ["write", "read"] else "FAIL"

    real, _ = cargo_result(alias_session, HONEST_CAPSULE, SESSION, True, "", True)
    killed.append(mutant_killed("M-session-alias", m_alias_session(), real, "session == capsule_id"))

    predictable = lines(
        extra={"session_id": "session-1", "module_hash": GUEST_HASH, "guest_function": GUEST_FN},
        seqs=(1, 2),
    )

    def m_session_1():
        return "PASS" if isolation_actions(predictable) == ["write", "read"] else "FAIL"

    real, _ = cargo_result(predictable, HONEST_CAPSULE, "session-1", True, "", True)
    killed.append(mutant_killed("M-session-1", m_session_1(), real, "session-1"))

    gapped = complete[:]
    gapped[1] = dict(gapped[1])
    gapped[1]["seq"] = 3

    def m_seq():
        return "PASS" if isolation_actions(gapped) == ["write", "read"] else "FAIL"

    real, _ = cargo_result(gapped, HONEST_CAPSULE, SESSION, True, "", True)
    killed.append(mutant_killed("M-seq-ignored", m_seq(), real, "seq 1 then 3"))

    print(f"\n{sum(killed)} of {len(killed)} mutants KILLED")
    sys.exit(0 if all(killed) else 1)


if __name__ == "__main__":
    main()
