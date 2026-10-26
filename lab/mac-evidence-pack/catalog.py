"""Pinned macOS evidence rows. The pack calls these runners; it does not reimplement them."""

from __future__ import annotations

from dataclasses import dataclass


REPO = "https://github.com/Elacity/elastos-agent-host-spike.git"

# Draft-PR heads recorded on 26 Oct 2026. The pack checks out this exact commit.
PIN_A8 = (
    "cursor/a1-a8-hardening-85ce",
    "1a82d25bdd00d3a383433de84e97c39a4184d107",
    301,
)
PIN_C = (
    "cursor/redteam-fix-4bfb",
    "fa1841f35d32e7bea98e124fd406231d0088fd4e",
    323,
)
PIN_A6A12 = (
    "cursor/a6-a12-evidence-fix-6e3b",
    "011d01f283a3f4ed4717383ecedf55622d451b4d",
    343,
)
PIN_A14 = (
    "cursor/demo-a14-installed-demo-83e1",
    "39b4b47edc64d8705a0294c978e6171819cea9fc",
    289,
)


@dataclass(frozen=True)
class Row:
    """One summary line. Several rows may share a checkout (same commit)."""

    id: str
    title: str
    branch: str
    commit: str
    pr: int
    commands: tuple[tuple[str, ...], ...]
    expect_ok: tuple[str, ...] = ()
    expect_text: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    unset_cargo_target: bool = False
    demo_pointer: str = ""

    @property
    def checkout_name(self) -> str:
        return f"pr-{self.pr}-{self.commit[:12]}"


def _row(
    id: str,
    title: str,
    pin: tuple[str, str, int],
    commands: list[list[str]],
    **kwargs,
) -> Row:
    branch, commit, pr = pin
    return Row(
        id=id,
        title=title,
        branch=branch,
        commit=commit,
        pr=pr,
        commands=tuple(tuple(cmd) for cmd in commands),
        **kwargs,
    )


ROWS: tuple[Row, ...] = (
    _row(
        "A8",
        "A8 macOS run: agent-host host key refused by the Runtime",
        PIN_A8,
        [["bash", "lab/a1-a8-hardening/run.sh"]],
        expect_ok=("agent_host_host_key_read_is_refused",),
        expect_text=("A8 | agent_host_host_key_read_is_refused | PASS",),
        notes=(
            "Existing runner on draft PR #301. The shipped-bytes row stays BLOCKED (AC-002-ARGS).",
        ),
    ),
    _row(
        "C1",
        "C1 did-provider refuses to start without its storage root",
        PIN_C,
        [
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "capsules/did-provider/Cargo.toml",
                "init_requires_storage_without_key",
                "--",
                "--exact",
                "--nocapture",
            ]
        ],
        expect_ok=("init_requires_storage_without_key",),
        notes=("Named test from #323's did-provider tree. Not a sandbox-exec row.",),
    ),
    _row(
        "C2",
        "C2 denied nickname read reports a storage error",
        PIN_C,
        [
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "elastos/crates/elastos-identity/Cargo.toml",
                "nickname_metadata_change_reports_storage_error",
                "--",
                "--exact",
                "--nocapture",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "capsules/did-provider/Cargo.toml",
                "init_reports_nickname_read_error",
                "--",
                "--exact",
                "--nocapture",
            ],
        ],
        expect_ok=(
            "nickname_metadata_change_reports_storage_error",
            "init_reports_nickname_read_error",
        ),
        notes=("Named tests from #323. Store row is cfg(unix).",),
    ),
    _row(
        "C3",
        "C3 did-provider confine.sb denies outside write and read",
        PIN_C,
        [
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "capsules/did-provider/Cargo.toml",
                "--test",
                "confine",
                "outside_write_denied",
                "--",
                "--exact",
                "--nocapture",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "capsules/did-provider/Cargo.toml",
                "--test",
                "confine",
                "outside_read_denied",
                "--",
                "--exact",
                "--nocapture",
            ],
        ],
        expect_ok=("outside_write_denied", "outside_read_denied"),
        notes=(
            "sandbox-exec tests from #323. On Linux they are ignored; a skip is not a pass.",
        ),
    ),
    _row(
        "C4",
        "C4 verify_did_recovery under the did-provider profile",
        PIN_C,
        [
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "capsules/did-provider/Cargo.toml",
                "--test",
                "confine",
                "verify_did_recovery_under_profile",
                "--",
                "--exact",
                "--nocapture",
            ]
        ],
        expect_ok=("verify_did_recovery_under_profile",),
        notes=("sandbox-exec test from #323.",),
    ),
    _row(
        "C5",
        "C5 wallet-provider refuses to start without its storage root",
        PIN_C,
        [
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "capsules/wallet-provider/Cargo.toml",
                "missing_storage_root_is_refused",
                "--",
                "--exact",
                "--nocapture",
            ]
        ],
        expect_ok=("missing_storage_root_is_refused",),
        notes=("Named test from #323's wallet-provider tree. Not a sandbox-exec row.",),
    ),
    _row(
        "C6",
        "C6 wallet-provider confine.sb denies outside write and read",
        PIN_C,
        [
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "capsules/wallet-provider/Cargo.toml",
                "--test",
                "confine",
                "confined_outside_write_is_denied",
                "--",
                "--exact",
                "--nocapture",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "capsules/wallet-provider/Cargo.toml",
                "--test",
                "confine",
                "confined_outside_read_is_denied",
                "--",
                "--exact",
                "--nocapture",
            ],
        ],
        expect_ok=(
            "confined_outside_write_is_denied",
            "confined_outside_read_is_denied",
        ),
        notes=("sandbox-exec tests from #323.",),
    ),
    _row(
        "C7",
        "C7 model-provider confine.sb serves under the profile and denies outside write",
        PIN_C,
        [
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "capsules/model-provider/Cargo.toml",
                "--test",
                "confine",
                "model_provider_ops_under_profile",
                "--",
                "--exact",
                "--nocapture",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "capsules/model-provider/Cargo.toml",
                "--test",
                "confine",
                "model_outside_write_denied",
                "--",
                "--exact",
                "--nocapture",
            ],
        ],
        expect_ok=("model_provider_ops_under_profile", "model_outside_write_denied"),
        notes=("sandbox-exec tests from #323.",),
    ),
    _row(
        "A6",
        "A6 token bind plus full ThrowawayHome journeys",
        PIN_A6A12,
        [
            ["sh", "lab/a6-a12-evidence-fix/run.sh"],
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "lab/agent-conformance/Cargo.toml",
                "--test",
                "effects",
                "two_instances_overlap_with_separate_grants",
                "--",
                "--exact",
                "--show-output",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "lab/agent-conformance/Cargo.toml",
                "--test",
                "effects",
                "instance_grant_does_not_authorise_sibling",
                "--",
                "--exact",
                "--show-output",
            ],
        ],
        expect_ok=(
            "a6_owner_may_use_own_session_token",
            "a6_sibling_presenting_owner_token_is_refused",
            "two_instances_overlap_with_separate_grants",
            "instance_grant_does_not_authorise_sibling",
        ),
        notes=(
            "lab/a6-a12-evidence-fix/run.sh on draft PR #343, then the existing A6 journeys.",
            "ThrowawayHome is macOS only (lab/agent-conformance/src/harness.rs).",
        ),
    ),
    _row(
        "A12",
        "A12 in-root cleanup plus runtime-temp census",
        PIN_A6A12,
        [
            ["sh", "lab/a6-a12-evidence-fix/run.sh"],
            [
                "cargo",
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "lab/agent-conformance/Cargo.toml",
                "--test",
                "runtime",
                "cleanup_census_refuses_each_leftover",
                "--",
                "--exact",
                "--nocapture",
            ],
        ],
        expect_ok=(
            "a12_census_lists_runtime_storage",
            "cleanup_census_refuses_each_leftover",
        ),
        notes=(
            "In-root leftover is cleanup_census_refuses_each_leftover (ThrowawayHome).",
            "run.sh also walks /tmp/elastos/storage; this pack itself never deletes that tree.",
        ),
    ),
    _row(
        "A14",
        "A14 installed-demo preflight only",
        PIN_A14,
        [["sh", "lab/demo-a14/preflight.sh"]],
        expect_text=("preflight: OK",),
        unset_cargo_target=True,
        demo_pointer=(
            "A14 demo itself is NOT RUN by this pack. "
            "On this checkout run the remaining morning steps in lab/demo-a14/RUNBOOK.md: "
            "bash lab/demo-a14/install.sh --sign ; bash lab/demo-a14/run.sh ; "
            "then open the newest folder under "
            "$HOME/Library/Application Support/elastos-demo-a14/runs/ . "
            "Book A14 only on the line A14: PASS."
        ),
        notes=(
            "Calls lab/demo-a14/preflight.sh from draft PR #289 only.",
            "Does not call install.sh or run.sh.",
        ),
    ),
)


def row_by_id(row_id: str) -> Row:
    for row in ROWS:
        if row.id == row_id:
            return row
    raise KeyError(row_id)


def unique_checkouts() -> list[tuple[str, str, int]]:
    seen = []
    out = []
    for row in ROWS:
        key = (row.branch, row.commit, row.pr)
        if key not in seen:
            seen.append(key)
            out.append(key)
    return out


def a14_runs_demo(rows: tuple[Row, ...] = ROWS) -> bool:
    """True when any A14 command would start the installed demo."""
    banned = ("lab/demo-a14/install.sh", "lab/demo-a14/run.sh", "demo.py")
    for row in rows:
        if row.id != "A14":
            continue
        for cmd in row.commands:
            joined = " ".join(cmd)
            for token in banned:
                if token in joined and "preflight.sh" not in joined:
                    return True
            if any(part.endswith("install.sh") or part.endswith("run.sh") for part in cmd):
                return True
            if "demo.py" in cmd:
                return True
    return False
