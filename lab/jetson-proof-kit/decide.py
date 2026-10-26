# Policy oracle that copies fail_closed_linux public functions at
# #307 commit 2c70a0d845f9acc15144a2afec889370612cca66.
#
# This file is not the guard. Simulated-kernel tables use these functions
# because fcl-launch talks to the real kernel. The live kit also runs
# fcl-launch for did-provider, wallet-provider, and model-provider.
#
# Pinned functions from lab/fail-closed-linux/src/lib.rs:
#   TRUNCATE_ABI = 3, IOCTL_DEV_ABI = 5
#   missing_required_mask(abi)
#   missing_rights_reason(abi, mask)
#   file_profile_launches_on_abi(abi)
#   extra floor: "Landlock ABI {n} is below the required {floor}"
#   AbiProbe: "Landlock is not available"
#
# #307 trusts the ABI number. It does not read measured right.truncate
# or right.ioctl_dev. A lying ABI 5 therefore launches under per_right.
import argparse
import sys

PROVIDERS = ("did", "wallet", "model")
ABI_FLOOR = 5
TRUNCATE_ABI = 3
IOCTL_DEV_ABI = 5
MISSING_TRUNCATE = 1
MISSING_IOCTL_DEV = 2
# <linux/capability.h>. Bit 21 is CAP_SYS_ADMIN, not this check.
CAP_SETPCAP = 8
PER_RIGHT_SHA = "2c70a0d845f9acc15144a2afec889370612cca66"
OLD_ABI5_FLOOR_SHA = "129fdc98428c9029b328976511478c46ebe765a6"
FILE_PROFILE_NEEDED_RIGHTS = (
    ("truncate", TRUNCATE_ABI, MISSING_TRUNCATE),
    ("ioctl_dev", IOCTL_DEV_ABI, MISSING_IOCTL_DEV),
)
MEASURED_RIGHTS = ("right.truncate", "right.ioctl_dev")


def parse_facts(text):
    facts = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, sep, rest = stripped.partition(" ")
        if not sep:
            facts[key] = ""
            continue
        facts[key] = rest.strip()
    return facts


def token(facts, key):
    value = facts.get(key, "")
    if not value:
        return ""
    return value.split()[0]


def landlock_abi_value(facts):
    return token(facts, "landlock_abi")


def missing_required_mask(abi):
    mask = 0
    for _name, minimum_abi, bit in FILE_PROFILE_NEEDED_RIGHTS:
        if abi < minimum_abi:
            mask |= bit
    return mask if mask else None


def missing_rights_reason(abi, mask):
    names = [
        f"{name} (needs ABI {minimum_abi})"
        for name, minimum_abi, bit in FILE_PROFILE_NEEDED_RIGHTS
        if mask & bit
    ]
    return "this kernel's Landlock ABI {} cannot deny {}".format(
        abi, "; ".join(names)
    )


def file_profile_launches_on_abi(abi):
    return missing_required_mask(abi) is None


def per_right_table_allowed(pin):
    if not pin:
        return True
    if pin == OLD_ABI5_FLOOR_SHA:
        return False
    return True


def cap_setpcap_from_mask(mask):
    if mask == 0 or mask & (1 << CAP_SETPCAP):
        return "available"
    return "unavailable"


def _available(facts, key):
    return token(facts, key) == "available"


def _measured_missing(facts):
    missing = []
    for key in MEASURED_RIGHTS:
        if not _available(facts, key):
            missing.append(key.split(".", 1)[1])
    return missing


def _layer_blockers(facts):
    blockers = []
    if not _available(facts, "userns"):
        blockers.append("unprivileged user namespace unavailable")
    if not _available(facts, "seccomp"):
        blockers.append("seccomp unavailable")
    cap = token(facts, "cap_setpcap")
    if cap and cap != "available":
        blockers.append("capability bounding set cannot be dropped")
    elif not cap:
        raw = token(facts, "cap_bnd")
        try:
            mask = int(raw, 16)
        except ValueError:
            blockers.append("capability bounding set cannot be dropped")
        else:
            if cap_setpcap_from_mask(mask) != "available":
                blockers.append("capability bounding set cannot be dropped")
    return blockers


def _join(parts):
    return "; ".join(part for part in parts if part)


def _landlock_absent_reason():
    return "Landlock is not available"


def decide_abi5(facts):
    abi = landlock_abi_value(facts)
    if not abi.isdigit():
        landlock = [_landlock_absent_reason()]
    else:
        found = int(abi)
        if found < ABI_FLOOR:
            landlock = [f"Landlock ABI {found} is below the required {ABI_FLOOR}"]
        else:
            landlock = []
    blockers = landlock + _layer_blockers(facts)
    if blockers:
        return "REFUSE", _join(blockers)
    return (
        "LAUNCH",
        _join(
            [
                f"Landlock ABI {abi} meets floor {ABI_FLOOR} (guard trusts the ABI number)",
                "user namespace available",
                "seccomp available",
                "capability bounding set droppable",
            ]
        ),
    )


def decide_per_right(facts, pin=""):
    if not per_right_table_allowed(pin):
        return (
            "REFUSE",
            f"per-right table refused: C0 pin {pin} is the ABI 5 floor, not {PER_RIGHT_SHA}",
        )
    abi = landlock_abi_value(facts)
    if not abi.isdigit():
        landlock = [_landlock_absent_reason()]
    else:
        found = int(abi)
        mask = missing_required_mask(found)
        if mask is not None:
            landlock = [missing_rights_reason(found, mask)]
        else:
            landlock = []
    blockers = landlock + _layer_blockers(facts)
    if blockers:
        return "REFUSE", _join(blockers)
    honesty = [f"Landlock ABI {abi} meets the per-right floor (guard trusts the ABI number)"]
    measured = _measured_missing(facts)
    if measured:
        honesty.append("measured " + ", ".join(measured) + " absent")
    return (
        "LAUNCH",
        _join(
            honesty
            + [
                "user namespace available",
                "seccomp available",
                "capability bounding set droppable",
            ]
        ),
    )


def decide_all(facts, pin=""):
    rows = []
    for provider in PROVIDERS:
        decision, reason = decide_abi5(facts)
        rows.append((provider, "abi5", decision, reason))
        decision, reason = decide_per_right(facts, pin)
        rows.append((provider, "per_right", decision, reason))
    return rows


def format_rows(rows):
    return "".join(
        f"{provider}\t{floor}\t{decision}\t{reason}\n"
        for provider, floor, decision, reason in rows
    )


def main(argv):
    parser = argparse.ArgumentParser(
        description="Policy oracle that copies #307 fail_closed_linux at 2c70a0d8"
    )
    parser.add_argument(
        "--pin",
        default="",
        help="C0 commit pin; the old ABI 5 floor refuses the per-right table",
    )
    parser.add_argument("facts", nargs="?", help="facts file (stdin when omitted)")
    args = parser.parse_args(argv[1:])
    if args.facts:
        with open(args.facts, encoding="utf-8") as handle:
            text = handle.read()
    else:
        text = sys.stdin.read()
    sys.stdout.write(format_rows(decide_all(parse_facts(text), args.pin)))


if __name__ == "__main__":
    main(sys.argv)
