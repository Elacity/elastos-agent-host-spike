# Decide, from host facts, whether did, wallet, and model would launch
# under a single ABI 5 floor or a per-right floor.
# Reads a facts file or stdin. Prints one TSV row per provider and floor:
# provider<TAB>floor<TAB>LAUNCH|REFUSE<TAB>reason
import sys

PROVIDERS = ("did", "wallet", "model")
ABI_FLOOR = 5
REQUIRED_RIGHTS = ("right.truncate", "right.ioctl_dev")
RIGHT_NAMES = {
    "right.truncate": "TRUNCATE",
    "right.ioctl_dev": "IOCTL_DEV",
}


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


def _available(facts, key):
    return token(facts, key) == "available"


def _missing_required_rights(facts):
    missing = []
    for key in REQUIRED_RIGHTS:
        if not _available(facts, key):
            missing.append(RIGHT_NAMES[key])
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
            if mask != 0 and (mask & (1 << 21)) == 0:
                blockers.append("capability bounding set cannot be dropped")
    return blockers


def _join(parts):
    return "; ".join(part for part in parts if part)


def decide_abi5(facts):
    abi = landlock_abi_value(facts)
    landlock = []
    if abi.isdigit():
        found = int(abi)
        if found < ABI_FLOOR:
            landlock.append(f"Landlock ABI {found} is below the required {ABI_FLOOR}")
    else:
        landlock.append(f"Landlock is not available ({abi or 'missing'})")
    blockers = landlock + _layer_blockers(facts)
    if blockers:
        return "REFUSE", _join(blockers)
    return (
        "LAUNCH",
        _join(
            [
                f"Landlock ABI {abi} meets floor {ABI_FLOOR}",
                "user namespace available",
                "seccomp available",
                "capability bounding set droppable",
            ]
        ),
    )


def decide_per_right(facts):
    abi = landlock_abi_value(facts)
    landlock = []
    if not abi.isdigit():
        landlock.append(f"Landlock is not available ({abi or 'missing'})")
    missing = _missing_required_rights(facts)
    if missing:
        landlock.append("missing " + ", ".join(missing))
    blockers = landlock + _layer_blockers(facts)
    if blockers:
        return "REFUSE", _join(blockers)
    return (
        "LAUNCH",
        _join(
            [
                "TRUNCATE and IOCTL_DEV available",
                "user namespace available",
                "seccomp available",
                "capability bounding set droppable",
            ]
        ),
    )


def decide_all(facts):
    rows = []
    for provider in PROVIDERS:
        for floor, fn in (("abi5", decide_abi5), ("per_right", decide_per_right)):
            decision, reason = fn(facts)
            rows.append((provider, floor, decision, reason))
    return rows


def format_rows(rows):
    return "".join(
        f"{provider}\t{floor}\t{decision}\t{reason}\n"
        for provider, floor, decision, reason in rows
    )


def main(argv):
    if len(argv) > 1:
        with open(argv[1], encoding="utf-8") as handle:
            text = handle.read()
    else:
        text = sys.stdin.read()
    sys.stdout.write(format_rows(decide_all(parse_facts(text))))


if __name__ == "__main__":
    main(sys.argv)
