"""Parse the Linux labs on the pinned #296 and #307 commits."""

from __future__ import annotations

import re

from .gitread import locate_line, read_pinned

STORAGE_RIGHT_NAMES = (
    "LANDLOCK_ACCESS_FS_READ_FILE",
    "LANDLOCK_ACCESS_FS_READ_DIR",
    "LANDLOCK_ACCESS_FS_WRITE_FILE",
    "LANDLOCK_ACCESS_FS_TRUNCATE",
    "LANDLOCK_ACCESS_FS_MAKE_REG",
    "LANDLOCK_ACCESS_FS_MAKE_DIR",
    "LANDLOCK_ACCESS_FS_REMOVE_FILE",
    "LANDLOCK_ACCESS_FS_REMOVE_DIR",
)

EIGHT_RIGHT_MASK = 0x41BE


def _extract_macro_names(text: str, macro: str) -> list[str]:
    match = re.search(
        rf"#define {re.escape(macro)} \((.*?)\)\s*$",
        text,
        flags=re.M | re.S,
    )
    if match is None:
        match = re.search(rf"#define {re.escape(macro)} \((.*?)\)", text, flags=re.S)
    if match is None:
        return []
    return re.findall(r"LANDLOCK_ACCESS_FS_[A-Z_]+", match.group(1))


def _const_block_names(text: str, const: str) -> list[str]:
    match = re.search(
        rf"pub const {re.escape(const)}: u64 = (.*?);",
        text,
        flags=re.S,
    )
    if match is None:
        return []
    return re.findall(r"ACCESS_FS_[A-Z_]+", match.group(1))


def parse_linux_confine(setup_c: str, policy_rs: str, sha: str) -> dict:
    """Read the C9 launcher. Verdicts come from the source, not the README."""
    storage_names = _extract_macro_names(setup_c, "LC_STORAGE_RIGHTS")
    unshare = sorted(set(re.findall(r"unshare\(CLONE_NEW(\w+)\)", setup_c)))
    deny_socket = "pub const DENY_SOCKET: bool = true" in policy_rs
    socket_denied = "SYS_socket" in setup_c and "denied[]" in setup_c
    denied_block = ""
    denied_match = re.search(
        r"int denied\[\] = \{([^}]+)\}",
        setup_c,
        flags=re.S,
    )
    if denied_match is not None:
        denied_block = denied_match.group(1)
    socket_in_denied = "SYS_socket" in denied_block
    socketpair_unix = (
        "SYS_socketpair" in setup_c and "AF_UNIX" in setup_c and "deny_network" in setup_c
    )
    ioctl_in_storage = "LANDLOCK_ACCESS_FS_IOCTL_DEV" in storage_names
    parent_rule = 'add_rule(ruleset, pol->parent' in setup_c
    parent_remount = "hide_parent_siblings" in setup_c
    exec_rule = "LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE" in setup_c
    no_root_rule = 'a Landlock rule on `/`' in setup_c or "literal \"/\")" not in setup_c
    uname = "SYS_uname" in setup_c
    pid_ns = "PID" in unshare
    net_ns = "NET" in unshare
    storage_line = locate_line(setup_c, "#define LC_STORAGE_RIGHTS")
    pid_line = locate_line(setup_c, "unshare(CLONE_NEWPID)")
    net_line = locate_line(setup_c, "unshare(CLONE_NEWNET)")
    socket_line = locate_line(setup_c, "SYS_socket,")
    pair_line = locate_line(setup_c, "SYS_socketpair")
    exec_line = locate_line(setup_c, "LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE")
    parent_line = locate_line(setup_c, "pol->parent")
    ioctl_refuse = locate_line(setup_c, "cannot express device ioctl")
    policy_line = locate_line(policy_rs, "pub const DENY_SOCKET")
    file = "lab/linux-confine/helper/setup.c"
    policy_file = "lab/linux-confine/src/policy.rs"
    return {
        "lab": "linux-confine",
        "pr": 296,
        "sha": sha,
        "storage_names": storage_names,
        "storage_has_eight_rights": set(storage_names) == set(STORAGE_RIGHT_NAMES),
        "ioctl_in_storage": ioctl_in_storage,
        "unshare": unshare,
        "deny_socket": deny_socket and socket_in_denied,
        "socketpair_unix": socketpair_unix,
        "parent_rule": parent_rule,
        "parent_remount": parent_remount,
        "exec_rule": exec_rule,
        "no_root_rule": no_root_rule,
        "uname": uname,
        "pid_ns": pid_ns,
        "net_ns": net_ns,
        "socket_denied": socket_denied,
        "lines": {
            "storage": {"file": file, "line": storage_line},
            "pid": {"file": file, "line": pid_line},
            "net": {"file": file, "line": net_line},
            "socket": {"file": file, "line": socket_line},
            "socketpair": {"file": file, "line": pair_line},
            "exec": {"file": file, "line": exec_line},
            "parent": {"file": file, "line": parent_line},
            "ioctl": {"file": file, "line": ioctl_refuse},
            "deny_socket": {"file": policy_file, "line": policy_line},
        },
    }


def parse_fail_closed(lib_rs: str, seccomp_rs: str, real_rs: str, sha: str) -> dict:
    """Read the C0 guard. Verdicts come from the source, not the README."""
    storage_names = _const_block_names(lib_rs, "STORAGE_ROOT_ACCESS")
    needed = re.findall(r'name: "([a-z_]+)"', lib_rs)
    unshare_user_only = (
        "unshare(libc::CLONE_NEWUSER)" in real_rs
        and "CLONE_NEWPID" not in real_rs
        and "CLONE_NEWNET" not in real_rs
    )
    denied_match = re.search(r"pub const DENIED: &\[libc::c_long\] = &\[(.*?)\];", seccomp_rs, flags=re.S)
    denied = denied_match.group(1) if denied_match else ""
    socket_denied = "SYS_socket" in denied
    socketpair_denied = "SYS_socketpair" in denied
    scope_signal = "SCOPE_SIGNAL_ABI: u32 = 6" in lib_rs
    ioctl_needed = "ioctl_dev" in needed
    ioctl_granted = "IOCTL_DEV" in storage_names
    pid_gap = "pid_namespace_and_scope_signal_gaps" in lib_rs
    exec_rule = "EXECUTABLE_ACCESS" in lib_rs
    storage_line = locate_line(lib_rs, "pub const STORAGE_ROOT_ACCESS")
    needed_line = locate_line(lib_rs, 'name: "ioctl_dev"')
    scope_line = locate_line(lib_rs, "SCOPE_SIGNAL_ABI")
    gap_line = locate_line(lib_rs, "pid_namespace_and_scope_signal_gaps")
    socket_line = locate_line(seccomp_rs, "SYS_socket")
    pair_line = locate_line(seccomp_rs, "SYS_socketpair")
    unshare_line = locate_line(real_rs, "CLONE_NEWUSER")
    exec_line = locate_line(lib_rs, "pub const EXECUTABLE_ACCESS")
    return {
        "lab": "fail-closed-linux",
        "pr": 307,
        "sha": sha,
        "storage_names": storage_names,
        "storage_has_eight_rights": set(storage_names)
        == {
            "ACCESS_FS_READ_FILE",
            "ACCESS_FS_READ_DIR",
            "ACCESS_FS_WRITE_FILE",
            "ACCESS_FS_TRUNCATE",
            "ACCESS_FS_MAKE_REG",
            "ACCESS_FS_MAKE_DIR",
            "ACCESS_FS_REMOVE_FILE",
            "ACCESS_FS_REMOVE_DIR",
        },
        "ioctl_in_storage": ioctl_granted,
        "ioctl_needed": ioctl_needed,
        "unshare_user_only": unshare_user_only,
        "socket_denied": socket_denied,
        "socketpair_denied": socketpair_denied,
        "scope_signal_abi6": scope_signal,
        "pid_gap": pid_gap,
        "exec_rule": exec_rule,
        "needed": needed,
        "lines": {
            "storage": {"file": "lab/fail-closed-linux/src/lib.rs", "line": storage_line},
            "ioctl": {"file": "lab/fail-closed-linux/src/lib.rs", "line": needed_line},
            "scope": {"file": "lab/fail-closed-linux/src/lib.rs", "line": scope_line},
            "pid_gap": {"file": "lab/fail-closed-linux/src/lib.rs", "line": gap_line},
            "socket": {"file": "lab/fail-closed-linux/src/seccomp.rs", "line": socket_line},
            "socketpair": {"file": "lab/fail-closed-linux/src/seccomp.rs", "line": pair_line},
            "unshare": {"file": "lab/fail-closed-linux/src/real.rs", "line": unshare_line},
            "exec": {"file": "lab/fail-closed-linux/src/lib.rs", "line": exec_line},
        },
    }


def load_linux(pins: dict, root=None) -> tuple[dict, dict]:
    confine_sha = pins["linux_confine"]["sha"]
    guard_sha = pins["fail_closed_linux"]["sha"]
    setup = read_pinned(confine_sha, "lab/linux-confine/helper/setup.c", root)
    policy = read_pinned(confine_sha, "lab/linux-confine/src/policy.rs", root)
    lib = read_pinned(guard_sha, "lab/fail-closed-linux/src/lib.rs", root)
    seccomp = read_pinned(guard_sha, "lab/fail-closed-linux/src/seccomp.rs", root)
    real = read_pinned(guard_sha, "lab/fail-closed-linux/src/real.rs", root)
    return parse_linux_confine(setup, policy, confine_sha), parse_fail_closed(
        lib, seccomp, real, guard_sha
    )


def _cite(lines: dict, key: str, rule: str, note: str, verdict: str) -> dict:
    cell = lines[key]
    return {
        "verdict": verdict,
        "rule": rule,
        "file": cell["file"],
        "line": cell["line"],
        "note": note,
    }


def linux_confine_sides(parsed: dict, provider: str) -> dict:
    """C9 launcher verdicts for one provider."""
    lines = parsed["lines"]
    storage_verdict = "allow" if parsed["storage_has_eight_rights"] else "missing"
    parent_note = (
        "wallet launch bind-mounts a private parent that holds only STORAGE_ROOT, then grants read of that parent"
        if provider == "wallet-provider" and parsed["parent_remount"]
        else "Landlock has no literal-directory rule; did and model get no host-parent grant"
    )
    parent_verdict = (
        "partial"
        if provider == "wallet-provider" and parsed["parent_remount"]
        else "missing"
    )
    return {
        "bound-executable": _cite(
            lines,
            "exec",
            "Landlock EXECUTE|READ_FILE on PROVIDER_EXECUTABLE",
            "Linux execve opens the binary for read and execute",
            "allow" if parsed["exec_rule"] else "missing",
        ),
        "storage.root": _cite(
            lines,
            "storage",
            f"LC_STORAGE_RIGHTS eight bits (0x{EIGHT_RIGHT_MASK:x})",
            "read/write/truncate/make-reg/make-dir/remove; no ioctl, refer, or special-file create",
            storage_verdict,
        ),
        "storage.parent": _cite(
            lines,
            "parent",
            "hide_parent_siblings + parent read rule"
            if parent_verdict == "partial"
            else "no Landlock rule on the host STORAGE_PARENT",
            parent_note,
            parent_verdict,
        ),
        "startup-root-directory": _cite(
            lines,
            "storage",
            "no Landlock rule on /",
            "a rule on / would grant the whole tree, so the launcher adds none",
            "missing",
        ),
        "startup-sysctl": _cite(
            lines,
            "exec",
            "SYS_uname on the probe filter; no sysctl right",
            "Landlock has no sysctl; the provider filter admits the loader syscalls it needs",
            "partial" if parsed["uname"] else "missing",
        ),
        "outside.read": _cite(
            lines,
            "storage",
            "Landlock default denial outside STORAGE_ROOT",
            "no path rule names an outside file",
            "deny",
        ),
        "outside.write": _cite(
            lines,
            "storage",
            "Landlock default denial outside STORAGE_ROOT",
            "no path rule names an outside file",
            "deny",
        ),
        "network": _cite(
            lines,
            "socket" if parsed["deny_socket"] else "deny_socket",
            "network namespace + seccomp denied[] includes SYS_socket"
            if parsed["net_ns"]
            else "seccomp denied[] includes SYS_socket",
            "DENY_SOCKET stays true; connect/bind/listen/accept are refused by name",
            "deny" if parsed["deny_socket"] and parsed["net_ns"] else "missing",
        ),
        "unix-socketpair": _cite(
            lines,
            "socketpair",
            "provider filter allows socketpair only when arg0 is AF_UNIX",
            "model Tokio needs the pair; did and wallet take the same filter; socket itself stays refused",
            "allow" if parsed["socketpair_unix"] else "deny",
        ),
        "exec.other": _cite(
            lines,
            "exec",
            "Landlock EXECUTE only on PROVIDER_EXECUTABLE",
            "a copy under STORAGE_ROOT is readable and not executable",
            "deny" if parsed["exec_rule"] else "missing",
        ),
        "signal.host": _cite(
            lines,
            "pid",
            "unshare(CLONE_NEWPID)",
            "a host pid cannot be named inside the new PID namespace",
            "deny" if parsed["pid_ns"] else "missing",
        ),
        "device.ioctl": _cite(
            lines,
            "ioctl",
            "IOCTL_DEV is handled and not in LC_STORAGE_RIGHTS",
            "ABI below 5 refuses the start so the deny cannot be dropped",
            "deny" if (not parsed["ioctl_in_storage"] and parsed["storage_has_eight_rights"]) else "allow",
        ),
    }


def fail_closed_sides(parsed: dict, provider: str) -> dict:
    """C0 guard verdicts. The three providers share one file-profile list."""
    del provider
    lines = parsed["lines"]
    storage_verdict = "allow" if parsed["storage_has_eight_rights"] else "missing"
    signal_verdict = "partial" if parsed["scope_signal_abi6"] and parsed["pid_gap"] else "missing"
    return {
        "bound-executable": _cite(
            lines,
            "exec",
            "EXECUTABLE_ACCESS = EXECUTE|READ_FILE",
            "the guard adds a path rule only for the named executable",
            "allow" if parsed["exec_rule"] else "missing",
        ),
        "storage.root": _cite(
            lines,
            "storage",
            "STORAGE_ROOT_ACCESS eight bits",
            "same eight-right mask as #296; no REFER, no IOCTL_DEV",
            storage_verdict,
        ),
        "storage.parent": _cite(
            lines,
            "storage",
            "no STORAGE_PARENT path rule",
            "the guard unshares only CLONE_NEWUSER and grants the storage root",
            "missing",
        ),
        "startup-root-directory": _cite(
            lines,
            "storage",
            "no Landlock rule on /",
            "the guard does not grant the startup root-directory read",
            "missing",
        ),
        "startup-sysctl": _cite(
            lines,
            "unshare",
            "no sysctl grant",
            "the seccomp layer is a deny-list; it does not name sysctl-read",
            "missing",
        ),
        "outside.read": _cite(
            lines,
            "storage",
            "Landlock default denial outside STORAGE_ROOT",
            "F14 plants a parent-covering storage rule",
            "deny",
        ),
        "outside.write": _cite(
            lines,
            "storage",
            "Landlock default denial outside STORAGE_ROOT",
            "F14 plants a parent-covering storage rule",
            "deny",
        ),
        "network": _cite(
            lines,
            "socket",
            "seccomp DENIED includes SYS_socket",
            "TCP bind/connect is not a launch requirement; the filter denies the call",
            "deny" if parsed["socket_denied"] else "missing",
        ),
        "unix-socketpair": _cite(
            lines,
            "socketpair",
            "seccomp DENIED includes SYS_socketpair",
            "no AF_UNIX exception; this is stricter than the #296 provider filter",
            "deny" if parsed["socketpair_denied"] else "allow",
        ),
        "exec.other": _cite(
            lines,
            "exec",
            "EXECUTABLE_ACCESS only on the named file",
            "Landlock EXECUTE is not granted on STORAGE_ROOT",
            "deny" if parsed["exec_rule"] else "missing",
        ),
        "signal.host": _cite(
            lines,
            "pid_gap",
            "LANDLOCK_SCOPE_SIGNAL at ABI 6; no PID namespace",
            "the guard unshares only CLONE_NEWUSER; a host signal is a named gap below ABI 6",
            signal_verdict,
        ),
        "device.ioctl": _cite(
            lines,
            "ioctl",
            "ioctl_dev is a needed deny-right (ABI 5), not a storage grant",
            "FILE_PROFILE_NEEDED_RIGHTS keeps the start refused when the ABI cannot deny ioctl",
            "deny" if parsed["ioctl_needed"] and not parsed["ioctl_in_storage"] else "allow",
        ),
    }
