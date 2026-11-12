"""Comparison rights consumed from the existing declared-rights template.

C8 / spark/confine 005 already owns the bridge-contract template:
`CONTRACT_RIGHTS`, `PLATFORM_BASELINE_IDS`, and `SHARED_RULES` in
`capsules/wallet-provider/tests/confine.rs`, plus each provider's
`tests/fixtures/confine/declared-rights.json`.

This lab does not add a second template. It reads those files and splits
the two `storage` rules so B4 can compare them one by one. The remaining
rows are the implicit denials of `(deny default)` and `(deny network*)`.
Those denials are not new declared rights.

`baseline.json` proposes one polarity per comparison right, including a
`STORAGE_PARENT` right. It is a proposal. It is not a second C8 template.
"""

PROVIDERS = ("did-provider", "wallet-provider", "model-provider")

# The two approved ids the shared contract names. A declared-rights file
# may claim only these under `rights`.
CONTRACT_RIGHT_IDS = ("storage", "bound-executable")

# The two platform-baseline ids the shared contract names.
PLATFORM_BASELINE_IDS = ("startup-root-directory", "startup-sysctl")

SHARED_RULES = {
    "bound-executable": '(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))',
    "storage.parent": '(allow file-read* (literal (param "STORAGE_PARENT")))',
    "storage.root": '(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))',
}

STARTUP_RULES = {
    "startup-root-directory": '(allow file-read* (literal "/"))',
    "startup-root-directory-model": '(allow file-read-data (literal "/"))',
    "startup-sysctl": "(allow sysctl-read)",
}

DECLARED_RIGHTS_ROLE = (
    "lab stand-in for the Runtime generator's input, not a manifest field"
)

# Each row is one B4 comparison. `declared` is the C8 id, or None when the
# row is an implicit denial rather than an approved right.
COMPARISON_RIGHTS = (
    {
        "id": "bound-executable",
        "declared": "bound-executable",
        "kind": "declared",
        "title": "exec the bound provider binary",
    },
    {
        "id": "storage.root",
        "declared": "storage",
        "kind": "declared",
        "title": "read and write under STORAGE_ROOT",
    },
    {
        "id": "storage.parent",
        "declared": "storage",
        "kind": "declared",
        "title": "literal read of STORAGE_PARENT only",
    },
    {
        "id": "startup-root-directory",
        "declared": "startup-root-directory",
        "kind": "platform_baseline",
        "title": "startup read of /",
    },
    {
        "id": "startup-sysctl",
        "declared": "startup-sysctl",
        "kind": "platform_baseline",
        "title": "startup sysctl-read",
    },
    {
        "id": "outside.read",
        "declared": None,
        "kind": "implied_deny",
        "implied_by": "(deny default)",
        "title": "read outside STORAGE_ROOT",
    },
    {
        "id": "outside.write",
        "declared": None,
        "kind": "implied_deny",
        "implied_by": "(deny default)",
        "title": "write outside STORAGE_ROOT",
    },
    {
        "id": "network",
        "declared": None,
        "kind": "implied_deny",
        "implied_by": "(deny network*)",
        "title": "network sockets",
    },
    {
        "id": "unix-socketpair",
        "declared": None,
        "kind": "implied_deny",
        "implied_by": "(deny network*)",
        "title": "AF_UNIX socketpair",
    },
    {
        "id": "exec.other",
        "declared": None,
        "kind": "implied_deny",
        "implied_by": "(deny default)",
        "title": "exec a file other than PROVIDER_EXECUTABLE",
    },
    {
        "id": "signal.host",
        "declared": None,
        "kind": "implied_deny",
        "implied_by": "(deny default)",
        "title": "signal a host process",
    },
    {
        "id": "device.ioctl",
        "declared": None,
        "kind": "implied_deny",
        "implied_by": "(deny default)",
        "title": "device ioctl",
    },
)

NOT_RUN = {
    "kind": "static source comparison",
    "linux_x86_64_execution": "NOT RUN",
    "jetson_aarch64_execution": "NOT RUN",
    "macos_execution": "NOT RUN",
}
