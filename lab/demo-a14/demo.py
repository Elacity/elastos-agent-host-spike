#!/usr/bin/env python3
"""One install and one run for M1 check A14, bound to one VERSIONS.json.

`install` takes the receipt that lab/agent-conformance/run.sh writes, pins the
Runtime and localhost-provider it names, and records in INSTALL.json the hash of
the agent-host guest and of every test executable and provider binary Cargo
built for the journeys. `run` refuses before any journey when an installed file,
a recorded executable, the receipt or the checkout differs, and when signing is
on, when either receipt file lacks a valid signature by this machine's demo key.
It then walks journeys.json and checks every identity the journeys print.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

LANE = Path(__file__).resolve().parent
REPO = LANE.parents[1]
JOURNEYS = LANE / "journeys.json"
RECEIPT_SCHEMA = "agent-conformance.versions/v1"
INSTALL_SCHEMA = "demo-a14.install/v1"
JOURNEYS_SCHEMA = "demo-a14.journeys/v1"
A14_ROW = "versions_receipt (A14) | PASS"
IDENTITY_PREFIX = "version identity: "
RECEIPT_LINE = "versions receipt: "
SKIP_MARKERS = ("SKIP ", "SKIPPED ")
NATIVE = {"elastos": "runtime_sha256", "localhost-provider": "localhost_provider_sha256"}
AGENT_HOST = "capsules/agent-host/agent-host.component.wasm"
# The conformance run builds offline, so install fetches every manifest first.
FETCH = (
    "elastos/Cargo.toml",
    "elastos/tools/componentize/Cargo.toml",
    "lab/agent-conformance/Cargo.toml",
    "examples/agent-host/Cargo.toml",
    "capsules/did-provider/Cargo.toml",
    "capsules/wallet-provider/Cargo.toml",
    "capsules/model-provider/Cargo.toml",
)
SUITE_TIMEOUT = 1800
EXIT_PASS, EXIT_FAIL, EXIT_USAGE, EXIT_REFUSED, EXIT_NOT_RUN = 0, 1, 2, 3, 4
PASSING = ("PASS", "REFUSED")
SIGNER = "demo-a14"
SIGNING_NAMESPACE = "demo-a14-receipt"
SIGNED = ("VERSIONS.json", "INSTALL.json")
SIGNATURE_SCOPE = (
    "it proves VERSIONS.json and INSTALL.json are unchanged since install on this machine; "
    "it does not prove who published them"
)
CARGO_RUNNING = re.compile(r"^\s+Running .*\((.+)\)$")
NEED_FREE = 40 * 1024 ** 3
MAC_TOOLS = (
    ("/usr/bin/shasum", "/usr/bin/shasum is missing; the conformance run hashes binaries with this path"),
    ("/usr/sbin/lsof", "/usr/sbin/lsof is missing; the conformance run checks earlier homes with this path"),
    (
        "/usr/bin/sandbox-exec",
        "/usr/bin/sandbox-exec is missing; the C1-C7 steps run provider profiles with this macOS program",
    ),
)
RUSTC_TRIPLE = {
    ("Darwin", "arm64"): "aarch64-apple-darwin",
    ("Darwin", "x86_64"): "x86_64-apple-darwin",
    ("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
    ("Linux", "aarch64"): "aarch64-unknown-linux-gnu",
    ("Linux", "arm64"): "aarch64-unknown-linux-gnu",
}


@dataclass(frozen=True)
class Layout:
    repo: Path
    install: Path

    @property
    def conformance(self) -> Path:
        return self.repo / "lab" / "agent-conformance"

    @property
    def runtime_build(self) -> Path:
        return self.conformance / "target" / "runtime" / "debug"

    @property
    def agent_host_wasm(self) -> Path:
        return self.repo / "examples" / "agent-host" / "agent-host.component.wasm"

    @property
    def signing_key(self) -> Path:
        return self.install.parent / "signing" / "receipt-signing.key"

    @property
    def signing_pub(self) -> Path:
        return self.signing_key.with_name(self.signing_key.name + ".pub")


@dataclass(frozen=True)
class Checkout:
    commit: Optional[str]
    tree: Optional[str]
    clean: bool
    error: Optional[str] = None


@dataclass(frozen=True)
class Step:
    id: str
    check: str
    title: str
    expect: str
    suite: str
    test: str
    platform: str
    reason: str
    show: tuple = ()


@dataclass(frozen=True)
class Outcome:
    step: Step
    status: str
    detail: str
    shown: tuple = ()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def is_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def pinned_channel(repo: Path) -> Optional[str]:
    try:
        text = (repo / "rust-toolchain.toml").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("channel"):
            _, _, value = stripped.partition("=")
            return value.strip().strip("\"'") or None
    return None


def rustup_home(env: dict) -> Path:
    return Path(env.get("RUSTUP_HOME") or Path.home() / ".rustup")


def toolchain_root(repo: Path, host_os: str, machine: str, env: dict) -> Optional[Path]:
    channel = pinned_channel(repo)
    triple = RUSTC_TRIPLE.get((host_os, machine))
    if not channel or not triple:
        return None
    return rustup_home(env) / "toolchains" / f"{channel}-{triple}"


def space_problem(label: str, path: Path) -> Optional[str]:
    if " " in str(path):
        return (
            f"{label} contains a space ({path}); the guest build puts that path in RUSTFLAGS, "
            "and rustc splits RUSTFLAGS on spaces"
        )
    return None


def proc_translated() -> str:
    try:
        done = subprocess.run(
            ["sysctl", "-n", "sysctl.proc_translated"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        )
    except OSError:
        return "0"
    return done.stdout.strip() if done.returncode == 0 and done.stdout.strip() else "0"


def machine_problems(
    layout: Layout,
    host_os: str,
    env: Optional[dict] = None,
    disk_free: Optional[Callable] = None,
    machine: Optional[str] = None,
    translated: Optional[str] = None,
    present: Optional[Callable] = None,
    home: Optional[Path] = None,
) -> list:
    """Why this machine cannot start the install. Empty when it can.

    Looks at directories and `sysctl` only. It does not start rustup, rustc, or cargo.
    """
    env = dict(os.environ if env is None else env)
    machine = platform.machine() if machine is None else machine
    present = present or (lambda path: os.path.isfile(path) and os.access(path, os.X_OK))
    free_of = disk_free or (lambda path: shutil.disk_usage(path).free)
    problems = []
    if host_os == "Darwin":
        if machine != "arm64":
            problems.append(
                f"architecture is {machine}; A14 needs native Apple Silicon (arm64). "
                "open a native arm64 Terminal"
            )
        if translated is None:
            translated = proc_translated()
        if translated == "1":
            problems.append("this shell is Rosetta (sysctl.proc_translated=1); open a native arm64 Terminal")
        for path, message in MAC_TOOLS:
            if not present(path):
                problems.append(message)
    raw_target = env.get("CARGO_TARGET_DIR")
    if raw_target:
        target = Path(raw_target)
        if target.is_absolute() and not inside(layout.repo, str(target)):
            problems.append(
                f"CARGO_TARGET_DIR={raw_target} is outside the repository; "
                "install records test executables only from inside the checkout and refuses these"
            )
    channel = pinned_channel(layout.repo)
    if not channel:
        problems.append("rust-toolchain.toml has no channel pin")
    root = toolchain_root(layout.repo, host_os, machine, env)
    triple = RUSTC_TRIPLE.get((host_os, machine))
    if channel and triple and root is not None:
        rustc = root / "bin" / "rustc"
        wasm = root / "lib" / "rustlib" / "wasm32-unknown-unknown"
        if not rustc.is_file():
            problems.append(
                f"Rust toolchain {channel} for {triple} is not installed under {rustup_home(env)}; "
                "preflight does not install it"
            )
        elif not wasm.is_dir():
            problems.append(
                f"wasm32-unknown-unknown is not installed for {channel}; "
                "the guest build needs it, and the morning steps do not add it"
            )
    home = Path.home() if home is None else home
    cargo_home = Path(env.get("CARGO_HOME") or (home / ".cargo"))
    for label, path in (
        ("HOME", home),
        ("the checkout path", layout.repo),
        ("CARGO_HOME", cargo_home),
    ):
        problem = space_problem(label, path)
        if problem:
            problems.append(problem)
    if root is not None and root.is_dir():
        problem = space_problem("the Rust sysroot", root)
        if problem:
            problems.append(problem)
    for label, path in (("the checkout", layout.repo), ("the home directory", home)):
        try:
            free = free_of(path)
        except OSError:
            problems.append(f"free space for {label} ({path}) could not be read")
            continue
        if free < NEED_FREE:
            problems.append(
                f"free space for {label} ({path}) is {free / 1024 ** 3:.1f} GiB; the runbook asks for 40 GB"
            )
    return problems


def new_run_dir(layout: Layout) -> Path:
    runs = layout.install.parent / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%dT%H%M%SZ-", time.gmtime()), dir=runs))


def write_summary(run_dir: Path, say: "Say") -> Path:
    path = run_dir / "summary.txt"
    path.write_text("\n".join(say.lines) + "\n", encoding="utf-8")
    return path


def read_checkout(repo: Path) -> Checkout:
    def git(*args: str) -> str:
        done = subprocess.run(
            ["git", *args],
            cwd=repo,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
        )
        if done.returncode != 0:
            raise RuntimeError(f"git {args[0]} exited {done.returncode}")
        return done.stdout

    try:
        commit = git("rev-parse", "--verify", "HEAD").strip()
        tree = git("rev-parse", "--verify", "HEAD^{tree}").strip()
        status = git("status", "--porcelain=v1", "--untracked-files=all")
    except (OSError, RuntimeError) as error:
        return Checkout(None, None, False, f"Git query failed: {error}")
    return Checkout(commit, tree, status == "")


def receipt_problems(receipt: object) -> list:
    """Why a VERSIONS.json cannot bind a demo run; empty when it can."""
    if not isinstance(receipt, dict):
        return ["VERSIONS.json is not a JSON object"]
    problems = []
    if receipt.get("schema") != RECEIPT_SCHEMA:
        problems.append(
            f"VERSIONS.json schema is {receipt.get('schema')!r}, expected {RECEIPT_SCHEMA!r}"
        )
    if receipt.get("identity_status") != "complete":
        problems.append(
            f"VERSIONS.json identity_status is {receipt.get('identity_status')!r}, not 'complete'"
        )
    if receipt.get("command_success") is not True:
        problems.append("VERSIONS.json records a failed agent-conformance run")
    if receipt.get("missing_or_invalid") != []:
        problems.append(
            f"VERSIONS.json lists missing or invalid identities: {receipt.get('missing_or_invalid')!r}"
        )
    repository = receipt.get("repository")
    commit = repository.get("commit") if isinstance(repository, dict) else None
    if not (is_hex(commit, 40) or is_hex(commit, 64)):
        problems.append("VERSIONS.json has no valid repository commit")
    elif repository.get("dirty") is not False:
        problems.append("VERSIONS.json was made from a checkout with local changes")
    for field in NATIVE.values():
        if not is_hex(receipt.get(field), 64):
            problems.append(f"VERSIONS.json has no valid {field}")
    report = receipt.get("report")
    table = report.get("table") if isinstance(report, dict) else None
    if not isinstance(table, str):
        problems.append("VERSIONS.json has no report table")
    elif report.get("sha256") != sha256_bytes(table.encode("utf-8")):
        problems.append("VERSIONS.json report table does not match its SHA-256")
    elif A14_ROW not in table.splitlines():
        problems.append(f"VERSIONS.json report has no '{A14_ROW}' row")
    effects = []
    for key in ("probes", "build_only_probes"):
        entries = receipt.get(key)
        if not isinstance(entries, list) or not all(
            isinstance(entry, dict)
            and isinstance(entry.get("effect"), str)
            and is_hex(entry.get("component_sha256"), 64)
            and isinstance(entry.get("bundle_lab_cid"), str)
            for entry in entries
        ):
            problems.append(f"VERSIONS.json {key} are malformed")
        elif key == "probes":
            effects = [entry["effect"] for entry in entries]
    if len(effects) != len(set(effects)):
        problems.append("VERSIONS.json names one probe effect twice")
    return problems


def probe_index(receipt: dict) -> dict:
    index = {}
    for key in ("build_only_probes", "probes"):
        for entry in receipt[key]:
            index[entry["effect"]] = (entry["component_sha256"], entry["bundle_lab_cid"])
    return index


def compare(label: str, path: Path, expected: str, source: str) -> list:
    try:
        actual = sha256_file(path)
    except FileNotFoundError:
        return [f"{label} is missing: {path}"]
    except OSError as error:
        return [f"{label} cannot be read: {path}: {error}"]
    if actual != expected:
        return [f"{label} differs from {source}: {path} has SHA-256 {actual}, expected {expected}"]
    return []


def keygen(args: list, data: Optional[bytes] = None) -> tuple:
    """Run ssh-keygen without the ssh agent; return its status and output."""
    tool = shutil.which("ssh-keygen")
    if tool is None:
        return None, b"ssh-keygen not found"
    env = {key: value for key, value in os.environ.items() if key != "SSH_AUTH_SOCK"}
    done = subprocess.run(
        [tool, *args],
        input=data,
        stdin=None if data is not None else subprocess.DEVNULL,
        capture_output=True,
        env=env,
    )
    return done.returncode, done.stdout + done.stderr


def make_signing_key(layout: Layout) -> list:
    """One ed25519 key for this machine, kept in the demo folder, outside the repository."""
    if layout.signing_key.exists():
        return []
    layout.signing_key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    status, output = keygen(
        ["-q", "-t", "ed25519", "-N", "", "-C", "demo-a14 receipt key on this machine", "-f", str(layout.signing_key)]
    )
    if status != 0:
        return [f"ssh-keygen could not make the signing key: {output.decode('utf-8', 'replace').strip()}"]
    return []


def sign_file(layout: Layout, path: Path) -> list:
    status, output = keygen(["-Y", "sign", "-f", str(layout.signing_key), "-n", SIGNING_NAMESPACE], path.read_bytes())
    signature = output[output.find(b"-----BEGIN SSH SIGNATURE-----"):] if status == 0 else b""
    if not signature.startswith(b"-----BEGIN SSH SIGNATURE-----"):
        return [f"could not sign {path.name}: {output.decode('utf-8', 'replace').strip()}"]
    path.with_name(path.name + ".sig").write_bytes(signature)
    return []


def signature_problems(layout: Layout) -> list:
    """Signing is on while this machine's demo key exists; then both receipt files need its signature."""
    if not layout.signing_pub.exists():
        return []
    try:
        key = layout.signing_pub.read_text(encoding="utf-8").split()
    except OSError as error:
        return [f"the demo signing key cannot be read: {error}"]
    if len(key) < 2 or key[0] != "ssh-ed25519":
        return [f"the demo signing key is not an ed25519 key: {layout.signing_pub}"]
    problems = []
    with tempfile.TemporaryDirectory(prefix="demo-a14-signers-") as scratch:
        allowed = Path(scratch) / "allowed_signers"
        allowed.write_text(f"{SIGNER} {key[0]} {key[1]}\n", encoding="utf-8")
        for name in SIGNED:
            path = layout.install / name
            signature = path.with_name(name + ".sig")
            if not signature.is_file():
                problems.append(f"{name} is unsigned, but signing is on ({layout.signing_pub} exists)")
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            status, output = keygen(
                ["-Y", "verify", "-f", str(allowed), "-I", SIGNER, "-n", SIGNING_NAMESPACE, "-s", str(signature)],
                data,
            )
            if status is None:
                problems.append("signing is on, but ssh-keygen is not found to check the signatures")
                break
            if status != 0:
                problems.append(
                    f"{name} signature does not verify with this machine's demo key: "
                    "the file changed after signing, or another key signed it"
                )
    return problems


def inside(repo: Path, path: str) -> bool:
    return Path(path).is_absolute() and repo in Path(path).parents


def step_problems(layout: Layout, record: dict, suite: str) -> list:
    """The test executable and provider binaries of one suite must be the ones INSTALL.json hashed."""
    steps = record.get("steps")
    entry = steps.get(suite) if isinstance(steps, dict) else None
    test = entry.get("test") if isinstance(entry, dict) else None
    bins = entry.get("bins") if isinstance(entry, dict) else None
    if not isinstance(test, dict) or not isinstance(bins, dict):
        return [f"INSTALL.json binds no executables for {suite}; run install.sh again"]
    if not isinstance(test.get("cwd"), str) or not inside(layout.repo, test["cwd"] + "/x"):
        return [f"INSTALL.json gives {suite} a working folder outside the repository: {test.get('cwd')!r}"]
    problems = []
    for label, item in [("test executable", test)] + [(f"binary {name}", bins[name]) for name in sorted(bins)]:
        path = item.get("path") if isinstance(item, dict) else None
        expected = item.get("sha256") if isinstance(item, dict) else None
        if not isinstance(path, str) or not is_hex(expected, 64):
            problems.append(f"INSTALL.json has a malformed {suite} {label} entry")
        elif not inside(layout.repo, path):
            problems.append(f"the {suite} {label} is outside the repository: {path}")
        else:
            problems += compare(f"the {suite} {label}", Path(path), expected, "its hash in INSTALL.json")
    return problems


def launch_problems(layout: Layout, suite: dict) -> list:
    """A journey that launches its own build of a native binary must launch the installed bytes."""
    problems = []
    for name in suite.get("launches", []):
        installed = layout.install / "bin" / name
        try:
            expected = sha256_file(installed)
        except OSError as error:
            problems.append(f"installed {name} cannot be read: {error}")
            continue
        problems += compare(
            f"the {name} that {suite['label']} launches", layout.runtime_build / name, expected, "the installed copy"
        )
    return problems


def record_executables(suite: str, artifacts: list, repo: Path) -> tuple:
    """Pick one suite's test executable and its package's binaries from Cargo's artifact messages."""
    tests = [a for a in artifacts if isinstance(a.get("profile"), dict) and a["profile"].get("test")]
    if len(tests) != 1:
        return None, [f"Cargo built {len(tests)} test executables for {suite}; the run needs exactly one"]
    test = tests[0]
    bins = {
        a["target"]["name"]: a["executable"]
        for a in artifacts
        if a is not test and a.get("package_id") == test.get("package_id") and "bin" in a["target"]["kind"]
    }
    files = {"test executable": test["executable"], **{f"binary {name}": path for name, path in bins.items()}}
    problems = [f"the {suite} {label} is outside the repository: {path}" for label, path in files.items() if not inside(repo, path)]
    if problems:
        return None, problems
    try:
        entry = {
            "test": {
                "path": test["executable"],
                "cwd": str(Path(test["manifest_path"]).parent),
                "sha256": sha256_file(Path(test["executable"])),
            },
            "bins": {name: {"path": path, "sha256": sha256_file(Path(path))} for name, path in sorted(bins.items())},
        }
    except OSError as error:
        return None, [f"a {suite} executable Cargo reported cannot be read: {error}"]
    return entry, []


def version_gate(layout: Layout, checkout: Checkout, suites: tuple = ()) -> list:
    """Every reason the installed demo does not match its VERSIONS.json."""
    try:
        record = json.loads((layout.install / "INSTALL.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [f"no installed demo at {layout.install}; run lab/demo-a14/install.sh first"]
    except (OSError, ValueError) as error:
        return [f"INSTALL.json cannot be read: {error}"]
    if not isinstance(record, dict) or record.get("schema") != INSTALL_SCHEMA:
        return ["INSTALL.json is not a demo-a14 install record"]
    try:
        receipt_bytes = (layout.install / "VERSIONS.json").read_bytes()
    except OSError as error:
        return [f"the installed VERSIONS.json cannot be read: {error}"]
    problems = signature_problems(layout)
    actual = sha256_bytes(receipt_bytes)
    if actual != record.get("versions_sha256"):
        problems.append(
            f"the installed VERSIONS.json changed after install: SHA-256 {actual}, "
            f"install recorded {record.get('versions_sha256')}"
        )
    try:
        receipt = json.loads(receipt_bytes)
    except ValueError:
        return problems + ["the installed VERSIONS.json is not JSON"]
    invalid = receipt_problems(receipt)
    if invalid:
        return problems + invalid
    for name, field in NATIVE.items():
        expected = receipt[field]
        source = f"VERSIONS.json {field}"
        problems += compare(f"installed {name}", layout.install / "bin" / name, expected, source)
        problems += compare(
            f"the {name} the journeys launch", layout.runtime_build / name, expected, source
        )
    components = record.get("components")
    agent = components.get("agent-host") if isinstance(components, dict) else None
    pinned = agent.get("sha256") if isinstance(agent, dict) else None
    if not is_hex(pinned, 64):
        problems.append("INSTALL.json has no agent-host component SHA-256")
    else:
        source = "the agent-host component pinned at install"
        problems += compare("installed agent-host component", layout.install / AGENT_HOST, pinned, source)
        problems += compare(
            "the agent-host component the journeys load", layout.agent_host_wasm, pinned, source
        )
    for suite in suites:
        problems += step_problems(layout, record, suite)
    commit = receipt["repository"]["commit"]
    installed = record.get("repository")
    if not isinstance(installed, dict) or installed.get("commit") != commit:
        problems.append("INSTALL.json names another commit than VERSIONS.json")
    if checkout.error:
        problems.append(checkout.error)
    else:
        if checkout.commit != commit:
            problems.append(
                f"this checkout is at commit {checkout.commit}; VERSIONS.json was made at {commit}"
            )
        if not checkout.clean:
            problems.append(
                "this checkout has local changes, so the journeys would not build the source VERSIONS.json names"
            )
    return problems


def parse_observations(text: str) -> tuple:
    observations, problems = [], []
    for line in text.splitlines():
        if not line.startswith(IDENTITY_PREFIX):
            continue
        try:
            value = json.loads(line[len(IDENTITY_PREFIX):])
        except ValueError:
            value = None
        if isinstance(value, dict):
            observations.append(value)
        else:
            problems.append(f"a journey printed a malformed identity line: {line[:160]}")
    return observations, problems


def observation_key(observation: dict) -> str:
    if observation.get("kind") == "native":
        return f"native:{observation.get('role')}"
    probe = observation.get("probe")
    effect = probe.get("effect") if isinstance(probe, dict) else None
    return f"{observation.get('kind')}:{effect}"


def identity_problems(observations: list, receipt: dict) -> list:
    """Each identity a journey printed must be the one VERSIONS.json names."""
    problems = []
    probes = probe_index(receipt)
    for observation in observations:
        kind = observation.get("kind")
        if kind == "native":
            role = observation.get("role")
            field = NATIVE.get(role)
            if field is None:
                problems.append(f"a journey printed an unknown native role {role!r}")
            elif observation.get("sha256") != receipt[field]:
                problems.append(
                    f"a journey ran {role} with SHA-256 {observation.get('sha256')}; "
                    f"VERSIONS.json names {receipt[field]}"
                )
        elif kind in ("launched", "build_only"):
            probe = observation.get("probe")
            probe = probe if isinstance(probe, dict) else {}
            effect = probe.get("effect")
            seen = (probe.get("component_sha256"), probe.get("bundle_lab_cid"))
            if effect not in probes:
                problems.append(f"a journey printed probe {effect!r}, which VERSIONS.json does not name")
            elif seen != probes[effect]:
                problems.append(
                    f"a journey printed probe {effect!r} as component {seen[0]} bundle {seen[1]}; "
                    f"VERSIONS.json names component {probes[effect][0]} bundle {probes[effect][1]}"
                )
        else:
            problems.append(f"a journey printed an unknown identity kind {kind!r}")
    return problems


def load_journeys(path: Path = JOURNEYS) -> tuple:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != JOURNEYS_SCHEMA:
        raise ValueError(f"{path.name}: schema is not {JOURNEYS_SCHEMA}")
    checks, suites = data["checks"], data["suites"]
    steps, ids, tests = [], set(), set()
    for raw in data["steps"]:
        step = Step(
            id=raw["id"],
            check=raw["check"],
            title=raw["title"],
            expect=raw["expect"],
            suite=raw["suite"],
            test=raw["test"],
            platform=raw["platform"],
            reason=raw["reason"],
            show=tuple(raw.get("show", ())),
        )
        if (
            step.expect not in ("pass", "refusal")
            or step.platform not in ("any", "macos")
            or step.suite not in suites
            or step.check not in checks
            or not step.test
            or step.id in ids
            or (step.suite, step.test) in tests
        ):
            raise ValueError(f"{path.name}: step {step.id} is malformed or repeated")
        ids.add(step.id)
        tests.add((step.suite, step.test))
        steps.append(step)
    return checks, suites, steps


def runs_here(step: Step, host_os: str) -> bool:
    return step.platform == "any" or host_os == "Darwin"


def suite_order(steps: list) -> list:
    order = []
    for step in steps:
        if step.suite not in order:
            order.append(step.suite)
    return order


def suites_here(steps: list, host_os: str) -> tuple:
    return tuple(name for name in suite_order(steps) if any(s.suite == name and runs_here(s, host_os) for s in steps))


def suite_env(suite: dict, repo: Path) -> dict:
    env = dict(os.environ)
    env.update(suite.get("env", {}))
    env.update({key: str(repo / value) for key, value in suite.get("env_paths", {}).items()})
    env["CARGO_TERM_COLOR"] = "never"
    return env


def invocation(suite: dict, entry: dict, names: list, repo: Path) -> tuple:
    """A direct suite runs the hashed test executable itself, so Cargo cannot rebuild it first."""
    env = suite_env(suite, repo)
    if suite.get("runner") == "cargo":
        return ["cargo", *suite["cargo"], "--", *suite["libtest"], *names], repo / suite["cwd"], env
    env["CARGO_MANIFEST_DIR"] = entry["test"]["cwd"]
    return [entry["test"]["path"], *suite["libtest"], *names], Path(entry["test"]["cwd"]), env


def cargo_ran_problems(text: str, cwd: Path, entry: dict) -> list:
    """Cargo must report that it ran exactly the test executable INSTALL.json hashed."""
    ran = []
    for line in text.splitlines():
        if line.startswith("running "):
            break
        match = CARGO_RUNNING.match(line)
        if match:
            ran.append(match.group(1))
    recorded = Path(entry["test"]["path"]).resolve()
    if [(cwd / path).resolve() for path in ran] != [recorded]:
        return [f"cargo ran {ran or 'no test executable'}, not the recorded test executable {recorded}"]
    return []


RESULT = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored\b.*)$")
SECTION = re.compile(r"^---- (\S+) stdout ----$")
LISTED = re.compile(r"^    (\S+)$")


def parse_libtest(text: str) -> tuple:
    """Result words and captured output per test from libtest's text format."""
    results, sections, listed = {}, {}, {}
    current, heading = None, None
    for line in text.splitlines():
        match = RESULT.match(line)
        if match:
            results.setdefault(match.group(1), []).append(match.group(2))
            current = None
            continue
        match = SECTION.match(line)
        if match:
            current, heading = match.group(1), None
            sections.setdefault(current, [])
            continue
        if line in ("successes:", "failures:"):
            current, heading = None, line
            continue
        match = LISTED.match(line) if heading else None
        if match:
            listed[match.group(1)] = "ok" if heading == "successes:" else "FAILED"
            continue
        if current is not None:
            sections[current].append(line)
    # Child output can split a result line; the end-of-run lists still name it.
    for name, verdict in listed.items():
        results.setdefault(name, [verdict])
    return results, sections


def failure_message(section: list) -> Optional[str]:
    for index, line in enumerate(section):
        if "panicked at" in line:
            rest = [later.strip() for later in section[index + 1:] if later.strip()]
            return (rest[0] if rest else line.strip())[:300]
    return None


def grade(step: Step, results: dict, sections: dict, status, host_os: str, suites: dict, log) -> Outcome:
    """A SKIP is never a PASS: only a real `ok` without a skip line passes."""
    if not runs_here(step, host_os):
        return Outcome(step, "NOT RUN", f"needs macOS: {suites[step.suite]['macos_reason']}")
    section = sections.get(step.test, [])
    shown = tuple(line for line in section if step.show and line.startswith(step.show))
    skip = next((line for line in section if line.startswith(SKIP_MARKERS)), None)
    if skip:
        return Outcome(step, "NOT RUN", f"the test could not run here: {skip}", shown)
    found = results.get(step.test, [])
    if len(found) != 1:
        what = "no result" if not found else f"{len(found)} results"
        cause = "timed out" if status is None else f"cargo exit {status}"
        return Outcome(step, "FAIL", f"{what} for this test ({cause}); see {log}", shown)
    if found[0] == "ok":
        return Outcome(step, "PASS" if step.expect == "pass" else "REFUSED", step.reason, shown)
    if found[0] == "FAILED":
        return Outcome(step, "FAIL", failure_message(section) or f"the test failed; see {log}", shown)
    return Outcome(step, "FAIL", f"the test was {found[0]}, so it did not run", shown)


def check_verdict(outcomes: list) -> str:
    statuses = {outcome.status for outcome in outcomes}
    if "FAIL" in statuses:
        return "FAIL"
    if "NOT RUN" in statuses:
        return "NOT RUN"
    return "PASS"


def capture(args: list, cwd: Path, env: dict, log: Path, timeout: int) -> tuple:
    """Run one command; keep its combined output in `log` and return it."""
    try:
        done = subprocess.run(
            args,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        status, data = done.returncode, done.stdout
    except subprocess.TimeoutExpired as expired:
        status, data = None, expired.stdout or b""
    except OSError as error:
        status, data = 127, f"could not start {args[0]}: {error}\n".encode()
    text = data.decode("utf-8", "replace")
    log.write_text(text, encoding="utf-8")
    return status, text


def stream(args: list, cwd: Path, env: Optional[dict] = None) -> tuple:
    """Run one command in view of the person; return its status and lines."""
    lines = []
    try:
        with subprocess.Popen(
            args,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            bufsize=1,
        ) as child:
            for line in child.stdout:
                sys.stdout.write(line)
                lines.append(line.rstrip("\n"))
            status = child.wait()
    except OSError as error:
        print(f"could not start {args[0]}: {error}")
        return 127, lines
    return status, lines


def cargo_artifacts(args: list, cwd: Path, env: dict) -> tuple:
    """Build with Cargo in view of the person; return its status and the executables it reported."""
    artifacts = []
    try:
        with subprocess.Popen(
            [*args, "--message-format=json-render-diagnostics"],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
            errors="replace",
        ) as child:
            for line in child.stdout:
                try:
                    message = json.loads(line)
                except ValueError:
                    continue
                if isinstance(message, dict) and message.get("reason") == "compiler-artifact" and message.get("executable"):
                    artifacts.append(message)
            status = child.wait()
    except OSError as error:
        print(f"could not start {args[0]}: {error}")
        return 127, []
    return status, artifacts


class Say:
    """Print each line and keep it for the run's summary file."""

    def __init__(self) -> None:
        self.lines = []

    def __call__(self, line: str = "") -> None:
        print(line, flush=True)
        self.lines.append(line)


def refuse(say: Say, headline: str, problems: list, next_step: str) -> None:
    say(f"REFUSED: {headline}")
    for problem in problems:
        say(f"  - {problem}")
    say(f"Next: {next_step}")


def run_demo(
    layout: Layout,
    host_os: str,
    runner: Callable = capture,
    read: Callable = read_checkout,
    journeys: Path = JOURNEYS,
) -> int:
    say = Say()
    say(f"A14 installed demo: {layout.install}")
    run_dir = new_run_dir(layout)
    checks, suites, steps = load_journeys(journeys)
    here = suites_here(steps, host_os)
    problems = version_gate(layout, read(layout.repo), here)
    if problems:
        installed = (layout.install / "INSTALL.json").exists()
        summary = run_dir / "summary.txt"
        refuse(
            say,
            ("the installed versions do not match VERSIONS.json" if installed else "the demo is not installed")
            + ". No journey was run.",
            problems,
            f"read {summary}, then run `bash lab/demo-a14/install.sh`, then run this command again.",
        )
        say(f"Saved: {run_dir}")
        write_summary(run_dir, say)
        return EXIT_REFUSED
    receipt_bytes = (layout.install / "VERSIONS.json").read_bytes()
    receipt = json.loads(receipt_bytes)
    record = json.loads((layout.install / "INSTALL.json").read_text(encoding="utf-8"))
    say("Versions match VERSIONS.json:")
    say(f"  receipt  SHA-256 {sha256_bytes(receipt_bytes)}")
    say(f"  commit   {receipt['repository']['commit']}")
    for name, field in NATIVE.items():
        say(f"  {name:<19} SHA-256 {receipt[field]}")
    bins = sum(len(record["steps"][name]["bins"]) for name in here)
    say(f"  steps    {len(here)} test executables and {bins} provider binaries match their hashes in INSTALL.json")
    if layout.signing_pub.exists():
        say(f"  signature  valid for both receipt files; {SIGNATURE_SCOPE}")
    else:
        say("  signature  off (install with --sign to turn it on)")
    outcomes, binding = [], []
    for name in suite_order(steps):
        suite = suites[name]
        members = [step for step in steps if step.suite == name]
        runnable = [step for step in members if runs_here(step, host_os)]
        status, text, log = None, "", run_dir / f"{name}.log"
        blocked = []
        say()
        if runnable:
            blocked = step_problems(layout, record, name) + launch_problems(layout, suite)
        if blocked:
            say(f"Refusing {suite['label']}: it would not run the bytes this install recorded.")
            binding += blocked
        elif runnable:
            say(f"Running {suite['label']}: {len(runnable)} of {len(members)} steps...")
            args, cwd, env = invocation(suite, record["steps"][name], [s.test for s in runnable], layout.repo)
            status, text = runner(args, cwd, env, log, SUITE_TIMEOUT)
            binding += step_problems(layout, record, name) + launch_problems(layout, suite)
            if suite.get("runner") == "cargo":
                binding += cargo_ran_problems(text, cwd, record["steps"][name])
        else:
            say(f"Skipping {suite['label']}: it needs macOS ({suite['macos_reason']}).")
        results, sections = parse_libtest(text)
        graded = [grade(step, results, sections, status, host_os, suites, log) for step in members]
        if blocked:
            refused = "refused before running: " + "; ".join(blocked)
            graded = [Outcome(o.step, "FAIL", refused) if runs_here(o.step, host_os) else o for o in graded]
        outcomes += graded
        for outcome in graded:
            label = {"PASS": "why", "REFUSED": "reason", "FAIL": "failure", "NOT RUN": "not run"}
            say(f"  {outcome.step.id:<10} {outcome.status:<8} {outcome.step.title}")
            say(f"  {'':<19} {label[outcome.status]}: {outcome.detail}")
            for line in outcome.shown:
                say(f"  {'':<19} observed: {line}")
            say(f"  {'':<19} test: {outcome.step.test}")
        observations, malformed = parse_observations(text)
        binding += malformed + identity_problems(observations, receipt)
        if any(outcome.status in PASSING for outcome in graded):
            seen = {observation_key(observation) for observation in observations}
            for required in suite.get("identities", []):
                if required not in seen:
                    binding.append(f"{suite['label']} printed no {required} identity, so it is not bound")
    binding += version_gate(layout, read(layout.repo), here)
    say()
    say("Summary")
    for check, title in checks.items():
        mine = [outcome for outcome in outcomes if outcome.step.check == check]
        steps_word = "step" if len(mine) == 1 else "steps"
        say(f"  {check:<4} {title:<62} {check_verdict(mine)} ({len(mine)} {steps_word})")
    say(f"  versions bound after the run: {'no' if binding else 'yes'}")
    for problem in binding:
        say(f"    - {problem}")
    verdict = "FAIL" if binding else check_verdict(outcomes)
    not_run = sum(outcome.status == "NOT RUN" for outcome in outcomes)
    if verdict == "PASS":
        say(f"A14: PASS. Every step ran against the versions in VERSIONS.json {sha256_bytes(receipt_bytes)}.")
    elif verdict == "NOT RUN":
        say(f"A14: NOT RUN. {not_run} of {len(outcomes)} steps did not run on this machine.")
    else:
        say("A14: FAIL. See the failures above.")
    say(f"Saved: {run_dir}")
    write_summary(run_dir, say)
    return {"PASS": EXIT_PASS, "NOT RUN": EXIT_NOT_RUN}.get(verdict, EXIT_FAIL)


def write_install(
    layout: Layout, receipt_bytes: bytes, receipt_source: Path, checkout: Checkout, steps: dict
) -> list:
    home = layout.install.parent
    if layout.install.exists() and not (layout.install / "INSTALL.json").is_file():
        return [f"{layout.install} exists and is not a demo install; move it away, then install again"]
    home.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".install-", dir=home))
    try:
        (staging / "bin").mkdir()
        for name in NATIVE:
            shutil.copy2(layout.runtime_build / name, staging / "bin" / name)
        pinned = staging / AGENT_HOST
        pinned.parent.mkdir(parents=True)
        shutil.copy2(layout.agent_host_wasm, pinned)
        (staging / "VERSIONS.json").write_bytes(receipt_bytes)
        components = {
            name: {"path": f"bin/{name}", "sha256": sha256_file(staging / "bin" / name)}
            for name in NATIVE
        }
        components["agent-host"] = {"path": AGENT_HOST, "sha256": sha256_file(pinned)}
        record = {
            "schema": INSTALL_SCHEMA,
            "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "repository": {"commit": checkout.commit, "tree": checkout.tree},
            "receipt_source": str(receipt_source),
            "versions_sha256": sha256_bytes(receipt_bytes),
            "components": components,
            "steps": steps,
        }
        (staging / "INSTALL.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        signed = []
        if layout.signing_key.exists():
            for name in SIGNED:
                signed += sign_file(layout, staging / name)
    except OSError as error:
        shutil.rmtree(staging, ignore_errors=True)
        return [f"could not write the install: {error}"]
    if signed:
        shutil.rmtree(staging, ignore_errors=True)
        return signed
    if layout.install.exists():
        retired = Path(tempfile.mkdtemp(prefix=".replaced-", dir=home))
        layout.install.rename(retired / "current")
        shutil.rmtree(retired)
    staging.rename(layout.install)
    return []


def install(
    layout: Layout,
    host_os: str,
    receipt_arg: Optional[str] = None,
    read: Callable = read_checkout,
    runner: Callable = stream,
    journeys: Path = JOURNEYS,
    sign: bool = False,
    builder: Optional[Callable] = None,
    ready: Optional[Callable] = None,
) -> int:
    say = Say()
    builder = builder or cargo_artifacts
    ready = ready or machine_problems
    again = "fix the item above, then run `bash lab/demo-a14/install.sh` again."
    say(f"Installing the A14 demo into {layout.install}")
    checkout = read(layout.repo)
    if checkout.error or not checkout.clean:
        problems = [checkout.error or "this copy of the repository has local changes; commit or stash them"]
        refuse(say, "the repository is not ready.", problems, again)
        return EXIT_REFUSED
    problems = ready(layout, host_os)
    if problems:
        refuse(say, "this machine is not ready.", problems, again)
        return EXIT_REFUSED
    if not receipt_arg and host_os != "Darwin":
        problems = [
            "VERSIONS.json comes from lab/agent-conformance/run.sh, which runs on macOS only; "
            "on this machine give --receipt PATH"
        ]
        refuse(say, "no VERSIONS.json for this machine.", problems, again)
        return EXIT_REFUSED
    say("Step 1 of 5: downloading the Rust packages the builds need (this needs the internet)")
    for manifest in FETCH:
        status, _ = runner(["cargo", "fetch", "--locked", "--manifest-path", manifest], layout.repo)
        if status != 0:
            refuse(say, "a download failed.", [f"cargo fetch for {manifest} exited {status}"], again)
            return EXIT_REFUSED
    if receipt_arg:
        say("Step 2 of 5: reading the VERSIONS.json you named")
        receipt_path = Path(receipt_arg).expanduser().resolve()
    else:
        say("Step 2 of 5: making a fresh VERSIONS.json with lab/agent-conformance/run.sh")
        status, lines = runner(["bash", str(layout.conformance / "run.sh")], layout.repo)
        found = [line[len(RECEIPT_LINE):] for line in lines if line.startswith(RECEIPT_LINE)]
        if status != 0 or len(found) != 1:
            problems = [f"lab/agent-conformance/run.sh exited {status} and printed {len(found)} receipt paths"]
            refuse(say, "the conformance run did not pass.", problems, again)
            return EXIT_REFUSED
        receipt_path = (layout.conformance / found[0]).resolve()
    try:
        receipt_bytes = receipt_path.read_bytes()
        receipt = json.loads(receipt_bytes)
    except (OSError, ValueError) as error:
        refuse(say, "VERSIONS.json cannot be used.", [f"{receipt_path}: {error}"], again)
        return EXIT_REFUSED
    problems = receipt_problems(receipt)
    if not problems:
        if receipt["repository"]["commit"] != checkout.commit:
            problems.append(
                f"VERSIONS.json was made at {receipt['repository']['commit']}; this checkout is at {checkout.commit}"
            )
        for name, field in NATIVE.items():
            problems += compare(
                f"the {name} lab/agent-conformance built",
                layout.runtime_build / name,
                receipt[field],
                f"VERSIONS.json {field}",
            )
    if problems:
        refuse(say, f"{receipt_path} cannot bind this install.", problems, again)
        return EXIT_REFUSED
    say("Step 3 of 5: building the agent-host guest from this commit")
    status, _ = runner(["bash", str(layout.repo / "examples" / "agent-host" / "build.sh")], layout.repo)
    if status != 0:
        refuse(say, "the agent-host guest did not build.", [f"examples/agent-host/build.sh exited {status}"], again)
        return EXIT_REFUSED
    say("Step 4 of 5: building the journey tests and recording the hash of each executable")
    _, suites, steps = load_journeys(journeys)
    here = suites_here(steps, host_os)
    recorded = {}
    for name in here:
        suite = suites[name]
        args = ["cargo", *suite["cargo"], "--no-run"]
        status, artifacts = builder(args, layout.repo / suite["cwd"], suite_env(suite, layout.repo))
        if status != 0:
            refuse(say, f"the {suite['label']} tests did not build.", [f"{' '.join(args)} exited {status}"], again)
            return EXIT_REFUSED
        recorded[name], problems = record_executables(name, artifacts, layout.repo)
        if problems:
            refuse(say, f"the {suite['label']} executables cannot be recorded.", problems, again)
            return EXIT_REFUSED
    if sign:
        problems = make_signing_key(layout)
        if problems:
            refuse(say, "signing cannot be turned on.", problems, again)
            return EXIT_REFUSED
    if layout.signing_key.exists():
        say(f"Signing is on: this machine's key is {layout.signing_key} ({SIGNATURE_SCOPE}).")
    say("Step 5 of 5: copying the pinned files")
    problems = write_install(layout, receipt_bytes, receipt_path, checkout, recorded)
    problems = problems or version_gate(layout, read(layout.repo), here)
    if problems:
        refuse(say, "the install does not match VERSIONS.json.", problems, again)
        return EXIT_REFUSED
    say(f"Installed. VERSIONS.json SHA-256 {sha256_bytes(receipt_bytes)}.")
    say(f"Receipt: {receipt_path}")
    say("Next: bash lab/demo-a14/run.sh")
    return EXIT_PASS


def demo_home(host_os: str, repo: Path) -> Path:
    override = os.environ.get("DEMO_A14_HOME")
    if override:
        home = Path(override).expanduser().resolve()
    elif host_os == "Darwin":
        home = Path.home() / "Library" / "Application Support" / "elastos-demo-a14"
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        home = Path(base) / "elastos-demo-a14"
    if home == repo or repo in home.parents:
        raise ValueError(f"the demo folder {home} is inside the repository; choose a folder outside it")
    return home


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(prog="demo.py", description="M1 check A14: the installed demo.")
    commands = parser.add_subparsers(dest="command", required=True)
    install_command = commands.add_parser("install", help="pin one VERSIONS.json and its components")
    install_command.add_argument("--receipt", help="use this VERSIONS.json instead of making a fresh one")
    install_command.add_argument(
        "--sign", action="store_true", help="make this machine's demo key if needed and sign both receipt files"
    )
    commands.add_parser("run", help="walk the journeys against the installed versions")
    args = parser.parse_args(argv)
    host_os = platform.system()
    try:
        layout = Layout(REPO, demo_home(host_os, REPO) / "current")
    except ValueError as error:
        print(f"REFUSED: {error}")
        return EXIT_USAGE
    if args.command == "install":
        return install(layout, host_os, args.receipt, sign=args.sign)
    return run_demo(layout, host_os)


if __name__ == "__main__":
    sys.exit(main())
