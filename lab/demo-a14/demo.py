#!/usr/bin/env python3
"""One install and one run for M1 check A14, bound to one VERSIONS.json.

`install` takes the receipt that lab/agent-conformance/run.sh writes, pins the
Runtime and localhost-provider it names, and pins the agent-host guest built
from the same commit. `run` refuses before any journey when an installed file,
the receipt or the checkout differs. It then walks journeys.json and checks
every identity the journeys print against the same receipt.
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


def version_gate(layout: Layout, checkout: Checkout) -> list:
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
    problems = []
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


def suite_env(suite: dict, repo: Path) -> dict:
    env = dict(os.environ)
    env.update(suite.get("env", {}))
    env.update({key: str(repo / value) for key, value in suite.get("env_paths", {}).items()})
    return env


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
    problems = version_gate(layout, read(layout.repo))
    if problems:
        installed = (layout.install / "INSTALL.json").exists()
        refuse(
            say,
            ("the installed versions do not match VERSIONS.json" if installed else "the demo is not installed")
            + ". No journey was run.",
            problems,
            "run `bash lab/demo-a14/install.sh`, then run this command again.",
        )
        return EXIT_REFUSED
    receipt_bytes = (layout.install / "VERSIONS.json").read_bytes()
    receipt = json.loads(receipt_bytes)
    say("Versions match VERSIONS.json:")
    say(f"  receipt  SHA-256 {sha256_bytes(receipt_bytes)}")
    say(f"  commit   {receipt['repository']['commit']}")
    for name, field in NATIVE.items():
        say(f"  {name:<19} SHA-256 {receipt[field]}")
    checks, suites, steps = load_journeys(journeys)
    runs = layout.install.parent / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%dT%H%M%SZ-", time.gmtime()), dir=runs))
    outcomes, binding = [], []
    for name in suite_order(steps):
        suite = suites[name]
        members = [step for step in steps if step.suite == name]
        runnable = [step for step in members if runs_here(step, host_os)]
        status, text, log = None, "", run_dir / f"{name}.log"
        say()
        if runnable:
            say(f"Running {suite['label']}: {len(runnable)} of {len(members)} steps...")
            args = ["cargo", *suite["cargo"], "--", *suite["libtest"], *(s.test for s in runnable)]
            status, text = runner(args, layout.repo / suite["cwd"], suite_env(suite, layout.repo), log, SUITE_TIMEOUT)
        else:
            say(f"Skipping {suite['label']}: it needs macOS ({suite['macos_reason']}).")
        results, sections = parse_libtest(text)
        graded = [grade(step, results, sections, status, host_os, suites, log) for step in members]
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
    binding += version_gate(layout, read(layout.repo))
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
    (run_dir / "summary.txt").write_text("\n".join(say.lines) + "\n", encoding="utf-8")
    return {"PASS": EXIT_PASS, "NOT RUN": EXIT_NOT_RUN}.get(verdict, EXIT_FAIL)


def write_install(layout: Layout, receipt_bytes: bytes, receipt_source: Path, checkout: Checkout) -> list:
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
        }
        (staging / "INSTALL.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as error:
        shutil.rmtree(staging, ignore_errors=True)
        return [f"could not write the install: {error}"]
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
) -> int:
    say = Say()
    again = "fix the item above, then run `bash lab/demo-a14/install.sh` again."
    say(f"Installing the A14 demo into {layout.install}")
    checkout = read(layout.repo)
    if checkout.error or not checkout.clean:
        problems = [checkout.error or "this copy of the repository has local changes; commit or stash them"]
        refuse(say, "the repository is not ready.", problems, again)
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
    say("Step 4 of 5: building the journey tests, so the run only runs them")
    _, suites, steps = load_journeys(journeys)
    for name in suite_order(steps):
        if not any(runs_here(step, host_os) for step in steps if step.suite == name):
            continue
        suite = suites[name]
        args = ["cargo", *suite["cargo"], "--no-run"]
        status, _ = runner(args, layout.repo / suite["cwd"], suite_env(suite, layout.repo))
        if status != 0:
            refuse(say, f"the {suite['label']} tests did not build.", [f"{' '.join(args)} exited {status}"], again)
            return EXIT_REFUSED
    say("Step 5 of 5: copying the pinned files")
    problems = write_install(layout, receipt_bytes, receipt_path, checkout)
    problems = problems or version_gate(layout, read(layout.repo))
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
    commands.add_parser("run", help="walk the journeys against the installed versions")
    args = parser.parse_args(argv)
    host_os = platform.system()
    try:
        layout = Layout(REPO, demo_home(host_os, REPO) / "current")
    except ValueError as error:
        print(f"REFUSED: {error}")
        return EXIT_USAGE
    if args.command == "install":
        return install(layout, host_os, args.receipt)
    return run_demo(layout, host_os)


if __name__ == "__main__":
    sys.exit(main())
