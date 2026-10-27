#!/usr/bin/env python3
"""Linux dry-run of the C1-C7 Mac runbook fence.

Pastes the exact ```bash block from README.md with a macOS uname /
xcode-select / sandbox-exec shim. Does not compile the confine suites
or run a real sandbox-exec. C1-C7 on macOS stays NOT RUN ON MAC.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
README = HERE / "README.md"
RUN_SH = HERE / "run.sh"
REPO_ROOT = HERE.parents[1]
BRANCH = "cursor/c1-c7-mac-runbook-5f39"
PIN_C17 = "ea25c4d6d58f1dc08d29173b45349bfeb80903f3"
GIT_IDENT = ["-c", "user.email=lab@ela.city", "-c", "user.name=c1-c7-mac-runbook"]

WALLET = (
    "confined_provider_serves_wallet_operations_under_its_root",
    "confined_outside_write_is_denied",
    "confined_outside_read_is_denied",
    "planted_key_beneath_storage_parent_is_not_read",
    "account_operations_beneath_storage_parent_are_refused",
    "startup_is_refused_when_the_profile_cannot_be_applied",
    "unbound_copy_is_refused_under_profile",
    "bound_copy_serves_under_profile",
    "startup_denial_reports_its_reason",
    "the_bare_value_fixture_loads_under_sandbox_exec",
    "the_string_fixture_loads_under_sandbox_exec",
)
MODEL = (
    "model_provider_ops_under_profile",
    "model_outside_write_denied",
    "model_outside_read_denied",
    "model_outside_create_reports_access_denied",
    "model_local_offer_fails_closed_under_profile",
    "model_hosted_run_fails_closed_under_profile",
    "model_hosted_run_reaches_runtime_socket_when_unconfined",
    "model_unbound_program_refused_under_profile",
    "model_bound_copy_serves_under_profile",
    "byte_different_file_at_bound_path_starts",
    "startup_is_refused_when_the_profile_cannot_be_applied",
)
DID = (
    "confined_provider_serves_did_operations_under_its_root",
    "verify_did_recovery_under_profile",
    "outside_write_denied",
    "outside_read_denied",
    "planted_file_beneath_storage_parent_is_neither_read_nor_written",
    "persona_key_beneath_storage_parent_is_not_adopted",
    "startup_denial_reports_its_reason",
    "startup_is_refused_when_the_profile_cannot_be_applied",
    "unbound_copy_is_refused_under_profile",
    "bound_copy_serves_under_profile",
)
ROWS = tuple(f"wallet/{name}" for name in WALLET) + tuple(f"model/{name}" for name in MODEL) + tuple(
    f"did/{name}" for name in DID
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_block(readme: Path) -> bytes:
    text = readme.read_text(encoding="utf-8")
    fences = re.findall(r"```bash\n(.*?)```", text, flags=re.S)
    if len(fences) != 1:
        raise SystemExit(f"{readme}: expected exactly one ```bash fence, found {len(fences)}")
    return fences[0].encode("utf-8")


def block_meta(block: bytes) -> tuple[str, int]:
    return sha256_bytes(block), len(block)


def read_readme_meta(readme: Path) -> tuple[str, int]:
    text = readme.read_text(encoding="utf-8")
    digest = None
    size = None
    for line in text.splitlines():
        if line.startswith("- sha256:"):
            digest = line.split(":", 1)[1].strip().strip("`")
        if line.startswith("- bytes:"):
            size = int(line.split(":", 1)[1].strip().strip("`"))
    if digest is None or size is None:
        raise SystemExit(f"{readme}: missing sha256/bytes lines")
    return digest, size


def write_macos_shims(shim_dir: Path, *, sandbox: bool = True) -> None:
    shim_dir.mkdir(parents=True, exist_ok=True)
    uname = shim_dir / "uname"
    uname.write_text(
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  -s) printf 'Darwin\\n' ;;\n"
        "  -m) printf 'arm64\\n' ;;\n"
        "  -sm) printf 'Darwin arm64\\n' ;;\n"
        "  *)\n"
        "    if [ -x /usr/bin/uname ]; then exec /usr/bin/uname \"$@\"; fi\n"
        "    printf 'Darwin\\n'\n"
        "    ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    xcode = shim_dir / "xcode-select"
    xcode.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"-p\" ]; then\n"
        "  printf '/Library/Developer/CommandLineTools\\n'\n"
        "  exit 0\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    paths = [uname, xcode]
    if sandbox:
        sbx = shim_dir / "sandbox-exec"
        sbx.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        paths.append(sbx)
    for path in paths:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def evidence_text(kind: str) -> str:
    statuses = {row: "PASS" for row in ROWS}
    extras: list[str] = []
    passed = 32
    failed = 0
    ignored = 0
    probe = "DENIED"
    if kind == "fail":
        statuses["wallet/confined_outside_write_is_denied"] = "FAIL"
        passed = 31
        failed = 1
    elif kind == "missing-test":
        statuses.pop("model/model_outside_write_denied")
        passed = 31
    elif kind == "duplicate-row":
        extras.append("wallet/confined_outside_write_is_denied: PASS")
    elif kind == "ignored-count":
        ignored = 1
    elif kind == "pass-then-fail":
        extras.append("wallet/confined_outside_write_is_denied: FAIL")
        failed = 1
        passed = 31
    lines = ["C1-C7 mac sandbox-exec", f"pin: {PIN_C17}"]
    lines.extend(f"{row}: {statuses[row]}" for row in ROWS if row in statuses)
    lines.extend(extras)
    lines.append(f"passed: {passed}")
    lines.append(f"failed: {failed}")
    lines.append(f"ignored: {ignored}")
    lines.append(f"SBPL_PROBE: {probe}")
    return "\n".join(lines) + "\n"


def write_run_sh(run: Path, kind: str) -> None:
    header = "#!/usr/bin/env bash\nset -euo pipefail\nlane=$(cd -- \"$(dirname -- \"$0\")\" && pwd -P)\n"
    happy = evidence_text("happy")
    if kind == "late-rewrite":
        fail = evidence_text("fail")
        body = (
            header
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n"
            + "(\n"
            + "  sleep 8\n"
            + f"  cat > \"$lane/evidence.txt\" <<'EOF'\n{fail}EOF\n"
            + ") &\n"
        )
    elif kind == "elastos":
        body = header + "mkdir -p -- \"$HOME/.elastos\"\n" + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n"
    elif kind == "exit1":
        body = header + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n" + "exit 1\n"
    elif kind == "survived":
        body = header + "printf 'F-C17 SURVIVED\\n'\n" + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n"
    else:
        ev_kind = kind if kind in ("fail", "missing-test", "duplicate-row", "ignored-count", "pass-then-fail") else "happy"
        body = header + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{evidence_text(ev_kind)}EOF\n"
    run.write_text(body, encoding="utf-8")
    run.chmod(0o755)


def graft_pin(repo: Path, kind: str) -> None:
    fetched = subprocess.run(
        ["git", "fetch", "--", str(REPO_ROOT), PIN_C17],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    if fetched.returncode != 0:
        raise SystemExit(f"fixture fetch pin failed: {fetched.stderr}")
    tree = subprocess.run(
        ["git", "write-tree"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    commit = subprocess.run(
        ["git", *GIT_IDENT, "commit-tree", tree, "-p", PIN_C17, "-m", f"fixture {kind}"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "reset", "--hard", commit], cwd=repo, check=True, capture_output=True)


def write_fixture(root: Path, kind: str, *, include_pin: bool = True) -> Path:
    repo = root / "remote"
    (repo / "lab" / "c1-c7-mac-runbook").mkdir(parents=True)
    (repo / "capsules" / "wallet-provider" / "tests").mkdir(parents=True)
    (repo / "capsules" / "model-provider" / "tests" / "confine").mkdir(parents=True)
    (repo / "capsules" / "did-provider" / "tests").mkdir(parents=True)
    (repo / "capsules" / "wallet-provider" / "tests" / "confine.rs").write_text("// fixture\n", encoding="utf-8")
    (repo / "capsules" / "model-provider" / "tests" / "confine" / "main.rs").write_text("// fixture\n", encoding="utf-8")
    (repo / "capsules" / "did-provider" / "tests" / "confine.rs").write_text("// fixture\n", encoding="utf-8")
    write_run_sh(repo / "lab" / "c1-c7-mac-runbook" / "run.sh", kind)
    subprocess.run(["git", "init", "-b", BRANCH], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    if include_pin:
        graft_pin(repo, kind)
    else:
        subprocess.run(
            ["git", *GIT_IDENT, "commit", "-m", f"fixture {kind}"],
            cwd=repo,
            check=True,
            capture_output=True,
        )
    return repo


def hide_tool(path: str, name: str) -> str:
    kept = []
    for part in path.split(":"):
        if not part:
            continue
        if (Path(part) / name).exists():
            continue
        kept.append(part)
    return ":".join(kept)


def run_block(
    block: bytes,
    *,
    kind: str,
    shim: bool,
    hide: str | None = None,
    include_pin: bool = True,
    fake_home: bool = False,
    stale_summary: bool = False,
) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix=f"c17-mac-dryrun-{kind}-"))
    started = time.time()
    timeout = 180 if kind == "late-rewrite" else 120
    try:
        shim_dir = tmp / "shims"
        if shim:
            write_macos_shims(shim_dir, sandbox=(hide != "sandbox-exec"))
        work = tmp / "work"
        summary = tmp / "summary.txt"
        if stale_summary:
            summary.write_text("stale C1-C7 run\nC1-C7: PASS.\n", encoding="utf-8")
        env = os.environ.copy()
        env.pop("CARGO_TARGET_DIR", None)
        path_parts = []
        if shim:
            path_parts.append(str(shim_dir))
        base_path = env.get("PATH", "")
        if hide == "rustup":
            base_path = hide_tool(base_path, "rustup")
        path_parts.append(base_path)
        env["PATH"] = ":".join(path_parts)
        env["C17_WORKDIR"] = str(work)
        env["C17_SUMMARY"] = str(summary)
        env["C17_CLEAN"] = "0"
        if fake_home:
            home = tmp / "fake-home"
            home.mkdir()
            env["HOME"] = str(home)
            rustup_home = Path.home() / ".rustup"
            cargo_home = Path.home() / ".cargo"
            if rustup_home.is_dir():
                env["RUSTUP_HOME"] = str(rustup_home)
            if cargo_home.is_dir():
                env["CARGO_HOME"] = str(cargo_home)
        if hide is None:
            remote = write_fixture(tmp, kind, include_pin=include_pin)
            env["C17_REMOTE"] = str(remote)
            env["C17_BRANCH"] = BRANCH
        script = tmp / "block.sh"
        script.write_bytes(block)
        script.chmod(0o700)
        done = subprocess.run(
            ["zsh", "--no-rcs", str(script)],
            cwd=tmp,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        output = (done.stdout or "") + (done.stderr or "")
        last = ""
        reason = ""
        if summary.is_file():
            lines = summary.read_text(encoding="utf-8").splitlines()
            if lines:
                last = lines[-1]
            for line in lines:
                if line.startswith("reason: "):
                    reason = line[len("reason: ") :]
        return {
            "kind": kind,
            "exit": done.returncode,
            "seconds": round(time.time() - started, 3),
            "last": last,
            "reason": reason,
            "output": output,
            "summary": str(summary) if summary.is_file() else "",
            "workdir": str(work),
            "tmp": str(tmp),
        }
    except subprocess.TimeoutExpired as error:
        return {
            "kind": kind,
            "exit": 124,
            "seconds": round(time.time() - started, 3),
            "last": "",
            "reason": f"TIMEOUT after {error.timeout}s",
            "output": (error.stdout or "") + (error.stderr or ""),
            "summary": "",
            "workdir": str(tmp / "work"),
            "tmp": str(tmp),
        }


def caught(ok: bool) -> str:
    return "CAUGHT" if ok else "MISSED"


def names_present(text: str) -> bool:
    return all(name in text for name in WALLET + MODEL + DID)


def main() -> int:
    if len(sys.argv) != 1:
        sys.stderr.write("usage: dryrun.py\n")
        return 2
    if len(ROWS) != 32:
        print(f"ROWS count MISSED: {len(ROWS)}")
        return 1
    block = extract_block(README)
    digest, size = block_meta(block)
    print(f"BLOCK sha256:{digest} bytes:{size}")
    readme_digest, readme_size = read_readme_meta(README)
    if (readme_digest, readme_size) != (digest, size):
        print("README meta MISSED")
        print(f"README sha256:{readme_digest} bytes:{readme_size}")
        return 1
    print("README meta CAUGHT")

    text = block.decode("utf-8")
    run_text = RUN_SH.read_text(encoding="utf-8")
    static_ok = True

    def static(name: str, ok: bool) -> None:
        nonlocal static_ok
        if ok:
            print(f"static {name} CAUGHT")
        else:
            print(f"static {name} MISSED")
            static_ok = False

    static("sudo", re.search(r"\bsudo\b", text) is None and re.search(r"\bsudo\b", run_text) is None)
    static("elastos-serve", "elastos serve" not in text and "elastos serve" not in run_text)
    static("curl-sh", not re.search(r"curl(\s|$|\|)", text) and "curl -" not in text)
    static("sed-i", "sed -i" not in text and "sed -i" not in run_text)
    static("readlink-f", "readlink -f" not in text and "readlink -f" not in run_text)
    static("gnu-stat", "stat -c" not in text and "stat --printf" not in text and "stat -f" not in text)
    static("rustup-skip", "already present; skip" in text)
    static("mktemp-trap", "mktemp -d" in text and "trap c17_on_exit EXIT" in text)
    static("no-single-branch", "--single-branch" not in text)
    static("pin", PIN_C17 in text and PIN_C17 in run_text)
    static("names-fence", names_present(text))
    static("names-run", names_present(run_text))
    static("cargo-list", "cargo --list" in text or "--list" in run_text)
    static("exact", "--exact" in run_text)
    static("probe", r"#\; x (allow file*)" in run_text)
    static("ignored-fixture-excluded", "ignored_falsifier_fixture" not in text and "ignored_falsifier_fixture" not in run_text)

    cases = [
        ("happy", run_block(block, kind="happy", shim=True), "C1-C7: PASS.", None),
        ("missing-test", run_block(block, kind="missing-test", shim=True), "C1-C7: NOT RUN.", "model_outside_write_denied"),
        ("duplicate-row", run_block(block, kind="duplicate-row", shim=True), "C1-C7: FAIL.", None),
        ("ignored-count", run_block(block, kind="ignored-count", shim=True), "C1-C7: FAIL.", "ignored"),
        ("exit1-with-pass", run_block(block, kind="exit1", shim=True), "C1-C7: FAIL.", "run.sh exited"),
        ("late-rewrite", run_block(block, kind="late-rewrite", shim=True), "C1-C7: FAIL.", None),
        ("stale-summary", run_block(block, kind="stale-summary", shim=True, stale_summary=True), "C1-C7: NOT RUN.", "summary"),
        ("missing-pin", run_block(block, kind="happy", shim=True, include_pin=False), "C1-C7: NOT RUN.", "ea25c4d6"),
        ("planted-fail", run_block(block, kind="fail", shim=True), "C1-C7: FAIL.", "FAIL"),
        ("elastos-created", run_block(block, kind="elastos", shim=True, fake_home=True), "C1-C7: FAIL.", ".elastos"),
        ("missing-sandbox-exec", run_block(block, kind="missing-sandbox-exec", shim=True, hide="sandbox-exec"), "C1-C7: NOT RUN.", "sandbox-exec"),
        ("pass-then-fail", run_block(block, kind="pass-then-fail", shim=True), "C1-C7: FAIL.", None),
    ]

    missed = 0 if static_ok else 1
    for name, result, want_last, want_reason in cases:
        last_ok = result["last"] == want_last
        reason_ok = True
        if want_reason:
            blob = result["reason"] + "\n" + result["output"]
            reason_ok = want_reason in blob
        ok = last_ok and reason_ok
        tag = caught(ok)
        if not ok:
            missed += 1
        print(f"{name}: last={result['last']!r} exit={result['exit']} {tag}")
        if result["reason"]:
            print(f"  reason: {result['reason']}")
        if not ok:
            tail = "\n".join(result["output"].splitlines()[-40:])
            print(tail)
        shutil.rmtree(result["tmp"], ignore_errors=True)

    if missed:
        print("DRYRUN: FAIL")
        return 1
    print("DRYRUN: PASS")
    print("C1-C7 booking: NOT RUN ON MAC")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
