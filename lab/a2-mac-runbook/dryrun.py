#!/usr/bin/env python3
"""Linux dry-run of the A2 Mac runbook fence.

Pastes the exact ```bash block from RUNBOOK.md with a macOS uname /
xcode-select shim. Does not edit lab/a2-e2e-resume or run a real
guest build. A2 itself stays NOT RUN ON MAC.
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
RUNBOOK = HERE / "RUNBOOK.md"
README = HERE / "README.md"
ROWS = ("WRITE", "STALE", "STOP", "START", "RESUME", "WRITE2")
OLD_PIN = "0" * 64
BRANCH = "cursor/a2-mac-runbook-f873"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_block(runbook: Path) -> bytes:
    text = runbook.read_text(encoding="utf-8")
    fences = re.findall(r"```bash\n(.*?)```", text, flags=re.S)
    if len(fences) != 1:
        raise SystemExit(f"{runbook}: expected exactly one ```bash fence, found {len(fences)}")
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


def write_macos_shims(shim_dir: Path) -> None:
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
    for path in (uname, xcode):
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def evidence_text(kind: str) -> str:
    if kind == "fail":
        rows = {
            "WRITE": "PASS — computed from fixture journal",
            "STALE": "FAIL — planted stale row",
            "STOP": "NOT RUN — planted fail stopped later rows",
            "START": "NOT RUN — planted fail stopped later rows",
            "RESUME": "NOT RUN — planted fail stopped later rows",
            "WRITE2": "NOT RUN — planted fail stopped later rows",
        }
        counted = "no"
    else:
        rows = {
            "WRITE": "PASS — computed from fixture journal",
            "STALE": "PASS — computed from fixture conflict",
            "STOP": "PASS — computed from fixture exit 0",
            "START": "PASS — computed from fixture second pid",
            "RESUME": "PASS — computed from fixture read:ok",
            "WRITE2": "PASS — computed from fixture write:ok",
        }
        counted = "yes"
    lines = ["A2 e2e resume proof", ""]
    lines.extend(f"{name}: {rows[name]}" for name in ROWS)
    lines.append(f"A2_counted: {counted}")
    lines.append("skipped: none" if counted == "yes" else "skipped: STOP, START, RESUME, WRITE2")
    lines.append("")
    return "\n".join(lines) + "\n"


def write_fixture(root: Path, kind: str) -> Path:
    repo = root / "remote"
    (repo / "examples" / "agent-host").mkdir(parents=True)
    (repo / "lab" / "a2-e2e-resume").mkdir(parents=True)
    build = repo / "examples" / "agent-host" / "build.sh"
    build.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "dir=$(cd -- \"$(dirname -- \"$0\")\" && pwd -P)\n"
        "printf '%s' 'fake-guest-wasm-for-a2-mac-runbook-dryrun\n' "
        "> \"$dir/agent-host.component.wasm\"\n",
        encoding="utf-8",
    )
    build.chmod(0o755)
    run = repo / "lab" / "a2-e2e-resume" / "run.sh"
    if kind == "tamper":
        run.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "lane=$(cd -- \"$(dirname -- \"$0\")\" && pwd -P)\n"
            "root=$(cd -- \"$lane/../..\" && pwd -P)\n"
            "printf x >> \"$root/examples/agent-host/agent-host.component.wasm\"\n"
            f"cat > \"$lane/evidence.txt\" <<'EOF'\n{evidence_text('happy')}EOF\n",
            encoding="utf-8",
        )
    else:
        run.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "lane=$(cd -- \"$(dirname -- \"$0\")\" && pwd -P)\n"
            f"cat > \"$lane/evidence.txt\" <<'EOF'\n{evidence_text(kind)}EOF\n",
            encoding="utf-8",
        )
    run.chmod(0o755)
    (repo / "lab" / "a2-e2e-resume" / "harness.py").write_text(
        "# fixture stub; the Mac paste runs run.sh\n",
        encoding="utf-8",
    )
    (repo / "lab" / "a2-e2e-resume" / "guest.sha256").write_text(OLD_PIN + "\n", encoding="utf-8")
    subprocess.run(["git", "init", "-b", BRANCH], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=lab@ela.city",
            "-c",
            "user.name=a2-mac-runbook",
            "commit",
            "-m",
            f"fixture {kind}",
        ],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    return repo


def hide_rustup(path: str) -> str:
    kept = []
    for part in path.split(":"):
        if not part:
            continue
        if (Path(part) / "rustup").exists():
            continue
        kept.append(part)
    return ":".join(kept)


def run_block(
    block: bytes,
    *,
    kind: str,
    shim: bool,
    hide_tool: str | None = None,
) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix=f"a2-mac-dryrun-{kind}-"))
    started = time.time()
    try:
        shim_dir = tmp / "shims"
        if shim:
            write_macos_shims(shim_dir)
        work = tmp / "work"
        summary = tmp / "summary.txt"
        env = os.environ.copy()
        env.pop("CARGO_TARGET_DIR", None)
        path_parts = []
        if shim:
            path_parts.append(str(shim_dir))
        base_path = env.get("PATH", "")
        if hide_tool == "rustup":
            base_path = hide_rustup(base_path)
        path_parts.append(base_path)
        env["PATH"] = ":".join(path_parts)
        env["A2_WORKDIR"] = str(work)
        env["A2_SUMMARY"] = str(summary)
        env["A2_CLEAN"] = "0"
        if hide_tool is None:
            remote = write_fixture(tmp, kind)
            env["A2_REMOTE"] = str(remote)
            env["A2_BRANCH"] = BRANCH
        script = tmp / "block.sh"
        script.write_bytes(block)
        script.chmod(0o700)
        shell = ["zsh", "--no-rcs", str(script)]
        done = subprocess.run(
            shell,
            cwd=tmp,
            env=env,
            text=True,
            capture_output=True,
            timeout=120,
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


def main() -> int:
    if len(sys.argv) != 1:
        printf = sys.stderr.write
        printf("usage: dryrun.py\n")
        return 2
    block = extract_block(RUNBOOK)
    digest, size = block_meta(block)
    print(f"BLOCK sha256:{digest} bytes:{size}")
    readme_digest, readme_size = read_readme_meta(README)
    if (readme_digest, readme_size) != (digest, size):
        print("README meta MISSED")
        print(f"README sha256:{readme_digest} bytes:{readme_size}")
        return 1
    print("README meta CAUGHT")

    text = block.decode("utf-8")
    static_ok = True
    if re.search(r"\bsudo\b", text):
        print("static sudo MISSED")
        static_ok = False
    else:
        print("static sudo CAUGHT")
    if "elastos serve" in text:
        print("static elastos-serve MISSED")
        static_ok = False
    else:
        print("static elastos-serve CAUGHT")
    if "already present; skip" not in text:
        print("static rustup-skip MISSED")
        static_ok = False
    else:
        print("static rustup-skip CAUGHT")
    if "mktemp -d" not in text or "trap a2_on_exit EXIT" not in text:
        print("static mktemp-trap MISSED")
        static_ok = False
    else:
        print("static mktemp-trap CAUGHT")

    cases = []
    cases.append(
        (
            "happy",
            run_block(block, kind="happy", shim=True),
            "A2: PASS.",
            None,
        )
    )
    cases.append(
        (
            "planted-fail",
            run_block(block, kind="fail", shim=True),
            "A2: FAIL.",
            "STALE",
        )
    )
    cases.append(
        (
            "missing-tool",
            run_block(block, kind="missing-tool", shim=True, hide_tool="rustup"),
            "A2: NOT RUN.",
            "rustup",
        )
    )
    cases.append(
        (
            "tampered-hash",
            run_block(block, kind="tamper", shim=True),
            "A2: FAIL.",
            "tampered guest hash",
        )
    )

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
            tail = "\n".join(result["output"].splitlines()[-30:])
            print(tail)
        shutil.rmtree(result["tmp"], ignore_errors=True)

    if missed:
        print("DRYRUN: FAIL")
        return 1
    print("DRYRUN: PASS")
    print("A2 booking: NOT RUN ON MAC")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
