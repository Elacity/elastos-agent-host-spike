#!/usr/bin/env python3
"""Linux dry-run of the A2 Mac runbook fence.

Pastes the exact ```bash block from RUNBOOK.md with a macOS uname /
xcode-select / chflags shim. Does not edit lab/a2-e2e-resume or run a
real guest build. Never writes the login-home ~/.elastos. A2 itself
stays NOT RUN ON MAC.
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
REPO_ROOT = HERE.parents[1]
ROWS = ("WRITE", "STALE", "STOP", "START", "RESUME", "WRITE2")
OLD_PIN = "0" * 64
BRANCH = "cursor/a2-mac-runbook-f873"
PIN_A2 = "9e7a85d631aec12de8c1da4fc4958bce18252d21"
GIT_IDENT = ["-c", "user.email=lab@ela.city", "-c", "user.name=a2-mac-runbook"]


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
    chflags = shim_dir / "chflags"
    chflags.write_text(
        "#!/bin/sh\n"
        "flag=\"\"\n"
        "for arg in \"$@\"; do\n"
        "  case \"$arg\" in\n"
        "    -*) continue ;;\n"
        "    uchg|nouchg|schg|noschg|dump|nodump)\n"
        "      flag=$arg\n"
        "      continue\n"
        "      ;;\n"
        "  esac\n"
        "  if [ -z \"$flag\" ] || [ ! -e \"$arg\" ]; then\n"
        "    continue\n"
        "  fi\n"
        "  if [ \"$flag\" = uchg ]; then\n"
        "    chmod a-w \"$arg\"\n"
        "  elif [ \"$flag\" = nouchg ]; then\n"
        "    chmod u+w \"$arg\" 2>/dev/null || chmod a+w \"$arg\"\n"
        "  fi\n"
        "done\n"
        "exit 0\n",
        encoding="utf-8",
    )
    for path in (uname, xcode, chflags):
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
        extras: list[str] = []
    elif kind == "missing-row":
        rows = {
            "WRITE": "PASS — computed from fixture journal",
            "STALE": "PASS — computed from fixture conflict",
            "STOP": "PASS — computed from fixture exit 0",
            "START": "PASS — computed from fixture second pid",
            "RESUME": "PASS — computed from fixture read:ok",
        }
        counted = "yes"
        extras = []
    elif kind == "duplicate-write":
        rows = {
            "WRITE": "PASS — computed from fixture journal",
            "STALE": "PASS — computed from fixture conflict",
            "STOP": "PASS — computed from fixture exit 0",
            "START": "PASS — computed from fixture second pid",
            "RESUME": "PASS — computed from fixture read:ok",
            "WRITE2": "PASS — computed from fixture write:ok",
        }
        counted = "yes"
        extras = ["WRITE: PASS — duplicate planted line"]
    elif kind == "pass-then-fail":
        rows = {
            "WRITE": "PASS — computed from fixture journal",
            "STALE": "PASS — computed from fixture conflict",
            "STOP": "PASS — computed from fixture exit 0",
            "START": "PASS — computed from fixture second pid",
            "RESUME": "PASS — computed from fixture read:ok",
            "WRITE2": "PASS — computed from fixture write:ok",
        }
        counted = "yes"
        extras = ["WRITE: FAIL — planted second result"]
    elif kind == "lookalike":
        rows = {
            "WRITE": "PASS — computed from fixture journal",
            "STALE": "PASS — computed from fixture conflict",
            "STOP": "PASS — computed from fixture exit 0",
            "START": "PASS — computed from fixture second pid",
            "RESUME": "PASS — computed from fixture read:ok",
            "WRITE2": "PASS — computed from fixture write:ok",
        }
        counted = "yes"
        extras = ["WR\u0399TE: FAIL — planted lookalike"]
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
        extras = []
    lines = ["A2 e2e resume proof", ""]
    lines.extend(f"{name}: {rows[name]}" for name in ROWS if name in rows)
    lines.extend(extras)
    lines.append(f"A2_counted: {counted}")
    if counted == "yes":
        lines.append("skipped: none")
    else:
        lines.append("skipped: STOP, START, RESUME, WRITE2")
    lines.append("")
    return "\n".join(lines) + "\n"


def write_run_sh(run: Path, kind: str) -> None:
    header = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "lane=$(cd -- \"$(dirname -- \"$0\")\" && pwd -P)\n"
        "root=$(cd -- \"$lane/../..\" && pwd -P)\n"
    )
    happy = evidence_text("happy")
    if kind == "tamper":
        body = (
            header
            + "printf x >> \"$root/examples/agent-host/agent-host.component.wasm\"\n"
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n"
        )
    elif kind == "survived":
        body = (
            header
            + "printf 'F-REV-GUEST-HASH SURVIVED\\n'\n"
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n"
        )
    elif kind == "late-rewrite":
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
        body = (
            header
            + "mkdir -p -- \"$HOME/.elastos\"\n"
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n"
        )
    elif kind == "exit1":
        body = header + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n" + "exit 1\n"
    elif kind in ("setsid", "python-double-fork"):
        fail = evidence_text("fail")
        helper = (
            "cat > \"$lane/rewrite-later.py\" <<'PY'\n"
            "import pathlib, sys, time\n"
            "time.sleep(12)\n"
            "pathlib.Path(sys.argv[1]).write_bytes(pathlib.Path(sys.argv[2]).read_bytes())\n"
            "PY\n"
            f"cat > \"$lane/rewrite-later.txt\" <<'EOF'\n{fail}EOF\n"
        )
        if kind == "setsid":
            launch = (
                "setsid python3 -I \"$lane/rewrite-later.py\" "
                "\"$lane/evidence.txt\" \"$lane/rewrite-later.txt\" &\n"
            )
        else:
            launch = (
                "cat > \"$lane/double-fork.py\" <<'PY'\n"
                "import os, sys\n"
                "script, ev, src = sys.argv[1], sys.argv[2], sys.argv[3]\n"
                "if os.fork() > 0:\n"
                "    raise SystemExit(0)\n"
                "os.setsid()\n"
                "if os.fork() > 0:\n"
                "    os._exit(0)\n"
                "os.execv(sys.executable, [sys.executable, '-I', script, ev, src])\n"
                "PY\n"
                "python3 -I \"$lane/double-fork.py\" "
                "\"$lane/rewrite-later.py\" \"$lane/evidence.txt\" \"$lane/rewrite-later.txt\"\n"
            )
        body = (
            header
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n"
            + helper
            + launch
        )
    elif kind == "symlink":
        body = (
            header
            + f"cat > \"$HOME/planted-evidence.txt\" <<'EOF'\n{happy}EOF\n"
            + "ln -s -- \"$HOME/planted-evidence.txt\" \"$lane/evidence.txt\"\n"
        )
    elif kind == "home-redirect":
        body = (
            header
            + "a2_login=$(eval echo ~$(id -un))\n"
            + "mkdir -p -- \"$a2_login/.elastos\"\n"
            + "printf 'planted\\n' > \"$a2_login/.elastos/a2-home-redirect\"\n"
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n"
        )
    elif kind == "existing-elastos-write":
        body = (
            header
            + "mkdir -p -- \"$HOME/.elastos\"\n"
            + "printf 'planted\\n' > \"$HOME/.elastos/a2-existing-write\"\n"
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n"
        )
    elif kind == "exec-a-delay22":
        fail = evidence_text("fail")
        body = (
            header
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n"
            + "plant_dir=/tmp/a2-mac-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "ev=$(cd -- \"$lane\" && pwd -P)/evidence.txt\n"
            + "fail=$plant_dir/fail.txt\n"
            + f"cat > \"$fail\" <<'EOF'\n{fail}EOF\n"
            + "cat > \"$plant_dir/rewriter.py\" <<PY\n"
            + "import pathlib, time\n"
            + "time.sleep(22)\n"
            + "pathlib.Path(r'''$ev''').write_bytes(pathlib.Path(r'''$fail''').read_bytes())\n"
            + "PY\n"
            + "python3 -I -c 'import os,sys; os.setsid(); "
            + "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
            + "\"$plant_dir/rewriter.py\" &\n"
        )
    elif kind == "reopen-fd-22":
        fail = evidence_text("fail")
        body = (
            header
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n"
            + "plant_dir=/tmp/a2-mac-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "ev=$(cd -- \"$lane\" && pwd -P)/evidence.txt\n"
            + "fail=$plant_dir/fail.txt\n"
            + f"cat > \"$fail\" <<'EOF'\n{fail}EOF\n"
            + "cat > \"$plant_dir/rewriter.py\" <<PY\n"
            + "import pathlib, time\n"
            + "path = pathlib.Path(r'''$ev''')\n"
            + "fh = path.open('rb')\n"
            + "fh.close()\n"
            + "time.sleep(22)\n"
            + "path.write_bytes(pathlib.Path(r'''$fail''').read_bytes())\n"
            + "PY\n"
            + "python3 -I -c 'import os,sys; os.setsid(); "
            + "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
            + "\"$plant_dir/rewriter.py\" &\n"
        )
    elif kind == "hardlink-delay22":
        fail = evidence_text("fail")
        body = (
            header
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n"
            + "plant_dir=/tmp/a2-mac-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "outside=$plant_dir/linked-evidence\n"
            + "ln -- \"$lane/evidence.txt\" \"$outside\"\n"
            + "fail=$plant_dir/fail.txt\n"
            + f"cat > \"$fail\" <<'EOF'\n{fail}EOF\n"
            + "cat > \"$plant_dir/rewriter.py\" <<PY\n"
            + "import pathlib, time\n"
            + "time.sleep(22)\n"
            + "pathlib.Path(r'''$outside''').write_bytes(pathlib.Path(r'''$fail''').read_bytes())\n"
            + "PY\n"
            + "python3 -I -c 'import os,sys; os.setsid(); "
            + "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
            + "\"$plant_dir/rewriter.py\" &\n"
        )
    elif kind == "summary-rewrite":
        fail = evidence_text("fail")
        body = (
            header
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{fail}EOF\n"
            + "plant_dir=/tmp/a2-mac-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "sum=${A2_SUMMARY:-}\n"
            + "cat > \"$plant_dir/rewriter.py\" <<PY\n"
            + "import pathlib, time, os\n"
            + "path = pathlib.Path(os.environ.get('A2_SUMMARY_BAK', r'''$sum'''))\n"
            + "deadline = time.time() + 40\n"
            + "while time.time() < deadline:\n"
            + "    if path.is_file() and 'A2: ' in path.read_text(encoding='utf-8', errors='replace'):\n"
            + "        time.sleep(1.5)\n"
            + "        text = path.read_text(encoding='utf-8', errors='replace')\n"
            + "        lines = text.splitlines()\n"
            + "        if lines:\n"
            + "            lines[-1] = 'A2: PASS.'\n"
            + "        path.write_text('\\n'.join(lines) + '\\n', encoding='utf-8')\n"
            + "        break\n"
            + "    time.sleep(0.05)\n"
            + "PY\n"
            + "export A2_SUMMARY_BAK=\"$sum\"\n"
            + "python3 -I -c 'import os,sys; os.setsid(); "
            + "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
            + "\"$plant_dir/rewriter.py\" &\n"
        )
    elif kind == "mtime-preserve":
        body = (
            header
            + "python3 -I -c '\n"
            + "import os\n"
            + "from pathlib import Path\n"
            + "p = Path.home() / \".elastos\" / \"pre-existing\"\n"
            + "st = p.stat()\n"
            + "p.write_text(\"plante\\n\", encoding=\"utf-8\")\n"
            + "os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))\n"
            + "'\n"
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n"
        )
    elif kind == "mds-reader":
        body = (
            header
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{happy}EOF\n"
            + "plant_dir=/tmp/a2-mac-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "target=$(cd -- \"$lane\" && pwd -P)/evidence.txt\n"
            + "cat > \"$plant_dir/reader.py\" <<PY\n"
            + "import time\n"
            + "fh = open(r'''$target''', 'rb')\n"
            + "time.sleep(20)\n"
            + "fh.close()\n"
            + "PY\n"
            + "python3 -I -c 'import os,sys; os.setsid(); "
            + "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
            + "\"$plant_dir/reader.py\" &\n"
        )
    else:
        ev_kind = (
            kind
            if kind in ("fail", "missing-row", "duplicate-write", "pass-then-fail", "lookalike")
            else "happy"
        )
        body = header + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{evidence_text(ev_kind)}EOF\n"
    run.write_text(body, encoding="utf-8")
    run.chmod(0o755)


def graft_pin(repo: Path, kind: str) -> None:
    fetched = subprocess.run(
        ["git", "fetch", "--", str(REPO_ROOT), PIN_A2],
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
        ["git", *GIT_IDENT, "commit-tree", tree, "-p", PIN_A2, "-m", f"fixture {kind}"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "reset", "--hard", commit], cwd=repo, check=True, capture_output=True)


def write_fixture(root: Path, kind: str, *, include_pin: bool = True) -> Path:
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
    write_run_sh(repo / "lab" / "a2-e2e-resume" / "run.sh", kind)
    (repo / "lab" / "a2-e2e-resume" / "harness.py").write_text(
        "# fixture stub; the Mac paste runs run.sh\n",
        encoding="utf-8",
    )
    (repo / "lab" / "a2-e2e-resume" / "guest.sha256").write_text(OLD_PIN + "\n", encoding="utf-8")
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


def login_home_path() -> Path:
    out = subprocess.check_output(["bash", "-c", "eval echo ~$(id -un)"], text=True)
    return Path(out.strip())


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
    include_pin: bool = True,
    fake_home: bool = False,
    existing_elastos: bool = False,
    linger: float = 0,
    timeout: int = 180,
    a2_clean: str = "0",
    pre_proc: subprocess.Popen | None = None,
) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix=f"a2-mac-dryrun-{kind}-"))
    started = time.time()
    login_elastos = login_home_path() / ".elastos"
    login_existed = login_elastos.exists()
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
        env["A2_CLEAN"] = a2_clean
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
            if existing_elastos:
                elastos = home / ".elastos"
                elastos.mkdir()
                (elastos / "pre-existing").write_text("before\n", encoding="utf-8")
        if hide_tool is None:
            remote = write_fixture(tmp, kind if kind != "argv-hang" else "happy", include_pin=include_pin)
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
            timeout=timeout,
        )
        if linger > 0:
            time.sleep(linger)
        output = (done.stdout or "") + (done.stderr or "")
        last = ""
        reason = ""
        summary_text = ""
        if summary.is_file():
            summary_text = summary.read_text(encoding="utf-8", errors="replace")
            lines = summary_text.splitlines()
            if lines:
                last = lines[-1]
            for line in lines:
                if line.startswith("reason: "):
                    reason = line[len("reason: ") :]
        evidence = ""
        ev = work / "src" / "lab" / "a2-e2e-resume" / "evidence.txt"
        if ev.is_file():
            evidence = ev.read_text(encoding="utf-8", errors="replace")
        home_after = ""
        if fake_home:
            planted = Path(env["HOME"]) / ".elastos" / "pre-existing"
            if planted.is_file():
                home_after = planted.read_text(encoding="utf-8")
        return {
            "kind": kind,
            "exit": done.returncode,
            "seconds": round(time.time() - started, 3),
            "last": last,
            "reason": reason,
            "output": output,
            "summary": str(summary) if summary.is_file() else "",
            "summary_text": summary_text,
            "evidence": evidence,
            "home_after": home_after,
            "workdir": str(work),
            "workdir_exists": work.exists(),
            "tmp": str(tmp),
            "timeout": False,
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
            "summary_text": "",
            "evidence": "",
            "home_after": "",
            "workdir": str(tmp / "work"),
            "workdir_exists": (tmp / "work").exists(),
            "tmp": str(tmp),
            "timeout": True,
        }
    finally:
        if pre_proc is not None:
            pre_proc.terminate()
            try:
                pre_proc.wait(timeout=2)
            except Exception:
                pre_proc.kill()
        if kind == "home-redirect" and not login_existed and login_elastos.exists():
            shutil.rmtree(login_elastos, ignore_errors=True)


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
    if "--single-branch" in text:
        print("static no-single-branch MISSED")
        static_ok = False
    else:
        print("static no-single-branch CAUGHT")
    if "readlink -f" in text or "sed -i" in text or "stat -c" in text:
        print("static bsd-portable MISSED")
        static_ok = False
    else:
        print("static bsd-portable CAUGHT")
    if re.search(r"curl\s*\|", text):
        print("static no-curl-sh MISSED")
        static_ok = False
    else:
        print("static no-curl-sh CAUGHT")
    if '["ps", "-ax", "-o", "pid,command"]' not in text:
        print("static argv-wait MISSED")
        static_ok = False
    else:
        print("static argv-wait CAUGHT")
    if "lsof" not in text or "sleep 15" not in text:
        print("static lsof-quiet MISSED")
        static_ok = False
    else:
        print("static lsof-quiet CAUGHT")
    if "eval echo ~$(id -un)" not in text:
        print("static login-home MISSED")
        static_ok = False
    else:
        print("static login-home CAUGHT")
    if "chflags uchg" not in text or "a2_freeze_file" not in text:
        print("static freeze-uchg MISSED")
        static_ok = False
    else:
        print("static freeze-uchg CAUGHT")
    if "chflags nouchg" not in text or "a2_nouchg_if_inside" not in text:
        print("static nouchg-clean MISSED")
        static_ok = False
    else:
        print("static nouchg-clean CAUGHT")
    if "hashlib.sha256" not in text or ".DS_Store" not in text:
        print("static elastos-sha256 MISSED")
        static_ok = False
    else:
        print("static elastos-sha256 CAUGHT")
    if "lsof +D" in text or 'cmds.append(["lsof", "+D"' in text:
        print("static lsof-file-only MISSED")
        static_ok = False
    else:
        print("static lsof-file-only CAUGHT")
    if 'for item in (workdir, lane, "lab/a2-e2e-resume")' in text:
        print("static wait-abs-paths MISSED")
        static_ok = False
    elif "for item in (workdir, lane):" not in text:
        print("static wait-abs-paths MISSED")
        static_ok = False
    else:
        print("static wait-abs-paths CAUGHT")

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
    cases.append(
        (
            "missing-row",
            run_block(block, kind="missing-row", shim=True),
            "A2: NOT RUN.",
            "WRITE2",
        )
    )
    cases.append(
        (
            "duplicate-write",
            run_block(block, kind="duplicate-write", shim=True),
            "A2: FAIL.",
            None,
        )
    )
    cases.append(
        (
            "survived-line",
            run_block(block, kind="survived", shim=True),
            "A2: FAIL.",
            "SURVIVED",
        )
    )
    cases.append(
        (
            "late-rewrite",
            run_block(block, kind="late-rewrite", shim=True),
            "A2: FAIL.",
            None,
        )
    )
    cases.append(
        (
            "missing-pin",
            run_block(block, kind="happy", shim=True, include_pin=False),
            "A2: NOT RUN.",
            "9e7a85d6",
        )
    )
    cases.append(
        (
            "elastos-created",
            run_block(block, kind="elastos", shim=True, fake_home=True),
            "A2: FAIL.",
            ".elastos",
        )
    )
    cases.append(
        (
            "runsh-exit1",
            run_block(block, kind="exit1", shim=True),
            "A2: FAIL.",
            "run.sh exited",
        )
    )
    cases.append(
        (
            "pass-then-fail",
            run_block(block, kind="pass-then-fail", shim=True),
            "A2: FAIL.",
            None,
        )
    )
    cases.append(
        (
            "setsid-rewrite",
            run_block(block, kind="setsid", shim=True),
            "A2: FAIL.",
            None,
        )
    )
    cases.append(
        (
            "python-double-fork",
            run_block(block, kind="python-double-fork", shim=True),
            "A2: FAIL.",
            None,
        )
    )
    cases.append(
        (
            "evidence-symlink",
            run_block(block, kind="symlink", shim=True, fake_home=True),
            "A2: FAIL.",
            "evidence.txt",
        )
    )
    cases.append(
        (
            "lookalike-row",
            run_block(block, kind="lookalike", shim=True),
            "A2: FAIL.",
            "non-ASCII",
        )
    )
    cases.append(
        (
            "home-redirect",
            run_block(block, kind="home-redirect", shim=True, fake_home=True),
            "A2: FAIL.",
            ".elastos",
        )
    )
    cases.append(
        (
            "existing-elastos-write",
            run_block(
                block,
                kind="existing-elastos-write",
                shim=True,
                fake_home=True,
                existing_elastos=True,
            ),
            "A2: FAIL.",
            ".elastos",
        )
    )
    cases.append(
        (
            "exec-a-delay22",
            run_block(block, kind="exec-a-delay22", shim=True, linger=8),
            "A2: PASS.",
            None,
        )
    )
    cases.append(
        (
            "reopen-fd-22",
            run_block(block, kind="reopen-fd-22", shim=True, linger=8),
            "A2: PASS.",
            None,
        )
    )
    cases.append(
        (
            "hardlink-delay22",
            run_block(block, kind="hardlink-delay22", shim=True, linger=8),
            "A2: PASS.",
            None,
        )
    )
    cases.append(
        (
            "summary-rewrite",
            run_block(block, kind="summary-rewrite", shim=True, linger=3),
            "A2: FAIL.",
            None,
        )
    )
    cases.append(
        (
            "mtime-preserve",
            run_block(
                block,
                kind="mtime-preserve",
                shim=True,
                fake_home=True,
                existing_elastos=True,
            ),
            "A2: FAIL.",
            ".elastos",
        )
    )
    cases.append(
        (
            "mds-reader",
            run_block(block, kind="mds-reader", shim=True),
            "A2: PASS.",
            None,
        )
    )
    decoy = subprocess.Popen(
        [sys.executable, "-I", "-c", "import time; time.sleep(120)  # lab/a2-e2e-resume"],
    )
    cases.append(
        (
            "argv-hang",
            run_block(block, kind="argv-hang", shim=True, timeout=40, pre_proc=decoy),
            "A2: PASS.",
            None,
        )
    )
    cases.append(
        (
            "clean-uchg",
            run_block(block, kind="happy", shim=True, a2_clean="1"),
            "A2: PASS.",
            None,
        )
    )

    missed = 0 if static_ok else 1
    for name, result, want_last, want_reason in cases:
        last_ok = result["last"] == want_last
        reason_ok = True
        if want_reason:
            blob = result["reason"] + "\n" + result["output"]
            reason_ok = want_reason in blob
        extra_ok = True
        evidence = result.get("evidence") or ""
        if name in ("exec-a-delay22", "reopen-fd-22", "hardlink-delay22"):
            extra_ok = "STALE: FAIL" not in evidence
        elif name == "summary-rewrite":
            extra_ok = result["last"] == "A2: FAIL."
        elif name == "mtime-preserve":
            extra_ok = result.get("home_after") == "plante\n"
        elif name == "argv-hang":
            extra_ok = not result.get("timeout")
        elif name == "clean-uchg":
            extra_ok = not result.get("workdir_exists", True)
        ok = last_ok and reason_ok and extra_ok
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
