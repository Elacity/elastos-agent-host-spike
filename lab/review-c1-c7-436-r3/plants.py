#!/usr/bin/env python3
"""r3 plants against the #436 C1-C7 Mac runbook fence at 5f50fc48.

Imports the author's dryrun helpers. Does not edit #436 files.
C1-C7 on a Mac stays NOT RUN ON MAC.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

RUNBOOK_DIR = Path(
    os.environ.get("C17_RUNBOOK_DIR", "/workspace/lab/c1-c7-mac-runbook")
).resolve()
sys.path.insert(0, str(RUNBOOK_DIR))
import dryrun as d  # noqa: E402

d.REPO_ROOT = Path(os.environ.get("C17_REPO_ROOT", "/workspace")).resolve()

REVIEWED = "5f50fc484fcc679c46715340ea5474f9ceec06a9"
WANT_SHA = "bfd28dcdd2d8823e31c3d151bf63d0fd84944437c9c104cbfcddb0553ebe1569"
WANT_BYTES = 27143

HAPPY = d.evidence_text("happy")
FAIL = d.evidence_text("fail")
_ORIG_WRITE = d.write_run_sh
FAIL_MARK = "wallet/confined_outside_write_is_denied: FAIL"


def header() -> str:
    return (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "lane=$(cd -- \"$(dirname -- \"$0\")\" && pwd -P)\n"
    )


def probe_denied() -> str:
    return (
        "mkdir -p -- \"$lane/probe\"\n"
        "cat > \"$lane/probe/sbpl.out\" <<'EOF'\n"
        "SBPL_PROBE: DENIED\n"
        "EOF\n"
    )


def detached_rewriter(sleep_s: int, dest_var: str, src_var: str) -> str:
    """Write a /tmp helper and exec -a mds after setsid. dest/src are shell vars."""
    return (
        "plant_dir=/tmp/r3-c17-plant-$$\n"
        "mkdir -p -- \"$plant_dir\"\n"
        f"cat > \"$plant_dir/rewriter.py\" <<PY\n"
        "import pathlib, time\n"
        f"time.sleep({sleep_s})\n"
        f"pathlib.Path(r'''{dest_var}''').write_bytes("
        f"pathlib.Path(r'''{src_var}''').read_bytes())\n"
        "PY\n"
        "python3 -I -c 'import os,sys; os.setsid(); "
        "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
        "\"$plant_dir/rewriter.py\" &\n"
    )


def write_custom_run_sh(run: Path, kind: str) -> None:
    if kind == "exec-a-delay22":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
            + probe_denied()
            + "ev=$(cd -- \"$lane\" && pwd -P)/evidence.txt\n"
            + "plant_dir=/tmp/r3-c17-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "fail=$plant_dir/fail.txt\n"
            + f"cat > \"$fail\" <<'EOF'\n{FAIL}EOF\n"
            + "cat > \"$plant_dir/rewriter.py\" <<PY\n"
            + "import pathlib, time\n"
            + "time.sleep(22)\n"
            + "pathlib.Path(r'''$ev''').write_bytes(pathlib.Path(r'''$fail''').read_bytes())\n"
            + "PY\n"
            + "python3 -I -c 'import os,sys; os.setsid(); "
            + "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
            + "\"$plant_dir/rewriter.py\" &\n"
        )
    elif kind == "nohup-exec-a-delay22":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
            + probe_denied()
            + "ev=$(cd -- \"$lane\" && pwd -P)/evidence.txt\n"
            + "plant_dir=/tmp/r3-c17-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "fail=$plant_dir/fail.txt\n"
            + f"cat > \"$fail\" <<'EOF'\n{FAIL}EOF\n"
            + "cat > \"$plant_dir/rewriter.py\" <<PY\n"
            + "import pathlib, time\n"
            + "time.sleep(22)\n"
            + "pathlib.Path(r'''$ev''').write_bytes(pathlib.Path(r'''$fail''').read_bytes())\n"
            + "PY\n"
            + "nohup python3 -I -c 'import os,sys; os.setsid(); "
            + "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
            + "\"$plant_dir/rewriter.py\" >/dev/null 2>&1 &\n"
        )
    elif kind == "inherited-fd-open":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
            + probe_denied()
            + "plant_dir=/tmp/r3-c17-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "fail=$plant_dir/fail.txt\n"
            + f"cat > \"$fail\" <<'EOF'\n{FAIL}EOF\n"
            + "python3 -I -c '\n"
            + "import os, sys, time\n"
            + "os.setsid()\n"
            + "time.sleep(8)\n"
            + "data = open(sys.argv[1], \"rb\").read()\n"
            + "os.lseek(3, 0, os.SEEK_SET)\n"
            + "os.write(3, data)\n"
            + "os.ftruncate(3, len(data))\n"
            + f"' \"$fail\" 3>>\"$lane/evidence.txt\" &\n"
        )
    elif kind == "inherited-fd-reopen22":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
            + probe_denied()
            + "ev=$(cd -- \"$lane\" && pwd -P)/evidence.txt\n"
            + "plant_dir=/tmp/r3-c17-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "fail=$plant_dir/fail.txt\n"
            + f"cat > \"$fail\" <<'EOF'\n{FAIL}EOF\n"
            + "cat > \"$plant_dir/rewriter.py\" <<PY\n"
            + "import pathlib, time\n"
            + "time.sleep(22)\n"
            + "pathlib.Path(r'''$ev''').write_bytes(pathlib.Path(r'''$fail''').read_bytes())\n"
            + "PY\n"
            + "python3 -I -c 'import os,sys; os.setsid(); "
            + "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
            + "\"$plant_dir/rewriter.py\" &\n"
        )
    elif kind == "hardlink-quiet":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
            + probe_denied()
            + "outside=/tmp/r3-c17-hardlink-$$\n"
            + "ln -- \"$lane/evidence.txt\" \"$outside\"\n"
            + "(\n"
            + "  sleep 8\n"
            + f"  cat > \"$outside\" <<'EOF'\n{FAIL}EOF\n"
            + ") &\n"
        )
    elif kind == "hardlink-delay22":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
            + probe_denied()
            + "plant_dir=/tmp/r3-c17-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "outside=$plant_dir/linked-evidence\n"
            + "ln -- \"$lane/evidence.txt\" \"$outside\"\n"
            + "fail=$plant_dir/fail.txt\n"
            + f"cat > \"$fail\" <<'EOF'\n{FAIL}EOF\n"
            + "cat > \"$plant_dir/rewriter.py\" <<PY\n"
            + "import pathlib, time\n"
            + "time.sleep(22)\n"
            + "pathlib.Path(r'''$outside''').write_bytes("
            + "pathlib.Path(r'''$fail''').read_bytes())\n"
            + "PY\n"
            + "python3 -I -c 'import os,sys; os.setsid(); "
            + "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
            + "\"$plant_dir/rewriter.py\" &\n"
        )
    elif kind == "toctou-snap":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
            + probe_denied()
            + "work=$(cd -- \"$lane/../..\" && pwd -P)/..\n"
            + "work=$(cd -- \"$work\" && pwd -P)\n"
            + "plant_dir=/tmp/r3-c17-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "ev=$(cd -- \"$lane\" && pwd -P)/evidence.txt\n"
            + "fail=$plant_dir/fail.txt\n"
            + "snap=$work/evidence.snap\n"
            + f"cat > \"$fail\" <<'EOF'\n{FAIL}EOF\n"
            + "cat > \"$plant_dir/rewriter.py\" <<PY\n"
            + "import pathlib, time\n"
            + "snap = pathlib.Path(r'''$snap''')\n"
            + "deadline = time.time() + 40\n"
            + "while time.time() < deadline:\n"
            + "    if snap.is_file():\n"
            + "        pathlib.Path(r'''$ev''').write_bytes("
            + "pathlib.Path(r'''$fail''').read_bytes())\n"
            + "        break\n"
            + "    time.sleep(0.01)\n"
            + "PY\n"
            + "python3 -I -c 'import os,sys; os.setsid(); "
            + "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
            + "\"$plant_dir/rewriter.py\" &\n"
        )
    elif kind == "summary-rewrite":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{FAIL}EOF\n"
            + probe_denied()
            + "plant_dir=/tmp/r3-c17-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "sum=${C17_SUMMARY:-}\n"
            + "cat > \"$plant_dir/rewriter.py\" <<PY\n"
            + "import pathlib, time, os\n"
            + "path = pathlib.Path(os.environ.get('C17_SUMMARY_BAK', r'''$sum'''))\n"
            + "deadline = time.time() + 40\n"
            + "while time.time() < deadline:\n"
            + "    if path.is_file() and 'C1-C7: ' in path.read_text("
            + "encoding='utf-8', errors='replace'):\n"
            + "        time.sleep(1.5)\n"
            + "        text = path.read_text(encoding='utf-8', errors='replace')\n"
            + "        lines = text.splitlines()\n"
            + "        if lines:\n"
            + "            lines[-1] = 'C1-C7: PASS.'\n"
            + "        path.write_text('\\n'.join(lines) + '\\n', encoding='utf-8')\n"
            + "        break\n"
            + "    time.sleep(0.05)\n"
            + "PY\n"
            + "export C17_SUMMARY_BAK=\"$sum\"\n"
            + "python3 -I -c 'import os,sys; os.setsid(); "
            + "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
            + "\"$plant_dir/rewriter.py\" &\n"
        )
    elif kind == "hardlink-summary":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{FAIL}EOF\n"
            + probe_denied()
            + "plant_dir=/tmp/r3-c17-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "sum=${C17_SUMMARY:-}\n"
            + "cat > \"$plant_dir/rewriter.py\" <<PY\n"
            + "import os, pathlib, time\n"
            + "src = pathlib.Path(os.environ.get('C17_SUMMARY_BAK', r'''$sum'''))\n"
            + "outside = pathlib.Path(r'''$plant_dir''') / 'linked-summary'\n"
            + "deadline = time.time() + 40\n"
            + "while time.time() < deadline:\n"
            + "    if src.is_file() and 'C1-C7: ' in src.read_text("
            + "encoding='utf-8', errors='replace'):\n"
            + "        time.sleep(1.5)\n"
            + "        try:\n"
            + "            if not outside.exists():\n"
            + "                os.link(src, outside)\n"
            + "        except OSError:\n"
            + "            pass\n"
            + "        text = outside.read_text(encoding='utf-8', errors='replace') "
            + "if outside.is_file() else src.read_text(encoding='utf-8', errors='replace')\n"
            + "        lines = text.splitlines()\n"
            + "        if lines:\n"
            + "            lines[-1] = 'C1-C7: PASS.'\n"
            + "        target = outside if outside.is_file() else src\n"
            + "        target.write_text('\\n'.join(lines) + '\\n', encoding='utf-8')\n"
            + "        break\n"
            + "    time.sleep(0.05)\n"
            + "PY\n"
            + "export C17_SUMMARY_BAK=\"$sum\"\n"
            + "python3 -I -c 'import os,sys; os.setsid(); "
            + "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
            + "\"$plant_dir/rewriter.py\" &\n"
        )
    elif kind == "combining-row":
        extra = "wallet/conf\u0301ined_outside_write_is_denied: FAIL\n"
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}{extra}EOF\n"
            + probe_denied()
        )
    elif kind == "zwsp-row":
        extra = "wallet/conf\u200bined_outside_write_is_denied: FAIL\n"
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}{extra}EOF\n"
            + probe_denied()
        )
    elif kind == "nul-after-pass":
        body = (
            header()
            + "python3 -I -c '\n"
            + "from pathlib import Path\n"
            + "p = Path(\"lab/c1-c7-mac-runbook\")\n"
            + "p.mkdir(parents=True, exist_ok=True)\n"
            + f"raw = {HAPPY.encode('utf-8')!r}.replace(\n"
            + '    b"wallet/confined_outside_write_is_denied: PASS",\n'
            + '    b"wallet/confined_outside_write_is_denied: PASS\\x00FAIL",\n'
            + "    1,\n"
            + ")\n"
            + "(p / \"evidence.txt\").write_bytes(raw)\n"
            + "'\n"
            + probe_denied()
        )
    elif kind == "mtime-preserve":
        body = (
            header()
            + "python3 -I -c '\n"
            + "import os\n"
            + "from pathlib import Path\n"
            + "p = Path.home() / \".elastos\" / \"pre-existing\"\n"
            + "st = p.stat()\n"
            + "p.write_text(\"plante\\n\", encoding=\"utf-8\")\n"
            + "os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))\n"
            + "'\n"
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
            + probe_denied()
        )
    elif kind == "mds-reader":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
            + probe_denied()
            + "plant_dir=/tmp/r3-c17-plant-$$\n"
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
    elif kind == "probe-stale-allowed":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
        )
    elif kind == "probe-delay22":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
            + probe_denied()
            + "pr=$(cd -- \"$lane\" && pwd -P)/probe/sbpl.out\n"
            + "plant_dir=/tmp/r3-c17-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "cat > \"$plant_dir/allowed.txt\" <<'EOF'\n"
            + "SBPL_PROBE: ALLOWED\n"
            + "EOF\n"
            + "cat > \"$plant_dir/rewriter.py\" <<PY\n"
            + "import pathlib, time\n"
            + "time.sleep(22)\n"
            + "pathlib.Path(r'''$pr''').write_bytes("
            + "pathlib.Path(r'''$plant_dir/allowed.txt''').read_bytes())\n"
            + "PY\n"
            + "python3 -I -c 'import os,sys; os.setsid(); "
            + "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
            + "\"$plant_dir/rewriter.py\" &\n"
        )
    elif kind == "happy-probe":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
            + probe_denied()
        )
    else:
        _ORIG_WRITE(run, kind)
        return
    run.write_text(body, encoding="utf-8")
    run.chmod(0o755)
    if kind == "probe-stale-allowed":
        probe = run.parent / "probe"
        probe.mkdir(parents=True, exist_ok=True)
        (probe / "sbpl.out").write_text("SBPL_PROBE: ALLOWED\n", encoding="utf-8")


def run_block_custom(
    block: bytes,
    *,
    kind: str,
    fake_home: bool = False,
    existing_elastos: bool = False,
    include_pin: bool = True,
    timeout: int = 90,
    extra_env: dict | None = None,
    hide: str | None = None,
    pre_proc: subprocess.Popen | None = None,
    linger: float = 0,
    shell: list[str] | None = None,
) -> dict:
    orig = d.write_run_sh
    d.write_run_sh = write_custom_run_sh  # type: ignore[assignment]
    tmp = Path(tempfile.mkdtemp(prefix=f"c17-r3-{kind}-"))
    started = time.time()
    login_elastos = d.login_home_path() / ".elastos"
    login_existed = login_elastos.exists()
    planted_login = login_elastos / "c17-home-redirect"
    try:
        shim_dir = tmp / "shims"
        d.write_macos_shims(shim_dir)
        work = tmp / "work"
        summary = tmp / "summary.txt"
        env = os.environ.copy()
        env.pop("CARGO_TARGET_DIR", None)
        base_path = env.get("PATH", "")
        if hide:
            blocker = tmp / "hide" / hide
            blocker.parent.mkdir(parents=True, exist_ok=True)
            blocker.write_text("#!/bin/sh\nexit 127\n", encoding="utf-8")
            blocker.chmod(0o755)
            env["PATH"] = str(blocker.parent) + ":" + str(shim_dir) + ":" + base_path
        else:
            env["PATH"] = str(shim_dir) + ":" + base_path
        env["C17_WORKDIR"] = str(work)
        env["C17_SUMMARY"] = str(summary)
        env["C17_CLEAN"] = "0"
        if extra_env:
            env.update(extra_env)
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
        if hide != "python3":
            remote = d.write_fixture(tmp, kind, include_pin=include_pin)
            env["C17_REMOTE"] = str(remote)
            env["C17_BRANCH"] = d.BRANCH
        script = tmp / "block.sh"
        script.write_bytes(block)
        script.chmod(0o700)
        cmd = shell or ["zsh", "--no-rcs", str(script)]
        done = subprocess.run(
            cmd,
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
        probe = ""
        summary_later = ""
        if summary.is_file():
            summary_later = summary.read_text(encoding="utf-8", errors="replace")
            lines = summary_later.splitlines()
            if lines:
                last = lines[-1]
            for line in lines:
                if line.startswith("reason: "):
                    reason = line[len("reason: ") :]
                if line.startswith("SBPL_PROBE:"):
                    probe = line
        ev = work / "src" / "lab" / "c1-c7-mac-runbook" / "evidence.txt"
        evidence_later = ""
        if ev.is_file() or ev.is_symlink():
            evidence_later = ev.read_bytes().decode("utf-8", errors="replace")
        pr = work / "src" / "lab" / "c1-c7-mac-runbook" / "probe" / "sbpl.out"
        probe_later = ""
        if pr.is_file():
            probe_later = pr.read_text(encoding="utf-8", errors="replace")
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
            "probe": probe,
            "output": output,
            "summary": str(summary) if summary.is_file() else "",
            "summary_text": summary_later,
            "evidence": evidence_later,
            "probe_later": probe_later,
            "home_after": home_after,
            "tmp": str(tmp),
            "workdir": str(work),
            "timeout": False,
        }
    except subprocess.TimeoutExpired as error:
        return {
            "kind": kind,
            "exit": 124,
            "seconds": round(time.time() - started, 3),
            "last": "",
            "reason": f"TIMEOUT after {error.timeout}s",
            "probe": "",
            "output": (error.stdout or "") + (error.stderr or ""),
            "summary": "",
            "summary_text": "",
            "evidence": "",
            "probe_later": "",
            "home_after": "",
            "tmp": str(tmp),
            "workdir": str(tmp / "work"),
            "timeout": True,
        }
    finally:
        d.write_run_sh = orig  # type: ignore[assignment]
        if pre_proc is not None:
            pre_proc.terminate()
            try:
                pre_proc.wait(timeout=2)
            except Exception:
                pre_proc.kill()
        if planted_login.exists():
            planted_login.unlink()
        if kind == "home-redirect" and not login_existed and login_elastos.exists():
            shutil.rmtree(login_elastos, ignore_errors=True)


def bash4_hits(text: str) -> list[str]:
    hits = []
    for needle, label in (
        ("mapfile ", "mapfile"),
        ("readarray ", "readarray"),
        ("declare -n", "nameref"),
        ("|&", "|&"),
        ("readlink -f", "readlink -f"),
        ("sed -i", "sed -i"),
        ("stat -c", "stat -c"),
        ("stat --printf", "stat --printf"),
    ):
        if needle in text:
            hits.append(label)
    return sorted(set(hits))


def later_fail(evidence: str) -> bool:
    return FAIL_MARK in evidence


def main() -> int:
    block = d.extract_block(d.README)
    digest, size = d.block_meta(block)
    print(f"REVIEWED {REVIEWED}")
    print(f"BLOCK sha256:{digest} bytes:{size}")
    if digest != WANT_SHA or size != WANT_BYTES:
        print("fence meta MISSED")
        return 1
    print("fence meta CAUGHT")
    text = block.decode("utf-8")
    run_text = d.RUN_SH.read_text(encoding="utf-8")
    rows: list[tuple[str, str, str]] = []

    def record(name: str, result: str, detail: str) -> None:
        rows.append((name, result, detail))
        print(f"{name}: {result} — {detail}")

    r = run_block_custom(block, kind="exec-a-delay22", linger=8)
    if r["last"] == "C1-C7: PASS." and later_fail(r["evidence"]):
        record("exec-a-delay22", "SURVIVED", f"last={r['last']!r} then evidence FAIL after {r['seconds']}s")
    elif r["last"] == "C1-C7: FAIL.":
        record("exec-a-delay22", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record("exec-a-delay22", "SURVIVED", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="nohup-exec-a-delay22", linger=8)
    if r["last"] == "C1-C7: PASS." and later_fail(r["evidence"]):
        record("nohup-exec-a-delay22", "SURVIVED", "PASS then evidence FAIL")
    elif r["last"] == "C1-C7: FAIL.":
        record("nohup-exec-a-delay22", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record("nohup-exec-a-delay22", "SURVIVED", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="inherited-fd-open")
    if r["last"] == "C1-C7: FAIL.":
        record("inherited-fd-open", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record("inherited-fd-open", "SURVIVED", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="inherited-fd-reopen22", linger=8)
    if r["last"] == "C1-C7: PASS." and later_fail(r["evidence"]):
        record("inherited-fd-reopen22", "SURVIVED", "PASS then write via reopened path")
    elif r["last"] == "C1-C7: FAIL.":
        record("inherited-fd-reopen22", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record("inherited-fd-reopen22", "SURVIVED", f"last={r['last']!r}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    at_path = shutil.which("at")
    launchctl = shutil.which("launchctl")
    record(
        "launchd-at-cron",
        "SURVIVED",
        "no at/launchctl on this host; same hole as exec-a-delay22 "
        f"(at={at_path} launchctl={launchctl})",
    )

    r = run_block_custom(block, kind="hardlink-quiet")
    if r["last"] == "C1-C7: FAIL.":
        record("hardlink-quiet", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record("hardlink-quiet", "SURVIVED", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="hardlink-delay22", linger=8)
    if r["last"] == "C1-C7: PASS." and later_fail(r["evidence"]):
        record("hardlink-delay22", "SURVIVED", "PASS; later write through other hard-link name")
    elif r["last"] == "C1-C7: FAIL.":
        record("hardlink-delay22", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record("hardlink-delay22", "SURVIVED", f"last={r['last']!r}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="toctou-snap")
    if r["last"] == "C1-C7: FAIL.":
        record("toctou-snap", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    elif r["last"] == "C1-C7: PASS.":
        record("toctou-snap", "SURVIVED", "PASS scored snap while live moved")
    else:
        record("toctou-snap", "SURVIVED", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="summary-rewrite", linger=3)
    last_now = r["summary_text"].splitlines()[-1] if r["summary_text"] else ""
    if last_now == "C1-C7: PASS." and later_fail(r["evidence"]):
        record("summary-rewrite", "SURVIVED", "FAIL journey; summary.txt rewritten to PASS after score")
    elif r["last"] == "C1-C7: FAIL." and last_now == "C1-C7: FAIL.":
        record("summary-rewrite", "CAUGHT", "summary stayed FAIL")
    else:
        record(
            "summary-rewrite",
            "SURVIVED" if last_now == "C1-C7: PASS." else "CAUGHT",
            f"paste_last={r['last']!r} file_last={last_now!r}",
        )
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="hardlink-summary", linger=3)
    last_now = r["summary_text"].splitlines()[-1] if r["summary_text"] else ""
    if last_now == "C1-C7: PASS." and later_fail(r["evidence"]):
        record("hardlink-summary", "SURVIVED", "FAIL journey; summary rewritten via outside hard link")
    elif r["last"] == "C1-C7: FAIL." and last_now == "C1-C7: FAIL.":
        record("hardlink-summary", "CAUGHT", "summary stayed FAIL")
    else:
        record(
            "hardlink-summary",
            "SURVIVED" if last_now == "C1-C7: PASS." else "CAUGHT",
            f"paste_last={r['last']!r} file_last={last_now!r}",
        )
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="combining-row")
    if r["last"] == "C1-C7: PASS.":
        record("combining-row", "SURVIVED", "combining acute in a row name still PASS")
    else:
        record("combining-row", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="zwsp-row")
    if r["last"] == "C1-C7: PASS.":
        record("zwsp-row", "SURVIVED", "zero-width in a row name still PASS")
    else:
        record("zwsp-row", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="nul-after-pass")
    if r["last"] == "C1-C7: PASS.":
        record("nul-after-pass", "SURVIVED", "NUL after PASS still scores PASS (startswith)")
    else:
        record("nul-after-pass", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(
        block,
        kind="mtime-preserve",
        fake_home=True,
        existing_elastos=True,
    )
    if r["last"] == "C1-C7: PASS." and r["home_after"] == "plante\n":
        record(
            "mtime-preserve",
            "SURVIVED",
            "PASS after same-size overwrite of ~/.elastos/pre-existing with mtime restored",
        )
    elif r["last"] == "C1-C7: FAIL.":
        record("mtime-preserve", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record(
            "mtime-preserve",
            "SURVIVED" if r["last"] == "C1-C7: PASS." else "CAUGHT",
            f"last={r['last']!r} home_after={r['home_after']!r}",
        )
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = d.run_block(block, kind="home-redirect", shim=True, fake_home=True)
    if r["last"] == "C1-C7: FAIL.":
        record("home-redirect-replay", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record("home-redirect-replay", "SURVIVED", f"last={r['last']!r}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = d.run_block(block, kind="stale-summary", shim=True, stale_summary=True)
    if r["last"] == "C1-C7: NOT RUN.":
        record("stale-summary-replay", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record("stale-summary-replay", "SURVIVED", f"last={r['last']!r}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="mds-reader")
    if r["last"] == "C1-C7: FAIL.":
        record(
            "mds-reader",
            "SURVIVED",
            f"false FAIL: read-only fd on evidence.txt last={r['last']!r} reason={r['reason']}",
        )
    elif r["last"] == "C1-C7: PASS.":
        record("mds-reader", "CAUGHT", "read-only indexer did not fail the booking")
    else:
        record("mds-reader", "SURVIVED", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    hang_tmp = Path(tempfile.mkdtemp(prefix="c17-r3-hang-"))
    try:
        shim_dir = hang_tmp / "shims"
        d.write_macos_shims(shim_dir)
        work = hang_tmp / "work"
        summary = hang_tmp / "summary.txt"
        env = os.environ.copy()
        env.pop("CARGO_TARGET_DIR", None)
        env["PATH"] = str(shim_dir) + ":" + env.get("PATH", "")
        env["C17_WORKDIR"] = str(work)
        env["C17_SUMMARY"] = str(summary)
        env["C17_CLEAN"] = "0"
        d.write_run_sh = write_custom_run_sh  # type: ignore[assignment]
        remote = d.write_fixture(hang_tmp, "happy-probe", include_pin=True)
        d.write_run_sh = _ORIG_WRITE  # type: ignore[assignment]
        env["C17_REMOTE"] = str(remote)
        env["C17_BRANCH"] = d.BRANCH
        script = hang_tmp / "block.sh"
        script.write_bytes(block)
        script.chmod(0o700)
        decoy = subprocess.Popen(
            [sys.executable, "-I", "-c", f"import time; time.sleep(120)  # {work}"],
        )
        try:
            done = subprocess.run(
                ["zsh", "--no-rcs", str(script)],
                cwd=hang_tmp,
                env=env,
                text=True,
                capture_output=True,
                timeout=25,
            )
            last = ""
            if summary.is_file():
                lines = summary.read_text(encoding="utf-8").splitlines()
                last = lines[-1] if lines else ""
            if last == "C1-C7: PASS.":
                record("argv-abs-hang", "CAUGHT", "absolute workdir in an unrelated argv did not block PASS")
            else:
                record("argv-abs-hang", "SURVIVED", f"last={last!r} exit={done.returncode}")
        except subprocess.TimeoutExpired:
            record(
                "argv-abs-hang",
                "SURVIVED",
                "unrelated process whose argv contains the absolute workdir hung the waiter",
            )
        finally:
            decoy.terminate()
            try:
                decoy.wait(timeout=2)
            except Exception:
                decoy.kill()
    finally:
        d.write_run_sh = _ORIG_WRITE  # type: ignore[assignment]
        shutil.rmtree(hang_tmp, ignore_errors=True)

    decoy = subprocess.Popen(
        [sys.executable, "-I", "-c", "import time; time.sleep(120)  # lab/c1-c7-mac-runbook"],
    )
    r = run_block_custom(block, kind="happy-probe", timeout=40, pre_proc=decoy)
    if r["timeout"] or r["exit"] == 124:
        record("argv-bare", "SURVIVED", "bare lab/c1-c7-mac-runbook in argv hung the waiter")
    elif r["last"] == "C1-C7: PASS.":
        record("argv-bare", "CAUGHT", "bare lane string is not a needle; needles are absolute")
    elif r["last"] == "C1-C7: FAIL.":
        record("argv-bare", "SURVIVED", f"false FAIL last={r['last']!r} reason={r['reason']}")
    else:
        record("argv-bare", "SURVIVED", f"last={r['last']!r} timeout={r['timeout']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="probe-stale-allowed")
    if r["last"] == "C1-C7: PASS." and r["probe"] == "SBPL_PROBE: ALLOWED":
        record(
            "probe-stale-allowed",
            "SURVIVED",
            "PASS booked a committed ALLOWED probe that run.sh never measured",
        )
    elif r["probe"] == "SBPL_PROBE: NOT RUN" and r["last"] == "C1-C7: PASS.":
        record("probe-stale-allowed", "CAUGHT", "stale committed probe was not trusted as ALLOWED")
    else:
        record(
            "probe-stale-allowed",
            "SURVIVED" if r["probe"] == "SBPL_PROBE: ALLOWED" else "CAUGHT",
            f"last={r['last']!r} probe={r['probe']!r}",
        )
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="probe-delay22", linger=8)
    later = r["probe_later"].strip()
    if r["last"] == "C1-C7: PASS." and later == "SBPL_PROBE: ALLOWED" and r["probe"] != "SBPL_PROBE: ALLOWED":
        record("probe-delay22", "SURVIVED", f"booked {r['probe']!r}; live probe later {later!r}")
    elif r["last"] == "C1-C7: FAIL.":
        record("probe-delay22", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    elif r["last"] == "C1-C7: PASS.":
        record(
            "probe-delay22",
            "SURVIVED",
            f"PASS; booked probe={r['probe']!r} later={later!r}",
        )
    else:
        record("probe-delay22", "SURVIVED", f"last={r['last']!r}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="happy-probe", hide="python3", timeout=30)
    if r["last"] == "C1-C7: NOT RUN." and "python3" in (r["reason"] + r["output"]):
        record("missing-python3", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    elif r["last"] == "C1-C7: PASS.":
        record("missing-python3", "SURVIVED", "PASS without python3")
    else:
        record("missing-python3", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    hits = bash4_hits(text)
    bash_n = subprocess.run(["bash", "-n", "-c", text], capture_output=True, text=True)
    zsh_n = subprocess.run(["zsh", "-n", "--no-rcs", "-c", text], capture_output=True, text=True)
    if bash_n.returncode == 0 and zsh_n.returncode == 0 and not hits:
        record("bash32-syntax", "CAUGHT", "bash -n and zsh -n rc 0; no bash-4-only flags")
    else:
        record(
            "bash32-syntax",
            "SURVIVED",
            f"bash -n rc={bash_n.returncode} zsh -n rc={zsh_n.returncode} hits={hits}",
        )

    pipe_zsh = subprocess.run(
        ["zsh", "--no-rcs", "-c", "set -euo pipefail; false | true; printf AFTER\n"],
        capture_output=True,
        text=True,
    )
    pipe_bash = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", "set -euo pipefail; false | true; printf AFTER\n"],
        capture_output=True,
        text=True,
    )
    if pipe_zsh.returncode != 0 and pipe_bash.returncode != 0 and "AFTER" not in (pipe_zsh.stdout + pipe_bash.stdout):
        record("set-e-pipefail", "CAUGHT", "false|true aborts under pipefail in zsh and bash")
    else:
        record(
            "set-e-pipefail",
            "SURVIVED",
            f"zsh rc={pipe_zsh.returncode} bash rc={pipe_bash.returncode}",
        )

    bash_tmp = Path(tempfile.mkdtemp(prefix="c17-r3-bash-"))
    try:
        shim_dir = bash_tmp / "shims"
        d.write_macos_shims(shim_dir)
        work = bash_tmp / "work"
        summary = bash_tmp / "summary.txt"
        env = os.environ.copy()
        env.pop("CARGO_TARGET_DIR", None)
        env["PATH"] = str(shim_dir) + ":" + env.get("PATH", "")
        env["C17_WORKDIR"] = str(work)
        env["C17_SUMMARY"] = str(summary)
        env["C17_CLEAN"] = "0"
        d.write_run_sh = write_custom_run_sh  # type: ignore[assignment]
        remote = d.write_fixture(bash_tmp, "happy-probe", include_pin=True)
        d.write_run_sh = _ORIG_WRITE  # type: ignore[assignment]
        env["C17_REMOTE"] = str(remote)
        env["C17_BRANCH"] = d.BRANCH
        script = bash_tmp / "block.sh"
        script.write_bytes(block)
        script.chmod(0o700)
        done = subprocess.run(
            ["bash", "--noprofile", "--norc", str(script)],
            cwd=bash_tmp,
            env=env,
            text=True,
            capture_output=True,
            timeout=90,
        )
        last = ""
        if summary.is_file():
            lines = summary.read_text(encoding="utf-8").splitlines()
            last = lines[-1] if lines else ""
        if last == "C1-C7: PASS." and done.returncode == 0:
            record("bash-happy", "CAUGHT", "bash 5.2 happy path PASS (no bash 3.2 on this host)")
        else:
            record("bash-happy", "SURVIVED", f"last={last!r} exit={done.returncode}")
    except subprocess.TimeoutExpired:
        record("bash-happy", "SURVIVED", "TIMEOUT under bash")
    finally:
        d.write_run_sh = _ORIG_WRITE  # type: ignore[assignment]
        shutil.rmtree(bash_tmp, ignore_errors=True)

    if "readlink -f" not in text and "sed -i" not in text and "stat -c" not in text:
        record("bsd-flags", "CAUGHT", "no sed -i, readlink -f, or GNU stat -c")
    else:
        record("bsd-flags", "SURVIVED", "GNU-only flag present")

    sudo_hit = ("sudo" in text.split() or "sudo" in run_text.split())
    rm_rf = "rm -rf -- \"$c17_workdir\"" in text and text.count("rm -rf") == 1
    rustup_net = "rustup toolchain install" in text
    no_bound = "7200" in text and "sleep 15" in text
    if not sudo_hit and rm_rf:
        record("safety-sudo-rm", "CAUGHT", "no sudo; rm -rf only the temp workdir when C17_CLEAN=1")
    else:
        record("safety-sudo-rm", "SURVIVED", f"sudo={sudo_hit} rm_rf_ok={rm_rf}")
    if rustup_net:
        record(
            "safety-network",
            "SURVIVED",
            "paste can rustup toolchain install 1.91.0 and git fetch the pin; not clone-only",
        )
    else:
        record("safety-network", "CAUGHT", "no rustup install")
    if no_bound:
        record(
            "safety-runtime-bound",
            "SURVIVED",
            "wait is 7200s; lsof, rustup install, and git clone have no timeout; no total bound",
        )

    print("PLANTS: done")
    survived = [name for name, result, _ in rows if result == "SURVIVED"]
    print(f"SURVIVED {len(survived)}: {', '.join(survived)}")
    for name, result, detail in rows:
        if result == "SURVIVED":
            print(f"  SURVIVED {name}: {detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
