#!/usr/bin/env python3
"""r3 plants against the #416 A2 Mac runbook fence at a1971a3c.

Imports the author's dryrun helpers. Does not edit #416 files.
A2 on a Mac stays NOT RUN ON MAC.
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
    os.environ.get("A2_RUNBOOK_DIR", "/workspace/lab/a2-mac-runbook")
).resolve()
sys.path.insert(0, str(RUNBOOK_DIR))
import dryrun as d  # noqa: E402

d.REPO_ROOT = Path(os.environ.get("A2_REPO_ROOT", "/workspace")).resolve()

PIN_PARENT = "a9e0e28048ee42fd42f6c017780dc8bf9aa22b05"
REVIEWED = "a1971a3cdd3cd20145174bad8ada9c753af3456b"
WANT_SHA = "d19219ff8b076f12aed711ca048130219c2b5e4b0646559eeb4f10569361d517"
WANT_BYTES = 22309

HAPPY = d.evidence_text("happy")
FAIL = d.evidence_text("fail")
_ORIG_WRITE = d.write_run_sh


def header() -> str:
    return (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "lane=$(cd -- \"$(dirname -- \"$0\")\" && pwd -P)\n"
        "root=$(cd -- \"$lane/../..\" && pwd -P)\n"
    )


def write_custom_run_sh(run: Path, kind: str) -> None:
    if kind == "exec-a-delay22":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
            + "plant_dir=/tmp/r3-a2-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "ev=$(cd -- \"$lane\" && pwd -P)/evidence.txt\n"
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
            + "plant_dir=/tmp/r3-a2-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "ev=$(cd -- \"$lane\" && pwd -P)/evidence.txt\n"
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
            + "plant_dir=/tmp/r3-a2-plant-$$\n"
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
            + "plant_dir=/tmp/r3-a2-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "ev=$(cd -- \"$lane\" && pwd -P)/evidence.txt\n"
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
            + "outside=/tmp/r3-a2-hardlink-$$\n"
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
            + "plant_dir=/tmp/r3-a2-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "outside=$plant_dir/linked-evidence\n"
            + "ln -- \"$lane/evidence.txt\" \"$outside\"\n"
            + "fail=$plant_dir/fail.txt\n"
            + f"cat > \"$fail\" <<'EOF'\n{FAIL}EOF\n"
            + "cat > \"$plant_dir/rewriter.py\" <<PY\n"
            + "import pathlib, time\n"
            + "time.sleep(22)\n"
            + "pathlib.Path(r'''$outside''').write_bytes(pathlib.Path(r'''$fail''').read_bytes())\n"
            + "PY\n"
            + "python3 -I -c 'import os,sys; os.setsid(); "
            + "os.execv(sys.executable, [\"mds\", \"-I\", sys.argv[1]])' "
            + "\"$plant_dir/rewriter.py\" &\n"
        )
    elif kind == "toctou-snap":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
            + "work=$(cd -- \"$lane/../..\" && pwd -P)/..\n"
            + "work=$(cd -- \"$work\" && pwd -P)\n"
            + "plant_dir=/tmp/r3-a2-plant-$$\n"
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
            + "        pathlib.Path(r'''$ev''').write_bytes(pathlib.Path(r'''$fail''').read_bytes())\n"
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
            + "plant_dir=/tmp/r3-a2-plant-$$\n"
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
    elif kind == "zwsp-row":
        extra = "W\u200bRITE: FAIL — zero-width planted\n"
        body = header() + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}{extra}EOF\n"
    elif kind == "fullwidth-row":
        extra = "ＷＲＩＴＥ: FAIL — fullwidth planted\n"
        body = header() + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}{extra}EOF\n"
    elif kind == "trailing-ws-pass":
        text = HAPPY.replace("WRITE: PASS —", "WRITE: PASS  —", 1)
        # trailing whitespace on the WRITE line
        lines = HAPPY.splitlines(keepends=True)
        out = []
        for line in lines:
            if line.startswith("WRITE: PASS"):
                line = line.rstrip("\n") + "   \n"
            out.append(line)
        body = header() + "cat > \"$lane/evidence.txt\" <<'EOF'\n" + "".join(out) + "EOF\n"
    elif kind == "nul-row":
        body = (
            header()
            + "python3 -I -c '\n"
            + "from pathlib import Path\n"
            + "p = Path(\"lab/a2-e2e-resume/evidence.txt\")\n"
            + f"raw = {HAPPY.encode('utf-8')!r}.replace(b\"WRITE: PASS\", b\"WRITE\\x00: PASS\", 1)\n"
            + "p.write_bytes(raw)\n"
            + "'\n"
        )
    elif kind == "case-dup":
        extra = "write: FAIL — planted lowercase row\nWRITE: PASS — duplicate mixed case\n"
        # keep original WRITE PASS plus lowercase fail
        extra = "write: FAIL — planted lowercase row\n"
        body = header() + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}{extra}EOF\n"
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
        )
    elif kind == "mds-reader":
        body = (
            header()
            + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
            + "plant_dir=/tmp/r3-a2-plant-$$\n"
            + "mkdir -p -- \"$plant_dir\"\n"
            + "target=$(cd -- \"$lane\" && pwd -P)/harness.py\n"
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
    elif kind == "emdash-happy":
        body = header() + f"cat > \"$lane/evidence.txt\" <<'EOF'\n{HAPPY}EOF\n"
    else:
        _ORIG_WRITE(run, kind)
        return
    run.write_text(body, encoding="utf-8")
    run.chmod(0o755)


def graft_stale_parent(repo: Path) -> None:
    fetched = subprocess.run(
        ["git", "fetch", "--", str(d.REPO_ROOT), PIN_PARENT],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    if fetched.returncode != 0:
        raise SystemExit(f"stale parent fetch failed: {fetched.stderr}")
    tree = subprocess.run(
        ["git", "write-tree"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    commit = subprocess.run(
        ["git", *d.GIT_IDENT, "commit-tree", tree, "-p", PIN_PARENT, "-m", "stale parent"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "reset", "--hard", commit], cwd=repo, check=True, capture_output=True)


def run_block_custom(
    block: bytes,
    *,
    kind: str,
    fake_home: bool = False,
    existing_elastos: bool = False,
    include_pin: bool = True,
    stale_parent: bool = False,
    timeout: int = 90,
    extra_env: dict | None = None,
    pre_proc: subprocess.Popen | None = None,
    linger: float = 0,
) -> dict:
    orig = d.write_run_sh
    orig_graft = d.graft_pin

    def graft_maybe(repo: Path, graft_kind: str) -> None:
        if stale_parent:
            graft_stale_parent(repo)
        else:
            orig_graft(repo, graft_kind)

    d.write_run_sh = write_custom_run_sh  # type: ignore[assignment]
    d.graft_pin = graft_maybe  # type: ignore[assignment]
    tmp = Path(tempfile.mkdtemp(prefix=f"a2-r3-{kind}-"))
    started = time.time()
    login_elastos = d.login_home_path() / ".elastos"
    login_existed = login_elastos.exists()
    try:
        shim_dir = tmp / "shims"
        d.write_macos_shims(shim_dir)
        work = tmp / "work"
        summary = tmp / "summary.txt"
        env = os.environ.copy()
        env.pop("CARGO_TARGET_DIR", None)
        env["PATH"] = str(shim_dir) + ":" + env.get("PATH", "")
        env["A2_WORKDIR"] = str(work)
        env["A2_SUMMARY"] = str(summary)
        env["A2_CLEAN"] = "0"
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
        remote = d.write_fixture(tmp, kind, include_pin=include_pin)
        env["A2_REMOTE"] = str(remote)
        env["A2_BRANCH"] = d.BRANCH
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
        if linger > 0:
            time.sleep(linger)
        output = (done.stdout or "") + (done.stderr or "")
        last = ""
        reason = ""
        summary_later = ""
        evidence_later = ""
        if summary.is_file():
            lines = summary.read_text(encoding="utf-8", errors="replace").splitlines()
            if lines:
                last = lines[-1]
            for line in lines:
                if line.startswith("reason: "):
                    reason = line[len("reason: ") :]
            summary_later = summary.read_text(encoding="utf-8", errors="replace")
        ev = work / "src" / "lab" / "a2-e2e-resume" / "evidence.txt"
        if ev.is_file():
            evidence_later = ev.read_text(encoding="utf-8", errors="replace")
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
            "summary_text": summary_later,
            "evidence": evidence_later,
            "home_after": home_after,
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
            "tmp": str(tmp),
            "timeout": True,
        }
    finally:
        d.write_run_sh = orig  # type: ignore[assignment]
        d.graft_pin = orig_graft  # type: ignore[assignment]
        if pre_proc is not None:
            pre_proc.terminate()
            try:
                pre_proc.wait(timeout=2)
            except Exception:
                pre_proc.kill()
        if kind == "home-redirect" and not login_existed and login_elastos.exists():
            shutil.rmtree(login_elastos, ignore_errors=True)


def bash4_hits(text: str) -> list[str]:
    hits = []
    for needle, label in (
        ("mapfile ", "mapfile"),
        ("readarray ", "readarray"),
        ("${!", "nameref/indirection"),
        ("${var,,}", "case transform"),
        ("|&", "|&"),
        ("&>", "&>"),
        ("readlink -f", "readlink -f"),
        ("sed -i", "sed -i"),
        ("stat -c", "stat -c"),
        ("stat --format", "stat --format"),
    ):
        if needle in text and needle not in ("${!",):
            hits.append(label)
    if "declare -n" in text or "nameref" in text:
        hits.append("nameref")
    if "|&" in text:
        hits.append("|&")
    return sorted(set(hits))


def main() -> int:
    if not (RUNBOOK_DIR / "RUNBOOK.md").is_file():
        sys.stderr.write(f"missing runbook at {RUNBOOK_DIR}\n")
        return 2
    block = d.extract_block(RUNBOOK_DIR / "RUNBOOK.md")
    digest, size = d.block_meta(block)
    print(f"REVIEWED {REVIEWED}")
    print(f"BLOCK sha256:{digest} bytes:{size}")
    if digest != WANT_SHA or size != WANT_BYTES:
        print("fence meta MISSED")
        return 1
    print("fence meta CAUGHT")
    text = block.decode("utf-8")

    rows = []

    def record(name: str, result: str, detail: str) -> None:
        rows.append((name, result, detail))
        print(f"{name}: {result} — {detail}")

    # 1. exec -a + setsid, delay 22s (beyond quiet period)
    r = run_block_custom(block, kind="exec-a-delay22", linger=8)
    booked = r["last"] == "A2: PASS."
    later_fail = "STALE: FAIL" in r["evidence"]
    if booked and later_fail:
        record(
            "exec-a-delay22",
            "SURVIVED",
            f"last={r['last']!r} then evidence became FAIL after {r['seconds']}s",
        )
    elif booked:
        record("exec-a-delay22", "SURVIVED", f"last={r['last']!r} evidence stayed PASS")
    else:
        record("exec-a-delay22", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="nohup-exec-a-delay22", linger=8)
    booked = r["last"] == "A2: PASS."
    later_fail = "STALE: FAIL" in r["evidence"]
    if booked and later_fail:
        record(
            "nohup-exec-a-delay22",
            "SURVIVED",
            f"last={r['last']!r} then evidence became FAIL",
        )
    elif r["last"] == "A2: FAIL.":
        record("nohup-exec-a-delay22", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record("nohup-exec-a-delay22", "SURVIVED", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="inherited-fd-open")
    if r["last"] == "A2: FAIL.":
        record("inherited-fd-open", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record("inherited-fd-open", "SURVIVED", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="inherited-fd-reopen22", linger=8)
    booked = r["last"] == "A2: PASS."
    later_fail = "STALE: FAIL" in r["evidence"]
    if booked and later_fail:
        record("inherited-fd-reopen22", "SURVIVED", "PASS then write via reopened path")
    elif r["last"] == "A2: FAIL.":
        record("inherited-fd-reopen22", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record("inherited-fd-reopen22", "SURVIVED", f"last={r['last']!r}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    # scheduled-write stand-in: at/launchd absent; delay22 is the stand-in
    at_path = shutil.which("at")
    launchctl = shutil.which("launchctl")
    record(
        "launchd-at-cron",
        "SURVIVED" if True else "CAUGHT",
        "no at/launchctl on this host; same hole as exec-a-delay22 "
        f"(at={at_path} launchctl={launchctl})",
    )

    r = run_block_custom(block, kind="hardlink-quiet")
    if r["last"] == "A2: FAIL.":
        record("hardlink-quiet", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record("hardlink-quiet", "SURVIVED", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="hardlink-delay22", linger=8)
    booked = r["last"] == "A2: PASS."
    later_fail = "STALE: FAIL" in r["evidence"]
    if booked and later_fail:
        record("hardlink-delay22", "SURVIVED", "PASS; later write through other hard-link name")
    elif r["last"] == "A2: FAIL.":
        record("hardlink-delay22", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record("hardlink-delay22", "SURVIVED", f"last={r['last']!r}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="toctou-snap")
    if r["last"] == "A2: FAIL.":
        record("toctou-snap", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    elif r["last"] == "A2: PASS.":
        record("toctou-snap", "SURVIVED", f"last={r['last']!r} scored snap while live moved")
    else:
        record("toctou-snap", "SURVIVED", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="summary-rewrite", linger=3)
    last_now = ""
    if r["summary_text"]:
        lines = r["summary_text"].splitlines()
        last_now = lines[-1] if lines else ""
    if last_now == "A2: PASS." and "STALE: FAIL" in r["evidence"]:
        record("summary-rewrite", "SURVIVED", "FAIL journey; summary.txt rewritten to PASS after score")
    elif r["last"] == "A2: FAIL." and last_now == "A2: FAIL.":
        record("summary-rewrite", "CAUGHT", "summary stayed FAIL")
    else:
        record(
            "summary-rewrite",
            "SURVIVED" if last_now == "A2: PASS." else "CAUGHT",
            f"paste_last={r['last']!r} file_last={last_now!r}",
        )
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="zwsp-row")
    if r["last"] == "A2: PASS.":
        record("zwsp-row", "SURVIVED", "zero-width in a row name still PASS")
    else:
        record("zwsp-row", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="fullwidth-row")
    if r["last"] == "A2: PASS.":
        record("fullwidth-row", "SURVIVED", "fullwidth row name still PASS")
    else:
        record("fullwidth-row", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="trailing-ws-pass")
    if r["last"] == "A2: PASS.":
        record("trailing-ws-pass", "CAUGHT", "trailing spaces after PASS still score PASS")
    else:
        record("trailing-ws-pass", "SURVIVED", f"false FAIL last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="nul-row")
    if r["last"] == "A2: PASS.":
        record("nul-row", "SURVIVED", "NUL in WRITE name still PASS")
    else:
        record("nul-row", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="case-dup")
    if r["last"] == "A2: PASS.":
        record(
            "case-dup",
            "CAUGHT",
            "lowercase write: FAIL is not a scored row; WRITE stayed PASS",
        )
    else:
        record("case-dup", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(block, kind="stale-parent", stale_parent=True, timeout=40)
    if r["last"] == "A2: NOT RUN." and "9e7a85d6" in (r["reason"] + r["output"]):
        record("stale-pin-ancestor", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    elif r["last"] == "A2: PASS.":
        record("stale-pin-ancestor", "SURVIVED", "PASS without the A2 pin as ancestor")
    else:
        record("stale-pin-ancestor", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    r = run_block_custom(
        block,
        kind="mtime-preserve",
        fake_home=True,
        existing_elastos=True,
    )
    if r["last"] == "A2: PASS." and r["home_after"] == "plante\n":
        record(
            "mtime-preserve",
            "SURVIVED",
            "PASS after same-size overwrite of ~/.elastos/pre-existing with mtime restored",
        )
    elif r["last"] == "A2: FAIL.":
        record("mtime-preserve", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record(
            "mtime-preserve",
            "SURVIVED" if r["last"] == "A2: PASS." else "CAUGHT",
            f"last={r['last']!r} home_after={r['home_after']!r} reason={r['reason']}",
        )
    shutil.rmtree(r["tmp"], ignore_errors=True)

    # HOME vs login already in author dryrun; replay quickly
    r = d.run_block(block, kind="home-redirect", shim=True, fake_home=True)
    if r["last"] == "A2: FAIL.":
        record("home-redirect-replay", "CAUGHT", f"last={r['last']!r} reason={r['reason']}")
    else:
        record("home-redirect-replay", "SURVIVED", f"last={r['last']!r}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    # false FAIL: mds-like reader
    r = run_block_custom(block, kind="mds-reader")
    if r["last"] == "A2: FAIL.":
        record(
            "mds-reader",
            "SURVIVED",
            f"false FAIL: read-only fd on harness.py last={r['last']!r} reason={r['reason']}",
        )
    elif r["last"] == "A2: PASS.":
        record("mds-reader", "CAUGHT", "read-only indexer did not fail the booking")
    else:
        record("mds-reader", "SURVIVED", f"last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    # false FAIL / hang: unrelated argv mentions lab/a2-e2e-resume
    decoy = subprocess.Popen(
        [sys.executable, "-I", "-c", "import time; time.sleep(120)  # lab/a2-e2e-resume"],
    )
    r = run_block_custom(block, kind="emdash-happy", timeout=25, pre_proc=decoy)
    if r["timeout"] or r["exit"] == 124:
        record(
            "argv-hang",
            "SURVIVED",
            "unrelated process whose argv contains lab/a2-e2e-resume hung the waiter",
        )
    elif r["last"] == "A2: FAIL.":
        record("argv-hang", "SURVIVED", f"false FAIL last={r['last']!r} reason={r['reason']}")
    elif r["last"] == "A2: PASS.":
        record("argv-hang", "CAUGHT", "unrelated argv did not block PASS")
    else:
        record("argv-hang", "SURVIVED", f"last={r['last']!r} timeout={r['timeout']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    # em-dash happy (false FAIL check)
    r = run_block_custom(block, kind="emdash-happy")
    if r["last"] == "A2: PASS.":
        record("emdash-happy", "CAUGHT", "em-dash in row details still PASS")
    else:
        record("emdash-happy", "SURVIVED", f"false FAIL last={r['last']!r} reason={r['reason']}")
    shutil.rmtree(r["tmp"], ignore_errors=True)

    # bash 3.2 / zsh: syntax and happy path under bash
    hits = bash4_hits(text)
    bash_n = subprocess.run(["bash", "-n", "-c", text], capture_output=True, text=True)
    zsh_n = subprocess.run(["zsh", "-n", "--no-rcs", "-c", text], capture_output=True, text=True)
    r_bash = None
    # run happy path under bash by temporarily patching dryrun shell? reuse run_block but zsh.
    # Isolated: write script and run with bash.
    tmp = Path(tempfile.mkdtemp(prefix="a2-r3-bash-"))
    try:
        # reuse author's run_block (zsh). Separate bash invocation of happy via d.run_block
        # after swapping the shell list is messy; run fence under bash with same env by
        # copying run_block and replacing zsh.
        orig_run = subprocess.run
        # just run author's happy under zsh already proven; here bash -n + feature scan
        record(
            "bash32-syntax",
            "CAUGHT" if bash_n.returncode == 0 and not hits else "SURVIVED",
            f"bash -n rc={bash_n.returncode} zsh -n rc={zsh_n.returncode} bash4-hits={hits or 'none'}",
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    r = d.run_block(block, kind="happy", shim=True)
    # force bash instead: already have zsh happy from author. Run a bash happy ourselves.
    shutil.rmtree(r["tmp"], ignore_errors=True)
    # bash happy
    orig_run_block = d.run_block

    def run_block_bash(*args, **kwargs):
        raise RuntimeError("unused")

    tmp = Path(tempfile.mkdtemp(prefix="a2-r3-bashhappy-"))
    try:
        shim_dir = tmp / "shims"
        d.write_macos_shims(shim_dir)
        work = tmp / "work"
        summary = tmp / "summary.txt"
        env = os.environ.copy()
        env.pop("CARGO_TARGET_DIR", None)
        env["PATH"] = str(shim_dir) + ":" + env.get("PATH", "")
        env["A2_WORKDIR"] = str(work)
        env["A2_SUMMARY"] = str(summary)
        env["A2_CLEAN"] = "0"
        remote = d.write_fixture(tmp, "happy", include_pin=True)
        env["A2_REMOTE"] = str(remote)
        env["A2_BRANCH"] = d.BRANCH
        script = tmp / "block.sh"
        script.write_bytes(block)
        script.chmod(0o700)
        done = subprocess.run(
            ["bash", "--noprofile", "--norc", str(script)],
            cwd=tmp,
            env=env,
            text=True,
            capture_output=True,
            timeout=90,
        )
        last = ""
        if summary.is_file():
            lines = summary.read_text(encoding="utf-8").splitlines()
            last = lines[-1] if lines else ""
        if last == "A2: PASS." and done.returncode == 0:
            record("bash-happy", "CAUGHT", "bash 5.2 happy path PASS (no bash 3.2 on this host)")
        else:
            record("bash-happy", "SURVIVED", f"last={last!r} exit={done.returncode}")
    except subprocess.TimeoutExpired:
        record("bash-happy", "SURVIVED", "TIMEOUT under bash")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # BSD flags already static; lsof-missing fail-closed
    if "readlink -f" not in text and "sed -i" not in text and "stat -c" not in text:
        record("bsd-flags", "CAUGHT", "no sed -i, readlink -f, or GNU stat -c")
    else:
        record("bsd-flags", "SURVIVED", "GNU-only flag present")

    print("PLANTS: done")
    survived = [name for name, result, _ in rows if result == "SURVIVED"]
    print(f"SURVIVED {len(survived)}: {', '.join(survived)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
