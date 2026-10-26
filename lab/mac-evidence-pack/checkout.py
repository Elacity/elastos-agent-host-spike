"""Fetch a draft-PR commit into the work dir. Network is git fetch of this repo only."""

from __future__ import annotations

import subprocess
from pathlib import Path

from catalog import REPO
from paths import PathRefusal, is_inside, require_inside, resolve

SAFE_ORIGIN = REPO


class CheckoutError(Exception):
    """Clone, fetch, or worktree failed."""


def _run(argv: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def sanitize_origin(url: str) -> str:
    """Drop userinfo so a token in the source remote is not copied into the work dir."""
    if url.startswith("https://") and "@github.com/" in url:
        return "https://github.com/" + url.split("@github.com/", 1)[1]
    if url.startswith("http://") and "@github.com/" in url:
        return "https://github.com/" + url.split("@github.com/", 1)[1]
    return url


def has_commit(repo: Path, commit: str) -> bool:
    result = _run(["git", "-C", str(repo), "cat-file", "-e", f"{commit}^{{commit}}"])
    return result.returncode == 0


def recorded_commit(tree: Path) -> str:
    result = _run(["git", "-C", str(tree), "rev-parse", "HEAD"])
    if result.returncode != 0:
        raise CheckoutError(result.stderr.strip() or "rev-parse failed")
    return result.stdout.strip()


def ensure_mirror(work: Path, source_repo: Path) -> Path:
    """Local clone of this repo under the work dir. Fetch origin only when a pin is missing."""
    dest = require_inside(work / "repo", work, "repo clone")
    if not dest.exists():
        result = _run(
            [
                "git",
                "clone",
                "--local",
                "--no-hardlinks",
                str(resolve(source_repo)),
                str(dest),
            ]
        )
        if result.returncode != 0:
            raise CheckoutError(result.stderr.strip() or "git clone failed")
        origin = _run(["git", "-C", str(dest), "remote", "get-url", "origin"])
        if origin.returncode == 0:
            safe = sanitize_origin(origin.stdout.strip()) or SAFE_ORIGIN
            _run(["git", "-C", str(dest), "remote", "set-url", "origin", safe])
    return dest


def fetch_branch(repo: Path, work: Path, branch: str) -> None:
    require_inside(repo, work, "fetch repo")
    result = _run(["git", "-C", str(repo), "fetch", "--no-tags", "origin", branch])
    if result.returncode != 0:
        raise CheckoutError(
            result.stderr.strip() or f"git fetch origin {branch} failed"
        )


def checkout_commit(work: Path, source_repo: Path, branch: str, commit: str) -> Path:
    """Return the worktree path pinned at commit. Recorded HEAD must match."""
    if not is_inside(work, work):
        raise PathRefusal("work dir is not self-contained")
    repo = ensure_mirror(work, source_repo)
    if not has_commit(repo, commit):
        fetch_branch(repo, work, branch)
    if not has_commit(repo, commit):
        raise CheckoutError(
            f"commit {commit} is not in this repo after git fetch origin {branch}"
        )
    dest = require_inside(work / "checkouts" / commit[:12], work, "row checkout")
    if dest.exists():
        got = recorded_commit(dest)
        if got != commit:
            raise CheckoutError(
                f"checkout {dest} is {got}, expected {commit}"
            )
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    result = _run(
        [
            "git",
            "-C",
            str(repo),
            "worktree",
            "add",
            "--detach",
            str(dest),
            commit,
        ]
    )
    if result.returncode != 0:
        raise CheckoutError(result.stderr.strip() or "git worktree add failed")
    got = recorded_commit(dest)
    if got != commit:
        raise CheckoutError(f"worktree HEAD is {got}, expected {commit}")
    return dest
