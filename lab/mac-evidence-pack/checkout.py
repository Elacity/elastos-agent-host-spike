"""Pack-owned clone only. Changing git never runs in any other directory."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from paths import PathRefusal, is_inside, require_inside, resolve
from pins import (
    MARKER_TEXT,
    PACK_BRANCH,
    REMOTE,
    is_pack_owned,
    write_marker,
)

SAFE_ORIGIN = REMOTE

CHANGING_GIT = frozenset(
    {
        "add",
        "am",
        "branch",
        "checkout",
        "cherry-pick",
        "clean",
        "clone",
        "commit",
        "config",
        "fetch",
        "gc",
        "init",
        "merge",
        "mv",
        "pull",
        "rebase",
        "remote",
        "reset",
        "restore",
        "revert",
        "rm",
        "stash",
        "switch",
        "tag",
        "update-ref",
        "worktree",
    }
)


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


def enclosing_git(start: Path) -> Path | None:
    cursor = resolve(start)
    if cursor.is_file():
        cursor = cursor.parent
    for folder in (cursor, *cursor.parents):
        if (folder / ".git").exists():
            return folder
    return None


def _is_git_url(value: str) -> bool:
    return "://" in value or value.startswith("git@")


def _flag_takes_value(flag: str) -> bool:
    return flag in {
        "-C",
        "-c",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--config-env",
        "-o",
        "--origin",
        "-b",
        "--branch",
        "--reference",
        "--separate-git-dir",
        "--depth",
        "--shallow-since",
        "--shallow-exclude",
        "--jobs",
        "--recurse-submodules",
        "--filter",
    }


def parse_git_argv(
    argv: list[str], cwd: Path | None
) -> tuple[str | None, Path | None, Path | None]:
    """Return (subcommand, operate_on, local_source)."""
    if not argv or Path(argv[0]).name != "git":
        return None, cwd, None
    operate_on = resolve(cwd) if cwd is not None else None
    tokens = argv[1:]
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == "-C" and i + 1 < len(tokens):
            operate_on = resolve(Path(tokens[i + 1]))
            i += 2
            continue
        if token.startswith("-") and _flag_takes_value(token.split("=", 1)[0]):
            i += 1 if "=" in token else 2
            continue
        if token.startswith("-"):
            i += 1
            continue
        break
    if i >= len(tokens):
        return None, operate_on, None
    sub = tokens[i]
    rest = tokens[i + 1 :]
    local_source = None
    if sub == "clone":
        positionals: list[str] = []
        j = 0
        while j < len(rest):
            token = rest[j]
            if token.startswith("-") and _flag_takes_value(token.split("=", 1)[0]):
                j += 1 if "=" in token else 2
                continue
            if token.startswith("-"):
                j += 1
                continue
            positionals.append(token)
            j += 1
        if positionals:
            src = positionals[0]
            if not _is_git_url(src):
                local_source = resolve(Path(src))
            if len(positionals) > 1:
                operate_on = resolve(Path(positionals[1]))
    return sub, operate_on, local_source


def _refuse_foreign(path: Path, what: str) -> None:
    repo = enclosing_git(path)
    if repo is None:
        return
    if not is_pack_owned(repo):
        raise PathRefusal(
            f"FOREIGN_CLONE: refuses to operate inside existing non-pack clone ({repo}) [{what}]"
        )


def owned_git(argv: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run git. Changing commands are allowed only on a pack-owned clone."""
    sub, operate_on, local_source = parse_git_argv(argv, cwd)
    if local_source is not None:
        _refuse_foreign(local_source, f"git {sub or ''} source")
    if sub in CHANGING_GIT and operate_on is not None:
        if operate_on.exists():
            _refuse_foreign(operate_on, f"git {sub}")
    return _run(argv, cwd=cwd)


def has_commit(repo: Path, commit: str) -> bool:
    result = _run(["git", "-C", str(repo), "cat-file", "-e", f"{commit}^{{commit}}"])
    return result.returncode == 0


def recorded_commit(tree: Path) -> str:
    result = _run(["git", "-C", str(tree), "rev-parse", "HEAD"])
    if result.returncode != 0:
        raise CheckoutError(result.stderr.strip() or "rev-parse failed")
    return result.stdout.strip()


def ensure_owned_clone(
    dest: Path,
    *,
    remote: str = REMOTE,
    branch: str = PACK_BRANCH,
) -> Path:
    """Create or reuse the dedicated pack-owned clone. Refuse a foreign path."""
    dest = resolve(dest)
    if dest.exists():
        if is_pack_owned(dest) and (dest / ".git").exists():
            return dest
        raise PathRefusal(
            f"PACK_CLONE_FOREIGN: {dest} already holds something this pack did not create"
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    result = owned_git(
        [
            "git",
            "clone",
            "--branch",
            branch,
            "--single-branch",
            remote,
            str(dest),
        ]
    )
    if result.returncode != 0:
        if dest.exists() and not is_pack_owned(dest):
            shutil.rmtree(dest)
        raise CheckoutError(result.stderr.strip() or "git clone failed")
    write_marker(dest)
    origin = _run(["git", "-C", str(dest), "remote", "get-url", "origin"])
    if origin.returncode == 0:
        safe = sanitize_origin(origin.stdout.strip()) or SAFE_ORIGIN
        owned_git(["git", "-C", str(dest), "remote", "set-url", "origin", safe])
    if dest.joinpath(".mac-evidence-pack-owned").read_text(encoding="utf-8") != MARKER_TEXT:
        raise CheckoutError("failed to write pack-owned marker")
    return dest


def fetch_branch(repo: Path, branch: str) -> None:
    if not is_pack_owned(repo):
        raise PathRefusal(
            f"FOREIGN_CLONE: refuses to fetch inside existing non-pack clone ({repo})"
        )
    result = owned_git(["git", "-C", str(repo), "fetch", "--no-tags", "origin", branch])
    if result.returncode != 0:
        raise CheckoutError(
            result.stderr.strip() or f"git fetch origin {branch} failed"
        )


def checkout_commit(work: Path, pack_clone: Path, branch: str, commit: str) -> Path:
    """Return the worktree path pinned at commit. Recorded HEAD must match."""
    if not is_inside(work, work):
        raise PathRefusal("work dir is not self-contained")
    clone = resolve(pack_clone)
    if not is_pack_owned(clone):
        raise PathRefusal(
            f"FOREIGN_CLONE: refuses to operate inside existing non-pack clone ({clone})"
        )
    if not has_commit(clone, commit):
        fetch_branch(clone, branch)
    if not has_commit(clone, commit):
        raise CheckoutError(
            f"PIN_MISSING: commit {commit} is not in the pack clone after git fetch origin {branch}"
        )
    dest = require_inside(work / "checkouts" / commit[:12], work, "row checkout")
    if dest.exists():
        got = recorded_commit(dest)
        if got != commit:
            raise CheckoutError(f"checkout {dest} is {got}, expected {commit}")
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    result = owned_git(
        [
            "git",
            "-C",
            str(clone),
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


# Older name used by tests that want the dedicated HOME path.
ensure_mirror = ensure_owned_clone
