"""The environment for a test's git command against its own fixture repository.

git ignores ``-C`` and the working directory when GIT_DIR, GIT_WORK_TREE,
GIT_INDEX_FILE, GIT_COMMON_DIR or GIT_OBJECT_DIRECTORY is set, and git sets
them for hooks and ``git rebase --exec``. A fixture command that inherits them
writes to that caller's repository. Load this file by path (tests in other
folders use ``importlib``); it is not a script.
"""

import hashlib
import os
import subprocess
from pathlib import Path

IDENTITY = frozenset({"GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"})


def fixture_git_env(root, identity=None):
    """``os.environ`` with no ``GIT_*`` variable, for a fixture inside ``root``.

    ``root`` is the test's temporary directory. Repository discovery stops at
    it, and no system, user or XDG git config is read: ``HOME`` is ``root``.
    ``identity`` may set only the four author and committer names in IDENTITY.
    """
    unknown = sorted(set(identity or ()) - IDENTITY)
    if unknown:
        raise ValueError(f"not an identity variable: {unknown}")
    root = Path(root).resolve()
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("GIT_") and key != "XDG_CONFIG_HOME"}
    env.update(identity or {})
    env.update(GIT_CEILING_DIRECTORIES=str(root.parent), GIT_CONFIG_NOSYSTEM="1", HOME=str(root))
    return env


def victim_repo(root, untracked=("untracked.txt",)):
    """A scratch repository under ``root`` that a leaked fixture command would change.

    It has one commit and leaves the ``untracked`` paths untracked, so a
    leaked ``git add`` of those paths, or of everything, has something to stage.
    Returns the repository and the environment that points git at it.
    """
    repo = Path(root).resolve() / "victim"
    (repo / "tracked.txt").parent.mkdir(parents=True)
    (repo / "tracked.txt").write_text("victim\n")
    env = fixture_git_env(root, {key: "victim" for key in IDENTITY})
    for args in (("init", "-q", "-b", "victim"), ("add", "tracked.txt"), ("commit", "-q", "-m", "victim")):
        subprocess.run(["git", "-C", str(repo), *args], env=env, check=True, capture_output=True)
    for name in untracked:
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text("victim untracked\n")
    return repo, {"GIT_DIR": str(repo / ".git"), "GIT_WORK_TREE": str(repo)}


def shared_config(checkout):
    """The bytes of the common config of the real repository holding ``checkout``.

    A hostile-GIT_DIR test reads it before and after: a leaked ``git init --bare``
    or ``git config`` there changes every worktree that shares it.
    """
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    common = subprocess.run(["git", "-C", str(checkout), "rev-parse", "--path-format=absolute", "--git-common-dir"],
                            env=env, check=True, capture_output=True, text=True).stdout.strip()
    return (Path(common) / "config").read_bytes()


def repo_state(repo):
    """HEAD, the index's sha256 and every work-tree file's bytes."""
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], env=fixture_git_env(Path(repo).parent),
                          check=True, capture_output=True, text=True).stdout.strip()
    index = hashlib.sha256((Path(repo) / ".git" / "index").read_bytes()).hexdigest()
    files = {path.relative_to(repo).as_posix(): path.read_bytes() for path in sorted(Path(repo).rglob("*"))
             if path.is_file() and ".git" not in path.relative_to(repo).parts}
    return head, index, files
