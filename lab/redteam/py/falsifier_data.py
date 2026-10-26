"""One reader, one commit, one edit rule for the lane's falsifier probes.

Task 004 and the model-provider honesty probe import this module. It is not a
test module: its name does not match ``test*.py``, so ``unittest discover``
does not collect it.

Three rules live here and nowhere else (P10):

- ``load_json`` is the strict JSON reader. It refuses bytes that are not
  UTF-8, broken syntax, a duplicate key in any object, the constants
  ``NaN``, ``Infinity`` and ``-Infinity``, and an unpaired surrogate.
  A high surrogate and a low surrogate each have their own reason. A valid
  pair is one Unicode scalar and is accepted.
- ``Snapshot`` resolves HEAD once, to one full SHA, and every later byte,
  pin and history query for that snapshot uses that SHA. A file is recorded
  under the path the caller named. When the checkout redirects that path,
  the bytes are the named file at that commit, not the target; if the
  commit has no such file, the redirect is refused.
- ``apply_edits`` applies one file's edits in order. Each ``old`` text is
  counted in the text the earlier edits left, and must occur exactly once,
  the way ``falsify.py`` counts it in ``Mutation.__enter__``.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
from pathlib import Path


_HEX = frozenset("0123456789abcdef")


class StrictJsonError(ValueError):
    """``load_json`` refused the bytes. The message is the probe's reason."""


def digest(data: bytes | None) -> str:
    """``sha256 <hex>`` of bytes, or ``absent`` when the file is missing."""
    if data is None:
        return "absent"
    return "sha256 " + hashlib.sha256(data).hexdigest()


def text_of(data: bytes) -> str:
    """The text ``Path.read_text(encoding="utf-8")`` gives.

    Strict UTF-8, and every line ending read as a newline. A non-UTF-8 file
    raises ``LookupError``; the anchor probe reports that reason and does not
    count anchors in a file it cannot read.
    """
    try:
        return io.TextIOWrapper(io.BytesIO(data), encoding="utf-8").read()
    except UnicodeDecodeError:
        raise LookupError("the file is not UTF-8") from None


def _surrogate_reason(text: str):
    """Why ``text`` is not a sequence of Unicode scalar values, or None.

    ``json.loads`` joins a high surrogate (U+D800..U+DBFF) to a following
    low surrogate (U+DC00..U+DFFF) and returns one scalar. A surrogate that
    remains is unpaired. The first one names the reason.
    """
    for char in text:
        code = ord(char)
        if 0xD800 <= code <= 0xDBFF:
            return "unpaired high surrogate is not strict JSON"
        if 0xDC00 <= code <= 0xDFFF:
            return "unpaired low surrogate is not strict JSON"
    return None


def _reject_unpaired_surrogates(value):
    """Refuse any string in ``value`` that contains an unpaired surrogate.

    Keys and values, at every depth. This is the one Unicode check. Every
    probe reads JSON through ``load_json``.
    """
    if isinstance(value, str):
        reason = _surrogate_reason(value)
        if reason is not None:
            raise StrictJsonError(reason)
        return
    if isinstance(value, list):
        for item in value:
            _reject_unpaired_surrogates(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_unpaired_surrogates(key)
            _reject_unpaired_surrogates(item)


def load_json(data: bytes):
    """The one strict JSON reader.

    ``json.loads`` on its own accepts ``NaN``, ``Infinity``, ``-Infinity``,
    a repeated key, and an unpaired surrogate escape. Those are refusals
    here, each with a reason that names the constant, the key, or the
    surrogate. A high surrogate and a low surrogate are different refusals.
    A valid pair is one scalar value and is accepted. Broken syntax and
    bytes that are not UTF-8 are refusals too.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise StrictJsonError("the file is not UTF-8") from None

    def reject_constant(token: str):
        raise StrictJsonError(f"{token} is not strict JSON")

    def object_pairs(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise StrictJsonError(f"duplicate key {key!r}")
            obj[key] = value
        return obj

    try:
        value = json.loads(text, parse_constant=reject_constant, object_pairs_hook=object_pairs)
    except StrictJsonError:
        raise
    except ValueError:
        raise StrictJsonError("the file is not JSON") from None
    _reject_unpaired_surrogates(value)
    return value


def apply_edits(text: str, edits):
    """Apply ``edits`` in order to ``text``.

    ``edits`` is a sequence of ``(index, edit)`` in the order the runner
    applies them. ``edit["old"]`` is counted in the text the earlier edits
    left, not in the original, and it must be found once. The first edit that
    is not found once stops the file. Returns ``(updated, None)`` or
    ``(text_so_far, (index, count))``.
    """
    for index, edit in edits:
        count = text.count(edit["old"])
        if count != 1:
            return text, (index, count)
        text = text.replace(edit["old"], edit["new"])
    return text, None


def execute(root, args):
    """Stdout of one local git command, or None when git cannot answer.

    ``GIT_*`` variables are dropped, so the repository is ``root`` and not a
    directory named in the environment. A successful empty blob is ``b""``,
    which is not the same as git failing.
    """
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    try:
        done = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            env=env,
        )
    except OSError:
        return None
    if done.returncode != 0:
        return None
    return done.stdout


def resolve_head(run) -> str | None:
    """HEAD as one full 40-character SHA, or None.

    Call this once, when a snapshot is taken, and pass that SHA from then on.
    A second call is a second resolution: HEAD may have moved.
    """
    out = run("rev-parse", "--verify", "--quiet", "HEAD^{commit}")
    if out is None:
        return None
    text = out.decode("ascii", "replace").strip()
    if len(text) == 40 and all(char in _HEX for char in text):
        return text
    return None


def blob_at(run, commit: str | None, path: str) -> bytes | None:
    """The blob at ``commit:path``, or None when the commit has no such file."""
    if commit is None:
        return None
    return run("cat-file", "blob", f"{commit}:{path}")


def _bind(root):
    def run(*args):
        return execute(root, args)
    return run


def _requested_key(root: Path, requested: Path) -> str | None:
    """Repo-relative path of ``requested``, without following symlinks.

    ``.`` and ``..`` are collapsed. None when the path is ``root`` itself
    or leaves ``root``.
    """
    root_text = root.as_posix().rstrip("/")
    named_text = os.path.normpath(requested.as_posix())
    prefix = root_text + "/"
    if not named_text.startswith(prefix):
        return None
    relative = named_text[len(prefix):]
    if not relative or relative == ".":
        return None
    return relative


class Snapshot:
    """One commit and the bytes judged against it.

    HEAD is resolved in ``__init__`` and stored on ``commit``. Pins, history
    and the report take that SHA. They do not resolve HEAD again. Each file
    is recorded under the path the caller named. A checkout that redirects
    that path is not read as the target: the named file at ``commit`` is.
    """

    def __init__(self, root, run=None):
        self.root = Path(root).resolve()
        self.run = run or _bind(self.root)
        self.files = {}
        self._parents = {}
        self.commit = resolve_head(self.run)

    def read_relative(self, base, name: str) -> bytes:
        """Bytes of the repository path ``base/name``.

        The path the caller named is the path recorded and verified. A name
        that leaves the repository is refused before any read. When the
        checkout redirects that name onto another file, the bytes are the
        named file at the snapshot commit (``git``'s blob), not the target.
        The target is not read. A redirect the commit cannot name is refused
        with the two paths.
        """
        requested = Path(base) / name
        key = _requested_key(self.root, requested)
        resolved = requested.resolve()
        if key is None or not resolved.is_relative_to(self.root):
            raise LookupError("the file is outside the repository")
        resolved_key = resolved.relative_to(self.root).as_posix()
        if key not in self.files:
            if resolved_key != key:
                data = blob_at(self.run, self.commit, key)
                if data is None:
                    raise LookupError(
                        f"the path is redirected from {key} to {resolved_key}")
                self.files[key] = data
            else:
                self.files[key] = requested.read_bytes() if requested.is_file() else None
        if self.files[key] is None:
            raise LookupError("the file does not exist")
        return self.files[key]

    def last_change(self, path: str, commit: str | None = None) -> str | None:
        """``hash subject`` of the last commit at ``commit`` that changed ``path``."""
        commit = self.commit if commit is None else commit
        if not commit:
            return None
        out = self.run("log", "-1", "--format=%H %s", commit, "--", path)
        return out.decode("utf-8", "replace").strip() if out else None

    def commit_line(self, commit: str) -> str | None:
        """``hash subject`` of one commit, or None."""
        out = self.run("log", "-1", "--format=%H %s", commit)
        return out.decode("utf-8", "replace").strip() if out else None

    def first_parent_line(self, commit: str | None) -> tuple | None:
        """``commit``'s first-parent line, newest first, or None."""
        if not commit:
            return None
        if commit not in self._parents:
            out = self.run("rev-list", "--first-parent", commit)
            self._parents[commit] = None if out is None else tuple(out.decode("ascii").split())
        return self._parents[commit]

    def entry_point(self, change: str, commit: str | None = None) -> str | None:
        """The commit that brought ``change`` onto ``commit``'s first-parent line.

        That is the merge of its pull request, or ``change`` itself when it
        was committed on that line. The merge subject's text names the PR.
        """
        commit = self.commit if commit is None else commit
        line = self.first_parent_line(commit)
        if not commit:
            return None
        after = self.run("rev-list", "--ancestry-path", f"{change}..{commit}")
        if line is None or after is None:
            return None
        if change in line:
            return change
        descendants = set(after.decode("ascii").split())
        return next((item for item in reversed(line) if item in descendants), None)

    def describe(self, files, commit: str | None = None) -> str:
        """Where ``files`` were read: the snapshot SHA, each sha256, each pin.

        ``commit`` defaults to the SHA resolved when this snapshot was taken.
        Passing another SHA does not resolve HEAD.
        """
        if commit is None:
            commit = self.commit
        lines = [f"read at HEAD {commit or '(unresolved)'}"]
        for path, data in sorted(files.items()):
            change = self.last_change(path, commit) if commit else None
            lines.append(f"  {path} {digest(data)}, last changed in {change or '(unknown)'}")
            entry = self.entry_point(change.split()[0], commit) if change else None
            if entry:
                lines.append(
                    f"    first on HEAD's first-parent line in {self.commit_line(entry)}")
        return "\n".join(lines)
