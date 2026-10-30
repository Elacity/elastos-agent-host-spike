import tempfile
import unittest
from pathlib import Path

import common  # noqa: F401
from common import init_repo

from checkout import (
    checkout_commit,
    ensure_owned_clone,
    owned_git,
    recorded_commit,
    sanitize_origin,
)
from paths import PathRefusal
from pins import is_pack_owned


class CheckoutTests(unittest.TestCase):
    def test_sanitize_origin_drops_userinfo(self):
        raw = "https://x-access-token:secret@github.com/Elacity/elastos-agent-host-spike.git"
        self.assertEqual(
            sanitize_origin(raw),
            "https://github.com/Elacity/elastos-agent-host-spike.git",
        )

    def test_sanitize_origin_keeps_clean_https(self):
        url = "https://github.com/Elacity/elastos-agent-host-spike.git"
        self.assertEqual(sanitize_origin(url), url)

    def test_refuses_existing_non_pack_clone_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "pack-clone"
            sha = init_repo(dest)
            with self.assertRaises(PathRefusal) as caught:
                ensure_owned_clone(dest)
            self.assertIn("PACK_CLONE_FOREIGN", str(caught.exception))
            self.assertEqual(recorded_commit(dest), sha)
            self.assertFalse(is_pack_owned(dest))

    def test_refuses_changing_git_inside_foreign_clone(self):
        with tempfile.TemporaryDirectory() as tmp:
            foreign = Path(tmp) / "sash-spike"
            sha = init_repo(foreign)
            with self.assertRaises(PathRefusal) as caught:
                owned_git(["git", "-C", str(foreign), "checkout", "-B", "tamper"], cwd=foreign)
            self.assertIn("FOREIGN_CLONE", str(caught.exception))
            self.assertEqual(recorded_commit(foreign), sha)
            branches = __import__("subprocess").check_output(
                ["git", "-C", str(foreign), "branch", "--list"],
                text=True,
            )
            self.assertNotIn("tamper", branches)

    def test_refuses_local_clone_from_foreign_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            foreign = Path(tmp) / "sash-spike"
            sha = init_repo(foreign)
            dest = Path(tmp) / "stolen"
            with self.assertRaises(PathRefusal) as caught:
                owned_git(
                    [
                        "git",
                        "clone",
                        "--local",
                        "--no-hardlinks",
                        str(foreign),
                        str(dest),
                    ]
                )
            self.assertIn("FOREIGN_CLONE", str(caught.exception))
            self.assertFalse(dest.exists())
            self.assertEqual(recorded_commit(foreign), sha)

    def test_refuses_checkout_commit_on_foreign_clone(self):
        with tempfile.TemporaryDirectory() as tmp:
            foreign = Path(tmp) / "sash-spike"
            sha = init_repo(foreign)
            work = Path(tmp) / "work"
            work.mkdir()
            with self.assertRaises(PathRefusal) as caught:
                checkout_commit(work, foreign, "main", sha)
            self.assertIn("FOREIGN_CLONE", str(caught.exception))
            self.assertEqual(recorded_commit(foreign), sha)
            self.assertFalse((work / "checkouts").exists())

    def test_owned_clone_from_local_remote_writes_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            init_repo(src)
            __import__("subprocess").run(
                ["git", "-C", str(src), "branch", "-M", "cursor/mac-evidence-pack-be32"],
                check=True,
                capture_output=True,
            )
            dest = Path(tmp) / "pack-clone"
            remote = src.resolve().as_uri()
            got = ensure_owned_clone(
                dest,
                remote=remote,
                branch="cursor/mac-evidence-pack-be32",
            )
            self.assertEqual(got, dest.resolve())
            self.assertTrue(is_pack_owned(dest))
            again = ensure_owned_clone(dest, remote=remote)
            self.assertEqual(again, dest.resolve())
