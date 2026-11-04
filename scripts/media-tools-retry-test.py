#!/usr/bin/env python3
"""FFmpeg source fetch retry, exhaustion and digest checks for media-tools-build.py."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

builder = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "builder", Path(__file__).with_name("media-tools-build.py")))
builder.__spec__.loader.exec_module(builder)
BODY = b"ffmpeg fixture source"
DIGEST = hashlib.sha256(BODY).hexdigest()
URL = "https://example.invalid/f"


class FakeNetwork:
    """Fails `failures` calls (every call when negative); a success serves `body` in one block."""
    def __init__(self, failures, body=BODY):
        self.failures, self.body, self.calls = failures, body, []
        self.headers = {"Content-Length": str(len(BODY))}  # the count the server announced

    def read(self, size=-1):  # shutil.copyfileobj asks for blocks
        body, self.body = self.body, b""
        return body

    def __call__(self, url, timeout=None):
        self.calls.append(timeout)
        if self.failures < 0 or len(self.calls) <= self.failures:
            raise urllib.error.URLError("timed out")
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RetryTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.archive = Path(self.home.name) / "ffmpeg-9.0.1.tar.xz"
        self.sleeps, self.leftovers = [], []
        patch.object(builder.time, "sleep", self.sleeps.append).start()
        patch.object(builder, "sha", sha).start()
        self.addCleanup(patch.stopall)

    def fetch(self, network, digest=DIGEST):
        self.leftovers = lambda: sorted(p.name for p in Path(self.home.name).iterdir())
        with patch.object(builder.urllib.request, "urlopen", network):
            builder.fetch_source(self.archive, URL, digest)

    def test_transient_failures_then_success(self):
        network = FakeNetwork(2)  # two refusals, the third call succeeds
        self.fetch(network)
        self.assertEqual((len(network.calls), self.sleeps, set(network.calls)), (3, [5, 15], {300}))
        self.assertEqual(self.archive.read_bytes(), BODY)

    def test_exhaustion_reraises_and_leaves_no_side_file(self):
        network = FakeNetwork(0, BODY[:1])  # a short body, so every attempt writes a side file
        with self.assertRaisesRegex(OSError, "short source download"):
            self.fetch(network)
        self.assertEqual((len(network.calls), self.sleeps, self.leftovers()), (3, [5, 15], []))
        self.assertEqual(self.archive.exists(), False)

    def test_wrong_pinned_digest_rejects_download(self):
        network = FakeNetwork(0)  # the download is complete, the pinned digest does not match
        with self.assertRaisesRegex(ValueError, "Source checksum mismatch"):
            self.fetch(network, hashlib.sha256(b"other").hexdigest())
        self.assertEqual((len(network.calls), self.sleeps, self.leftovers(),
                          self.archive.exists()), (1, [], [], False))

if __name__ == "__main__":
    unittest.main()
