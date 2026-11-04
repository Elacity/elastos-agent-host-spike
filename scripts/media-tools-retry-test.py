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
    """Fails `failures` calls (every call when negative); a success serves a copy of the body."""
    def __init__(self, failures, body=BODY, truncate=0):
        self.failures, self.body, self.calls, self.truncate = failures, body, [], truncate

    def read(self):
        if self.truncate:
            self.truncate -= 1
            return self.body[:1]  # part of the body, then the connection drops
        return self.body

    @property
    def headers(self):
        return {"Content-Length": str(len(self.body))}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __call__(self, url, timeout=None):
        self.calls.append(timeout)
        if self.failures < 0 or len(self.calls) <= self.failures:
            raise urllib.error.URLError("timed out")
        return self


def copy_all(source, dest):
    dest.write(source.read())


class RetryTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.archive = Path(self.home.name) / "ffmpeg-9.0.1.tar.xz"
        self.sleeps = []
        patch.object(builder.time, "sleep", self.sleeps.append).start()
        self.addCleanup(patch.stopall)

    def fetch(self, network, digest=DIGEST):
        with patch.object(builder.urllib.request, "urlopen", network), \
                patch.object(builder.shutil, "copyfileobj", copy_all):
            builder.fetch_source(self.archive, URL, digest)

    def leftovers(self):
        return sorted(p.name for p in Path(self.home.name).iterdir())

    def test_transient_failures_then_success(self):
        network = FakeNetwork(2)  # two refusals, the third call succeeds
        self.fetch(network)
        self.assertEqual((len(network.calls), self.sleeps, set(network.calls)), (3, [5, 15], {300}))
        self.assertEqual(self.archive.read_bytes(), BODY)

    def test_exhaustion_reraises_and_leaves_no_archive(self):
        network = FakeNetwork(0, truncate=99)  # every attempt drops after part of the body
        with self.assertRaisesRegex(OSError, "short source download"):
            self.fetch(network)
        self.assertEqual((len(network.calls), self.sleeps), (3, [5, 15]))
        self.assertEqual(self.leftovers(), [])

    def test_attempt_count_is_bounded(self):
        network = FakeNetwork(10)  # the bound, not the supply of failures, must stop the fetch
        with self.assertRaisesRegex(urllib.error.URLError, "timed out"):
            self.fetch(network)
        self.assertEqual(len(network.calls), 3)

    def test_wrong_pinned_digest_rejects_download(self):
        network = FakeNetwork(0)  # the download succeeds, the pinned digest does not match
        with self.assertRaisesRegex(ValueError, "Source checksum mismatch"):
            self.fetch(network, hashlib.sha256(b"other").hexdigest())
        self.assertEqual(self.sleeps, [])
if __name__ == "__main__":
    unittest.main()
