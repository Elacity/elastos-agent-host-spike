#!/usr/bin/env python3
"""A failed FFmpeg source fetch attempt leaves no side file; the attempt count is bounded."""
from http.client import IncompleteRead
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

_spec = importlib.util.spec_from_file_location("builder", Path(__file__).with_name("media-tools-build.py"))
builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(builder)
BODY = b"ffmpeg fixture source"
URL = "https://example.invalid/f"
DIGEST = hashlib.sha256(BODY).hexdigest()


class FakeNetwork:
    """Fails `failures` calls (every call when negative); a success sends `body` then raises `error`."""
    def __init__(self, failures=0, body=BODY, error=IncompleteRead(b"")):
        self.failures, self.body, self.calls, self.error = failures, body, [], error
        self.headers = {"Content-Length": str(len(BODY))}  # the count the server announced

    def read(self, size=-1):
        body, self.body = self.body, None
        if body is not None:
            return body
        raise self.error

    def __call__(self, url, timeout=None):
        self.calls.append(timeout)
        if self.failures < 0 or len(self.calls) <= self.failures:
            raise urllib.error.URLError("timed out")
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FetchCleanupTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.archive = Path(self.home.name) / "ffmpeg-9.0.1.tar.xz"
        self.sleeps = []
        patch.object(builder, "sha", lambda path: hashlib.sha256(path.read_bytes()).hexdigest()).start()
        patch.object(builder.time, "sleep", self.sleeps.append).start()
        self.addCleanup(patch.stopall)

    def leftovers(self, network):
        """Names left in the directory after run_fetch, plus its call count."""
        return len(network.calls), sorted(p.name for p in Path(self.home.name).iterdir())

    def run_fetch(self, network):
        with patch.object(builder.urllib.request, "urlopen", network):
            builder.fetch_source(self.archive, URL, DIGEST)

    def test_short_body_is_not_retried_and_leaves_no_side_file(self):
        network = FakeNetwork(body=BODY[:1])  # 1 byte, then the connection drops
        with self.assertRaises(IncompleteRead): self.run_fetch(network)
        self.assertEqual(self.leftovers(network), (1, []))

    def test_malformed_content_length_is_not_retried(self):
        network = FakeNetwork(error=ValueError("bad Content-Length"))  # rejected while reading it
        with self.assertRaisesRegex(ValueError, "bad Content-Length"): self.run_fetch(network)
        self.assertEqual(self.leftovers(network), (1, []))

    def test_attempt_count_is_bounded(self):
        network = FakeNetwork(-1)  # the bound, not the supply of failures, must stop the fetch
        with self.assertRaisesRegex(urllib.error.URLError, "timed out"): self.run_fetch(network)
        self.assertEqual((len(network.calls), self.sleeps), (3, [5, 15]))

if __name__ == "__main__": unittest.main()
