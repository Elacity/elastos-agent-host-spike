#!/usr/bin/env python3
"""FFmpeg source cache fail-closed checks for media-tools-build.py."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

builder = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
    "builder", Path(__file__).with_name("media-tools-build.py")))
builder.__spec__.loader.exec_module(builder)
SOURCE = b"ffmpeg fixture source"
DIGEST = hashlib.sha256(SOURCE).hexdigest()
URL = "https://example.invalid/f"


class FakeNetwork:
    """Serves one body once and records every call's timeout."""

    def __init__(self):
        self.body, self.calls = SOURCE, []
    __enter__ = lambda self: self
    __exit__ = lambda *exc: False

    def read(self, size=-1):
        self.body, body = b"", self.body
        return body

    def __call__(self, url, timeout=None):
        self.calls.append(timeout)
        return copy.copy(self)


class MediaSourceCacheTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.archive, self.cached = Path(temp.name) / "ffmpeg-9.0.1.tar.xz", Path(temp.name) / "c" / "ffmpeg-9.0.1.tar.xz"
        self.cached.parent.mkdir()
        patch.dict(os.environ, {"ELASTOS_MEDIA_SOURCE_CACHE": str(self.cached.parent)}).start()

    def fetch(self, network, digest=DIGEST):
        with patch.object(builder.urllib.request, "urlopen", network):
            builder.fetch_source(self.archive, URL, digest)

    def test_poisoned_cache_fails_closed(self):
        self.cached.write_bytes(b"poisoned")
        network = FakeNetwork()
        with self.assertRaisesRegex(ValueError, "Source cache checksum mismatch: ffmpeg-9.0.1.tar.xz"):
            self.fetch(network)
        self.assertEqual((network.calls, self.archive.exists()), ([], False))
        self.assertEqual(self.cached.read_bytes(), b"poisoned")  # the victim entry is untouched

    def test_valid_cache_skips_network(self):
        self.cached.write_bytes(SOURCE)
        network = FakeNetwork()
        self.fetch(network)
        self.assertEqual((network.calls, self.archive.read_bytes()), ([], SOURCE))

    def test_wrong_pinned_digest_rejects_download(self):
        with self.assertRaisesRegex(ValueError, "Source checksum mismatch: ffmpeg-9.0.1.tar.xz"):
            self.fetch(FakeNetwork(), "0" * 64)
        self.assertEqual(list(self.cached.parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
