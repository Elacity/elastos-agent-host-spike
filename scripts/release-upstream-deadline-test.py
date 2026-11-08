#!/usr/bin/env python3
"""Exercise deadline interruption with real local sockets, without downloads."""
import importlib.util
import io
from pathlib import Path
import signal
import socket
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "upstream", Path(__file__).with_name("release-upstream-input.py"))
upstream = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upstream)


class BlockingDeadlineTest(unittest.TestCase):
    def test_blocking_headers_body_and_chunk_framing_are_interrupted(self):
        source = {"url": "https://upstream.example.test/input", "max_bytes": 32}
        frames = (b"HTTP/1.1 200 OK\r\nContent-Length:",
                  b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx",
                  b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1")
        for frame in frames:
            with self.subTest(frame=frame):
                # Each pair is closed by its context, including a failing plant.
                reader, writer = socket.socketpair()
                with reader, writer, tempfile.TemporaryFile() as output:
                    reader.settimeout(0.5)  # Also bounds the old-behaviour plant.
                    writer.sendall(frame)
                    reply = upstream.http.client.HTTPResponse(reader)

                    def opened(*args, **kwargs):
                        reply.begin()
                        return reply

                    handler = signal.getsignal(signal.SIGALRM)
                    started = time.monotonic()
                    with reply, patch.object(upstream, "TOTAL_DEADLINE_SECONDS", 0.05), \
                            patch.object(upstream.urllib.request, "build_opener") as build:
                        build.return_value.open.side_effect = opened
                        with self.assertRaisesRegex(ValueError, "upstream.example.test/input.*deadline"):
                            upstream.fetch(source, output, "sha256", delays=())
                    self.assertLess(time.monotonic() - started, 0.4)
                    self.assertIs(signal.getsignal(signal.SIGALRM), handler)
                    self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_deadline_is_checked_before_the_next_read(self):
        source = {"url": "https://upstream.example.test/input", "max_bytes": 32}
        elapsed, reads = [0], []

        class Body(io.BytesIO):
            def read(self, size):
                reads.append(size)
                return super().read(size)

        with tempfile.TemporaryFile() as output, \
                patch.object(upstream, "response", return_value=Body(b"payload")), \
                patch.object(output, "write", side_effect=lambda chunk: elapsed.__setitem__(0, 360)):
            with self.assertRaisesRegex(ValueError, "360 s deadline"):
                upstream.fetch(source, output, "sha256", clock=lambda: elapsed[0])
        self.assertEqual(len(reads), 1)


if __name__ == "__main__":
    unittest.main()
