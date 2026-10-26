import unittest

import common  # noqa: F401

from checkout import sanitize_origin


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
