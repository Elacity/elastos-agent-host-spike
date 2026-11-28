"""Parse the pinned #296 and #307 sources."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))

from b4map.gitread import load_pins
from b4map.linux import load_linux


class LinuxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pins = load_pins()
        cls.c9, cls.c0 = load_linux(cls.pins)

    def test_pins_are_the_draft_pr_heads(self):
        self.assertEqual(self.pins["linux_confine"]["pr"], 296)
        self.assertEqual(self.pins["fail_closed_linux"]["pr"], 307)
        self.assertEqual(self.c9["sha"], self.pins["linux_confine"]["sha"])
        self.assertEqual(self.c0["sha"], self.pins["fail_closed_linux"]["sha"])

    def test_linux_confine_has_pid_net_and_eight_storage_rights(self):
        self.assertIn("PID", self.c9["unshare"])
        self.assertIn("NET", self.c9["unshare"])
        self.assertTrue(self.c9["storage_has_eight_rights"])
        self.assertFalse(self.c9["ioctl_in_storage"])
        self.assertTrue(self.c9["deny_socket"])
        self.assertTrue(self.c9["socketpair_unix"])
        self.assertTrue(self.c9["pid_ns"])
        self.assertIsNotNone(self.c9["lines"]["storage"]["line"])
        self.assertIsNotNone(self.c9["lines"]["pid"]["line"])

    def test_fail_closed_has_no_pid_ns_and_denies_socketpair(self):
        self.assertTrue(self.c0["unshare_user_only"])
        self.assertTrue(self.c0["storage_has_eight_rights"])
        self.assertFalse(self.c0["ioctl_in_storage"])
        self.assertTrue(self.c0["ioctl_needed"])
        self.assertTrue(self.c0["socket_denied"])
        self.assertTrue(self.c0["socketpair_denied"])
        self.assertTrue(self.c0["pid_gap"])
        self.assertTrue(self.c0["scope_signal_abi6"])
        self.assertIsNotNone(self.c0["lines"]["socket"]["line"])
        self.assertIsNotNone(self.c0["lines"]["pid_gap"]["line"])


if __name__ == "__main__":
    unittest.main()
