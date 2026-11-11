"""Tests for ARP table parsing."""

from __future__ import annotations

import unittest

from netscan.arp import parse_arp

WINDOWS_OUTPUT = """
Interface: 192.168.1.20 --- 0x8
  Internet Address      Physical Address      Type
  192.168.1.1           a4-2b-8c-11-22-33     dynamic
  192.168.1.10          b8-27-eb-44-55-66     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""

LINUX_OUTPUT = """
192.168.1.1 dev eth0 lladdr a4:2b:8c:11:22:33 REACHABLE
192.168.1.10 dev eth0 lladdr b8:27:eb:44:55:66 STALE
192.168.1.99 dev eth0  FAILED
"""

MACOS_OUTPUT = """
? (192.168.1.1) at a4:2b:8c:11:22:33 on en0 ifscope [ethernet]
? (192.168.1.10) at b8:27:eb:44:55:66 on en0 ifscope [ethernet]
"""


class ParseArpTests(unittest.TestCase):
    def test_windows_output(self) -> None:
        table = parse_arp(WINDOWS_OUTPUT)
        self.assertEqual(table["192.168.1.1"], "a4:2b:8c:11:22:33")
        self.assertEqual(table["192.168.1.10"], "b8:27:eb:44:55:66")

    def test_broadcast_entries_are_ignored(self) -> None:
        table = parse_arp(WINDOWS_OUTPUT)
        self.assertNotIn("192.168.1.255", table)
        self.assertNotIn("224.0.0.22", table)

    def test_linux_output(self) -> None:
        table = parse_arp(LINUX_OUTPUT)
        self.assertEqual(len(table), 2)
        self.assertEqual(table["192.168.1.10"], "b8:27:eb:44:55:66")
        self.assertNotIn("192.168.1.99", table)

    def test_macos_output(self) -> None:
        table = parse_arp(MACOS_OUTPUT)
        self.assertEqual(table["192.168.1.1"], "a4:2b:8c:11:22:33")


if __name__ == "__main__":
    unittest.main()
