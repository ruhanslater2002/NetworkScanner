"""Tests for port specification parsing."""

from __future__ import annotations

import unittest

from netscan.constants import TOP_PORTS
from netscan.ports import PortError, parse_ports


class ParsePortsTests(unittest.TestCase):
    def test_top_set(self) -> None:
        self.assertEqual(parse_ports(None), TOP_PORTS)
        self.assertEqual(parse_ports("top"), TOP_PORTS)

    def test_explicit_list_is_sorted_and_deduplicated(self) -> None:
        self.assertEqual(parse_ports("443,80,443"), (80, 443))

    def test_inclusive_range(self) -> None:
        self.assertEqual(parse_ports("1-3"), (1, 2, 3))

    def test_mixed_specification(self) -> None:
        self.assertEqual(parse_ports("22,80-81"), (22, 80, 81))

    def test_service_names(self) -> None:
        self.assertEqual(parse_ports("http,https"), (80, 443))

    def test_reversed_range_is_rejected(self) -> None:
        with self.assertRaises(PortError):
            parse_ports("100-1")

    def test_unknown_service_is_rejected(self) -> None:
        with self.assertRaises(PortError):
            parse_ports("definitely-not-a-service")

    def test_out_of_bounds_is_rejected(self) -> None:
        with self.assertRaises(PortError):
            parse_ports("0")


if __name__ == "__main__":
    unittest.main()
