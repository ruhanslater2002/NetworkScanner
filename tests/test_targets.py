"""Tests for target expression parsing."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from netscan.targets import (
    TargetError,
    enforce_scope,
    parse_excludes,
    parse_scope_entries,
    parse_scope_file,
    parse_targets,
    public_targets,
)


class ParseTargetsTests(unittest.TestCase):
    def test_cidr_skips_network_and_broadcast(self) -> None:
        self.assertEqual(
            parse_targets(["192.168.1.0/30"]),
            ["192.168.1.1", "192.168.1.2"],
        )

    def test_single_host(self) -> None:
        self.assertEqual(parse_targets([" 192.168.1.10 "]), ["192.168.1.10"])

    def test_short_range(self) -> None:
        self.assertEqual(
            parse_targets(["10.0.0.1-3"]),
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        )

    def test_full_range(self) -> None:
        self.assertEqual(
            parse_targets(["172.16.0.1-172.16.0.3"]),
            ["172.16.0.1", "172.16.0.2", "172.16.0.3"],
        )

    def test_duplicates_are_removed(self) -> None:
        self.assertEqual(
            parse_targets(["10.0.0.0/30", "10.0.0.1"]),
            ["10.0.0.1", "10.0.0.2"],
        )

    def test_reversed_range_is_rejected(self) -> None:
        with self.assertRaises(TargetError):
            parse_targets(["10.0.0.5-1"])

    def test_invalid_network_is_rejected(self) -> None:
        with self.assertRaises(TargetError):
            parse_targets(["192.168.1.0/99"])

    def test_oversized_network_is_rejected(self) -> None:
        with self.assertRaises(TargetError):
            parse_targets(["10.0.0.0/8"])

    def test_unresolvable_host_is_rejected(self) -> None:
        with self.assertRaises(TargetError):
            parse_targets(["this-host-should-not-exist.invalid"])


class ScopeTests(unittest.TestCase):
    def test_entries_accept_comments_commas_and_ranges(self) -> None:
        networks = parse_scope_entries(
            ["# authorised lab", "192.168.10.0/24, 10.20.0.5", "10.20.0.10-12 # range"]
        )
        self.assertEqual(
            [str(network) for network in networks],
            [
                "192.168.10.0/24",
                "10.20.0.5/32",
                "10.20.0.10/31",
                "10.20.0.12/32",
            ],
        )

    def test_invalid_scope_entry_is_rejected(self) -> None:
        with self.assertRaises(TargetError):
            parse_scope_entries(["not a network"])

    def test_scope_file_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.txt"
            path.write_text("# authorised\n192.168.10.0/24\n", encoding="utf-8")
            networks = parse_scope_file(path)
        self.assertEqual([str(network) for network in networks], ["192.168.10.0/24"])

    def test_missing_scope_file_is_an_error(self) -> None:
        with self.assertRaises(TargetError):
            parse_scope_file("this-file-does-not-exist.txt")

    def test_empty_scope_file_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.txt"
            path.write_text("# nothing here\n", encoding="utf-8")
            with self.assertRaises(TargetError):
                parse_scope_file(path)

    def test_enforce_scope_allows_listed_targets(self) -> None:
        allow = parse_scope_entries(["192.168.10.0/24"])
        targets = ["192.168.10.5", "192.168.10.6"]
        self.assertEqual(enforce_scope(targets, allow), targets)

    def test_enforce_scope_rejects_outside_targets(self) -> None:
        allow = parse_scope_entries(["192.168.10.0/24"])
        with self.assertRaises(TargetError):
            enforce_scope(["10.0.0.1"], allow)

    def test_enforce_scope_rejects_denied_targets(self) -> None:
        allow = parse_scope_entries(["192.168.10.0/24"])
        deny = parse_excludes(["192.168.10.1,192.168.10.2"])
        with self.assertRaises(TargetError):
            enforce_scope(["192.168.10.1"], allow, deny)

    def test_enforce_scope_without_allowlist_permits_targets(self) -> None:
        self.assertEqual(enforce_scope(["10.0.0.1"], []), ["10.0.0.1"])

    def test_public_targets_are_identified(self) -> None:
        self.assertEqual(
            public_targets(["8.8.8.8", "192.168.1.1", "127.0.0.1"]),
            ["8.8.8.8"],
        )


if __name__ == "__main__":
    unittest.main()
