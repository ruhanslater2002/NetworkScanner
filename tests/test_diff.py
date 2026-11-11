"""Tests for report diffing."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from netscan.diff import DiffError, diff_reports, load_report, render_diff_text


def report(*hosts: dict, targets: list[str] | None = None) -> dict:
    return {
        "tool": "NetScan",
        "targets": targets or ["192.168.1.0/24"],
        "hosts": list(hosts),
    }


class DiffTests(unittest.TestCase):
    def test_added_removed_and_changed(self) -> None:
        before = report(
            {"ip": "192.168.1.1", "open_ports": [80], "methods": ["ping"]},
            {"ip": "192.168.1.2", "open_ports": [22], "methods": ["ping"]},
        )
        after = report(
            {"ip": "192.168.1.1", "open_ports": [80, 443], "methods": ["ping"]},
            {"ip": "192.168.1.3", "open_ports": [8080], "methods": ["tcp"]},
        )
        diff = diff_reports(before, after)
        self.assertEqual([change.ip for change in diff.added], ["192.168.1.3"])
        self.assertEqual([change.ip for change in diff.removed], ["192.168.1.2"])
        self.assertEqual([change.ip for change in diff.changed], ["192.168.1.1"])
        self.assertEqual(diff.unchanged, 0)
        self.assertIn("opened 443", diff.changed[0].details)

    def test_unchanged_hosts_are_counted(self) -> None:
        before = report({"ip": "10.0.0.1", "open_ports": [22], "methods": ["ping"]})
        diff = diff_reports(before, before)
        self.assertTrue(diff.empty)
        self.assertEqual(diff.unchanged, 1)
        self.assertIn("No changes", render_diff_text(diff))

    def test_hostname_and_service_changes(self) -> None:
        before = report(
            {
                "ip": "10.0.0.1",
                "hostname": "old.lan",
                "open_ports": [80],
                "methods": ["tcp"],
                "services": [{"port": 80, "server": "nginx"}],
            }
        )
        after = report(
            {
                "ip": "10.0.0.1",
                "hostname": "new.lan",
                "open_ports": [80],
                "methods": ["tcp"],
                "services": [{"port": 80, "server": "caddy"}],
            }
        )
        details = diff_reports(before, after).changed[0].details
        self.assertTrue(any("hostname" in detail for detail in details))
        self.assertTrue(any("service" in detail for detail in details))

    def test_load_report_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "stress.json"
            path.write_text(json.dumps({"kind": "load_test", "hosts": []}))
            with self.assertRaises(DiffError):
                load_report(path)

    def test_invalid_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.json"
            path.write_text("{not json")
            with self.assertRaises(DiffError):
                load_report(path)

    def test_text_rendering_lists_changes(self) -> None:
        diff = diff_reports(
            report({"ip": "10.0.0.1", "open_ports": []}),
            report({"ip": "10.0.0.1", "open_ports": [443]}),
        )
        text = render_diff_text(diff)
        self.assertIn("~ 10.0.0.1", text)
        self.assertIn("opened 443", text)
        self.assertIn("1 changed", text)


if __name__ == "__main__":
    unittest.main()
