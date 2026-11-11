"""Tests for report serialisation."""

from __future__ import annotations

import json
import unittest
from datetime import datetime

from netscan.exporters import render_csv, render_json, render_text, report_to_dict
from netscan.models import DiscoveryMethod, Host, ScanReport


def make_report() -> ScanReport:
    now = datetime(2026, 11, 11, 12, 0, 0)
    hosts = [
        Host(
            ip="192.168.1.1",
            methods=frozenset({DiscoveryMethod.PING, DiscoveryMethod.TCP}),
            hostname="router.lan",
            mac="a4:2b:8c:11:22:33",
            latency_ms=1.25,
            open_ports=(80, 443),
        ),
        Host(
            ip="192.168.1.20",
            methods=frozenset({DiscoveryMethod.ARP}),
        ),
    ]
    return ScanReport(
        targets=("192.168.1.0/24",),
        hosts=hosts,
        started_at=now,
        finished_at=now,
        duration_s=1.5,
        probed=254,
    )


class ExporterTests(unittest.TestCase):
    def test_json_structure(self) -> None:
        payload = json.loads(render_json(make_report()))
        self.assertEqual(payload["tool"], "NetScan")
        self.assertEqual(payload["summary"]["hosts_online"], 2)
        self.assertEqual(payload["summary"]["by_method"], {"ping": 1, "tcp": 1, "arp": 1})
        self.assertEqual(payload["hosts"][0]["open_ports"], [80, 443])
        self.assertIsNone(payload["hosts"][1]["mac"])

    def test_csv_header_and_rows(self) -> None:
        lines = render_csv(make_report()).strip().splitlines()
        self.assertEqual(
            lines[0],
            "ip,hostname,mac,latency_ms,methods,open_ports,port_states",
        )
        self.assertEqual(len(lines), 3)
        self.assertIn("192.168.1.1,router.lan,a4:2b:8c:11:22:33,1.2,ping tcp,80 443", lines[1])

    def test_text_output_contains_hosts(self) -> None:
        text = render_text(make_report())
        self.assertIn("192.168.1.1", text)
        self.assertIn("ICMP+TCP", text)
        self.assertIn("2 host(s)", text)

    def test_dict_is_serialisable(self) -> None:
        json.dumps(report_to_dict(make_report()))


if __name__ == "__main__":
    unittest.main()
