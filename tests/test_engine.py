"""Engine tests using a stubbed neighbour table (no network access needed)."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from netscan.engine import NetworkScanner
from netscan.models import DiscoveryMethod, ScanConfig

ARP_TABLE = {
    "192.168.50.1": "aa:bb:cc:00:00:01",
    "192.168.50.9": "aa:bb:cc:00:00:09",
}


class EngineTests(unittest.IsolatedAsyncioTestCase):
    async def test_arp_only_scan_uses_neighbour_table(self) -> None:
        async def fake_arp_table() -> dict[str, str]:
            return dict(ARP_TABLE)

        config = ScanConfig(
            targets=("192.168.50.1-2",),
            methods=frozenset({DiscoveryMethod.ARP}),
            resolve_hostnames=False,
        )

        with patch("netscan.engine.read_arp_table", fake_arp_table):
            report = await NetworkScanner(config).scan()

        self.assertEqual([host.ip for host in report.hosts], ["192.168.50.1"])
        self.assertEqual(report.hosts[0].mac, "aa:bb:cc:00:00:01")
        self.assertEqual(report.hosts[0].methods, frozenset({DiscoveryMethod.ARP}))
        self.assertEqual(report.probed, 2)
        self.assertEqual(report.targets, ("192.168.50.1-2",))
        self.assertEqual(report.errors, 0)

    async def test_progress_reporter_lifecycle(self) -> None:
        events: list[tuple] = []

        class Reporter:
            def on_start(self, total: int) -> None:
                events.append(("start", total))

            def on_host(self, ip: str) -> None:
                events.append(("host", ip))

            def on_progress(self, done: int, total: int, found: int) -> None:
                events.append(("progress", done, total, found))

            def on_finish(self) -> None:
                events.append(("finish",))

        async def fake_arp_table() -> dict[str, str]:
            return dict(ARP_TABLE)

        config = ScanConfig(
            targets=("192.168.50.1",),
            methods=frozenset({DiscoveryMethod.ARP}),
            resolve_hostnames=False,
        )

        with patch("netscan.engine.read_arp_table", fake_arp_table):
            await NetworkScanner(config).scan(Reporter())

        self.assertEqual(events[0], ("start", 1))
        self.assertIn(("host", "192.168.50.1"), events)
        self.assertEqual(events[-2], ("progress", 1, 1, 1))
        self.assertEqual(events[-1], ("finish",))


if __name__ == "__main__":
    unittest.main()
