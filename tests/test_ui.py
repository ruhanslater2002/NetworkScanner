"""Presentation tests: the UI must never rewrite or drop scan data."""

from __future__ import annotations

import io
import unittest
from datetime import datetime

from rich.console import Console

from netscan.models import DiscoveryMethod, Host, ScanReport
from netscan.ui import THEME, ConsoleUI


def _report(*hosts: Host) -> ScanReport:
    now = datetime.now()
    return ScanReport(
        targets=["192.168.1.0/24"],
        hosts=list(hosts),
        started_at=now,
        finished_at=now,
        duration_s=1.0,
        probed=254,
    )


def _render(report: ScanReport, *, width: int = 200, emoji: bool = True) -> str:
    stream = io.StringIO()
    console = Console(file=stream, theme=THEME, width=width, emoji=emoji, no_color=True)
    ConsoleUI(console).results(report)
    return stream.getvalue()


class TestMacRendering(unittest.TestCase):
    """Rich rewrites ``:ab:``-style shortcodes into emoji inside plain strings.

    MAC addresses are built from exactly that pattern, so cells must be built
    as ``Text`` instances (or the console must have emoji parsing disabled).
    """

    MAC = "4c:49:29:ab:bf:99"

    def _output(self, emoji: bool) -> str:
        host = Host(
            ip="192.168.1.14",
            mac=self.MAC,
            latency_ms=1.23,
            methods=frozenset({DiscoveryMethod.ARP}),
        )
        return _render(_report(host), emoji=emoji)

    def test_mac_is_verbatim_with_emoji_parsing_enabled(self) -> None:
        self.assertIn(self.MAC, self._output(emoji=True))

    def test_mac_is_verbatim_with_emoji_parsing_disabled(self) -> None:
        self.assertIn(self.MAC, self._output(emoji=False))

    def test_mac_survives_medium_layout(self) -> None:
        host = Host(
            ip="192.168.1.14",
            mac=self.MAC,
            latency_ms=1.23,
            methods=frozenset({DiscoveryMethod.ARP}),
        )
        self.assertIn(self.MAC, _render(_report(host), width=92))


class TestHostnameRendering(unittest.TestCase):
    def test_hostname_with_colons_is_verbatim(self) -> None:
        host = Host(
            ip="192.168.1.20",
            hostname="nas:ab:cd",
            latency_ms=2.0,
            methods=frozenset({DiscoveryMethod.PING}),
        )
        self.assertIn("nas:ab:cd", _render(_report(host)))


if __name__ == "__main__":
    unittest.main()
