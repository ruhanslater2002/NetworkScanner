"""Tests for the self-contained HTML reports."""

from __future__ import annotations

import unittest
from datetime import datetime

from netscan.models import (
    DiscoveryMethod,
    Host,
    PortResult,
    PortState,
    ScanReport,
    ServiceInfo,
)
from netscan.report_html import render_scan_html, render_stress_html
from netscan.stress import (
    AuditInfo,
    SloThresholds,
    StressMethod,
    StressReport,
    StressSnapshot,
)


def make_scan_report() -> ScanReport:
    now = datetime(2026, 11, 11, 12, 0, 0)
    service = ServiceInfo(port=80, server="nginx/1.27")
    host = Host(
        ip="192.168.1.1",
        methods=frozenset({DiscoveryMethod.PING, DiscoveryMethod.TCP}),
        hostname="router.lan",
        mac="a4:2b:8c:11:22:33",
        latency_ms=1.25,
        open_ports=(80,),
        port_details=(
            PortResult(port=80, state=PortState.OPEN, service=service),
            PortResult(port=443, state=PortState.FILTERED),
        ),
        services=(service,),
    )
    return ScanReport(
        targets=("192.168.1.0/24",),
        hosts=[host],
        started_at=now,
        finished_at=now,
        duration_s=1.5,
        probed=254,
    )


def make_stress_report() -> StressReport:
    now = datetime(2026, 11, 11, 12, 0, 0)
    return StressReport(
        target="http://127.0.0.1:8080/",
        resolved_ip="127.0.0.1",
        method=StressMethod.HTTP,
        scope="loopback",
        started_at=now,
        finished_at=now,
        duration_s=10.0,
        planned_duration_s=10.0,
        concurrency=10,
        rate=100,
        timeout=2.0,
        attempts=1000,
        successes=999,
        failures=1,
        timeouts=1,
        http_errors=0,
        bytes_sent=100_000,
        bytes_received=200_000,
        latency_min_ms=1.0,
        latency_mean_ms=12.0,
        latency_p50_ms=10.0,
        latency_p90_ms=20.0,
        latency_p99_ms=30.0,
        latency_max_ms=60.0,
        error_counts={"refused": 1},
        status_codes={200: 999},
        samples=[
            StressSnapshot(
                elapsed_s=0.0,
                attempts=0,
                successes=0,
                failures=0,
                in_flight=0,
                rps=0.0,
                success_rate=0.0,
                p50_ms=None,
                p99_ms=None,
                errors={},
                statuses={},
            ),
            StressSnapshot(
                elapsed_s=10.0,
                attempts=1000,
                successes=999,
                failures=1,
                in_flight=0,
                rps=100.0,
                success_rate=0.999,
                p50_ms=10.0,
                p99_ms=30.0,
                errors={},
                statuses={200: 999},
            ),
        ],
        slo_results=(),
        audit=AuditInfo(operator="alice", authorization_ref="CHG-1234"),
    )


class ScanHtmlTests(unittest.TestCase):
    def test_report_is_self_contained(self) -> None:
        document = render_scan_html(make_scan_report())
        self.assertTrue(document.startswith("<!doctype html>"))
        self.assertIn("192.168.1.1", document)
        self.assertIn("router.lan", document)
        self.assertIn("nginx/1.27", document)
        self.assertIn("filtered", document)
        self.assertNotIn("<script", document)
        self.assertNotIn("http://", document)
        self.assertNotIn("https://", document)

    def test_empty_report_renders(self) -> None:
        report = make_scan_report()
        report.hosts = []
        document = render_scan_html(report)
        self.assertIn("No live hosts", document)

    def test_html_is_escaped(self) -> None:
        report = make_scan_report()
        report.hosts[0] = Host(
            ip="192.168.1.1",
            methods=frozenset({DiscoveryMethod.ARP}),
            hostname="<script>alert(1)</script>",
        )
        document = render_scan_html(report)
        self.assertNotIn("<script>alert(1)</script>", document)
        self.assertIn("&lt;script&gt;", document)


class StressHtmlTests(unittest.TestCase):
    def test_report_contains_metrics_and_svg(self) -> None:
        document = render_stress_html(make_stress_report())
        self.assertIn("Load-test report", document)
        self.assertIn("127.0.0.1", document)
        self.assertIn("alice", document)
        self.assertIn("CHG-1234", document)
        self.assertIn("<svg", document)
        self.assertIn("Service stayed responsive", document)
        self.assertNotIn("<script", document)

    def test_slo_panel_renders(self) -> None:
        report = make_stress_report()
        from netscan.stress import evaluate_slo

        report.slo_results = evaluate_slo(
            plan_slo=SloThresholds(min_success_rate=0.95, max_p99_ms=50),
            attempts=report.attempts,
            successes=report.successes,
            timeouts=report.timeouts,
            p99_ms=report.latency_p99_ms,
        )
        document = render_stress_html(report)
        self.assertIn("Service-level objectives", document)
        self.assertIn("all passed", document)
        self.assertIn("success rate", document)

    def test_slo_breach_is_reported(self) -> None:
        report = make_stress_report()
        from netscan.stress import evaluate_slo

        report.slo_results = evaluate_slo(
            plan_slo=SloThresholds(min_success_rate=0.9999),
            attempts=report.attempts,
            successes=report.successes,
            timeouts=report.timeouts,
            p99_ms=report.latency_p99_ms,
        )
        document = render_stress_html(report)
        self.assertIn("breach", document)
        self.assertIn("fail", document)


if __name__ == "__main__":
    unittest.main()
