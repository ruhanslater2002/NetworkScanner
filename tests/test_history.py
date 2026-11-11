"""Tests for the SQLite run history."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from netscan.history import HistoryStore
from netscan.models import DiscoveryMethod, Host, ScanReport
from netscan.stress import StressMethod, StressReport


def scan_report() -> ScanReport:
    now = datetime(2026, 11, 11, 12, 0, 0)
    return ScanReport(
        targets=("192.168.1.0/24",),
        hosts=[Host(ip="192.168.1.1", methods=frozenset({DiscoveryMethod.PING}))],
        started_at=now,
        finished_at=now,
        duration_s=1.0,
        probed=254,
    )


def stress_report() -> StressReport:
    now = datetime(2026, 11, 11, 12, 0, 0)
    return StressReport(
        target="http://127.0.0.1:8080/",
        resolved_ip="127.0.0.1",
        method=StressMethod.HTTP,
        scope="loopback",
        started_at=now,
        finished_at=now,
        duration_s=1.0,
        planned_duration_s=1.0,
        concurrency=5,
        rate=10,
        timeout=1.0,
        attempts=10,
        successes=10,
        failures=0,
        timeouts=0,
        http_errors=0,
        bytes_sent=1,
        bytes_received=1,
        latency_min_ms=1.0,
        latency_mean_ms=1.0,
        latency_p50_ms=1.0,
        latency_p90_ms=1.0,
        latency_p99_ms=1.0,
        latency_max_ms=1.0,
        error_counts={},
        status_codes={200: 10},
        samples=[],
    )


class HistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "runs.db"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_records_and_lists_runs(self) -> None:
        with HistoryStore(self.path) as store:
            scan_id = store.record_scan(scan_report())
            stress_id = store.record_stress(stress_report())
            rows = store.runs()
            self.assertEqual([row["id"] for row in rows], [stress_id, scan_id])
            self.assertEqual(rows[0]["kind"], "stress")
            self.assertEqual(rows[0]["primary_count"], 10)
            self.assertEqual(rows[1]["primary_count"], 1)

    def test_kind_filter_and_limit(self) -> None:
        with HistoryStore(self.path) as store:
            store.record_scan(scan_report())
            store.record_scan(scan_report())
            store.record_stress(stress_report())
            self.assertEqual(len(store.runs(kind="scan")), 2)
            self.assertEqual(len(store.runs(kind="stress")), 1)
            self.assertEqual(len(store.runs(limit=1)), 1)

    def test_payload_round_trips(self) -> None:
        with HistoryStore(self.path) as store:
            run_id = store.record_scan(scan_report())
            payload = store.payload(run_id)
            self.assertIsNotNone(payload)
            self.assertEqual(payload["summary"]["hosts_online"], 1)
            self.assertIsNone(store.payload(9999))

    def test_database_is_reopened(self) -> None:
        with HistoryStore(self.path) as store:
            store.record_scan(scan_report())
        with HistoryStore(self.path) as store:
            self.assertEqual(len(store.runs()), 1)


if __name__ == "__main__":
    unittest.main()
