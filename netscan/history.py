"""SQLite run history.

Every scan or load test can be appended to a small local database. The full
JSON report is stored alongside a few indexed columns, so history stays
queryable without locking the schema to today's report shape.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .exporters import report_to_dict
from .models import ScanReport
from .stress import StressReport


class HistoryError(ValueError):
    """Raised when the history database cannot be opened or queried."""


class HistoryStore:
    """Append-only store for scan and load-test reports."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(self.path)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    target TEXT NOT NULL,
                    primary_count INTEGER NOT NULL,
                    secondary_count INTEGER NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            self._connection.commit()
        except (OSError, sqlite3.Error) as exc:
            raise HistoryError(f"cannot open history '{path}': {exc}") from exc

    def record_scan(self, report: ScanReport) -> int:
        return self._insert(
            kind="scan",
            started_at=report.started_at.isoformat(timespec="seconds"),
            finished_at=report.finished_at.isoformat(timespec="seconds"),
            target=", ".join(report.targets) or "local network",
            primary_count=len(report.hosts),
            secondary_count=report.probed,
            payload=report_to_dict(report),
        )

    def record_stress(self, report: StressReport) -> int:
        return self._insert(
            kind="stress",
            started_at=report.started_at.isoformat(timespec="seconds"),
            finished_at=report.finished_at.isoformat(timespec="seconds"),
            target=report.target,
            primary_count=report.attempts,
            secondary_count=report.successes,
            payload=report.to_dict(),
        )

    def runs(self, *, kind: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        query = (
            "SELECT id, kind, started_at, finished_at, target, "
            "primary_count, secondary_count FROM runs"
        )
        parameters: list[object] = []
        if kind is not None:
            query += " WHERE kind = ?"
            parameters.append(kind)
        query += " ORDER BY id DESC LIMIT ?"
        parameters.append(max(1, limit))
        try:
            rows = self._connection.execute(query, parameters).fetchall()
        except sqlite3.Error as exc:
            raise HistoryError(f"cannot read history: {exc}") from exc
        return [dict(row) for row in rows]

    def payload(self, run_id: int) -> dict[str, Any] | None:
        try:
            row = self._connection.execute(
                "SELECT payload FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise HistoryError(f"cannot read history: {exc}") from exc
        if row is None:
            return None
        try:
            return json.loads(row["payload"])
        except json.JSONDecodeError:
            return None

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> HistoryStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _insert(
        self,
        *,
        kind: str,
        started_at: str,
        finished_at: str,
        target: str,
        primary_count: int,
        secondary_count: int,
        payload: dict[str, Any],
    ) -> int:
        try:
            cursor = self._connection.execute(
                """
                INSERT INTO runs
                    (kind, started_at, finished_at, target,
                     primary_count, secondary_count, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    kind,
                    started_at,
                    finished_at,
                    target,
                    primary_count,
                    secondary_count,
                    json.dumps(payload),
                ),
            )
            self._connection.commit()
        except sqlite3.Error as exc:
            raise HistoryError(f"cannot write history: {exc}") from exc
        return int(cursor.lastrowid or 0)


__all__ = ["HistoryError", "HistoryStore"]
