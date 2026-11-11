"""``netscan history`` - inspect the local SQLite run log."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .history import HistoryError, HistoryStore
from .streams import prepare_output_streams
from .ui import THEME

DEFAULT_DB = "netscan-history.db"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscan history",
        description="List scans and load tests recorded in a local SQLite database.",
    )
    parser.add_argument(
        "--db",
        default=DEFAULT_DB,
        metavar="PATH",
        help=f"history database (default: {DEFAULT_DB})",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        metavar="N",
        help="number of recent runs to show (default: 20)",
    )
    parser.add_argument(
        "--kind",
        choices=("scan", "stress"),
        help="show only one kind of run",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON",
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    prepare_output_streams()
    args = build_parser().parse_args(argv)
    console = Console(
        theme=THEME,
        no_color=args.no_color,
        highlight=False,
        legacy_windows=False,
        emoji=False,
    )

    try:
        with HistoryStore(args.db) as store:
            rows = store.runs(kind=args.kind, limit=args.limit)
    except HistoryError as exc:
        console.print(
            Panel(
                Text(str(exc), style="err"),
                title=Text("history error", style="err"),
                title_align="left",
                border_style="err",
                padding=(0, 2),
            )
        )
        return 2

    if args.json:
        sys.stdout.write(json.dumps(rows, indent=2) + "\n")
        return 0

    if not rows:
        console.print()
        console.print(
            Panel(
                Text(
                    "No runs recorded yet. Add --db PATH to a scan or load test.",
                    style="muted",
                ),
                title=Text("history", style="accent"),
                title_align="left",
                border_style="accent",
                padding=(0, 2),
            )
        )
        return 0

    table = Table(
        box=box.SIMPLE_HEAVY,
        border_style="dim",
        header_style="muted",
        expand=True,
    )
    table.add_column("ID", justify="right", no_wrap=True)
    table.add_column("KIND", no_wrap=True)
    table.add_column("STARTED", no_wrap=True)
    table.add_column("TARGET", overflow="fold")
    table.add_column("COUNT", justify="right", no_wrap=True)
    table.add_column("DETAIL", justify="right", no_wrap=True)

    for row in rows:
        kind = row["kind"]
        if kind == "scan":
            count = f"{row['primary_count']:,} hosts"
            detail = f"{row['secondary_count']:,} probed"
            style = "ok"
        else:
            count = f"{row['primary_count']:,} reqs"
            detail = f"{row['secondary_count']:,} responses"
            style = "accent"
        table.add_row(
            str(row["id"]),
            Text(kind, style=style),
            str(row["started_at"]).replace("T", " "),
            Text(str(row["target"]), style="ip"),
            Text(count, style="ip"),
            Text(detail, style="muted"),
        )

    console.print()
    console.print(table)
    console.print(Text(f"{len(rows)} run(s) from {args.db}", style="muted"))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
