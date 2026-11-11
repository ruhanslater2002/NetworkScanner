"""``netscan diff`` - compare two JSON discovery reports."""

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

from .diff import DiffError, ScanDiff, diff_reports, load_report
from .streams import prepare_output_streams
from .ui import THEME


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscan diff",
        description=(
            "Compare two discovery reports produced with 'netscan -f json'. "
            "Shows hosts that appeared, disappeared or changed."
        ),
    )
    parser.add_argument("before", metavar="OLD.json", help="older report")
    parser.add_argument("after", metavar="NEW.json", help="newer report")
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a machine-readable diff instead of a table",
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
        before = load_report(args.before)
        after = load_report(args.after)
        diff = diff_reports(before, after)
    except DiffError as exc:
        console.print(
            Panel(
                Text(str(exc), style="err"),
                title=Text("diff error", style="err"),
                title_align="left",
                border_style="err",
                padding=(0, 2),
            )
        )
        return 2

    if args.json:
        payload = {
            "before_targets": list(diff.before_targets),
            "after_targets": list(diff.after_targets),
            "added": [_change_dict(change) for change in diff.added],
            "removed": [_change_dict(change) for change in diff.removed],
            "changed": [_change_dict(change) for change in diff.changed],
            "unchanged": diff.unchanged,
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 0

    _render(console, diff)
    return 0


def _render(console: Console, diff: ScanDiff) -> None:
    header = Table.grid(expand=True)
    header.add_column(ratio=1)
    header.add_column(justify="right", no_wrap=True)
    title = Text()
    title.append("REPORT DIFF  ", style="muted")
    title.append(f"{', '.join(diff.after_targets) or 'unknown targets'}", style="ip")
    counts = Text()
    counts.append(f"+{len(diff.added)}", style="ok")
    counts.append("  ", style="dim")
    counts.append(f"-{len(diff.removed)}", style="err")
    counts.append("  ", style="dim")
    counts.append(f"~{len(diff.changed)}", style="warn")
    counts.append("  ", style="dim")
    counts.append(f"={diff.unchanged}", style="muted")
    header.add_row(title, counts)

    if diff.empty:
        console.print()
        console.print(
            Panel(
                Text("No changes between the two reports.", style="ok"),
                title=Text("diff complete", style="ok"),
                title_align="left",
                border_style="ok",
                padding=(0, 2),
            )
        )
        return

    table = Table(
        box=box.SIMPLE_HEAVY,
        border_style="dim",
        header_style="muted",
        expand=True,
    )
    table.add_column("", width=2, no_wrap=True)
    table.add_column("ADDRESS", no_wrap=True, style="ip")
    table.add_column("CHANGE", no_wrap=True)
    table.add_column("DETAIL", overflow="fold")

    styles = {"added": ("+", "ok"), "removed": ("-", "err"), "changed": ("~", "warn")}
    for change in diff.changes:
        marker, style = styles[change.kind]
        detail = ", ".join(change.details) if change.details else _default_detail(change)
        table.add_row(
            Text(marker, style=style),
            Text(change.ip, style="ip"),
            Text(change.kind, style=style),
            Text(detail, style="muted"),
        )

    console.print()
    console.print(header)
    console.print()
    console.print(table)
    console.print(
        Text(
            f"{len(diff.added)} added · {len(diff.removed)} removed · "
            f"{len(diff.changed)} changed · {diff.unchanged} unchanged",
            style="muted",
        )
    )


def _default_detail(change) -> str:
    host = change.after or change.before
    ports = host.get("open_ports") or []
    if ports:
        return "open ports " + ", ".join(str(port) for port in ports)
    return "no open ports"


def _change_dict(change) -> dict:
    return {
        "ip": change.ip,
        "kind": change.kind,
        "details": list(change.details),
    }


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
