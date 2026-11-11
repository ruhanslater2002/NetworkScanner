"""Command-line interface for NetScan."""

from __future__ import annotations

import argparse
import asyncio
import errno
import sys
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console

from .config import (
    ConfigError,
    apply_scan_config,
    default_config_path,
    provided_flags,
    resolve_config,
)
from .constants import APP_NAME, APP_TAGLINE, VERSION
from .engine import NetworkScanner, ProgressReporter
from .exporters import export, render_csv, render_json
from .history import HistoryError, HistoryStore
from .models import DiscoveryMethod, Host, Intensity, ScanConfig, ScanReport
from .ports import PortError, parse_ports
from .streams import discard_stdout, prepare_output_streams
from .targets import (
    TargetError,
    detect_local_target,
    enforce_scope,
    parse_excludes,
    parse_scope_file,
    parse_targets,
    public_targets,
)
from .ui import THEME, ConsoleUI, ScanProgress

_EXAMPLES = """\
examples:
  netscan                                 scan the local /24 automatically
  netscan 192.168.1.0/24                  scan a subnet
  netscan 10.0.0.5 -p 22,80,443           probe selected services
  netscan 192.168.1.10-50 --timeout 2     scan an address range, patiently
  netscan 192.168.1.0/24 -m arp           include layer-2 neighbours
  netscan 192.168.1.0/24 --intensity polite --services
                                          gentle pacing with banner detection
  netscan 10.0.0.0/24 --scope-file scope.txt --exclude 10.0.0.1
                                          enforce an allowlist and denylist
  netscan 192.168.1.0/24 -f json -o out.json
  netscan --watch 15                      re-scan every 15 seconds
  netscan diff old.json new.json          compare two discovery reports
  netscan history --db runs.db            list recorded scans and load tests
  netscan stress 127.0.0.1:8080 --authorize
                                          authorised load test (see stress --help)

exit codes:
  0  scan completed        2  invalid usage        130  interrupted
"""

_METHOD_ALIASES = {
    "icmp": DiscoveryMethod.PING,
    "ping": DiscoveryMethod.PING,
    "port": DiscoveryMethod.TCP,
    "tcp": DiscoveryMethod.TCP,
    "arp": DiscoveryMethod.ARP,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscan",
        description=(
            f"{APP_NAME} - {APP_TAGLINE}. Asynchronous ICMP, TCP and ARP "
            "discovery with a live console view."
        ),
        epilog=_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help="IP address, CIDR network, IPv4 range (192.168.1.10-20) or hostname. "
        "Defaults to the local network.",
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target_options",
        action="append",
        default=[],
        metavar="TARGET",
        help="additional target (may be repeated, combines with positional targets)",
    )

    connection = parser.add_argument_group("discovery")
    connection.add_argument(
        "-p",
        "--ports",
        default="top",
        metavar="SPEC",
        help="ports to probe: 'top', 'all', a range '1-1024', a list '22,80,443' "
        "or service names 'ssh,http'. Default: top.",
    )
    connection.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="wait time per probe (default: from --intensity, normally 1.0)",
    )
    connection.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=None,
        metavar="N",
        help="maximum probes in flight (default: from --intensity, normally 256)",
    )
    connection.add_argument(
        "--intensity",
        choices=("polite", "normal", "aggressive"),
        default="normal",
        help="probe pacing preset; polite batches 4 ports and adds a 50 ms gap (default: normal)",
    )
    connection.add_argument(
        "--rate",
        type=float,
        default=None,
        metavar="N",
        help="global probe cap per second (default: unlimited)",
    )
    connection.add_argument(
        "--host-delay",
        type=float,
        default=None,
        metavar="SECONDS",
        help="delay between port batches for each host (overrides the preset)",
    )
    connection.add_argument(
        "-m",
        "--method",
        action="append",
        choices=("ping", "tcp", "arp"),
        help="discovery method; repeat to combine. Default: ping + tcp",
    )
    connection.add_argument(
        "--no-dns",
        action="store_true",
        help="skip reverse DNS lookups (faster on large scans)",
    )
    connection.add_argument(
        "--services",
        action="store_true",
        help="grab banners and Server headers from open ports",
    )
    connection.add_argument(
        "--tls-info",
        action="store_true",
        help="collect TLS certificate subject, issuer and expiry from open ports",
    )

    scope = parser.add_argument_group("scope and safety")
    scope.add_argument(
        "--scope-file",
        metavar="PATH",
        help="allowlist of CIDRs/addresses/ranges; targets outside it are refused",
    )
    scope.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="SPEC",
        help="address, CIDR or range to exclude (may be repeated)",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "-f",
        "--format",
        choices=("auto", "table", "compact", "json", "csv", "txt", "html"),
        default="auto",
        help="output format; inferred from --output extension when omitted",
    )
    output.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="write the report to a file (json, csv, txt or a standalone html "
        "report); created if needed",
    )
    output.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="no banner, no progress, no summary - results only",
    )
    output.add_argument(
        "--db",
        metavar="PATH",
        help="append this run to a SQLite history database",
    )

    behaviour = parser.add_argument_group("behaviour")
    behaviour.add_argument(
        "-w",
        "--watch",
        nargs="?",
        type=float,
        const=10.0,
        metavar="SECONDS",
        help="keep scanning and report hosts joining or leaving (default: 10s)",
    )
    behaviour.add_argument(
        "--config",
        metavar="PATH",
        help="TOML config file (default: netscan.toml in the current directory)",
    )
    behaviour.add_argument(
        "--profile",
        metavar="NAME",
        help="named profile from the config file",
    )
    behaviour.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colours",
    )
    behaviour.add_argument(
        "--debug",
        action="store_true",
        help="show full tracebacks when something goes wrong",
    )
    behaviour.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="accepted for compatibility; progress is shown by default",
    )
    behaviour.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    # Legacy flag from the 1.x CLI, kept working but out of normal help output.
    parser.add_argument(
        "-s",
        "--scanner",
        action="append",
        choices=("icmp", "port", "arp"),
        help=argparse.SUPPRESS,
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point that survives a closed pipe (e.g. ``netscan | head``)."""
    try:
        return _main(argv)
    except BrokenPipeError:
        discard_stdout()
        return 0
    except OSError as exc:
        # Windows reports a closed pipe as EINVAL rather than EPIPE.
        if exc.errno not in {errno.EPIPE, errno.EINVAL, errno.EBADF}:
            raise
        discard_stdout()
        return 0


def _main(argv: Sequence[str] | None = None) -> int:
    # ``stress`` is a sub-command rather than a positional target so the
    # discovery CLI keeps its flat, backwards-compatible interface.
    arguments = list(argv) if argv is not None else sys.argv[1:]
    if arguments and arguments[0] in {"stress", "load", "loadtest"}:
        from .stress_cli import main as stress_main

        return stress_main(arguments[1:])
    if arguments and arguments[0] == "diff":
        from .diff_cli import main as diff_main

        return diff_main(arguments[1:])
    if arguments and arguments[0] == "history":
        from .history_cli import main as history_main

        return history_main(arguments[1:])

    prepare_output_streams()
    args = build_parser().parse_args(argv)

    # ``legacy_windows=False`` keeps Rich on the Unicode path. Python's Windows
    # console uses WriteConsoleW, and redirected output is UTF-8 after the
    # reconfigure above, so box drawing and symbols render everywhere.
    # ``emoji=False`` is required: Rich rewrites ``:xx:`` sequences inside plain
    # strings, which mangles MAC addresses (``4c:49:29:ab:...`` becomes an
    # emoji). Our content is data, never emoji shortcodes.
    console = Console(
        theme=THEME,
        no_color=args.no_color,
        highlight=False,
        legacy_windows=False,
        emoji=False,
    )
    ui = ConsoleUI(console, quiet=args.quiet)

    try:
        config_path = Path(args.config).expanduser() if args.config else default_config_path()
        scan_defaults, _ = resolve_config(config_path, args.profile)
        apply_scan_config(args, scan_defaults, provided_flags(arguments))
    except ConfigError as exc:
        ui.error(str(exc), "See README.md for the netscan.toml format.")
        return 2

    fmt = _resolve_format(args)
    to_stdout = fmt in {"json", "csv"} and not args.output

    if fmt == "html" and not args.output:
        ui.error(
            "HTML reports must be written to a file",
            "Use --output report.html, or choose json/csv for streaming output.",
        )
        return 2

    if args.watch is not None and to_stdout:
        ui.error(
            "--watch cannot stream JSON or CSV to the terminal",
            "Use table output, or write the report to a file with --output.",
        )
        return 2

    auto_target = not args.targets and not args.target_options
    target_specs = [*args.targets, *args.target_options]
    if auto_target:
        try:
            target_specs = [detect_local_target()]
        except TargetError as exc:
            ui.error(str(exc))
            return 2

    try:
        intensity = Intensity(args.intensity)
        timeout = args.timeout if args.timeout is not None else intensity.timeout
        concurrency = args.concurrency if args.concurrency is not None else intensity.concurrency
        targets = parse_targets(target_specs)
        allow = parse_scope_file(args.scope_file) if args.scope_file else []
        deny = parse_excludes(args.exclude)
        enforce_scope(targets, allow, deny)
        ports = parse_ports(args.ports)
        config = ScanConfig(
            targets=tuple(target_specs),
            ports=ports,
            timeout=timeout,
            concurrency=concurrency,
            methods=_resolve_methods(args),
            resolve_hostnames=not args.no_dns,
            intensity=intensity,
            rate=args.rate,
            host_delay=args.host_delay,
            service_info=args.services,
            tls_info=args.tls_info,
        )
        if args.watch is not None and args.watch <= 0:
            raise ValueError("--watch interval must be greater than zero")
    except (TargetError, PortError, ValueError) as exc:
        ui.error(str(exc), _hint_for(exc))
        return 2

    if not args.quiet and not to_stdout:
        ui.banner()
        ui.configuration(config, _target_label(target_specs, auto_target), len(targets))
        external = public_targets(targets)
        if external:
            ui.warn(
                f"{len(external):,} public address(es) in scope — only scan systems "
                "you own or have explicit written permission to test"
            )
        if len(ports) > 1024:
            ui.warn(f"{len(ports):,} ports per host — this scan will take considerably longer")

    scanner = NetworkScanner(config)
    show_progress = not args.quiet and not to_stdout

    try:
        if args.watch is not None:
            asyncio.run(
                _watch(
                    scanner,
                    ui,
                    args.watch,
                    show_progress=show_progress,
                    output=args.output,
                    fmt=fmt,
                )
            )
            return 0

        reporter: ProgressReporter | None = ScanProgress(console) if show_progress else None
        report = asyncio.run(scanner.scan(reporter))
    except KeyboardInterrupt:
        ui.interrupted()
        return 130
    except Exception as exc:
        if args.debug:
            raise
        ui.error(
            f"scan failed: {exc}",
            "Re-run with --debug to see the full traceback.",
        )
        return 1

    _emit(report, args, ui, fmt, to_stdout)
    if args.db:
        try:
            with HistoryStore(args.db) as store:
                run_id = store.record_scan(report)
            if not args.quiet:
                ui.info(f"recorded run #{run_id} in {args.db}")
        except HistoryError as exc:
            ui.warn(str(exc))
    return 0


# ----------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------
def _emit(
    report: ScanReport,
    args: argparse.Namespace,
    ui: ConsoleUI,
    fmt: str,
    to_stdout: bool,
) -> None:
    if to_stdout:
        payload = render_json(report) if fmt == "json" else render_csv(report)
        sys.stdout.write(payload if payload.endswith("\n") else payload + "\n")
        return

    # ``--quiet`` with a file destination means "script mode": no console noise.
    silent = args.quiet and bool(args.output)
    if not silent:
        if fmt == "compact":
            ui.compact(report)
        else:
            ui.results(report)

    export_path = None
    if args.output:
        try:
            export_path = str(export(report, args.output, fmt))
        except OSError as exc:
            ui.error(f"could not write '{args.output}': {exc}")

    if not args.quiet:
        ui.summary(report, export_path)
    elif export_path and not silent:
        ui.info(f"saved to {export_path}")


async def _watch(
    scanner: NetworkScanner,
    ui: ConsoleUI,
    interval: float,
    *,
    show_progress: bool,
    output: str | None = None,
    fmt: str = "table",
) -> None:
    previous: dict[str, Host] | None = None
    cycle = 0

    while True:
        cycle += 1
        reporter = ScanProgress(ui.console) if show_progress else None
        report = await scanner.scan(reporter)
        current = {host.ip: host for host in report.hosts}

        saved: str | None = None
        if output:
            try:
                saved = str(export(report, output, fmt))
            except OSError as exc:
                ui.warn(f"could not write '{output}': {exc}")
                output = None

        if previous is None:
            if not ui.quiet:
                ui.results(report)
                ui.summary(report, saved)
        else:
            added = [current[ip] for ip in current.keys() - previous.keys()]
            removed = [previous[ip] for ip in previous.keys() - current.keys()]
            added.sort(key=lambda host: host.sort_key)
            removed.sort(key=lambda host: host.sort_key)
            if added or removed:
                ui.changes(added, removed)
            if not ui.quiet:
                ui.cycle_summary(report, cycle, len(added), len(removed), interval)

        previous = current
        await asyncio.sleep(interval)


# ----------------------------------------------------------------------
# Argument helpers
# ----------------------------------------------------------------------
def _resolve_format(args: argparse.Namespace) -> str:
    fmt = (args.format or "auto").lower()
    if fmt != "auto":
        return fmt

    if args.output:
        suffix = Path(args.output).suffix.lower().lstrip(".")
        if suffix in {"json", "csv", "txt", "html"}:
            return suffix
        if suffix == "text":
            return "txt"
    return "table"


def _resolve_methods(args: argparse.Namespace) -> frozenset[DiscoveryMethod]:
    names = [*(args.method or []), *(args.scanner or [])]
    if not names:
        return frozenset({DiscoveryMethod.PING, DiscoveryMethod.TCP})
    return frozenset(_METHOD_ALIASES[name] for name in names)


def _target_label(specs: list[str], auto: bool) -> str:
    if len(specs) == 1:
        label = specs[0]
        return f"{label}  (auto)" if auto else label
    shown = ", ".join(specs[:3])
    if len(specs) > 3:
        shown += f" +{len(specs) - 3} more"
    return shown


def _hint_for(exc: Exception) -> str | None:
    if isinstance(exc, TargetError):
        return (
            "Try a single address, a CIDR such as 192.168.1.0/24, or a range "
            "such as 192.168.1.10-50. Scope and exclude files use the same syntax."
        )
    if isinstance(exc, PortError):
        return "Try --ports top, --ports 22,80,443 or --ports 1-1024."
    if isinstance(exc, ValueError):
        return "Check --timeout, --concurrency, --rate, --host-delay and --watch for valid values."
    return None


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
