"""Command-line front-end for authorised load tests."""

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
    apply_stress_config,
    default_config_path,
    provided_flags,
    resolve_config,
)
from .constants import DEFAULT_STRESS_RATE, VERSION
from .exporters import export_stress, render_stress_csv, render_stress_json
from .history import HistoryError, HistoryStore
from .streams import discard_stdout, prepare_output_streams
from .stress import (
    AuditInfo,
    SloThresholds,
    StressConfig,
    StressError,
    StressMethod,
    StressReport,
    StressTester,
)
from .stress_ui import StressLive, StressUI
from .ui import THEME

_EXAMPLES = """\
examples:
  netscan stress 127.0.0.1:8080 --authorize
      a short TCP connect test against a local service

  netscan stress http://192.168.1.10/ --authorize --duration 30 -c 50
      sustained HTTP load with 50 workers for 30 seconds

  netscan stress 10.0.0.5:53 -m udp --authorize -r 2000 --payload-bytes 64
      paced UDP datagrams at 2,000 per second

  netscan stress https://staging.example.com/health --authorize --allow-public --yes
      non-interactive run against a host you are authorised to test

  netscan stress http://10.0.0.5:8080/api --authorize -r 500 --warmup 10 --ramp 20 \
      --slo-success 99.5 --slo-p99 250 --operator alice --authorization-ref CHG-1234
      warmed-up, ramped run gated on SLOs with an audit trail

  netscan stress http://127.0.0.1:8000 --authorize --keep-alive \
      --header "Accept: application/json" --basic-auth user:secret --expect-status 200
      realistic HTTP with connection reuse and expectations

safety:
  * --authorize is mandatory; there is no way to run without it
  * private, loopback and link-local targets are allowed by default
  * public targets additionally require --allow-public
  * redirects are followed only within the same origin
  * duration <= 600s, concurrency <= 512, rate <= 50,000/s, payload <= 1400 B

exit codes:
  0  test completed and SLOs passed
  1  no successful requests / failure
  2  invalid usage, missing authorization or refused safety check
  3  completed but an SLO threshold was breached
  130  interrupted
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscan stress",
        description=(
            "Authorised, bounded load testing for a service you own or are "
            "contracted to test. Single origin only: this is a load generator, "
            "not a botnet."
        ),
        epilog=_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        metavar="TARGET",
        help="host, host:port, http(s)://host/path, or [ipv6]:port",
    )

    traffic = parser.add_argument_group("traffic")
    traffic.add_argument(
        "-m",
        "--method",
        choices=("tcp", "http", "udp"),
        default=None,
        help="traffic pattern; inferred from the URL scheme (http/https -> http) when omitted",
    )
    traffic.add_argument(
        "-p",
        "--port",
        type=int,
        metavar="N",
        help="override the port taken from the target",
    )
    traffic.add_argument(
        "-d",
        "--duration",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="test length in seconds, max 600 (default: 10)",
    )
    traffic.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=25,
        metavar="N",
        help="parallel workers, max 512 (default: 25)",
    )
    traffic.add_argument(
        "-r",
        "--rate",
        type=float,
        default=DEFAULT_STRESS_RATE,
        metavar="N",
        help="global request cap per second; 0 means worker-bound "
        f"(default: {DEFAULT_STRESS_RATE:g}, max 50,000)",
    )
    traffic.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="per-request timeout, max 30 (default: 2)",
    )
    traffic.add_argument(
        "--path",
        default=None,
        metavar="PATH",
        help="override the HTTP request path (default: from the target, else /)",
    )
    traffic.add_argument(
        "--http-method",
        default="GET",
        metavar="VERB",
        help="HTTP verb (default: GET)",
    )
    traffic.add_argument(
        "--payload-bytes",
        type=int,
        default=64,
        metavar="N",
        help="UDP datagram size, max 1400 (default: 64)",
    )
    traffic.add_argument(
        "--warmup",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="traffic before measurement starts; excluded from statistics (default: 0)",
    )
    traffic.add_argument(
        "--ramp",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="linearly ramp the offered rate over this window (default: 0)",
    )

    http = parser.add_argument_group("HTTP realism")
    http.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="'NAME: VALUE'",
        help="add a request header (may be repeated)",
    )
    http.add_argument(
        "--basic-auth",
        metavar="USER:PASS",
        help="send HTTP basic authentication",
    )
    http.add_argument(
        "--expect-status",
        action="append",
        default=[],
        metavar="CODE[,CODE]",
        help="treat other status codes as failures (may be repeated)",
    )
    http.add_argument(
        "--expect-body",
        metavar="TEXT",
        help="require this text in the response body",
    )
    http.add_argument(
        "--keep-alive",
        action="store_true",
        help="reuse HTTP/1.1 connections between requests",
    )
    http.add_argument(
        "--follow-redirects",
        action="store_true",
        help="follow up to 3 redirects, but only within the same origin",
    )

    slo = parser.add_argument_group("service-level objectives")
    slo.add_argument(
        "--slo-success",
        type=float,
        metavar="PCT",
        help="minimum success rate, as a percentage (99.5) or fraction (0.995)",
    )
    slo.add_argument(
        "--slo-error",
        type=float,
        metavar="PCT",
        help="maximum error rate, as a percentage or fraction",
    )
    slo.add_argument(
        "--slo-timeout",
        type=float,
        metavar="PCT",
        help="maximum timeout rate, as a percentage or fraction",
    )
    slo.add_argument(
        "--slo-p99",
        type=float,
        metavar="MS",
        help="maximum p99 latency in milliseconds",
    )

    audit = parser.add_argument_group("audit trail")
    audit.add_argument("--operator", metavar="NAME", help="who ran the test")
    audit.add_argument(
        "--authorization-ref",
        metavar="REF",
        help="ticket, change or contract reference for the authorization",
    )
    audit.add_argument(
        "--note",
        metavar="TEXT",
        help="free-form note stored with the report",
    )

    tls = parser.add_argument_group("TLS")
    toggle = tls.add_mutually_exclusive_group()
    toggle.add_argument("--tls", dest="tls", action="store_true", help="force TLS")
    toggle.add_argument("--no-tls", dest="tls", action="store_false", help="force plaintext")
    parser.set_defaults(tls=None)
    tls.add_argument(
        "--insecure",
        action="store_true",
        help="do not verify TLS certificates (self-signed test endpoints)",
    )

    safety = parser.add_argument_group("authorization")
    safety.add_argument(
        "--authorize",
        action="store_true",
        help="confirm you own or are authorised to test the target (required)",
    )
    safety.add_argument(
        "--allow-public",
        action="store_true",
        help="permit public addresses; still requires written authorization",
    )
    safety.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="skip the interactive confirmation (automation)",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "-f",
        "--format",
        choices=("auto", "table", "json", "csv", "html"),
        default="auto",
        help="console or export format; inferred from --output when omitted",
    )
    output.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="write a JSON, CSV or standalone HTML report to a file",
    )
    output.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="no banner, dashboard or summary",
    )
    output.add_argument(
        "--db",
        metavar="PATH",
        help="append this run to a SQLite history database",
    )

    behaviour = parser.add_argument_group("behaviour")
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
    behaviour.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    behaviour.add_argument("--debug", action="store_true", help="show full tracebacks on errors")
    behaviour.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return _main(argv)
    except BrokenPipeError:
        discard_stdout()
        return 0
    except OSError as exc:
        if exc.errno not in {errno.EPIPE, errno.EINVAL, errno.EBADF}:
            raise
        discard_stdout()
        return 0


def _main(argv: Sequence[str] | None = None) -> int:
    prepare_output_streams()
    arguments = list(argv) if argv is not None else sys.argv[1:]
    args = build_parser().parse_args(arguments)

    console = Console(
        theme=THEME,
        no_color=args.no_color,
        highlight=False,
        legacy_windows=False,
        emoji=False,
    )
    ui = StressUI(console, quiet=args.quiet)

    try:
        config_path = Path(args.config).expanduser() if args.config else default_config_path()
        _, stress_defaults = resolve_config(config_path, args.profile)
        apply_stress_config(args, stress_defaults, provided_flags(arguments))
    except ConfigError as exc:
        ui.error(str(exc), "See README.md for the netscan.toml format.")
        return 2

    fmt = _resolve_format(args)
    to_stdout = fmt in {"json", "csv"} and not args.output
    silent = args.quiet or to_stdout

    if fmt == "html" and not args.output:
        ui.error(
            "HTML reports must be written to a file",
            "Use --output report.html, or choose json/csv for streaming output.",
        )
        return 2

    if not args.authorize:
        ui.error(
            "authorization is required before any traffic is generated",
            "Re-run with --authorize once you have confirmed you own the target "
            "or hold written permission to test it.",
        )
        return 2

    try:
        user, password = _parse_basic_auth(args.basic_auth)
        config = StressConfig(
            target=args.target,
            method=StressMethod(args.method) if args.method else _infer_method(args.target),
            port=args.port,
            duration=args.duration,
            concurrency=args.concurrency,
            rate=None if args.rate == 0 else args.rate,
            timeout=args.timeout,
            path=args.path,
            tls=args.tls,
            verify_tls=not args.insecure,
            http_method=args.http_method,
            payload_bytes=args.payload_bytes,
            authorized=True,
            allow_public=args.allow_public,
            warmup=args.warmup,
            ramp=args.ramp,
            headers=_parse_headers(args.header),
            http_user=user,
            http_password=password,
            expected_status=_parse_statuses(args.expect_status),
            expect_body=args.expect_body,
            keep_alive=args.keep_alive,
            follow_redirects=args.follow_redirects,
            slo=_build_slo(args),
            audit=_build_audit(args),
        )
    except (StressError, ValueError) as exc:
        ui.error(str(exc), _hint_for(exc))
        return 2

    tester = StressTester(config)
    try:
        plan = asyncio.run(tester.prepare())
    except (StressError, ValueError) as exc:
        ui.error(str(exc), _hint_for(exc))
        return 2

    if not silent:
        ui.banner()
        ui.authorization_notice(plan)

    if not args.yes and not ui.confirm():
        ui.info("aborted before any traffic was sent")
        return 2
    if not silent and plan.scope == "public":
        ui.warn(
            "public target: you are responsible for having written authorization "
            "on file for this address"
        )

    reporter = None if silent else StressLive(console)
    try:
        report = asyncio.run(tester.run(reporter))
    except KeyboardInterrupt:
        if not silent:
            partial = tester.last_report
            if partial is not None:
                ui.summary(partial)
            else:
                ui.interrupted()
        return 130
    except Exception as exc:
        if args.debug:
            raise
        ui.error(
            f"load test failed: {exc}",
            "Re-run with --debug to see the full traceback.",
        )
        return 1

    if to_stdout:
        payload = render_stress_json(report) if fmt == "json" else render_stress_csv(report)
        sys.stdout.write(payload if payload.endswith("\n") else payload + "\n")
        return _exit_code(report)

    export_path = None
    if args.output:
        export_format = fmt if fmt in {"json", "csv", "html"} else "json"
        try:
            export_path = str(export_stress(report, args.output, export_format))
        except (OSError, ValueError) as exc:
            ui.error(f"could not write '{args.output}': {exc}")

    if not args.quiet:
        ui.summary(report, export_path)
    if args.db:
        try:
            with HistoryStore(args.db) as store:
                run_id = store.record_stress(report)
            if not args.quiet:
                ui.info(f"recorded run #{run_id} in {args.db}")
        except HistoryError as exc:
            ui.warn(str(exc))
    return _exit_code(report)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _parse_headers(values: Sequence[str]) -> tuple[tuple[str, str], ...]:
    headers: list[tuple[str, str]] = []
    for raw in values:
        name, separator, value = raw.partition(":")
        if not separator or not name.strip():
            raise ValueError(f"invalid header '{raw}'; use 'Name: value'")
        headers.append((name.strip(), value.strip()))
    return tuple(headers)


def _parse_statuses(values: Sequence[str]) -> tuple[int, ...]:
    codes: list[int] = []
    for raw in values:
        for token in str(raw).split(","):
            token = token.strip()
            if not token:
                continue
            try:
                codes.append(int(token))
            except ValueError as exc:
                raise ValueError(f"invalid status code '{token}'") from exc
    return tuple(codes)


def _parse_basic_auth(value: str | None) -> tuple[str | None, str | None]:
    if value is None:
        return None, None
    user, separator, password = value.partition(":")
    if not separator or not user:
        raise ValueError("--basic-auth expects USER:PASS")
    return user, password


def _rate_fraction(value: float | None, name: str) -> float | None:
    if value is None:
        return None
    fraction = value / 100.0 if value > 1 else value
    if not 0.0 <= fraction <= 1.0:
        raise ValueError(f"{name} must be a percentage or a fraction between 0 and 1")
    return fraction


def _build_slo(args: argparse.Namespace) -> SloThresholds | None:
    thresholds = SloThresholds(
        min_success_rate=_rate_fraction(args.slo_success, "--slo-success"),
        max_error_rate=_rate_fraction(args.slo_error, "--slo-error"),
        max_timeout_rate=_rate_fraction(args.slo_timeout, "--slo-timeout"),
        max_p99_ms=args.slo_p99,
    )
    return thresholds if thresholds.configured else None


def _build_audit(args: argparse.Namespace) -> AuditInfo | None:
    audit = AuditInfo(
        operator=args.operator,
        authorization_ref=args.authorization_ref,
        note=args.note,
    )
    return audit if audit.configured else None


def _exit_code(report: StressReport) -> int:
    if report.slo_results and not report.slo_ok:
        return 3
    return 0 if report.successes else 1


def _resolve_format(args: argparse.Namespace) -> str:
    fmt = (args.format or "auto").lower()
    if fmt != "auto":
        return fmt
    if args.output:
        suffix = Path(args.output).suffix.lower().lstrip(".")
        if suffix in {"json", "csv", "html"}:
            return suffix
    return "table"


def _infer_method(target: str) -> StressMethod:
    """An ``http(s)://`` URL means an HTTP test unless told otherwise."""
    if target.strip().lower().startswith(("http://", "https://")):
        return StressMethod.HTTP
    return StressMethod.TCP


def _hint_for(exc: Exception) -> str | None:
    message = str(exc).lower()
    if "authorization" in message:
        return (
            "Load testing is only lawful against systems you own or have written "
            "permission to test."
        )
    if "public address" in message:
        return (
            "Use --allow-public only after confirming authorization; private, "
            "loopback and link-local targets work without it."
        )
    if "duration" in message or "concurrency" in message or "rate" in message:
        return (
            "Caps are 600s, 512 workers, 50,000 requests/s and 1400-byte "
            "datagrams. Lower the value and retry."
        )
    if "resolve" in message:
        return "Check the hostname, or pass an IP address directly."
    return "Run 'netscan stress --help' for the full option list."


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
