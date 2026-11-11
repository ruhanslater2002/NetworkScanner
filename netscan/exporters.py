"""Report serialisation: JSON, CSV and plain text."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from .constants import VERSION
from .models import DiscoveryMethod, Host, ScanReport, ServiceInfo
from .report_html import render_scan_html, render_stress_html
from .stress import StressReport

_CSV_FIELDS = (
    "ip",
    "hostname",
    "mac",
    "latency_ms",
    "methods",
    "open_ports",
    "port_states",
)

_STRESS_CSV_FIELDS = (
    "elapsed_s",
    "attempts",
    "responses",
    "failures",
    "rps",
    "p50_ms",
    "p99_ms",
)


def report_to_dict(report: ScanReport) -> dict:
    """Convert a report into a JSON-serialisable mapping."""
    counts = report.hosts_by_method
    return {
        "tool": "NetScan",
        "version": VERSION,
        "started_at": report.started_at.isoformat(timespec="seconds"),
        "finished_at": report.finished_at.isoformat(timespec="seconds"),
        "duration_s": round(report.duration_s, 3),
        "targets": list(report.targets),
        "summary": {
            "hosts_online": len(report.hosts),
            "addresses_probed": report.probed,
            "probe_errors": report.errors,
            "by_method": {method.value: count for method, count in counts.items() if count},
            "port_states": {
                state.value: count for state, count in report.port_states.items() if count
            },
            "services": report.service_count,
        },
        "hosts": [_host_to_dict(host) for host in report.hosts],
    }


def render_json(report: ScanReport) -> str:
    return json.dumps(report_to_dict(report), indent=2)


def render_csv(report: ScanReport) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=_CSV_FIELDS)
    writer.writeheader()
    for host in report.hosts:
        writer.writerow(
            {
                "ip": host.ip,
                "hostname": host.hostname or "",
                "mac": host.mac or "",
                "latency_ms": "" if host.latency_ms is None else round(host.latency_ms, 1),
                "methods": " ".join(sorted(method.value for method in host.methods)),
                "open_ports": " ".join(str(port) for port in host.open_ports),
                "port_states": " ".join(
                    f"{result.port}={result.state.value}" for result in host.port_details
                ),
            }
        )
    return buffer.getvalue()


def render_text(report: ScanReport) -> str:
    """Fixed-width plain-text table, suitable for logs and diffs."""
    header = (
        f"NetScan {VERSION}  |  {report.started_at:%Y-%m-%d %H:%M:%S}  |  "
        f"{len(report.hosts)} host(s)  |  {report.duration_s:.2f}s"
    )
    columns = (
        ("IP", 16),
        ("HOSTNAME", 24),
        ("MAC", 18),
        ("RTT", 9),
        ("FOUND BY", 12),
        ("OPEN PORTS", 32),
    )
    lines = [header, ""]
    lines.append("  ".join(title.ljust(width) for title, width in columns).rstrip())

    for host in report.hosts:
        hostname = (host.hostname or "-")[: columns[1][1] - 1]
        mac = host.mac or "-"
        rtt = "-" if host.latency_ms is None else f"{host.latency_ms:.1f} ms"
        methods = "+".join(method.label for method in _ordered_methods(host))
        ports = ", ".join(str(port) for port in host.open_ports) or "-"
        row = (
            host.ip.ljust(columns[0][1]),
            hostname.ljust(columns[1][1]),
            mac.ljust(columns[2][1]),
            rtt.ljust(columns[3][1]),
            methods.ljust(columns[4][1]),
            ports,
        )
        lines.append("  ".join(row).rstrip())

    if not report.hosts:
        lines.append("(no live hosts)")

    return "\n".join(lines) + "\n"


def export(report: ScanReport, destination: str | Path, fmt: str) -> Path:
    """Write the report and return the absolute path that was written."""
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        payload = render_json(report)
    elif fmt == "csv":
        payload = render_csv(report)
    elif fmt == "html":
        payload = render_scan_html(report)
    elif fmt in {"text", "txt", "table", "compact"}:
        payload = render_text(report)
    else:
        raise ValueError(f"unsupported export format '{fmt}'")

    path.write_text(payload, encoding="utf-8", newline="")
    return path.resolve()


# ----------------------------------------------------------------------
# Load-test reports
# ----------------------------------------------------------------------
def render_stress_json(report: StressReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def render_stress_csv(report: StressReport) -> str:
    """One row per timeline sample, which is what spreadsheets want."""
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=_STRESS_CSV_FIELDS)
    writer.writeheader()
    for sample in report.samples:
        writer.writerow(
            {
                "elapsed_s": round(sample.elapsed_s, 2),
                "attempts": sample.attempts,
                "responses": sample.successes,
                "failures": sample.failures,
                "rps": round(sample.rps, 2),
                "p50_ms": "" if sample.p50_ms is None else round(sample.p50_ms, 2),
                "p99_ms": "" if sample.p99_ms is None else round(sample.p99_ms, 2),
            }
        )
    return buffer.getvalue()


def export_stress(report: StressReport, destination: str | Path, fmt: str) -> Path:
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        payload = render_stress_json(report)
    elif fmt == "csv":
        payload = render_stress_csv(report)
    elif fmt == "html":
        payload = render_stress_html(report)
    else:
        raise ValueError(f"unsupported load-test export format '{fmt}'")

    path.write_text(payload, encoding="utf-8", newline="")
    return path.resolve()


def _host_to_dict(host: Host) -> dict:
    return {
        "ip": host.ip,
        "hostname": host.hostname,
        "mac": host.mac,
        "latency_ms": None if host.latency_ms is None else round(host.latency_ms, 1),
        "methods": sorted(method.value for method in host.methods),
        "open_ports": list(host.open_ports),
        "ports": [
            {
                "port": result.port,
                "state": result.state.value,
                "latency_ms": (None if result.latency_ms is None else round(result.latency_ms, 1)),
                "service": _service_to_dict(result.service),
            }
            for result in host.port_details
        ],
        "services": [_service_to_dict(service) for service in host.services],
    }


def _service_to_dict(service: ServiceInfo | None) -> dict | None:
    if service is None:
        return None
    return {
        "port": service.port,
        "banner": service.banner,
        "server": service.server,
        "tls": service.tls,
        "tls_subject": service.tls_subject,
        "tls_issuer": service.tls_issuer,
        "tls_expires": service.tls_expires,
        "tls_days_left": service.tls_days_left,
    }


def _ordered_methods(host: Host) -> list:
    order = (DiscoveryMethod.PING, DiscoveryMethod.TCP, DiscoveryMethod.ARP)
    return [method for method in order if method in host.methods]
