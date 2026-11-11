# ruff: noqa: E501
"""Self-contained HTML reports.

The output is a single file with inline CSS and SVG: no scripts, no external
fonts and no network requests. That makes it safe to attach to a ticket, open
from a USB stick or publish as a build artefact.
"""

from __future__ import annotations

import html
from datetime import datetime

from .constants import VERSION
from .models import DiscoveryMethod, Host, PortState, ScanReport
from .stress import StressReport

_ACCENT = "#4f8cff"
_OK = "#2fbf71"
_WARN = "#e0a33a"
_ERR = "#e05a5a"
_MUTED = "#7a8494"

_CSS = """
:root {
  --bg: #f5f7fb;
  --panel: #ffffff;
  --ink: #1c2333;
  --muted: #6b7280;
  --line: #e3e8f0;
  --accent: #2f6fed;
  --ok: #1f9d5b;
  --warn: #b7791f;
  --err: #c0392b;
  --chip: #eef3ff;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1420;
    --panel: #171e2d;
    --ink: #e7ecf5;
    --muted: #9aa4b5;
    --line: #263044;
    --accent: #7aa7ff;
    --ok: #4bd18d;
    --warn: #f0b45a;
    --err: #ff7b72;
    --chip: #1d2942;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    "Helvetica Neue", Arial, sans-serif;
}
.page { max-width: 1180px; margin: 0 auto; padding: 40px 24px 64px; }
.masthead { border-bottom: 1px solid var(--line); padding-bottom: 22px; margin-bottom: 26px; }
.brand { display: flex; align-items: baseline; gap: 10px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
.brand .mark { color: var(--accent); font-size: 20px; }
.brand .version { color: var(--muted); font-weight: 500; letter-spacing: .04em; }
h1 { font-size: 30px; line-height: 1.15; margin: 16px 0 8px; letter-spacing: -.02em; }
.lede { color: var(--muted); margin: 0; max-width: 70ch; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin: 26px 0; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 16px 18px; }
.card .label { color: var(--muted); font-size: 12px; letter-spacing: .08em; text-transform: uppercase; }
.card .value { font-size: 26px; font-weight: 650; margin-top: 6px; letter-spacing: -.01em; }
.card .hint { color: var(--muted); font-size: 12px; margin-top: 4px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 20px 22px; margin: 22px 0; overflow: hidden; }
.panel h2 { font-size: 16px; margin: 0 0 14px; letter-spacing: .02em; }
.panel h2 .sub { color: var(--muted); font-weight: 400; margin-left: 8px; font-size: 13px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th { text-align: left; color: var(--muted); font-size: 11px; letter-spacing: .09em; text-transform: uppercase; padding: 8px 10px; border-bottom: 1px solid var(--line); white-space: nowrap; }
td { padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: color-mix(in srgb, var(--chip) 55%, transparent); }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.muted { color: var(--muted); }
.chips { display: flex; flex-wrap: wrap; gap: 8px; }
.chip { display: inline-block; background: var(--chip); color: var(--accent); border-radius: 999px; padding: 3px 10px; font-size: 12px; font-weight: 600; }
.chip.ok { color: var(--ok); }
.chip.warn { color: var(--warn); }
.chip.err { color: var(--err); }
.chip.muted { color: var(--muted); }
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 18px; }
.kv { display: grid; grid-template-columns: max-content 1fr; gap: 6px 18px; font-size: 14px; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; }
.empty { color: var(--muted); padding: 18px 0 6px; }
.slo { display: grid; gap: 10px; }
.slo-row { display: flex; justify-content: space-between; gap: 16px; padding: 10px 12px; border: 1px solid var(--line); border-radius: 10px; }
.slo-row .name { font-weight: 600; }
.slo-row .detail { color: var(--muted); font-size: 13px; }
.badge { font-size: 12px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase; }
.badge.ok { color: var(--ok); }
.badge.err { color: var(--err); }
.chart { width: 100%; height: auto; display: block; }
.chart .axis { stroke: var(--line); stroke-width: 1; }
.chart .label { fill: var(--muted); font-size: 11px; }
.chart .area { fill: color-mix(in srgb, var(--accent) 16%, transparent); }
.chart .line { fill: none; stroke: var(--accent); stroke-width: 2.2; stroke-linejoin: round; }
footer { margin-top: 34px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--line); padding-top: 16px; }
@media (max-width: 640px) {
  .page { padding: 24px 14px 44px; }
  h1 { font-size: 24px; }
  .panel { padding: 16px 14px; }
  th, td { padding: 7px 6px; }
}
"""


def render_scan_html(report: ScanReport) -> str:
    """Render a discovery report as a standalone HTML document."""
    states = report.port_states
    cards = _cards(
        [
            ("Hosts online", f"{len(report.hosts):,}", "answered at least one probe"),
            ("Addresses probed", f"{report.probed:,}", f"{report.errors:,} probe errors"),
            ("Duration", _duration(report.duration_s), f"{report.rate:.1f} hosts/s"),
            ("Services", f"{report.service_count:,}", "banners or certificates"),
        ]
    )

    state_chips = "".join(
        _chip(
            f"{state.value} {states.get(state, 0):,}",
            {
                PortState.OPEN: "ok",
                PortState.CLOSED: "muted",
                PortState.FILTERED: "warn",
                PortState.ERROR: "err",
            }[state],
        )
        for state in (PortState.OPEN, PortState.CLOSED, PortState.FILTERED, PortState.ERROR)
        if states.get(state)
    )
    state_panel = (
        f'<section class="panel"><h2>Port states</h2>'
        f'<div class="chips">{state_chips}</div></section>'
        if state_chips
        else ""
    )

    rows: list[str] = []
    for host in report.hosts:
        mac = host.mac or "—"
        rows.append(
            "<tr>"
            f'<td class="mono">{_e(host.ip)}</td>'
            f"<td>{_e(host.hostname or '—')}</td>"
            f'<td class="mono muted">{_e(mac)}</td>'
            f"<td>{_methods(host)}</td>"
            f'<td class="num">{_ms(host.latency_ms)}</td>'
            f"<td>{_ports(host)}</td>"
            f"<td>{_service_cell(host)}</td>"
            "</tr>"
        )

    if rows:
        host_table = (
            '<section class="panel"><h2>Hosts '
            f'<span class="sub">{len(report.hosts):,} live</span></h2>'
            '<div style="overflow-x:auto"><table><thead><tr>'
            "<th>Address</th><th>Hostname</th><th>MAC</th><th>Found by</th>"
            "<th class='num'>RTT</th><th>Open ports</th><th>Service</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div></section>"
        )
    else:
        host_table = (
            '<section class="panel"><h2>Hosts</h2>'
            '<p class="empty">No live hosts answered during this scan.</p>'
            "</section>"
        )

    targets = ", ".join(report.targets) if report.targets else "local network"
    return _document(
        title="Network discovery report",
        kind="Discovery",
        lede=(
            f"Targets: {_e(targets)} · started "
            f"{report.started_at:%Y-%m-%d %H:%M:%S} · finished "
            f"{report.finished_at:%H:%M:%S}"
        ),
        body=cards + state_panel + host_table,
        generated=report.finished_at,
    )


def render_stress_html(report: StressReport) -> str:
    """Render a load-test report as a standalone HTML document."""
    verdict, verdict_class = _stress_verdict(report)
    cards = _cards(
        [
            ("Attempts", f"{report.attempts:,}", f"{report.attempt_rate:,.0f}/s offered"),
            ("Responses", f"{report.successes:,}", f"{report.throughput:,.0f}/s completed"),
            (
                "Success rate",
                f"{report.success_rate * 100:.1f}%",
                f"{report.failures:,} failures",
            ),
            ("Duration", _duration(report.duration_s), f"{report.concurrency} workers"),
        ]
    )

    summary_panel = (
        '<section class="panel"><h2>Run summary</h2>'
        f'<p class="badge {verdict_class}">{_e(verdict)}</p>'
        '<div class="grid2" style="margin-top:14px">'
        f"<dl class='kv'>{_stress_kv(report)}</dl>"
        f"<dl class='kv'>{_latency_kv(report)}</dl>"
        "</div></section>"
    )

    slo_panel = _slo_panel(report)
    chart_panel = _chart_panel(report)
    diagnostics = _diagnostics_panel(report)

    return _document(
        title="Load-test report",
        kind="Load test",
        lede=(
            f"Target: {_e(report.target)} · resolved to "
            f"{_e(report.resolved_ip)} ({_e(report.scope)}) · started "
            f"{report.started_at:%Y-%m-%d %H:%M:%S}"
        ),
        body=cards + summary_panel + slo_panel + chart_panel + diagnostics,
        generated=report.finished_at,
    )


# ----------------------------------------------------------------------
# Building blocks
# ----------------------------------------------------------------------
def _document(
    *,
    title: str,
    kind: str,
    lede: str,
    body: str,
    generated: datetime,
) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetScan · {_e(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<main class="page">
<header class="masthead">
  <div class="brand"><span class="mark">◈</span> NetScan
    <span class="version">v{VERSION}</span></div>
  <h1>{_e(title)}</h1>
  <p class="lede">{lede}</p>
</header>
{body}
<footer>Generated {generated:%Y-%m-%d %H:%M:%S} · {_e(kind)} report ·
NetScan v{VERSION} · authorised use only</footer>
</main>
</body>
</html>
"""


def _cards(items: list[tuple[str, str, str]]) -> str:
    cards = "".join(
        f'<div class="card"><div class="label">{_e(label)}</div>'
        f'<div class="value">{_e(value)}</div>'
        f'<div class="hint">{_e(hint)}</div></div>'
        for label, value, hint in items
    )
    return f'<section class="cards">{cards}</section>'


def _chip(text: str, style: str) -> str:
    return f'<span class="chip {style}">{_e(text)}</span>'


def _methods(host: Host) -> str:
    if not host.methods:
        return '<span class="muted">—</span>'
    order = (DiscoveryMethod.PING, DiscoveryMethod.TCP, DiscoveryMethod.ARP)
    chips = "".join(_chip(method.label, "muted") for method in order if method in host.methods)
    return f'<div class="chips">{chips}</div>'


def _ports(host: Host) -> str:
    if not host.open_ports:
        return '<span class="muted">—</span>'
    return "".join(_chip(str(port), "ok") for port in host.open_ports)


def _service_cell(host: Host) -> str:
    if not host.services:
        return '<span class="muted">—</span>'
    lines = []
    for service in host.services[:4]:
        label = f"{service.port} · {service.summary}"
        lines.append(f'<div class="mono">{_e(label)}</div>')
    if len(host.services) > 4:
        lines.append(f'<div class="muted">+{len(host.services) - 4} more</div>')
    return "".join(lines)


def _stress_kv(report: StressReport) -> str:
    rows = [
        ("Pattern", report.method.label),
        ("Resolved IP", report.resolved_ip),
        ("Scope", report.scope),
        ("Planned", f"{report.planned_duration_s:g}s"),
        ("Warmup", f"{report.warmup_s:g}s"),
        ("Ramp", f"{report.ramp_s:g}s"),
        ("Rate cap", "unlimited" if report.rate is None else f"{report.rate:,.0f}/s"),
        ("Bytes sent", _bytes(report.bytes_sent)),
        ("Bytes received", _bytes(report.bytes_received)),
        ("Dropped schedules", f"{report.dropped:,}"),
        ("Schedule lag p99", _ms(report.schedule_lag_p99_ms)),
    ]
    if report.audit is not None:
        if report.audit.operator:
            rows.append(("Operator", report.audit.operator))
        if report.audit.authorization_ref:
            rows.append(("Authorization", report.audit.authorization_ref))
        if report.audit.note:
            rows.append(("Note", report.audit.note))
    return "".join(f"<dt>{_e(label)}</dt><dd>{_e(value)}</dd>" for label, value in rows)


def _latency_kv(report: StressReport) -> str:
    rows = [
        ("Minimum", _ms(report.latency_min_ms)),
        ("Mean", _ms(report.latency_mean_ms)),
        ("p50", _ms(report.latency_p50_ms)),
        ("p90", _ms(report.latency_p90_ms)),
        ("p99", _ms(report.latency_p99_ms)),
        ("Maximum", _ms(report.latency_max_ms)),
        ("Timeouts", f"{report.timeouts:,}"),
        ("HTTP errors", f"{report.http_errors:,}"),
    ]
    return "".join(f"<dt>{_e(label)}</dt><dd>{_e(value)}</dd>" for label, value in rows)


def _slo_panel(report: StressReport) -> str:
    if not report.slo_results:
        return ""
    rows = []
    for result in report.slo_results:
        state = "ok" if result.ok else "err"
        comparator = "≥" if result.metric == "success_rate" else "≤"
        actual = _slo_value(result.actual, result.unit)
        threshold = _slo_value(result.threshold, result.unit)
        rows.append(
            f'<div class="slo-row"><div><div class="name">{_e(result.label)}</div>'
            f'<div class="detail">actual {_e(actual)} · target {comparator} '
            f"{_e(threshold)}</div></div>"
            f'<div class="badge {state}">{"pass" if result.ok else "fail"}</div></div>'
        )
    status = "all passed" if report.slo_ok else "breach"
    return (
        '<section class="panel"><h2>Service-level objectives'
        f'<span class="sub">{status}</span></h2>'
        f'<div class="slo">{"".join(rows)}</div></section>'
    )


def _chart_panel(report: StressReport) -> str:
    if not report.samples:
        return ""
    return (
        '<section class="panel"><h2>Offered throughput'
        '<span class="sub">requests per second</span></h2>'
        f"{_line_chart([sample.rps for sample in report.samples])}</section>"
    )


def _diagnostics_panel(report: StressReport) -> str:
    parts: list[str] = []
    if report.error_counts:
        rows = "".join(
            f"<tr><td>{_e(name)}</td><td class='num'>{count:,}</td></tr>"
            for name, count in sorted(
                report.error_counts.items(), key=lambda item: item[1], reverse=True
            )
        )
        parts.append(
            "<div><h2>Errors</h2><table><thead><tr><th>Class</th>"
            f"<th class='num'>Count</th></tr></thead><tbody>{rows}</tbody></table></div>"
        )
    if report.status_codes:
        rows = "".join(
            f"<tr><td class='mono'>{code}</td><td class='num'>{count:,}</td></tr>"
            for code, count in sorted(report.status_codes.items())
        )
        parts.append(
            "<div><h2>Status codes</h2><table><thead><tr><th>Code</th>"
            f"<th class='num'>Count</th></tr></thead><tbody>{rows}</tbody></table></div>"
        )
    if not parts:
        return ""
    return f'<section class="panel"><div class="grid2">{"".join(parts)}</div></section>'


def _line_chart(values: list[float]) -> str:
    width, height = 900, 240
    left, right, top, bottom = 48, 18, 16, 34
    plot_w = width - left - right
    plot_h = height - top - bottom
    peak = max(values) if values else 0.0
    peak = max(peak, 1.0)

    points: list[tuple[float, float]]
    if len(values) == 1:
        points = [(left, top + plot_h - values[0] / peak * plot_h)]
    else:
        points = [
            (
                left + index / (len(values) - 1) * plot_w,
                top + plot_h - value / peak * plot_h,
            )
            for index, value in enumerate(values)
        ]

    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    area = (
        f"M {points[0][0]:.1f},{top + plot_h:.1f} "
        + " ".join(f"L {x:.1f},{y:.1f}" for x, y in points)
        + f" L {points[-1][0]:.1f},{top + plot_h:.1f} Z"
    )
    grid = "".join(
        f'<line class="axis" x1="{left}" y1="{top + plot_h * fraction:.1f}" '
        f'x2="{width - right}" y2="{top + plot_h * fraction:.1f}"/>'
        for fraction in (0.0, 0.5, 1.0)
    )
    labels = "".join(
        f'<text class="label" x="{left - 8}" y="{top + plot_h * fraction + 4:.1f}" '
        f'text-anchor="end">{peak * (1 - fraction):,.0f}</text>'
        for fraction in (0.0, 0.5, 1.0)
    )
    return (
        f'<svg class="chart" viewBox="0 0 {width} {height}" '
        'role="img" aria-label="Throughput over time">'
        f"{grid}{labels}"
        f'<path class="area" d="{area}"/>'
        f'<polyline class="line" points="{line}"/>'
        f'<text class="label" x="{left}" y="{height - 8}">start</text>'
        f'<text class="label" x="{width - right}" y="{height - 8}" '
        'text-anchor="end">end</text>'
        "</svg>"
    )


# ----------------------------------------------------------------------
# Formatting
# ----------------------------------------------------------------------
def _stress_verdict(report: StressReport) -> tuple[str, str]:
    if report.aborted:
        return ("Interrupted — partial results", "err")
    if report.attempts == 0:
        return ("No requests were sent", "err")
    if report.successes == 0:
        return ("The target did not answer a single request", "err")
    if report.slo_results and not report.slo_ok:
        failed = sum(1 for result in report.slo_results if not result.ok)
        return (f"{failed} SLO check(s) breached", "err")
    if report.success_rate >= 0.995 and not report.http_errors:
        return ("Service stayed responsive under load", "ok")
    if report.success_rate >= 0.95:
        return ("Service degraded slightly under load", "warn")
    return ("Service degraded significantly under load", "err")


def _slo_value(value: float | None, unit: str) -> str:
    if value is None:
        return "—"
    if unit == "ms":
        return _ms(value)
    return f"{value * 100:.2f}%"


def _duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes, rest = divmod(seconds, 60)
    return f"{int(minutes)}m {rest:.0f}s"


def _ms(value: float | None) -> str:
    if value is None:
        return "—"
    if value < 0.01:
        return "<0.01 ms"
    if value < 1:
        return f"{value:.2f} ms"
    if value < 10:
        return f"{value:.1f} ms"
    return f"{value:,.0f} ms"


def _bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KiB"
    return f"{value / (1024 * 1024):.1f} MiB"


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


__all__ = ["render_scan_html", "render_stress_html"]
