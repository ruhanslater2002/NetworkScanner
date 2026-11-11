"""Rich presentation for authorised load tests.

The engine never imports Rich; this module owns every visual decision, from the
authorization notice to the live dashboard and the closing verdict.
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from .constants import APP_NAME, VERSION
from .stress import StressPlan, StressReport, StressSnapshot

_BLOCKS = "▁▂▃▄▅▆▇█"
_SPARK_WIDTH = 48
_MAX_SAMPLES = 600


class StressLive:
    """Live dashboard implementing :class:`netscan.stress.StressReporter`."""

    def __init__(self, console: Console) -> None:
        self.console = console
        self.plan: StressPlan | None = None
        self.report: StressReport | None = None
        self.snapshot: StressSnapshot | None = None
        self._samples: list[StressSnapshot] = []
        self._live = Live(
            Text("starting load test…", style="muted"),
            console=console,
            refresh_per_second=8,
            transient=True,
            vertical_overflow="visible",
        )

    def on_start(self, plan: StressPlan) -> None:
        self.plan = plan
        self._live.start()

    def on_tick(self, snapshot: StressSnapshot) -> None:
        self.snapshot = snapshot
        self._samples.append(snapshot)
        if len(self._samples) > _MAX_SAMPLES:
            del self._samples[: len(self._samples) - _MAX_SAMPLES]
        self._live.update(self._render())

    def on_finish(self, report: StressReport) -> None:
        self.report = report
        self._live.update(self._render())
        self._live.stop()

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------
    def _render(self):
        if self.plan is None:
            return Text("starting load test…", style="muted")

        plan = self.plan
        snapshot = self.snapshot
        elapsed = snapshot.elapsed_s if snapshot else 0.0
        if self.report is not None:
            elapsed = min(self.report.duration_s, plan.duration)

        header = Table.grid(expand=True)
        header.add_column(ratio=1)
        header.add_column(justify="right", no_wrap=True)
        title = Text()
        title.append("TARGET  ", style="muted")
        title.append(plan.display, style="ip")
        meta = Text()
        meta.append(plan.method.label, style="accent")
        meta.append("  ·  ", style="dim")
        meta.append(plan.resolved_ip, style="ip")
        meta.append("  ·  ", style="dim")
        meta.append(plan.scope, style="muted")
        header.add_row(title, meta)

        progress = ProgressBar(
            total=max(plan.duration, 0.001),
            completed=min(elapsed, plan.duration),
            width=None,
            complete_style="accent",
            finished_style="ok",
            pulse_style="accent",
        )
        timing = Text()
        timing.append(f"{elapsed:5.1f}s", style="ip")
        timing.append(f" / {plan.duration:g}s", style="muted")
        timing.append("   ", style="dim")
        timing.append(f"{max(plan.duration - elapsed, 0):4.1f}s left", style="muted")
        timing.append("   ", style="dim")
        if plan.rate is None:
            timing.append(f"{plan.concurrency} workers · unlimited rate", style="muted")
        else:
            timing.append(
                f"{plan.concurrency} workers · {plan.rate:,.0f} req/s cap",
                style="muted",
            )
        if plan.warmup:
            timing.append(f" · {plan.warmup:g}s warmup", style="muted")
        if plan.ramp:
            timing.append(f" · {plan.ramp:g}s ramp", style="muted")

        metrics = Table.grid(expand=True, padding=(0, 2))
        for _ in range(4):
            metrics.add_column(ratio=1)
        attempts = snapshot.attempts if snapshot else 0
        successes = snapshot.successes if snapshot else 0
        failures = snapshot.failures if snapshot else 0
        rps = snapshot.rps if snapshot else 0.0
        in_flight = snapshot.in_flight if snapshot else 0
        success_rate = snapshot.success_rate if snapshot else 0.0
        p50 = snapshot.p50_ms if snapshot else None
        p99 = snapshot.p99_ms if snapshot else None

        metrics.add_row(
            _metric("attempts", f"{attempts:,}", "ip"),
            _metric("responses", f"{successes:,}", "ok"),
            _metric("failures", f"{failures:,}", "err" if failures else "muted"),
            _metric("throughput", f"{rps:,.0f} req/s", "accent"),
        )
        metrics.add_row(
            _metric("success", _percent(success_rate), _rate_style(success_rate)),
            _metric("p50 latency", _ms(p50), "ip"),
            _metric("p99 latency", _ms(p99), _latency_style(p99)),
            _metric("in flight", f"{in_flight:,}", "muted"),
        )
        spark = Text()
        spark.append("throughput  ", style="muted")
        spark.append_text(_sparkline([sample.rps for sample in self._samples]))
        spark.append("  ", style="dim")
        spark.append("recent samples", style="dim")

        body = Group(header, Text(), progress, timing, Text(), metrics, Text(), spark)
        if snapshot and (snapshot.dropped or snapshot.schedule_lag_p99_ms):
            schedule = Text()
            schedule.append("scheduler  ", style="muted")
            schedule.append("dropped ", style="warn" if snapshot.dropped else "muted")
            schedule.append(f"{snapshot.dropped:,}", style="ip")
            schedule.append("   lag p99 ", style="muted")
            lag_style = (
                "warn"
                if snapshot.schedule_lag_p99_ms and snapshot.schedule_lag_p99_ms > 50
                else "ip"
            )
            schedule.append(_ms(snapshot.schedule_lag_p99_ms), style=lag_style)
            body = Group(body, Text(), schedule)
        if snapshot and (snapshot.errors or snapshot.statuses):
            body = Group(body, Text(), _diagnostics(snapshot))

        if self.report is None:
            border, title_text = "accent", Text("live load test", style="accent")
        elif self.report.aborted:
            border, title_text = "warn", Text("load test interrupted", style="warn")
        else:
            border, title_text = "ok", Text("load test complete", style="ok")
        return Panel(
            body,
            title=title_text,
            title_align="left",
            subtitle=Text("authorised single-origin test", style="dim"),
            subtitle_align="right",
            border_style=border,
            padding=(0, 2),
        )


class StressUI:
    """High-level console helpers for the load-test command."""

    def __init__(self, console: Console, *, quiet: bool = False) -> None:
        self.console = console
        self.quiet = quiet

    # ------------------------------------------------------------------
    # Before the run
    # ------------------------------------------------------------------
    def banner(self) -> None:
        if self.quiet:
            return

        header = Table.grid(expand=True)
        header.add_column(ratio=1)
        header.add_column(justify="right", no_wrap=True)
        brand = Text()
        brand.append("» ", style="accent")
        brand.append(f"{APP_NAME.upper()}  LOAD TEST", style="brand")
        brand.append("  authorised stress testing", style="muted")
        header.add_row(brand, Text(f"v{VERSION}", style="dim"))

        body = Group(
            header,
            Text("bounded single-origin traffic · TCP · HTTP · UDP", style="dim"),
        )
        self.console.print(Panel(body, box=box.ROUNDED, border_style="accent", padding=(0, 2)))
        self.console.print()

    def authorization_notice(self, plan: StressPlan) -> None:
        if self.quiet:
            return

        grid = Table.grid(padding=(0, 2))
        grid.add_column(justify="right", style="muted", no_wrap=True)
        grid.add_column()
        grid.add_row("target", Text(plan.display, style="ip"))
        grid.add_row("resolves to", Text(plan.resolved_ip, style="ip"))
        grid.add_row("scope", Text(plan.scope, style="warn" if plan.scope == "public" else "ok"))
        grid.add_row("pattern", Text(plan.method.label, style="accent"))
        rate = "unlimited (worker-bound)" if plan.rate is None else f"{plan.rate:,.0f} req/s cap"
        grid.add_row(
            "limits",
            Text(f"{plan.concurrency} workers · {rate} · {plan.duration:g}s", style="ip"),
        )
        if plan.warmup or plan.ramp:
            phases = []
            if plan.warmup:
                phases.append(f"{plan.warmup:g}s warmup")
            if plan.ramp:
                phases.append(f"{plan.ramp:g}s ramp")
            grid.add_row("phases", Text(" · ".join(phases), style="ip"))
        if plan.audit is not None:
            if plan.audit.operator:
                grid.add_row("operator", Text(plan.audit.operator, style="ip"))
            if plan.audit.authorization_ref:
                grid.add_row("authorization", Text(plan.audit.authorization_ref, style="ip"))
            if plan.audit.note:
                grid.add_row("note", Text(plan.audit.note, style="muted"))

        body = Group(
            Text("You are about to generate real traffic.", style="warn"),
            Text(),
            grid,
            Text(),
            Text(
                "Only test systems you own or are contractually authorised to test. "
                "Unauthorised load testing is illegal in most jurisdictions and can "
                "take a service offline.",
                style="muted",
            ),
        )
        self.console.print(
            Panel(
                body,
                title=Text("authorization required", style="warn"),
                title_align="left",
                border_style="warn",
                padding=(0, 2),
            )
        )
        self.console.print()

    def confirm(self) -> bool:
        """Interactive confirmation. Returns False when the operator declines."""
        if not self.console.is_terminal:
            self.console.print(
                Text(
                    "non-interactive shell: pass --yes to confirm authorization",
                    style="err",
                )
            )
            return False
        self.console.print(
            Text("Type 'yes' to confirm you are authorised to test this target.", style="muted")
        )
        try:
            answer = self.console.input("  confirm › ")
        except EOFError:
            return False
        return answer.strip().lower() in {"yes", "y"}

    # ------------------------------------------------------------------
    # After the run
    # ------------------------------------------------------------------
    def summary(self, report: StressReport, export_path: str | None = None) -> None:
        if self.quiet:
            return

        verdict, style = _verdict(report)
        grid = Table.grid(padding=(0, 2))
        grid.add_column(justify="right", style="muted", no_wrap=True)
        grid.add_column(justify="left", no_wrap=True)
        grid.add_column(justify="left", width=2)
        grid.add_column(justify="right", style="muted", no_wrap=True)
        grid.add_column(justify="left", no_wrap=True)

        metrics = [
            ("attempts", Text(f"{report.attempts:,}", style="ip")),
            ("responses", Text(f"{report.successes:,}", style="ok")),
            (
                "failures",
                Text(f"{report.failures:,}", style="err" if report.failures else "muted"),
            ),
            (
                "success rate",
                Text(_percent(report.success_rate), style=_rate_style(report.success_rate)),
            ),
            ("throughput", Text(f"{report.throughput:,.0f} req/s", style="accent")),
            ("duration", Text(f"{report.duration_s:.2f}s", style="ip")),
            ("payload sent", Text(_bytes(report.bytes_sent), style="ip")),
            ("payload received", Text(_bytes(report.bytes_received), style="ip")),
        ]
        for index in range(0, len(metrics), 2):
            left, right = metrics[index], metrics[index + 1]
            grid.add_row(left[0], left[1], "", right[0], right[1])

        latency = Table.grid(expand=True, padding=(0, 2))
        for _ in range(6):
            latency.add_column(ratio=1)
        latency.add_row(
            *(
                _metric(label, _ms(value), _latency_style(value))
                for label, value in (
                    ("min", report.latency_min_ms),
                    ("mean", report.latency_mean_ms),
                    ("p50", report.latency_p50_ms),
                    ("p90", report.latency_p90_ms),
                    ("p99", report.latency_p99_ms),
                    ("max", report.latency_max_ms),
                )
            )
        )

        body: list = [Text(verdict, style=style), Text(), grid, Text(), latency]

        if report.error_counts:
            errors = Text()
            errors.append("errors  ", style="muted")
            for name, count in sorted(
                report.error_counts.items(), key=lambda item: item[1], reverse=True
            )[:5]:
                errors.append(f"{name} ", style="warn")
                errors.append(f"{count:,}", style="ip")
                errors.append("   ", style="dim")
            body.extend((Text(), errors))

        if report.status_codes:
            statuses = Text()
            statuses.append("status  ", style="muted")
            for code, count in sorted(report.status_codes.items())[:6]:
                statuses.append(f"{code} ", style="err" if code >= 400 else "ok")
                statuses.append(f"{count:,}", style="ip")
                statuses.append("   ", style="dim")
            body.extend((Text(), statuses))

        if report.http_errors:
            body.extend(
                (
                    Text(),
                    Text(
                        f"{report.http_errors:,} responses were HTTP 4xx/5xx",
                        style="warn",
                    ),
                )
            )

        if report.slo_results:
            body.extend((Text(), _slo_block(report)))

        if report.dropped:
            body.extend(
                (
                    Text(),
                    Text(
                        f"{report.dropped:,} scheduled requests were dropped "
                        "because every worker was busy",
                        style="warn",
                    ),
                )
            )

        if export_path:
            saved = Text("saved to  ", style="muted")
            saved.append(export_path, style="accent")
            body.extend((Text(), saved))

        self.console.print()
        self.console.print(
            Panel(
                Group(*body),
                title=Text(
                    "test interrupted" if report.aborted else "test complete",
                    style="warn" if report.aborted else "ok",
                ),
                title_align="left",
                border_style="warn" if report.aborted else "ok",
                padding=(0, 2),
            )
        )

    # ------------------------------------------------------------------
    # Messages
    # ------------------------------------------------------------------
    def error(self, message: str, hint: str | None = None) -> None:
        body = Text(message, style="err")
        if hint:
            body.append("\n\n")
            body.append(hint, style="muted")
        self.console.print(
            Panel(
                body,
                title=Text("error", style="err"),
                title_align="left",
                border_style="err",
                padding=(0, 2),
            )
        )

    def interrupted(self) -> None:
        self.console.print()
        self.console.print(Text("  load test interrupted", style="warn"))

    def warn(self, message: str) -> None:
        self.console.print(Text(f"  ! {message}", style="warn"))

    def info(self, message: str) -> None:
        self.console.print(Text(f"  {message}", style="muted"))


# ----------------------------------------------------------------------
# Formatting helpers
# ----------------------------------------------------------------------
def _metric(label: str, value: str, style: str) -> Text:
    text = Text()
    text.append(f"{label}\n", style="muted")
    text.append(value, style=style)
    return text


def _sparkline(values: list[float], width: int = _SPARK_WIDTH) -> Text:
    if not values:
        return Text("·" * 8, style="dim")
    window = values[-width:]
    peak = max(window) or 1.0
    top = len(_BLOCKS) - 1
    rendered = "".join(
        _BLOCKS[min(top, max(0, int(round(value / peak * top))))] for value in window
    )
    return Text(rendered, style="accent")


def _slo_block(report: StressReport) -> Text:
    text = Text()
    text.append("SLOs  ", style="muted")
    text.append("all passed" if report.slo_ok else "breach", style="ok" if report.slo_ok else "err")
    for result in report.slo_results:
        text.append("\n  ")
        text.append("✓ " if result.ok else "✗ ", style="ok" if result.ok else "err")
        text.append(result.label, style="muted")
        text.append("  ")
        text.append(_slo_value(result.actual, result.unit), style="ip")
        comparator = "≥" if result.metric == "success_rate" else "≤"
        text.append(f"  {comparator} ", style="dim")
        text.append(_slo_value(result.threshold, result.unit), style="muted")
    return text


def _slo_value(value: float | None, unit: str) -> str:
    if value is None:
        return "—"
    if unit == "ms":
        return _ms(value)
    return _percent(value)


def _diagnostics(snapshot: StressSnapshot) -> Text:
    text = Text()
    if snapshot.errors:
        text.append("errors  ", style="muted")
        for name, count in sorted(snapshot.errors.items(), key=lambda item: item[1], reverse=True)[
            :4
        ]:
            text.append(f"{name} ", style="warn")
            text.append(f"{count:,}", style="ip")
            text.append("   ", style="dim")
    if snapshot.statuses:
        if text.plain:
            text.append("\n")
        text.append("status  ", style="muted")
        for code, count in sorted(snapshot.statuses.items())[:5]:
            text.append(f"{code} ", style="err" if code >= 400 else "ok")
            text.append(f"{count:,}", style="ip")
            text.append("   ", style="dim")
    return text


def _verdict(report: StressReport) -> tuple[str, str]:
    if report.aborted:
        return (
            f"Interrupted after {report.duration_s:.1f}s — partial results below.",
            "warn",
        )
    if report.attempts == 0:
        return ("No requests were sent. Check the target and rate limit.", "warn")
    if report.successes == 0:
        return ("The target did not answer a single request.", "err")
    if report.slo_results and not report.slo_ok:
        failed = sum(1 for result in report.slo_results if not result.ok)
        return (
            f"{failed} of {len(report.slo_results)} SLO check(s) breached — "
            "the service did not meet its objective.",
            "err",
        )
    if report.success_rate >= 0.995 and not report.http_errors:
        return (
            f"Service stayed responsive at {report.throughput:,.0f} req/s.",
            "ok",
        )
    if report.success_rate >= 0.95:
        return ("Service degraded slightly under load.", "warn")
    return ("Service degraded significantly under load.", "err")


def _rate_style(rate: float) -> str:
    if rate >= 0.995:
        return "ok"
    if rate >= 0.95:
        return "warn"
    return "err"


def _latency_style(value: float | None) -> str:
    if value is None:
        return "muted"
    if value < 50:
        return "ok"
    if value < 250:
        return "accent"
    return "warn"


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


def _percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def _bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KiB"
    return f"{value / (1024 * 1024):.1f} MiB"


__all__ = ["StressLive", "StressUI"]
