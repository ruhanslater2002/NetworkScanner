"""Console presentation layer built on Rich.

All visual decisions live here; the scan engine is unaware of the UI.
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from .constants import APP_NAME, APP_TAGLINE, TOP_PORTS, VERSION
from .models import DiscoveryMethod, Host, PortState, ScanConfig, ScanReport

THEME = Theme(
    {
        "brand": "bold bright_cyan",
        "heading": "bold cyan",
        "accent": "cyan",
        "ip": "bright_white",
        "mac": "bright_magenta",
        "port": "bright_yellow",
        "muted": "grey58",
        "dim": "grey42",
        "ok": "bold bright_green",
        "warn": "bold yellow",
        "err": "bold bright_red",
    }
)

_METHOD_ORDER = (DiscoveryMethod.PING, DiscoveryMethod.TCP, DiscoveryMethod.ARP)
_METHOD_STYLES = {
    DiscoveryMethod.PING: "ok",
    DiscoveryMethod.TCP: "accent",
    DiscoveryMethod.ARP: "mac",
}


class ScanProgress:
    """Live progress reporter for the scan engine."""

    def __init__(self, console: Console) -> None:
        self._progress = Progress(
            SpinnerColumn("line", style="accent"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(
                bar_width=None,
                complete_style="accent",
                finished_style="ok",
                pulse_style="accent",
            ),
            MofNCompleteColumn(),
            TextColumn("[muted]live[/] [ok]{task.fields[found]}[/]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
            refresh_per_second=12,
        )
        self._task_id: TaskID | None = None

    def on_start(self, total: int) -> None:
        self._progress.start()
        self._task_id = self._progress.add_task(
            "[muted]probing hosts[/]", total=max(total, 1), found=0
        )

    def on_host(self, ip: str) -> None:
        if self._task_id is not None:
            self._progress.update(self._task_id, description=f"[muted]probing[/] [ip]{ip}[/]")

    def on_progress(self, done: int, total: int, found: int) -> None:
        if self._task_id is not None:
            self._progress.update(self._task_id, completed=done, total=max(total, 1), found=found)

    def on_finish(self) -> None:
        if self._task_id is not None:
            self._progress.stop()
            self._task_id = None


class ConsoleUI:
    """High-level reporting helpers."""

    def __init__(self, console: Console, *, quiet: bool = False) -> None:
        self.console = console
        self.quiet = quiet

    # ------------------------------------------------------------------
    # Pre-scan
    # ------------------------------------------------------------------
    def banner(self) -> None:
        if self.quiet:
            return

        header = Table.grid(expand=True)
        header.add_column(justify="left", ratio=1)
        header.add_column(justify="right", no_wrap=True)

        brand = Text()
        brand.append("» ", style="accent")
        brand.append(APP_NAME.upper(), style="brand")
        brand.append("  ")
        brand.append(APP_TAGLINE, style="muted")
        header.add_row(brand, Text(f"v{VERSION}", style="dim"))

        body = Group(
            header,
            Text("async ICMP · TCP · ARP discovery", style="dim"),
        )
        self.console.print(
            Panel(
                body,
                box=box.ROUNDED,
                border_style="accent",
                padding=(0, 2),
            )
        )
        self.console.print()

    def configuration(self, config: ScanConfig, target_label: str, address_count: int) -> None:
        if self.quiet:
            return

        grid = Table.grid(padding=(0, 2))
        grid.add_column(justify="right", style="muted", no_wrap=True)
        grid.add_column(no_wrap=True)

        targets = Text(target_label, style="ip")
        targets.append(f"   {address_count:,} address", style="muted")
        if address_count != 1:
            targets.append("es", style="muted")
        grid.add_row("targets", targets)

        if DiscoveryMethod.TCP not in config.methods:
            grid.add_row("ports", Text("not used", style="muted"))
        else:
            ports = Text(f"{len(config.ports):,}", style="ip")
            ports.append(" port" if len(config.ports) == 1 else " ports")
            ports.append(" selected", style="muted")
            if tuple(config.ports) == TOP_PORTS:
                ports.append("   curated common set", style="dim")
            grid.add_row("ports", ports)

        grid.add_row("timeout", Text(f"{config.timeout:g} s", style="ip"))

        concurrency = Text(f"{config.concurrency:,}", style="ip")
        concurrency.append(" probes in flight", style="muted")
        grid.add_row("concurrency", concurrency)

        grid.add_row("methods", _methods_text(config.methods))

        intensity = Text(config.intensity.label, style="ip")
        intensity.append("  probe pacing", style="muted")
        if config.intensity.value == "polite":
            gap = config.effective_host_delay * 1000
            intensity.append("  ·  ", style="dim")
            intensity.append(f"{gap:.0f} ms between batches", style="muted")
        grid.add_row("intensity", intensity)

        if config.rate is not None:
            rate = Text(f"{config.rate:,.0f}", style="ip")
            rate.append(" probes/s cap", style="muted")
            grid.add_row("rate limit", rate)

        if config.service_info or config.tls_info:
            parts = []
            if config.service_info:
                parts.append("banners")
            if config.tls_info:
                parts.append("TLS certificates")
            grid.add_row("services", Text(" + ".join(parts), style="ip"))

        dns = Text("on" if config.resolve_hostnames else "off", style="ip")
        dns.append("  reverse DNS", style="muted")
        grid.add_row("lookups", dns)

        self.console.print(Padding(grid, (0, 0, 0, 2)))
        self.console.print()

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------
    def results(self, report: ScanReport) -> None:
        if not report.hosts:
            self.no_hosts()
            return

        heading = Text()
        heading.append("live hosts", style="heading")
        heading.append(f"   {len(report.hosts):,}", style="ok")
        self.console.print(heading)
        self.console.print(self._host_table(report.hosts))

    def compact(self, report: ScanReport) -> None:
        """One line per host, ideal for logs and piping."""
        for host in report.hosts:
            line = Text()
            line.append(host.ip.ljust(16), style="ip")
            line.append((host.hostname or "-").ljust(26), style="white")
            line.append((host.mac or "-").ljust(18), style="mac")
            methods = "+".join(method.label for method in _ordered(host.methods))
            line.append(methods.ljust(11), style="muted")
            if host.open_ports:
                line.append(", ".join(str(port) for port in host.open_ports), style="port")
            self.console.print(line)

    def summary(self, report: ScanReport, export_path: str | None = None) -> None:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(justify="right", style="muted", no_wrap=True)
        grid.add_column(justify="left", no_wrap=True)
        grid.add_column(justify="left", width=2)
        grid.add_column(justify="right", style="muted", no_wrap=True)
        grid.add_column(justify="left", no_wrap=True)

        error_style = "warn" if report.errors else "muted"
        metrics = [
            ("hosts online", Text(f"{len(report.hosts):,}", style="ok")),
            ("duration", Text(_format_duration(report.duration_s), style="ip")),
            ("addresses probed", Text(f"{report.probed:,}", style="ip")),
            ("throughput", Text(f"{report.rate:.1f} hosts/s", style="ip")),
            ("found by", _method_counts_text(report.hosts_by_method)),
            ("probe errors", Text(f"{report.errors:,}", style=error_style)),
        ]
        for index in range(0, len(metrics), 2):
            left, right = metrics[index], metrics[index + 1]
            grid.add_row(left[0], left[1], "", right[0], right[1])

        states = report.port_states
        if any(states.values()):
            grid.add_row(
                "ports",
                _port_states_text(states),
                "",
                "services",
                Text(f"{report.service_count:,}", style="ip"),
            )

        body: list = [grid]
        if export_path:
            saved = Text("saved to  ", style="muted")
            saved.append(export_path, style="accent")
            body.extend((Text(), saved))

        self.console.print()
        self.console.print(
            Panel(
                Group(*body),
                title=Text("scan complete", style="ok"),
                title_align="left",
                border_style="ok",
                padding=(0, 2),
            )
        )

    def no_hosts(self) -> None:
        body = Group(
            Text("No hosts answered the probe set.", style="warn"),
            Text(),
            Text("Things worth trying:", style="muted"),
            Text("  ·  confirm you are on the same subnet as the target", style="muted"),
            Text("  ·  raise the wait time with --timeout 2", style="muted"),
            Text("  ·  add local layer-2 discovery with --method arp", style="muted"),
            Text("  ·  probe services explicitly, e.g. --ports 22,80,443", style="muted"),
        )
        self.console.print()
        self.console.print(
            Panel(
                body,
                title=Text("no live hosts", style="warn"),
                title_align="left",
                border_style="warn",
                padding=(0, 2),
            )
        )

    # ------------------------------------------------------------------
    # Watch mode
    # ------------------------------------------------------------------
    def changes(
        self,
        added: list[Host],
        removed: list[Host],
    ) -> None:
        if not added and not removed:
            return

        self.console.print()
        table = Table(
            box=box.SIMPLE,
            show_header=False,
            pad_edge=False,
            padding=(0, 2),
        )
        table.add_column(width=2)
        table.add_column(style="ip", no_wrap=True)
        table.add_column(style="white", max_width=28, overflow="ellipsis")
        table.add_column(style="muted", no_wrap=True)

        for host in added:
            table.add_row(
                Text("+", style="ok"),
                Text(host.ip, style="ip"),
                Text(host.hostname) if host.hostname else Text("—", style="muted"),
                Text("joined", style="ok"),
            )
        for host in removed:
            table.add_row(
                Text("-", style="err"),
                Text(host.ip, style="ip"),
                Text(host.hostname) if host.hostname else Text("—", style="muted"),
                Text("left", style="err"),
            )

        self.console.print(table)

    def cycle_summary(
        self,
        report: ScanReport,
        cycle: int,
        added: int,
        removed: int,
        interval: float,
    ) -> None:
        line = Text()
        line.append(f"  cycle {cycle}", style="muted")
        line.append("  ·  ", style="dim")
        line.append(f"{len(report.hosts):,} online", style="ok")
        line.append("  ·  ", style="dim")
        line.append(f"+{added}", style="ok")
        line.append(" / ", style="dim")
        line.append(f"-{removed}", style="err" if removed else "muted")
        line.append("  ·  ", style="dim")
        line.append(f"{report.duration_s:.1f}s", style="ip")
        line.append("  ·  ", style="dim")
        line.append(f"next in {interval:g}s", style="muted")
        self.console.print(line)

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

    def warn(self, message: str) -> None:
        self.console.print(Text(f"  ! {message}", style="warn"))

    def info(self, message: str) -> None:
        self.console.print(Text(f"  {message}", style="muted"))

    def interrupted(self) -> None:
        self.console.print()
        self.console.print(Text("  scan interrupted", style="warn"))

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _host_table(self, hosts: list[Host]) -> Table:
        # Adapt the layout to the terminal instead of letting Rich squeeze every
        # column into an ellipsis on 80-column consoles.
        width = self.console.width
        show_service = width >= 150 and any(host.services for host in hosts)
        if width >= 136:
            show_index, show_mac, show_hostname = True, True, True
            hostname_width, ports_width = 28, 36
            method_header = "FOUND BY"
        elif width >= 112:
            show_index, show_mac, show_hostname = True, True, True
            hostname_width, ports_width = 22, 22
            method_header = "FOUND BY"
        elif width >= 92:
            show_index, show_mac, show_hostname = False, True, True
            hostname_width, ports_width = 16, 14
            method_header = "METHOD"
        elif width >= 80:
            show_index, show_mac, show_hostname = False, True, True
            hostname_width, ports_width = 10, 9
            method_header = "METHOD"
        elif width >= 60:
            show_index, show_mac, show_hostname = False, False, True
            hostname_width, ports_width = 8, 8
            method_header = "METHOD"
        else:
            show_index, show_mac, show_hostname = False, False, False
            hostname_width, ports_width = 0, 8
            method_header = "METHOD"

        table = Table(
            box=box.SIMPLE_HEAD,
            show_edge=False,
            pad_edge=False,
            header_style="heading",
            border_style="dim",
            expand=False,
        )
        if show_index:
            table.add_column("#", justify="right", style="dim", width=3)
        table.add_column("IP", style="ip", no_wrap=True)
        if show_hostname:
            table.add_column(
                "HOSTNAME", max_width=hostname_width, overflow="ellipsis", no_wrap=True
            )
        if show_mac:
            table.add_column("MAC", style="mac", no_wrap=True)
        table.add_column("RTT", justify="right", no_wrap=True)
        table.add_column(method_header, no_wrap=True)
        table.add_column(
            "OPEN PORTS" if width >= 112 else "PORTS",
            max_width=ports_width,
            overflow="ellipsis",
            no_wrap=True,
        )
        if show_service:
            table.add_column(
                "SERVICE",
                max_width=28,
                overflow="ellipsis",
                no_wrap=True,
            )

        if ports_width >= 30:
            port_limit = 8
        elif ports_width >= 18:
            port_limit = 6
        elif ports_width >= 12:
            port_limit = 4
        else:
            port_limit = 2

        for index, host in enumerate(hosts, start=1):
            cells: list[Text | str] = []
            if show_index:
                cells.append(str(index))
            cells.append(Text(host.ip))
            if show_hostname:
                cells.append(_hostname_text(host.hostname, hostname_width))
            if show_mac:
                mac_cell = Text(host.mac, style="mac") if host.mac else Text("—", style="muted")
                cells.append(mac_cell)
            cells.extend(
                (
                    _latency_text(host.latency_ms),
                    _methods_text(host.methods),
                    _ports_text(host.open_ports, limit=port_limit),
                )
            )
            if show_service:
                cells.append(_service_text(host))
            table.add_row(*cells)
        return table


# ----------------------------------------------------------------------
# Formatting helpers
# ----------------------------------------------------------------------
def _ordered(methods: frozenset[DiscoveryMethod]) -> list[DiscoveryMethod]:
    return [method for method in _METHOD_ORDER if method in methods]


def _methods_text(methods: frozenset[DiscoveryMethod]) -> Text:
    text = Text()
    for index, method in enumerate(_ordered(methods)):
        if index:
            text.append(" · ", style="dim")
        text.append(method.label, style=_METHOD_STYLES[method])
    return text


def _method_counts_text(counts: dict[DiscoveryMethod, int]) -> Text:
    text = Text()
    for method in _METHOD_ORDER:
        count = counts.get(method, 0)
        if not count:
            continue
        if text.plain:
            text.append(" · ", style="dim")
        text.append(method.label, style=_METHOD_STYLES[method])
        text.append(f" {count:,}", style="ip")
    return text


def _latency_text(latency_ms: float | None) -> Text:
    if latency_ms is None:
        return Text("—", style="muted")
    label = f"{latency_ms:.1f} ms" if latency_ms < 10 else f"{latency_ms:,.0f} ms"
    if latency_ms < 25:
        style = "ok"
    elif latency_ms < 100:
        style = "accent"
    else:
        style = "warn"
    return Text(label, style=style)


def _ports_text(ports: tuple[int, ...], limit: int = 8) -> Text:
    if not ports:
        return Text("—", style="muted")
    separator = ", " if limit >= 4 else ","
    text = Text(separator.join(str(port) for port in ports[:limit]), style="port")
    if len(ports) > limit:
        text.append(f" +{len(ports) - limit}", style="muted")
    return text


def _port_states_text(counts: dict[PortState, int]) -> Text:
    text = Text()
    styles = {
        PortState.OPEN: "ok",
        PortState.CLOSED: "muted",
        PortState.FILTERED: "warn",
        PortState.ERROR: "err",
    }
    for state in (PortState.OPEN, PortState.CLOSED, PortState.FILTERED, PortState.ERROR):
        count = counts.get(state, 0)
        if not count:
            continue
        if text.plain:
            text.append(" · ", style="dim")
        text.append(state.value, style=styles[state])
        text.append(f" {count:,}", style="ip")
    return text or Text("—", style="muted")


def _service_text(host: Host) -> Text:
    if not host.services:
        return Text("—", style="muted")
    service = next(
        (
            item
            for item in host.services
            if item.server or item.banner or item.tls_subject or item.tls
        ),
        host.services[0],
    )
    label = f"{service.port} {service.summary}"
    return Text(label, style="muted")


def _hostname_text(hostname: str | None, width: int) -> Text:
    if not hostname:
        return Text("—", style="muted")
    if width <= 16 and "." in hostname:
        # Narrow terminals are better served by the short name than by an
        # FQDN truncated to its first few characters.
        short = hostname.split(".", 1)[0]
        if short:
            return Text(short)
    return Text(hostname)


def _format_duration(seconds: float) -> str:
    total = int(round(seconds))
    if total < 60:
        return f"{seconds:.2f}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m {secs:02d}s"
