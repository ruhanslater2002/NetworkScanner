"""Compare two discovery reports.

The diff is intentionally about *observable change*: hosts that appeared or
disappeared, and hosts whose open ports, addresses or service banners changed.
It works on the JSON documents produced by ``netscan -f json``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


class DiffError(ValueError):
    """Raised when a report cannot be loaded or is not a discovery report."""


@dataclass(frozen=True, slots=True)
class HostChange:
    ip: str
    kind: str
    details: tuple[str, ...] = ()
    before: dict = field(default_factory=dict, compare=False)
    after: dict = field(default_factory=dict, compare=False)


@dataclass(slots=True)
class ScanDiff:
    before_targets: tuple[str, ...]
    after_targets: tuple[str, ...]
    changes: list[HostChange]
    unchanged: int = 0

    @property
    def added(self) -> list[HostChange]:
        return [change for change in self.changes if change.kind == "added"]

    @property
    def removed(self) -> list[HostChange]:
        return [change for change in self.changes if change.kind == "removed"]

    @property
    def changed(self) -> list[HostChange]:
        return [change for change in self.changes if change.kind == "changed"]

    @property
    def empty(self) -> bool:
        return not self.changes


def load_report(path: str | Path) -> dict:
    """Read a NetScan JSON report, with a helpful error for other formats."""
    report_path = Path(path).expanduser()
    try:
        text = report_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DiffError(f"cannot read '{path}': {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DiffError(f"'{path}' is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "hosts" not in data:
        raise DiffError(f"'{path}' is not a NetScan discovery report")
    if data.get("kind") == "load_test":
        raise DiffError("diff compares discovery reports, not load-test reports")
    return data


def diff_reports(before: dict, after: dict) -> ScanDiff:
    """Compare two parsed discovery reports."""
    old_hosts = _index(before.get("hosts"))
    new_hosts = _index(after.get("hosts"))

    changes: list[HostChange] = []
    unchanged = 0
    for ip in sorted(set(old_hosts) | set(new_hosts), key=_sort_key):
        old = old_hosts.get(ip)
        new = new_hosts.get(ip)
        if old is None and new is not None:
            changes.append(HostChange(ip=ip, kind="added", after=new))
        elif new is None and old is not None:
            changes.append(HostChange(ip=ip, kind="removed", before=old))
        elif old is not None and new is not None:
            details = _changes_between(old, new)
            if details:
                changes.append(
                    HostChange(
                        ip=ip,
                        kind="changed",
                        details=details,
                        before=old,
                        after=new,
                    )
                )
            else:
                unchanged += 1

    return ScanDiff(
        before_targets=tuple(before.get("targets") or ()),
        after_targets=tuple(after.get("targets") or ()),
        changes=changes,
        unchanged=unchanged,
    )


def render_diff_text(diff: ScanDiff) -> str:
    """Plain-text rendering, useful in CI logs and terminal pipes."""
    lines = [
        "NetScan report diff",
        f"  before: {', '.join(diff.before_targets) or '(unknown)'}",
        f"  after:  {', '.join(diff.after_targets) or '(unknown)'}",
        "",
    ]
    if diff.empty:
        lines.append("No changes.")
        return "\n".join(lines) + "\n"

    for change in diff.changes:
        if change.kind == "added":
            lines.append(f"+ {change.ip}  new host")
        elif change.kind == "removed":
            lines.append(f"- {change.ip}  host disappeared")
        else:
            lines.append(f"~ {change.ip}  {', '.join(change.details)}")
    lines.append("")
    lines.append(
        f"{len(diff.added)} added · {len(diff.removed)} removed · "
        f"{len(diff.changed)} changed · {diff.unchanged} unchanged"
    )
    return "\n".join(lines) + "\n"


def _index(hosts: object) -> dict[str, dict]:
    if not isinstance(hosts, list):
        return {}
    indexed: dict[str, dict] = {}
    for host in hosts:
        if isinstance(host, dict) and isinstance(host.get("ip"), str):
            indexed[host["ip"]] = host
    return indexed


def _changes_between(before: dict, after: dict) -> tuple[str, ...]:
    details: list[str] = []

    old_ports = set(before.get("open_ports") or ())
    new_ports = set(after.get("open_ports") or ())
    opened = sorted(new_ports - old_ports)
    closed = sorted(old_ports - new_ports)
    if opened:
        details.append("opened " + ", ".join(str(port) for port in opened))
    if closed:
        details.append("closed " + ", ".join(str(port) for port in closed))

    for key, label in (("hostname", "hostname"), ("mac", "MAC")):
        old_value = before.get(key)
        new_value = after.get(key)
        if old_value != new_value:
            details.append(f"{label} {old_value or '—'} → {new_value or '—'}")

    old_methods = set(before.get("methods") or ())
    new_methods = set(after.get("methods") or ())
    if old_methods != new_methods:
        details.append(
            "methods " + " ".join(sorted(old_methods)) + " → " + " ".join(sorted(new_methods))
        )

    old_service = _service_summary(before)
    new_service = _service_summary(after)
    if old_service != new_service:
        details.append(f"service {old_service or '—'} → {new_service or '—'}")

    return tuple(details)


def _service_summary(host: dict) -> str:
    services = host.get("services")
    if not isinstance(services, list):
        return ""
    parts = []
    for service in services:
        if not isinstance(service, dict):
            continue
        label = service.get("server") or service.get("banner")
        if label:
            parts.append(f"{service.get('port')}:{label}")
    return ", ".join(parts)


def _sort_key(ip: str) -> tuple[int, object]:
    import ipaddress

    try:
        return (0, ipaddress.ip_address(ip))
    except ValueError:
        return (1, ip)


__all__ = [
    "DiffError",
    "HostChange",
    "ScanDiff",
    "diff_reports",
    "load_report",
    "render_diff_text",
]
