"""Target expression parsing and local-network detection."""

from __future__ import annotations

import contextlib
import ipaddress
import re
import socket
from collections.abc import Iterable, Iterator
from pathlib import Path

from .constants import LOCAL_PREFIX, MAX_TARGETS


class TargetError(ValueError):
    """Raised when a target expression is invalid or too large."""


_RANGE_RE = re.compile(
    r"^(?P<start>\d{1,3}(?:\.\d{1,3}){3})\s*-\s*"
    r"(?P<end>(?:\d{1,3}(?:\.\d{1,3}){3}|\d{1,3}))$"
)


def parse_targets(specs: Iterable[str]) -> list[str]:
    """Expand target expressions into a deduplicated list of addresses.

    Each item may be a CIDR network, a single address, an IPv4 range
    (``192.168.1.10-20``), a hostname, or ``auto`` to scan the local /24.
    """
    cleaned = [item.strip() for item in specs if item and item.strip()]
    if not cleaned:
        cleaned = ["auto"]

    targets: list[str] = []
    seen: set[str] = set()
    for spec in cleaned:
        for address in _expand(spec):
            if address not in seen:
                seen.add(address)
                targets.append(address)

    return targets


def detect_local_target() -> str:
    """Best-effort guess at the network the machine is attached to."""
    address = _local_ipv4()
    return f"{address}/{_local_prefix(address)}"


# ----------------------------------------------------------------------
# Scope files
# ----------------------------------------------------------------------
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_scope_entries(entries: Iterable[str]) -> list[Network]:
    """Parse CIDRs, single addresses and ranges into a list of networks.

    Comments start with ``#``. Entries may be separated by whitespace, commas
    or newlines, which makes a hand-written scope file forgiving.
    """
    networks: list[Network] = []
    for raw in entries:
        line = raw.split("#", 1)[0]
        for token in re.split(r"[\s,]+", line.strip()):
            if token:
                networks.extend(_scope_token(token))
    return networks


def parse_scope_file(path: str | Path) -> list[Network]:
    """Read a scope file. Missing files are a hard error, not a silent pass."""
    scope_path = Path(path).expanduser()
    try:
        text = scope_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TargetError(f"cannot read scope file '{path}': {exc}") from exc
    networks = parse_scope_entries(text.splitlines())
    if not networks:
        raise TargetError(f"scope file '{path}' contains no networks")
    return networks


def parse_excludes(specs: Iterable[str]) -> list[Network]:
    """Parse ``--exclude`` values with the same grammar as a scope file."""
    return parse_scope_entries(specs)


def enforce_scope(
    targets: Iterable[str],
    allow: list[Network],
    deny: list[Network] | None = None,
) -> list[str]:
    """Refuse any target outside the allowlist or inside a denylist."""
    deny = deny or []
    checked = list(targets)
    for target in checked:
        address = ipaddress.ip_address(target)
        if any(address in network for network in deny):
            raise TargetError(f"target '{target}' is excluded by the deny list")
        if allow and not any(address in network for network in allow):
            raise TargetError(
                f"target '{target}' is outside the configured scope; "
                "add it to --scope-file only if you are authorised to scan it"
            )
    return checked


def public_targets(targets: Iterable[str]) -> list[str]:
    """Return the targets that are globally routable."""
    public: list[str] = []
    for target in targets:
        with contextlib.suppress(ValueError):
            if ipaddress.ip_address(target).is_global:
                public.append(target)
    return public


def _scope_token(token: str) -> list[Network]:
    if "/" in token:
        try:
            return [ipaddress.ip_network(token, strict=False)]
        except ValueError as exc:
            raise TargetError(f"invalid scope network '{token}'") from exc

    try:
        suffix = "/32" if "." in token else "/128"
        return [ipaddress.ip_network(f"{token}{suffix}", strict=False)]
    except ValueError:
        pass

    match = _RANGE_RE.match(token)
    if match:
        try:
            start = ipaddress.ip_address(match["start"])
            end_text = match["end"]
            if "." in end_text or ":" in end_text:
                end = ipaddress.ip_address(end_text)
            else:
                end = ipaddress.ip_address(f"{match['start'].rsplit('.', 1)[0]}.{end_text}")
            if start.version != end.version or int(end) < int(start):
                raise ValueError
            return list(ipaddress.summarize_address_range(start, end))
        except ValueError as exc:
            raise TargetError(f"invalid scope range '{token}'") from exc

    raise TargetError(f"invalid scope entry '{token}'; use a CIDR, an address or an IPv4 range")


def _expand(spec: str) -> Iterator[str]:
    if spec.lower() in {"auto", "local"}:
        yield from _network_hosts(detect_local_target())
        return

    if "/" in spec:
        yield from _network_hosts(spec)
        return

    match = _RANGE_RE.match(spec)
    if match:
        yield from _range_hosts(match["start"], match["end"])
        return

    yield _resolve(spec)


def _network_hosts(cidr: str) -> Iterator[str]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise TargetError(f"invalid network '{cidr}'") from exc

    if network.num_addresses > MAX_TARGETS:
        raise TargetError(
            f"'{cidr}' contains {network.num_addresses:,} addresses, which exceeds the "
            f"{MAX_TARGETS:,}-address limit; narrow the range or scan one subnet at a time"
        )

    # ``hosts()`` skips the network and broadcast addresses for ordinary IPv4
    # subnets, which is exactly what a discovery scan wants.
    addresses = (
        network.hosts() if network.version == 4 and network.prefixlen < 31 else iter(network)
    )
    for address in addresses:
        yield str(address)


def _range_hosts(start_text: str, end_text: str) -> Iterator[str]:
    start = ipaddress.ip_address(_resolve(start_text))

    if "." in end_text or ":" in end_text:
        end = ipaddress.ip_address(_resolve(end_text))
    else:
        if start.version != 4:
            raise TargetError(f"invalid range '{start_text}-{end_text}'")
        prefix = start_text.rsplit(".", 1)[0]
        end = ipaddress.ip_address(f"{prefix}.{end_text}")

    if start.version != end.version:
        raise TargetError("range endpoints must use the same address family")
    if int(end) < int(start):
        raise TargetError(f"range '{start_text}-{end_text}' ends before it starts")
    if int(end) - int(start) + 1 > MAX_TARGETS:
        raise TargetError(
            f"range '{start_text}-{end_text}' exceeds the {MAX_TARGETS:,}-address limit"
        )

    address_class = type(start)
    for value in range(int(start), int(end) + 1):
        yield str(address_class(value))


def _resolve(host: str) -> str:
    candidate = host.strip().strip("[]")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(candidate, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetError(f"cannot resolve host '{host}'") from exc

    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            return str(sockaddr[0])
    return str(infos[0][4][0])


def _local_ipv4() -> str:
    for probe in ("8.8.8.8", "1.1.1.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.25)
                sock.connect((probe, 80))
                candidate = sock.getsockname()[0]
        except OSError:
            continue
        if candidate and not candidate.startswith("127."):
            return candidate

    with contextlib.suppress(OSError):
        candidate = socket.gethostbyname(socket.gethostname())
        if candidate and not candidate.startswith("127."):
            return candidate

    raise TargetError("could not detect a local network; pass a target such as 192.168.1.0/24")


def _local_prefix(address: str) -> int:
    """Use psutil's netmask when available, otherwise assume a /24."""
    try:
        import psutil
    except ImportError:
        return LOCAL_PREFIX

    with contextlib.suppress(Exception):
        for addresses in psutil.net_if_addrs().values():
            for entry in addresses:
                if entry.family == socket.AF_INET and entry.address == address and entry.netmask:
                    return ipaddress.ip_network(
                        f"{address}/{entry.netmask}", strict=False
                    ).prefixlen
    return LOCAL_PREFIX
