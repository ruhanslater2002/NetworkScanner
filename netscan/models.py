"""Typed value objects used by the scan engine and the CLI."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .constants import TOP_PORTS


class DiscoveryMethod(str, Enum):
    """How a host was found alive."""

    PING = "ping"
    TCP = "tcp"
    ARP = "arp"

    @property
    def label(self) -> str:
        return {"ping": "ICMP", "tcp": "TCP", "arp": "ARP"}[self.value]


class Intensity(str, Enum):
    """Politeness preset for a discovery scan.

    The presets change how probes are batched and paced. They intentionally do
    not override an explicit ``concurrency`` or ``timeout`` supplied by the
    operator; the CLI resolves those defaults from the preset.
    """

    POLITE = "polite"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"

    @property
    def label(self) -> str:
        return self.value.capitalize()

    @property
    def port_batch(self) -> int:
        return {"polite": 4, "normal": 16, "aggressive": 64}[self.value]

    @property
    def host_delay(self) -> float:
        return {"polite": 0.05, "normal": 0.0, "aggressive": 0.0}[self.value]

    @property
    def concurrency(self) -> int:
        return {"polite": 32, "normal": 256, "aggressive": 1_024}[self.value]

    @property
    def timeout(self) -> float:
        return {"polite": 2.0, "normal": 1.0, "aggressive": 0.5}[self.value]


class PortState(str, Enum):
    """Observed state of a TCP port."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    ERROR = "error"

    @property
    def label(self) -> str:
        return self.value.capitalize()


@dataclass(frozen=True, slots=True)
class ServiceInfo:
    """Optional metadata collected from an open port."""

    port: int
    banner: str | None = None
    server: str | None = None
    tls: bool = False
    tls_subject: str | None = None
    tls_issuer: str | None = None
    tls_expires: str | None = None
    tls_days_left: int | None = None

    @property
    def summary(self) -> str:
        """One-line description suitable for a table cell."""
        if self.server:
            return self.server
        if self.banner:
            return self.banner
        if self.tls_subject:
            return f"TLS: {self.tls_subject}"
        if self.tls:
            return "TLS"
        return "—"


@dataclass(frozen=True, slots=True)
class PortResult:
    """State and optional service metadata for one probed port."""

    port: int
    state: PortState
    latency_ms: float | None = None
    service: ServiceInfo | None = None


@dataclass(frozen=True, slots=True)
class Host:
    """A host that answered at least one probe."""

    ip: str
    methods: frozenset[DiscoveryMethod]
    hostname: str | None = None
    mac: str | None = None
    latency_ms: float | None = None
    open_ports: tuple[int, ...] = ()
    port_details: tuple[PortResult, ...] = ()
    services: tuple[ServiceInfo, ...] = ()

    @property
    def sort_key(self) -> tuple[int, object]:
        """Sort numerically by address, falling back to lexical order."""
        try:
            return (0, ipaddress.ip_address(self.ip))
        except ValueError:
            return (1, self.ip)

    @property
    def closed_ports(self) -> tuple[int, ...]:
        return tuple(
            result.port for result in self.port_details if result.state is PortState.CLOSED
        )

    @property
    def filtered_ports(self) -> tuple[int, ...]:
        return tuple(
            result.port
            for result in self.port_details
            if result.state in {PortState.FILTERED, PortState.ERROR}
        )


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Everything needed to run a scan."""

    targets: tuple[str, ...]
    ports: tuple[int, ...] = TOP_PORTS
    timeout: float = 1.0
    concurrency: int = 256
    methods: frozenset[DiscoveryMethod] = field(
        default_factory=lambda: frozenset({DiscoveryMethod.PING, DiscoveryMethod.TCP})
    )
    resolve_hostnames: bool = True
    intensity: Intensity = Intensity.NORMAL
    rate: float | None = None
    host_delay: float | None = None
    service_info: bool = False
    tls_info: bool = False

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if not self.methods:
            raise ValueError("at least one discovery method is required")
        if DiscoveryMethod.TCP in self.methods and not self.ports:
            raise ValueError("TCP discovery requires at least one port")
        if self.rate is not None and self.rate <= 0:
            raise ValueError("rate must be greater than zero")
        if self.host_delay is not None and self.host_delay < 0:
            raise ValueError("host delay cannot be negative")
        if not isinstance(self.intensity, Intensity):
            try:
                object.__setattr__(self, "intensity", Intensity(str(self.intensity).lower()))
            except ValueError as exc:
                raise ValueError(f"unknown intensity '{self.intensity}'") from exc

    @property
    def effective_host_delay(self) -> float:
        if self.host_delay is not None:
            return self.host_delay
        return self.intensity.host_delay


@dataclass(slots=True)
class ScanReport:
    """Aggregated outcome of one complete scan."""

    targets: tuple[str, ...]
    hosts: list[Host]
    started_at: datetime
    finished_at: datetime
    duration_s: float
    probed: int
    errors: int = 0

    @property
    def rate(self) -> float:
        """Hosts discovered per second."""
        return len(self.hosts) / self.duration_s if self.duration_s > 0 else 0.0

    @property
    def hosts_by_method(self) -> dict[DiscoveryMethod, int]:
        counts = dict.fromkeys(DiscoveryMethod, 0)
        for host in self.hosts:
            for method in host.methods:
                counts[method] += 1
        return counts

    @property
    def port_states(self) -> dict[PortState, int]:
        counts = dict.fromkeys(PortState, 0)
        for host in self.hosts:
            for result in host.port_details:
                counts[result.state] += 1
        return counts

    @property
    def service_count(self) -> int:
        return sum(len(host.services) for host in self.hosts)
